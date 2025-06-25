use core::{
    cell::RefCell,
    pin::Pin,
    task::{Context, Poll},
};

use embassy_futures::select::{Either3, select3};
use embassy_sync::{
    blocking_mutex::raw::NoopRawMutex,
    channel::{Channel, DynamicSender},
};
use embassy_time::{Duration, Timer};
use pin_project::pin_project;
use zerocopy::{FromBytes, Immutable, KnownLayout, Ref, Unaligned};

use crate::{
    address::{GroupAddress, IndividualAddress, KNXAddress},
    layers::DropBomb,
    messages::{
        buffers::{Buffer, DynBufferManager},
        knx::KnxMessageBuffer,
    },
};

pub trait LowerLinkLayer {
    async fn receive(&mut self) -> KnxMessageBuffer<Buffer<'static>>;
    async fn transmit(&mut self, msg: KnxMessageBuffer<Buffer<'static>>) -> KnxMessageBuffer<Buffer<'static>>;
}

/// TP-Uart services
const L_DATA_CON: u8 = 0x0b;
const L_DATA_EXTENDED_IND: u8 = 0x10;
//const L_DATA_STANDARD_IND: u8 = 0x90;
//const L_POLL_DATA_IND: u8     = 0xf0;
const U_RESET_REQ: u8 = 0x01;
const U_STATE_RQ: u8 = 0x02;
const U_RESET_IND: u8 = 0x03;
const U_STATE_IND: u8 = 0x07;
const U_ACK_INFORMATION: u8 = 0x10;
const U_L_DATA_START: u8 = 0x80;
const U_L_DATA_END: u8 = 0x40;
const U_MAX_RST_CNT: u8 = 0x24;
const U_SET_ADDRESS: u8 = 0x28;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum TpUartState {
    New,
    Error,
    Start,
    InReset,
    InSendConfig,
    InGetState,

    /// The TP-Uart is configured and waiting to receive a frame from the bus
    /// or transmit a frame
    Idle,

    /// The TP-Uart received an L-Data.ind (Standard or extended) and receives
    /// the frame byte by byte. After it gathered enough of the frame if can
    /// parse the `expected_len` and receive as many bytes as necessary from the
    /// bus.
    /// Should a frame be received completely and the FCS is correct, it
    /// is passed to the upper layer.
    /// In case of a wrong FCS, the frame is silently discarded.
    /// In case of a timeout, the state is transitioned into `ReceiveTimeout`
    Receive {
        acked: bool,
        expected_len: Option<usize>,
        is_echo: bool,
    },

    ReceiveTimeout,
    // WaitKeepalive,
    // BusMonitor,
    Invalid,
}

#[pin_project]
struct Timeout<State: Copy> {
    pending_timeout: Option<Duration>,
    num_attempts: usize,
    max_retries: usize,
    retry_state: Option<State>,
    failure_state: Option<State>,
    #[pin]
    timer: Option<Timer>,
}

impl<State: Copy> Timeout<State> {
    fn new() -> Self {
        Self {
            pending_timeout: None,
            num_attempts: 0,
            max_retries: 0,
            retry_state: None,
            failure_state: None,
            timer: None,
        }
    }

    fn start(&mut self, failure_state: State, retry_state: State, timeout: Duration, max_retries: usize) {
        self.pending_timeout = Some(timeout);
        self.max_retries = max_retries;
        self.retry_state = Some(retry_state);
        self.failure_state = Some(failure_state);
        self.timer = Some(Timer::after(timeout));
    }

    fn stop(&mut self) {
        self.pending_timeout = None;
        self.num_attempts = 0;
        self.max_retries = 0;
        self.retry_state = None;
        self.failure_state = None;
        self.timer = None;
    }

    fn retry(&mut self) {
        self.num_attempts += 1;
        if let Some(timeout) = self.pending_timeout {
            self.timer = Some(Timer::after(timeout));
        }
    }
}

// Future implementation that resolves when timer expires
impl<State: Copy> Future for Timeout<State> {
    type Output = State;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let mut this = self.project();

        // Check if we have a pending timeout
        if this.pending_timeout.is_none() {
            return Poll::Pending; // No timeout active
        }

        // Determine which state to return based on attempts
        let target_state = if *this.num_attempts == *this.max_retries {
            *this.failure_state.as_ref().unwrap()
        } else {
            *this.retry_state.as_ref().unwrap()
        };

        // Poll the timer if we have one
        if let Some(timer) = this.timer.as_mut().as_pin_mut() {
            match timer.poll(cx) {
                // Timer expired, resolve with the target state
                Poll::Ready(_) => Poll::Ready(target_state),
                // Timer still pending, return Poll::Pending
                Poll::Pending => Poll::Pending,
            }
        } else {
            // No timer, remain pending
            Poll::Pending
        }
    }
}

/// Start of a TP1 standard frame
///
/// see KNX 03/02/02 - 2.2.4.1
#[derive(Debug, FromBytes, Unaligned, KnownLayout, Immutable)]
#[repr(C)]
struct TPFrameHeaderStandard {
    ctrl: u8,
    source_addr: IndividualAddress,
    dst_addr: [u8; 2],
    at_length: u8,
}

/// Start of a TP1 extended frame
///
/// see KNX 03/02/02 - 2.2.5.1
#[derive(Debug, FromBytes, Unaligned, KnownLayout, Immutable)]
#[repr(C)]
struct TPFrameHeaderExtended {
    ctrl: u8,
    ext_ctrl: u8,
    source_addr: IndividualAddress,
    dst_addr: [u8; 2],
    length: u8,
}

/// ReceiveInfo contains information about an ongoing reception of a frame and
/// info parsed from a partially received frame still on the wire.
///
/// Parsed info contains information like the expected length, if the frame
/// should be acked because a destination address matched, if it's an echo
/// because we are transmitting this frame currently etc.
#[derive(Debug)]
enum ReceiveInfo {
    None,
    ParsedHeader { ack: bool, expected_len: usize, is_echo: bool },
    ReceiveComplete,
    TransmitComplete,
}

// FIXME: find out proper size based on extended frames
const MAX_APDU_LEN_STD: usize = 15;
const MAX_TPUART_LDATA_FRAME_LEN: usize = 64;

// FIXME: retry count dynamic as part of a config?
const NAK_RETRY_COUNT: u8 = 3;
const BSY_RETRY_COUNT: u8 = 3;

pub struct TpUartLinkLayer<'a, U>
where
    U: embedded_io_async::Read + embedded_io_async::Write,
{
    uart: U,
    buffer_manager: &'a RefCell<DynBufferManager<'static>>,
    state: TpUartState,
    state_timeout: Timeout<TpUartState>,
    tx_queue: Channel<
        NoopRawMutex,
        (KnxMessageBuffer<Buffer<'static>>, DynamicSender<'static, KnxMessageBuffer<Buffer<'static>>>),
        1,
    >,
    message_in: Option<Buffer<'static>>,
    message_out: Option<(Buffer<'static>, DynamicSender<'static, KnxMessageBuffer<Buffer<'static>>>)>,
    individual_addr: Option<IndividualAddress>,
}

impl<'a, U> TpUartLinkLayer<'a, U>
where
    U: embedded_io_async::Read + embedded_io_async::Write,
{
    pub fn new(
        uart: U,
        individual_addr: Option<IndividualAddress>,
        buffer_manager: &'a RefCell<DynBufferManager<'static>>,
    ) -> Self {
        Self {
            uart,
            buffer_manager,
            state: TpUartState::New,
            state_timeout: Timeout::new(),
            tx_queue: Channel::new(),
            message_in: None,
            message_out: None,
            individual_addr,
        }
    }

    async fn handle_incoming_byte(&mut self, incoming: u8) {
        // Are we already in the process of receiving a frame?
        if self.state != TpUartState::Idle
            && let Some(message_in) = self.message_in.as_mut()
            && message_in.len() > 0
        {
            // Save the byte we just received
            message_in.push(incoming);

            // Reset receive timeout for the next byte to 1s
            self.state_timeout.start(TpUartState::ReceiveTimeout, TpUartState::Invalid, Duration::from_secs(1), 0);

            // Try to parse the header of the message we partly received
            match self.header_parse() {
                ReceiveInfo::None => {}
                ReceiveInfo::ParsedHeader { ack, expected_len, is_echo } => {
                    // FIXME: if ack is true, we should send an immediate ACK command to TPUART. I think...
                    //        right now our individual addr is auto-acked, we don't handle grp addrs yet, but we need it for that

                    self.state_transition(TpUartState::Receive {
                        acked: ack,
                        expected_len: Some(expected_len),
                        is_echo,
                    })
                    .await;
                }
                ReceiveInfo::ReceiveComplete => {
                    debug!("Received TP1 frame: {:x?}", &self.message_in.as_ref().unwrap()[..]);

                    self.state_timeout.stop();
                    self.state_transition(TpUartState::Idle).await;

                    // if self.message_in.iter().copied().reduce(|a, b| a ^ b) == Some(0xff) {
                    //     trace!("Checksum of received frame was correct");

                    //     // FIXME: make tp1_to_cemi work in place on the existing Vec<u8>?
                    //     let cemi_packet = tp1_to_cemi(&self.message_in, CemiMessageCode::LDataInd, false);
                    //     // FIXME: no unwrap!
                    //     let cemi_parsed =
                    //         CemiPacket::<_, CemiLDataInd>::parse(&mut &cemi_packet[..], ()).unwrap();

                    //     // FIXME: it's weird to check this here. Why not do it in the network layer?
                    //     //        The LinkLayer spec defines these messages, but eh...
                    //     if cemi_parsed.message().ctrl1().sb() == SystemBroadcast::SysBroadcast {
                    //         // Send out the L_SystemBroadcast.ind to the network layer
                    //         indications
                    //             .notify(DataLinkLayerInd::LSystemBroadcast(cemi_parsed.into()))
                    //             .await;
                    //     } else {
                    //         // Send out the L_Data.ind to the network layer
                    //         indications.notify(DataLinkLayerInd::LData(cemi_parsed.into())).await;
                    //     }
                    // } else {
                    //     error!("Checksum of received frame is wrong, discarding");
                    // }
                }
                ReceiveInfo::TransmitComplete => {
                    trace!("Transmission completed");

                    self.state_timeout.stop();
                    self.state_transition(TpUartState::Idle).await;
                }
            };

            return;
        }

        // We are receiving the first byte of a new frame
        if self.state == TpUartState::Idle && (incoming & 0x50) == L_DATA_EXTENDED_IND {
            trace!("RX L_Data.ind {:02x}", incoming);

            let mut buffer = self.buffer_manager.borrow().alloc().await;
            buffer.push(incoming);
            self.message_in = Some(buffer);

            // Start the TX timeout (gets reset when the next byte is received)
            self.state_timeout.start(TpUartState::ReceiveTimeout, TpUartState::Invalid, Duration::from_secs(1), 0);

            self.state_transition(TpUartState::Receive { acked: false, expected_len: None, is_echo: false }).await;

        // We are receiving reset indication in response to a request request
        } else if incoming == U_RESET_IND {
            trace!("RX U_Reset.ind, cur state: {:?}", self.state);
            if self.state == TpUartState::InReset {
                trace!("Expected U_Reset.ind, attempting to set address now");
                self.state_timeout.stop();
                self.state_transition(TpUartState::InSendConfig).await;
            } else {
                error!("Received spurious U_Reset.ind")
            }

        // We are receiving a state indication in response to a get state request
        } else if (incoming & 0x07) == U_STATE_IND {
            trace!(
                "RX U_State.ind SC: {:?} - RE: {:?} - TE: {:?} - PE: {:?} -  TW: {:?}",
                incoming & 0x80 != 0,
                incoming & 0x40 != 0,
                incoming & 0x20 != 0,
                incoming & 0x10 != 0,
                incoming & 0x08 != 0,
            );

            match self.state {
                TpUartState::InReset => {}

                TpUartState::InSendConfig => {
                    self.state_timeout.stop();
                    self.state_transition(TpUartState::InGetState).await
                }

                TpUartState::InGetState => {
                    self.state_timeout.stop();
                    self.state_transition(TpUartState::Idle).await
                }

                _ => error!("TpUart state {:?} invalid", self.state),
            }

        // We are receiving a confirmation from a remote device
        // That means it's either an ACK or a NACK
        } else if incoming & 0x7F == L_DATA_CON {
            // FIXME: what if no ack is requested in the frame to be transmitted? Does the uart still send this .con?
            // FIXME: what about a LSystemBroadcast.Con?
            let ack = incoming & 0x80 != 0;

            if ack {
                trace!("L_Data.con ACK");
            } else {
                trace!("L_Data.con NACK");
            }

            // FIXME: Readd once we implemented TX
            // if let Some((_, con_channel)) = self.message_out.take() {
            //     // We need to take the received message and relay that back as a cemi confirmation
            //     // The received message also contains the repeated flag
            //     trace!("Received L_Data.con: {:x?}", self.message_in);

            //     // NOTE: invert the ACK bit here, because a confirmation with no errors is false
            //     let cemi_packet = tp1_to_cemi(&self.message_in, CemiMessageCode::LDataCon, !ack);
            //     // FIXME: no unwrap()!
            //     let cemi_parsed = CemiPacket::<_, CemiLDataCon>::parse(&mut &cemi_packet[..], ()).unwrap();

            //     con_channel.send(DataLinkLayerCon::LData(cemi_parsed.into())).await;
            // } else {
            //     warn!("Received L_Data.con (N)ACK, but not sending")
            // }

            // That's BUSMON stuff
            // //                    ACK                 NACK                BSY
            // } else if incoming == 0xCC || incoming == 0xC0 || incoming == 0x0C {
            //     if incoming == 0xCC {
            //         trace!("L_Ackn.ind ACK");
            //     } else if incoming == 0xC0 {
            //         trace!("L_Ackn.ind NACK");
            //     } else if incoming == 0x0C {
            //         trace!("L_Ackn.ind BSY");
            //     }
        } else {
            error!("Unknown TPUart command: {:02x}", incoming);
        }
    }

    fn header_parse(&mut self) -> ReceiveInfo {
        let mut ret = ReceiveInfo::None;

        // Do we have enough information yet to ACK the packet and determine its length?
        // If not, try to get this info
        if let TpUartState::Receive { acked: false, expected_len: None, .. } = self.state {
            // First make sure that we have enough data. For that we need to
            // know if we are dealing with a standard or extended frame.
            // Uppermost bit cleared means extended frame format
            let ext = (self.message_in.as_ref().unwrap()[0] & 0x80) != 0x80;
            let min_header_len = if ext {
                core::mem::size_of::<TPFrameHeaderExtended>()
            } else {
                core::mem::size_of::<TPFrameHeaderStandard>()
            };

            // Did we receive enough of the packet to have a parsable header?
            if self.message_in.as_ref().unwrap().len() >= min_header_len {
                trace!("Received enough of a frame to parse the header");

                // FIXME: use if let chains
                // FIXME: readd
                // let is_echo = if let Some(message_out) = &self.message_out {
                //     (self.message_in[0] ^ message_out.0[0]) & !0x20 == 0 && self.message_in[1..5] == message_out.0[1..5]
                // } else {
                //     false
                // };
                let is_echo = false;

                // Do we have to deal with a individual dst address of a group dst address?
                // Depending on the extended frame format or the standard format, we
                // need to check different bytes for the addr type flag
                let (dst_addr, expected_len) = if ext {
                    let header: Ref<_, TPFrameHeaderExtended> =
                        Ref::new_unaligned(&self.message_in.as_ref().unwrap()[..min_header_len]).unwrap();

                    let addr = if header.ext_ctrl & 0x80 == 0 {
                        KNXAddress::Individual(IndividualAddress::from_bytes(&header.dst_addr))
                    } else {
                        KNXAddress::Group(GroupAddress::from_bytes(&header.dst_addr))
                    };

                    // The length is the payload, header and CRC
                    let expected_length = header.length as usize + core::mem::size_of::<TPFrameHeaderExtended>() + 2;

                    (addr, expected_length)
                } else {
                    let header: Ref<_, TPFrameHeaderStandard> =
                        Ref::new_unaligned(&self.message_in.as_ref().unwrap()[..min_header_len]).unwrap();

                    let addr = if header.at_length & 0x80 == 0 {
                        KNXAddress::Individual(IndividualAddress::from_bytes(&header.dst_addr))
                    } else {
                        KNXAddress::Group(GroupAddress::from_bytes(&header.dst_addr))
                    };

                    // The length is the payload, header and CRC
                    let expected_length =
                        (header.at_length & 0x0F) as usize + core::mem::size_of::<TPFrameHeaderStandard>() + 2;

                    (addr, expected_length)
                };

                trace!("Parsed header. DST Addr: {:?}, expected length: {:?}", dst_addr, expected_len);

                // Check if we should ACK the packet
                let ack = if let Some(individual_addr) = self.individual_addr {
                    match dst_addr {
                        KNXAddress::Individual(addr) => {
                            // FIXME: we don't really need this, because we set a hw addr
                            addr == individual_addr
                        }
                        KNXAddress::Group(_) => {
                            // FIXME: need access to group address table and decide if we should ACK
                            false
                        }
                        KNXAddress::Unspecified(_) => unreachable!(),
                    }
                } else {
                    false
                };

                ret = ReceiveInfo::ParsedHeader { ack, expected_len, is_echo };
            }

        // Did we receive enough of the message so that we know how much we should expect?
        } else if let TpUartState::Receive { expected_len: Some(expected_len), is_echo: false, .. } = self.state {
            // If we received as many bytes as we expect, we can notify the main loop about that
            if self.message_in.as_ref().unwrap().len() == expected_len {
                ret = ReceiveInfo::ReceiveComplete;
            }

        // If we are receiving an echo, we can expect a TP-UART confirmation byte (positive or negative) at some point.
        // We need to tell the main loop that it needs to await this confirmation byte or a repeated transmission that
        // happens automatically because the TP-UART didn't see an ACK yet.
        } else if let TpUartState::Receive { expected_len: Some(expected_len), is_echo: true, .. } = self.state {
            // If we received as many bytes as we expect, we can notify the main loop about that
            if self.message_in.as_ref().unwrap().len() == expected_len {
                // Grab the last byte which contains the confirmation
                ret = ReceiveInfo::TransmitComplete;
            }
        }

        ret
    }

    async fn state_transition(&mut self, new_state: TpUartState) {
        trace!("State transition {:?} -> {:?}", self.state, new_state);

        match new_state {
            TpUartState::Start | TpUartState::InReset => {
                // FIXME: clear message_out, message_in and other data that might be useless now?
                let _ = self.message_in.take();

                // Send reset
                self.uart.write_all(&[U_RESET_REQ]).await.expect("Unable to send reset command to TP-Uart");

                self.state_timeout.start(TpUartState::Error, TpUartState::InReset, Duration::from_millis(500), 2);
                self.state = TpUartState::InReset;
            }

            s @ TpUartState::InSendConfig | s @ TpUartState::InGetState => {
                if s == TpUartState::InSendConfig {
                    // Set an individual address if we have one
                    if let Some(addr) = self.individual_addr {
                        debug!("Sending address {:?}", addr);
                        let mut buf = [U_SET_ADDRESS, 0x00, 0x00];
                        buf[1..].copy_from_slice(addr.as_bytes());
                        self.uart.write_all(&buf).await.unwrap();
                    }

                    // Set maximum retry count
                    debug!("Setting maximum retry counts (NAK/BSY) to {:?} & {:?}", NAK_RETRY_COUNT, BSY_RETRY_COUNT);
                    let buf = [U_MAX_RST_CNT, (BSY_RETRY_COUNT & 0x7) << 5 | (NAK_RETRY_COUNT & 0x7)];
                    self.uart.write_all(&buf).await.unwrap();
                }

                trace!("Getting state from TP-Uart");

                // Send get state cmd
                self.uart.write_all(&[U_STATE_RQ]).await.expect("Unable to send get state command to TP-Uart");

                self.state_timeout.start(TpUartState::Error, TpUartState::InGetState, Duration::from_millis(500), 2);
                self.state = TpUartState::InGetState
            }

            // TpUartState::BusMonitor => {
            //     // Send busmon cmd
            //     self.uart.write_all(&[0x05]).await.unwrap();
            //     self.state = TpUartState::BusMonitor
            // },
            TpUartState::Idle => {
                self.state = TpUartState::Idle;
            }

            s @ TpUartState::Receive { acked: false, .. } => {
                self.state = s;
            }

            s @ TpUartState::Receive { acked: true, .. } => {
                trace!("Sending ACK for this frame");
                self.uart
                    .write_all(&[U_ACK_INFORMATION | 1])
                    .await
                    .expect("Unable to send immediate ACK command to TP-Uart");

                self.state = s;
            }

            TpUartState::ReceiveTimeout => {
                error!("RX timeout when receiving TP-Uart frame, going back to Idle");
                self.state_timeout.stop();
                self.state = TpUartState::Idle;
            }

            // TpUartState::WaitKeepalive => {
            //     //FIXME: what is this for?
            //     self.uart.write_all(&[0x02]).await.unwrap();
            //     //timer.start(0.5,0);

            //     self.state = TpUartState::WaitKeepalive
            // },
            TpUartState::Error => {
                error!("Entered error state");
                self.state_timeout.stop();
                self.state = TpUartState::Error
            }

            _ => unreachable!(),
        }
    }
}

impl<'a, U> LowerLinkLayer for TpUartLinkLayer<'a, U>
where
    U: embedded_io_async::Read + embedded_io_async::Write,
{
    async fn receive(&mut self) -> KnxMessageBuffer<Buffer<'static>> {
        // Start the interface if necessary
        if self.state == TpUartState::New {
            self.state_transition(TpUartState::Start).await;
        }

        loop {
            let mut buf = [0u8];

            match select3(Pin::new(&mut self.state_timeout), self.uart.read(&mut buf), core::future::pending()).await {
                Either3::First(timeout_state) => {
                    trace!("Timeout timer fired, transitioning to {:?}", timeout_state);
                    self.state_timeout.retry();
                    self.state_transition(timeout_state).await;
                }
                Either3::Second(_) => {
                    trace!("TPUART RX: {:x?}", buf[0]);
                    self.handle_incoming_byte(buf[0]).await;
                }
                Either3::Third(()) => {}
            }
        }
    }

    async fn transmit(&mut self, msg: KnxMessageBuffer<Buffer<'static>>) -> KnxMessageBuffer<Buffer<'static>> {
        type T = KnxMessageBuffer<Buffer<'static>>;

        let channel: Channel<NoopRawMutex, T, 1> = Channel::new();
        let sender: DynamicSender<'_, T> = channel.sender().into();
        let bomb = DropBomb::new();

        // We guarantee that channel lives until we've been notified on it, at which
        // point its out of reach for the replier.
        let con_channel = unsafe {
            core::mem::transmute::<
                &embassy_sync::channel::DynamicSender<'_, T>,
                &embassy_sync::channel::DynamicSender<'_, T>,
            >(&sender)
        };

        self.tx_queue.send((msg, con_channel.clone())).await;
        let res = channel.receive().await;

        bomb.defuse();
        res
    }
}
