use core::{
    cell::RefCell,
    future::Future,
    pin::Pin,
    task::{Context, Poll},
};

use embassy_futures::select::{Either, select};
use embassy_sync::{
    blocking_mutex::raw::NoopRawMutex,
    channel::{Channel, DynamicSender},
};
use embassy_time::{Duration, Timer};
use pin_project::pin_project;
use zerocopy::{FromBytes, Immutable, KnownLayout, Ref, Unaligned};

use crate::{
    address::{GroupAddress, IndividualAddress, KNXAddress},
    messages::{
        buffers::{Buffer, DynBufferManager},
        knx::{KnxMessageBuffer, ServiceType},
    },
};

pub trait LowerLinkLayer {
    async fn receive(&mut self) -> KnxMessageBuffer<Buffer<'static>>;
    async fn transmit(&mut self, msg: KnxMessageBuffer<Buffer<'static>>) -> KnxMessageBuffer<Buffer<'static>>;
}

// TODO:
// * If the length of the LSDU requires an L_Data-Frame with value of the field Length ≥ 255
//   characters, then no L_Data-Frame shall be transmitted on the bus; the L_Data.req shall
//   be confirmed by an L_Data.con with l_status = not_ok
// * If the remote Data Link Layer instance receives an L_Data-Frame, it shall check the Frame correctness.
//   An L_Data-Frame shall be considered correct if all of the following requirements are fulfilled.
//       1. The L_Data-Frame is correct according the general KNX TP1 Frame check conditions as
//          specified in clause 2.5.3 Checking for correct request Frames.
//       2. The length of the Frame is between 8 and 23 characters for an L_Data_Standard-Frame or
//          between 9 and 263 for an L_Data_Extended-Frame. (The character counting includes the Check
//          octet.)
// * If the received Frame is not correct then it shall not be passed to the Data Link Layer user.
// * Address checking as per 01/03/02 2.4.2

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

    /// Transmission completed, waiting for ACK/NACK confirmation.
    /// During this time, more frames caused by automatic retransmissions may be received.
    WaitingForConfirmation,

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
    message_out: Option<Buffer<'static>>,
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

    pub async fn initialize(&mut self) {
        // Start the interface if necessary
        if self.state == TpUartState::New {
            self.state_transition(TpUartState::Start).await;
        }

        // Wait for initialization to complete
        while !matches!(self.state, TpUartState::Idle | TpUartState::Error) {
            let mut buf = [0u8];

            match select(Pin::new(&mut self.state_timeout), self.uart.read(&mut buf)).await {
                Either::First(timeout_state) => {
                    trace!("Timeout timer fired during init, transitioning to {:?}", timeout_state);
                    self.state_timeout.retry();
                    self.state_transition(timeout_state).await;
                }
                Either::Second(_) => {
                    trace!("TPUART INIT RX: {:x?}", buf[0]);
                    let _ = self.handle_incoming_byte(buf[0]).await;
                }
            }
        }

        if self.state == TpUartState::Error {
            error!("TPUART initialization failed");
        } else {
            trace!("TPUART initialization completed successfully");
        }
    }

    async fn handle_incoming_byte(&mut self, incoming: u8) -> Option<KnxMessageBuffer<Buffer<'static>>> {
        // Are we already in the process of receiving a frame?
        if let TpUartState::Receive { .. } = self.state
            && let Some(message_in) = self.message_in.as_mut()
            && message_in.len() > 0
        {
            trace!("Adding byte to ongoing receive: {:02x}", incoming);

            // Save the byte we just received
            message_in.push(incoming);

            // Reset receive timeout for the next byte to 1s
            self.state_timeout.start(TpUartState::ReceiveTimeout, TpUartState::Invalid, Duration::from_secs(1), 0);

            // Try to parse the header of the message we partly received
            match self.header_parse() {
                ReceiveInfo::None => {}
                ReceiveInfo::ParsedHeader { ack, expected_len, is_echo } => {
                    trace!(
                        "Header for ongoing receive parsed, ack: {}, expected_len: {}, is_echo: {}",
                        ack, expected_len, is_echo
                    );
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

                    // Take the received message and return it
                    // FIXME: need to check if CRC is correct
                    if let Some(buffer) = self.message_in.take() {
                        return Some(KnxMessageBuffer::new(buffer, ServiceType::L_Data_Ind));
                    }
                }
                ReceiveInfo::TransmitComplete => {
                    trace!("Transmission completed");

                    self.state_timeout.stop();
                    self.state_transition(TpUartState::WaitingForConfirmation).await;
                }
            };

            return None;
        }

        // We are receiving the first byte of a new frame or an automatically retransmitted frame
        if (self.state == TpUartState::Idle || self.state == TpUartState::WaitingForConfirmation)
            && (incoming & 0x50) == L_DATA_EXTENDED_IND
        {
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
                trace!("Received expected U_Reset.ind, sending config now");
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

                // FIXME: if we receive this during transmission, something is wrong and we should reset
                // FIXME: always reset?
                _ => error!("TpUart state {:?} invalid", self.state),
            }

        // We are receiving a confirmation from a remote device
        // That means it's either an ACK or a NACK
        } else if incoming & 0x7F == L_DATA_CON {
            // FIXME: what if no ack is requested in the frame to be transmitted? Does the uart still send this .con?
            let ack = incoming & 0x80 != 0;

            if ack {
                trace!("L_Data.con ACK");
            } else {
                trace!("L_Data.con NACK");
            }

            // If we're waiting for confirmation, handle the ACK/NACK
            if self.state == TpUartState::WaitingForConfirmation {
                if let Some(mut transmitted_data) = self.message_in.take() {
                    // Set the error flag in the confirmation based on ACK/NACK
                    if !ack && transmitted_data.len() > 0 {
                        transmitted_data[0] |= 0x01;
                    } else {
                        transmitted_data[0] &= 0xFE;
                    }

                    self.state_transition(TpUartState::Idle).await;
                    return Some(KnxMessageBuffer::new(transmitted_data, ServiceType::L_Data_Con));
                }
            }

        // That's BUSMON stuff
        //                    ACK                 NACK                BSY
        } else if incoming == 0xCC || incoming == 0xC0 || incoming == 0x0C {
            if incoming == 0xCC {
                trace!("L_Ackn.ind ACK");
            } else if incoming == 0xC0 {
                trace!("L_Ackn.ind NACK");
            } else if incoming == 0x0C {
                trace!("L_Ackn.ind BSY");
            }
        } else {
            error!("Unknown TPUart command: {:02x}", incoming);
        }

        None
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

                // Check if this is an echo of our transmitted message
                let is_echo = if let Some(message_out) = &self.message_out {
                    (self.message_in.as_ref().unwrap()[0] ^ message_out[0]) & !0x20 == 0
                        && self.message_in.as_ref().unwrap()[1..5] == message_out[1..5]
                } else {
                    false
                };

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

        // If we are receiving an echo, this means the TP-UART has transmitted our frame onto the bus.
        // We may receive multiple echo frames (retransmissions) until an ACK is received from the destination.
        // When we've received a complete echo frame, we signal TransmitComplete so the transmit loop knows
        // the echo phase is done and can wait for ACK/NACK confirmation.
        } else if let TpUartState::Receive { expected_len: Some(expected_len), is_echo: true, .. } = self.state {
            // If we received as many bytes as we expect for this echo frame
            if self.message_in.as_ref().unwrap().len() == expected_len {
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
                // Clear any partially received message
                let _ = self.message_in.take();
                self.state = TpUartState::Idle;
            }

            TpUartState::WaitingForConfirmation => {
                self.state = TpUartState::WaitingForConfirmation;
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
        if self.state != TpUartState::Idle {
            panic!("TP-Uart is not idle, cannot receive. Current state: {:?}", self.state);
        }

        loop {
            let mut buf = [0u8];

            match select(Pin::new(&mut self.state_timeout), self.uart.read(&mut buf)).await {
                Either::First(timeout_state) => {
                    trace!("Timeout timer fired, transitioning to {:?}", timeout_state);
                    self.state_timeout.retry();
                    self.state_transition(timeout_state).await;
                }
                Either::Second(_) => {
                    trace!("TPUART RX: {:x?}", buf[0]);
                    if let Some(message) = self.handle_incoming_byte(buf[0]).await {
                        return message;
                    }
                }
            }
        }
    }

    async fn transmit(&mut self, msg: KnxMessageBuffer<Buffer<'static>>) -> KnxMessageBuffer<Buffer<'static>> {
        if self.state != TpUartState::Idle {
            panic!("TP-Uart is not idle, cannot transmit. Current state: {:?}", self.state);
        }

        // Get the data from the message
        let data = msg.into_inner();

        trace!("Starting transmission of {} bytes: {:x?}", data.len(), data);

        // Calculate checksum: XOR all bytes in the frame
        let mut checksum = 0u8;
        for &byte in &data[..] {
            checksum ^= byte;
        }
        // The checksum is XORed with 0xFF so that XORing all bytes including checksum results in 0
        checksum ^= 0xFF;
        let checksum = &[checksum];

        // Store the outgoing message for echo detection
        self.message_out = Some(data);

        let mut it = self.message_out.as_ref().unwrap().iter().chain(checksum).enumerate().peekable();
        while let Some((i, b)) = it.next() {
            let cmd = if it.peek().is_some() {
                [U_L_DATA_START | (i & 0xff) as u8, *b]
            } else {
                [U_L_DATA_END | (i & 0xff) as u8, *b]
            };

            self.uart.write_all(&cmd).await.expect("Unable to write to UART");
        }

        // Now the TP-UART will buffer and start transmitting on the bus
        // We transition to waiting for confirmation and echo frames
        self.state_transition(TpUartState::WaitingForConfirmation).await;

        // Wait for echo frames and final ACK/NACK confirmation
        loop {
            let mut buf = [0u8];

            match select(Pin::new(&mut self.state_timeout), self.uart.read(&mut buf)).await {
                Either::First(timeout_state) => {
                    trace!("Timeout timer fired during transmit, transitioning to {:?}", timeout_state);
                    self.state_timeout.retry();
                    self.state_transition(timeout_state).await;
                }
                Either::Second(_) => {
                    trace!("TPUART RX: {:x?}", buf[0]);
                    if let Some(confirmation) = self.handle_incoming_byte(buf[0]).await {
                        // If we received a confirmation message (ACK/NACK), return it
                        return confirmation;
                    }
                }
            }
        }
    }
}
