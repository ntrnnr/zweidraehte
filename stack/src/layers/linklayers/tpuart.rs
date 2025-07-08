use core::{
    cell::RefCell,
    future::Future,
    pin::Pin,
    task::{Context, Poll},
};

use embassy_futures::select::{Either, Either3, select, select3};
use embassy_sync::channel::DynamicSender;
use embassy_time::{Duration, Timer};
use pin_project::pin_project;
use zerocopy::{FromBytes, Immutable, KnownLayout, Ref, Unaligned};

use crate::{
    address::{GroupAddress, IndividualAddress, KNXAddress},
    messages::{
        buffers::{Buffer, DynBufferManager, MessageBuffer},
        knx::*,
    },
};

use super::super::{Inbox, Layer, LayerOp};

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

// FIXME: if incoming frame is oversized, reject it, don't ACK
// FIXME: if outgoing frame is oversized, reject it, return error
// FIXME: turn TP1 into EMI2 when receiving
// FIXME: turn EMI2 into TP1 when queuing for transmission
// FIXME: ACK received frames when we handle the destination group address
// FIXME: Detect repeated frames that we already sent an indication upwards for and ignore them
// FIXME: Add support for NCN5120/30/31
// FIXME: Add support for TPUART1?
// FIXME: Add support for Elmos
// FIXME: Do we want to support BUSY singalling? Maybe for flash erasure and similar when the CPU stalls on AVRs or other small controllers?
// FIXME: add support fo bus monitor mode
// FIXME: add statistics?
// FIMXE: when running into RX timeouts, should we reset the TPUART? In case of n unsuccessful attempts to reset,
//        we can mark the bus a failed and keep resetting until we succeed. We need to test this with a microcontroller
//        that is independent from a TPUART and runs without bus power supply

// FIXME: right now we detect end of frames by parsing them and checking the length fields
//        the TPUART datasheet says we should rather detect this by applying a timeout of 2ms to 2.5ms
//        we can't do that with an FTDI or similar though, do we keep this?
// FIXME: Do we want a keepalive mechanism with a timer and state requests? Do we are if the bus is okay or not?
// FIXME: Do we want a timer that handles confirmations when transmitting?
//        Right now we trust the TPUART to give us a positive or negative confirmation after n retransmissions

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
    network_layer: DynamicSender<'a, LayerOp<KnxMessageBuffer<Buffer<'static>>>>,
    message_in: Option<Buffer<'static>>,
    message_out: Option<(Buffer<'static>, DynamicSender<'static, KnxMessageBuffer<Buffer<'static>>>)>,
    individual_addr: Option<IndividualAddress>,
    pending_transmission: Option<(Buffer<'static>, DynamicSender<'static, KnxMessageBuffer<Buffer<'static>>>)>,
}

impl<'a, U> TpUartLinkLayer<'a, U>
where
    U: embedded_io_async::Read + embedded_io_async::Write,
{
    pub fn new(
        uart: U,
        individual_addr: Option<IndividualAddress>,
        buffer_manager: &'a RefCell<DynBufferManager<'static>>,
        network_layer: DynamicSender<'a, LayerOp<KnxMessageBuffer<Buffer<'static>>>>,
    ) -> Self {
        Self {
            uart,
            buffer_manager,
            state: TpUartState::New,
            state_timeout: Timeout::new(),
            network_layer,
            message_in: None,
            message_out: None,
            individual_addr,
            pending_transmission: None,
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
                    self.handle_incoming_byte(buf[0]).await;
                }
            }
        }

        if self.state == TpUartState::Error {
            error!("TPUART initialization failed");
        } else {
            trace!("TPUART initialization completed successfully");
        }
    }

    async fn handle_incoming_byte(&mut self, incoming: u8) {
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
                // Unable to parse the header yet, continue receiving
                ReceiveInfo::None => {}

                // We received enough of the frame to parse the header
                // We'll just store the necessary information we gathered from the header in the state now
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

                // We received the complete frame, we can now process it further
                ReceiveInfo::ReceiveComplete => {
                    debug!("Received TP1 frame: {:x?}", &self.message_in.as_ref().unwrap()[..]);

                    self.state_timeout.stop();

                    // Take the received message and send it to network layer as indication
                    if let Some(buffer) = self.message_in.take() {
                        let mut checksum = 0u8;
                        for &byte in &buffer[..] {
                            checksum ^= byte;
                        }
                        checksum ^= 0xFF;

                        if checksum != 0x00 {
                            error!("WRRRRRRROOOOOOOOOOOOOOOOOOOOOONG CHECKSUM!");
                        }

                        let indication = KnxMessageBuffer::new(buffer, ServiceType::L_Data_Ind);
                        trace!("Sending L_Data.ind to network layer: {:?}", indication);
                        self.network_layer.send(LayerOp::Indication(indication)).await;
                    }

                    self.state_transition(TpUartState::Idle).await;

                    trace!(
                        "State: {:?}, Message In: {:?}, Message out: {:?}, Pending TX: {:?}",
                        self.state,
                        self.message_in,
                        self.message_out.as_ref().map(|(buf, _)| buf),
                        self.pending_transmission.as_ref().map(|(msg, _)| msg)
                    );
                }

                // If we received an echo, we can be sure that we transmitted this frame onto the bus
                // Now we need to wait for a positive or negative confirmation
                ReceiveInfo::TransmitComplete => {
                    trace!("Transmission completed");
                    self.state_timeout.stop();
                    self.state_transition(TpUartState::WaitingForConfirmation).await;
                }
            };

            return;
        }

        // We are receiving a state indication
        if (self.state == TpUartState::Idle
            || self.state == TpUartState::WaitingForConfirmation
            || self.state == TpUartState::InGetState)
            && (incoming & 0x07) == U_STATE_IND
        {
            trace!(
                "RX U_State.ind SC: {:?} - RE: {:?} - TE: {:?} - PE: {:?} - TW: {:?}",
                incoming & 0x80 != 0,
                incoming & 0x40 != 0,
                incoming & 0x20 != 0,
                incoming & 0x10 != 0,
                incoming & 0x08 != 0,
            );

            match self.state {
                TpUartState::InGetState => {
                    self.state_timeout.stop();
                    self.state_transition(TpUartState::Idle).await
                }

                TpUartState::Idle => {
                    // If we have a currently outgoing message and we receive any error
                    // indication except a temperature warning, reschedule it for transmission again
                    if let Some(msg) = self.message_out.take()
                        && incoming & 0xF0 != 0
                    {
                        warn!("Rescheduling failed out message for new send attempt");
                        self.pending_transmission = Some(msg);
                    }
                }

                _ => error!("TpUart state {:?} invalid - incoming: {:02x?}", self.state, incoming),
            }
        }
        // We are receiving reset indication in response to a request request
        else if (self.state == TpUartState::InReset) && incoming == U_RESET_IND {
            trace!("RX U_Reset.ind, cur state: {:?}", self.state);
            if self.state == TpUartState::InReset {
                trace!("Received expected U_Reset.ind, sending config now");
                self.state_timeout.stop();
                self.state_transition(TpUartState::InSendConfig).await;
            } else {
                error!("Received spurious U_Reset.ind")
            }
        }
        // We are receiving a confirmation from a remote device
        // That means it's either an ACK or a NACK
        else if (self.state == TpUartState::WaitingForConfirmation) && (incoming & 0x7F == L_DATA_CON) {
            // FIXME: what if no ack is requested in the frame to be transmitted? Does the uart still send this .con?
            let ack = incoming & 0x80 != 0;

            if ack {
                trace!("L_Data.con ACK");
            } else {
                trace!("L_Data.con NACK");
            }

            // If we're waiting for confirmation, handle the ACK/NACK
            if self.state == TpUartState::WaitingForConfirmation {
                if let Some((mut transmitted_data, response_tx)) = self.message_out.take() {
                    // Set the error flag in the confirmation based on ACK/NACK
                    if !ack && transmitted_data.len() > 0 {
                        transmitted_data[0] |= 0x01;
                    } else {
                        transmitted_data[0] &= 0xFE;
                    }

                    self.state_transition(TpUartState::Idle).await;

                    // Send confirmation back to the requester
                    let confirmation = KnxMessageBuffer::new(transmitted_data, ServiceType::L_Data_Con);
                    response_tx.send(confirmation).await;
                }
            }
        }
        // Incoming message
        else if (self.state == TpUartState::Idle || self.state == TpUartState::WaitingForConfirmation)
            && (incoming & 0x50) == L_DATA_EXTENDED_IND
        {
            trace!("RX L_Data.ind {:02x}", incoming);

            let mut buffer = self.buffer_manager.borrow().alloc().await;
            buffer.push(incoming);
            self.message_in = Some(buffer);

            // Start the TX timeout (gets reset when the next byte is received)
            self.state_timeout.start(TpUartState::ReceiveTimeout, TpUartState::Invalid, Duration::from_secs(1), 0);

            self.state_transition(TpUartState::Receive { acked: false, expected_len: None, is_echo: false }).await;
        }
        // Error
        else {
            error!("Unknown TPUart command: {:02x} in state {:?}", incoming, self.state);
        }

        // // // That's BUSMON stuff
        // // //                    ACK                 NACK                BSY
        // // } else if incoming == 0xCC || incoming == 0xC0 || incoming == 0x0C {
        // //     if incoming == 0xCC {
        // //         trace!("L_Ackn.ind ACK");
        // //     } else if incoming == 0xC0 {
        // //         trace!("L_Ackn.ind NACK");
        // //     } else if incoming == 0x0C {
        // //         trace!("L_Ackn.ind BSY");
        // //     }
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
                let is_echo = if let Some((message_out, _)) = &self.message_out {
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
                        Ref::from_bytes(&self.message_in.as_ref().unwrap()[..min_header_len]).unwrap();

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
                        Ref::from_bytes(&self.message_in.as_ref().unwrap()[..min_header_len]).unwrap();

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
                // Clear any pending message in and out
                let _ = self.message_in.take();
                let _ = self.message_out.take();

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

    async fn queue_frame_transmission(
        &mut self,
        msg: Buffer<'static>,
        response_tx: DynamicSender<'static, KnxMessageBuffer<Buffer<'static>>>,
    ) {
        // If we're idle and no transmission is pending, start transmission immediately
        if self.state == TpUartState::Idle && self.pending_transmission.is_none() {
            trace!("TP-UART is idle, starting transmission immediately");
            self.transmit_frame(msg, response_tx).await;
            return;
        }

        // If there's already a pending transmission, replace it with this new one
        // This implements a "latest wins" policy to avoid blocking
        if let Some((old_msg, old_response_tx)) = self.pending_transmission.take() {
            warn!("Replacing pending transmission - sending error for previous request");
            let mut error_msg = KnxMessageBuffer::new(old_msg, ServiceType::L_Data_Con);
            error_msg.ctrl_field_mut().set_c(Confirm::Err);
            old_response_tx.send(error_msg).await;
        }

        // Store the new pending transmission
        self.pending_transmission = Some((msg, response_tx));
        trace!("Stored pending transmission (state: {:?})", self.state);
    }

    async fn transmit_frame(
        &mut self,
        msg: Buffer<'static>,
        response_tx: DynamicSender<'static, KnxMessageBuffer<Buffer<'static>>>,
    ) {
        trace!("Transmitting frame ({} bytes): {:?}", msg.len(), msg);

        // Calculate checksum: XOR all bytes in the frame
        let mut checksum = 0u8;
        for &byte in &msg[..] {
            checksum ^= byte;
        }
        // The checksum is XORed with 0xFF so that XORing all bytes including checksum results in 0
        checksum ^= 0xFF;
        let checksum = &[checksum];

        // Store the outgoing message for echo detection and response handling
        self.message_out = Some((msg, response_tx));

        let mut it = self.message_out.as_ref().unwrap().0.iter().chain(checksum).enumerate().peekable();
        while let Some((i, b)) = it.next() {
            let cmd = if it.peek().is_some() {
                [U_L_DATA_START | (i & 0xff) as u8, *b]
            } else {
                [U_L_DATA_END | (i & 0xff) as u8, *b]
            };

            trace!("TPUART TX: {:x?}", &cmd);
            if let Err(_) = self.uart.write_all(&cmd).await {
                // // If write fails, send error confirmation
                // if let Some((mut data, response_tx)) = self.message_out.take() {
                //     data[0] |= 0x01; // Set error flag
                //     let error_msg = KnxMessageBuffer::new(data, ServiceType::L_Data_Con);
                //     response_tx.send(error_msg).await;
                // }
                // return;
                panic!("Failed to write to TP-UART: {:?}", cmd);
            }
        }
    }
}

// IMPORTANT: DEADLOCK PREVENTION
// This implementation prevents deadlocks by ensuring the main event loop never blocks.
// The main loop MUST always be able to poll:
// 1. UART RX future (to read confirmations that complete transmissions)
// 2. Timeout future (to handle state machine timeouts)
// 3. Inbox future (to receive new requests)
//
// We use a simple single-slot pending transmission approach:
// - If link layer is idle and no pending transmission: start immediately
// - If link layer is busy or has pending transmission: replace pending with new request
// - This implements "latest wins" policy and never blocks the main loop
//
// The main loop processes pending transmissions only when idle, ensuring proper coordination.

impl<'a, U> Layer<'a> for TpUartLinkLayer<'a, U>
where
    U: embedded_io_async::Read + embedded_io_async::Write,
{
    type Message = KnxMessageBuffer<Buffer<'static>>;

    async fn process<M>(&mut self, mut inbox: M) -> !
    where
        M: Inbox<LayerOp<Self::Message>>,
    {
        self.initialize().await;

        loop {
            let mut buf = [0u8];

            match select3(Pin::new(&mut self.state_timeout), self.uart.read(&mut buf), inbox.next()).await {
                Either3::First(timeout_state) => {
                    trace!("Timeout timer fired, transitioning to {:?}", timeout_state);
                    self.state_timeout.retry();
                    self.state_transition(timeout_state).await;
                }
                Either3::Second(_) => {
                    trace!("TPUART RX: {:x?}", buf[0]);
                    self.handle_incoming_byte(buf[0]).await;
                }
                Either3::Third(layer_op) => {
                    trace!("TP-UART Link Layer received layer op: {:?}", layer_op);

                    match layer_op {
                        LayerOp::Indication(_msg) => {
                            // Link layer typically doesn't receive indications from upper layers
                            error!("TP-UART Link Layer received unexpected indication");
                        }
                        LayerOp::Request { message: msg, response_tx } => {
                            // Handle transmission requests
                            match msg.service_type() {
                                ServiceType::L_Data_Req => {
                                    self.queue_frame_transmission(msg.into_inner(), response_tx).await;
                                }
                                _ => {
                                    // Return error for unsupported service types
                                    let mut error_msg = msg;
                                    error_msg.ctrl_field_mut().set_c(Confirm::Err);
                                    response_tx.send(error_msg).await;
                                }
                            }
                        }
                    }
                }
            }

            // IMPORTANT: Only check for pending transmissions AFTER handling all other events
            // and only when we're in a safe state to start a new transmission
            if self.state == TpUartState::Idle && self.pending_transmission.is_some() {
                trace!("Starting pending transmission");
                if let Some((msg, response_tx)) = self.pending_transmission.take() {
                    self.transmit_frame(msg, response_tx).await;
                }
            }
        }
    }
}

/// Calculate TP1 checksum for a message (excluding the checksum byte itself)
fn calculate_tp1_checksum(data: &[u8]) -> u8 {
    let mut checksum = 0u8;
    for &byte in data {
        checksum ^= byte;
    }
    checksum
}

/// Validate TP1 checksum for a complete message (including checksum byte)
fn validate_tp1_checksum(data: &[u8]) -> bool {
    if data.is_empty() {
        return false;
    }

    let mut checksum = 0u8;
    for &byte in data {
        checksum ^= byte;
    }
    checksum == 0
}

// Message formats
//
// Standard KNX frame:
//      +--------+-------------------+---------------------+----------------+--------------+-------------------+---------+
//      | Ctrl   | Source Address    | Destination Address | Addr/Hop/Len   | TPCI/APCI    | APDU (Data)       | Chksum  |
//      | Field  | (2 bytes)         | (2 bytes)           | (1 byte)       | (1 byte)     | (1-15 bytes)      | (1 byte)|
//      +--------+-------------------+---------------------+----------------+--------------+-------------------+---------+
//      | 1 byte | 2 bytes           | 2 bytes             | 1 byte         | 1 byte       | 1-15 bytes        | 1 byte  |
//      +--------+-------------------+---------------------+----------------+--------------+-------------------+---------+
//
//      Bit breakdown for Control Field (CTRL):
//        7   6   5   4   3   2   1   0
//      +---+---+---+---+---+---+---+---+
//      |FT | 0 | RF| 1 | PR| PR| 0 | 0 |
//      +---+---+---+---+---+---+---+---+
//      FT  = Frame Type (0: standard, 1: extended)
//      0   = Always 0
//      RF  = Repeat Flag (0: repeat, 1: do not repeat)
//      1   = Always 1
//      PR  = Priority (2 bits: 00 = system, 01 = alarm, 10 = high, 11 = low)
//      0   = Always 0
//
//      Bit breakdown for Addr/Hop/Len byte:
//        7   6   5   4   3   2   1   0
//      +---+---+---+---+---+---+---+---+
//      |AT | HC| HC| HC|LEN|LEN|LEN|LEN|
//      +---+---+---+---+---+---+---+---+
//      AT  = Address Type (0: individual, 1: group)
//      HC  = Hop Count (routing counter, 3 bits)
//      LEN = Length (number of bytes after this field, including TPCI/APCI + APDU, 4 bits, 1–15)
//
//
// Extended KNX TP 1 frame:
//      +--------+--------+-------------------+---------------------+-------------------+-------------------+-------------------+---------+
//      | Ctrl   | Ext    | Source Address    | Destination Address | Length            | TPCI/APCI         | APDU (Data)       | Chksum  |
//      | Field  | Ctrl   | (2 bytes)         | (2 bytes)           | (1 byte)          | (1 byte)          | (1-254 bytes)     | (1 byte)|
//      +--------+--------+-------------------+---------------------+-------------------+-------------------+-------------------+---------+
//      | 1 byte | 1 byte | 2 bytes           | 2 bytes             | 1 byte            | 1 byte            | 1-254 bytes       | 1 byte  |
//      +--------+--------+-------------------+---------------------+-------------------+-------------------+-------------------+---------+
//
//      Bit breakdown for Control Field (CTRL):
//        7   6   5   4   3   2   1   0
//      +---+---+---+---+---+---+---+---+
//      | 1 | 0 | RF| 1 | PR| PR| 0 | 0 |
//      +---+---+---+---+---+---+---+---+
//      1   = Frame Type (1: extended)
//      0   = Always 0
//      RF  = Repeat Flag (0: repeat, 1: do not repeat)
//      1   = Always 1
//      PR  = Priority (2 bits: 00 = system, 01 = alarm, 10 = high, 11 = low)
//      0   = Always 0
//
//      Bit breakdown for Extended Control Field (ECF):
//        7   6   5   4   3   2   1   0
//      +---+---+---+---+---+---+---+---+
//      |AT | HC| HC| HC|EFF|EFF|EFF|EFF|
//      +---+---+---+---+---+---+---+---+
//      AT  = Address Type (0: individual, 1: group)
//      HC  = Hop Count (routing counter, 3 bits)
//      EFF = Extended Frame Format (4 bits, defines fragmentation, etc.)
//
//
// KnxMessageBuffer abstraction:
//      +--------+---------+---------+--------+---------+--------------------+
//      | CTRL   | SRC     | DEST    | AT/HC/ | TPCI    | DATA               |
//      | Field  | Address | Address | EFF    | /APCI   | (variable length)  |
//      +--------+---------+---------+--------+---------+--------------------+
//      | 1 byte | 2 bytes | 2 bytes | 1 byte | 1 byte  | 0..(buffer_size-7) |
//      +--------+---------+---------+--------+---------+--------------------+
//
//      Bit breakdown for CTRL field (Ctrl1Field, byte 0):
//        7   6   5   4   3   2   1   0
//      +---+---+---+---+---+---+---+---+
//      |FT | - | R | SB| PR| PR| A | C |
//      +---+---+---+---+---+---+---+---+
//      FT  = Frame Type (bit 7, 0: standard, 1: extended)
//      -   = (bit 6, unused)
//      R   = Repeat Flag (bit 5)
//      SB  = System Broadcast (bit 4)
//      PR  = Priority (bits 3-2, 2 bits)
//      A   = Acknowledge (bit 1, only valid for L_Data.req)
//      C   = Confirm (bit 0, only valid for L_Data.con)
//
//      Field meanings:
//      - FT: Frame type (standard/extended)
//      - R: Repeat flag
//      - SB: System broadcast
//      - PR: Priority
//      - A: Acknowledge (L_Data.req only)
//      - C: Confirm (L_Data.con only)

fn tp1_to_knx_message<B: MessageBuffer>(mut msg: B) -> B {
    if !validate_tp1_checksum(&msg) {
        // For now, we'll proceed but could add error handling here
        // In a real implementation, this might return an error
    }

    // Remove the checksum byte (last byte)
    let new_len = msg.len() - 1;
    msg.set_len(new_len);

    // Check if this is an extended frame (control field bit 7 == 0)
    if (msg[0] & 0x80) == 0 {
        // Extended frame
        let ext_ctrl = msg[1]; // This is the extended control field in TP1

        // Shift data from position 1 onwards (after control field) to make room
        // We need to move data starting from MSG_DEST_ADDR (3) leftward by 1 position
        let msg_len = msg.len();
        for i in 1..msg_len - 1 {
            msg[i] = msg[i + 1];
        }

        // Place the extended control field at the NPDU position (5)
        msg[5] = ext_ctrl;

        // Remove the last byte as we shifted everything left to get rid of the extended control field
        let new_len = msg.len() - 1;
        msg.set_len(new_len);
    } else {
        // Standard frame - clear lower 4 bits of the NPDU field (EFF type - can't be set in standard frames)
        msg[5] &= 0xf0;
    }

    msg
}

fn knx_to_tp1_message<B: MessageBuffer>(mut msg: B) -> B {
    let len = msg.len();

    // Check for standard frame: length <= 23 and lower 4 bits of NPDU are 0
    if (len < 23) && ((msg[5] & 0xf) == 0) {
        // Standard frame
        msg[5] = (msg[5] & 0xf0) | ((len - 7) as u8);
        msg[0] = (msg[0] & 0x0c) | 0xb0;

        // Generate and append checksum
        msg.push(calculate_tp1_checksum(&msg));

        return msg;
    }

    // Extended frame - need to shift data rightward to make room for extended control
    // Save the original NPDU value before shifting
    let orig_npdu = msg[5];

    // Shift data from index 1 onwards rightward by 1 position
    msg.set_len(len + 1);
    for i in (1..len).rev() {
        msg[i + 1] = msg[i];
    }

    // Set up extended frame fields
    msg[0] = (msg[0] & 0x0C) | 0x30;
    msg[1] = orig_npdu; // Extended control field: AT/HC/EFF from original NPDU
    msg[6] = (len - 7) as u8; // Length field for extended frame

    // Generate and append checksum
    msg.push(calculate_tp1_checksum(&msg));

    msg
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::ops::{Deref, DerefMut};

    #[derive(Debug)]
    struct TestBuffer {
        data: Vec<u8>,
    }

    impl TestBuffer {
        fn new(data: &[u8]) -> Self {
            Self { data: data.to_vec() }
        }
    }

    impl MessageBuffer for TestBuffer {
        fn len(&self) -> usize {
            self.data.len()
        }

        fn set_len(&mut self, len: usize) {
            self.data.resize(len, 0);
        }

        fn capacity(&self) -> usize {
            self.data.capacity()
        }

        fn resize(&mut self, new_len: usize, fill_value: u8) {
            self.data.resize(new_len, fill_value)
        }
    }

    impl Deref for TestBuffer {
        type Target = [u8];

        fn deref(&self) -> &Self::Target {
            &self.data
        }
    }

    impl DerefMut for TestBuffer {
        fn deref_mut(&mut self) -> &mut Self::Target {
            &mut self.data
        }
    }

    #[test]
    fn test_checksum_calculation() {
        // Test checksum calculation
        let data = [0xBC, 0x11, 0x22, 0x11, 0x01, 0xE1, 0x00, 0x81u8];
        let checksum = calculate_tp1_checksum(&data);

        // Verify that XOR of all bytes including checksum equals 0
        let mut verify = data.into_iter().reduce(|a, b| a ^ b).unwrap();
        verify ^= checksum;
        assert_eq!(verify, 0, "Checksum verification failed");
    }

    #[test]
    fn test_checksum_validation() {
        let valid_data = &[0xBC, 0x11, 0x22, 0x11, 0x01, 0xE1, 0x00, 0x81, 0xFF]; // 0xFF is correct checksum
        assert!(validate_tp1_checksum(valid_data), "Valid checksum should pass");

        let invalid_data = &[0xBC, 0x11, 0x22, 0x11, 0x01, 0xE1, 0x00, 0x81, 0x00]; // Wrong checksum
        assert!(!validate_tp1_checksum(invalid_data), "Invalid checksum should fail");

        assert!(!validate_tp1_checksum(&[]), "Empty data should fail");
    }

    #[test]
    fn test_tp1_to_knx_standard_frame() {
        // Standard TP1 frame: GroupValue.Write to 1/1/1 with data 0x01
        // Control=0xBC (standard frame, bit 7=1), Source=1.1.34, Dest=1/1/1, NPDU+data
        let tp1_data = &[
            0xBC, // Control byte: 10111100 (standard frame, priority 3, no repeat, system broadcast)
            0x11, 0x22, // Source address: 1.1.34
            0x11, 0x01, // Destination address: 1/1/1 (group address)
            0xE1, // NPDU: 11100001 (hop count 7, group address)
            0x00, 0x81, // TPCI/APCI + Data: GroupValue.Write with data 0x01
            0xFF, // Checksum
        ];

        let buffer = TestBuffer::new(tp1_data);
        let result = tp1_to_knx_message(buffer);

        assert_eq!(result.len(), 8, "Frame length");
        assert_eq!(result[0], 0xBC, "Control field should be preserved");
        assert_eq!(result[1], 0x11, "Source address high byte");
        assert_eq!(result[2], 0x22, "Source address low byte");
        assert_eq!(result[3], 0x11, "Destination address high byte");
        assert_eq!(result[4], 0x01, "Destination address low byte");
        assert_eq!(result[5], 0xE0, "NPDU should have EFF bits cleared");
        assert_eq!(result[6], 0x00, "TPCI/APCI data");
        assert_eq!(result[7], 0x81, "Application data");
    }

    #[test]
    fn test_tp1_to_knx_extended_frame() {
        // Extended TP1 frame: PropertyValue.Read
        // Control=0x1C (extended frame, bit 7=0), ExtCtrl=0xE0, Source=1.1.34, etc.
        let tp1_data = &[
            0x1C, // Control byte: 00011100 (extended frame, priority 3)
            0xE0, // Extended control field
            0x11, 0x22, // Source address: 1.1.34
            0x00, 0x00, // Destination address: 0.0.0 (individual)
            0x60, // NPDU: 01100000 (hop count 3, individual address)
            0x43, 0xD2, // TPCI/APCI: PropertyValue.Read
            0x00, 0x51, // Additional data
            0x90, // Checksum
        ];

        let buffer = TestBuffer::new(tp1_data);
        let result = tp1_to_knx_message(buffer);

        assert_eq!(result.len(), 10, "Frame length");
        assert_eq!(result[0], 0x1C, "Control field preserved");
        assert_eq!(result[1], 0x11, "Source addr high");
        assert_eq!(result[2], 0x22, "Source addr low");
        assert_eq!(result[3], 0x00, "Dest addr high");
        assert_eq!(result[4], 0x00, "Dest addr low");
        assert_eq!(result[5], 0xE0, "Extended control");
        assert_eq!(result[6], 0x43, "TPCI data");
        assert_eq!(result[7], 0xD2, "APCI data");
        assert_eq!(result[8], 0x00, "Additional data");
        assert_eq!(result[9], 0x51, "Additional data 2");
    }

    #[test]
    fn test_knx_to_tp1_standard_frame() {
        // KNX standard frame: GroupValue.Write to 1/1/1
        let knx_data = &[
            0xBC, // Control: standard frame
            0x11, 0x22, // Source: 1.1.34
            0x11, 0x01, // Dest: 1/1/1
            0xE0, // NPDU (lower 4 bits are 0 - indicates standard frame)
            0x00, 0x81, // TPCI/APCI + data
        ];

        let buffer = TestBuffer::new(knx_data);
        let result = knx_to_tp1_message(buffer);

        assert_eq!(result.len(), 9, "Frame length");
        assert_eq!(result[0], 0xBC, "Control field preserved");
        assert_eq!(result[1], 0x11, "Source address high");
        assert_eq!(result[2], 0x22, "Source address low");
        assert_eq!(result[3], 0x11, "Destination address high");
        assert_eq!(result[4], 0x01, "Destination address low");
        assert_eq!(result[5], 0xE1, "NPDU: 0xE1");
        assert_eq!(result[6], 0x00, "TPCI data");
        assert_eq!(result[7], 0x81, "Application data");
        assert_eq!(result[8], 0xFF, "Checksum");
    }

    #[test]
    fn test_knx_to_tp1_extended_frame() {
        // KNX extended frame: PropertyValue.Read (longer frame or NPDU lower bits != 0)
        let knx_data = &[
            0x1C, // Control: extended frame
            0x11, 0x22, // Source: 1.1.34
            0x00, 0x00, // Dest: individual
            0x61, // NPDU: lower 4 bits = 1 (triggers extended frame)
            0x43, 0xD2, // TPCI/APCI
            0x00, 0x51, // Additional data
            0x8E,
        ];

        let buffer = TestBuffer::new(knx_data);
        let result = knx_to_tp1_message(buffer);

        assert_eq!(result.len(), 13, "Frame length");
        assert_eq!(result[0], 0x3C, "Control field");
        assert_eq!(result[1], 0x61, "Extended control");
        assert_eq!(result[2], 0x11, "Source high");
        assert_eq!(result[3], 0x22, "Source low");
        assert_eq!(result[4], 0x00, "Dest high");
        assert_eq!(result[5], 0x00, "Dest low");
        assert_eq!(result[6], 0x04, "APDU Length");
        assert_eq!(result[7], 0x43, "Original TPCI");
        assert_eq!(result[8], 0xD2, "Original APCI");
        assert_eq!(result[9], 0x00, "Additional data");
        assert_eq!(result[10], 0x51, "Additional data");
        assert_eq!(result[11], 0x8E, "Checksum");
    }

    #[test]
    fn test_round_trip_standard_frame() {
        // Test that TP1 -> KNX -> TP1 produces the original frame
        let original_tp1 = &[
            0xBC, // Control
            0x11, 0x22, // Source
            0x11, 0x01, // Dest
            0xE1, // NPDU
            0x00, 0x81, // Data
            0xFF, // Checksum
        ];

        let buffer1 = TestBuffer::new(original_tp1);
        let knx_msg = tp1_to_knx_message(buffer1);

        // Create new buffer for return conversion
        let buffer2 = TestBuffer::new(&knx_msg);
        let final_tp1 = knx_to_tp1_message(buffer2);

        // The round trip should be equal
        assert_eq!(&final_tp1[..], &original_tp1[..]);
    }

    #[test]
    fn test_knx_to_tp1_length_boundary_23_bytes_standard() {
        // 22-byte KNX message with EFF = 0 → should be standard TP1
        let knx_data = &[
            0xBC, // Control
            0x11, 0x22, // Source
            0x11, 0x01, // Dest
            0xE0, // NPDU: EFF = 0
            0x00, 0x81, // TPCI/APCI
            // 14 more bytes to reach exactly 22 bytes
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E,
        ];

        let buffer = TestBuffer::new(knx_data);
        let result = knx_to_tp1_message(buffer);

        // Should remain standard frame: len=23 < 24 AND EFF = 0
        assert_eq!(result.len(), 23, "Frame length");
        assert_eq!(result[0], 0xBC, "Control field");
        assert_eq!(result[5], 0xEF, "NPDU");
    }

    #[test]
    fn test_knx_to_tp1_length_boundary_24_bytes_extended() {
        // 23-byte KNX message with EFF = 0 → should be extended TP1
        let knx_data = &[
            0xBC, // Control
            0x11, 0x22, // Source
            0x11, 0x01, // Dest
            0xE0, // NPDU: lower 4 bits = 0, but length >= 24 triggers extended
            0x00, 0x81, // TPCI/APCI
            // 15 more bytes (triggers extended frame format)
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
        ];

        let buffer = TestBuffer::new(knx_data);
        let result = knx_to_tp1_message(buffer);

        assert_eq!(result.len(), 25, "Frame length");
        assert_eq!(result[0], 0x3C, "Control field");
        assert_eq!(result[1], 0xE0, "Extended control field");
        assert_eq!(result[6], 0x10, "APDU length");
    }

    #[test]
    fn test_knx_to_tp1_npdu_lower_bits_boundary() {
        // Short KNX message but EFF != 0 → should be extended TP1
        let knx_data = &[
            0xBC, // Control
            0x11, 0x22, // Source
            0x11, 0x01, // Dest
            0xE1, // NPDU: EFF = 1 (forces extended frame)
            0x00, 0x81, // TPCI/APCI
        ];

        let buffer = TestBuffer::new(knx_data);
        let result = knx_to_tp1_message(buffer);

        assert_eq!(result.len(), 10, "Frame length");
        assert_eq!(result[0], 0x3C, "Control field");
        assert_eq!(result[1], 0xE1, "Extended control field");
        assert_eq!(result[6], 0x01, "APDU Length");
    }

    #[test]
    fn test_round_trip_format_change_standard_to_extended() {
        // Start with TP1 standard frame, convert to KNX, then back to TP1
        // The return trip might change format due to boundary conditions
        let original_tp1 = &[
            0xBC, // Control: standard frame
            0x11, 0x22, // Source
            0x11, 0x01, // Dest
            0xE1, // NPDU
            0x00, 0x81, // Data
            0,    // Checksum
        ];

        // TP1 → KNX: standard frame, NPDU gets cleared to 0xE0
        let buffer1 = TestBuffer::new(original_tp1);
        let knx_msg = tp1_to_knx_message(buffer1);
        assert_eq!(knx_msg[5], 0xE0, "TP1→KNX: NPDU EFF = 0");

        // KNX → TP1: short length + NPDU EFF = 0 → stays standard
        let buffer2 = TestBuffer::new(&knx_msg);
        let final_tp1 = knx_to_tp1_message(buffer2);

        assert_eq!(final_tp1.len(), original_tp1.len(), "Round trip standard→standard");
        assert_eq!(final_tp1[0], 0xBC, "Control preserved in standard format");
        assert_eq!(final_tp1[5], 0xE1, "NPDU: length info=1");
    }

    #[test]
    fn test_round_trip_format_change_extended_to_standard() {
        // Start with TP1 extended frame that becomes standard after conversion
        let original_tp1 = &[
            0x1C, // Control: extended frame
            0xE0, // Extended control: 0xE0
            0x11, 0x22, // Source
            0x11, 0x01, // Dest
            0x01, // Length
            0x00, 0x81, // TPCI/APCI + data
            0xA3, // Checksum
        ];

        // TP1 → KNX: extended frame processing
        let buffer1 = TestBuffer::new(original_tp1);
        let knx_msg = tp1_to_knx_message(buffer1);

        assert_eq!(knx_msg.len(), 8, "Frame length");
        assert_eq!(knx_msg[5], 0xE0, "Extended control");

        // KNX → TP1: len=9 < 24 AND NPDU=0x00 (EFF = 0) → becomes standard!
        let buffer2 = TestBuffer::new(&knx_msg);
        let final_tp1 = knx_to_tp1_message(buffer2);

        assert_eq!(final_tp1[0], 0xBC, "Control field for standard frame = 0xBC");
        assert_eq!(final_tp1[5], 0xE1, "Length field = 0x01");
    }

    #[test]
    fn test_length_calculation_edge_cases() {
        let knx_8_bytes = &[0xBC, 0x11, 0x22, 0x11, 0x01, 0xE0, 0x00, 0x81];
        let buffer = TestBuffer::new(knx_8_bytes);
        let result = knx_to_tp1_message(buffer);
        assert_eq!(result[5], 0xE1, "8 bytes: NPDU = 0xE1 | 1 = 0xE1");

        let knx_9_bytes = &[0xBC, 0x11, 0x22, 0x11, 0x01, 0xE0, 0x00, 0x81, 0xFF];
        let buffer = TestBuffer::new(knx_9_bytes);
        let result = knx_to_tp1_message(buffer);
        assert_eq!(result[5], 0xE2, "9 bytes: NPDU = 0xE2 | 2 = 0xE2");

        let knx_15_bytes = &[0xBC, 0x11, 0x22, 0x11, 0x01, 0xE0, 0x00, 0x81, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07];
        let buffer = TestBuffer::new(knx_15_bytes);
        let result = knx_to_tp1_message(buffer);
        assert_eq!(result[5], 0xE8, "15 bytes: NPDU = 0xE0 | 8 = 0xE8");

        let knx_23_bytes = &[
            0xBC, 0x11, 0x22, 0x11, 0x01, 0xE0, 0x00, 0x81, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A,
            0x0B, 0x0C, 0x0D, 0x0E,
        ];
        let buffer = TestBuffer::new(knx_23_bytes);
        let result = knx_to_tp1_message(buffer);
        assert_eq!(result[5], 0xEF, "23 bytes: NPDU = 0xE0 | 15 = 0xEF");
    }

    #[test]
    fn test_npdu_preservation_in_extended_frames() {
        for npdu_val in [0xE1, 0xE2, 0xE5, 0xEA, 0xEF] {
            let knx_data = &[
                0x1C, // Control: will trigger extended due to NPDU EFF field
                0x11, 0x22, // Source
                0x11, 0x01,     // Dest
                npdu_val, // NPDU with EFF bits != 0
                0x43, 0xD2, // TPCI/APCI
                0x00, 0x51, // Extra data
            ];

            let buffer = TestBuffer::new(knx_data);
            let result = knx_to_tp1_message(buffer);

            // Should be extended frame due to EFF != 0
            assert_eq!(result.len(), 12, "NPDU 0x{:02X}: becomes extended frame", npdu_val);
            assert_eq!(result[0], 0x3C, "NPDU 0x{:02X}: extended control field", npdu_val);
            assert_eq!(result[6], 0x03, "NPDU 0x{:02X}: Length = 3", npdu_val);
        }
    }
}
