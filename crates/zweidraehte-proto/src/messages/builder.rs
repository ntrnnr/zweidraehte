//! Type-safe message builder with compile-time guarantees
//!
//! This module provides a zero-cost abstraction for building KNX messages with:
//! - Compile-time direction safety (Indication vs Request)
//! - Automatic context preservation from incoming messages
//! - Layer-specific builders (Network, Transport, Application)
//! - Prevention of common bugs (sending Indication instead of Request)
//!
//! # Design
//!
//! The builder uses the typestate pattern to track:
//! 1. **Direction**: Whether the message is an Indication (going UP) or Request (going DOWN)
//! 2. **State**: What layer context has been set (Network, Transport, Application)
//!
//! This ensures at compile time that:
//! - Responses preserve priority/addressing from requests
//! - You can't accidentally send an Indication when you meant a Request
//! - All required fields are set before building the message
//!
//! # Examples
//!
//! ```ignore
//! // Respond to an indication with application data
//! let msg = MessageBuilder::respond_to(buffer, &incoming_indication)
//!     .with_application(ApciCode::DeviceDescriptorResponse)
//!     .with_data(|data| {
//!         data[offsets::MSG_APCI + 2..offsets::MSG_APCI + 4]
//!             .copy_from_slice(&mask_version);
//!     });
//! transport_layer.request(msg).await;
//!
//! // Send a transport control PDU
//! let ack = MessageBuilder::new_request(
//!         buffer,
//!         ServiceType::N_Data_Req,
//!         Priority::System,
//!         DestinationAddress::Individual(dest)
//!     )
//!     .with_transport_control(Tpci::Ack(seq_no))
//!     .build();
//! network_layer.request(ack).await;
//! ```

use core::marker::PhantomData;
use core::ops::{Deref, DerefMut};

use crate::messages::knx::{
    ApciCode, DestinationAddress, KnxMessageBuffer, Priority, RequiredSecurity, ServiceType, Tpci,
};

// ============================================================================
// Direction Type States
// ============================================================================

/// Type-level marker for message direction
pub mod direction {
    /// Message flowing UP the stack (Link → Network → Transport → Application)
    /// These are indications of received data.
    pub struct Indication;

    /// Message flowing DOWN the stack (Application → Transport → Network → Link)
    /// These are requests to send data.
    pub struct Request;

    /// Confirmation message sent in response to a request.
    /// Reuses the original request's buffer with modified service type and confirm flag.
    pub struct Confirmation;
}

// ============================================================================
// Typed Message Wrapper
// ============================================================================

/// A message typed by its direction (Indication, Request, or Confirmation)
///
/// This wrapper carries the message direction in the type system, enabling
/// compile-time enforcement that:
/// - Indication channels only accept `IndicationMessage`
/// - Request channels only accept `RequestMessage`
/// - Confirmation channels only accept `ConfirmationMessage`
///
/// Uses `Deref`/`DerefMut` for ergonomic transparent access to the inner
/// `KnxMessageBuffer`, so you can call methods directly without unwrapping.
pub struct TypedMessage<B: Deref<Target = [u8]>, Dir> {
    inner: KnxMessageBuffer<B>,
    _direction: PhantomData<Dir>,
}

/// A message indicating data received from the bus (flows UP the stack)
pub type IndicationMessage<B> = TypedMessage<B, direction::Indication>;

/// A message requesting an action (flows DOWN the stack)
pub type RequestMessage<B> = TypedMessage<B, direction::Request>;

/// A confirmation message in response to a request
pub type ConfirmationMessage<B> = TypedMessage<B, direction::Confirmation>;

// ----------------------------------------------------------------------------
// TypedMessage: Core Implementation
// ----------------------------------------------------------------------------

impl<B: Deref<Target = [u8]>, Dir> TypedMessage<B, Dir> {
    /// Consume the wrapper and return the inner `KnxMessageBuffer`
    ///
    /// Use this when you need to pass the message to an API that consumes it,
    /// such as `.confirm()` or `.error()`.
    pub fn into_inner(self) -> KnxMessageBuffer<B> {
        self.inner
    }
}

impl<B: Deref<Target = [u8]>, Dir> Deref for TypedMessage<B, Dir> {
    type Target = KnxMessageBuffer<B>;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl<B: Deref<Target = [u8]> + DerefMut, Dir> DerefMut for TypedMessage<B, Dir> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.inner
    }
}

impl<B: Deref<Target = [u8]> + core::fmt::Debug, Dir> core::fmt::Debug for TypedMessage<B, Dir> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        self.inner.fmt(f)
    }
}

#[cfg(feature = "defmt")]
impl<B: Deref<Target = [u8]>, Dir> defmt::Format for TypedMessage<B, Dir> {
    fn format(&self, f: defmt::Formatter) {
        defmt::write!(f, "{}", self.inner)
    }
}

// ----------------------------------------------------------------------------
// IndicationMessage: Creation
// ----------------------------------------------------------------------------

impl<B: Deref<Target = [u8]>> IndicationMessage<B> {
    /// Create an indication message from a received `KnxMessageBuffer`
    ///
    /// Used by link layers when they receive data from the bus and need
    /// to pass it up to the network layer.
    pub fn indication(msg: KnxMessageBuffer<B>) -> Self {
        TypedMessage { inner: msg, _direction: PhantomData }
    }
}

// ----------------------------------------------------------------------------
// RequestMessage: Creation
// ----------------------------------------------------------------------------

impl<B: Deref<Target = [u8]>> RequestMessage<B> {
    /// Create a request message from a `KnxMessageBuffer`
    ///
    /// Used when building requests that will flow down the stack.
    pub fn request(msg: KnxMessageBuffer<B>) -> Self {
        TypedMessage { inner: msg, _direction: PhantomData }
    }
}

// ----------------------------------------------------------------------------
// ConfirmationMessage: Creation
// ----------------------------------------------------------------------------

impl<B: Deref<Target = [u8]>> ConfirmationMessage<B> {
    /// Create a confirmation message from a `KnxMessageBuffer`
    ///
    /// Used when building confirmations to return via `response_tx`.
    pub fn confirmation(msg: KnxMessageBuffer<B>) -> Self {
        TypedMessage { inner: msg, _direction: PhantomData }
    }
}

// ============================================================================
// Layer State Types
// ============================================================================

/// Type-level marker for builder state progression
pub mod state {
    use super::*;
    use crate::messages::knx::Confirm;

    /// Freshly allocated buffer with no context set
    pub struct Allocated;

    /// Network layer context for a request
    pub struct NetworkRequest {
        pub service_type: ServiceType,
        pub priority: Priority,
        pub dest: DestinationAddress,
        /// Required security level applied to the finalised message.
        ///
        /// Defaults to [`RequiredSecurity::Unspecified`]. Producers chain
        /// `.with_required_security(level)` to stamp an explicit policy
        /// (e.g. Auth/AuthConf for spontaneous secure GO writes, or Plain
        /// for spontaneous broadcasts that are plaintext by spec).
        pub required_security: RequiredSecurity,
        /// Whether the finalised message must be encrypted with the tool
        /// key. Orthogonal to `required_security` — selects the key,
        /// not the algorithm. Inherited from indications by `respond_to`
        /// so reactive responses to tool-access requests carry it
        /// automatically.
        pub tool_access_required: bool,
        /// TL outgoing sequence number. Carried so `respond_to` can
        /// propagate the indication's TL seqnr onto the response, where
        /// the S-AL's CCM B0 construction uses it. `None` for new
        /// (non-reactive) requests.
        pub outgoing_tl_seq: Option<u8>,
    }

    /// Transport layer context for a request
    pub struct TransportRequest {
        pub network: NetworkRequest,
        pub tpci: Tpci,
    }

    /// Application layer context for a request
    pub struct ApplicationRequest {
        pub network: NetworkRequest,
        pub apci: ApciCode,
    }

    /// Confirmation ready to be built.
    /// The service type will be converted from _Req to _Con and the confirm flag set.
    pub struct ConfirmationReady {
        pub service_type: ServiceType,
        pub confirm: Confirm,
    }
}

// ============================================================================
// Message Builder
// ============================================================================

/// Type-safe message builder
///
/// Generic parameters:
/// - `B`: Buffer type (`Buffer<'static>` in the device stack, `Vec<u8>` in clients)
/// - `Dir`: Direction (Indication or Request)
/// - `State`: Current builder state (Allocated, NetworkRequest, etc.)
pub struct MessageBuilder<B, Dir, State> {
    buffer: B,
    _direction: PhantomData<Dir>,
    state: State,
}

// ============================================================================
// Starting Points: Creating Builders
// ============================================================================

impl<B: Deref<Target = [u8]> + DerefMut> MessageBuilder<B, direction::Request, state::Allocated> {
    /// Create a Request by responding to an Indication
    ///
    /// This automatically extracts:
    /// - Priority from the incoming message
    /// - Source address (becomes destination for response)
    /// - Appropriate response service type
    ///
    /// The indication buffer type `I` is independent of the output buffer type
    /// `B` — the builder only reads from the indication to extract context.
    ///
    /// # Example
    /// ```ignore
    /// let msg = MessageBuilder::respond_to(buffer, &indication)
    ///     .with_application(ApciCode::DeviceDescriptorResponse)
    ///     .build();
    /// ```
    pub fn respond_to<I: Deref<Target = [u8]>>(
        buffer: B,
        indication: &KnxMessageBuffer<I>,
    ) -> MessageBuilder<B, direction::Request, state::NetworkRequest> {
        let service_type = indication_to_request_service(indication.service_type());

        MessageBuilder {
            buffer,
            _direction: PhantomData,
            state: state::NetworkRequest {
                service_type,
                priority: indication.ctrl_field().priority(),
                dest: DestinationAddress::Individual(indication.get_source_addr()),
                // Inherit the security context from the indication so
                // reactive responses encrypt with the same parameters
                // the request used. The S-AL stamps these on incoming
                // secure indications during `try_process_secure`; for
                // plain incoming frames they stay at the defaults
                // (`Unspecified` + `false`) and the response goes plain.
                required_security: indication.required_security(),
                tool_access_required: indication.tool_access_required(),
                outgoing_tl_seq: indication.outgoing_tl_seq(),
            },
        }
    }

    /// Create a new Request from scratch (not responding to anything)
    ///
    /// Used for initiating communication:
    /// - Establishing connections
    /// - Unsolicited writes
    /// - Periodic transmissions
    ///
    /// # Example
    /// ```ignore
    /// let msg = MessageBuilder::new_request(
    ///         buffer,
    ///         ServiceType::N_Data_Req,
    ///         Priority::System,
    ///         DestinationAddress::Individual(dest)
    ///     )
    ///     .with_transport_control(Tpci::Connect)
    ///     .build();
    /// network_layer.request(ack).await;
    /// ```
    pub fn new_request(
        buffer: B,
        service_type: ServiceType,
        priority: Priority,
        dest: DestinationAddress,
    ) -> MessageBuilder<B, direction::Request, state::NetworkRequest> {
        MessageBuilder {
            buffer,
            _direction: PhantomData,
            state: state::NetworkRequest {
                service_type,
                priority,
                dest,
                required_security: RequiredSecurity::Unspecified,
                tool_access_required: false,
                outgoing_tl_seq: None,
            },
        }
    }
}

/// Convert an indication service type to its corresponding request type.
fn indication_to_request_service(ind_service: ServiceType) -> ServiceType {
    match ind_service {
        // Network layer
        ServiceType::N_Data_Ind => ServiceType::N_Data_Req,
        ServiceType::N_GroupData_Ind => ServiceType::N_GroupData_Req,
        ServiceType::N_Broadcast_Ind => ServiceType::N_Broadcast_Req,
        ServiceType::N_SystemBroadcast_Ind => ServiceType::N_SystemBroadcast_Req,

        // Transport layer
        ServiceType::T_Data_Ind => ServiceType::T_Data_Req,
        ServiceType::T_DataUnack_Ind => ServiceType::T_DataUnack_Req,
        ServiceType::T_GroupData_Ind => ServiceType::T_GroupData_Req,
        ServiceType::T_Broadcast_Ind => ServiceType::T_Broadcast_Req,
        ServiceType::T_SystemBroadcast_Ind => ServiceType::T_SystemBroadcast_Req,

        // If already a request, keep it (shouldn't happen, but safe)
        ServiceType::N_Data_Req
        | ServiceType::N_GroupData_Req
        | ServiceType::N_Broadcast_Req
        | ServiceType::N_SystemBroadcast_Req
        | ServiceType::T_Data_Req
        | ServiceType::T_DataUnack_Req
        | ServiceType::T_GroupData_Req
        | ServiceType::T_Broadcast_Req
        | ServiceType::T_SystemBroadcast_Req => ind_service,

        // Default fallback for other types
        _ => ServiceType::N_Data_Req,
    }
}

// ============================================================================
// Network Layer: Request Building
// ============================================================================

impl<B: Deref<Target = [u8]> + DerefMut> MessageBuilder<B, direction::Request, state::NetworkRequest> {
    /// Annotate the outbound message with a required security level.
    ///
    /// Stamped onto the finalised [`KnxMessageBuffer`] so the Secure
    /// Application Layer can apply the §5.5.3.x decision tree at outbox
    /// drain. Use [`RequiredSecurity::Auth`] / [`AuthConf`] for
    /// spontaneous secure paths (e.g. group writes that originate from
    /// a GO whose `PID_GO_SECURITY_FLAGS` requires security), and
    /// [`RequiredSecurity::Plain`] for spontaneous outputs that are
    /// plaintext by spec (e.g. `A_NetworkParameter_InfoReport` security
    /// reports per 03/05/01 §6.3.11.4).
    ///
    /// Reactive-response call sites built via [`MessageBuilder::respond_to`]
    /// inherit their stamp from the indication automatically and do not
    /// need to chain this — even when the framing differs from a normal
    /// `1.x.y → src` reply. Override the service type and destination
    /// via [`Self::with_service_type`] / [`Self::with_destination`]
    /// while keeping the inherited security context.
    ///
    /// Spontaneous (non-reactive) sites stamp explicitly:
    /// [`RequiredSecurity::Auth`] / [`AuthConf`] for paths that must
    /// encrypt (e.g. group writes from a GO whose
    /// `PID_GO_SECURITY_FLAGS` requires security), or
    /// [`RequiredSecurity::Plain`] for outputs the spec mandates as
    /// plain (e.g. `A_NetworkParameter_InfoReport` security reports
    /// per 03/05/01 §6.3.11.4).
    ///
    /// [`AuthConf`]: RequiredSecurity::AuthConf
    pub fn with_required_security(mut self, level: RequiredSecurity) -> Self {
        self.state.required_security = level;
        self
    }

    /// Stamp the tool-access requirement on the finalised message.
    ///
    /// Selects whether the S-AL drain path encrypts with the tool key
    /// (`true`) or with a destination-derived key (`false`). Reactive
    /// responses inherit this from the indication via `respond_to`;
    /// spontaneous tool-access sends chain `.with_tool_access(true)`.
    pub fn with_tool_access(mut self, tool_access: bool) -> Self {
        self.state.tool_access_required = tool_access;
        self
    }

    /// Override the service type carried by the finalised message.
    ///
    /// `respond_to` derives the service type from the indication
    /// (e.g. `T_Data_Ind` → `T_Data_Req`). For reactive responses
    /// whose framing differs — broadcast `IndividualAddressResponse`
    /// answering a `T_Broadcast_Ind` via `T_Broadcast_Req`,
    /// system-broadcast serial reads, etc. — chain this to override
    /// while still inheriting the security context
    /// (`required_security`, `tool_access_required`, `outgoing_tl_seq`).
    /// A bare `new_request` call would lose those stamps and risk
    /// emitting plaintext when a secure response was expected.
    pub fn with_service_type(mut self, service_type: ServiceType) -> Self {
        self.state.service_type = service_type;
        self
    }

    /// Override the destination address.
    ///
    /// Same rationale as [`Self::with_service_type`]: lets a reactive
    /// response retarget (e.g. broadcast back to `0x0000` rather than
    /// to the requester's IA) without losing the inherited security
    /// stamps from the indication.
    pub fn with_destination(mut self, dest: DestinationAddress) -> Self {
        self.state.dest = dest;
        self
    }

    /// Build a network-layer message (no transport/application layer)
    ///
    /// This is used when you only need network layer context.
    /// Returns a `RequestMessage` for sending through request channels.
    pub fn build(self) -> RequestMessage<B> {
        let mut msg = KnxMessageBuffer::new(self.buffer, self.state.service_type);
        msg.ctrl_field_mut().set_priority(self.state.priority);
        msg.set_dest_addr(self.state.dest);
        msg.set_required_security(self.state.required_security);
        msg.set_tool_access_required(self.state.tool_access_required);
        if let Some(seq) = self.state.outgoing_tl_seq {
            msg.set_outgoing_tl_seq(seq);
        }
        RequestMessage::request(msg)
    }

    /// Add transport layer control PDU
    ///
    /// Used for transport control messages:
    /// - T_Connect
    /// - T_Disconnect
    /// - T_ACK
    /// - T_NACK
    ///
    /// # Example
    /// ```ignore
    /// let ack = builder
    ///     .with_transport_control(Tpci::Ack(seq_no))
    ///     .build();
    /// ```
    pub fn with_transport_control(self, tpci: Tpci) -> MessageBuilder<B, direction::Request, state::TransportRequest> {
        MessageBuilder {
            buffer: self.buffer,
            _direction: PhantomData,
            state: state::TransportRequest { network: self.state, tpci },
        }
    }

    /// Add application layer context
    ///
    /// Used for application-layer messages like:
    /// - DeviceDescriptorRead/Response
    /// - PropertyRead/Write
    /// - Memory operations
    ///
    /// The transport service type is inherited from the network context
    /// (set by `new_request` or derived from the indication in `respond_to`).
    ///
    /// # Example
    /// ```ignore
    /// let response = builder
    ///     .with_application(ApciCode::DeviceDescriptorResponse)
    ///     .with_data(|data| { /* write application data */ });
    /// ```
    pub fn with_application(self, apci: ApciCode) -> MessageBuilder<B, direction::Request, state::ApplicationRequest> {
        MessageBuilder {
            buffer: self.buffer,
            _direction: PhantomData,
            state: state::ApplicationRequest { network: self.state, apci },
        }
    }
}

// ============================================================================
// Transport Layer: Request Building
// ============================================================================

impl<B: Deref<Target = [u8]> + DerefMut> MessageBuilder<B, direction::Request, state::TransportRequest> {
    /// Build a transport control PDU
    ///
    /// This finalizes the message with transport layer context (ACK, NACK, Connect, Disconnect).
    /// Returns a `RequestMessage` for sending through request channels.
    pub fn build(self) -> RequestMessage<B> {
        let mut msg = KnxMessageBuffer::new(self.buffer, self.state.network.service_type);
        msg.ctrl_field_mut().set_priority(self.state.network.priority);
        msg.set_dest_addr(self.state.network.dest);
        msg.set_tpci(self.state.tpci);
        msg.set_required_security(self.state.network.required_security);
        msg.set_tool_access_required(self.state.network.tool_access_required);
        if let Some(seq) = self.state.network.outgoing_tl_seq {
            msg.set_outgoing_tl_seq(seq);
        }
        RequestMessage::request(msg)
    }
}

// ============================================================================
// Application Layer: Request Building
// ============================================================================

impl<B: Deref<Target = [u8]> + DerefMut> MessageBuilder<B, direction::Request, state::ApplicationRequest> {
    /// Build an application message with custom data writer
    ///
    /// The writer function receives mutable access to the buffer to write
    /// application-specific data (descriptor type, property values, etc.).
    /// Returns a `RequestMessage` for sending through request channels.
    ///
    /// # Example
    /// ```ignore
    /// let msg = builder.with_data(|data| {
    ///     // Set descriptor type to 0
    ///     data[offsets::MSG_APCI + 1] &= 0xC0;
    ///     // Copy mask version
    ///     data[offsets::MSG_APCI + 2..offsets::MSG_APCI + 4]
    ///         .copy_from_slice(&mask_version);
    /// });
    /// ```
    pub fn with_data<F>(self, writer: F) -> RequestMessage<B>
    where
        F: FnOnce(&mut [u8]),
    {
        let mut msg = KnxMessageBuffer::new(self.buffer, self.state.network.service_type);

        // Apply network context
        msg.ctrl_field_mut().set_priority(self.state.network.priority);
        msg.set_dest_addr(self.state.network.dest);

        // Let caller write application-specific data first, then set APCI code.
        // Order matters for short APCI codes (GroupValue*, Adc*, Memory*, etc.):
        // set_apci_code merges APCI bits into the upper bits of MSG_APCI+1,
        // preserving the lower 6 data bits. If APCI were set first, a raw
        // copy_from_slice in the writer would clobber the APCI bits.
        writer(msg.buf_mut());
        msg.set_apci_code(self.state.apci);
        msg.set_required_security(self.state.network.required_security);
        msg.set_tool_access_required(self.state.network.tool_access_required);
        if let Some(seq) = self.state.network.outgoing_tl_seq {
            msg.set_outgoing_tl_seq(seq);
        }

        RequestMessage::request(msg)
    }

    /// Build an application message without additional data
    ///
    /// Used when the APCI code is sufficient (e.g., simple read requests).
    /// Returns a `RequestMessage` for sending through request channels.
    pub fn build(self) -> RequestMessage<B> {
        self.with_data(|_| {})
    }
}

// ============================================================================
// Convenience Extensions
// ============================================================================

/// Extension trait for cleaner API when responding to indications.
///
/// Generic over the output buffer type `B`, so the same indication can
/// produce a response backed by any buffer type.
pub trait IndicationExt<B: Deref<Target = [u8]> + DerefMut> {
    /// Start building a response to this indication
    ///
    /// # Example
    /// ```ignore
    /// let response = indication.respond_with(buffer)
    ///     .with_application(ApciCode::DeviceDescriptorResponse)
    ///     .build();
    /// ```
    fn respond_with(&self, buffer: B) -> MessageBuilder<B, direction::Request, state::NetworkRequest>;
}

impl<I: Deref<Target = [u8]>, B: Deref<Target = [u8]> + DerefMut> IndicationExt<B> for KnxMessageBuffer<I> {
    fn respond_with(&self, buffer: B) -> MessageBuilder<B, direction::Request, state::NetworkRequest> {
        MessageBuilder::respond_to(buffer, self)
    }
}

// ============================================================================
// Confirmation Building
// ============================================================================

use crate::messages::knx::Confirm;

/// Extension trait for converting request messages to confirmations.
///
/// This provides a type-safe way to build confirmation messages that:
/// - Automatically converts service types (T_Data_Req → T_Data_Con)
/// - Sets the appropriate Confirm flag (NoError or Err)
/// - Reuses the original request's buffer (zero-copy)
///
/// # Example
/// ```ignore
/// use crate::messages::builder::ConfirmationExt;
///
/// async fn handle_request(&mut self, msg: KnxMessageBuffer<...>) -> KnxMessageBuffer<...> {
///     match process(&msg) {
///         Ok(_) => msg.confirm().build(),
///         Err(_) => msg.error().build(),
///     }
/// }
/// ```
pub trait ConfirmationExt<B: Deref<Target = [u8]>> {
    /// Convert this request message into a successful confirmation.
    ///
    /// Sets `Confirm::NoError` and converts service type (e.g., T_Data_Req → T_Data_Con).
    fn confirm(self) -> MessageBuilder<B, direction::Confirmation, state::ConfirmationReady>;

    /// Convert this request message into an error confirmation.
    ///
    /// Sets `Confirm::Err` and converts service type (e.g., T_Data_Req → T_Data_Con).
    fn error(self) -> MessageBuilder<B, direction::Confirmation, state::ConfirmationReady>;
}

impl<B: Deref<Target = [u8]>> ConfirmationExt<B> for KnxMessageBuffer<B> {
    fn confirm(self) -> MessageBuilder<B, direction::Confirmation, state::ConfirmationReady> {
        let (buffer, service_type) = self.into_parts();
        MessageBuilder {
            buffer,
            _direction: PhantomData,
            state: state::ConfirmationReady { service_type, confirm: Confirm::NoError },
        }
    }

    fn error(self) -> MessageBuilder<B, direction::Confirmation, state::ConfirmationReady> {
        let (buffer, service_type) = self.into_parts();
        MessageBuilder {
            buffer,
            _direction: PhantomData,
            state: state::ConfirmationReady { service_type, confirm: Confirm::Err },
        }
    }
}

// ============================================================================
// Confirmation Builder Implementation
// ============================================================================

impl<B: Deref<Target = [u8]> + DerefMut> MessageBuilder<B, direction::Confirmation, state::ConfirmationReady> {
    /// Build the confirmation message.
    ///
    /// This finalizes the confirmation by:
    /// - Converting the service type from _Req to _Con
    /// - Setting the Confirm flag (NoError or Err)
    ///
    /// Returns a `ConfirmationMessage` which can only be sent via `response_tx`.
    pub fn build(self) -> ConfirmationMessage<B> {
        let mut msg = KnxMessageBuffer::new(self.buffer, self.state.service_type.to_confirmation());
        msg.ctrl_field_mut().set_c(self.state.confirm);
        ConfirmationMessage::confirmation(msg)
    }
}
