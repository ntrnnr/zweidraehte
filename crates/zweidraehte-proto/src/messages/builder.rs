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
//!     .with_application(ApciCode::DeviceDescriptorResponse, ServiceType::T_Data_Req)
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

use crate::messages::knx::{ApciCode, DestinationAddress, KnxMessageBuffer, Priority, ServiceType, Tpci};

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
    }

    /// Transport layer context for a request
    pub struct TransportRequest {
        pub network: NetworkRequest,
        pub tpci: Tpci,
    }

    /// Application layer context for a request
    pub struct ApplicationRequest {
        pub network: NetworkRequest,
        pub transport_service: ServiceType,
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
    ///     .with_application(ApciCode::DeviceDescriptorResponse, ServiceType::T_Data_Req)
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
            state: state::NetworkRequest { service_type, priority, dest },
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

        // If already a request, keep it (shouldn't happen, but safe)
        ServiceType::N_Data_Req
        | ServiceType::N_GroupData_Req
        | ServiceType::N_Broadcast_Req
        | ServiceType::N_SystemBroadcast_Req
        | ServiceType::T_Data_Req
        | ServiceType::T_DataUnack_Req
        | ServiceType::T_GroupData_Req => ind_service,

        // Default fallback for other types
        _ => ServiceType::N_Data_Req,
    }
}

// ============================================================================
// Network Layer: Request Building
// ============================================================================

impl<B: Deref<Target = [u8]> + DerefMut> MessageBuilder<B, direction::Request, state::NetworkRequest> {
    /// Build a network-layer message (no transport/application layer)
    ///
    /// This is used when you only need network layer context.
    /// Returns a `RequestMessage` for sending through request channels.
    pub fn build(self) -> RequestMessage<B> {
        let mut msg = KnxMessageBuffer::new(self.buffer, self.state.service_type);
        msg.ctrl_field_mut().set_priority(self.state.priority);
        msg.set_dest_addr(self.state.dest);
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
    pub fn with_transport_control(
        self,
        tpci: Tpci,
    ) -> MessageBuilder<B, direction::Request, state::TransportRequest> {
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
    /// # Parameters
    /// - `apci`: Application layer service code
    /// - `transport_service`: Transport service type (T_Data_Req, T_DataUnack_Req, etc.)
    ///
    /// # Example
    /// ```ignore
    /// let response = builder
    ///     .with_application(ApciCode::DeviceDescriptorResponse, ServiceType::T_Data_Req)
    ///     .with_data(|data| { /* write application data */ });
    /// ```
    pub fn with_application(
        self,
        apci: ApciCode,
        transport_service: ServiceType,
    ) -> MessageBuilder<B, direction::Request, state::ApplicationRequest> {
        MessageBuilder {
            buffer: self.buffer,
            _direction: PhantomData,
            state: state::ApplicationRequest { network: self.state, transport_service, apci },
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
        let mut msg = KnxMessageBuffer::new(self.buffer, self.state.transport_service);

        // Apply network context
        msg.ctrl_field_mut().set_priority(self.state.network.priority);
        msg.set_dest_addr(self.state.network.dest);

        // Apply application context
        msg.set_apci_code(self.state.apci);

        // Let caller write application-specific data
        writer(msg.buf_mut());

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
    ///     .with_application(ApciCode::DeviceDescriptorResponse, ServiceType::T_Data_Req)
    ///     .build();
    /// ```
    fn respond_with(
        &self,
        buffer: B,
    ) -> MessageBuilder<B, direction::Request, state::NetworkRequest>;
}

impl<I: Deref<Target = [u8]>, B: Deref<Target = [u8]> + DerefMut> IndicationExt<B> for KnxMessageBuffer<I> {
    fn respond_with(
        &self,
        buffer: B,
    ) -> MessageBuilder<B, direction::Request, state::NetworkRequest> {
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
