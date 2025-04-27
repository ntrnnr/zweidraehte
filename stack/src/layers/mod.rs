use crate::address::GroupAddress as KNXGroupAddress;

/// Service primitives for KNX application layer
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ServicePrimitive<T = ()> {
    /// Indication from the network layer (incoming message)
    Indication(T),
    /// Confirmation from the network layer (response to a request)
    Confirmation(T, bool), // T, success
    /// Response to send back to the network layer
    Response(T),
}

/// Application layer service for KNX group communication
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GroupValueService<T = ()> {
    /// A_GroupValue_Read service
    Read {
        /// Group address being read
        group_address: KNXGroupAddress,
    },
    /// A_GroupValue_Response service
    Response {
        /// Group address being responded to
        group_address: KNXGroupAddress,
        /// Value being sent
        value: T,
    },
    /// A_GroupValue_Write service
    Write {
        /// Group address being written to
        group_address: KNXGroupAddress,
        /// Value being sent
        value: T,
    },
}
