//! Group-object RAM flags — the one byte of communication state each
//! group object keeps in RAM (03/05/01 §4.18.4, RT2 realization).
//!
//! The flags live wherever the group object table's RAM-flags pointer
//! says, one byte per object, and are the application's entire
//! interface to group communication: the stack sets the update flag
//! when a value arrives, the application sets the transmit-request
//! state to send. Both sides poll; nothing blocks.
//!
//! Bit layout (low nibble is the spec's "communication flags"):
//!
//! ```text
//! bits 1..0  transmission status: 0 idle/ok, 1 idle/error,
//!            2 transmitting, 3 transmit request
//! bit  2     data request (a read request is pending / was received)
//! bit  3     update (a value was written by the bus)
//! bit  4     value changed on last bus update
//! bit  5     value valid (some value has been sent or received)
//! bits 7..6  free for the application
//! ```

pub const TX_STATE_MASK: u8 = 0x03;
pub const TX_IDLE_OK: u8 = 0x00;
pub const TX_IDLE_ERROR: u8 = 0x01;
pub const TX_TRANSMITTING: u8 = 0x02;
pub const TX_REQUEST: u8 = 0x03;

pub const READ_REQUEST: u8 = 0x04;
pub const UPDATE: u8 = 0x08;
pub const VALUE_CHANGED: u8 = 0x10;
pub const VALUE_VALID: u8 = 0x20;

/// Set the transmission status bits, leaving the rest untouched.
pub fn set_tx_state(flags: u8, state: u8) -> u8 {
    (flags & !TX_STATE_MASK) | (state & TX_STATE_MASK)
}

pub fn tx_state(flags: u8) -> u8 {
    flags & TX_STATE_MASK
}
