//! Access control types for KNX authorization.
//!
//! This module provides the 4-level authorization model used by KNX devices:
//! - Level 0: Maximum access (system-level)
//! - Level 3: Minimum access (everyone)
//!
//! The transport layer tracks per-connection levels in [`ConnectionAuthLevels`],
//! while [`AccessSource`] tags messages with where to look up the effective level.

use core::cell::Cell;

/// Number of authorization access levels supported (0-3).
pub const MAX_ACCESS_LEVELS: usize = 4;

/// Number of settable authorization keys (levels 0-2).
/// Level 3 is "access for everyone" and has no key - it's what you get when auth fails.
pub const NUM_AUTH_KEYS: usize = 3;

// ============================================================================
// Access Context
// ============================================================================

/// Authorization context for a service request.
///
/// Bundles all access-related state needed to evaluate policies.
/// Currently contains only the legacy 4-level access level.
/// Will be extended for KNX Secure with security mode, role, etc.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct AccessContext {
    /// Legacy access level (0 = max access, 3 = min access).
    pub access_level: u8,
    // Future KNX Secure fields:
    // pub security_mode: bool,
    // pub security_ctrl: SecurityControl,
}

impl AccessContext {
    /// Create a new access context with the given legacy access level.
    pub const fn new(access_level: u8) -> Self {
        Self { access_level }
    }

    /// Check whether this context has at least the given access level.
    ///
    /// In KNX, lower number = more access. Returns true if
    /// `self.access_level <= required`.
    pub const fn has_level(&self, required: u8) -> bool {
        self.access_level <= required
    }

    /// Minimum-access context (level 3, no special privileges).
    pub const MIN_ACCESS: Self = Self { access_level: 3 };

    /// Maximum-access context (level 0, full system access).
    pub const MAX_ACCESS: Self = Self { access_level: 0 };
}

// ============================================================================
// Access Source
// ============================================================================

/// Describes where to look up the access level for a message.
///
/// Messages flowing through the stack carry this tag so the application layer
/// knows how to resolve the effective [`AccessContext`]:
///
/// - **Connectionless** messages (broadcast, group, individual-unaddressed)
///   use the default access level from [`StackState::default_access_level()`](crate::StackState::default_access_level).
/// - **Connection-oriented** messages reference a slot in the shared
///   [`ConnectionAuthLevels`] where the transport layer maintains the
///   current authorization level per connection.
/// - **Explicit** is for special paths (e.g. KNX/IP Device Management) that
///   bypass the transport layer and need to stamp a fixed access level.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum AccessSource {
    /// Connectionless — use the default access level.
    Default,
    /// Connection-oriented — look up from shared store by slot index.
    Connection(u8),
    /// Explicit access context (e.g. KNX/IP device management).
    Explicit(AccessContext),
}

// ============================================================================
// Connection Access Store
// ============================================================================

/// Per-connection access level store.
///
/// Sized by the total number of transport-layer connections
/// (`TL_MAX_INCOMING + TL_MAX_OUTGOING`) and owned by the device state type.
/// The transport and application layers access it through the
/// [`HasConnectionAuth`] trait, which hides the const generic `N`.
///
/// The slot index matches the connection table: slot 0 is the first incoming
/// connection, etc.  On connect the TL resets the slot to the default level;
/// on authorize the AL writes the granted level directly.
///
/// Single-threaded (embassy `NoopRawMutex`), so [`Cell`] is safe.
pub struct ConnectionAuthLevels<const N: usize> {
    levels: [Cell<AccessContext>; N],
}

impl<const N: usize> ConnectionAuthLevels<N> {
    pub const fn new() -> Self {
        Self { levels: [const { Cell::new(AccessContext::MIN_ACCESS) }; N] }
    }

    /// Read the access context for a connection slot.
    pub fn get(&self, slot: u8) -> AccessContext {
        self.levels[slot as usize].get()
    }

    /// Write the access context for a connection slot.
    pub fn set(&self, slot: u8, ctx: AccessContext) {
        self.levels[slot as usize].set(ctx);
    }

    /// Reset a slot back to the given default level.
    pub fn reset(&self, slot: u8, default_level: u8) {
        self.levels[slot as usize].set(AccessContext::new(default_level));
    }
}

impl<const N: usize> Default for ConnectionAuthLevels<N> {
    fn default() -> Self {
        Self::new()
    }
}

/// Trait for state types that contain a [`ConnectionAuthLevels`].
///
/// Provides slot-level access to per-connection authorization levels.
/// The const generic `N` on [`ConnectionAuthLevels`] is hidden behind
/// these methods so that layers don't need to carry the generic.
///
/// The transport layer resets slot levels on connect/disconnect; the
/// application layer reads and writes them on authorize and access checks.
pub trait HasConnectionAuth {
    /// Read the access context for a connection slot.
    fn connection_access(&self, slot: u8) -> AccessContext;

    /// Write the access context for a connection slot.
    fn set_connection_access(&self, slot: u8, ctx: AccessContext);

    /// Reset a slot back to the given default level.
    fn reset_connection_access(&self, slot: u8, default_level: u8);
}
