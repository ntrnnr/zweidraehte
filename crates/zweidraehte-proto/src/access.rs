//! Access control types for KNX authorization.
//!
//! This module provides two coexisting access control mechanisms:
//!
//! ## Legacy Authorization (A_Authorize)
//! The 4-level model (levels 0-3) with 4-byte keys:
//! - Level 0: Maximum access (system manufacturer)
//! - Level 1: Product manufacturer
//! - Level 2: ETS configuration
//! - Level 3: Minimum access (runtime, everyone)
//!
//! ## KNX Data Secure Access Policies
//! Per-property permission matrices encoding access rights across:
//! - **Security Mode**: Off (plain) / On (secure communication required)
//! - **Client type**: Unlisted / Role Rx / Tool
//! - **Security level**: None / Authentication / Authentication+Confidentiality
//! - **Direction**: Read / Write
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
// Security Types (KNX Data Secure)
// ============================================================================

/// Security protection level of an incoming message.
///
/// Determined by the Secure Application Layer (S-AL) before the message
/// reaches the plain Application Layer. When Data Secure is not in use,
/// all messages are [`Plain`](SecurityMode::Plain).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum SecurityMode {
    /// No S-AL protection — plain (unencrypted, unauthenticated) communication.
    Plain,
    /// S-AL authentication only (MAC verified, data not encrypted).
    AuthOnly,
    /// S-AL authentication + confidentiality (MAC verified, data encrypted).
    AuthConf,
}

impl Default for SecurityMode {
    fn default() -> Self {
        Self::Plain
    }
}

/// Client classification for access policy evaluation.
///
/// Determined by looking up the sender's Individual Address in the
/// Point-to-point Key Table (for secure links) or assigning "Unlisted"
/// for plain communication.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum ClientRole {
    /// Not in the P2P Key Table — plain communication or unknown sender.
    Unlisted,
    /// Secure link with assigned roles. The `u16` is a bitmask of R0-R15
    /// from the P2P Key Table entry for this sender.
    Roles(u16),
    /// Tool Key access — the sender used the Tool Key with T-flag set in SCF.
    Tool,
}

impl Default for ClientRole {
    fn default() -> Self {
        Self::Unlisted
    }
}

// ============================================================================
// Access Context
// ============================================================================

/// Authorization context for a service request.
///
/// Bundles all access-related state needed to evaluate both legacy access
/// levels and KNX Data Secure access policies. The security fields default
/// to `Plain`/`Unlisted`, preserving backward compatibility with code that
/// only uses the legacy access level.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct AccessContext {
    /// Legacy access level (0 = max access, 3 = min access).
    pub access_level: u8,
    /// Security protection level of the incoming message.
    pub security: SecurityMode,
    /// Client classification (Unlisted / Roles / Tool).
    pub role: ClientRole,
}

impl AccessContext {
    /// Create a new access context with the given legacy access level.
    ///
    /// Security defaults to `Plain` and role to `Unlisted`.
    pub const fn new(access_level: u8) -> Self {
        Self {
            access_level,
            security: SecurityMode::Plain,
            role: ClientRole::Unlisted,
        }
    }

    /// Create a full access context with all fields.
    pub const fn with_security(access_level: u8, security: SecurityMode, role: ClientRole) -> Self {
        Self { access_level, security, role }
    }

    /// Check whether this context has at least the given access level.
    ///
    /// In KNX, lower number = more access. Returns true if
    /// `self.access_level <= required`.
    pub const fn has_level(&self, required: u8) -> bool {
        self.access_level <= required
    }

    /// Minimum-access context (level 3, no special privileges).
    pub const MIN_ACCESS: Self = Self {
        access_level: 3,
        security: SecurityMode::Plain,
        role: ClientRole::Unlisted,
    };

    /// Maximum-access context (level 0, full system access).
    pub const MAX_ACCESS: Self = Self {
        access_level: 0,
        security: SecurityMode::Plain,
        role: ClientRole::Unlisted,
    };
}

// ============================================================================
// Access Policy (KNX Data Secure)
// ============================================================================

/// Per-property access policy from KNX spec 03/04/01, section 6.2.
///
/// Encodes a 20-bit permission matrix across Security Mode (Off/On),
/// Client type (Unlisted/RoleX/Tool), Security level (none/A+C/A),
/// and direction (Write/Read).
///
/// The spec notation `sec_off_hex / sec_on_hex` maps each half to a
/// 10-bit value. Within each 10-bit value, bits are arranged as W/R
/// pairs for each (client, security) combination:
///
/// ```text
/// Bit:  9  8 | 7  6 | 5  4 | 3  2 | 1  0
///       W  R | W  R | W  R | W  R | W  R
///       Unlisted   RoleX    RoleX   Tool    Tool
///       none       A+C      A       A+C     A
/// ```
///
/// # Legacy Compatibility
///
/// When Data Secure is not active, all messages are `Plain`/`Unlisted`,
/// which checks bits 9/8 (Unlisted/none W/R) of the `sec_off` half.
/// Standard policies like `3FF` have these bits set, so legacy behavior
/// is preserved — plain unlisted clients can always read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct AccessPolicy {
    /// 10-bit permissions when device Security Mode is Off (plain allowed).
    pub sec_off: u16,
    /// 10-bit permissions when device Security Mode is On (secure required).
    pub sec_on: u16,
}

impl AccessPolicy {
    /// Create a new access policy with the given permission masks.
    ///
    /// Arguments match the spec notation: `AccessPolicy::new(sec_off, sec_on)`
    /// maps to the spec's `sec_off_hex / sec_on_hex`.
    pub const fn new(sec_off: u16, sec_on: u16) -> Self {
        Self { sec_off, sec_on }
    }

    /// Check if read access is permitted for the given context.
    pub const fn can_read(&self, ctx: &AccessContext, device_security_on: bool) -> bool {
        let mask = if device_security_on { self.sec_on } else { self.sec_off };
        let bit_offset = Self::column_offset(ctx);
        // Read is the even bit (lower) in each W/R pair
        mask & (1 << bit_offset) != 0
    }

    /// Check if write access is permitted for the given context.
    pub const fn can_write(&self, ctx: &AccessContext, device_security_on: bool) -> bool {
        let mask = if device_security_on { self.sec_on } else { self.sec_off };
        let bit_offset = Self::column_offset(ctx);
        // Write is the odd bit (upper) in each W/R pair
        mask & (1 << (bit_offset + 1)) != 0
    }

    /// Get the bit offset for the Read bit of the relevant column.
    ///
    /// Returns the position of the R bit; the W bit is at offset+1.
    ///
    /// ```text
    /// Bits 9,8: Unlisted/none (W,R)
    /// Bits 7,6: RoleX/A+C (W,R)
    /// Bits 5,4: RoleX/A (W,R)
    /// Bits 3,2: Tool/A+C (W,R)
    /// Bits 1,0: Tool/A (W,R)
    /// ```
    const fn column_offset(ctx: &AccessContext) -> u32 {
        match ctx.role {
            ClientRole::Unlisted => 8, // Unlisted/none R bit
            ClientRole::Roles(_) => {
                match ctx.security {
                    SecurityMode::AuthConf => 6, // RoleX/A+C R bit
                    SecurityMode::AuthOnly => 4, // RoleX/A R bit
                    // Role client in plain → treated as Unlisted
                    SecurityMode::Plain => 8,
                }
            }
            ClientRole::Tool => {
                match ctx.security {
                    SecurityMode::AuthConf => 2, // Tool/A+C R bit
                    SecurityMode::AuthOnly => 0, // Tool/A R bit
                    // Tool in plain → treated as Unlisted
                    SecurityMode::Plain => 8,
                }
            }
        }
    }

    // ========================================================================
    // Standard Access Policy Constants (from KNX spec 03/04/01, Tables 3/6)
    // ========================================================================

    /// `3FF / 1FF` — All read+write when sec off; sec on: unlisted read-only,
    /// roles + tool full access.
    pub const OPEN: Self = Self::new(0x3FF, 0x1FF);

    /// `3FF / 0CC` — Everyone reads; only Tool writes.
    /// The most common policy for configuration properties.
    pub const READ_OPEN_WRITE_TOOL: Self = Self::new(0x3FF, 0x0CC);

    /// `15F / 04C` — Sec off: unlisted read-only, roles+tool read+write.
    /// Sec on: roles+tool read+write, unlisted no access.
    /// Used for security-sensitive config like load state, security mode.
    pub const RESTRICTED: Self = Self::new(0x15F, 0x04C);

    /// `155 / 155` — Role x (A) + Tool (A) read+write, both security modes.
    pub const ROLE_AND_TOOL_AUTH: Self = Self::new(0x155, 0x155);

    /// `008 / 008` — Only Tool with Authentication+Confidentiality write access.
    /// Used for keys, device authentication code, password hashes.
    pub const TOOL_ONLY_CONFIDENTIAL: Self = Self::new(0x008, 0x008);

    /// `00C / 00C` — Only Tool (A+C or A), both security modes.
    /// Used for P2P key table, group key table.
    pub const TOOL_ONLY: Self = Self::new(0x00C, 0x00C);

    /// `3FF / 000` — Everyone can read+write when sec off; no access when sec on.
    /// Used for master reset (erase code 03h) — only local or plain access.
    pub const READ_ONLY_NO_REMOTE_WRITE: Self = Self::new(0x3FF, 0x000);

    /// `2AA / 008` — Read with auth roles; write only Tool A+C.
    pub const READ_AUTH_WRITE_TOOL_CONF: Self = Self::new(0x2AA, 0x008);

    /// `00C / 008` — Only Tool can read (A+C or A), only Tool A+C can write.
    /// Used for sequence number sending.
    pub const TOOL_READ_TOOL_CONF_WRITE: Self = Self::new(0x00C, 0x008);
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

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // Verify our bit layout matches the spec by checking raw bit patterns.
    // 0x3FF = 0b_11_1111_1111 = all 10 bits set (all W and R for all columns)
    // 0x1FF = 0b_01_1111_1111 = bits 8..0 set, bit 9 clear
    //   → Unlisted W (bit 9) is clear, Unlisted R (bit 8) is set
    // 0x0CC = 0b_00_1100_1100 = bits 7,6,3,2
    //   → RoleX A+C W+R (7,6) and Tool A+C W+R (3,2)

    #[test]
    fn access_policy_open_allows_unlisted_plain() {
        // 3FF / 1FF: sec off = 0x3FF, all bits set
        let ctx = AccessContext::new(3); // Plain, Unlisted
        assert!(AccessPolicy::OPEN.can_read(&ctx, false));  // bit 8 of 0x3FF
        assert!(AccessPolicy::OPEN.can_write(&ctx, false)); // bit 9 of 0x3FF
    }

    #[test]
    fn access_policy_open_sec_on_unlisted_read_only() {
        // 3FF / 1FF: sec on = 0x1FF, bit 9 clear, bit 8 set
        let ctx = AccessContext::new(3); // Plain, Unlisted
        assert!(AccessPolicy::OPEN.can_read(&ctx, true));   // bit 8 of 0x1FF = 1
        assert!(!AccessPolicy::OPEN.can_write(&ctx, true));  // bit 9 of 0x1FF = 0
    }

    #[test]
    fn access_policy_read_open_write_tool() {
        // 3FF / 0CC
        let unlisted = AccessContext::new(3);
        // Sec off (0x3FF): unlisted can read+write (bits 9,8 both set)
        assert!(AccessPolicy::READ_OPEN_WRITE_TOOL.can_read(&unlisted, false));
        assert!(AccessPolicy::READ_OPEN_WRITE_TOOL.can_write(&unlisted, false));

        // Sec on (0x0CC): unlisted cannot read or write (bits 9,8 both clear)
        assert!(!AccessPolicy::READ_OPEN_WRITE_TOOL.can_read(&unlisted, true));
        assert!(!AccessPolicy::READ_OPEN_WRITE_TOOL.can_write(&unlisted, true));

        // Sec on (0x0CC = 0b_00_1100_1100): Tool A+C can read+write (bits 3,2 set)
        let tool_ac = AccessContext::with_security(0, SecurityMode::AuthConf, ClientRole::Tool);
        assert!(AccessPolicy::READ_OPEN_WRITE_TOOL.can_read(&tool_ac, true));
        assert!(AccessPolicy::READ_OPEN_WRITE_TOOL.can_write(&tool_ac, true));

        // Tool A cannot (bits 1,0 clear in 0x0CC)
        let tool_a = AccessContext::with_security(0, SecurityMode::AuthOnly, ClientRole::Tool);
        assert!(!AccessPolicy::READ_OPEN_WRITE_TOOL.can_read(&tool_a, true));
        assert!(!AccessPolicy::READ_OPEN_WRITE_TOOL.can_write(&tool_a, true));
    }

    #[test]
    fn access_policy_tool_only_confidential() {
        // 008 / 008 = 0b_00_0000_1000: only bit 3 set (Tool/A+C Write)
        let unlisted = AccessContext::new(3);
        assert!(!AccessPolicy::TOOL_ONLY_CONFIDENTIAL.can_read(&unlisted, false));
        assert!(!AccessPolicy::TOOL_ONLY_CONFIDENTIAL.can_write(&unlisted, false));
        assert!(!AccessPolicy::TOOL_ONLY_CONFIDENTIAL.can_read(&unlisted, true));
        assert!(!AccessPolicy::TOOL_ONLY_CONFIDENTIAL.can_write(&unlisted, true));

        // Tool with AuthOnly: bits 1,0 → both clear in 0x008
        let tool_a = AccessContext::with_security(0, SecurityMode::AuthOnly, ClientRole::Tool);
        assert!(!AccessPolicy::TOOL_ONLY_CONFIDENTIAL.can_read(&tool_a, false));
        assert!(!AccessPolicy::TOOL_ONLY_CONFIDENTIAL.can_write(&tool_a, false));

        // Tool with A+C: bit 3 (W) set, bit 2 (R) clear → write-only!
        let tool_ac = AccessContext::with_security(0, SecurityMode::AuthConf, ClientRole::Tool);
        assert!(!AccessPolicy::TOOL_ONLY_CONFIDENTIAL.can_read(&tool_ac, false));
        assert!(AccessPolicy::TOOL_ONLY_CONFIDENTIAL.can_write(&tool_ac, false));
        assert!(!AccessPolicy::TOOL_ONLY_CONFIDENTIAL.can_read(&tool_ac, true));
        assert!(AccessPolicy::TOOL_ONLY_CONFIDENTIAL.can_write(&tool_ac, true));
    }

    #[test]
    fn access_policy_restricted() {
        // 15F / 04C
        // 0x15F = 0b_01_0101_1111
        //   Unlisted: bits 9=0(W), 8=1(R) → read only
        //   RoleX A+C: bits 7=0(W), 6=1(R) → read only
        //   RoleX A: bits 5=1(W), 4=1(R) → read+write
        //   Tool A+C: bits 3=1(W), 2=1(R) → read+write
        //   Tool A: bits 1=1(W), 0=1(R) → read+write
        let unlisted = AccessContext::new(3);
        assert!(AccessPolicy::RESTRICTED.can_read(&unlisted, false));
        assert!(!AccessPolicy::RESTRICTED.can_write(&unlisted, false));

        // Sec on (0x04C = 0b_00_0100_1100):
        //   Unlisted: 0,0 → no access
        //   RoleX A+C: 0,1 → read only? Wait 0x04C = 0b_00_0100_1100
        //   bits 7=0,6=1 → RoleX A+C read only
        //   bits 3=1,2=0 → Tool A+C write only
        assert!(!AccessPolicy::RESTRICTED.can_read(&unlisted, true));
        assert!(!AccessPolicy::RESTRICTED.can_write(&unlisted, true));

        // Role x with A, sec off: bits 5=0(W), 4=1(R) of 0x15F → read only
        let role_a = AccessContext::with_security(2, SecurityMode::AuthOnly, ClientRole::Roles(0x01));
        assert!(AccessPolicy::RESTRICTED.can_read(&role_a, false));
        assert!(!AccessPolicy::RESTRICTED.can_write(&role_a, false));

        // Tool A+C, sec off: bits 3=1(W), 2=1(R) of 0x15F → read+write
        let tool_ac = AccessContext::with_security(0, SecurityMode::AuthConf, ClientRole::Tool);
        assert!(AccessPolicy::RESTRICTED.can_read(&tool_ac, false));
        assert!(AccessPolicy::RESTRICTED.can_write(&tool_ac, false));
    }

    #[test]
    fn access_policy_no_remote_write_sec_on() {
        // 3FF / 000 — sec on: no access at all
        let tool = AccessContext::with_security(0, SecurityMode::AuthConf, ClientRole::Tool);
        // Sec off: all access
        assert!(AccessPolicy::READ_ONLY_NO_REMOTE_WRITE.can_read(&tool, false));
        assert!(AccessPolicy::READ_ONLY_NO_REMOTE_WRITE.can_write(&tool, false));
        // Sec on: no access
        assert!(!AccessPolicy::READ_ONLY_NO_REMOTE_WRITE.can_read(&tool, true));
        assert!(!AccessPolicy::READ_ONLY_NO_REMOTE_WRITE.can_write(&tool, true));
    }

    #[test]
    fn access_policy_tool_only() {
        // 00C / 00C = 0b_00_0000_1100: bits 3,2 set (Tool A+C W+R)
        let tool_ac = AccessContext::with_security(0, SecurityMode::AuthConf, ClientRole::Tool);
        let tool_a = AccessContext::with_security(0, SecurityMode::AuthOnly, ClientRole::Tool);
        let role = AccessContext::with_security(0, SecurityMode::AuthConf, ClientRole::Roles(0x01));

        // Tool A+C: bits 3,2 set → read+write
        assert!(AccessPolicy::TOOL_ONLY.can_read(&tool_ac, true));
        assert!(AccessPolicy::TOOL_ONLY.can_write(&tool_ac, true));
        assert!(AccessPolicy::TOOL_ONLY.can_read(&tool_ac, false));
        assert!(AccessPolicy::TOOL_ONLY.can_write(&tool_ac, false));

        // Tool A: bits 1,0 clear in 0x00C → no access
        assert!(!AccessPolicy::TOOL_ONLY.can_read(&tool_a, true));
        assert!(!AccessPolicy::TOOL_ONLY.can_write(&tool_a, true));

        // Role: no
        assert!(!AccessPolicy::TOOL_ONLY.can_read(&role, true));
        assert!(!AccessPolicy::TOOL_ONLY.can_write(&role, true));
    }

    #[test]
    fn legacy_context_backward_compat() {
        let ctx = AccessContext::new(2);
        assert!(ctx.has_level(2));
        assert!(ctx.has_level(3));
        assert!(!ctx.has_level(1));

        // Plain/Unlisted with sec off: checks bits 9,8 of sec_off mask
        // 3FF has both set → read+write allowed
        assert!(AccessPolicy::OPEN.can_read(&ctx, false));
        assert!(AccessPolicy::OPEN.can_write(&ctx, false));
        // READ_OPEN_WRITE_TOOL (3FF/0CC): sec off also 0x3FF → read+write
        assert!(AccessPolicy::READ_OPEN_WRITE_TOOL.can_read(&ctx, false));
        assert!(AccessPolicy::READ_OPEN_WRITE_TOOL.can_write(&ctx, false));
    }
}
