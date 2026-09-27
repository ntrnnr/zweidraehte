//! What the specification grants, written independently of the code
//! under test.
//!
//! Two access-control models apply to every property:
//!
//! - **Legacy access levels** (03/04/01 §4.3.2.2, 06 Profiles Annex A): a
//!   request at level `L` may read when `L <= read level` and write when
//!   `L <= write level`. Levels are stated as audiences (03/04/01 Table 1),
//!   because a 16-level profile resolves the free audience to 15.
//! - **Access Policies** (03/04/01 §6.2, AN193): ten permission bits for
//!   Security Mode off and ten for Security Mode on, written as two hex
//!   numbers such as `3FF/0CC`.
//!
//! Secured requests carry legacy level 0 (the Secure Application Layer
//! grants the whole decision to the policy), so only plain requests
//! exercise the levels.

use zweidraehte_proto::access::{AccessContext, ClientRole, SecurityMode};

// ============================================================================
// Audiences and property kinds
// ============================================================================

/// An access-level audience (03/04/01 §4.3.2.2 Table 1).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Audience {
    /// Unrestricted: level 3 of 4, level 15 of 16.
    Free,
    /// End-user adjustable, level 3 in both models.
    Controller,
    /// ETS configuration, level 2.
    Configuration,
    /// DevEdit/TransApp, level 1.
    ProductManufacturer,
    /// Level 0.
    SystemManufacturer,
}

impl Audience {
    pub const fn level(self, max_levels: u8) -> u8 {
        match self {
            Self::Free => max_levels - 1,
            Self::Controller => 3,
            Self::Configuration => 2,
            Self::ProductManufacturer => 1,
            Self::SystemManufacturer => 0,
        }
    }
}

/// How a property's value is reached.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    /// Data property, read-only.
    ReadOnly,
    /// Data property, readable and writable.
    ReadWrite,
    /// Data property, write-only.
    WriteOnly,
    /// PDT_FUNCTION: reached only through the function-property services
    /// (03/04/01 §4.4.2.1 Table 2); a data-property service is refused.
    Function,
}

// ============================================================================
// Access Policies, decoded from the spec's notation
// ============================================================================

/// One side of an Access Policy, in the notation of 03/04/01 §6.2 Table 3:
/// ten bits, most significant first, in five W/R column pairs — Unlisted
/// (no security), Role A+C, Role A, Tool A+C, Tool A.
#[derive(Clone, Copy, Debug)]
pub struct Policy {
    pub off: u16,
    pub on: u16,
}

/// Parse `"3FF/0CC"`.
pub fn policy(notation: &str) -> Policy {
    let (off, on) = notation.split_once('/').expect("notation is off/on");
    let parse = |half: &str| u16::from_str_radix(half.trim(), 16).expect("hex policy half");
    Policy { off: parse(off), on: parse(on) }
}

/// The column a caller falls in. The Roles and the Tool are only told apart
/// when authenticated; a plain request is Unlisted (03/04/01 §6.2.3).
fn column(caller: &Caller) -> u32 {
    // Column index counted from the most significant pair.
    match (caller.role, caller.security) {
        (_, SecurityMode::Plain) | (ClientRole::Unlisted, _) => 0,
        (ClientRole::Roles(_), SecurityMode::AuthConf) => 1,
        (ClientRole::Roles(_), SecurityMode::AuthOnly) => 2,
        (ClientRole::Tool, SecurityMode::AuthConf) => 3,
        (ClientRole::Tool, SecurityMode::AuthOnly) => 4,
    }
}

impl Policy {
    fn bit(&self, caller: &Caller, security_mode: bool, write: bool) -> bool {
        let half = if security_mode { self.on } else { self.off };
        // Pair `c` occupies bits 9-2c (W) and 8-2c (R).
        let read_bit = 8 - 2 * column(caller);
        let bit = if write { read_bit + 1 } else { read_bit };
        half & (1 << bit) != 0
    }

    pub fn permits_read(&self, caller: &Caller, security_mode: bool) -> bool {
        self.bit(caller, security_mode, false)
    }

    pub fn permits_write(&self, caller: &Caller, security_mode: bool) -> bool {
        self.bit(caller, security_mode, true)
    }
}

// ============================================================================
// Callers
// ============================================================================

#[derive(Clone, Copy, Debug)]
pub struct Caller {
    pub level: u8,
    pub security: SecurityMode,
    pub role: ClientRole,
}

impl Caller {
    pub const fn plain(level: u8) -> Self {
        Self { level, security: SecurityMode::Plain, role: ClientRole::Unlisted }
    }

    pub const fn secure(security: SecurityMode, role: ClientRole) -> Self {
        Self { level: 0, security, role }
    }

    pub fn context(&self) -> AccessContext {
        AccessContext::with_security(self.level, self.security, self.role)
    }

    /// Every caller class: plain at each legacy level, then the Roles and
    /// the Tool with authentication only and with confidentiality.
    pub fn all(max_levels: u8) -> Vec<Self> {
        let mut callers: Vec<Self> = (0..max_levels).map(Self::plain).collect();
        for role in [ClientRole::Roles(0x0001), ClientRole::Tool] {
            for security in [SecurityMode::AuthOnly, SecurityMode::AuthConf] {
                callers.push(Self::secure(security, role));
            }
        }
        callers
    }
}

// ============================================================================
// Expected properties
// ============================================================================

/// One property as the specification describes it.
#[derive(Clone, Copy, Debug)]
pub struct Expected {
    pub object_type: u16,
    pub pid: u16,
    pub kind: Kind,
    pub read: Audience,
    pub write: Audience,
    /// Access Policy in the spec's notation.
    pub policy: &'static str,
    /// Where the values come from, and why they deviate if they do.
    pub source: &'static str,
}

/// What a caller may do with one property.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Permissions {
    /// A data-property read, or a function-property state read.
    pub read: bool,
    /// A data-property write, or a function-property command.
    pub write: bool,
}

impl Expected {
    pub fn permissions(&self, caller: &Caller, security_mode: bool, max_levels: u8) -> Permissions {
        let policy = policy(self.policy);
        let policy_read = policy.permits_read(caller, security_mode);
        let policy_write = policy.permits_write(caller, security_mode);

        match self.kind {
            // A Function Property has no value to read or write; its
            // services are governed by the Access Policy (03/04/01 §6.2,
            // AN193: the access level of a function property "can have any
            // value", 03/03/07 §3.4.7).
            Kind::Function => Permissions { read: policy_read, write: policy_write },
            kind => {
                let readable = matches!(kind, Kind::ReadOnly | Kind::ReadWrite);
                let writable = matches!(kind, Kind::ReadWrite | Kind::WriteOnly);
                Permissions {
                    read: readable && caller.level <= self.read.level(max_levels) && policy_read,
                    write: writable && caller.level <= self.write.level(max_levels) && policy_write,
                }
            }
        }
    }

    /// The description is readable by whoever may read or write the value
    /// (AN193 §2.2.4.4).
    pub fn description_visible(&self, caller: &Caller, security_mode: bool, max_levels: u8) -> bool {
        let permissions = self.permissions(caller, security_mode, max_levels);
        permissions.read || permissions.write
    }
}
