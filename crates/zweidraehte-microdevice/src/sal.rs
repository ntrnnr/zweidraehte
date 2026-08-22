//! Request-scoped types for the Secure Application Layer integration.
//!
//! Security metadata belongs to the frame that produced it. Keeping it in
//! these copyable values, instead of in device or management state, prevents
//! a rejected secure request from changing how a later plaintext response is
//! authorised or wrapped.

use zweidraehte_proto::access::{AccessContext, SecurityMode};

/// How an authenticated request may be answered.
///
/// The key is deliberately not cached here. A secure property write may
/// replace the Tool Key, and its response has to use that new key. The S-AL
/// resolves the live key only when it wraps the response.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReplySecurity {
    pub security: SecurityMode,
    pub tool_access: bool,
    pub key: ReplyKey,
}

/// Where the response obtains its key and sequence number.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReplyKey {
    /// Resolve the live Tool Key and reserve the sequence number at send time.
    /// Tool-key writes use this so their confirmation carries the new key.
    Live,
    /// A factory-reset response belongs to the security context that accepted
    /// the request, even though the durable state is reset before it is sent.
    Prepared { key: [u8; 16], sequence: [u8; 6] },
}

/// Security and authorisation facts derived from one accepted frame.
///
/// `R` is selected by the profile module. It is `()` for [`NoSecurity`]
/// and therefore occupies no space in a plain stack; Data Secure uses it to
/// carry the request-scoped reply protection.
///
/// [`NoSecurity`]: crate::security::NoSecurity
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RequestContext<R> {
    pub access: AccessContext,
    pub reply: R,
}
