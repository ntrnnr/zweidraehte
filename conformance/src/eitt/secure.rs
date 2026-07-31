//! Reading a template's KNX Data Security attributes.
//!
//! A secure telegram carries its security in attributes rather than in
//! `Data`: the `Data` is the *plaintext* frame, and `SecKey`, `SecType`,
//! `TA`, `SBC`, `SeqNum` and the rest say how to wrap it. This module
//! turns those attributes into the parameter structs the engine already
//! understands, and nothing else — the decision of which step to emit
//! belongs to [`super::lower`], which knows the direction.
//!
//! Everything here fails loudly. A `SecType` we cannot read, a key the
//! harness does not hold, a `SAL` outside the three we know: all are
//! errors. Guessing would send a security test in the clear or against
//! the wrong key, and it would still look green.

use std::collections::BTreeMap;

use super::frame;
use crate::{InvalidSecurityParam, SecType, SecureParams, SeqSource, SyncReqParams, SyncResExpect, TestVariable};

/// The keys `crate::tests::security::variables::security_keys` installs.
///
/// Checked at lowering time so a template naming a key we do not hold
/// stops the run, rather than reaching `SecurityTestContext::key` and
/// panicking in the middle of it.
const KNOWN_KEYS: &[&str] = &[
    "TK1", "TK2", "GK1", "GK2", "GK3", "GK4", "GK5", "GK6", "FDSK", "ZERO_KEY", "P2PK1", "P2PK2", "P2PK3", "P2PK4",
    "P2PK5", "P2PK6", "P2PK7", "P2PK8",
];

/// What a telegram's `SAL` says the security layer is carrying.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecureLayer {
    /// `SAL="data"` — an ordinary secured APDU.
    Data,
    /// `SAL="sync_req"` — an S-A_Sync_Req.
    SyncReq,
    /// `SAL="sync_resp"` — an S-A_Sync_Res.
    SyncRes,
}

/// Why a telegram's security attributes could not be read.
#[derive(Debug)]
pub struct SecureError(pub String);

impl std::fmt::Display for SecureError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

fn err<T>(msg: impl Into<String>) -> Result<T, SecureError> {
    Err(SecureError(msg.into()))
}

fn attr<'a>(v: Option<&'a String>) -> Option<&'a str> {
    v.map(|s| s.trim()).filter(|s| !s.is_empty())
}

/// Which of the three security layers this telegram carries.
pub fn layer(t: &super::schema::Telegram) -> Result<SecureLayer, SecureError> {
    // `SAI` names the algorithm. CCM is the only one KNX Data Security
    // defines and the only one the runner implements, so anything else
    // is either a newer spec or a typo — both worth stopping for.
    match attr(t.sai.as_ref()) {
        None | Some("ccm") => {}
        Some(other) => return err(format!("SAI={other:?} is not CCM, which is the only algorithm we implement")),
    }
    match attr(t.sal.as_ref()) {
        Some("data") => Ok(SecureLayer::Data),
        Some("sync_req") => Ok(SecureLayer::SyncReq),
        Some("sync_resp") => Ok(SecureLayer::SyncRes),
        Some(other) => err(format!("SAL={other:?} is not one of data, sync_req, sync_resp")),
        None => err("a secure telegram with no SAL: cannot tell data from a sync exchange"),
    }
}

/// `SecType` → authentication only, or authentication and confidentiality.
fn sec_type(t: &super::schema::Telegram) -> Result<SecType, SecureError> {
    match attr(t.sec_type.as_ref()) {
        Some("conf") => Ok(SecType::AuthConf),
        Some("auth") => Ok(SecType::AuthOnly),
        Some(other) => err(format!("SecType={other:?} is neither \"conf\" nor \"auth\"")),
        None => err("a secure telegram with no SecType"),
    }
}

/// `SecKey` → a key name the harness holds.
///
/// The template usually names the key, but eight telegrams write the
/// all-zero key out in full instead. That is the wrong-key negative
/// test, and the harness holds the same key under a name.
fn key_name(t: &super::schema::Telegram) -> Result<String, SecureError> {
    let Some(raw) = attr(t.sec_key.as_ref()) else {
        return err("a secure telegram with no SecKey");
    };
    let compact: String = raw.chars().filter(|c| !c.is_whitespace()).collect();
    if compact.len() == 32 && compact.chars().all(|c| c == '0') {
        return Ok("ZERO_KEY".to_string());
    }
    if KNOWN_KEYS.iter().any(|k| k.eq_ignore_ascii_case(raw)) {
        return Ok(raw.to_ascii_uppercase());
    }
    err(format!(
        "SecKey={raw:?} is not a key the harness holds. Known: {}. A literal key is only \
         recognised when it is the all-zero one, which is ZERO_KEY.",
        KNOWN_KEYS.join(", ")
    ))
}

/// `TA` → the tool-access flag in the SCF.
fn tool_access(t: &super::schema::Telegram) -> Result<bool, SecureError> {
    match attr(t.ta.as_ref()) {
        Some(v) if v.eq_ignore_ascii_case("yes") || v.eq_ignore_ascii_case("y") => Ok(true),
        Some(v) if v.eq_ignore_ascii_case("no") || v.eq_ignore_ascii_case("n") => Ok(false),
        Some(other) => err(format!("TA={other:?} is neither yes nor no")),
        None => Ok(false),
    }
}

/// `SBC` → the system-broadcast flag in the SCF.
fn system_broadcast(t: &super::schema::Telegram) -> Result<bool, SecureError> {
    match attr(t.sbc.as_ref()) {
        Some(v) if v.eq_ignore_ascii_case("broadcast") => Ok(true),
        Some(v) if v.eq_ignore_ascii_case("service") => Ok(false),
        Some(other) => err(format!("SBC={other:?} is neither \"service\" nor \"broadcast\"")),
        None => Ok(false),
    }
}

/// A sequence-number attribute: a named counter, or a literal.
///
/// `tool` is our own sending counter and `table` is what we believe the
/// device will send next; the split follows the direction, with `tool`
/// on the telegrams we inject and `table` on the ones we expect. A
/// literal pins the number outright, which the rollover tests need —
/// 3.8.15 counts up from 280375465082876, two short of the 48-bit
/// ceiling.
fn seq_source(raw: Option<&str>) -> Result<Option<SeqSource>, SecureError> {
    let Some(raw) = raw else { return Ok(None) };
    if raw.eq_ignore_ascii_case("tool") {
        return Ok(Some(SeqSource::Tool));
    }
    if raw.eq_ignore_ascii_case("table") {
        return Ok(Some(SeqSource::Table));
    }
    // A `#VAR` the template never declares is its way of writing "the
    // number the device happens to be at" — 3.9 puts `#SEC_SEQ_NUM` on
    // the two responses whose counter nothing has pinned yet. On a
    // telegram we expect that is exactly `table`, the value we track and
    // update from the frame. On one we send it is not: we would have to
    // choose a number, and choosing wrong is a test that passes for the
    // wrong reason.
    if raw.starts_with('#') {
        return Ok(Some(SeqSource::Unpinned(raw.to_string())));
    }
    match raw.parse::<u64>() {
        Ok(v) => Ok(Some(SeqSource::Fixed(v))),
        Err(_) => err(format!("SeqNum={raw:?} is neither \"tool\", \"table\", a number, nor a #variable")),
    }
}

/// `SeqNumOfs` → the signed shift applied to whatever the source yields.
fn seq_offset(t: &super::schema::Telegram) -> Result<i64, SecureError> {
    match attr(t.seq_num_ofs.as_ref()) {
        None => Ok(0),
        Some(raw) => raw.parse::<i64>().map_err(|_| SecureError(format!("SeqNumOfs={raw:?} is not a number"))),
    }
}

/// Six octets written either as `001122334455` or `00 11 22 33 44 55`.
fn six_octets(raw: &str, what: &str) -> Result<[u8; 6], SecureError> {
    let compact: String = raw.chars().filter(|c| !c.is_whitespace()).collect();
    if compact.len() != 12 || !compact.chars().all(|c| c.is_ascii_hexdigit()) {
        return err(format!("{what}={raw:?} is not six hex octets"));
    }
    let mut out = [0u8; 6];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&compact[i * 2..i * 2 + 2], 16)
            .map_err(|_| SecureError(format!("{what}={raw:?} is not six hex octets")))?;
    }
    Ok(out)
}

/// The security parameters for an `SAL="data"` telegram.
pub fn data_params(t: &super::schema::Telegram, inbound: bool) -> Result<SecureParams, SecureError> {
    // Absent `SeqNum` follows the direction, which is what the template
    // means by leaving it off: our counter for what we send, the
    // device's for what we expect.
    let source = match seq_source(attr(t.seq_num.as_ref()))? {
        Some(SeqSource::Unpinned(name)) if inbound => {
            return err(format!(
                "SeqNum={name:?} on a telegram we send: an undeclared variable says the number is \
                 whatever the device is at, which we cannot know for something we are about to \
                 transmit. Declare it in [template.variables] if it has a value."
            ));
        }
        Some(SeqSource::Unpinned(_)) => SeqSource::Table,
        Some(other) => other,
        None => {
            if inbound {
                SeqSource::Tool
            } else {
                SeqSource::Table
            }
        }
    };
    Ok(SecureParams {
        sec_type: sec_type(t)?,
        key_name: key_name(t)?,
        tool_access: tool_access(t)?,
        seq_source: source,
        seq_offset: seq_offset(t)?,
        system_broadcast: system_broadcast(t)?,
    })
}

/// The deliberate corruption a telegram asks for, if any.
///
/// At most one applies. The template never combines two, and the engine
/// takes a single [`InvalidSecurityParam`], so a telegram naming more
/// than one is an error rather than a silent first-wins.
pub fn corruption(t: &super::schema::Telegram) -> Result<Option<InvalidSecurityParam>, SecureError> {
    let mut found: Vec<(&str, InvalidSecurityParam)> = Vec::new();

    if let Some(raw) = attr(t.inval_scf.as_ref()) {
        let byte =
            u8::from_str_radix(raw, 16).map_err(|_| SecureError(format!("InvalSCF={raw:?} is not a hex octet")))?;
        found.push(("InvalSCF", InvalidSecurityParam::InvalidScf(byte)));
    }
    if let Some(raw) = attr(t.inval_resv.as_ref()) {
        let bits =
            u8::from_str_radix(raw, 16).map_err(|_| SecureError(format!("InvalResv={raw:?} is not a hex octet")))?;
        found.push(("InvalResv", InvalidSecurityParam::ScfReservedBits(bits)));
    }
    if let Some(raw) = attr(t.inval_mac.as_ref()) {
        found.push(("InvalMAC", mac_pattern(raw)?));
    }
    if let Some(raw) = attr(t.inval_cypher.as_ref()) {
        // A single `FF` is the template asking for the ciphertext to be
        // damaged; a longer run is the "plain APDU in an A+C frame"
        // attack, where the bytes given are sent unencrypted.
        let bytes = hex_octets(raw, "InvalCypher")?;
        found.push((
            "InvalCypher",
            if bytes.len() <= 1 {
                InvalidSecurityParam::InvalidCipher
            } else {
                InvalidSecurityParam::PlainCipher(bytes)
            },
        ));
    }
    if let Some(raw) = attr(t.at_wrong.as_ref()) {
        if raw.eq_ignore_ascii_case("yes") || raw.eq_ignore_ascii_case("y") {
            found.push(("ATWrong", InvalidSecurityParam::WrongAddressType));
        } else {
            return err(format!("ATWrong={raw:?} is neither yes nor no"));
        }
    }

    match found.len() {
        0 => Ok(None),
        1 => Ok(Some(found.remove(0).1)),
        _ => {
            let names: Vec<&str> = found.iter().map(|(n, _)| *n).collect();
            err(format!("a telegram asks for {names:?} at once, and the engine applies one corruption"))
        }
    }
}

/// `InvalMAC` → a MAC pattern, where `??` keeps the computed octet.
///
/// The width matters as much as the content: three octets is 3.1.29's
/// "one byte too short", five is 3.1.28's "one byte too long".
fn mac_pattern(raw: &str) -> Result<InvalidSecurityParam, SecureError> {
    let mut pattern = Vec::new();
    for tok in raw.split_whitespace() {
        if tok == "??" {
            pattern.push(None);
        } else {
            pattern.push(Some(
                u8::from_str_radix(tok, 16)
                    .map_err(|_| SecureError(format!("InvalMAC={raw:?} has {tok:?}, neither ?? nor a hex octet")))?,
            ));
        }
    }
    if pattern.is_empty() {
        return err(format!("InvalMAC={raw:?} is empty"));
    }
    // A full-width pattern with every octet pinned is the plain
    // replacement, which the engine has had since the hand-written
    // suites; keep using it so those paths stay exercised.
    if pattern.len() == 4 && pattern.iter().all(Option::is_some) {
        let mut mac = [0u8; 4];
        for (slot, byte) in mac.iter_mut().zip(pattern.iter()) {
            *slot = byte.expect("just checked every octet is pinned");
        }
        return Ok(InvalidSecurityParam::InvalidMac(mac));
    }
    Ok(InvalidSecurityParam::MacPattern(pattern))
}

/// Whitespace-separated hex octets.
fn hex_octets(raw: &str, what: &str) -> Result<Vec<u8>, SecureError> {
    raw.split_whitespace()
        .map(|tok| u8::from_str_radix(tok, 16).map_err(|_| SecureError(format!("{what}={raw:?} is not hex octets"))))
        .collect()
}

/// The frame skeleton a sync telegram carries in `Data`.
///
/// A sync request is built from scratch rather than wrapped around a
/// plaintext APDU, so the engine needs the header fields separately.
/// They are all in `Data`, and where each one sits depends on the frame
/// layout — every sync telegram in the data-security template is
/// extended:
///
/// ```text
///   3C     60      #EDI   22 02   18    03    F1    92
///   ctrl   ctrle   src    dst     len   tpci  apci  scf
/// ```
struct SyncSkeleton {
    ctrl_byte: u8,
    npdu_byte: u8,
    src: String,
    dst: String,
    tpci_high: u8,
}

/// Read the header fields out of a sync telegram's `Data`.
///
/// Offsets come from [`frame::layout`] rather than from token positions.
/// Counting tokens is only ever right by accident: `3C 60 #EDI
/// #BDUT_ADDR 18 03 F1` puts the TPCI in the sixth token and `3C 60
/// #EDI 22 02 18 03 F1` puts it in the seventh, because writing an
/// address as two literal octets costs a token that a variable does not.
fn sync_skeleton(data: &str, vars: &BTreeMap<String, TestVariable>) -> Result<SyncSkeleton, SecureError> {
    let tokens: Vec<&str> = data.split_whitespace().collect();
    let ctrl_byte = tokens
        .first()
        .and_then(|t| u8::from_str_radix(t, 16).ok())
        .ok_or_else(|| SecureError("a sync telegram's Data must start with a literal control octet".to_string()))?;
    let layout = frame::layout(ctrl_byte);

    // A single literal octet — the NPDU and TPCI positions are never a
    // variable or a wildcard in any template we run, and a frame where
    // one of them is has to stop the run rather than be guessed at.
    let octet = |offset: usize, what: &str| -> Result<u8, SecureError> {
        let (index, _) = frame::token_at(&tokens, vars, offset)
            .ok_or_else(|| SecureError(format!("{what} is past the end of Data ({data:?})")))?;
        u8::from_str_radix(tokens[index], 16)
            .map_err(|_| SecureError(format!("{what} ({:?}) is not a hex octet", tokens[index])))
    };
    let address = |offset: usize, what: &str| -> Result<String, SecureError> {
        frame::token_span(&tokens, vars, offset, 2)
            .ok_or_else(|| SecureError(format!("{what} does not fall on token boundaries in Data ({data:?})")))
    };

    Ok(SyncSkeleton {
        ctrl_byte,
        npdu_byte: octet(layout.npdu, "the NPDU octet")?,
        src: address(layout.src, "the source address")?,
        dst: address(layout.dst, "the destination address")?,
        tpci_high: octet(layout.tpci, "the TPCI octet")?,
    })
}

/// Parameters for an S-A_Sync_Req we inject.
pub fn sync_req_params(
    t: &super::schema::Telegram,
    data: &str,
    vars: &BTreeMap<String, TestVariable>,
) -> Result<SyncReqParams, SecureError> {
    let skel = sync_skeleton(data, vars)?;
    let challenge = match attr(t.challenge.as_ref()) {
        Some(raw) if !raw.eq_ignore_ascii_case("auto") => six_octets(raw, "Challenge")?,
        // `auto` on a request would mean EITT picks one; the template
        // only writes it on responses, where it means "whatever the
        // request used". A request asking for it has nothing to inherit.
        Some(_) => return err("Challenge=\"auto\" on a sync request: there is no earlier challenge to reuse"),
        None => return err("a sync request with no Challenge"),
    };
    let serial = match attr(t.knx_ser_no.as_ref()) {
        Some(raw) => six_octets(raw, "KNXSerNo")?,
        None => [0u8; 6],
    };
    // `SeqNumLoc` is the number the request advertises as ours. A named
    // counter is carried through as such and resolved by the engine
    // against the live value — flattening it to a number here is how
    // every `SeqNumLoc="tool"` request used to go out advertising zero,
    // which the device rejects out of hand.
    //
    // Absent, it is the tool counter: `SeqNumLoc` is blank only on the
    // requests that are already tool-access, and a request with no
    // number to advertise has nothing to synchronise.
    let seq_local = seq_source(attr(t.seq_num_loc.as_ref()))?.unwrap_or(SeqSource::Tool);
    Ok(SyncReqParams {
        key_name: key_name(t)?,
        tool_access: tool_access(t)?,
        system_broadcast: system_broadcast(t)?,
        src_template: skel.src,
        dst_template: skel.dst,
        npdu_byte: skel.npdu_byte,
        ctrl_byte: skel.ctrl_byte,
        seq_local,
        serial_number: serial,
        challenge,
        tpci_high: skel.tpci_high,
    })
}

/// What we expect back in an S-A_Sync_Res.
///
/// `challenge` cannot come from this telegram when it says `auto`: the
/// value is whichever the matching request sent, so the caller supplies
/// it from the request it lowered a moment ago.
pub fn sync_res_expect(
    t: &super::schema::Telegram,
    data: &str,
    vars: &BTreeMap<String, TestVariable>,
    inherited_challenge: Option<[u8; 6]>,
) -> Result<SyncResExpect, SecureError> {
    let skel = sync_skeleton(data, vars)?;
    let challenge = match attr(t.challenge.as_ref()) {
        Some(raw) if raw.eq_ignore_ascii_case("auto") => match inherited_challenge {
            Some(c) => c,
            None => return err("Challenge=\"auto\" with no sync request before it in the case"),
        },
        Some(raw) => six_octets(raw, "Challenge")?,
        None => match inherited_challenge {
            Some(c) => c,
            None => return err("a sync response with no Challenge and no request before it"),
        },
    };
    // A named counter means "whatever the device says"; only a literal
    // pins the value we insist on.
    let pinned = |raw: Option<&str>| -> Result<Option<u64>, SecureError> {
        match seq_source(raw)? {
            Some(SeqSource::Fixed(v)) => Ok(Some(v)),
            _ => Ok(None),
        }
    };
    Ok(SyncResExpect {
        key_name: key_name(t)?,
        tool_access: tool_access(t)?,
        system_broadcast: system_broadcast(t)?,
        expected_seq_remote: pinned(attr(t.seq_num_rem.as_ref()))?,
        expected_seq_local: pinned(attr(t.seq_num_loc.as_ref()))?,
        challenge,
        expected_src_template: skel.src,
    })
}

/// Parameters for an S-A_Sync_Res we send unprompted.
///
/// Everything comes off this telegram, because there is no request to
/// take it from: the challenge it claims to answer, the sequence
/// numbers it asserts, and the addresses, which run the other way round
/// from a response the device sends — the source is us.
pub fn sync_res_inject(
    t: &super::schema::Telegram,
    data: &str,
    vars: &BTreeMap<String, TestVariable>,
) -> Result<crate::SyncResInject, SecureError> {
    let skel = sync_skeleton(data, vars)?;
    let challenge = match attr(t.challenge.as_ref()) {
        Some(raw) if raw.eq_ignore_ascii_case("auto") => {
            return err("Challenge=\"auto\" on an unsolicited sync response: there is no request to take it from");
        }
        Some(raw) => six_octets(raw, "Challenge")?,
        None => return err("an unsolicited sync response with no Challenge"),
    };
    let literal = |raw: Option<&str>| -> Result<u64, SecureError> {
        match seq_source(raw)? {
            Some(SeqSource::Fixed(v)) => Ok(v),
            // A named counter has no meaning in a frame we build from
            // nothing; zero is what the template's own records show.
            _ => Ok(0),
        }
    };
    Ok(crate::SyncResInject {
        key_name: key_name(t)?,
        tool_access: tool_access(t)?,
        system_broadcast: system_broadcast(t)?,
        src_template: skel.src,
        dst_template: skel.dst,
        seq_nr_remote: literal(attr(t.seq_num_rem.as_ref()))?,
        seq_nr_local: literal(attr(t.seq_num_loc.as_ref()))?,
        challenge,
        ctrl_byte: skel.ctrl_byte,
        npdu_byte: skel.npdu_byte,
        tpci_high: skel.tpci_high,
    })
}

/// The challenge a sync request carries, for the response that follows.
pub fn challenge_of(t: &super::schema::Telegram) -> Option<[u8; 6]> {
    let raw = attr(t.challenge.as_ref())?;
    if raw.eq_ignore_ascii_case("auto") {
        return None;
    }
    six_octets(raw, "Challenge").ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::eitt::schema::Telegram;

    fn tg() -> Telegram {
        Telegram { sai: Some("ccm".into()), ..Default::default() }
    }

    #[test]
    fn sec_type_and_flags_read_the_template_vocabulary() {
        let t = Telegram {
            sec_type: Some("conf".into()),
            sec_key: Some("TK1".into()),
            ta: Some("yes".into()),
            sbc: Some("service".into()),
            ..tg()
        };
        let p = data_params(&t, true).expect("reads");
        assert_eq!(p.sec_type, SecType::AuthConf);
        assert_eq!(p.key_name, "TK1");
        assert!(p.tool_access);
        assert!(!p.system_broadcast);
        assert_eq!(p.seq_source, SeqSource::Tool);
    }

    #[test]
    fn an_absent_seq_num_follows_the_direction() {
        let t = Telegram { sec_type: Some("auth".into()), sec_key: Some("TK1".into()), ..tg() };
        assert_eq!(data_params(&t, true).expect("in").seq_source, SeqSource::Tool);
        assert_eq!(data_params(&t, false).expect("out").seq_source, SeqSource::Table);
    }

    #[test]
    fn the_all_zero_key_is_the_one_the_harness_calls_zero_key() {
        let t = Telegram {
            sec_type: Some("conf".into()),
            sec_key: Some("00000000000000000000000000000000".into()),
            ..tg()
        };
        assert_eq!(data_params(&t, true).expect("reads").key_name, "ZERO_KEY");
    }

    #[test]
    fn an_unknown_key_stops_the_run_rather_than_panicking_later() {
        let t = Telegram { sec_type: Some("conf".into()), sec_key: Some("GK9".into()), ..tg() };
        assert!(data_params(&t, true).is_err());
    }

    #[test]
    fn a_non_ccm_algorithm_is_an_error() {
        let t = Telegram { sai: Some("aes-gcm".into()), sal: Some("data".into()), ..Default::default() };
        assert!(layer(&t).is_err());
    }

    /// 3.1.29 is "one byte too short" and 3.1.28 "one byte too long";
    /// the width of the pattern is the whole point of those two.
    #[test]
    fn mac_patterns_carry_their_width() {
        let short = mac_pattern("?? ?? ??").expect("reads");
        assert_eq!(short, InvalidSecurityParam::MacPattern(vec![None, None, None]));
        let long = mac_pattern("?? ?? ?? ?? 00").expect("reads");
        assert_eq!(long, InvalidSecurityParam::MacPattern(vec![None, None, None, None, Some(0)]));
        let masked = mac_pattern("FF ?? ?? ??").expect("reads");
        assert_eq!(masked, InvalidSecurityParam::MacPattern(vec![Some(0xFF), None, None, None]));
        // Fully pinned and full width stays the plain replacement.
        assert_eq!(mac_pattern("01 02 03 04").expect("reads"), InvalidSecurityParam::InvalidMac([1, 2, 3, 4]));
    }

    #[test]
    fn reserved_bits_are_not_a_whole_scf_replacement() {
        let t = Telegram { inval_resv: Some("04".into()), ..tg() };
        assert_eq!(corruption(&t).expect("reads"), Some(InvalidSecurityParam::ScfReservedBits(0x04)));
    }

    #[test]
    fn two_corruptions_at_once_are_an_error() {
        let t = Telegram { inval_resv: Some("04".into()), inval_scf: Some("00".into()), ..tg() };
        assert!(corruption(&t).is_err());
    }

    #[test]
    fn seq_offset_is_signed() {
        let t = Telegram { seq_num_ofs: Some("-2".into()), ..tg() };
        assert_eq!(seq_offset(&t).expect("reads"), -2);
    }

    fn skeleton_vars() -> BTreeMap<String, TestVariable> {
        BTreeMap::from([
            ("EDI".to_string(), TestVariable::Bytes(vec![0xAF, 0xFE])),
            ("BDUT_ADDR".to_string(), TestVariable::Bytes(vec![0x10, 0x01])),
        ])
    }

    #[test]
    fn a_sync_skeleton_comes_out_of_the_data() {
        let s = sync_skeleton("3C 60 #EDI #BDUT_ADDR 18 03 F1 92 00", &skeleton_vars()).expect("reads");
        assert_eq!(s.ctrl_byte, 0x3C);
        assert_eq!(s.npdu_byte, 0x60);
        assert_eq!(s.src, "#EDI");
        assert_eq!(s.dst, "#BDUT_ADDR");
        assert_eq!(s.tpci_high, 0x03);
    }

    #[test]
    fn a_literal_address_does_not_shift_the_skeleton() {
        // The shape this used to get wrong. Writing the destination as
        // two literal octets costs a token that `#BDUT_ADDR` does not,
        // so a token-index walk took `22` for the whole destination and
        // the `18` length octet for the TPCI — and `0x18 | 0x03` is the
        // `1B` that went out on the wire in 3.8.7.1.
        let s = sync_skeleton("3C 60 #EDI 22 02 18 03 F1 92 00", &skeleton_vars()).expect("reads");
        assert_eq!(s.ctrl_byte, 0x3C);
        assert_eq!(s.npdu_byte, 0x60);
        assert_eq!(s.src, "#EDI");
        assert_eq!(s.dst, "22 02");
        assert_eq!(s.tpci_high, 0x03);
    }

    #[test]
    fn a_broadcast_sync_skeleton_keeps_its_zero_destination() {
        let s = sync_skeleton("3C E0 #EDI 00 00 18 03 F1 92 00", &skeleton_vars()).expect("reads");
        assert_eq!(s.npdu_byte, 0xE0);
        assert_eq!(s.dst, "00 00");
        assert_eq!(s.tpci_high, 0x03);
    }

    #[test]
    fn a_standard_frame_skeleton_has_one_control_octet() {
        // No template we run writes a standard-frame sync telegram, but
        // the layout is chosen by the control byte rather than assumed,
        // so it costs nothing to be right about it.
        let s = sync_skeleton("BC #EDI #BDUT_ADDR 60 03 F1 92 00", &skeleton_vars()).expect("reads");
        assert_eq!(s.ctrl_byte, 0xBC);
        assert_eq!(s.npdu_byte, 0x60);
        assert_eq!(s.src, "#EDI");
        assert_eq!(s.dst, "#BDUT_ADDR");
        assert_eq!(s.tpci_high, 0x03);
    }
}
