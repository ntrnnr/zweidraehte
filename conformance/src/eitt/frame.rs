//! Where a telegram's header fields sit in its `Data` string.
//!
//! A template writes a frame as whitespace-separated tokens, but a token
//! is not an octet: `#EDI` is one token and two octets, `#SER_NUM` is one
//! token and six. Anything that wants a *field* rather than a token has
//! to walk the tokens accumulating widths, and it has to know which
//! layout the frame is in before it knows what offset to walk to.
//!
//! Both questions have one answer each, and they live here so the two
//! callers — the transport-layer sequence numbering in [`super::lower`]
//! and the sync-telegram skeleton in [`super::secure`] — cannot drift
//! apart. They did: the skeleton read the NPDU octet from the extended
//! layout and everything else from the standard one, which happens to
//! come out right whenever both addresses are single-token variables and
//! wrong the moment one is written as two literal octets.

use std::collections::BTreeMap;

use crate::TestVariable;

/// Octet offsets of the header fields, for one of the two frame layouts.
///
/// ```text
///   standard:  CTRL  src(2) dst(2) AT/HC/len  TPCI  APCI …
///   extended:  CTRL  CTRLE  src(2) dst(2)     len   TPCI  APCI …
/// ```
///
/// `npdu` names the octet carrying the address type and hop count. The
/// two layouts keep it in different places and spell it differently —
/// standard packs the payload length into its low nibble, extended
/// gives the length an octet of its own — but the engine's internal
/// frame is the standard shape either way, and
/// `knx_to_tp1_message_no_checksum` re-splits it on the way out. So for
/// an extended frame the octet to take is CTRLE, whose high nibble is
/// exactly what the internal form wants.
pub(crate) struct Layout {
    pub npdu: usize,
    pub src: usize,
    pub dst: usize,
    pub tpci: usize,
}

/// Pick the layout from the control byte.
///
/// The control byte is the authority, not the `FT` attribute: the
/// management template has 28 telegrams whose `FT` says `Normal` over an
/// extended control byte, and it is the octets the device parses. Bit 7
/// clear means extended.
pub(crate) fn layout(ctrl: u8) -> Layout {
    if ctrl & 0x80 != 0 {
        Layout { npdu: 5, src: 1, dst: 3, tpci: 6 }
    } else {
        Layout { npdu: 1, src: 2, dst: 4, tpci: 7 }
    }
}

/// How many octets a `Data` token contributes to the frame.
///
/// Mirrors the expression grammar in [`crate::telegram`]: a bare `#VAR`
/// and an offset `#VAR±N` are as wide as the variable, an indexed
/// `#VAR.N` picks a single octet out of it, and everything else — a hex
/// literal or a `??` wildcard — is one.
pub(crate) fn token_width(token: &str, vars: &BTreeMap<String, TestVariable>) -> usize {
    let Some(expr) = token.strip_prefix('#') else { return 1 };
    let name = expr.split(['.', '+', '-']).next().unwrap_or(expr);
    if expr[name.len()..].starts_with('.') {
        return 1;
    }
    vars.get(name).map_or(1, |v| v.as_bytes().len())
}

/// Index of the token covering `octet`, and the octet offset it starts at.
pub(crate) fn token_at(tokens: &[&str], vars: &BTreeMap<String, TestVariable>, octet: usize) -> Option<(usize, usize)> {
    let mut offset = 0usize;
    for (index, tok) in tokens.iter().enumerate() {
        let width = token_width(tok, vars);
        if (offset..offset + width).contains(&octet) {
            return Some((index, offset));
        }
        offset += width;
    }
    None
}

/// The tokens covering `octet..octet + width`, joined back into a
/// `Data` fragment.
///
/// Returned as text rather than bytes because the caller feeds it back
/// through [`crate::telegram::Telegram::parse`], which is what resolves
/// `#VAR` — so a two-octet address survives whether the template wrote
/// it as one variable or as two literal octets.
///
/// `None` when the range does not start and end on token boundaries: a
/// variable straddling half of it is not something we can hand on.
pub(crate) fn token_span(
    tokens: &[&str],
    vars: &BTreeMap<String, TestVariable>,
    octet: usize,
    width: usize,
) -> Option<String> {
    let (first, start) = token_at(tokens, vars, octet)?;
    if start != octet {
        return None;
    }
    let mut covered = 0usize;
    let mut last = first;
    while covered < width {
        let tok = tokens.get(last)?;
        covered += token_width(tok, vars);
        last += 1;
    }
    if covered != width {
        return None;
    }
    Some(tokens[first..last].join(" "))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn vars() -> BTreeMap<String, TestVariable> {
        BTreeMap::from([
            ("EDI".to_string(), TestVariable::Bytes(vec![0xAF, 0xFE])),
            ("BDUT_ADDR".to_string(), TestVariable::Bytes(vec![0x10, 0x01])),
            ("SER_NUM".to_string(), TestVariable::Bytes(vec![0; 6])),
        ])
    }

    #[test]
    fn the_control_byte_picks_the_layout() {
        // 0xBC is a standard frame, 0x3C an extended one; the `FT`
        // attribute does not enter into it.
        assert_eq!(layout(0xBC).tpci, 6);
        assert_eq!(layout(0x3C).tpci, 7);
        assert_eq!(layout(0x3C).npdu, 1);
    }

    #[test]
    fn a_variable_address_spans_two_octets_in_one_token() {
        let toks: Vec<&str> = "3C 60 #EDI #BDUT_ADDR 18 03 F1".split_whitespace().collect();
        let v = vars();
        let l = layout(0x3C);
        assert_eq!(token_span(&toks, &v, l.src, 2).as_deref(), Some("#EDI"));
        assert_eq!(token_span(&toks, &v, l.dst, 2).as_deref(), Some("#BDUT_ADDR"));
        // The TPCI is at octet 7, which is the `03` token — not the `18`
        // length octet a token-index walk would have landed on.
        assert_eq!(token_at(&toks, &v, l.tpci).map(|(i, _)| toks[i]), Some("03"));
    }

    #[test]
    fn a_literal_address_spans_two_tokens() {
        // The shape that used to misparse: with `22 02` written out, the
        // destination is two tokens and everything after shifts.
        let toks: Vec<&str> = "3C 60 #EDI 22 02 18 03 F1 92".split_whitespace().collect();
        let v = vars();
        let l = layout(0x3C);
        assert_eq!(token_span(&toks, &v, l.src, 2).as_deref(), Some("#EDI"));
        assert_eq!(token_span(&toks, &v, l.dst, 2).as_deref(), Some("22 02"));
        assert_eq!(token_at(&toks, &v, l.tpci).map(|(i, _)| toks[i]), Some("03"));
    }

    #[test]
    fn a_standard_frame_has_no_second_control_octet() {
        let toks: Vec<&str> = "BC #EDI #BDUT_ADDR 60 03 F1".split_whitespace().collect();
        let v = vars();
        let l = layout(0xBC);
        assert_eq!(token_span(&toks, &v, l.src, 2).as_deref(), Some("#EDI"));
        assert_eq!(token_span(&toks, &v, l.dst, 2).as_deref(), Some("#BDUT_ADDR"));
        assert_eq!(token_at(&toks, &v, l.npdu).map(|(i, _)| toks[i]), Some("60"));
        assert_eq!(token_at(&toks, &v, l.tpci).map(|(i, _)| toks[i]), Some("03"));
    }

    #[test]
    fn a_broadcast_destination_is_two_literal_zero_octets() {
        // The sync requests in the data-security template's broadcast
        // cases: `3C E0 #EDI 00 00 …`.
        let toks: Vec<&str> = "3C E0 #EDI 00 00 18 03 F1".split_whitespace().collect();
        let v = vars();
        let l = layout(0x3C);
        assert_eq!(token_span(&toks, &v, l.dst, 2).as_deref(), Some("00 00"));
        assert_eq!(token_at(&toks, &v, l.npdu).map(|(i, _)| toks[i]), Some("E0"));
    }

    #[test]
    fn a_span_that_splits_a_variable_is_refused() {
        // Asking for one octet of a two-octet variable cannot be handed
        // on as text, so it is `None` rather than a silent half-address.
        let toks: Vec<&str> = "3C 60 #EDI #BDUT_ADDR 18 03 F1".split_whitespace().collect();
        assert_eq!(token_span(&toks, &vars(), 2, 1), None);
        assert_eq!(token_span(&toks, &vars(), 3, 2), None);
    }
}
