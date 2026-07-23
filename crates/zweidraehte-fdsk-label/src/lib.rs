//! FDSK commissioning label rendering — the human-readable code and the QR
//! form ETS-style scanners read.
//!
//! A KNX Data Secure device is commissioned with its **FDSK** (Factory Default
//! Setup Key), which ETS accepts either typed in from the device label or
//! scanned from a QR code. Both forms come from the same Base32 encoding of
//! `serial || fdsk || crc4` produced by
//! [`provisioning::fdsk_string`](zweidraehte_device::provisioning::fdsk_string);
//! this crate turns that encoding into something you can print.
//!
//! It exists so the provisioning tool (which writes labels onto physical
//! devices) and the host-target device shells (which print their own label at
//! startup) share one implementation — they previously carried near-identical
//! copies.
//!
//! # The dash distinction
//!
//! The label is shown to humans **hyphenated** every six characters
//! (`XXXXXX-XXXXXX-…`) for readability, but scanners expect the **dashless**
//! 36-character payload. [`label`] returns the former, [`qr_payload`] the
//! latter, and [`qr_lines`] encodes the latter — so the two never drift.
//!
//! # Example
//!
//! ```
//! # let serial = [0x00, 0xFA, 0x00, 0x00, 0x00, 0x09];
//! # let fdsk = [0u8; 16];
//! println!("FDSK: {}", fdsk_label::label(&serial, &fdsk));
//! for line in fdsk_label::qr_lines(&serial, &fdsk).expect("36 chars always fit") {
//!     println!("  {line}");
//! }
//! ```

use qrcode::QrCode;
use qrcode::render::unicode::Dense1x2;
use zweidraehte_device::provisioning;

/// The hyphenated ETS label code, `XXXXXX-XXXXXX-XXXXXX-XXXXXX-XXXXXX-XXXXXX`.
///
/// This is the form printed on a device label and typed into ETS by hand. For
/// the scannable form, see [`qr_payload`].
pub fn label(serial: &[u8; 6], fdsk: &[u8; 16]) -> String {
    let bytes = provisioning::fdsk_string(serial, fdsk);
    // `fdsk_string` emits Base32 symbols and '-' only, so this is always valid
    // ASCII and the conversion cannot fail.
    core::str::from_utf8(&bytes).expect("fdsk_string emits ASCII").to_owned()
}

/// The dashless 36-character Base32 payload that goes into the QR code.
///
/// ETS-style scanners expect the code without separators; the hyphens in
/// [`label`] are a human-readability affordance only.
pub fn qr_payload(serial: &[u8; 6], fdsk: &[u8; 16]) -> String {
    label(serial, fdsk).chars().filter(|c| *c != '-').collect()
}

/// Render the label's QR code as terminal lines.
///
/// Uses `Dense1x2` unicode rendering — each character cell carries two QR rows
/// (`▀ ▄ █` and space), so the result looks roughly square at the usual 1:2
/// terminal aspect ratio. The default 4-module quiet zone is kept so phone
/// cameras lock on without fiddling.
///
/// The colours are deliberately inverted (`dark_color(Light)`): terminals
/// render light-on-dark by default, and scanners need dark modules on a light
/// background.
///
/// # Errors
///
/// Returns the underlying [`qrcode::types::QrError`] if encoding fails. With a
/// fixed 36-character payload this cannot happen in practice (well inside
/// version-3 capacity at the highest error correction), so callers may treat a
/// failure as non-fatal and fall back to printing [`label`] alone.
pub fn qr_lines(serial: &[u8; 6], fdsk: &[u8; 16]) -> Result<Vec<String>, qrcode::types::QrError> {
    let payload = qr_payload(serial, fdsk);
    let code = QrCode::new(payload.as_bytes())?;
    let rendered = code.render::<Dense1x2>().dark_color(Dense1x2::Light).light_color(Dense1x2::Dark).build();
    Ok(rendered.lines().map(str::to_owned).collect())
}

/// Print the label and its QR code to stdout, each line prefixed with `indent`.
///
/// The convenience both consumers want: one line of commissioning info plus
/// the scannable code. A QR encoding failure is reported to stderr and skipped
/// — the printed label above it is enough to commission the device by hand.
pub fn print_label(serial: &[u8; 6], fdsk: &[u8; 16], indent: &str) {
    println!("{indent}FDSK (for ETS):  {}", label(serial, fdsk));
    match qr_lines(serial, fdsk) {
        Ok(lines) => {
            for line in lines {
                println!("{indent}{line}");
            }
        }
        Err(e) => eprintln!("{indent}(QR render skipped: {e})"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SERIAL: [u8; 6] = [0x00, 0xFA, 0x00, 0x00, 0x00, 0x09];
    const FDSK: [u8; 16] =
        [0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF];

    #[test]
    fn label_is_hyphenated_base32() {
        let l = label(&SERIAL, &FDSK);
        assert_eq!(l.len(), 41, "36 symbols + 5 separators");
        assert_eq!(l.matches('-').count(), 5);
        for (i, group) in l.split('-').enumerate() {
            assert_eq!(group.len(), 6, "group {i} must be 6 symbols");
            assert!(
                group.bytes().all(|b| b.is_ascii_uppercase() || (b'2'..=b'7').contains(&b)),
                "group {i} must be RFC 4648 Base32: {group}"
            );
        }
    }

    /// The scanned payload and the printed label must encode the same key —
    /// they differ only by separators.
    #[test]
    fn qr_payload_is_the_label_without_dashes() {
        let payload = qr_payload(&SERIAL, &FDSK);
        assert_eq!(payload.len(), 36);
        assert!(!payload.contains('-'));
        assert_eq!(payload, label(&SERIAL, &FDSK).replace('-', ""));
    }

    /// A different key must produce a different label — guards against a
    /// constant/stub encoding slipping in.
    #[test]
    fn distinct_keys_yield_distinct_labels() {
        let other_fdsk = [0x01; 16];
        assert_ne!(label(&SERIAL, &FDSK), label(&SERIAL, &other_fdsk));

        let other_serial = [0x00, 0xFA, 0x00, 0x00, 0x00, 0x0A];
        assert_ne!(label(&SERIAL, &FDSK), label(&other_serial, &FDSK));
    }

    #[test]
    fn qr_renders_non_empty_lines() {
        let lines = qr_lines(&SERIAL, &FDSK).expect("36-char payload always encodes");
        assert!(!lines.is_empty());
        assert!(lines.iter().all(|l| !l.is_empty()));
    }

    /// This crate must be a pure re-presentation of
    /// [`provisioning::fdsk_string`] — a label printed by a device has to
    /// match the one `knx-provision` puts on its physical label, or ETS is
    /// handed a key that does not commission the device.
    #[test]
    fn label_matches_the_underlying_encoder() {
        let raw = provisioning::fdsk_string(&SERIAL, &FDSK);
        let expected = core::str::from_utf8(&raw).expect("ASCII");
        assert_eq!(label(&SERIAL, &FDSK), expected);
    }
}
