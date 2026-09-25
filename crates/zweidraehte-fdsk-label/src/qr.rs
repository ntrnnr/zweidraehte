//! Terminal QR rendering, enabled by the `qr` feature (which enables `std`).

use qrcode::QrCode;
use qrcode::render::unicode::Dense1x2;

use crate::{label, qr_payload};

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
    fn qr_renders_non_empty_lines() {
        let lines = qr_lines(&SERIAL, &FDSK).expect("36-char payload always encodes");
        assert!(!lines.is_empty());
        assert!(lines.iter().all(|l| !l.is_empty()));
    }
}
