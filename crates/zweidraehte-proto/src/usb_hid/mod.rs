//! KNX USB interface protocol (03/06/03 EMI/IMI + KNX USB Transfer
//! Protocol).
//!
//! The pure, I/O-free layers of talking to a KNX USB interface:
//!
//! - [`hid`] — HID report framing: 64-byte reports with a 3-byte header,
//!   fragmentation of larger frames across up to 5 reports, and the
//!   matching reassembly buffer.
//! - [`protocol`] — the KNX USB Transfer Protocol: the 8-byte header
//!   carried in the first report of every transfer, distinguishing the
//!   KNX tunnel (EMI frames) from the Bus Access Server feature service.
//! - [`bus_access`] — the Bus Access Server feature service frames used
//!   to query/set the interface's EMI type and bus status.
//!
//! Plus the [`KNOWN_KNX_DEVICES`] VID/PID table for interface discovery.
//!
//! Both sides of the USB cable share this module: the device stack's USB
//! host link layer (`zweidraehte-device`, embassy-driven) and the client
//! library's USB connector (`zweidraehte-client`, tokio-driven) each put
//! their own async transport around these primitives. Gated behind the
//! `usb-hid` feature.

pub mod bus_access;
pub mod hid;
pub mod protocol;

/// Known KNX USB interface vendor/product IDs
///
/// Taken from the Calimero project.
/// Device names are retrieved from USB device descriptors at runtime.
pub const KNOWN_KNX_DEVICES: &[(u16, u16)] = &[
    // VID 0x0111 - Makel Elektrik
    (0x0111, 0x1022), // Makel Elektrik
    // VID 0x0403 - FTDI
    (0x0403, 0x6898), // Tokka
    // VID 0x04CC - b+b Automations- und Steuerungstechnik
    (0x04CC, 0x0301), // b+b Automations- und Steuerungstechnik
    // VID 0x0681 - Siemens OCI700 interface (Synco family)
    (0x0681, 0x0014), // Siemens HVAC
    // VID 0x0908 - Siemens Automation & Drives
    (0x0908, 0x02DC), // Siemens HVAC
    (0x0908, 0x02DD), // Siemens
    (0x0908, 0x02E6), // Schrack Technik GmbH
    // VID 0x0E77 - Weinzierl Engineering GmbH
    (0x0E77, 0x0102), // Weinzierl Engineering GmbH
    (0x0E77, 0x0103), // Weinzierl Engineering GmbH
    (0x0E77, 0x0104), // GEWISS / Somfy / Weinzierl
    (0x0E77, 0x0111), // Siemens
    (0x0E77, 0x0112), // Siemens
    (0x0E77, 0x0115), // CONTROLtronic
    (0x0E77, 0x0117), // tecget
    (0x0E77, 0x0121), // Gustav Hensel GmbH & Co. KG
    (0x0E77, 0x0141), // Schneider Electric (MG)
    (0x0E77, 0x2001), // Weinzierl Engineering GmbH
    (0x0E77, 0x2002), // Gira
    (0x0E77, 0x6910), // Busch-Jaeger Elektro
    // VID 0x135E - Insta
    (0x135E, 0x0020), // Insta GmbH
    (0x135E, 0x0021), // Berker
    (0x135E, 0x0022), // GIRA Giersiepen
    (0x135E, 0x0023), // Albrecht Jung
    (0x135E, 0x0024), // Merten
    (0x135E, 0x0025), // Hager Electro
    (0x135E, 0x0026), // Feller
    (0x135E, 0x0027), // Panasonic
    (0x135E, 0x0028), // Glamox AS
    (0x135E, 0x0122), // GIRA Giersiepen
    (0x135E, 0x0123), // Albrecht Jung
    (0x135E, 0x0252), // Insta
    (0x135E, 0x0253), // Insta
    (0x135E, 0x0320), // Insta GmbH
    (0x135E, 0x0322), // GIRA Giersiepen
    (0x135E, 0x0323), // Albrecht Jung
    (0x135E, 0x0325), // Hager Electro
    (0x135E, 0x0326), // Feller
    (0x135E, 0x0329), // B.E.G.
    // VID 0x145C - Busch-Jaeger
    (0x145C, 0x1330), // Busch-Jaeger Elektro
    (0x145C, 0x1490), // Busch-Jaeger Elektro
    // VID 0x147B - ABB STOTZ-KONTAKT GmbH
    (0x147B, 0x2200), // ABB
    (0x147B, 0x5120), // ABB
    // VID 0x16D0 - MCS Electronics (OBSOLETE)
    (0x16D0, 0x0490), // TAPKO Technologies
    (0x16D0, 0x0491), // MDT technologies
    (0x16D0, 0x0492), // preussen automation
    // VID 0x16DE - Schneider Electric
    (0x16DE, 0x008E), // Schneider Electric Industries SAS
    // VID 0x24D5 - SATEL Ltd.
    (0x24D5, 0x0106), // Satel sp. z o.o.
    // VID 0x28C2 - Tapko Technologies GmbH
    (0x28C2, 0x0002), // Zennio
    (0x28C2, 0x0003), // Ekinex S.p.A.
    (0x28C2, 0x0004), // TAPKO Technologies
    (0x28C2, 0x0005), // Philips Controls
    (0x28C2, 0x0006), // HDL
    (0x28C2, 0x0007), // Niko-Zublin
    (0x28C2, 0x0008), // TAPKO Technologies
    (0x28C2, 0x000B), // VIVO
    (0x28C2, 0x000C), // ESYLUX
    (0x28C2, 0x000D), // VIVO
    (0x28C2, 0x000E), // APRICUM
    (0x28C2, 0x000F), // APRICUM
    (0x28C2, 0x0010), // Video-Star
    (0x28C2, 0x0011), // Griesser AG
    (0x28C2, 0x0012), // Griesser AG
    (0x28C2, 0x0013), // MEAN WELL Enterprises Co. Ltd.
    (0x28C2, 0x0014), // Ergo3 Sarl
    (0x28C2, 0x0015), // Bes - Ingenium
    (0x28C2, 0x0017), // Interra
    (0x28C2, 0x001A), // VIMAR
    (0x28C2, 0x001C), // OSix
    (0x28C2, 0x001D), // Panasonic
    (0x28C2, 0x001E), // Shenzhen HeGuang
    (0x28C2, 0x001F), // Module Electronic
    // VID 0x2A07 - ise GmbH
    (0x2A07, 0x0001), // ise GmbH
    (0x2A07, 0x0002), // Elsner Elektronik GmbH
    (0x2A07, 0x0003), // ise GmbH
    // VID 0x2D72 - DOGAWIST - Investment GmbH
    (0x2D72, 0x0002), // PEAKnx a DOGAWIST company
    // VID 0x7660 - KNX Association
    (0x7660, 0x0002), // KNX Association
];

/// Check if a VID:PID pair is a known KNX USB interface
pub fn is_known_knx_device(vendor_id: u16, product_id: u16) -> bool {
    KNOWN_KNX_DEVICES.iter().any(|(vid, pid)| *vid == vendor_id && *pid == product_id)
}
