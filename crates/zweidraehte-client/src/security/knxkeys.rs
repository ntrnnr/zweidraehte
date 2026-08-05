//! `.knxkeys` keyring parsing and decryption.
//!
//! ETS exports a project's security material as a password-protected
//! XML keyring (namespace `http://knx.org/xml/keyring/1`). All key
//! material in it is AES-128-CBC encrypted under a PBKDF2 hash of the
//! export password, and the whole document is integrity-protected by a
//! SHA-256-based signature that includes that password hash — so a
//! successful signature check also proves the password is right.
//!
//! Format and crypto verified against the two reference
//! implementations (xknx `secure/keyring.py`, Calimero
//! `secure/Keyring.java`) and real ETS 6.4.1 output:
//!
//! - password hash: PBKDF2-HMAC-SHA256(password,
//!   salt = `"1.keyring.ets.knx.org"`, 65 536 iterations) → 16 bytes
//! - IV: SHA-256(`Created` attribute)\[..16\]
//! - key attributes (ToolKey, group Key, backbone Key, FDSK):
//!   base64 → AES-128-CBC, exactly one block, no padding
//! - password attributes (ManagementPassword, Authentication,
//!   interface Password): base64 → AES-128-CBC → drop an 8-byte
//!   prefix, strip PKCS#7 padding → UTF-8
//! - signature: a length-prefixed byte stream over the document (see
//!   `RawKeyring::hash_element`), SHA-256\[..16\] against the
//!   `Signature` attribute
//!
//! `FDSK` and `SerialNumber` on `<Device>` are ETS 6.x additions the
//! reference implementations don't read yet; they decrypt/parse like
//! the rest and are exactly what [`super::SecurityEntry`] wants.

use std::collections::BTreeMap;
use std::path::Path;

use aes::cipher::block_padding::NoPadding;
use aes::cipher::{BlockDecryptMut, KeyIvInit};
use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use quick_xml::Reader;
use quick_xml::events::{BytesStart, Event};
use sha2::{Digest, Sha256};

use zweidraehte_proto::address::IndividualAddress;

type Aes128CbcDec = cbc::Decryptor<aes::Aes128>;

#[derive(Debug, thiserror::Error)]
pub enum KnxKeysError {
    #[error("while reading the keyring file: {0}")]
    Io(#[from] std::io::Error),

    #[error("keyring XML is malformed: {0}")]
    Xml(String),

    #[error("keyring signature mismatch (wrong password or tampered file)")]
    SignatureMismatch,

    #[error("keyring attribute is malformed: {0}")]
    MalformedAttribute(&'static str),
}

impl From<quick_xml::Error> for KnxKeysError {
    fn from(e: quick_xml::Error) -> Self {
        Self::Xml(e.to_string())
    }
}

/// The interface types a keyring can describe.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyringInterfaceType {
    Tunneling,
    Backbone,
    Usb,
}

/// The KNXnet/IP backbone entry (IP Secure routing material).
#[derive(Debug, Clone)]
pub struct KeyringBackbone {
    pub multicast_address: Option<String>,
    pub latency_ms: Option<u32>,
    /// Decrypted backbone key.
    pub key: Option<[u8; 16]>,
}

/// One tunneling slot / interface entry (IP Secure tunneling material).
#[derive(Debug, Clone)]
pub struct KeyringInterface {
    pub interface_type: KeyringInterfaceType,
    pub individual_address: IndividualAddress,
    /// The hosting device's IA (the interface itself).
    pub host: Option<IndividualAddress>,
    pub user_id: Option<u8>,
    /// Decrypted user password.
    pub password: Option<String>,
    /// Decrypted authentication code.
    pub authentication: Option<String>,
    /// Group addresses assigned to this interface, with their senders.
    pub group_addresses: Vec<(u16, Vec<IndividualAddress>)>,
}

/// One device's security material.
#[derive(Debug, Clone)]
pub struct KeyringDevice {
    pub individual_address: IndividualAddress,
    /// Decrypted tool key (the commissioned key the device is on).
    pub tool_key: Option<[u8; 16]>,
    /// Decrypted factory-default setup key.
    pub fdsk: Option<[u8; 16]>,
    pub serial: Option<[u8; 6]>,
    /// The device's last observed sending sequence number at export.
    pub sequence_number: u64,
    pub management_password: Option<String>,
    pub authentication: Option<String>,
}

/// A parsed, signature-verified, decrypted `.knxkeys` keyring.
#[derive(Debug)]
pub struct Keyring {
    pub project: String,
    pub created_by: String,
    pub created: String,
    pub backbone: Option<KeyringBackbone>,
    pub interfaces: Vec<KeyringInterface>,
    /// Decrypted group keys, by raw group address.
    pub group_keys: BTreeMap<u16, [u8; 16]>,
    pub devices: Vec<KeyringDevice>,
}

impl Keyring {
    /// Read and [`parse`](Self::parse) a keyring file.
    pub fn load(path: impl AsRef<Path>, password: &str) -> Result<Self, KnxKeysError> {
        let xml = std::fs::read_to_string(path)?;
        Self::parse(&xml, password)
    }

    /// Parse a keyring document, verify its signature against
    /// `password`, and decrypt all key material.
    pub fn parse(xml: &str, password: &str) -> Result<Self, KnxKeysError> {
        // ETS writes a UTF-8 BOM; it is not part of the document.
        let xml = xml.trim_start_matches('\u{feff}');

        let password_hash = hash_keyring_password(password);

        let mut raw = RawKeyring::parse(xml)?;

        // The signature stream ends with the base64 of the password
        // hash, so one comparison verifies integrity AND password.
        let mut sig_input = std::mem::take(&mut raw.signature_stream);
        append_lp(&mut sig_input, BASE64.encode(password_hash).as_bytes());
        let digest = Sha256::digest(&sig_input);
        let signature = BASE64.decode(&raw.signature).map_err(|_| KnxKeysError::MalformedAttribute("Signature"))?;
        if digest[..16] != signature[..] {
            return Err(KnxKeysError::SignatureMismatch);
        }

        let iv = created_iv(&raw.created);
        raw.decrypt(&password_hash, &iv)
    }
}

// ============================================================================
// Crypto helpers
// ============================================================================

fn hash_keyring_password(password: &str) -> [u8; 16] {
    let mut out = [0u8; 16];
    pbkdf2::pbkdf2_hmac::<Sha256>(password.as_bytes(), b"1.keyring.ets.knx.org", 65_536, &mut out);
    out
}

fn created_iv(created: &str) -> [u8; 16] {
    let digest = Sha256::digest(created.as_bytes());
    digest[..16].try_into().expect("SHA-256 digest holds 32 bytes")
}

fn decrypt_blocks(b64: &str, key: &[u8; 16], iv: &[u8; 16], what: &'static str) -> Result<Vec<u8>, KnxKeysError> {
    let mut data = BASE64.decode(b64).map_err(|_| KnxKeysError::MalformedAttribute(what))?;
    if data.is_empty() || data.len() % 16 != 0 {
        return Err(KnxKeysError::MalformedAttribute(what));
    }
    Aes128CbcDec::new(key.into(), iv.into())
        .decrypt_padded_mut::<NoPadding>(&mut data)
        .map_err(|_| KnxKeysError::MalformedAttribute(what))?;
    Ok(data)
}

/// Decrypt a 16-byte key attribute.
fn decrypt_key16(b64: &str, key: &[u8; 16], iv: &[u8; 16], what: &'static str) -> Result<[u8; 16], KnxKeysError> {
    decrypt_blocks(b64, key, iv, what)?.try_into().map_err(|_| KnxKeysError::MalformedAttribute(what))
}

/// Decrypt a password attribute: 8-byte prefix + UTF-8 password +
/// PKCS#7 padding.
fn decrypt_password(b64: &str, key: &[u8; 16], iv: &[u8; 16], what: &'static str) -> Result<String, KnxKeysError> {
    let data = decrypt_blocks(b64, key, iv, what)?;
    let pad = *data.last().expect("decrypt_blocks rejects empty input") as usize;
    if pad == 0 || data.len() < 8 + pad {
        return Err(KnxKeysError::MalformedAttribute(what));
    }
    String::from_utf8(data[8..data.len() - pad].to_vec()).map_err(|_| KnxKeysError::MalformedAttribute(what))
}

// ============================================================================
// Attribute value parsing
// ============================================================================

fn parse_ia(s: &str, what: &'static str) -> Result<IndividualAddress, KnxKeysError> {
    let parts: Vec<&str> = s.split('.').collect();
    let [area, line, device] = parts[..] else {
        return Err(KnxKeysError::MalformedAttribute(what));
    };
    let (Ok(area), Ok(line), Ok(device)) = (area.parse::<u8>(), line.parse::<u8>(), device.parse::<u8>()) else {
        return Err(KnxKeysError::MalformedAttribute(what));
    };
    if area > 15 || line > 15 {
        return Err(KnxKeysError::MalformedAttribute(what));
    }
    Ok(IndividualAddress::new(area, line, device))
}

fn parse_serial(s: &str) -> Result<[u8; 6], KnxKeysError> {
    if s.len() != 12 {
        return Err(KnxKeysError::MalformedAttribute("SerialNumber"));
    }
    let mut out = [0u8; 6];
    for (i, chunk) in out.iter_mut().enumerate() {
        *chunk = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16)
            .map_err(|_| KnxKeysError::MalformedAttribute("SerialNumber"))?;
    }
    Ok(out)
}

// ============================================================================
// XML parsing (single pass: signature stream + raw data)
// ============================================================================

/// Append one length-prefixed string to the signature stream.
///
/// The length is a single byte — attribute names and values in a
/// keyring are far below 256 bytes, and this matches what ETS signs.
fn append_lp(out: &mut Vec<u8>, value: &[u8]) {
    debug_assert!(value.len() <= u8::MAX as usize, "keyring signature strings fit one length byte");
    out.push(value.len() as u8);
    out.extend_from_slice(value);
}

/// Encrypted-attribute string as found in the XML (decrypted later).
#[derive(Default)]
struct RawDevice {
    individual_address: String,
    tool_key: Option<String>,
    fdsk: Option<String>,
    serial: Option<String>,
    sequence_number: u64,
    management_password: Option<String>,
    authentication: Option<String>,
}

#[derive(Default)]
struct RawInterface {
    interface_type: String,
    individual_address: String,
    host: Option<String>,
    user_id: Option<u8>,
    password: Option<String>,
    authentication: Option<String>,
    group_addresses: Vec<(u16, Vec<IndividualAddress>)>,
}

#[derive(Default)]
struct RawBackbone {
    multicast_address: Option<String>,
    latency_ms: Option<u32>,
    key: Option<String>,
}

#[derive(Default)]
struct RawKeyring {
    project: String,
    created_by: String,
    created: String,
    signature: String,
    backbone: Option<RawBackbone>,
    interfaces: Vec<RawInterface>,
    group_keys: Vec<(u16, String)>,
    devices: Vec<RawDevice>,
    signature_stream: Vec<u8>,
}

/// Which container element we are currently inside.
#[derive(PartialEq)]
enum Section {
    Top,
    Devices,
    GroupAddresses,
    Interface,
}

impl RawKeyring {
    fn parse(xml: &str) -> Result<Self, KnxKeysError> {
        let mut reader = Reader::from_str(xml);
        let mut raw = RawKeyring::default();
        let mut section = Section::Top;

        loop {
            match reader.read_event()? {
                Event::Start(el) => {
                    raw.hash_element(&el)?;
                    raw.dispatch_element(&el, &mut section, false)?;
                }
                Event::Empty(el) => {
                    // A self-closing element signs as start + end.
                    raw.hash_element(&el)?;
                    raw.signature_stream.push(2);
                    raw.dispatch_element(&el, &mut section, true)?;
                }
                Event::End(el) => {
                    raw.signature_stream.push(2);
                    match el.local_name().as_ref() {
                        b"Devices" | b"GroupAddresses" => section = Section::Top,
                        b"Interface" => section = Section::Top,
                        _ => {}
                    }
                }
                Event::Eof => break,
                // Text, comments, the XML declaration and processing
                // instructions are not part of the signature.
                _ => {}
            }
        }

        Ok(raw)
    }

    /// Contribute one element to the signature stream: 0x01 + tag, then
    /// each attribute (sorted by name, minus `xmlns` and `Signature`)
    /// as length-prefixed name + value.
    fn hash_element(&mut self, el: &BytesStart<'_>) -> Result<(), KnxKeysError> {
        self.signature_stream.push(1);
        append_lp(&mut self.signature_stream, el.name().as_ref());

        let mut attrs: Vec<(Vec<u8>, String)> = Vec::new();
        for attr in el.attributes() {
            let attr = attr.map_err(|e| KnxKeysError::Xml(e.to_string()))?;
            let name = attr.key.as_ref().to_vec();
            if name == b"xmlns" || name == b"Signature" {
                continue;
            }
            let value = attr.unescape_value().map_err(|e| KnxKeysError::Xml(e.to_string()))?.into_owned();
            attrs.push((name, value));
        }
        attrs.sort_by(|a, b| a.0.cmp(&b.0));
        for (name, value) in &attrs {
            append_lp(&mut self.signature_stream, name);
            append_lp(&mut self.signature_stream, value.as_bytes());
        }
        Ok(())
    }

    fn dispatch_element(
        &mut self,
        el: &BytesStart<'_>,
        section: &mut Section,
        self_closing: bool,
    ) -> Result<(), KnxKeysError> {
        let get = |name: &[u8]| -> Result<Option<String>, KnxKeysError> {
            for attr in el.attributes() {
                let attr = attr.map_err(|e| KnxKeysError::Xml(e.to_string()))?;
                if attr.key.as_ref() == name {
                    return Ok(Some(attr.unescape_value().map_err(|e| KnxKeysError::Xml(e.to_string()))?.into_owned()));
                }
            }
            Ok(None)
        };
        let require = |name: &[u8], what: &'static str| -> Result<String, KnxKeysError> {
            get(name)?.ok_or(KnxKeysError::MalformedAttribute(what))
        };

        match el.local_name().as_ref() {
            b"Keyring" => {
                self.project = require(b"Project", "Project")?;
                self.created_by = require(b"CreatedBy", "CreatedBy")?;
                self.created = require(b"Created", "Created")?;
                self.signature = require(b"Signature", "Signature")?;
            }
            b"Backbone" => {
                let latency_ms = match get(b"Latency")? {
                    Some(s) => Some(s.parse().map_err(|_| KnxKeysError::MalformedAttribute("Latency"))?),
                    None => None,
                };
                self.backbone =
                    Some(RawBackbone { multicast_address: get(b"MulticastAddress")?, latency_ms, key: get(b"Key")? });
            }
            b"Interface" => {
                let user_id = match get(b"UserID")? {
                    Some(s) => Some(s.parse().map_err(|_| KnxKeysError::MalformedAttribute("UserID"))?),
                    None => None,
                };
                self.interfaces.push(RawInterface {
                    interface_type: require(b"Type", "Interface Type")?,
                    individual_address: require(b"IndividualAddress", "Interface IndividualAddress")?,
                    host: get(b"Host")?,
                    user_id,
                    password: get(b"Password")?,
                    authentication: get(b"Authentication")?,
                    group_addresses: Vec::new(),
                });
                if !self_closing {
                    *section = Section::Interface;
                }
            }
            b"Devices" if !self_closing => *section = Section::Devices,
            b"GroupAddresses" if !self_closing => *section = Section::GroupAddresses,
            b"Group" => {
                let address: u16 = require(b"Address", "Group Address")?
                    .parse()
                    .map_err(|_| KnxKeysError::MalformedAttribute("Group Address"))?;
                match section {
                    // <GroupAddresses><Group Address Key>: a group key.
                    Section::GroupAddresses => {
                        self.group_keys.push((address, require(b"Key", "Group Key")?));
                    }
                    // <Interface><Group Address Senders>: an assignment.
                    Section::Interface => {
                        let mut senders = Vec::new();
                        for ia in get(b"Senders")?.unwrap_or_default().split_whitespace() {
                            senders.push(parse_ia(ia, "Group Senders")?);
                        }
                        let interface = self.interfaces.last_mut().expect("Interface section implies an entry");
                        interface.group_addresses.push((address, senders));
                    }
                    _ => return Err(KnxKeysError::Xml("Group element outside any container".into())),
                }
            }
            b"Device" if *section == Section::Devices => {
                let sequence_number = match get(b"SequenceNumber")? {
                    Some(s) => s.parse().map_err(|_| KnxKeysError::MalformedAttribute("SequenceNumber"))?,
                    None => 0,
                };
                self.devices.push(RawDevice {
                    individual_address: require(b"IndividualAddress", "Device IndividualAddress")?,
                    tool_key: get(b"ToolKey")?,
                    fdsk: get(b"FDSK")?,
                    serial: get(b"SerialNumber")?,
                    sequence_number,
                    management_password: get(b"ManagementPassword")?,
                    authentication: get(b"Authentication")?,
                });
            }
            _ => {}
        }
        Ok(())
    }

    /// Turn the raw (still encrypted) form into the public one.
    fn decrypt(self, key: &[u8; 16], iv: &[u8; 16]) -> Result<Keyring, KnxKeysError> {
        let backbone = match self.backbone {
            Some(raw) => Some(KeyringBackbone {
                multicast_address: raw.multicast_address,
                latency_ms: raw.latency_ms,
                key: raw.key.map(|k| decrypt_key16(&k, key, iv, "Backbone Key")).transpose()?,
            }),
            None => None,
        };

        let mut interfaces = Vec::with_capacity(self.interfaces.len());
        for raw in self.interfaces {
            let interface_type = match raw.interface_type.as_str() {
                "Tunneling" => KeyringInterfaceType::Tunneling,
                "Backbone" => KeyringInterfaceType::Backbone,
                "USB" => KeyringInterfaceType::Usb,
                _ => return Err(KnxKeysError::MalformedAttribute("Interface Type")),
            };
            interfaces.push(KeyringInterface {
                interface_type,
                individual_address: parse_ia(&raw.individual_address, "Interface IndividualAddress")?,
                host: raw.host.map(|h| parse_ia(&h, "Interface Host")).transpose()?,
                user_id: raw.user_id,
                password: raw.password.map(|p| decrypt_password(&p, key, iv, "Interface Password")).transpose()?,
                authentication: raw
                    .authentication
                    .map(|a| decrypt_password(&a, key, iv, "Interface Authentication"))
                    .transpose()?,
                group_addresses: raw.group_addresses,
            });
        }

        let mut group_keys = BTreeMap::new();
        for (address, b64) in self.group_keys {
            group_keys.insert(address, decrypt_key16(&b64, key, iv, "Group Key")?);
        }

        let mut devices = Vec::with_capacity(self.devices.len());
        for raw in self.devices {
            devices.push(KeyringDevice {
                individual_address: parse_ia(&raw.individual_address, "Device IndividualAddress")?,
                tool_key: raw.tool_key.map(|k| decrypt_key16(&k, key, iv, "ToolKey")).transpose()?,
                fdsk: raw.fdsk.map(|k| decrypt_key16(&k, key, iv, "FDSK")).transpose()?,
                serial: raw.serial.map(|s| parse_serial(&s)).transpose()?,
                sequence_number: raw.sequence_number,
                management_password: raw
                    .management_password
                    .map(|p| decrypt_password(&p, key, iv, "ManagementPassword"))
                    .transpose()?,
                authentication: raw
                    .authentication
                    .map(|a| decrypt_password(&a, key, iv, "Device Authentication"))
                    .transpose()?,
            });
        }

        Ok(Keyring {
            project: self.project,
            created_by: self.created_by,
            created: self.created,
            backbone,
            interfaces,
            group_keys,
            devices,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A real ETS 6.4.1 export from the "Teststand Mobil" test-bench
    /// project, password `d`. The 00FA-serial devices are this repo's
    /// dev-provisioned hardware, whose FDSK is the dev-provisioning
    /// default (`firmware/common/dev-provisioning-build`) — decrypting
    /// them cross-checks the whole chain against ETS output.
    const TESTSTAND_XML: &str = r#"<?xml version="1.0" encoding="utf-8"?>
<Keyring Project="Teststand Mobil" CreatedBy="6.4.1" Created="2026-08-05T01:12:58" Signature="kVZvnYrIYWRh7GRxDnMIvg==" xmlns="http://knx.org/xml/keyring/1">
  <Backbone MulticastAddress="224.0.23.12" />
  <GroupAddresses>
    <Group Address="2304" Key="Zy5k4aDGCd/En2iumka2Bw==" />
    <Group Address="2305" Key="BWKEHVc7a7HshpF/zIdWJA==" />
  </GroupAddresses>
  <Devices>
    <Device IndividualAddress="0.0.2" ToolKey="7SeMxq0GEPqHa85NuHVdYg==" ManagementPassword="vVd4/uyQgCQFyIRoKAS/XNayeJ8Lnrm8A+SLGmX0z8w=" Authentication="OGFdxmxDgII2pcw8AiGTG5MLlnUt41se6jBp1IVC+LI=" SequenceNumber="269705666847" FDSK="FbgBKwXE5E2suGC90hyx8w==" SerialNumber="00FA00000009" />
    <Device IndividualAddress="1.0.201" ToolKey="zg4+Vz1sT0zmjyh+p+jh5Q==" SequenceNumber="270477844941" />
    <Device IndividualAddress="1.0.203" ToolKey="4UkE8E/bb3N35HL+fhi9+Q==" SequenceNumber="270744056970" FDSK="FbgBKwXE5E2suGC90hyx8w==" SerialNumber="00FA00000005" />
    <Device IndividualAddress="1.2.4" ToolKey="7UwEYyTTw1Lbb/8kreioYw==" SequenceNumber="270744374244" FDSK="FbgBKwXE5E2suGC90hyx8w==" SerialNumber="00FA00000004" />
  </Devices>
</Keyring>"#;

    const PASSWORD: &str = "d";

    /// The dev-provisioning DEFAULT_FDSK
    /// (`firmware/common/dev-provisioning-build/src/lib.rs`).
    const DEV_FDSK: [u8; 16] = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, //
        0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
    ];

    fn device<'a>(keyring: &'a Keyring, ia: &str) -> &'a KeyringDevice {
        let ia = parse_ia(ia, "test").expect("valid test IA");
        keyring.devices.iter().find(|d| d.individual_address == ia).expect("device present in fixture")
    }

    #[test]
    fn real_ets_export_parses_and_verifies() {
        let keyring = Keyring::parse(TESTSTAND_XML, PASSWORD).expect("signature verifies with the right password");

        assert_eq!(keyring.project, "Teststand Mobil");
        assert_eq!(keyring.created_by, "6.4.1");
        assert_eq!(keyring.devices.len(), 4);
        assert_eq!(keyring.group_keys.len(), 2);
        assert!(keyring.group_keys.contains_key(&2304));
        assert!(keyring.group_keys.contains_key(&2305));

        let backbone = keyring.backbone.as_ref().expect("backbone element present");
        assert_eq!(backbone.multicast_address.as_deref(), Some("224.0.23.12"));
        assert!(backbone.key.is_none(), "fixture backbone has no key");
    }

    #[test]
    fn wrong_password_fails_signature() {
        assert!(matches!(Keyring::parse(TESTSTAND_XML, "wrong"), Err(KnxKeysError::SignatureMismatch)));
    }

    #[test]
    fn tampered_content_fails_signature() {
        let tampered = TESTSTAND_XML.replace("IndividualAddress=\"1.2.4\"", "IndividualAddress=\"1.2.5\"");
        assert!(matches!(Keyring::parse(&tampered, PASSWORD), Err(KnxKeysError::SignatureMismatch)));
    }

    #[test]
    fn dev_provisioned_fdsk_decrypts_to_default() {
        let keyring = Keyring::parse(TESTSTAND_XML, PASSWORD).expect("fixture parses");

        // All three 00FA dev devices share the provisioning default.
        for ia in ["0.0.2", "1.0.203", "1.2.4"] {
            let dev = device(&keyring, ia);
            assert_eq!(dev.fdsk, Some(DEV_FDSK), "FDSK of {ia} is the dev-provisioning default");
        }
    }

    #[test]
    fn device_attributes_parse() {
        let keyring = Keyring::parse(TESTSTAND_XML, PASSWORD).expect("fixture parses");

        // Exported without serial/FDSK: tool key + seq only.
        let partial = device(&keyring, "1.0.201");
        assert!(partial.tool_key.is_some());
        assert!(partial.fdsk.is_none());
        assert_eq!(partial.serial, None);
        assert_eq!(partial.sequence_number, 270477844941);

        // Fully exported device.
        let full = device(&keyring, "1.0.203");
        assert!(full.tool_key.is_some());
        assert_eq!(full.serial, Some([0x00, 0xFA, 0x00, 0x00, 0x00, 0x05]));
        assert_ne!(full.tool_key, full.fdsk, "commissioned tool key differs from the FDSK");
    }

    #[test]
    fn management_password_extracts() {
        let keyring = Keyring::parse(TESTSTAND_XML, PASSWORD).expect("fixture parses");
        let dev = device(&keyring, "0.0.2");
        let password = dev.management_password.as_ref().expect("fixture carries a management password");
        assert!(!password.is_empty());
        let auth = dev.authentication.as_ref().expect("fixture carries an authentication code");
        assert!(!auth.is_empty());
    }
}
