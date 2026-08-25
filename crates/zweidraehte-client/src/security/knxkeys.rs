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

use aes::cipher::block_padding::{NoPadding, Pkcs7};
use aes::cipher::{BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use quick_xml::events::{BytesDecl, BytesEnd, BytesStart, Event};
use quick_xml::{Reader, Writer};
use sha2::{Digest, Sha256};
use zweidraehte_project::SecretBytes;

use zweidraehte_proto::address::IndividualAddress;

type Aes128CbcDec = cbc::Decryptor<aes::Aes128>;
type Aes128CbcEnc = cbc::Encryptor<aes::Aes128>;

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

    #[error("keyring export failed: {0}")]
    Export(String),
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
#[derive(Clone)]
pub struct KeyringBackbone {
    pub multicast_address: Option<String>,
    pub latency_ms: Option<u32>,
    /// Decrypted backbone key.
    key: Option<SecretBytes>,
}

/// One tunneling slot / interface entry (IP Secure tunneling material).
#[derive(Clone)]
pub struct KeyringInterface {
    pub interface_type: KeyringInterfaceType,
    pub individual_address: IndividualAddress,
    /// The hosting device's IA (the interface itself).
    pub host: Option<IndividualAddress>,
    pub user_id: Option<u8>,
    /// Decrypted user password.
    password: Option<SecretBytes>,
    /// Decrypted authentication code.
    authentication: Option<SecretBytes>,
    /// Group addresses assigned to this interface, with their senders.
    pub group_addresses: Vec<(u16, Vec<IndividualAddress>)>,
}

/// One device's security material.
#[derive(Clone)]
pub struct KeyringDevice {
    pub individual_address: IndividualAddress,
    /// Decrypted tool key (the commissioned key the device is on).
    tool_key: Option<SecretBytes>,
    /// Decrypted factory-default setup key.
    fdsk: Option<SecretBytes>,
    pub serial: Option<[u8; 6]>,
    /// The device's last observed sending sequence number at export.
    pub sequence_number: u64,
    management_password: Option<SecretBytes>,
    authentication: Option<SecretBytes>,
}

/// A parsed, signature-verified, decrypted `.knxkeys` keyring.
pub struct Keyring {
    pub project: String,
    pub created_by: String,
    pub created: String,
    pub backbone: Option<KeyringBackbone>,
    pub interfaces: Vec<KeyringInterface>,
    /// Decrypted group keys, by raw group address.
    group_keys: BTreeMap<u16, SecretBytes>,
    pub devices: Vec<KeyringDevice>,
}

impl KeyringBackbone {
    pub fn new(multicast_address: Option<String>, latency_ms: Option<u32>) -> Self {
        Self { multicast_address, latency_ms, key: None }
    }

    pub fn with_key(mut self, key: Option<[u8; 16]>) -> Self {
        self.key = key.map(SecretBytes::from);
        self
    }

    pub fn key(&self) -> Option<&[u8; 16]> {
        self.key.as_ref().map(|key| key.key16_ref().expect("backbone keys have fixed width"))
    }
}

impl KeyringInterface {
    pub fn new(interface_type: KeyringInterfaceType, individual_address: IndividualAddress) -> Self {
        Self {
            interface_type,
            individual_address,
            host: None,
            user_id: None,
            password: None,
            authentication: None,
            group_addresses: Vec::new(),
        }
    }

    pub fn with_host(mut self, host: Option<IndividualAddress>) -> Self {
        self.host = host;
        self
    }

    pub fn with_user_id(mut self, user_id: Option<u8>) -> Self {
        self.user_id = user_id;
        self
    }

    pub fn with_password(mut self, password: Option<String>) -> Self {
        self.password = password.map(SecretBytes::from);
        self
    }

    pub fn with_authentication(mut self, authentication: Option<String>) -> Self {
        self.authentication = authentication.map(SecretBytes::from);
        self
    }

    pub fn with_group_addresses(mut self, group_addresses: Vec<(u16, Vec<IndividualAddress>)>) -> Self {
        self.group_addresses = group_addresses;
        self
    }

    pub fn password(&self) -> Option<&str> {
        self.password.as_ref().map(|password| password.as_str().expect("password originated as UTF-8"))
    }

    pub fn authentication(&self) -> Option<&str> {
        self.authentication
            .as_ref()
            .map(|authentication| authentication.as_str().expect("authentication originated as UTF-8"))
    }
}

impl KeyringDevice {
    pub fn new(individual_address: IndividualAddress) -> Self {
        Self {
            individual_address,
            tool_key: None,
            fdsk: None,
            serial: None,
            sequence_number: 0,
            management_password: None,
            authentication: None,
        }
    }

    pub fn with_tool_key(mut self, tool_key: Option<[u8; 16]>) -> Self {
        self.tool_key = tool_key.map(SecretBytes::from);
        self
    }

    pub fn with_fdsk(mut self, fdsk: Option<[u8; 16]>) -> Self {
        self.fdsk = fdsk.map(SecretBytes::from);
        self
    }

    pub fn with_serial(mut self, serial: Option<[u8; 6]>) -> Self {
        self.serial = serial;
        self
    }

    pub fn with_sequence_number(mut self, sequence_number: u64) -> Self {
        self.sequence_number = sequence_number;
        self
    }

    pub fn with_management_password(mut self, management_password: Option<String>) -> Self {
        self.management_password = management_password.map(SecretBytes::from);
        self
    }

    pub fn with_authentication(mut self, authentication: Option<String>) -> Self {
        self.authentication = authentication.map(SecretBytes::from);
        self
    }

    pub fn tool_key(&self) -> Option<&[u8; 16]> {
        self.tool_key.as_ref().map(|key| key.key16_ref().expect("tool keys have fixed width"))
    }

    pub fn fdsk(&self) -> Option<&[u8; 16]> {
        self.fdsk.as_ref().map(|key| key.key16_ref().expect("FDSKs have fixed width"))
    }

    pub fn management_password(&self) -> Option<&str> {
        self.management_password.as_ref().map(|password| password.as_str().expect("password originated as UTF-8"))
    }

    pub fn authentication(&self) -> Option<&str> {
        self.authentication
            .as_ref()
            .map(|authentication| authentication.as_str().expect("authentication originated as UTF-8"))
    }
}

impl Keyring {
    pub fn new(project: String, created_by: String, created: String) -> Self {
        Self {
            project,
            created_by,
            created,
            backbone: None,
            interfaces: Vec::new(),
            group_keys: BTreeMap::new(),
            devices: Vec::new(),
        }
    }

    pub fn with_backbone(mut self, backbone: Option<KeyringBackbone>) -> Self {
        self.backbone = backbone;
        self
    }

    pub fn with_interfaces(mut self, interfaces: Vec<KeyringInterface>) -> Self {
        self.interfaces = interfaces;
        self
    }

    pub fn with_group_keys(mut self, group_keys: BTreeMap<u16, [u8; 16]>) -> Self {
        self.group_keys = group_keys.into_iter().map(|(address, key)| (address, SecretBytes::from(key))).collect();
        self
    }

    pub fn with_devices(mut self, devices: Vec<KeyringDevice>) -> Self {
        self.devices = devices;
        self
    }

    pub fn group_keys(&self) -> impl ExactSizeIterator<Item = (u16, &[u8; 16])> {
        self.group_keys.iter().map(|(&address, key)| (address, key.key16_ref().expect("group keys have fixed width")))
    }

    pub fn group_key(&self, address: u16) -> Option<&[u8; 16]> {
        self.group_keys.get(&address).map(|key| key.key16_ref().expect("group keys have fixed width"))
    }

    pub fn group_key_count(&self) -> usize {
        self.group_keys.len()
    }
}

impl core::fmt::Debug for KeyringBackbone {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("KeyringBackbone")
            .field("multicast_address", &self.multicast_address)
            .field("latency_ms", &self.latency_ms)
            .field("key", &self.key.as_ref().map(|_| "[REDACTED]"))
            .finish()
    }
}

impl core::fmt::Debug for KeyringInterface {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("KeyringInterface")
            .field("interface_type", &self.interface_type)
            .field("individual_address", &self.individual_address)
            .field("host", &self.host)
            .field("user_id", &self.user_id)
            .field("password", &self.password.as_ref().map(|_| "[REDACTED]"))
            .field("authentication", &self.authentication.as_ref().map(|_| "[REDACTED]"))
            .field("group_addresses", &self.group_addresses)
            .finish()
    }
}

impl core::fmt::Debug for KeyringDevice {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("KeyringDevice")
            .field("individual_address", &self.individual_address)
            .field("tool_key", &self.tool_key.as_ref().map(|_| "[REDACTED]"))
            .field("fdsk", &self.fdsk.as_ref().map(|_| "[REDACTED]"))
            .field("serial", &self.serial)
            .field("sequence_number", &self.sequence_number)
            .field("management_password", &self.management_password.as_ref().map(|_| "[REDACTED]"))
            .field("authentication", &self.authentication.as_ref().map(|_| "[REDACTED]"))
            .finish()
    }
}

impl core::fmt::Debug for Keyring {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("Keyring")
            .field("project", &self.project)
            .field("created_by", &self.created_by)
            .field("created", &self.created)
            .field("backbone", &self.backbone)
            .field("interfaces", &self.interfaces)
            .field("group_key_addresses", &self.group_keys.keys().collect::<Vec<_>>())
            .field("devices", &self.devices)
            .finish()
    }
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

    /// Render an ETS-compatible, password-protected `.knxkeys` document.
    ///
    /// `SequenceNumber` is the last value sent by each device, matching the
    /// public model and ETS' wire format. A project's commissioning-client
    /// counter is deliberately absent: the keyring schema has no field for it.
    pub fn to_xml(&self, password: &str) -> Result<String, KnxKeysError> {
        let password_hash = hash_keyring_password(password);
        let iv = created_iv(&self.created);
        let mut root = self.export_tree(&password_hash, &iv)?;

        // Signature does not include its own attribute, but does include the
        // password hash as one final length-prefixed value. This is the same
        // stream the parser reconstructs when it verifies an ETS export.
        let mut signature_stream = Vec::new();
        root.hash(&mut signature_stream);
        append_lp(&mut signature_stream, BASE64.encode(password_hash).as_bytes());
        let digest = Sha256::digest(&signature_stream);
        root.attributes.insert(3, ("Signature", BASE64.encode(&digest[..16])));

        let mut writer = Writer::new_with_indent(Vec::new(), b' ', 2);
        writer.write_event(Event::Decl(BytesDecl::new("1.0", Some("utf-8"), None)))?;
        root.write(&mut writer)?;
        let mut xml = String::from_utf8(writer.into_inner()).expect("XML writer only emits UTF-8");
        xml.push('\n');
        Ok(xml)
    }

    fn export_tree(&self, password_hash: &[u8; 16], iv: &[u8; 16]) -> Result<ExportElement, KnxKeysError> {
        let mut root = ExportElement::new("Keyring")
            .attribute("Project", self.project.clone())
            .attribute("CreatedBy", self.created_by.clone())
            .attribute("Created", self.created.clone())
            .attribute("xmlns", "http://knx.org/xml/keyring/1");

        if let Some(backbone) = &self.backbone {
            let mut element = ExportElement::new("Backbone");
            if let Some(address) = &backbone.multicast_address {
                element = element.attribute("MulticastAddress", address.clone());
            }
            if let Some(latency) = backbone.latency_ms {
                element = element.attribute("Latency", latency.to_string());
            }
            if let Some(key) = backbone.key() {
                element = element.attribute("Key", encrypt_key16(*key, password_hash, iv));
            }
            root.children.push(element);
        }

        for interface in &self.interfaces {
            let interface_type = match interface.interface_type {
                KeyringInterfaceType::Tunneling => "Tunneling",
                KeyringInterfaceType::Backbone => "Backbone",
                KeyringInterfaceType::Usb => "USB",
            };
            let mut element = ExportElement::new("Interface")
                .attribute("Type", interface_type)
                .attribute("IndividualAddress", interface.individual_address.to_string());
            if let Some(host) = interface.host {
                element = element.attribute("Host", host.to_string());
            }
            if let Some(user_id) = interface.user_id {
                element = element.attribute("UserID", user_id.to_string());
            }
            if let Some(password) = interface.password() {
                element = element.attribute("Password", encrypt_password(password, password_hash, iv)?);
            }
            if let Some(authentication) = interface.authentication() {
                element = element.attribute("Authentication", encrypt_password(authentication, password_hash, iv)?);
            }
            for (address, senders) in &interface.group_addresses {
                element.children.push(
                    ExportElement::new("Group")
                        .attribute("Address", address.to_string())
                        .attribute("Senders", senders.iter().map(ToString::to_string).collect::<Vec<_>>().join(" ")),
                );
            }
            root.children.push(element);
        }

        let mut groups = ExportElement::new("GroupAddresses");
        for (address, key) in self.group_keys() {
            groups.children.push(
                ExportElement::new("Group")
                    .attribute("Address", address.to_string())
                    .attribute("Key", encrypt_key16(*key, password_hash, iv)),
            );
        }
        root.children.push(groups);

        let mut devices = ExportElement::new("Devices");
        for device in &self.devices {
            let mut element =
                ExportElement::new("Device").attribute("IndividualAddress", device.individual_address.to_string());
            if let Some(tool_key) = device.tool_key() {
                element = element.attribute("ToolKey", encrypt_key16(*tool_key, password_hash, iv));
            }
            if let Some(password) = device.management_password() {
                element = element.attribute("ManagementPassword", encrypt_password(password, password_hash, iv)?);
            }
            if let Some(authentication) = device.authentication() {
                element = element.attribute("Authentication", encrypt_password(authentication, password_hash, iv)?);
            }
            element = element.attribute("SequenceNumber", device.sequence_number.to_string());
            if let Some(fdsk) = device.fdsk() {
                element = element.attribute("FDSK", encrypt_key16(*fdsk, password_hash, iv));
            }
            if let Some(serial) = device.serial {
                element = element
                    .attribute("SerialNumber", serial.iter().map(|byte| format!("{byte:02X}")).collect::<String>());
            }
            devices.children.push(element);
        }
        root.children.push(devices);
        Ok(root)
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

fn encrypt_key16(mut plaintext: [u8; 16], key: &[u8; 16], iv: &[u8; 16]) -> String {
    let encrypted = Aes128CbcEnc::new(key.into(), iv.into())
        .encrypt_padded_mut::<NoPadding>(&mut plaintext, 16)
        .expect("one AES block needs no padding");
    BASE64.encode(encrypted)
}

fn encrypt_password(value: &str, key: &[u8; 16], iv: &[u8; 16]) -> Result<String, KnxKeysError> {
    // ETS prefixes password-like values with eight opaque bytes before
    // PKCS#7 padding. Readers discard the prefix after decryption; making it
    // random prevents equal passwords in one export from sharing ciphertext.
    let mut plaintext = vec![0; 8 + value.len() + 16];
    getrandom::fill(&mut plaintext[..8]).map_err(|error| KnxKeysError::Export(format!("OS random source: {error}")))?;
    plaintext[8..8 + value.len()].copy_from_slice(value.as_bytes());
    let message_len = 8 + value.len();
    let encrypted = Aes128CbcEnc::new(key.into(), iv.into())
        .encrypt_padded_mut::<Pkcs7>(&mut plaintext, message_len)
        .map_err(|_| KnxKeysError::Export("password value is too large".into()))?;
    Ok(BASE64.encode(encrypted))
}

// ============================================================================
// XML export tree
// ============================================================================

struct ExportElement {
    name: &'static str,
    attributes: Vec<(&'static str, String)>,
    children: Vec<Self>,
}

impl ExportElement {
    fn new(name: &'static str) -> Self {
        Self { name, attributes: Vec::new(), children: Vec::new() }
    }

    fn attribute(mut self, name: &'static str, value: impl Into<String>) -> Self {
        self.attributes.push((name, value.into()));
        self
    }

    fn hash(&self, output: &mut Vec<u8>) {
        output.push(1);
        append_lp(output, self.name.as_bytes());
        let mut attributes =
            self.attributes.iter().filter(|(name, _)| *name != "xmlns" && *name != "Signature").collect::<Vec<_>>();
        attributes.sort_by_key(|(name, _)| name.as_bytes());
        for (name, value) in attributes {
            append_lp(output, name.as_bytes());
            append_lp(output, value.as_bytes());
        }
        for child in &self.children {
            child.hash(output);
        }
        output.push(2);
    }

    fn write(&self, writer: &mut Writer<Vec<u8>>) -> Result<(), KnxKeysError> {
        let mut start = BytesStart::new(self.name);
        for (name, value) in &self.attributes {
            start.push_attribute((*name, value.as_str()));
        }
        if self.children.is_empty() {
            writer.write_event(Event::Empty(start))?;
            return Ok(());
        }
        writer.write_event(Event::Start(start))?;
        for child in &self.children {
            child.write(writer)?;
        }
        writer.write_event(Event::End(BytesEnd::new(self.name)))?;
        Ok(())
    }
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
            Some(raw) => Some(
                KeyringBackbone::new(raw.multicast_address, raw.latency_ms)
                    .with_key(raw.key.map(|k| decrypt_key16(&k, key, iv, "Backbone Key")).transpose()?),
            ),
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
            interfaces.push(
                KeyringInterface::new(
                    interface_type,
                    parse_ia(&raw.individual_address, "Interface IndividualAddress")?,
                )
                .with_host(raw.host.map(|h| parse_ia(&h, "Interface Host")).transpose()?)
                .with_user_id(raw.user_id)
                .with_password(raw.password.map(|p| decrypt_password(&p, key, iv, "Interface Password")).transpose()?)
                .with_authentication(
                    raw.authentication
                        .map(|a| decrypt_password(&a, key, iv, "Interface Authentication"))
                        .transpose()?,
                )
                .with_group_addresses(raw.group_addresses),
            );
        }

        let mut group_keys = BTreeMap::new();
        for (address, b64) in self.group_keys {
            group_keys.insert(address, decrypt_key16(&b64, key, iv, "Group Key")?);
        }

        let mut devices = Vec::with_capacity(self.devices.len());
        for raw in self.devices {
            devices.push(
                KeyringDevice::new(parse_ia(&raw.individual_address, "Device IndividualAddress")?)
                    .with_tool_key(raw.tool_key.map(|k| decrypt_key16(&k, key, iv, "ToolKey")).transpose()?)
                    .with_fdsk(raw.fdsk.map(|k| decrypt_key16(&k, key, iv, "FDSK")).transpose()?)
                    .with_serial(raw.serial.map(|s| parse_serial(&s)).transpose()?)
                    .with_sequence_number(raw.sequence_number)
                    .with_management_password(
                        raw.management_password
                            .map(|p| decrypt_password(&p, key, iv, "ManagementPassword"))
                            .transpose()?,
                    )
                    .with_authentication(
                        raw.authentication
                            .map(|a| decrypt_password(&a, key, iv, "Device Authentication"))
                            .transpose()?,
                    ),
            );
        }

        Ok(Keyring::new(self.project, self.created_by, self.created)
            .with_backbone(backbone)
            .with_interfaces(interfaces)
            .with_group_keys(group_keys)
            .with_devices(devices))
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
        assert_eq!(keyring.group_key_count(), 2);
        assert!(keyring.group_key(2304).is_some());
        assert!(keyring.group_key(2305).is_some());

        let backbone = keyring.backbone.as_ref().expect("backbone element present");
        assert_eq!(backbone.multicast_address.as_deref(), Some("224.0.23.12"));
        assert!(backbone.key().is_none(), "fixture backbone has no key");
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
            assert_eq!(dev.fdsk(), Some(&DEV_FDSK), "FDSK of {ia} is the dev-provisioning default");
        }
    }

    #[test]
    fn device_attributes_parse() {
        let keyring = Keyring::parse(TESTSTAND_XML, PASSWORD).expect("fixture parses");

        // Exported without serial/FDSK: tool key + seq only.
        let partial = device(&keyring, "1.0.201");
        assert!(partial.tool_key().is_some());
        assert!(partial.fdsk().is_none());
        assert_eq!(partial.serial, None);
        assert_eq!(partial.sequence_number, 270477844941);

        // Fully exported device.
        let full = device(&keyring, "1.0.203");
        assert!(full.tool_key().is_some());
        assert_eq!(full.serial, Some([0x00, 0xFA, 0x00, 0x00, 0x00, 0x05]));
        assert_ne!(full.tool_key(), full.fdsk(), "commissioned tool key differs from the FDSK");
    }

    #[test]
    fn management_password_extracts() {
        let keyring = Keyring::parse(TESTSTAND_XML, PASSWORD).expect("fixture parses");
        let dev = device(&keyring, "0.0.2");
        let password = dev.management_password().expect("fixture carries a management password");
        assert!(!password.is_empty());
        let auth = dev.authentication().expect("fixture carries an authentication code");
        assert!(!auth.is_empty());
    }

    #[test]
    fn exported_keyring_round_trips_every_supported_secret() {
        let expected = Keyring::new("Bench & workshop".into(), "zweidraehte".into(), "2026-08-25T12:34:56".into())
            .with_backbone(Some(KeyringBackbone::new(Some("224.0.23.12".into()), Some(50)).with_key(Some([0x10; 16]))))
            .with_interfaces(vec![
                KeyringInterface::new(KeyringInterfaceType::Tunneling, IndividualAddress::new(1, 0, 2))
                    .with_host(Some(IndividualAddress::new(1, 0, 1)))
                    .with_user_id(Some(2))
                    .with_password(Some("tunnel password".into()))
                    .with_authentication(Some("authentication code".into()))
                    .with_group_addresses(vec![(1, vec![IndividualAddress::new(1, 0, 10)])]),
            ])
            .with_group_keys(BTreeMap::from([(1, [0x20; 16])]))
            .with_devices(vec![
                KeyringDevice::new(IndividualAddress::new(1, 0, 10))
                    .with_tool_key(Some([0x30; 16]))
                    .with_fdsk(Some([0x40; 16]))
                    .with_serial(Some([0x00, 0xFA, 0, 0, 0, 1]))
                    .with_sequence_number(1234)
                    .with_management_password(Some("management password".into()))
                    .with_authentication(Some("device authentication".into())),
            ]);

        let xml = expected.to_xml(PASSWORD).expect("keyring exports");
        let actual = Keyring::parse(&xml, PASSWORD).expect("export signature verifies");
        assert_eq!(actual.project, expected.project);
        assert_eq!(actual.created_by, expected.created_by);
        assert_eq!(actual.created, expected.created);
        assert_eq!(actual.group_keys().collect::<Vec<_>>(), expected.group_keys().collect::<Vec<_>>());
        let actual_device = &actual.devices[0];
        let expected_device = &expected.devices[0];
        assert_eq!(actual_device.individual_address, expected_device.individual_address);
        assert_eq!(actual_device.tool_key(), expected_device.tool_key());
        assert_eq!(actual_device.fdsk(), expected_device.fdsk());
        assert_eq!(actual_device.serial, expected_device.serial);
        assert_eq!(actual_device.sequence_number, expected_device.sequence_number);
        assert_eq!(actual_device.management_password(), expected_device.management_password());
        assert_eq!(actual_device.authentication(), expected_device.authentication());
        assert_eq!(actual.interfaces[0].password(), expected.interfaces[0].password());
        assert_eq!(actual.interfaces[0].authentication(), expected.interfaces[0].authentication());
        assert!(matches!(Keyring::parse(&xml, "wrong"), Err(KnxKeysError::SignatureMismatch)));
    }

    #[test]
    fn debug_redacts_every_keyring_secret() {
        let keyring = Keyring::new("canary project".into(), "test".into(), "now".into())
            .with_backbone(Some(KeyringBackbone::new(None, None).with_key(Some([0xDE; 16]))))
            .with_interfaces(vec![
                KeyringInterface::new(KeyringInterfaceType::Tunneling, IndividualAddress::new(1, 1, 1))
                    .with_password(Some("swordfish".into()))
                    .with_authentication(Some("interface-canary".into())),
            ])
            .with_group_keys(BTreeMap::from([(1, [0xAD; 16])]))
            .with_devices(vec![
                KeyringDevice::new(IndividualAddress::new(1, 1, 2))
                    .with_tool_key(Some([0xBE; 16]))
                    .with_fdsk(Some([0xEF; 16]))
                    .with_sequence_number(1)
                    .with_management_password(Some("management-canary".into()))
                    .with_authentication(Some("device-canary".into())),
            ]);
        let debug = format!("{keyring:?}");
        for secret in ["swordfish", "interface-canary", "management-canary", "device-canary", "222", "173"] {
            assert!(!debug.contains(secret), "debug output contains `{secret}`: {debug}");
        }
    }
}
