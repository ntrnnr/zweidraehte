//! Serde mirror of the EITT conformance template XML.
//!
//! Deserialised with `quick_xml::de`, using the `@Attr` rename
//! convention already established in
//! `crates/zweidraehte-ets-files/src/schema/core.rs`.
//!
//! Only what we execute is modelled. `Header`, `History` and
//! `Interfaces` are kept because the version/date in them is the single
//! most useful thing to print when a run disagrees with expectations —
//! "which revision of the template is this?" is the first question.
//!
//! Every field that the templates leave empty in some places
//! (`Activate`, `Medium`, `Comment`, …) is `Option`, and the *meaning*
//! of an absent value is decided in [`super::lower`], never here.

use serde::Deserialize;

/// Root element, `<EITT_KnxConformanceTests>`.
#[derive(Debug, Clone, Deserialize)]
pub struct Template {
    #[serde(rename = "@Name")]
    pub name: Option<String>,
    /// Template revision. Independent of the KNX standard version in
    /// [`Header::volume`] — the template is revised far more often.
    #[serde(rename = "@Version")]
    pub version: Option<String>,
    #[serde(rename = "@DateOfVersion")]
    pub date_of_version: Option<String>,
    #[serde(rename = "@MinEITTVersion")]
    pub min_eitt_version: Option<String>,

    #[serde(rename = "Header")]
    pub header: Option<Header>,
    #[serde(rename = "History")]
    pub history: Option<History>,
    /// The tool interfaces a telegram's `Connection` refers to.
    #[serde(rename = "Interfaces")]
    pub interfaces: Option<Interfaces>,
    /// Template-global variables.
    #[serde(rename = "Fields", default)]
    pub fields: Vec<Fields>,
    #[serde(rename = "TestCollections")]
    pub test_collections: Option<TestCollections>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Header {
    #[serde(rename = "KNXStandard")]
    pub knx_standard: Option<String>,
    /// The specification chapter this template realises, e.g.
    /// "08_03_07 System Conformance Testing - AIL and Management Tests".
    #[serde(rename = "Volume")]
    pub volume: Option<String>,
    /// A template may realise several application notes at once — the
    /// Data Security one names six — so this repeats.
    #[serde(rename = "ApplicationNote", default)]
    pub application_note: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct History {
    #[serde(rename = "Hitem", default)]
    pub items: Vec<HistoryItem>,
}

/// One changelog entry. Worth surfacing: these say in one line what
/// changed between template revisions, which is the cheapest way to
/// find out why a case we used to pass now behaves differently.
#[derive(Debug, Clone, Deserialize)]
pub struct HistoryItem {
    #[serde(rename = "@Version")]
    pub version: Option<String>,
    #[serde(rename = "@Date")]
    pub date: Option<String>,
    #[serde(rename = "@Who")]
    pub who: Option<String>,
    #[serde(rename = "@Change")]
    pub change: Option<String>,
}

// ============================================================================
// Interfaces
// ============================================================================

/// The tool-side bus connections a template uses.
///
/// EITT drives up to two KNX interfaces so that a test can play two
/// remote devices at once; the transport-layer template needs that for
/// every "during an existing connection" case. Each `Telegram` names
/// the one it belongs to in [`Telegram::connection`].
#[derive(Debug, Clone, Deserialize)]
pub struct Interfaces {
    #[serde(rename = "Interface", default)]
    pub interfaces: Vec<Interface>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Interface {
    /// Referenced from `Telegram/@Connection`, `#IFACE0` style.
    #[serde(rename = "@Name")]
    pub name: Option<String>,
    #[serde(rename = "@DisplayName")]
    pub display_name: Option<String>,
    #[serde(rename = "@Comment")]
    pub comment: Option<String>,
}

// ============================================================================
// Variables
// ============================================================================

/// A `<Fields>` block. Appears once at template level and once per
/// collection; collection-level entries shadow template-level ones.
///
/// The two field kinds interleave freely in the templates, so this is a
/// single ordered list rather than one `Vec` per kind — grouping them
/// would make the deserialiser reject any file that alternates.
#[derive(Debug, Clone, Deserialize)]
pub struct Fields {
    #[serde(rename = "@Name")]
    pub name: Option<String>,
    #[serde(rename = "$value", default)]
    pub fields: Vec<Field>,
}

#[derive(Debug, Clone, Deserialize)]
pub enum Field {
    ByteField(ByteField),
    NumberField(NumberField),
}

impl Fields {
    pub fn byte_fields(&self) -> impl Iterator<Item = &ByteField> {
        self.fields.iter().filter_map(|f| match f {
            Field::ByteField(b) => Some(b),
            _ => None,
        })
    }

    pub fn number_fields(&self) -> impl Iterator<Item = &NumberField> {
        self.fields.iter().filter_map(|f| match f {
            Field::NumberField(n) => Some(n),
            _ => None,
        })
    }
}

/// A fixed-width byte variable, e.g. a group address or serial number.
#[derive(Debug, Clone, Deserialize)]
pub struct ByteField {
    #[serde(rename = "@Name")]
    pub name: String,
    #[serde(rename = "@Size")]
    pub size: Option<usize>,
    /// Space-separated hex, e.g. `"10 00"`.
    #[serde(rename = "@DefaultValue")]
    pub default_value: Option<String>,
    #[serde(rename = "@Format")]
    pub format: Option<String>,
    #[serde(rename = "@DisplayName")]
    pub display_name: Option<String>,
}

/// A scalar variable. Two quite different things share this element:
/// a number substituted into telegram data (`Format="Hex"`, with
/// `SizeInBits` deciding whether it contributes one byte or two), and a
/// duration used in `TimeToNext` (`Format="TimeToNextTelegram"`,
/// `SizeInBits="0"`).
#[derive(Debug, Clone, Deserialize)]
pub struct NumberField {
    #[serde(rename = "@Name")]
    pub name: String,
    #[serde(rename = "@SizeInBits")]
    pub size_in_bits: Option<u32>,
    #[serde(rename = "@DefaultValue")]
    pub default_value: Option<String>,
    #[serde(rename = "@Format")]
    pub format: Option<String>,
    #[serde(rename = "@DisplayName")]
    pub display_name: Option<String>,
    #[serde(rename = "@MinValue")]
    pub min_value: Option<String>,
    #[serde(rename = "@MaxValue")]
    pub max_value: Option<String>,
}

impl NumberField {
    /// Whether this field is a duration rather than telegram data.
    pub fn is_duration(&self) -> bool {
        self.format.as_deref().is_some_and(|f| f.eq_ignore_ascii_case("TimeToNextTelegram"))
    }
}

// ============================================================================
// Test hierarchy
// ============================================================================

#[derive(Debug, Clone, Deserialize)]
pub struct TestCollections {
    #[serde(rename = "TestCollection", default)]
    pub collections: Vec<TestCollection>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct TestCollection {
    #[serde(rename = "@ID")]
    pub id: Option<String>,
    #[serde(rename = "@Name")]
    pub name: Option<String>,
    #[serde(rename = "@Comment")]
    pub comment: Option<String>,
    /// Collection-scoped variables, shadowing the template-global ones.
    #[serde(rename = "Fields", default)]
    pub fields: Vec<Fields>,
    #[serde(rename = "TestSuites")]
    pub test_suites: Option<TestSuites>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct TestSuites {
    #[serde(rename = "TestSuite", default)]
    pub suites: Vec<TestSuite>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct TestSuite {
    #[serde(rename = "@ID")]
    pub id: Option<String>,
    #[serde(rename = "@Name")]
    pub name: Option<String>,
    #[serde(rename = "@Comment")]
    pub comment: Option<String>,
    /// Repeats: the transport-layer template splits suite 6.4.8 across
    /// two `<TestCases>` elements, and one of the two cases lives in
    /// the second. Modelling this as a single optional element made
    /// the whole file fail to parse.
    #[serde(rename = "TestCases", default)]
    pub test_cases: Vec<TestCases>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct TestCases {
    #[serde(rename = "TestCase", default)]
    pub cases: Vec<TestCase>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct TestCase {
    /// Stable GUID. Patch sets and profiles anchor on this rather than
    /// on the name, which gets reworded between revisions.
    #[serde(rename = "@ID")]
    pub id: Option<String>,
    #[serde(rename = "@Name")]
    pub name: Option<String>,
    #[serde(rename = "Sequence")]
    pub sequence: Option<Sequence>,
}

/// The ordered body of a test case.
///
/// `Comment` and `Telegram` interleave, and the order matters, so this
/// is a single `Vec` of an enum rather than two lists.
#[derive(Debug, Clone, Deserialize)]
pub struct Sequence {
    #[serde(rename = "$value", default)]
    pub items: Vec<SequenceItem>,
}

#[derive(Debug, Clone, Deserialize)]
// This mirrors the vendor XML node model. Boxing only telegram nodes would
// complicate every lowering match for a transient parse tree.
#[allow(clippy::large_enum_variant)]
pub enum SequenceItem {
    Comment(Comment),
    Telegram(Telegram),
    Preparation(Preparation),
}

impl SequenceItem {
    /// The GUID a patch or profile can anchor on.
    pub fn id(&self) -> Option<&str> {
        match self {
            Self::Comment(c) => c.id.as_deref(),
            Self::Telegram(t) => t.id.as_deref(),
            Self::Preparation(_) => None,
        }
    }
}

/// Something EITT does to itself before the sequence runs.
///
/// The data-security template has exactly one, loading its Security
/// Configuration Table from a CSV shipped beside the templates:
///
/// ```xml
/// <Preparation Operation="LoadSecurityTable" Parameter="file=TSSJ_SCT.csv"/>
/// ```
///
/// That table is EITT's own key provisioning — which key it uses for
/// which group address and which peer. We provision the runner and the
/// DUT together from `crate::tests::security::variables`, so the table
/// is already installed by the time a case runs and the operation has
/// nothing to do here.
#[derive(Debug, Clone, Deserialize)]
pub struct Preparation {
    #[serde(rename = "@Operation")]
    pub operation: Option<String>,
    #[serde(rename = "@Parameter")]
    pub parameter: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Comment {
    #[serde(rename = "@ID")]
    pub id: Option<String>,
    /// The `@`-command language; see [`super::comment`].
    #[serde(rename = "@Text")]
    pub text: Option<String>,
}

/// One telegram to send or expect.
///
/// The security and RF attributes are modelled so that a template using
/// them fails to lower with a clear message instead of silently running
/// as though they were absent — an `InvalMAC` we ignore turns a
/// negative test into a positive one.
///
/// `deny_unknown_fields` extends that to attributes we have never seen:
/// serde drops those silently, which is how `Connection` went unnoticed
/// on all 394 telegrams of the transport-layer template. An attribute
/// we have not read about is a template revision we have not read
/// about, so it stops the run.
/// `Default` is for tests: every field is optional, and building one by
/// naming only the two or three attributes a case is about keeps them
/// readable.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Telegram {
    #[serde(rename = "@ID")]
    pub id: Option<String>,
    /// Frame bytes in EITT's internal (checksum-free) notation, with
    /// `#VAR` references and `?` wildcards.
    #[serde(rename = "@Data")]
    pub data: Option<String>,
    /// `IN` — EITT sends it. `OUT` — EITT expects it.
    #[serde(rename = "@CWay")]
    pub cway: Option<String>,
    /// For `OUT`, the window within which the telegram must arrive.
    /// For `IN`, the gap before the next telegram. See the EITT manual
    /// §12.2.3.7.
    #[serde(rename = "@TimeToNext")]
    pub time_to_next: Option<String>,
    /// "Wait end time" flag (§12.2.3.8): `yes` waits out `TimeToNext`
    /// even once the telegram has been sent or received.
    #[serde(rename = "@Wait")]
    pub wait: Option<String>,
    /// `no` disables the step. This is how a template offers
    /// alternatives — 1.4.1.6 ships both a connectionless and a
    /// connection-oriented restart, with one of them deactivated.
    #[serde(rename = "@Activate")]
    pub activate: Option<String>,
    /// `Normal` or `Faulty`.
    #[serde(rename = "@FT")]
    pub ft: Option<String>,
    /// `Dpt_none`, `Mgmnt` or `Faulty`, in any capitalisation.
    #[serde(rename = "@TelegramType")]
    pub telegram_type: Option<String>,
    /// `tp` or `rf`. Absent means the template's default medium.
    #[serde(rename = "@Medium")]
    pub medium: Option<String>,
    /// Which of EITT's tool interfaces carries this telegram, named
    /// after an entry in [`Interfaces`]. We drive a single mock bus on
    /// which both tool addresses are visible, so this is deliberately
    /// not consulted — the source address in [`Telegram::data`] already
    /// says which of the two is speaking.
    #[serde(rename = "@Connection")]
    pub connection: Option<String>,
    /// Free-text comment, which may itself carry `@`-commands.
    #[serde(rename = "@Comment")]
    pub comment: Option<String>,
    /// `yes` when EITT should transmit via `L_SystemBroadcast.req`
    /// rather than `L_Data.req`.
    ///
    /// Modelled so the file parses — `Telegram` denies unknown fields,
    /// and the management template is the first to carry this — but
    /// deliberately not acted on.
    ///
    /// It selects a link-layer service on a real interface, and we
    /// inject octets straight into a mock bus, where the distinction is
    /// already in the frame: the system broadcast flag is bit 4 of the
    /// control field, clear for a system broadcast, and
    /// `KnxMessage::get_address_type` reads exactly that bit to tell
    /// `AddressType::SystemBroadcast` from `AddressType::Broadcast`.
    /// The management template's system broadcasts carry control byte
    /// `2C` where its ordinary broadcasts carry `BC`, so the DUT
    /// classifies them correctly with no help from this attribute.
    ///
    /// On the TP1 profile the question does not even arise: all 50 of
    /// them are either `Medium="rf"` or in a domain-address collection,
    /// so none survives the medium filter.
    #[serde(rename = "@UseSystemBroadcast")]
    pub use_system_broadcast: Option<String>,

    // ---- Transport layer ---------------------------------------------
    /// The "fix sequence" value from EITT's telegram properties
    /// (manual §15.6, "TL sequence number, if fix"): the sequence
    /// number to use instead of the one EITT would compute for itself
    /// while running the sequence.
    ///
    /// Despite sitting among the security attributes in the XML this
    /// has nothing to do with KNX Data Security. It is handled in
    /// [`super::lower`], which writes it into the TPCI octet.
    #[serde(rename = "@TLSeqNum")]
    pub tl_seq_num: Option<String>,

    // ---- RF ----------------------------------------------------------
    #[serde(rename = "@RFInfo")]
    pub rf_info: Option<String>,
    #[serde(rename = "@RFInfoEval")]
    pub rf_info_eval: Option<String>,
    #[serde(rename = "@RFSerial")]
    pub rf_serial: Option<String>,
    #[serde(rename = "@LFN")]
    pub lfn: Option<String>,

    // ---- KNX Data Security -------------------------------------------
    // Present and empty on every telegram in the non-security
    // templates; only the security templates populate them.
    #[serde(rename = "@Secure")]
    pub secure: Option<String>,
    #[serde(rename = "@SecType")]
    pub sec_type: Option<String>,
    #[serde(rename = "@SecKey")]
    pub sec_key: Option<String>,
    #[serde(rename = "@SeqNum")]
    pub seq_num: Option<String>,
    #[serde(rename = "@SeqNumLoc")]
    pub seq_num_loc: Option<String>,
    #[serde(rename = "@SeqNumRem")]
    pub seq_num_rem: Option<String>,
    #[serde(rename = "@SeqNumOfs")]
    pub seq_num_ofs: Option<String>,
    #[serde(rename = "@SAI")]
    pub sai: Option<String>,
    #[serde(rename = "@SAL")]
    pub sal: Option<String>,
    #[serde(rename = "@SBC")]
    pub sbc: Option<String>,
    #[serde(rename = "@TA")]
    pub ta: Option<String>,
    #[serde(rename = "@Challenge")]
    pub challenge: Option<String>,
    #[serde(rename = "@KNXSerNo")]
    pub knx_ser_no: Option<String>,
    #[serde(rename = "@SyncReqName")]
    pub sync_req_name: Option<String>,
    #[serde(rename = "@SyncReqRef")]
    pub sync_req_ref: Option<String>,
    #[serde(rename = "@InvalMAC")]
    pub inval_mac: Option<String>,
    #[serde(rename = "@InvalSCF")]
    pub inval_scf: Option<String>,
    #[serde(rename = "@InvalCypher")]
    pub inval_cypher: Option<String>,
    #[serde(rename = "@InvalResv")]
    pub inval_resv: Option<String>,
    #[serde(rename = "@ATWrong")]
    pub at_wrong: Option<String>,
}

impl Telegram {
    /// Whether the step is enabled. Absent `Activate` means enabled.
    pub fn is_active(&self) -> bool {
        !self.activate.as_deref().is_some_and(|a| a.eq_ignore_ascii_case("no"))
    }

    /// Whether "wait end time" is set, i.e. the full `TimeToNext`
    /// elapses even after the telegram has been handled.
    ///
    /// `None` for a value we do not recognise. The templates write the
    /// flag four ways — `yes`, `y`, `no`, `n`, in either case — and an
    /// unrecognised one used to read as "no", which silently dropped
    /// 161 waits in the load-state-machine template. The caller turns
    /// `None` into a hard error rather than guessing again.
    pub fn wait_flag(&self) -> Option<bool> {
        match self.wait.as_deref().map(str::trim) {
            None | Some("") => Some(false),
            Some(w) if w.eq_ignore_ascii_case("yes") || w.eq_ignore_ascii_case("y") => Some(true),
            Some(w) if w.eq_ignore_ascii_case("no") || w.eq_ignore_ascii_case("n") => Some(false),
            Some(_) => None,
        }
    }

    /// Any security attribute carrying a value. Used by the lowerer to
    /// refuse a telegram it would otherwise send in the clear.
    ///
    /// `TLSeqNum` is deliberately not here: it sits among these in the
    /// XML but is a transport-layer sequence number, and treating it as
    /// a security attribute made the whole transport-layer template
    /// unrunnable.
    pub fn security_attrs_set(&self) -> Vec<&'static str> {
        let candidates: [(&'static str, &Option<String>); 17] = [
            ("Secure", &self.secure),
            ("SecType", &self.sec_type),
            ("SecKey", &self.sec_key),
            ("SeqNum", &self.seq_num),
            ("SeqNumLoc", &self.seq_num_loc),
            ("SeqNumRem", &self.seq_num_rem),
            ("SeqNumOfs", &self.seq_num_ofs),
            ("SAI", &self.sai),
            ("SAL", &self.sal),
            ("SBC", &self.sbc),
            ("TA", &self.ta),
            ("Challenge", &self.challenge),
            ("KNXSerNo", &self.knx_ser_no),
            ("SyncReqName", &self.sync_req_name),
            ("InvalMAC", &self.inval_mac),
            ("InvalSCF", &self.inval_scf),
            ("InvalCypher", &self.inval_cypher),
        ];
        set_attrs(&candidates)
    }

    /// Any RF attribute carrying a value.
    ///
    /// A telegram with these is an RF frame whether or not it also
    /// carries `Medium="rf"`, and several do not — the medium filter
    /// would otherwise let them through and we would inject an RF frame
    /// on TP.
    pub fn rf_attrs_set(&self) -> Vec<&'static str> {
        let candidates: [(&'static str, &Option<String>); 4] = [
            ("RFInfo", &self.rf_info),
            ("RFInfoEval", &self.rf_info_eval),
            ("RFSerial", &self.rf_serial),
            ("LFN", &self.lfn),
        ];
        set_attrs(&candidates)
    }
}

fn set_attrs(candidates: &[(&'static str, &Option<String>)]) -> Vec<&'static str> {
    candidates.iter().filter(|(_, v)| v.as_deref().is_some_and(|s| !s.trim().is_empty())).map(|(k, _)| *k).collect()
}

// ============================================================================
// Loading
// ============================================================================

/// Parse a template from XML text.
pub fn parse(xml: &str) -> Result<Template, quick_xml::DeError> {
    quick_xml::de::from_str(xml)
}

#[cfg(test)]
#[allow(clippy::items_after_test_module)]
mod tests {
    use super::*;

    fn wrap(suite_body: &str) -> String {
        format!(
            "<EITT_KnxConformanceTests><TestCollections><TestCollection><TestSuites>\
             <TestSuite Name=\"s\">{suite_body}</TestSuite>\
             </TestSuites></TestCollection></TestCollections></EITT_KnxConformanceTests>"
        )
    }

    #[test]
    fn a_suite_may_hold_more_than_one_test_cases_block() {
        // Transport-layer suite 6.4.8 does, and one of its two cases
        // lives in the second block. Modelling this as a single optional
        // element used to fail the whole file with "duplicate field".
        let xml = wrap(
            "<TestCases><TestCase Name=\"a\"/></TestCases>\
             <TestCases><TestCase Name=\"b\"/></TestCases>",
        );
        let template = parse(&xml).expect("parses");
        let names: Vec<_> = template.cases().map(|(_, c)| c.name.clone().unwrap_or_default()).collect();
        assert_eq!(names, ["a", "b"]);
    }

    #[test]
    fn wait_accepts_every_spelling_the_templates_use() {
        let flag = |w: Option<&str>| schema_wait(w).wait_flag();
        for yes in ["yes", "Yes", "YES", "y", "Y"] {
            assert_eq!(flag(Some(yes)), Some(true), "{yes:?}");
        }
        for no in ["no", "No", "n", "N", ""] {
            assert_eq!(flag(Some(no)), Some(false), "{no:?}");
        }
        assert_eq!(flag(None), Some(false));
        // Anything else has to reach the caller as a question, not as a
        // "no" — that is how 161 waits went missing.
        assert_eq!(flag(Some("later")), None);
    }

    fn schema_wait(wait: Option<&str>) -> Telegram {
        Telegram { wait: wait.map(str::to_string), ..Default::default() }
    }

    #[test]
    fn an_attribute_we_have_never_seen_stops_the_parse() {
        let xml = wrap(
            "<TestCases><TestCase Name=\"a\"><Sequence>\
             <Telegram Data=\"BC\" CWay=\"IN\" Invented=\"1\"/>\
             </Sequence></TestCase></TestCases>",
        );
        assert!(parse(&xml).is_err(), "an unmodelled attribute must not be dropped silently");
    }

    #[test]
    fn tl_seq_num_is_not_a_security_attribute() {
        let t = Telegram { tl_seq_num: Some("3".into()), ..Default::default() };
        assert!(t.security_attrs_set().is_empty());
    }

    #[test]
    fn rf_attributes_are_recognised_without_a_medium() {
        let t = Telegram { rf_info: Some("02".into()), ..Default::default() };
        assert_eq!(t.rf_attrs_set(), ["RFInfo"]);
        assert!(t.medium.is_none());
    }
}

impl Template {
    /// A one-line identification for the run header.
    pub fn describe(&self) -> String {
        let name = self.name.as_deref().unwrap_or("(unnamed template)");
        match (&self.version, &self.date_of_version) {
            (Some(v), Some(d)) => format!("{name} — Version {v}, {d}"),
            (Some(v), None) => format!("{name} — Version {v}"),
            _ => name.to_string(),
        }
    }

    /// Every test case in document order, paired with the suite that
    /// contains it.
    pub fn cases(&self) -> impl Iterator<Item = (&TestSuite, &TestCase)> {
        self.test_collections
            .iter()
            .flat_map(|c| &c.collections)
            .flat_map(|c| c.test_suites.iter())
            .flat_map(|s| &s.suites)
            .flat_map(|s| s.test_cases.iter().flat_map(move |tc| tc.cases.iter().map(move |c| (s, c))))
    }
}
