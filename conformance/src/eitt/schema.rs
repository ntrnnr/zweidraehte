//! Serde mirror of the EITT conformance template XML.
//!
//! Deserialised with `quick_xml::de`, using the `@Attr` rename
//! convention already established in
//! `crates/zweidraehte-knxprod/src/schema/core.rs`.
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
    #[serde(rename = "ApplicationNote")]
    pub application_note: Option<String>,
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
    #[serde(rename = "TestCases")]
    pub test_cases: Option<TestCases>,
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
pub enum SequenceItem {
    Comment(Comment),
    Telegram(Telegram),
}

impl SequenceItem {
    /// The GUID a patch or profile can anchor on.
    pub fn id(&self) -> Option<&str> {
        match self {
            Self::Comment(c) => c.id.as_deref(),
            Self::Telegram(t) => t.id.as_deref(),
        }
    }
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
#[derive(Debug, Clone, Deserialize)]
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
    /// Free-text comment, which may itself carry `@`-commands.
    #[serde(rename = "@Comment")]
    pub comment: Option<String>,

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
    #[serde(rename = "@TLSeqNum")]
    pub tl_seq_num: Option<String>,
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
    pub fn waits_out_time(&self) -> bool {
        self.wait.as_deref().is_some_and(|w| w.eq_ignore_ascii_case("yes"))
    }

    /// Any security attribute carrying a value. Used by the lowerer to
    /// refuse a telegram it would otherwise send in the clear.
    pub fn security_attrs_set(&self) -> Vec<&'static str> {
        let candidates: [(&'static str, &Option<String>); 18] = [
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
            ("TLSeqNum", &self.tl_seq_num),
            ("Challenge", &self.challenge),
            ("KNXSerNo", &self.knx_ser_no),
            ("SyncReqName", &self.sync_req_name),
            ("InvalMAC", &self.inval_mac),
            ("InvalSCF", &self.inval_scf),
            ("InvalCypher", &self.inval_cypher),
        ];
        candidates.iter().filter(|(_, v)| v.as_deref().is_some_and(|s| !s.trim().is_empty())).map(|(k, _)| *k).collect()
    }
}

// ============================================================================
// Loading
// ============================================================================

/// Parse a template from XML text.
pub fn parse(xml: &str) -> Result<Template, quick_xml::DeError> {
    quick_xml::de::from_str(xml)
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
