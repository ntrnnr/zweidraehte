//! Canonical ETS XML parsing and serialization.

use serde::Serialize;
use serde::de::DeserializeOwned;

/// Errors produced by the shared XML codec.
#[derive(Debug, thiserror::Error)]
pub enum XmlError {
    #[error("cannot parse ETS XML")]
    Deserialize(#[source] quick_xml::DeError),
    #[error("cannot serialize ETS XML")]
    Serialize(#[source] quick_xml::SeError),
}

/// Parse one ETS XML document without discarding the parser's typed error.
pub fn from_str<T: DeserializeOwned>(xml: &str) -> Result<T, XmlError> {
    quick_xml::de::from_str(xml).map_err(XmlError::Deserialize)
}

/// Serialize an ETS XML document in the form expected by ETS packages.
///
/// All generators use this codec so declaration spelling and indentation do
/// not drift between application, hardware, catalogue, and project files.
pub fn to_string<T: Serialize>(value: &T) -> Result<String, XmlError> {
    let mut xml = String::from("<?xml version=\"1.0\" encoding=\"utf-8\"?>\n");
    let mut serializer = quick_xml::se::Serializer::new(&mut xml);
    serializer.indent(' ', 2);
    value.serialize(serializer).map_err(XmlError::Serialize)?;
    Ok(xml)
}

#[cfg(test)]
mod tests {
    use serde::{Deserialize, Serialize};

    #[derive(Debug, PartialEq, Serialize, Deserialize)]
    #[serde(rename = "Document")]
    struct Document {
        #[serde(rename = "Value")]
        value: String,
    }

    #[test]
    fn emits_the_canonical_declaration_and_indentation() {
        let xml = super::to_string(&Document { value: "hello".into() }).expect("document serializes");

        assert_eq!(xml, "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n<Document>\n  <Value>hello</Value>\n</Document>");
        assert_eq!(super::from_str::<Document>(&xml).expect("document parses").value, "hello");
    }

    fn canonical_round_trip<T>(document: &T)
    where
        T: Serialize + serde::de::DeserializeOwned,
    {
        let first = super::to_string(document).expect("document serializes");
        let parsed: T = super::from_str(&first).expect("canonical document parses");
        let second = super::to_string(&parsed).expect("parsed document serializes");
        assert_eq!(second, first);
    }

    #[test]
    fn supported_document_roots_round_trip_through_one_codec() {
        canonical_round_trip(&crate::schema::Knx::default());
        canonical_round_trip(&crate::schema::HardwareKnx::default());
        canonical_round_trip(&crate::schema::CatalogKnx::default());
        canonical_round_trip(&crate::schema::ProjectKnx::default());
        canonical_round_trip(&crate::schema::BaggagesKnx::default());
    }
}
