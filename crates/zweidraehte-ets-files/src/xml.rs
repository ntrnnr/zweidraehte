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

// XML 1.0 §3.3.3 normalizes literal attribute tabs/newlines to spaces, while
// character references survive: https://www.w3.org/TR/xml/#AVNormalize.
// quick-xml 0.37 leaves these characters literal even at QuoteLevel::Full.
// This writer sees only its generated markup: double-quoted attributes and
// escaped text, so comments, CDATA and arbitrary XML need no parsing here.
struct AttributeWhitespaceWriter<'a> {
    xml: &'a mut String,
    in_tag: bool,
    in_attribute: bool,
}

impl std::fmt::Write for AttributeWhitespaceWriter<'_> {
    fn write_str(&mut self, text: &str) -> std::fmt::Result {
        // State spans writes: the serializer emits delimiters and values
        // separately. Quotes in element text must not open an attribute.
        for ch in text.chars() {
            match ch {
                '<' if !self.in_attribute => self.in_tag = true,
                '>' if !self.in_attribute => self.in_tag = false,
                '"' if self.in_tag => self.in_attribute = !self.in_attribute,
                _ => {}
            }
            match (self.in_attribute, ch) {
                (true, '\t') => self.xml.push_str("&#9;"),
                (true, '\n') => self.xml.push_str("&#10;"),
                (true, '\r') => self.xml.push_str("&#13;"),
                _ => self.xml.push(ch),
            }
        }
        Ok(())
    }
}

/// Serialize an ETS XML document in the form expected by ETS packages.
///
/// All generators use this codec so declaration spelling and indentation do
/// not drift between application, hardware, catalogue, and project files.
pub fn to_string<T: Serialize>(value: &T) -> Result<String, XmlError> {
    let mut xml = String::from("<?xml version=\"1.0\" encoding=\"utf-8\"?>\n");
    let mut writer = AttributeWhitespaceWriter { xml: &mut xml, in_tag: false, in_attribute: false };
    let mut serializer = quick_xml::se::Serializer::new(&mut writer);
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

    #[test]
    fn attribute_whitespace_survives_xml_normalization() {
        #[derive(Debug, PartialEq, Serialize, Deserialize)]
        #[serde(rename = "Label")]
        struct Label {
            #[serde(rename = "@Text")]
            text: String,
            #[serde(rename = "@Help")]
            help: String,
            #[serde(rename = "Value")]
            value: String,
        }

        let label = Label {
            text: "Größe\nnext\r\n\t\"<&>' &#10;".into(),
            help: "first\nsecond".into(),
            value: "A \"quoted\nvalue\"".into(),
        };
        let xml = super::to_string(&label).expect("label serializes");

        assert!(xml.contains("Text=\"Größe&#10;next&#13;&#10;&#9;&quot;&lt;&amp;&gt;' &amp;#10;\""));
        assert!(xml.contains("Help=\"first&#10;second\""));
        assert!(xml.contains("<Value>A \"quoted\nvalue\"</Value>"));
        assert_eq!(super::from_str::<Label>(&xml).expect("label parses"), label);
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
