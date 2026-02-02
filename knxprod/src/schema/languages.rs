//! Language translation types for KNX product definitions.
//!
//! These types represent the `<Languages>` section that provides translations
//! for parameter names, enum values, and communication object texts.

use serde::{Deserialize, Serialize};

/// Container for all language translations.
///
/// Appears at the end of the ApplicationProgram element.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Languages {
    #[serde(rename = "Language", default, skip_serializing_if = "Vec::is_empty")]
    pub languages: Vec<Language>,
}

/// Translation data for a specific language.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Language {
    /// BCP 47 language identifier (e.g., "en-US", "de-DE", "fr-FR")
    #[serde(rename = "@Identifier")]
    pub identifier: String,

    #[serde(rename = "TranslationUnit", default, skip_serializing_if = "Vec::is_empty")]
    pub translation_units: Vec<TranslationUnit>,
}

/// Translation unit grouping translations for a specific program version.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TranslationUnit {
    /// Reference to the application program ID
    #[serde(rename = "@RefId")]
    pub ref_id: String,

    /// Optional version number
    #[serde(rename = "@Version", skip_serializing_if = "Option::is_none")]
    pub version: Option<u32>,

    #[serde(rename = "TranslationElement", default, skip_serializing_if = "Vec::is_empty")]
    pub elements: Vec<TranslationElement>,
}

/// Translation for a single element (parameter, enum value, comm object, etc.)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TranslationElement {
    /// Reference to the element being translated (e.g., "_P-3", "_O-72", "_PT-TypeName_EN-0")
    #[serde(rename = "@RefId")]
    pub ref_id: String,

    #[serde(rename = "Translation", default, skip_serializing_if = "Vec::is_empty")]
    pub translations: Vec<Translation>,
}

/// A single attribute translation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Translation {
    /// The attribute being translated: "Text", "SuffixText", "Name", "FunctionText"
    #[serde(rename = "@AttributeName")]
    pub attribute_name: String,

    /// The translated text
    #[serde(rename = "@Text")]
    pub text: String,
}

impl Languages {
    /// Create an empty Languages container.
    pub fn new() -> Self {
        Self::default()
    }

    /// Check if there are any translations.
    pub fn is_empty(&self) -> bool {
        self.languages.is_empty()
    }

    /// Add a language with its translations.
    pub fn add_language(&mut self, language: Language) {
        self.languages.push(language);
    }
}

impl Language {
    /// Create a new language translation container.
    pub fn new(identifier: impl Into<String>) -> Self {
        Self { identifier: identifier.into(), translation_units: Vec::new() }
    }

    /// Add a translation unit.
    pub fn add_unit(&mut self, unit: TranslationUnit) {
        self.translation_units.push(unit);
    }
}

impl TranslationUnit {
    /// Create a new translation unit for a program.
    pub fn new(ref_id: impl Into<String>) -> Self {
        Self { ref_id: ref_id.into(), version: None, elements: Vec::new() }
    }

    /// Set the version.
    pub fn with_version(mut self, version: u32) -> Self {
        self.version = Some(version);
        self
    }

    /// Add a translation element.
    pub fn add_element(&mut self, element: TranslationElement) {
        self.elements.push(element);
    }
}

impl TranslationElement {
    /// Create a new translation element.
    pub fn new(ref_id: impl Into<String>) -> Self {
        Self { ref_id: ref_id.into(), translations: Vec::new() }
    }

    /// Add a Text translation.
    pub fn with_text(mut self, text: impl Into<String>) -> Self {
        self.translations.push(Translation { attribute_name: "Text".to_string(), text: text.into() });
        self
    }

    /// Add a SuffixText translation.
    pub fn with_suffix(mut self, text: impl Into<String>) -> Self {
        self.translations.push(Translation { attribute_name: "SuffixText".to_string(), text: text.into() });
        self
    }

    /// Add a FunctionText translation (for comm objects).
    pub fn with_function(mut self, text: impl Into<String>) -> Self {
        self.translations.push(Translation { attribute_name: "FunctionText".to_string(), text: text.into() });
        self
    }

    /// Add a Name translation (for application program).
    pub fn with_name(mut self, text: impl Into<String>) -> Self {
        self.translations.push(Translation { attribute_name: "Name".to_string(), text: text.into() });
        self
    }
}
