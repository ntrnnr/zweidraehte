//! Applying a product's `<Languages>` translations to its parsed
//! program.
//!
//! The base attributes of an application program are written in its
//! `DefaultLanguage`; every other language lives in the manufacturer's
//! `Languages` section as `(element RefId, attribute) → text` entries.
//! [`Translations::apply`] rewrites the parsed
//! [`ApplicationProgram`]'s display attributes in place, so everything
//! downstream — the [`Device`](super::Device) caches, the TUI, the
//! dump tool — shows the chosen language without a single
//! display-site change. Rewriting is one-way; callers that switch
//! languages at runtime keep a pristine copy of the program and apply
//! onto a fresh clone.
//!
//! Only display attributes are touched (`Text`, `SuffixText`,
//! `FunctionText`); ids, values and memory locations are language
//! independent by construction.
//!
//! TODO: module-definition internals (`ModuleDefs`) are not walked
//! yet — the products we translate today are flat, and module texts
//! flow through interpolation paths that would need their own pass.

use std::collections::HashMap;

use crate::schema::{
    ApplicationProgram, ChannelIndependentItem, ChannelItem, Choose, Knx, ParameterBlock, ParameterBlockItem,
    ParameterItem, WhenItem,
};

/// All of a document's translations, indexed for application.
#[derive(Debug, Clone, Default)]
pub struct Translations {
    /// language → element ref id → attribute → text.
    map: HashMap<String, HashMap<String, HashMap<String, String>>>,
}

impl Translations {
    /// Collect the translations of every language in the document.
    pub fn from_knx(knx: &Knx) -> Self {
        let mut map: HashMap<String, HashMap<String, HashMap<String, String>>> = HashMap::new();
        if let Some(languages) = &knx.manufacturer_data.manufacturer.languages {
            for language in &languages.languages {
                let per_element = map.entry(language.identifier.clone()).or_default();
                for unit in &language.translation_units {
                    for element in &unit.elements {
                        let per_attribute = per_element.entry(element.ref_id.clone()).or_default();
                        for translation in &element.translations {
                            per_attribute.insert(translation.attribute_name.clone(), translation.text.clone());
                        }
                    }
                }
            }
        }
        Self { map }
    }

    /// The language identifiers the document translates into, sorted.
    /// The base attributes themselves are the program's
    /// `DefaultLanguage` and are not listed here.
    pub fn languages(&self) -> Vec<&str> {
        let mut languages: Vec<&str> = self.map.keys().map(String::as_str).collect();
        languages.sort_unstable();
        languages
    }

    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }

    /// Rewrite `program`'s display attributes into `language`.
    ///
    /// Returns the number of attributes replaced, or `None` when the
    /// document carries no such language (callers list
    /// [`languages`](Self::languages) in their error).
    pub fn apply(&self, program: &mut ApplicationProgram, language: &str) -> Option<usize> {
        let lookup = self.map.get(language)?;
        let mut applied = Applier { lookup, count: 0 };
        applied.program(program);
        Some(applied.count)
    }
}

/// The traversal: every display attribute the schema models, replaced
/// where the language has an entry for `(element id, attribute)`.
struct Applier<'a> {
    lookup: &'a HashMap<String, HashMap<String, String>>,
    count: usize,
}

impl Applier<'_> {
    fn set(&mut self, id: &str, attribute: &str, field: &mut String) {
        if let Some(text) = self.lookup.get(id).and_then(|attrs| attrs.get(attribute)) {
            *field = text.clone();
            self.count += 1;
        }
    }

    /// Optional attributes are set even when the base language leaves
    /// them out — the translation is the attribute's value in that
    /// language, presence included.
    fn set_opt(&mut self, id: &str, attribute: &str, field: &mut Option<String>) {
        if let Some(text) = self.lookup.get(id).and_then(|attrs| attrs.get(attribute)) {
            *field = Some(text.clone());
            self.count += 1;
        }
    }

    fn program(&mut self, program: &mut ApplicationProgram) {
        // Static: parameters (plain and union members).
        if let Some(parameters) = &mut program.static_section.parameters {
            for item in &mut parameters.items {
                match item {
                    ParameterItem::Parameter(p) => {
                        let id = p.id.clone();
                        self.set(&id, "Text", &mut p.text);
                        self.set_opt(&id, "SuffixText", &mut p.suffix_text);
                    }
                    ParameterItem::Union(u) => {
                        for p in &mut u.parameters {
                            let id = p.id.clone();
                            self.set(&id, "Text", &mut p.text);
                            self.set_opt(&id, "SuffixText", &mut p.suffix_text);
                        }
                    }
                }
            }
        }

        // Static: enumeration option texts.
        if let Some(types) = &mut program.static_section.parameter_types {
            for parameter_type in &mut types.types {
                if let crate::schema::ParameterTypeDef::TypeRestriction(r) = &mut parameter_type.type_def {
                    for enumeration in &mut r.enumerations {
                        let id = enumeration.id.clone();
                        self.set(&id, "Text", &mut enumeration.text);
                    }
                }
            }
        }

        // Static: ref-level text overrides.
        if let Some(refs) = &mut program.static_section.parameter_refs {
            for parameter_ref in &mut refs.refs {
                let id = parameter_ref.id.clone();
                self.set_opt(&id, "Text", &mut parameter_ref.text);
            }
        }

        // Static: com objects and their refs.
        if let Some(table) = &mut program.static_section.com_object_table {
            for object in &mut table.objects {
                let id = object.id.clone();
                self.set(&id, "Text", &mut object.text);
                self.set(&id, "FunctionText", &mut object.function_text);
            }
        }
        if let Some(refs) = &mut program.static_section.com_object_refs {
            for object_ref in &mut refs.refs {
                let id = object_ref.id.clone();
                self.set_opt(&id, "Text", &mut object_ref.text);
                self.set_opt(&id, "FunctionText", &mut object_ref.function_text);
            }
        }

        // Dynamic: channel, block, separator and rename titles.
        if let Some(dynamic) = &mut program.dynamic {
            if let Some(cib) = &mut dynamic.channel_independent_block {
                for item in &mut cib.items {
                    self.cib_item(item);
                }
            }
            for channel in &mut dynamic.channels {
                let id = channel.id.clone();
                self.set_opt(&id, "Text", &mut channel.text);
                for item in &mut channel.items {
                    self.channel_item(item);
                }
            }
        }
    }

    fn cib_item(&mut self, item: &mut ChannelIndependentItem) {
        match item {
            ChannelIndependentItem::ParameterBlock(pb) => self.block(pb),
            ChannelIndependentItem::Choose(choose) => self.choose(choose),
            ChannelIndependentItem::ParameterBlockRename(rename) => {
                let id = rename.id.clone();
                self.set_opt(&id, "Text", &mut rename.text);
            }
        }
    }

    fn channel_item(&mut self, item: &mut ChannelItem) {
        match item {
            ChannelItem::ParameterBlock(pb) => self.block(pb),
            ChannelItem::Choose(choose) => self.choose(choose),
            // Module texts flow through interpolation, out of scope
            // here (see the module TODO in the module docs).
            ChannelItem::Module(_) => {}
            ChannelItem::ParameterBlockRename(rename) => {
                let id = rename.id.clone();
                self.set_opt(&id, "Text", &mut rename.text);
            }
        }
    }

    fn block(&mut self, block: &mut ParameterBlock) {
        let id = block.id.clone();
        self.set_opt(&id, "Text", &mut block.text);
        for item in &mut block.items {
            self.block_item(item);
        }
    }

    fn block_item(&mut self, item: &mut ParameterBlockItem) {
        match item {
            ParameterBlockItem::ParameterSeparator(separator) => {
                let id = separator.id.clone();
                self.set_opt(&id, "Text", &mut separator.text);
            }
            ParameterBlockItem::Choose(choose) => self.choose(choose),
            ParameterBlockItem::ParameterBlockRename(rename) => {
                let id = rename.id.clone();
                self.set_opt(&id, "Text", &mut rename.text);
            }
            ParameterBlockItem::ParameterRefRef(_)
            | ParameterBlockItem::ComObjectRefRef(_)
            | ParameterBlockItem::Module(_)
            | ParameterBlockItem::Button(_)
            | ParameterBlockItem::Rows(_)
            | ParameterBlockItem::Columns(_) => {}
        }
    }

    fn choose(&mut self, choose: &mut Choose) {
        for when in &mut choose.whens {
            for item in &mut when.items {
                self.when_item(item);
            }
        }
    }

    fn when_item(&mut self, item: &mut WhenItem) {
        match item {
            WhenItem::ParameterBlock(pb) => self.block(pb),
            WhenItem::Choose(choose) => self.choose(choose),
            WhenItem::ParameterSeparator(separator) => {
                let id = separator.id.clone();
                self.set_opt(&id, "Text", &mut separator.text);
            }
            WhenItem::ParameterBlockRename(rename) => {
                let id = rename.id.clone();
                self.set_opt(&id, "Text", &mut rename.text);
            }
            WhenItem::ParameterRefRef(_) | WhenItem::ComObjectRefRef(_) | WhenItem::Module(_) | WhenItem::Assign(_) => {
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runtime::parser::parse_application_program;

    /// A one-parameter program with a German translation for the
    /// parameter text, an enum option, and a block title.
    const FIXTURE: &str = r#"<KNX xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" CreatedBy="zweidraehte" ToolVersion="0.1.0" xmlns="http://knx.org/xml/project/20">
  <ManufacturerData><Manufacturer RefId="M-00FA">
    <ApplicationPrograms>
    <ApplicationProgram Id="M-00FA_A-1" ApplicationNumber="1" ApplicationVersion="1" ProgramType="ApplicationProgram" MaskVersion="MV-0705" Name="Fixture" LoadProcedureStyle="ProductProcedure" PeiType="0" DefaultLanguage="en-US" DynamicTableManagement="false" Linkable="false">
      <Static>
        <ParameterTypes>
          <ParameterType Id="M-00FA_A-1_PT-1" Name="Mode"><TypeRestriction Base="Value" SizeInBit="8"><Enumeration Text="Off" Value="0" Id="M-00FA_A-1_PT-1_EN-0" /></TypeRestriction></ParameterType>
        </ParameterTypes>
        <Parameters>
          <Parameter Id="M-00FA_A-1_P-1" Name="Mode" ParameterType="M-00FA_A-1_PT-1" Text="Mode" Value="0" />
        </Parameters>
        <ParameterRefs><ParameterRef Id="M-00FA_A-1_P-1_R-1" RefId="M-00FA_A-1_P-1" /></ParameterRefs>
      </Static>
      <Dynamic>
        <Channel Id="M-00FA_A-1_CH-1" Name="Main">
          <ParameterBlock Id="M-00FA_A-1_PB-1" Text="General">
            <ParameterRefRef RefId="M-00FA_A-1_P-1_R-1" />
          </ParameterBlock>
        </Channel>
      </Dynamic>
    </ApplicationProgram>
    </ApplicationPrograms>
    <Languages>
      <Language Identifier="de-DE">
        <TranslationUnit RefId="M-00FA_A-1">
          <TranslationElement RefId="M-00FA_A-1_P-1"><Translation AttributeName="Text" Text="Modus" /></TranslationElement>
          <TranslationElement RefId="M-00FA_A-1_PT-1_EN-0"><Translation AttributeName="Text" Text="Aus" /></TranslationElement>
          <TranslationElement RefId="M-00FA_A-1_PB-1"><Translation AttributeName="Text" Text="Allgemein" /></TranslationElement>
        </TranslationUnit>
      </Language>
    </Languages>
  </Manufacturer></ManufacturerData>
</KNX>"#;

    #[test]
    fn applies_a_language_and_rejects_unknown_ones() {
        let knx = parse_application_program(FIXTURE).expect("fixture parses");
        let translations = Translations::from_knx(&knx);
        assert_eq!(translations.languages(), ["de-DE"]);

        let mut program =
            knx.manufacturer_data.manufacturer.application_programs.programs.into_iter().next().expect("one program");
        assert!(translations.apply(&mut program, "fr-FR").is_none(), "unknown languages are refused");

        assert_eq!(translations.apply(&mut program, "de-DE"), Some(3));
        let statics = &program.static_section;
        match &statics.parameters.as_ref().expect("parameters").items[0] {
            crate::schema::ParameterItem::Parameter(p) => assert_eq!(p.text, "Modus"),
            other => panic!("expected a parameter, got {other:?}"),
        }
        match &statics.parameter_types.as_ref().expect("types").types[0].type_def {
            crate::schema::ParameterTypeDef::TypeRestriction(r) => assert_eq!(r.enumerations[0].text, "Aus"),
            other => panic!("expected a restriction, got {other:?}"),
        }
        match &program.dynamic.as_ref().expect("dynamic").channels[0].items[0] {
            crate::schema::ChannelItem::ParameterBlock(pb) => assert_eq!(pb.text.as_deref(), Some("Allgemein")),
            other => panic!("expected a block, got {other:?}"),
        }
    }
}
