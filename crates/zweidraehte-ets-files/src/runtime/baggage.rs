//! Baggage file loading utilities.
//!
//! KNX product definitions can include "baggage" files - typically images
//! that are displayed in the ETS configuration interface. These are defined
//! in a separate Baggages.xml file and stored in a Baggages/ subdirectory.
//!
//! This module provides utilities for parsing the Baggages.xml index and
//! locating the corresponding files on disk.
//!
//! # Directory structure
//!
//! ```text
//! M-0083/
//! ├── M-0083_A-0070-35-1740.xml  (main application program)
//! ├── Baggages.xml               (baggage index)
//! └── Baggages/                  (baggage files)
//!     ├── jalousie.png
//!     ├── licht.png
//!     └── ...
//! ```
//!
//! # Example
//!
//! ```rust,ignore
//! use zweidraehte_ets_files::runtime::baggage::BaggageIndex;
//! use std::path::Path;
//!
//! let index = BaggageIndex::from_directory(Path::new("M-0083/"))?;
//! if let Some(baggage) = index.get("M-0083_BG--licht.2Epng") {
//!     let image_path = baggage.file_path();
//!     // Load the image from image_path
//! }
//! ```

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use crate::schema::BaggagesKnx;

/// A baggage index loaded from Baggages.xml.
#[derive(Debug, Clone)]
pub struct BaggageIndex {
    /// Base directory containing Baggages.xml and Baggages/
    base_dir: PathBuf,
    /// Map from baggage ID to baggage entry
    entries: HashMap<String, BaggageEntry>,
}

/// A single baggage entry.
#[derive(Debug, Clone)]
pub struct BaggageEntry {
    /// The baggage ID (e.g., "M-0083_BG--licht.2Epng")
    pub id: String,
    /// The file name (e.g., "licht.png")
    pub name: String,
    /// Target path within the Baggages directory (usually empty)
    pub target_path: String,
    /// Full path to the file on disk
    file_path: PathBuf,
}

impl BaggageEntry {
    /// Get the full path to the baggage file.
    pub fn file_path(&self) -> &Path {
        &self.file_path
    }

    /// Check if the baggage file exists on disk.
    pub fn exists(&self) -> bool {
        self.file_path.exists()
    }
}

impl BaggageIndex {
    /// Load a baggage index from a directory containing Baggages.xml.
    ///
    /// The directory should contain:
    /// - `Baggages.xml` - The baggage index file
    /// - `Baggages/` - Directory containing the actual baggage files
    pub fn from_directory(dir: &Path) -> Result<Self, BaggageError> {
        let baggages_xml = dir.join("Baggages.xml");
        if !baggages_xml.exists() {
            return Ok(Self { base_dir: dir.to_path_buf(), entries: HashMap::new() });
        }

        let content = std::fs::read_to_string(&baggages_xml).map_err(|e| BaggageError::Io(e, baggages_xml.clone()))?;

        Self::from_xml(&content, dir)
    }

    /// Parse baggage index from XML content.
    fn from_xml(xml: &str, base_dir: &Path) -> Result<Self, BaggageError> {
        let knx: BaggagesKnx = quick_xml::de::from_str(xml).map_err(BaggageError::Parse)?;

        let baggages_dir = base_dir.join("Baggages");
        let mut entries = HashMap::new();

        if let Some(baggages) = knx.manufacturer_data.manufacturer.baggages {
            for baggage in baggages.items {
                let file_path = if baggage.target_path.is_empty() {
                    baggages_dir.join(&baggage.name)
                } else {
                    baggages_dir.join(&baggage.target_path).join(&baggage.name)
                };

                entries.insert(baggage.id.clone(), BaggageEntry {
                    id: baggage.id,
                    name: baggage.name,
                    target_path: baggage.target_path,
                    file_path,
                });
            }
        }

        Ok(Self { base_dir: base_dir.to_path_buf(), entries })
    }

    /// Get a baggage entry by ID.
    pub fn get(&self, id: &str) -> Option<&BaggageEntry> {
        self.entries.get(id)
    }

    /// Check if any baggages are defined.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Get the number of baggage entries.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Iterate over all baggage entries.
    pub fn iter(&self) -> impl Iterator<Item = &BaggageEntry> {
        self.entries.values()
    }

    /// Get the base directory.
    pub fn base_dir(&self) -> &Path {
        &self.base_dir
    }
}

/// Errors that can occur when loading baggages.
#[derive(Debug, thiserror::Error)]
pub enum BaggageError {
    /// I/O error reading a file.
    #[error("cannot read baggage index {1:?}")]
    Io(#[source] std::io::Error, PathBuf),
    /// XML parsing error.
    #[error("cannot parse Baggages.xml")]
    Parse(#[source] quick_xml::DeError),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_baggages_xml() {
        let xml = r#"<?xml version="1.0"?>
<KNX xmlns="http://knx.org/xml/project/20">
  <ManufacturerData>
    <Manufacturer RefId="M-0083">
      <Baggages>
        <Baggage TargetPath="" Name="licht.png" Id="M-0083_BG--licht.2Epng">
          <FileInfo TimeInfo="2022-10-21T06:20:55.1409766Z" />
        </Baggage>
        <Baggage TargetPath="" Name="jalousie.png" Id="M-0083_BG--jalousie.2Epng">
          <FileInfo TimeInfo="2022-10-21T06:26:12.2027239Z" />
        </Baggage>
      </Baggages>
    </Manufacturer>
  </ManufacturerData>
</KNX>"#;

        let index = BaggageIndex::from_xml(xml, Path::new("/test")).unwrap();
        assert_eq!(index.len(), 2);

        let licht = index.get("M-0083_BG--licht.2Epng").unwrap();
        assert_eq!(licht.name, "licht.png");
        assert_eq!(licht.file_path(), Path::new("/test/Baggages/licht.png"));

        let jalousie = index.get("M-0083_BG--jalousie.2Epng").unwrap();
        assert_eq!(jalousie.name, "jalousie.png");
    }
}
