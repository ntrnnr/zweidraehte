//! Resolving [`MasterDataSource`] to actual `knx_master.xml` content.
//!
//! This is what ETS does: the master data is always present, fetched
//! from `update.knx.org` on first use and cached on disk thereafter.
//! Both the packaging path (which embeds master data in a `.knxprod`)
//! and the client's download engine (which needs the per-mask
//! resources and procedure templates) resolve through here.
//!
//! Gated on the `master-data` feature, which costs reqwest +
//! directories; the [`MasterDataSource`] enum itself is
//! unconditional, so callers can accept a source without pulling the
//! resolver in.

use std::fs;
use std::path::PathBuf;

use crate::signing::{KnxSchemaVersion, MasterDataSource, SigningError};

/// Get or download the KNX master data.
pub fn get_master_data(source: &MasterDataSource) -> Result<String, SigningError> {
    match source {
        MasterDataSource::Download => download_and_cache_master_data(KnxSchemaVersion::default()),
        MasterDataSource::DownloadVersion(version) => download_and_cache_master_data(*version),
        MasterDataSource::File(path) => Ok(fs::read_to_string(path)?),
        MasterDataSource::Content(content) => Ok(content.clone()),
    }
}

/// Download master data and cache it locally.
fn download_and_cache_master_data(version: KnxSchemaVersion) -> Result<String, SigningError> {
    // Cache filename includes version to support multiple versions
    let cache_filename = format!("knx_master_v{}.xml", version.as_str());

    // Check cache first
    if let Some(cache_dir) = get_cache_dir() {
        let cache_path = cache_dir.join(&cache_filename);
        if cache_path.exists()
            && let Ok(content) = fs::read_to_string(&cache_path)
        {
            log::info!("Using cached {} from {:?}", cache_filename, cache_path);
            return Ok(content);
        }
    }

    // Download
    let url = version.master_data_url();
    log::info!("Downloading knx_master.xml from {}", url);
    let response = reqwest::blocking::get(&url)?;
    let content = response.text()?;

    // Cache for future use
    if let Some(cache_dir) = get_cache_dir() {
        let _ = fs::create_dir_all(&cache_dir);
        let cache_path = cache_dir.join(&cache_filename);
        if let Err(e) = fs::write(&cache_path, &content) {
            log::warn!("Failed to cache {}: {}", cache_filename, e);
        } else {
            log::info!("Cached {} to {:?}", cache_filename, cache_path);
        }
    }

    Ok(content)
}

/// Get the cache directory for KNX data.
fn get_cache_dir() -> Option<PathBuf> {
    directories::ProjectDirs::from("org", "knx", "knxprod").map(|dirs| dirs.cache_dir().to_path_buf())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The cache directory is platform-dependent and may legitimately
    /// be unavailable (no HOME); the contract is only that resolving
    /// it never panics.
    #[test]
    fn cache_dir_resolves_without_panicking() {
        let _ = get_cache_dir();
    }

    /// `File` and `Content` resolve without touching the network.
    #[test]
    fn local_sources_resolve_offline() {
        let content = get_master_data(&MasterDataSource::Content("<KNX/>".to_string())).expect("inline content");
        assert_eq!(content, "<KNX/>");

        let missing = get_master_data(&MasterDataSource::File("/nonexistent/knx_master.xml".into()));
        assert!(missing.is_err(), "a missing file is an error, not a silent download");
    }
}
