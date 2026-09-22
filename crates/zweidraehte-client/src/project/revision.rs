//! Content guards shared by status acquisition and reviewed imports.

use crate::project::error::{Error, Result};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone)]
pub(super) struct FileRevision(pub(super) BTreeMap<PathBuf, Option<[u8; 32]>>);

impl FileRevision {
    pub(super) fn capture(paths: impl IntoIterator<Item = PathBuf>) -> Result<Self> {
        Ok(Self(paths.into_iter().map(|path| Ok((path.clone(), file_digest(&path)?))).collect::<Result<_>>()?))
    }

    pub(super) fn verify(&self, changed: impl FnOnce() -> Error) -> Result<()> {
        for (path, digest) in &self.0 {
            if file_digest(path)? != *digest {
                return Err(changed());
            }
        }
        Ok(())
    }
}

pub(super) fn file_digest(path: &Path) -> Result<Option<[u8; 32]>> {
    match std::fs::read(path) {
        Ok(bytes) => Ok(Some(Sha256::digest(&bytes).into())),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error.into()),
    }
}
