//! Project-operation errors, including adaptation from bus and product lowering.

use crate::configuration::ErrorDetail;
use zweidraehte_ets_files::archive::ProductLoadError;
use zweidraehte_ets_files::product::ProductError;
use zweidraehte_project::{NetId, ProjectDeviceId};

/// Failure of a project operation.
///
/// Variants that name a device or net carry it as a typed value. The others
/// classify the failure by domain and carry an [`ErrorDetail`] for display:
/// match the variant, never the text.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    #[error(transparent)]
    Bus(#[from] crate::bus::BusError),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("project has no device `{0}`")]
    UnknownDevice(ProjectDeviceId),

    #[error("device `{0}` is not in the evaluated plan")]
    NotPlanned(ProjectDeviceId),

    #[error("no product loaded for `{0}`")]
    MissingProduct(ProjectDeviceId),

    #[error("project has no net `{0}`")]
    UnknownNet(NetId),

    #[error("project source has no filesystem path for its package store")]
    NoPackageStore,

    /// The authored project contradicts itself or its products.
    #[error("device configuration invalid: {0}")]
    InvalidProject(ErrorDetail),

    /// An ETS keyring disagrees with the authored project.
    #[error("cannot import the keyring: {0}")]
    KeyringImport(ErrorDetail),

    /// The project cannot be expressed in the ETS keyring format.
    #[error("cannot export the keyring: {0}")]
    KeyringExport(ErrorDetail),

    /// Durable project state does not prove what the operation needs.
    #[error("project state: {0}")]
    StateEvidence(ErrorDetail),

    /// The project asks for behaviour this library does not implement.
    #[error("unsupported: {0}")]
    Unsupported(ErrorDetail),

    /// The status preview of one device does not compile.
    #[error("could not compile `{device}` status")]
    StatusPreview {
        device: ProjectDeviceId,
        #[source]
        source: crate::commissioning::CompileError,
    },

    #[error(transparent)]
    ProductConfiguration(#[from] zweidraehte_ets_files::runtime::configuration::ConfigurationError),

    #[error("managed SIAT sender `{device}` at {address} needs loaded product and serial input before planning")]
    MissingSenderInput { device: ProjectDeviceId, address: crate::IndividualAddress },

    #[error("product `{product}` has no selected installation Master Data")]
    MissingCatalog { product: String },

    #[error(transparent)]
    KeyMaterial(#[from] zweidraehte_project::KeyStoreError),

    #[error(transparent)]
    Keyring(#[from] crate::security::KnxKeysError),

    #[error(transparent)]
    ProjectStore(#[from] zweidraehte_project::ProjectStoreError),

    #[error(transparent)]
    ProjectRender(#[from] zweidraehte_project::RenderError),

    #[error(transparent)]
    ProductLoad(#[from] ProductLoadError),

    #[error(transparent)]
    PackageStore(#[from] zweidraehte_ets_files::archive::PackageStoreError),

    #[error(transparent)]
    ProductFormat(#[from] ProductError),

    #[error(transparent)]
    Commissioning(#[from] crate::commissioning::CommissioningError),

    /// The observer refused a prepared device before its first write.
    #[error("the prepared program was not approved: {0}")]
    Vetoed(crate::commissioning::CommissioningVeto),

    #[error("the shared project store lock is poisoned")]
    ProjectStorePoisoned,

    #[error("project status inputs changed; reload before comparing programming state")]
    StatusInputsChanged,

    #[error("project operation inputs changed; reload before programming")]
    OperationInputsChanged,

    #[error(
        "state recovery needs every managed secure receiver or an explicit client floor; unavailable: {unavailable:?}"
    )]
    RecoveryIncomplete { unavailable: Vec<zweidraehte_project::ProjectDeviceId> },

    #[error("management operation failed: {source}; closing the device connection also failed: {cleanup}")]
    ManagementCleanup { source: Box<Error>, cleanup: Box<Error> },

    #[error(transparent)]
    ProjectSetup(#[from] crate::project::ProjectSetupRequirement),

    #[error("project inputs changed; prepare the keyring import again")]
    KeyringImportInputsChanged,

    #[error(
        "keyring keys were committed and {observations_recorded} sequence observations were confirmed, but import persistence is incomplete: {source}"
    )]
    KeyringImportPartial {
        observations_recorded: usize,
        #[source]
        source: zweidraehte_project::ProjectStoreError,
    },

    #[error(transparent)]
    ProjectBatch(Box<crate::project::ProjectBatchFailure>),

    #[error("cannot load Master Data")]
    MasterDataLoad(#[from] zweidraehte_ets_files::MasterDataError),

    #[error("cannot use Master Data for programming")]
    Catalog(#[source] crate::commissioning::ProfileError),

    #[error("product data: {0}")]
    ProductData(ErrorDetail),
}

pub type Result<T> = core::result::Result<T, Error>;

// Preserve the established project error classification while lowering remains
// usable without the project's storage and orchestration dependencies.
impl From<crate::configuration::ConfigurationError> for Error {
    fn from(error: crate::configuration::ConfigurationError) -> Self {
        use crate::configuration::ConfigurationError;
        match error {
            ConfigurationError::ProductData(detail) => Self::ProductData(detail),
        }
    }
}

// CLI and TUI project workers share this adaptation when both capabilities are
// selected. Standalone CLI keyring loading remains independent of project storage.
#[cfg(feature = "cli")]
mod cli {
    use super::Error;
    use crate::cli::SecurityArgsError;
    use zweidraehte_project::KeyStoreError;

    impl From<SecurityArgsError> for Error {
        fn from(error: SecurityArgsError) -> Self {
            match error {
                SecurityArgsError::MissingPassword => Self::KeyMaterial(KeyStoreError::Unavailable(error.to_string())),
                SecurityArgsError::Keyring(error) => Self::Keyring(error),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::Error;
    use std::error::Error as _;
    use std::io;
    use zweidraehte_ets_files::archive::ProductLoadError;
    use zweidraehte_ets_files::product::ProductError;
    use zweidraehte_ets_files::runtime::configuration::ConfigurationError;

    #[test]
    fn product_error_adapters_preserve_messages_and_typed_causes() {
        let adapters: [fn(ProductError) -> Error; 3] =
            [Error::from, |error| ProductLoadError::from(error).into(), |error| ConfigurationError::from(error).into()];
        for adapt in adapters {
            let error = adapt(ProductError::Io(io::Error::from(io::ErrorKind::PermissionDenied)));
            assert_eq!(error.to_string(), "cannot read product XML");
            let cause =
                error.source().expect("retained I/O cause").downcast_ref::<io::Error>().expect("typed I/O error");
            assert_eq!(cause.kind(), io::ErrorKind::PermissionDenied);
        }

        let error = Error::from(ProductLoadError::ApplicationProgramPairing {
            path: "light-switch.knxprod".into(),
            source: ProductError::MissingApplicationProgram,
        });
        assert_eq!(
            error.to_string(),
            "light-switch.knxprod: cannot resolve the selected application's Hardware.xml relation"
        );
        assert!(matches!(
            error.source().expect("product context").downcast_ref::<ProductError>(),
            Some(ProductError::MissingApplicationProgram)
        ));
    }
}
