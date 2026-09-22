//! Project-operation errors, including adaptation from bus and product lowering.

use zweidraehte_ets_files::archive::ProductLoadError;
use zweidraehte_ets_files::product::ProductError;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error(transparent)]
    Bus(#[from] crate::bus::BusError),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("parse error: {0}")]
    Parse(&'static str),

    #[error("device configuration invalid: {0}")]
    DeviceConfiguration(String),

    #[error(transparent)]
    ProductConfiguration(#[from] zweidraehte_ets_files::runtime::configuration::ConfigurationError),

    #[error("managed SIAT sender `{device}` at {address} needs loaded product and serial input before planning")]
    MissingSenderInput { device: String, address: crate::IndividualAddress },

    #[error("product `{product}` has no loaded Master Data for schema {schema:?}")]
    MissingCatalog { product: String, schema: Option<u16> },

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

    #[error("cannot load programming catalog")]
    CatalogLoad(#[from] crate::commissioning::ProgrammingCatalogLoadError),

    #[error("cannot resolve programming catalog")]
    Catalog(#[source] crate::commissioning::CompileError),

    #[error("product data: {0}")]
    ProductData(String),
}

pub type Result<T> = core::result::Result<T, Error>;

// Preserve the established project error classification while lowering remains
// usable without the project's storage and orchestration dependencies.
impl From<crate::configuration::ConfigurationError> for Error {
    fn from(error: crate::configuration::ConfigurationError) -> Self {
        use crate::configuration::ConfigurationError;
        match error {
            ConfigurationError::DeviceConfiguration(message) => Self::DeviceConfiguration(message),
            ConfigurationError::ProductData(message) => Self::ProductData(message),
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
