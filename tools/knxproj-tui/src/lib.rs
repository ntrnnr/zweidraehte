//! Reusable terminal components for KNX product and project editing.

pub mod app;
pub mod catalog_view;
pub mod download;
pub mod project_view;
mod status;
pub mod ui;

/// Render typed failures only when sending them to a terminal or UI channel.
/// Display alone omits nested I/O/XML causes retained by the client libraries.
pub fn error_message(error: &dyn std::error::Error) -> String {
    let mut message = error.to_string();
    let mut source = error.source();
    while let Some(cause) = source {
        message.push_str(": ");
        message.push_str(&cause.to_string());
        source = cause.source();
    }
    message
}

#[cfg(test)]
mod tests {
    use super::error_message;
    use zweidraehte_ets_files::MasterDataError;

    #[test]
    fn catalog_error_display_includes_the_source_path_and_io_cause() {
        let error = zweidraehte_client::project::Error::from(MasterDataError::Io {
            path: "knx_master.xml".into(),
            source: std::io::Error::new(std::io::ErrorKind::NotFound, "fixture file is missing"),
        });
        assert_eq!(
            error_message(&error),
            "cannot load Master Data: cannot read ETS master data from knx_master.xml: fixture file is missing"
        );
    }
}
