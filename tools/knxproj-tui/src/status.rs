//! Thread/channel adaptation around the shared status acquisition boundary.

use crate::error_message;
use std::collections::BTreeSet;
use std::path::PathBuf;
use std::sync::mpsc::Sender;
use zweidraehte_client::cli::SecurityArgs;
use zweidraehte_client::project::{
    ProgrammingSnapshot, ProjectDownloadPreview, ProjectStatusCache, ProjectStatusRequest,
};
use zweidraehte_project::{AuthoredProject, ProjectDeviceId};

pub(crate) struct StatusRefreshJob {
    pub(crate) project_path: PathBuf,
    pub(crate) master_data: Option<PathBuf>,
    pub(crate) security: Option<SecurityArgs>,
    pub(crate) draft: (AuthoredProject, String),
    pub(crate) generation: u64,
    pub(crate) cache: ProjectStatusCache,
    /// The edited device, whose download procedure is compiled from the
    /// same inputs as the statuses.
    pub(crate) procedure_device: Option<ProjectDeviceId>,
}

pub(crate) struct StatusRefreshOutcome {
    pub(crate) snapshot: ProgrammingSnapshot,
    pub(crate) cache: ProjectStatusCache,
    pub(crate) procedure: Option<Result<DownloadPreview, String>>,
    /// Devices whose last successful programming established Data Secure.
    pub(crate) secured: BTreeSet<ProjectDeviceId>,
}

/// A compiled download procedure and whether a deployment record of the
/// device narrowed its sections.
pub(crate) struct DownloadPreview {
    pub(crate) preview: ProjectDownloadPreview,
    pub(crate) deployed: bool,
}

pub(crate) enum StatusRefreshMsg {
    Progress { generation: u64, label: String, completed: usize, total: usize },
    Done { generation: u64, result: Result<Box<StatusRefreshOutcome>, String> },
}

pub(crate) fn spawn(mut job: StatusRefreshJob, tx: Sender<StatusRefreshMsg>) {
    std::thread::spawn(move || {
        let result = calculate(&mut job, &tx);
        let _ = tx.send(StatusRefreshMsg::Done { generation: job.generation, result: result.map(Box::new) });
    });
}

fn calculate(job: &mut StatusRefreshJob, tx: &Sender<StatusRefreshMsg>) -> Result<StatusRefreshOutcome, String> {
    let mut request = ProjectStatusRequest::new(&job.project_path);
    request.draft = Some((&job.draft.0, &job.draft.1));
    request.master_data = job.master_data.as_deref();
    request.keyring_path = job.security.as_ref().and_then(SecurityArgs::keyring_path);
    let inputs = job
        .cache
        .load(
            request,
            || job.security.as_ref().map_or(Ok(None), SecurityArgs::load_keyring).map_err(Into::into),
            |id, completed, total| {
                let _ = tx.send(StatusRefreshMsg::Progress {
                    generation: job.generation,
                    label: format!("Loading product for {id}"),
                    completed,
                    total: total + 1,
                });
            },
        )
        .map_err(|error| error_message(&error))?;
    let _ = tx.send(StatusRefreshMsg::Progress {
        generation: job.generation,
        label: "Comparing desired and programmed data".into(),
        completed: inputs.products().len(),
        total: inputs.products().len() + 1,
    });
    let snapshot = inputs.snapshot().map_err(|error| error_message(&error))?;

    // The editor's own preview device has no project keys, secure peers or
    // topology, so it cannot know the desired security mode. Compile the
    // procedure here, from the inputs a download uses. Its failure is the
    // procedure tab's message, never a failed status calculation.
    let procedure = job.procedure_device.as_ref().map(|id| {
        let _ = tx.send(StatusRefreshMsg::Progress {
            generation: job.generation,
            label: format!("Compiling download procedure for {id}"),
            completed: inputs.products().len(),
            total: inputs.products().len() + 1,
        });
        let deployed = inputs.store().state().is_some_and(|state| state.deployment(id.as_str()).is_some());
        inputs
            .download_preview(id)
            .map(|preview| DownloadPreview { preview, deployed })
            .map_err(|error| error_message(&error))
    });
    // Only a recorded deployment says what the device runs. The project's
    // `data_secure` line is intent and may not have been programmed yet.
    let secured = inputs
        .store()
        .state()
        .map(|state| {
            state
                .deployments
                .iter()
                .filter(|(_, evidence)| {
                    evidence.commissioning.as_ref().and_then(|record| record.data_security_enabled) == Some(true)
                })
                .filter_map(|(id, _)| ProjectDeviceId::new(id.as_str()).ok())
                .collect()
        })
        .unwrap_or_default();
    Ok(StatusRefreshOutcome { snapshot, cache: std::mem::take(&mut job.cache), procedure, secured })
}
