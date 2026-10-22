//! Thread/channel adaptation around the shared status acquisition boundary.

use crate::error_message;
use std::path::PathBuf;
use std::sync::mpsc::Sender;
use zweidraehte_client::cli::SecurityArgs;
use zweidraehte_client::project::{ProgrammingSnapshot, ProjectStatusCache, ProjectStatusRequest};
use zweidraehte_project::AuthoredProject;

pub(crate) struct StatusRefreshJob {
    pub(crate) project_path: PathBuf,
    pub(crate) master_data: Option<PathBuf>,
    pub(crate) security: Option<SecurityArgs>,
    pub(crate) draft: (AuthoredProject, String),
    pub(crate) generation: u64,
    pub(crate) cache: ProjectStatusCache,
}

pub(crate) struct StatusRefreshOutcome {
    pub(crate) snapshot: ProgrammingSnapshot,
    pub(crate) cache: ProjectStatusCache,
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
    Ok(StatusRefreshOutcome { snapshot, cache: std::mem::take(&mut job.cache) })
}
