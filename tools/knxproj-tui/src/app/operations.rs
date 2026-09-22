//! Modal state and worker progress. The client operation owns bus execution.

use zweidraehte_client::BusTarget;
use zweidraehte_client::project::{ProjectBatchReport, Result as ProjectResult};

/// The live download popup's state, fed by the worker thread.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeviceOperation {
    Programming,
    Unloading,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProgrammingTarget {
    Selected,
    Affected,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProgrammingDialog {
    pub operation: crate::download::ProgrammingOperation,
    pub target: ProgrammingTarget,
    pub desired_address: String,
    /// Present while the overwrite operation is asking for the address that
    /// is currently on the physical device. ETS cannot infer this safely
    /// from project history, either: the operator has to name it explicitly.
    pub overwrite_address_input: Option<String>,
    pub overwrite_address_error: Option<String>,
}

pub struct DownloadUi {
    /// Operation named by the modal title and footer.
    pub operation: DeviceOperation,
    /// Finished task labels, oldest first.
    pub past: Vec<String>,
    /// The task currently running.
    pub current: Option<String>,
    /// `(index, total)` of the current procedure step; total 0 while
    /// still in the preparation stages.
    pub step: (usize, usize),
    /// Byte progress within the current step, when it has one.
    pub data: Option<(u64, u64)>,
    /// The outcome, once the worker is done.
    pub result: Option<Result<String, String>>,
    /// First wrapped result row shown in the finished modal. The renderer
    /// clamps this against the current terminal size after every resize.
    pub result_scroll: u16,
    /// Spinner phase, advanced every UI tick.
    pub spinner: usize,
    /// Present while the worker continuously scans for one physical
    /// programming-mode device. A serial shortcut is exposed only when the
    /// project has a usable serial and the product mask supports it.
    pub assignment_prompt: Option<AssignmentPrompt>,
    /// Retain physical reports and typed failures after rendering their summary.
    pub execution: Option<ProjectResult<ProjectBatchReport>>,
    receiver: std::sync::mpsc::Receiver<crate::download::DownloadMsg>,
    control: tokio::sync::mpsc::UnboundedSender<crate::download::DownloadControl>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AssignmentPrompt {
    pub serial_number: Option<[u8; 6]>,
}

/// What the App needs to start a download; provided from the CLI.
pub struct DownloadContext {
    pub target: Option<BusTarget>,
    pub master_data: Option<std::path::PathBuf>,
    pub security: zweidraehte_client::cli::SecurityArgs,
}

/// Operation dialogs and worker progress, independent of product selection.
/// Bus execution remains owned by the client operation on the worker.
#[derive(Default)]
pub struct OperationUi {
    pub(super) download_context: Option<DownloadContext>,
    pub(super) programming_dialog: Option<ProgrammingDialog>,
    pub(super) unload_confirmation: Option<crate::download::UnloadScope>,
    download: Option<DownloadUi>,
}

impl OperationUi {
    pub(super) fn start(
        &mut self,
        operation: DeviceOperation,
        receiver: std::sync::mpsc::Receiver<crate::download::DownloadMsg>,
        control: tokio::sync::mpsc::UnboundedSender<crate::download::DownloadControl>,
    ) {
        self.download = Some(DownloadUi {
            operation,
            receiver,
            control,
            past: Vec::new(),
            current: None,
            step: (0, 0),
            data: None,
            result: None,
            result_scroll: 0,
            spinner: 0,
            assignment_prompt: None,
            execution: None,
        });
    }

    pub(super) fn complete(
        &mut self,
        result: Result<String, String>,
        execution: Option<ProjectResult<ProjectBatchReport>>,
    ) {
        if let Some(download) = &mut self.download {
            download.result = Some(result);
            download.execution = execution;
        }
    }

    pub(super) fn poll(&mut self) -> Option<Result<crate::download::DownloadOutcome, String>> {
        let mut completion = None;
        {
            let Some(download) = &mut self.download else { return None };
            download.spinner = download.spinner.wrapping_add(1);
            while let Ok(message) = download.receiver.try_recv() {
                match message {
                    crate::download::DownloadMsg::Task(label, index, total) => {
                        download.assignment_prompt = None;
                        if let Some(previous) = download.current.take() {
                            download.past.push(previous);
                        }
                        download.current = Some(label);
                        download.step = (index, total);
                        download.data = None;
                    }
                    crate::download::DownloadMsg::Data(done, total) => {
                        download.data = Some((done, total));
                    }
                    crate::download::DownloadMsg::AwaitingProgrammingMode { serial_number } => {
                        if let Some(previous) = download.current.take() {
                            download.past.push(previous);
                        }
                        download.current = Some("Waiting for one device in physical programming mode".into());
                        download.step = (0, 0);
                        download.data = None;
                        download.assignment_prompt = Some(AssignmentPrompt { serial_number });
                    }
                    crate::download::DownloadMsg::Done(result) => {
                        download.assignment_prompt = None;
                        if let Some(previous) = download.current.take() {
                            download.past.push(previous);
                        }
                        completion = Some(result);
                    }
                }
            }
        }

        completion
    }

    pub fn download(&self) -> Option<&DownloadUi> {
        self.download.as_ref()
    }

    pub fn download_active(&self) -> bool {
        self.download.is_some()
    }

    pub fn download_finished(&self) -> bool {
        self.download.as_ref().is_some_and(|download| download.result.is_some())
    }

    /// Move through a finished download result. The renderer owns the
    /// viewport-dependent upper bound and clamps this value on the next draw.
    pub fn scroll_download_result(&mut self, delta: i16) {
        let Some(download) = self.download.as_mut().filter(|download| download.result.is_some()) else {
            return;
        };

        download.result_scroll = if delta.is_negative() {
            download.result_scroll.saturating_sub(delta.unsigned_abs())
        } else {
            download.result_scroll.saturating_add(delta as u16)
        };
    }

    pub fn reset_download_result_scroll(&mut self) {
        if let Some(download) = self.download.as_mut().filter(|download| download.result.is_some()) {
            download.result_scroll = 0;
        }
    }

    pub fn scroll_download_result_to_end(&mut self) {
        if let Some(download) = self.download.as_mut().filter(|download| download.result.is_some()) {
            // The exact last row depends on the popup size. The renderer turns
            // this sentinel into that row before the next input event.
            download.result_scroll = u16::MAX;
        }
    }

    pub fn clamp_download_result_scroll(&mut self, maximum: u16) {
        if let Some(download) = self.download.as_mut() {
            download.result_scroll = download.result_scroll.min(maximum);
        }
    }

    pub fn assignment_prompt_active(&self) -> bool {
        self.download.as_ref().is_some_and(|download| download.assignment_prompt.is_some())
    }

    /// Choose the serial-number alternative offered by the active IA
    /// assignment prompt.
    pub fn use_serial_number_for_assignment(&mut self) {
        let Some(download) = &mut self.download else { return };
        let Some(prompt) = download.assignment_prompt else { return };
        let Some(serial) = prompt.serial_number else { return };

        if download.control.send(crate::download::DownloadControl::UseSerialNumber).is_ok() {
            download.assignment_prompt = None;
            download.current =
                Some(format!("Selecting device by serial {}", zweidraehte_project::format_serial(&serial)));
        }
    }

    /// Stop an IA assignment that is waiting for a physical programming
    /// button. Other programming stages remain deliberately non-interactive.
    pub fn cancel_assignment_prompt(&mut self) {
        let Some(download) = &mut self.download else { return };
        if download.assignment_prompt.take().is_none() {
            return;
        }

        if download.control.send(crate::download::DownloadControl::Cancel).is_ok() {
            download.current = Some("Cancelling individual-address assignment".into());
        }
    }

    /// Close the popup once the worker finished.
    pub fn dismiss_download(&mut self) {
        if self.download.as_ref().is_some_and(|d| d.result.is_some()) {
            self.download = None;
        }
    }

    /// Overall progress of the running download, 0..=100.
    pub fn download_ratio(&self) -> u16 {
        let Some(download) = &self.download else { return 0 };
        if download.result.is_some() {
            return 100;
        }
        let (index, total) = download.step;
        if total == 0 {
            return 0;
        }
        let intra = download.data.map_or(0.0, |(done, all)| if all == 0 { 0.0 } else { done as f64 / all as f64 });
        (((index as f64 + intra) / total as f64) * 100.0).clamp(0.0, 100.0) as u16
    }

    pub fn programming_dialog(&self) -> Option<&ProgrammingDialog> {
        self.programming_dialog.as_ref()
    }

    pub fn unload_confirmation(&self) -> Option<crate::download::UnloadScope> {
        self.unload_confirmation
    }

    pub fn programming_dialog_active(&self) -> bool {
        self.programming_dialog.is_some()
    }

    pub fn unload_confirmation_active(&self) -> bool {
        self.unload_confirmation.is_some()
    }

    pub fn move_unload_selection(&mut self, delta: isize) {
        let Some(current) = self.unload_confirmation else { return };
        let scopes = crate::download::UnloadScope::ALL;
        let current = scopes.iter().position(|scope| *scope == current).expect("the selected unload scope is listed");
        let selected = current.saturating_add_signed(delta).min(scopes.len() - 1);

        self.unload_confirmation = Some(scopes[selected]);
    }

    pub fn cancel_unload_confirmation(&mut self) {
        self.unload_confirmation = None;
    }
}
