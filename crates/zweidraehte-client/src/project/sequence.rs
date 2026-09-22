//! Adapter from project-local mutable state to the bus sequence API.

use std::sync::Arc;

use zweidraehte_project::{ProjectEvent, ProjectStore, ProjectWriter, SenderIdentity, format_serial};
use zweidraehte_proto::address::IndividualAddress;

use super::session::LockedProjectStore;
use crate::security::SeqNumberStore;

/// Share the locked project session with the bus task without giving the
/// project crate a dependency back on the client.
#[derive(Clone)]
pub struct ProjectSeqStore {
    project: Arc<LockedProjectStore>,
}

impl ProjectSeqStore {
    pub(super) fn new(project: Arc<LockedProjectStore>) -> Self {
        Self { project }
    }

    fn with_project<T>(&self, operation: impl FnOnce(&ProjectStore) -> T) -> T {
        operation(self.project.lock().expect("project-store mutex is not poisoned").store())
    }

    fn with_project_mut<T>(
        &self,
        operation: impl FnOnce(&mut ProjectWriter) -> Result<T, zweidraehte_project::ProjectStoreError>,
    ) -> std::io::Result<T> {
        operation(&mut self.project.lock().expect("project-store mutex is not poisoned")).map_err(std::io::Error::other)
    }
}

impl SeqNumberStore for ProjectSeqStore {
    fn load_client_seq(&self) -> u64 {
        self.with_project(|project| project.state().map_or(1, |state| state.client_next.max(1)))
    }

    fn save_client_seq(&mut self, next: u64) -> std::io::Result<()> {
        self.with_project_mut(|project| project.advance_client_sequence(next).map(|_| ()))
    }

    fn reserve_client_seq(&mut self, floor: u64) -> std::io::Result<u64> {
        self.with_project_mut(|project| {
            project.advance_client_sequence(floor)?;
            project.reserve_client_sequence()
        })
    }

    fn reserve_management_client_seq(&mut self, floor: u64) -> std::io::Result<u64> {
        self.with_project_mut(|project| {
            project.advance_client_sequence(floor)?;
            project.reserve_recovery_management_sequence()
        })
    }

    fn load_device_seq(&self, serial: &[u8; 6]) -> u64 {
        let serial = format_serial(serial);
        self.with_project(|project| {
            project.state().and_then(|state| state.devices.get(&serial)).map_or(1, |device| device.outgoing_next.max(1))
        })
    }

    fn save_device_seq(&mut self, serial: &[u8; 6], next: u64) -> std::io::Result<()> {
        let serial = format_serial(serial);
        self.with_project_mut(|project| project.record(ProjectEvent::ObserveDeviceOutgoing { serial, next }))
    }

    fn load_sender_seq(&self, ia: IndividualAddress) -> u64 {
        let identity = SenderIdentity::UnmanagedAddress(ia.to_string());
        self.with_project(|project| {
            project
                .state()
                .and_then(|state| state.sender_floors.get(&identity))
                .map(|last_valid| last_valid.saturating_add(1))
                .unwrap_or(1)
        })
    }

    fn save_sender_seq(&mut self, ia: IndividualAddress, next: u64) -> std::io::Result<()> {
        self.with_project_mut(|project| {
            project.record(ProjectEvent::ObserveSender {
                sender: SenderIdentity::UnmanagedAddress(ia.to_string()),
                last_valid: next.saturating_sub(1),
            })
        })
    }
}

#[cfg(test)]
mod tests {
    use std::fs;

    use zweidraehte_project::ProjectStore;

    use super::*;

    const PROJECT: &str = "ga test = 1/0/1\nnet test : 1.001 { security authentication_confidentiality }\narea 1 a { line 1 l { medium tp1 device d { product package:\"sha256:0000000000000000000000000000000000000000000000000000000000000000\" catalog_item \"d\" address 1.1.1 serial \"00FA:00000001\" object 0 { on test } } } }\n";

    #[test]
    fn retained_sequence_writer_keeps_exclusion_after_session_finish_or_drop() {
        for finish in [false, true] {
            let directory = tempfile::tempdir().expect("temporary directory");
            let path = directory.path().join("project.knx");
            fs::write(&path, PROJECT).expect("project writes");
            let mut project = ProjectStore::open(&path).expect("project opens");
            project = project.initialize().expect("project initializes");
            let session = crate::project::ProjectCommissioningSession::begin(project).expect("session locks");
            let mut adapter = session.sequence_store();
            assert_eq!(adapter.reserve_client_seq(40).expect("first reservation"), 40);

            if finish {
                session.finish().expect("session compacts");
            } else {
                drop(session);
            }
            let other = ProjectStore::open(&path).expect("read-only open");
            assert!(other.into_writer().is_err(), "surviving writer retains exclusion");
            assert_eq!(adapter.reserve_client_seq(1).expect("retained reservation"), 41);
            drop(adapter);

            let reopened = ProjectStore::open(&path).expect("reopen after final writer drops");
            let session = crate::project::ProjectCommissioningSession::begin(reopened).expect("lock is released");
            let mut adapter = session.sequence_store();
            assert_eq!(adapter.reserve_client_seq(1).expect("reopened reservation"), 42);
        }
    }

    #[test]
    fn bus_reservations_land_in_the_project_journal() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = directory.path().join("project.knx");
        fs::write(&path, PROJECT).expect("project writes");
        let mut project = ProjectStore::open(&path).expect("project opens");
        project = project.initialize().expect("project initializes");
        let session = crate::project::ProjectCommissioningSession::begin(project).expect("session locks");
        let mut adapter = session.sequence_store();

        assert_eq!(adapter.reserve_client_seq(40).expect("sequence reserves"), 40);
        adapter.save_device_seq(&[0x00, 0xFA, 0, 0, 0, 1], 73).expect("observation saves");
        assert_eq!(adapter.load_client_seq(), 41);
        assert_eq!(adapter.load_device_seq(&[0x00, 0xFA, 0, 0, 0, 1]), 73);
    }
}
