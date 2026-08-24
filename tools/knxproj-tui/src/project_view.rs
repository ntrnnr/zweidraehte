//! Read-only project dashboard model shared by the terminal renderer and
//! future frontends. Secret values never enter this component.

use std::collections::BTreeMap;

use zweidraehte_project::{
    KeyEpoch, KeyId, KeyKind, KeyMaterialSource, KeyScope, MembershipRole, NetId, ProjectDeviceId, ProjectStore,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProjectOverview {
    pub devices: Vec<String>,
    pub nets: Vec<String>,
    pub keys: Vec<String>,
    pub state: Vec<String>,
}

/// Writable key slots shown by the project key editor. The model identifies
/// the destination only; secret bytes live solely in the transient input and
/// are passed directly to [`zweidraehte_project::ProjectKeyStore`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EditableKey {
    DeviceFdsk(ProjectDeviceId),
    DeviceToolKey(ProjectDeviceId),
    GroupKey { net: NetId, epoch: KeyEpoch },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyEditorEntry {
    pub target: EditableKey,
    pub label: String,
    pub status: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProjectKeyEditor {
    pub entries: Vec<KeyEditorEntry>,
    pub selected: usize,
    pub input: Option<String>,
}

impl ProjectKeyEditor {
    pub fn load(store: &ProjectStore) -> Result<Self, String> {
        let keys = store.keys().ok_or_else(|| "project keys are not initialized".to_string())?;
        let metadata = keys.list().map_err(|error| error.to_string())?;
        let mut by_id = BTreeMap::new();
        for key in metadata {
            by_id.insert((key.id.clone(), key.epoch), key);
        }

        let mut entries = Vec::new();
        for device in store.authored().devices.keys() {
            for (kind, suffix) in [(KeyKind::Fdsk, "FDSK"), (KeyKind::ToolKey, "tool key")] {
                let id = KeyId { scope: KeyScope::Device(device.0.clone()), kind };
                let key = by_id.get(&(id, None));
                entries.push(KeyEditorEntry {
                    target: if kind == KeyKind::Fdsk {
                        EditableKey::DeviceFdsk(device.clone())
                    } else {
                        EditableKey::DeviceToolKey(device.clone())
                    },
                    label: format!("device {device} {suffix}"),
                    status: masked_status(key),
                });
            }
        }
        for net in store.authored().nets.keys() {
            let id = KeyId { scope: KeyScope::Group(net.0.clone()), kind: KeyKind::GroupKey };
            let active = keys.read(&id, None).map_err(|error| error.to_string())?;
            let epoch = active.as_ref().and_then(|record| record.metadata.epoch).unwrap_or(KeyEpoch(1));
            entries.push(KeyEditorEntry {
                target: EditableKey::GroupKey { net: net.clone(), epoch },
                label: format!("net {net} group key epoch {}", epoch.0),
                status: active.as_ref().map_or_else(|| "unset".into(), |record| masked_record(&record.metadata)),
            });
        }
        Ok(Self { entries, selected: 0, input: None })
    }

    pub fn selected_target(&self) -> Option<&EditableKey> {
        self.entries.get(self.selected).map(|entry| &entry.target)
    }

    pub fn move_up(&mut self) {
        self.selected = self.selected.saturating_sub(1);
    }

    pub fn move_down(&mut self) {
        self.selected = (self.selected + 1).min(self.entries.len().saturating_sub(1));
    }
}

fn masked_status(metadata: Option<&zweidraehte_project::KeyMetadata>) -> String {
    metadata.map_or_else(|| "unset".into(), masked_record)
}

fn masked_record(metadata: &zweidraehte_project::KeyMetadata) -> String {
    format!(
        "set ({}…, {:?})",
        metadata.fingerprint[..4].iter().map(|byte| format!("{byte:02x}")).collect::<String>(),
        metadata.origin
    )
}

impl ProjectOverview {
    pub fn load(store: &ProjectStore) -> Result<Self, String> {
        let devices = store
            .authored()
            .devices
            .values()
            .map(|device| {
                let deployed = store.state().is_some_and(|state| state.deployments.contains_key(&device.id.0));
                format!(
                    "{}  {}  {}{}",
                    device.id,
                    device.address,
                    device
                        .serial
                        .as_ref()
                        .map(zweidraehte_project::format_serial)
                        .unwrap_or_else(|| "no serial".into()),
                    if deployed { "  deployed" } else { "  not deployed" }
                )
            })
            .collect();

        let nets = store
            .authored()
            .nets
            .values()
            .map(|net| {
                let mut members = Vec::new();
                for device in store.authored().devices.values() {
                    for object in device.objects.values() {
                        for membership in &object.memberships {
                            if membership.net == net.id {
                                let role = match membership.role {
                                    MembershipRole::Primary => "primary",
                                    MembershipRole::Additional => "additional",
                                };
                                members.push(format!("{}:O{}:{role}", device.id, object.com_object));
                            }
                        }
                    }
                }
                for sender in store.authored().external_senders.values() {
                    if sender.nets.contains(&net.id) {
                        members.push(format!("external:{}@{}", sender.id, sender.address));
                    }
                }
                members.sort();
                format!("{}  {}  {}  {:?}  [{}]", net.id, net.address, net.dpt, net.security, members.join(", "))
            })
            .collect();

        let keys = match store.keys() {
            Some(keys) => keys
                .list()
                .map_err(|error| error.to_string())?
                .into_iter()
                .map(|metadata| {
                    format!(
                        "{:?}  {:?}  epoch {:?}  {}…  {:?}",
                        metadata.id.scope,
                        metadata.id.kind,
                        metadata.epoch,
                        metadata.fingerprint[..4].iter().map(|byte| format!("{byte:02x}")).collect::<String>(),
                        metadata.origin
                    )
                })
                .collect(),
            None => vec!["not initialized".into()],
        };

        let state = match store.state() {
            Some(state) => vec![
                format!("identity: {}", if store.secure_state_ready() { "ready" } else { "blocked" }),
                format!("client next: {}", state.client_next),
                format!("device observations: {}", state.devices.len()),
                format!("sender observations: {}", state.sender_floors.len()),
                format!("inconsistent devices: {}", state.inconsistent_devices.join(", ")),
            ],
            None => vec!["not initialized".into()],
        };
        Ok(Self { devices, nets, keys, state })
    }

    pub fn lines(&self) -> Vec<String> {
        let mut lines = Vec::new();
        for (title, values) in [
            ("Devices", &self.devices),
            ("Nets", &self.nets),
            ("Masked key metadata", &self.keys),
            ("Mutable state", &self.state),
        ] {
            lines.push(title.to_string());
            lines.extend(values.iter().map(|value| format!("  {value}")));
            lines.push(String::new());
        }
        lines
    }
}

#[cfg(test)]
mod tests {
    use std::fs;

    use super::*;

    #[test]
    fn dashboard_never_contains_key_values() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = directory.path().join("project.knx");
        fs::write(
            &path,
            "ga n = 1/0/1\nnet n : 1.001 { security plain }\narea 1 a { line 1 l { medium tp1 device d { product local:\"d.mtxml\" address 1.1.1 object 0 { on n } } } }\n",
        )
        .expect("project writes");
        let mut store = ProjectStore::open(&path).expect("project opens");
        store.initialize().expect("store initializes");
        let overview = ProjectOverview::load(&store).expect("overview loads");
        assert!(overview.lines().iter().any(|line| line.contains("d  1.1.1")));
        assert!(!overview.lines().iter().any(|line| line.contains("value")));
    }

    #[test]
    fn key_editor_lists_device_and_net_slots_without_secret_values() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = directory.path().join("project.knx");
        fs::write(
            &path,
            "ga n = 1/0/1\nnet n : 1.001 { security automatic }\narea 1 a { line 1 l { medium tp1 device d { product local:\"d.mtxml\" address 1.1.1 object 0 { on n } } } }\n",
        )
        .expect("project writes");
        let mut store = ProjectStore::open(&path).expect("project opens");
        store.initialize().expect("store initializes");
        store
            .keys_mut()
            .expect("keys exist")
            .put_device_tool_key("d", "00112233445566778899AABBCCDDEEFF", zweidraehte_project::KeyOrigin::Manual)
            .expect("tool key persists");

        let editor = ProjectKeyEditor::load(&store).expect("key editor loads");
        assert_eq!(editor.entries.len(), 3);
        assert!(editor.entries.iter().any(|entry| entry.label == "device d tool key" && entry.status.contains("set")));
        assert!(!format!("{editor:?}").contains("00112233445566778899AABBCCDDEEFF"));
    }
}
