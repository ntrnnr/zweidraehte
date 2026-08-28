//! Read-only project dashboard model shared by the terminal renderer and
//! future frontends. Secret values never enter this component.

use std::collections::BTreeMap;

use zweidraehte_project::{
    AuthoredProject, DeviceProgrammingStatus, KeyEpoch, KeyId, KeyKind, KeyMaterialSource, KeyScope, MembershipRole,
    NetId, ProjectDeviceId, ProjectStore,
};

/// One selectable entry in the permanent project navigator.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProjectNavigationTarget {
    Device(ProjectDeviceId),
    Net(NetId),
}

/// A rendered topology row. Area and line rows deliberately are not
/// selectable: activating a row always has an unambiguous project entity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProjectTopologyRow {
    pub depth: usize,
    pub label: String,
    pub target: Option<ProjectDeviceId>,
    pub inactive: bool,
}

/// The small, product-independent view model used by the left project pane.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProjectNetRow {
    pub id: NetId,
    pub label: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProjectNavigation {
    pub topology: Vec<ProjectTopologyRow>,
    pub nets: Vec<ProjectNetRow>,
    pub active_device: ProjectDeviceId,
    pub selected: usize,
    targets: Vec<ProjectNavigationTarget>,
}

impl ProjectNavigation {
    pub fn from_project(project: &AuthoredProject, active_device: ProjectDeviceId) -> Self {
        let mut topology = Vec::new();
        let mut targets = Vec::new();
        let mut previous_area = None;
        let mut previous_line = None;

        let mut devices = project.devices.values().collect::<Vec<_>>();
        devices.sort_by_key(|device| (device.area, device.line, device.address, device.id.clone()));
        for device in devices {
            if previous_area != Some(device.area) {
                topology.push(ProjectTopologyRow {
                    depth: 0,
                    label: format!("Area {}", device.area),
                    target: None,
                    inactive: false,
                });
                previous_area = Some(device.area);
                previous_line = None;
            }
            if previous_line != Some(device.line) {
                topology.push(ProjectTopologyRow {
                    depth: 1,
                    label: format!("Line {}", device.line),
                    target: None,
                    inactive: false,
                });
                previous_line = Some(device.line);
            }
            let secure = if device.data_secure.is_enabled() { "  [DS]" } else { "" };
            let inactive = if device.active { "" } else { "  [inactive]" };
            topology.push(ProjectTopologyRow {
                depth: 2,
                label: format!("{}  {}{secure}{inactive}", device.id, device.address),
                target: Some(device.id.clone()),
                inactive: !device.active,
            });
            targets.push(ProjectNavigationTarget::Device(device.id.clone()));
        }

        let nets = project
            .nets
            .values()
            .map(|net| {
                let member_count = project
                    .devices
                    .values()
                    .filter(|device| device.active)
                    .flat_map(|device| device.objects.values())
                    .flat_map(|object| &object.memberships)
                    .filter(|membership| membership.net == net.id)
                    .count();
                targets.push(ProjectNavigationTarget::Net(net.id.clone()));
                let identity =
                    net.name.as_ref().map_or_else(|| net.id.to_string(), |name| format!("{name}  [{}]", net.id));
                ProjectNetRow {
                    id: net.id.clone(),
                    label: format!("{}  {identity}  {}  {:?}  ({member_count})", net.address, net.dpt, net.security),
                }
            })
            .collect();
        let selected = targets
            .iter()
            .position(|target| target == &ProjectNavigationTarget::Device(active_device.clone()))
            .unwrap_or(0);
        Self { topology, nets, active_device, selected, targets }
    }

    pub fn selected_target(&self) -> Option<&ProjectNavigationTarget> {
        self.targets.get(self.selected)
    }

    pub fn move_up(&mut self) {
        self.selected = self.selected.saturating_sub(1);
    }

    pub fn move_down(&mut self) {
        self.selected = (self.selected + 1).min(self.targets.len().saturating_sub(1));
    }

    pub fn select(&mut self, target: &ProjectNavigationTarget) {
        if let Some(selected) = self.targets.iter().position(|candidate| candidate == target) {
            self.selected = selected;
        }
    }
}

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
                let programming = store.state().map_or("not programmed", |state| {
                    let status = state.programming_status(&device.id.0);
                    if status.is_complete() {
                        "fully programmed"
                    } else if status != DeviceProgrammingStatus::NONE {
                        "partially programmed"
                    } else {
                        "not programmed"
                    }
                });
                format!(
                    "{}  {}  {}  Data Secure {}  {}",
                    device.id,
                    device.address,
                    device
                        .serial
                        .as_ref()
                        .map(zweidraehte_project::format_serial)
                        .unwrap_or_else(|| "no serial".into()),
                    if device.data_secure.is_enabled() { "enabled" } else { "disabled" },
                    if device.active { programming } else { "inactive" }
                )
            })
            .collect();

        let nets = store
            .authored()
            .nets
            .values()
            .map(|net| {
                let mut members = Vec::new();
                for device in store.authored().devices.values().filter(|device| device.active) {
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
                        members.push(format!(
                            "external:{}@{}:DS-{}",
                            sender.id,
                            sender.address,
                            if sender.data_secure.is_enabled() { "on" } else { "off" }
                        ));
                    }
                }
                members.sort();
                let identity =
                    net.name.as_ref().map_or_else(|| net.id.to_string(), |name| format!("{name} [{}]", net.id));
                format!("{identity}  {}  {}  {:?}  [{}]", net.address, net.dpt, net.security, members.join(", "))
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
    fn project_navigation_groups_devices_and_lists_nets() {
        let project = AuthoredProject::parse(
            "ga lights = 1/0/1\n\
             net lights : 1.001 { name \"Ceiling lights\" security authentication_confidentiality }\n\
             area 1 bench { line 1 main { medium tp1\n\
               device button { product local:\"button.xml\" address 1.1.10 data_secure enabled object 0 { on lights } }\n\
               device relay { active false product local:\"relay.xml\" address 1.1.20 data_secure enabled object 0 { on lights } }\n\
             } }\n",
        )
        .expect("project parses");
        let navigation = ProjectNavigation::from_project(&project, ProjectDeviceId("relay".into()));

        assert_eq!(navigation.topology[0].label, "Area 1");
        assert_eq!(navigation.topology[1].label, "Line 1");
        assert!(navigation.topology.iter().any(|row| row.label.contains("button  1.1.10  [DS]")));
        assert!(navigation.topology.iter().any(|row| row.label.contains("relay  1.1.20  [DS]  [inactive]")));
        assert_eq!(navigation.nets.len(), 1);
        assert!(navigation.nets[0].label.contains("1/0/1  Ceiling lights  [lights]"));
        assert_eq!(
            navigation.selected_target(),
            Some(&ProjectNavigationTarget::Device(ProjectDeviceId("relay".into())))
        );
    }

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
