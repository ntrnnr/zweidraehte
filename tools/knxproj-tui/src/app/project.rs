//! Optional authored project, draft commands and revision-bound status.
//! Only this owner mutates the saved base/draft pair or installs worker output.

use super::{DownloadContext, ProductView, ProjectContext};
use crate::project_view::{EditableKey, ProjectNavigation, ProjectNavigationTarget};
use std::collections::{BTreeMap, BTreeSet};
use zweidraehte_client::project::{ProgrammingSnapshot, ProjectStatusCache};
use zweidraehte_ets_files::runtime::configuration::{
    ProductConfiguration, ProductDptReferences, configuration_from_device, effective_com_objects,
};
use zweidraehte_ets_files::runtime::model::ParameterValue;
use zweidraehte_project::{AuthoredProject, NetId, NetSecurityPolicy, ProjectDeviceId, ProjectStore};

/// Background project-status calculation, fed by a read-only worker.
pub(crate) struct StartupStatusUi {
    pub(crate) current: String,
    pub(crate) completed: usize,
    pub(crate) total: usize,
    pub(crate) spinner: usize,
    pub(crate) error: Option<String>,
    generation: u64,
    receiver: std::sync::mpsc::Receiver<crate::status::StatusRefreshMsg>,
}

// Keep the request generation alive across standalone/product transitions.
// The authored context is optional; replacing it cannot revive an old worker.
#[derive(Default)]
pub(super) struct ProjectEditor {
    context: Option<ProjectContext>,
    navigation: Option<ProjectNavigation>,
    net_policy_overrides: BTreeMap<NetId, NetSecurityPolicy>,
    cache: ProjectStatusCache,
    snapshot: Option<ProgrammingSnapshot>,
    status: Option<StartupStatusUi>,
    generation: u64,
}

impl ProjectEditor {
    pub(super) fn persist_key_input(&mut self, target: EditableKey, input: &str) -> Result<(), String> {
        use zweidraehte_project::{KeyOrigin, parse_fdsk};

        self.invalidate();
        let context = self.context().ok_or_else(|| "no project context".to_string())?;
        let mut writer =
            ProjectStore::open(&context.path).and_then(ProjectStore::into_writer).map_err(|error| error.to_string())?;
        let expected = context.original_source.as_deref().ok_or_else(|| "no saved project source".to_string())?;
        writer.check_authored(expected).map_err(|error| error.to_string())?;
        let authored = writer.authored().clone();
        let mut keys = writer.keys_mut().ok_or_else(|| "project keys are not initialized".to_string())?;
        match target {
            EditableKey::DeviceFdsk(device) => {
                let decoded = parse_fdsk(input).map_err(|error| error.to_string())?;
                let configured = authored.devices.get(&device).and_then(|device| device.serial);
                if let (Some(configured), Some(embedded)) = (configured, decoded.serial)
                    && configured != embedded
                {
                    return Err(format!(
                        "FDSK serial {} disagrees with project serial {}",
                        zweidraehte_project::format_serial(&embedded),
                        zweidraehte_project::format_serial(&configured)
                    ));
                }
                let origin = if decoded.serial.is_some() { KeyOrigin::DeviceLabel } else { KeyOrigin::Manual };
                keys.put_device_fdsk(device.as_str(), input, origin).map_err(|error| error.to_string())
            }
            EditableKey::DeviceToolKey(device) => {
                keys.put_device_tool_key(device.as_str(), input, KeyOrigin::Manual).map_err(|error| error.to_string())
            }
            EditableKey::GroupKey { net, epoch } => {
                keys.put_group_key(&net.0, epoch, input, KeyOrigin::Manual, true).map_err(|error| error.to_string())
            }
        }
    }

    pub(super) fn context(&self) -> Option<&ProjectContext> {
        self.context.as_ref()
    }
    pub(super) fn navigation(&self) -> Option<&ProjectNavigation> {
        self.navigation.as_ref()
    }
    pub(super) fn navigation_mut(&mut self) -> Option<&mut ProjectNavigation> {
        self.navigation.as_mut()
    }
    pub(super) fn snapshot(&self) -> Option<&ProgrammingSnapshot> {
        self.snapshot.as_ref()
    }
    pub(super) fn status(&self) -> Option<&StartupStatusUi> {
        self.status.as_ref()
    }
    pub(super) fn generation(&self) -> u64 {
        self.generation
    }

    pub(super) fn replace_context(&mut self, context: ProjectContext) {
        let changed = self.context.as_ref().is_none_or(|previous| previous.path != context.path);
        if changed {
            self.cache = ProjectStatusCache::default();
        }
        self.invalidate();
        self.navigation =
            context.authored.as_ref().map(|project| ProjectNavigation::from_project(project, context.device.clone()));
        self.context = Some(context);
        self.net_policy_overrides.clear();
    }

    pub(super) fn set_language(&mut self, language: Option<&str>) -> Result<(), String> {
        if let Some(context) = &mut self.context
            && let Some(project) = &context.authored
        {
            let source = project.render_language_update(language).map_err(|e| e.to_string())?;
            context.authored = Some(project.reparse(source).map_err(|e| e.to_string())?);
            self.invalidate();
        }
        Ok(())
    }

    pub(super) fn cycle_net_security(&mut self, net: NetId, authored: NetSecurityPolicy) -> NetSecurityPolicy {
        let current = self.net_policy_overrides.get(&net).copied().unwrap_or(authored);
        let next = match current {
            NetSecurityPolicy::Plain => NetSecurityPolicy::Automatic,
            NetSecurityPolicy::Automatic => NetSecurityPolicy::Authentication,
            NetSecurityPolicy::Authentication => NetSecurityPolicy::AuthenticationConfidentiality,
            NetSecurityPolicy::AuthenticationConfidentiality => NetSecurityPolicy::Plain,
        };
        self.net_policy_overrides.insert(net, next);
        self.invalidate();
        next
    }

    pub(super) fn begin_status(
        &mut self,
        receiver: std::sync::mpsc::Receiver<crate::status::StatusRefreshMsg>,
        total: usize,
    ) -> u64 {
        self.invalidate();
        self.status = Some(StartupStatusUi {
            current: "Opening project status inputs".into(),
            completed: 0,
            total,
            spinner: 0,
            error: None,
            generation: self.generation(),
            receiver,
        });
        self.generation
    }

    pub(super) fn dismiss_status(&mut self) {
        if self.status.as_ref().is_some_and(|status| status.error.is_some()) {
            self.status = None;
        }
    }
    pub(super) fn refresh(&mut self, download: Option<&DownloadContext>) {
        self.invalidate();
        let Some(context) = self.context.as_ref() else { return };
        let Some(authored) = context.authored.clone() else { return };
        let Some(original) = context.original_source.clone() else { return };
        let total = authored.devices.values().filter(|device| device.active).count() + 1;
        let (tx, receiver) = std::sync::mpsc::channel();
        let mut job = crate::status::StatusRefreshJob {
            project_path: context.path.clone(),
            security: download.map(|context| context.security.clone()),
            master_data: download.and_then(|context| context.master_data.clone()),
            draft: (authored, original),
            generation: self.generation,
            cache: self.cache.clone(),
        };
        job.generation = self.begin_status(receiver, total);
        crate::status::spawn(job, tx);
    }

    pub(super) fn invalidate(&mut self) {
        self.snapshot = None;
        self.generation = self.generation.wrapping_add(1);
        self.status = None;
    }

    pub(super) fn stage(&mut self, product: &ProductView) -> Result<ProjectContext, String> {
        let mut context = self.context.clone().ok_or_else(|| "no project context is configured".to_string())?;
        let Some(project) = &context.authored else {
            return Ok(context);
        };
        let draft = self.draft(product)?;
        let source = project.render_device_update(&draft).map_err(|error| error.to_string())?;
        let authored = project.reparse(source).map_err(|error| error.to_string())?;
        self.navigation = Some(ProjectNavigation::from_project(&authored, context.device.clone()));
        context.authored = Some(authored);
        self.net_policy_overrides.clear();
        self.context = Some(context.clone());
        self.invalidate();
        Ok(context)
    }

    pub(super) fn rename_net_label(&mut self, net: &NetId, name: &str) -> Result<(), String> {
        let context = self.context.as_mut().ok_or_else(|| "no project context is configured".to_string())?;
        let project =
            context.authored.as_ref().ok_or_else(|| "save the product draft before renaming nets".to_string())?;
        let source = project.render_net_name_update(net, name).map_err(|error| error.to_string())?;
        let authored = project.reparse(source).map_err(|error| error.to_string())?;
        context.authored = Some(authored);
        self.navigation =
            context.authored.as_ref().map(|project| ProjectNavigation::from_project(project, context.device.clone()));
        if let Some(navigation) = &mut self.navigation {
            navigation.select(&ProjectNavigationTarget::Net(net.clone()));
        }
        self.invalidate();
        Ok(())
    }

    /// The operation has already saved these exact device updates under its
    /// writer lock. Merge them into both editor bases without overwriting drafts
    /// or writing the file again using whichever device is currently selected.
    pub(super) fn apply_persisted_serial_updates(
        &mut self,
        updates: &BTreeMap<ProjectDeviceId, Option<[u8; 6]>>,
    ) -> Result<(), String> {
        if updates.is_empty() {
            return Ok(());
        }
        let mut context = self.context.clone().ok_or_else(|| "no project context is configured".to_string())?;
        let mut authored = context.authored.clone().ok_or_else(|| "no authored project is open".to_string())?;
        let mut original = authored
            .reparse(context.original_source.clone().ok_or_else(|| "no original project source".to_string())?)
            .map_err(|error| error.to_string())?;
        for (id, serial) in updates {
            let source = authored.render_device_serial_update(id, *serial).map_err(|error| error.to_string())?;
            authored = authored.reparse(source).map_err(|error| error.to_string())?;
            let source = original.render_device_serial_update(id, *serial).map_err(|error| error.to_string())?;
            original = original.reparse(source).map_err(|error| error.to_string())?;
        }
        let selected = self.navigation.as_ref().and_then(|navigation| navigation.selected_target().cloned());
        let mut navigation = ProjectNavigation::from_project(&authored, context.device.clone());
        if let Some(selected) = selected {
            navigation.select(&selected);
        }
        self.navigation = Some(navigation);
        context.original_source = Some(original.source().to_owned());
        context.authored = Some(authored);
        self.context = Some(context);
        self.invalidate();
        Ok(())
    }

    pub(super) fn draft(&self, product: &ProductView) -> Result<zweidraehte_project::ProjectDeviceDraft, String> {
        use zweidraehte_project::{
            DraftNet, MembershipRole, NetId, NetSecurityPolicy, ObjectMembership, ParamValue as ProjectValue,
            ParameterAssignment, ProjectObjectConfiguration, SourceSpan,
        };
        let context = self.context.as_ref().ok_or_else(|| "no project context is configured".to_string())?;
        let zero = SourceSpan { start: 0, end: 0 };
        let project = context
            .authored
            .as_ref()
            .ok_or_else(|| "standalone product files are editor-only; no project device can be rendered".to_string())?;
        let existing = project
            .devices
            .get(&context.device)
            .ok_or_else(|| format!("project has no device `{}`", context.device))?;
        let mut nets = BTreeMap::new();
        let mut address_to_id = BTreeMap::new();
        if let Some(project) = &context.authored {
            for net in project.nets.values() {
                address_to_id.insert(net.address, net.id.clone());
                nets.insert(net.id.clone(), DraftNet {
                    id: net.id.clone(),
                    address: net.address,
                    dpt: net.dpt.clone(),
                    security: net.security,
                });
            }
        }
        for (net, policy) in &self.net_policy_overrides {
            if let Some(draft) = nets.get_mut(net) {
                draft.security = *policy;
            }
        }
        // Draft semantics must not depend on whether the communication-object
        // tab has rendered since the last parameter edit.
        let rows: BTreeMap<_, _> = effective_com_objects(&product.device, &ProductConfiguration::default())
            .into_iter()
            .map(|object| (object.number, object))
            .collect();
        let mut objects = BTreeMap::new();
        for (number, bindings) in product.device.all_bindings() {
            let mut memberships = Vec::new();
            for binding in bindings {
                let address = binding.group_address;
                let id = address_to_id.get(&address).cloned().unwrap_or_else(|| {
                    NetId(format!("ga_{}_{}_{}", address.main_group(), address.middle_group(), address.sub_group8()))
                });
                address_to_id.insert(address, id.clone());
                nets.entry(id.clone()).or_insert_with(|| DraftNet {
                    id: id.clone(),
                    address,
                    dpt: rows.get(&number).map_or_else(
                        || "1.001".into(),
                        |object| project_dpt(object.datapoint_type.as_deref().unwrap_or_default(), &object.object_size),
                    ),
                    security: NetSecurityPolicy::Automatic,
                });
                memberships.push(ObjectMembership {
                    net: id,
                    role: if binding.is_sending { MembershipRole::Primary } else { MembershipRole::Additional },
                    span: zero,
                });
            }
            objects.insert(number, ProjectObjectConfiguration {
                com_object: number,
                memberships,
                flags: product.object_flag_overrides.get(&number).copied().unwrap_or_default(),
                span: zero,
            });
        }
        // Preserve flag-only objects even when they currently have no links.
        for (&number, &flags) in &product.object_flag_overrides {
            objects.entry(number).or_insert(ProjectObjectConfiguration {
                com_object: number,
                memberships: Vec::new(),
                flags,
                span: zero,
            });
        }
        let parameters = configuration_from_device(&product.device)
            .parameters
            .into_iter()
            .map(|parameter| -> Result<ParameterAssignment, String> {
                let value = match parameter.value {
                    ParameterValue::Integer(value) => ProjectValue::Integer(value),
                    ParameterValue::Float(value) => ProjectValue::Float(value),
                    ParameterValue::Text(value) => ProjectValue::Text(value),
                    ParameterValue::Bytes(_) => {
                        return Err("raw-byte parameters cannot be stored in project.knx".into());
                    }
                };
                Ok(ParameterAssignment { id: parameter.id, value, span: zero })
            })
            .collect::<Result<Vec<_>, String>>()?;
        Ok(zweidraehte_project::ProjectDeviceDraft {
            id: context.device.clone(),
            active: existing.active,
            product: existing.product.clone(),
            address: existing.address,
            medium: existing.medium,
            domain: {
                context
                    .authored
                    .as_ref()
                    .and_then(|project| project.line_topology(existing.area, existing.line))
                    .and_then(|line| line.domain)
            },
            ip_line: {
                context
                    .authored
                    .as_ref()
                    .and_then(|project| project.line_topology(existing.area, existing.line))
                    .and_then(|line| line.ip)
            },
            rf_mode: existing.rf_mode,
            ip: existing.ip.clone(),
            routing: existing.routing,
            serial: existing.serial,
            max_apdu: existing.max_apdu,
            data_secure: product.data_secure,
            parameters,
            objects,
            nets,
        })
    }

    pub(super) fn save(
        &mut self,
        product: &ProductView,
        security: Option<&zweidraehte_client::cli::SecurityArgs>,
    ) -> Result<(), String> {
        let context = self.context.clone().ok_or_else(|| "no project context is configured".to_string())?;
        let project = context.authored.as_ref().ok_or_else(|| {
            "standalone product files are editor-only; import the .knxprod into a project and add its CatalogItem"
                .to_string()
        })?;
        let draft = self.draft(product)?;
        let source = project.render_device_update(&draft).map_err(|error| error.to_string())?;
        let checked = project.reparse(source.clone()).map_err(|error| error.to_string())?;
        checked.validate_download().map_err(|error| {
            error.diagnostics().iter().map(|diagnostic| diagnostic.message.as_str()).collect::<Vec<_>>().join("; ")
        })?;

        let keyring = if let Some(security) = security {
            security.load_keyring().map_err(|error| error.to_string())?
        } else {
            None
        };
        let imported_group_addresses = keyring
            .as_ref()
            .map_or_else(BTreeSet::new, |keyring| keyring.group_keys().map(|(address, _)| address).collect());
        let required_group_keys = group_keys_to_materialize(&checked, &imported_group_addresses);

        // Keep exclusion across credentials and source. Check the editor's
        // saved base before initializing or generating any keys.
        let mut writer =
            ProjectStore::open(&context.path).and_then(ProjectStore::into_writer).map_err(|error| error.to_string())?;
        let expected = context.original_source.as_deref().ok_or_else(|| "no saved project source".to_string())?;
        writer.check_authored(expected).map_err(|error| error.to_string())?;
        if writer.keys().is_none() && writer.state().is_none() {
            writer.initialize().map_err(|error| error.to_string())?;
        }
        writer
            .update_authored_with_keys(expected, source.clone(), |keys| {
                keys.materialize_group_keys(required_group_keys)
            })
            .map_err(|error| error.to_string())?;
        let store = writer.into_store();
        let authored = store.authored().clone();
        let refreshed = ProjectContext {
            path: context.path,
            device: context.device,
            authored: Some(authored),
            original_source: Some(source),
        };
        self.navigation = refreshed
            .authored
            .as_ref()
            .map(|project| ProjectNavigation::from_project(project, refreshed.device.clone()));
        self.context = Some(refreshed);
        self.invalidate();
        Ok(())
    }

    pub(super) fn poll_status(&mut self) -> (bool, Option<String>) {
        let mut completion = None;
        let mut disconnected = false;
        let mut changed = false;
        {
            let Some(status) = &mut self.status else { return (false, None) };
            if status.generation != self.generation {
                self.status = None;
                return (true, None);
            }
            if status.error.is_some() {
                return (false, None);
            }
            status.spinner = status.spinner.wrapping_add(1);
            loop {
                match status.receiver.try_recv() {
                    Ok(crate::status::StatusRefreshMsg::Progress { generation, label, completed, total }) => {
                        if generation != self.generation {
                            continue;
                        }
                        status.current = label;
                        status.completed = completed;
                        status.total = total;
                        changed = true;
                    }
                    Ok(crate::status::StatusRefreshMsg::Done { generation, result }) => {
                        if generation != self.generation {
                            continue;
                        }
                        completion = Some(result);
                        changed = true;
                        break;
                    }
                    Err(std::sync::mpsc::TryRecvError::Empty) => break,
                    Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                        disconnected = true;
                        changed = true;
                        break;
                    }
                }
            }
        }

        if disconnected && completion.is_none() {
            if let Some(status) = &mut self.status {
                status.error = Some("programming-status worker stopped without returning a result".into());
            }
            return (true, None);
        }

        let completion = completion.map(|result| {
            result.and_then(|outcome| {
                outcome.snapshot.verify_current().map_err(|error| error.to_string())?;
                Ok(outcome)
            })
        });
        match completion {
            Some(Ok(outcome)) => {
                let count = outcome.snapshot.view().statuses.len();
                let pending = outcome.snapshot.view().requirements.len();
                self.cache = outcome.cache;
                self.snapshot = Some(outcome.snapshot);
                self.status = None;
                let message = if pending == 0 {
                    format!("Calculated programming status for {count} devices")
                } else {
                    format!("Calculated programming status for {count} devices; {pending} need target observations")
                };
                (true, Some(message))
            }
            Some(Err(error)) => {
                if let Some(status) = &mut self.status {
                    status.error = Some(error);
                }
                (true, None)
            }
            None => (changed, None),
        }
    }
}

pub(super) fn project_dpt(references: &str, size: &str) -> String {
    if let Some(references) = ProductDptReferences::parse(references) {
        let preferred = references.preferred();
        return format!("{}.{:03}", preferred.main, preferred.subtype.unwrap_or(1));
    }
    match size {
        "1 Bit" => "1.001",
        "2 Bit" => "2.001",
        "4 Bit" => "3.007",
        "1 Byte" => "5.001",
        "2 Bytes" => "7.001",
        "3 Bytes" => "10.001",
        "4 Bytes" => "12.001",
        "6 Bytes" => "234.001",
        "8 Bytes" => "29.001",
        "14 Bytes" => "16.001",
        _ => "1.001",
    }
    .to_string()
}

pub(super) fn group_keys_to_materialize(project: &AuthoredProject, imported_addresses: &BTreeSet<u16>) -> Vec<String> {
    project
        .nets
        .values()
        .filter(|net| {
            matches!(
                project.effective_net_security(&net.id),
                Some(NetSecurityPolicy::Authentication | NetSecurityPolicy::AuthenticationConfidentiality)
            )
        })
        .filter(|net| !imported_addresses.contains(&u16::from_be_bytes(net.address.0)))
        .map(|net| net.id.0.clone())
        .collect()
}
