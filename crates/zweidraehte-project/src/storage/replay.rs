//! Journal validation and replay belong to the writer. Shared snapshots and
//! evidence retain their serialization without exposing mutation operations.

use crate::keys::KeyKind;
use crate::state::{
    CommissioningOutcome, CredentialCommitment, DeviceDeploymentEvidence, MutableProjectState, ProgrammingManifest,
    ProgrammingSection, ProjectEvent, SenderIdentity,
};

impl MutableProjectState {
    pub(super) fn validate_event(&self, event: &ProjectEvent) -> Result<(), String> {
        let proofs = match event {
            ProjectEvent::RecordCommissioningOutcome {
                outcome: CommissioningOutcome::Programmed { established, .. },
                ..
            } => &established.credentials,
            ProjectEvent::RecordCommissioningOutcome {
                outcome: CommissioningOutcome::Indeterminate { exposed_group_keys, .. },
                ..
            } => {
                if exposed_group_keys.iter().any(|proof| proof.id.kind != KeyKind::GroupKey) {
                    return Err("uncertain credential evidence must contain only group keys".into());
                }
                exposed_group_keys
            }
            _ => return Ok(()),
        };
        CredentialCommitment::validate_set(proofs)?;
        for proof in proofs.iter().filter(|proof| proof.id.kind == KeyKind::GroupKey) {
            if self
                .deployments
                .values()
                .flat_map(|device| &device.manifest.credentials)
                .any(|old| old.id == proof.id && old != proof)
            {
                return Err("conflicting deployed group-key commitments; key rotation is unsupported".into());
            }
        }
        Ok(())
    }

    pub(super) fn apply(&mut self, event: &ProjectEvent) {
        match event {
            ProjectEvent::AdvanceClient { next } => self.client_next = self.client_next.max(*next),
            ProjectEvent::ObserveSender { sender, last_valid } => {
                self.sender_floors
                    .entry(sender.clone())
                    .and_modify(|old| *old = (*old).max(*last_valid))
                    .or_insert(*last_valid);
            }
            ProjectEvent::ObserveDeviceOutgoing { serial, next } => {
                self.devices.entry(serial.clone()).or_default().outgoing_next =
                    self.devices.get(serial).map_or(*next, |old| old.outgoing_next.max(*next));
            }
            ProjectEvent::ObserveDeviceSiat { serial, sender, last_valid } => {
                let table = &mut self.devices.entry(serial.clone()).or_default().siat_last_valid;
                table.entry(sender.clone()).and_modify(|old| *old = (*old).max(*last_valid)).or_insert(*last_valid);
            }
            ProjectEvent::RecordCommissioningOutcome { device, outcome } => match outcome {
                CommissioningOutcome::Programmed { established, commissioning, fully_verified } => {
                    let deployment = self.deployments.entry(device.clone()).or_default();
                    deployment.manifest.sections.extend(&established.sections);
                    // Legacy Programmed journal entries lose their old image
                    // hashes during decoding. They can follow an unload, so
                    // their unknown image must also retire that unload fact.
                    if established.sections.is_empty()
                        || established.sections.keys().any(|section| {
                            matches!(
                                section,
                                ProgrammingSection::ApplicationProgram1
                                    | ProgrammingSection::ApplicationProgram2
                                    | ProgrammingSection::GroupCommunication
                            )
                        })
                    {
                        deployment.application_unloaded = false;
                    }
                    // A current image does not prove old group keys were erased:
                    // Preserve can skip the GKT, and removed nets may remain on
                    // the device. Keep those guards until a confirmed reset.
                    deployment.manifest.credentials.retain(|proof| {
                        proof.id.kind == KeyKind::GroupKey || !established.sections.contains_key(&proof.section())
                    });
                    deployment.manifest.record_credentials(&established.credentials);
                    if commissioning.is_some()
                        || established.sections.keys().any(|section| *section != ProgrammingSection::Address)
                    {
                        deployment.commissioning = commissioning.as_deref().cloned();
                    }
                    if *fully_verified && !established.sections.is_empty() {
                        self.inconsistent_devices.retain(|candidate| candidate != device);
                    }
                }
                CommissioningOutcome::Unloaded { preserve_network_configuration, serial } => {
                    if *preserve_network_configuration {
                        let deployment = self.deployments.entry(device.clone()).or_default();
                        for section in [
                            ProgrammingSection::ApplicationProgram1,
                            ProgrammingSection::ApplicationProgram2,
                            ProgrammingSection::Parameters,
                            ProgrammingSection::GroupCommunication,
                        ] {
                            deployment.manifest.sections.remove(&section);
                        }
                        deployment.application_unloaded = true;
                        deployment.commissioning = None;
                    } else {
                        // Retain an empty factual tombstone. It carries no
                        // established artifacts or differential image, but it
                        // distinguishes a completed factory unload from a
                        // never-commissioned device when regenerating peer
                        // SIAT manifests.
                        self.deployments.insert(device.clone(), DeviceDeploymentEvidence {
                            application_unloaded: true,
                            ..Default::default()
                        });
                        self.inconsistent_devices.retain(|candidate| candidate != device);
                        if let Some(serial) = serial {
                            self.clear_sender_observation(serial);
                        }
                    }
                }
                CommissioningOutcome::Indeterminate { sections, exposed_group_keys } => {
                    let deployment = self.deployments.entry(device.clone()).or_default();
                    for section in sections {
                        deployment.manifest.sections.remove(section);
                    }
                    deployment.manifest.record_credentials(exposed_group_keys);
                    if !exposed_group_keys.is_empty()
                        || sections.iter().any(|section| {
                            matches!(
                                section,
                                ProgrammingSection::ApplicationProgram1
                                    | ProgrammingSection::ApplicationProgram2
                                    | ProgrammingSection::GroupCommunication
                            )
                        })
                    {
                        deployment.application_unloaded = false;
                    }

                    // Any confirmed prefix of a failed procedure makes the
                    // exact complete image unusable as a differential base,
                    // even when only one manifest section was affected.
                    deployment.commissioning = None;
                }
            },
            ProjectEvent::MarkInconsistent { devices } => {
                for device in devices {
                    if !self.inconsistent_devices.contains(device) {
                        self.inconsistent_devices.push(device.clone());
                    }
                }
                self.inconsistent_devices.sort();
            }
            ProjectEvent::BeginRecovery => self.recovery_required = true,
            ProjectEvent::CompleteRecovery => self.recovery_required = false,
        }
    }

    fn clear_sender_observation(&mut self, serial: &str) {
        self.devices.remove(serial);

        let identity = SenderIdentity::ManagedSerial(serial.to_string());
        self.sender_floors.remove(&identity);
        for observation in self.devices.values_mut() {
            observation.siat_last_valid.remove(&identity);
        }
    }
}

impl ProgrammingManifest {
    fn record_credentials(&mut self, proofs: &[CredentialCommitment]) {
        for proof in proofs {
            if let Some(existing) = self.credentials.iter_mut().find(|old| old.id == proof.id) {
                *existing = proof.clone();
            } else {
                self.credentials.push(proof.clone());
            }
        }
        self.credentials.sort_by(|a, b| a.id.cmp(&b.id));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::{KeyId, KeyScope};
    use crate::state::{
        COMMISSIONING_DEPLOYMENT_RECORD_VERSION, CommissioningDeploymentRecord, CommissioningProfileVariant,
        DeviceSequenceObservation, MaskIdentity,
    };
    use std::collections::BTreeMap;

    fn group_key() -> CredentialCommitment {
        CredentialCommitment {
            id: KeyId { kind: KeyKind::GroupKey, scope: KeyScope::Group("floor:light".into()) },
            epoch: None,
            commitment: [7; 32],
        }
    }

    #[test]
    fn section_updates_preserve_previously_exposed_group_keys() {
        let mut state = MutableProjectState::new("state".into());
        let proof = group_key();
        state.deployments.insert("relay".into(), DeviceDeploymentEvidence {
            manifest: ProgrammingManifest { credentials: vec![proof.clone()], ..Default::default() },
            ..Default::default()
        });
        let event = ProjectEvent::RecordCommissioningOutcome {
            device: "relay".into(),
            outcome: CommissioningOutcome::Programmed {
                established: ProgrammingManifest {
                    sections: BTreeMap::from([(ProgrammingSection::GroupCommunication, [9; 32])]),
                    credentials: Vec::new(),
                },
                commissioning: None,
                fully_verified: true,
            },
        };
        state.validate_event(&event).expect("section can change without rotating keys");
        state.apply(&event);
        assert_eq!(state.deployments["relay"].manifest.credentials, vec![proof.clone()]);

        let mut changed = proof;
        changed.commitment = [8; 32];
        let conflicting = ProjectEvent::RecordCommissioningOutcome {
            device: "button".into(),
            outcome: CommissioningOutcome::Indeterminate {
                sections: vec![ProgrammingSection::GroupCommunication],
                exposed_group_keys: vec![changed],
            },
        };
        assert!(state.validate_event(&conflicting).expect_err("rotation remains blocked").contains("conflicting"));
    }

    #[test]
    fn uncertain_group_key_evidence_rejects_malformed_or_duplicate_proofs() {
        let proof = group_key();
        let mut wrong_kind = proof.clone();
        wrong_kind.id.kind = KeyKind::ToolKey;
        let mut wrong_scope = proof.clone();
        wrong_scope.id.scope = KeyScope::Device("relay".into());
        let mut empty_scope = proof.clone();
        empty_scope.id.scope = KeyScope::Group(String::new());
        let mut conflict = proof.clone();
        conflict.commitment = [8; 32];
        let state = MutableProjectState::new("state".into());
        for proofs in
            [vec![wrong_kind], vec![wrong_scope], vec![empty_scope], vec![proof.clone(), proof.clone()], vec![
                proof, conflict,
            ]]
        {
            let event = ProjectEvent::RecordCommissioningOutcome {
                device: "relay".into(),
                outcome: CommissioningOutcome::Indeterminate { sections: Vec::new(), exposed_group_keys: proofs },
            };
            assert!(state.validate_event(&event).is_err());
        }
    }

    fn artifact(value: u8) -> ProgrammingManifest {
        let mut manifest = ProgrammingManifest::default();
        manifest.insert(ProgrammingSection::Parameters, [value; 32]);
        manifest
    }

    #[test]
    fn programmed_sections_replace_complete_digests() {
        let mut state = MutableProjectState::new("test-state".into());
        for value in [1, 2] {
            state.apply(&ProjectEvent::RecordCommissioningOutcome {
                device: "relay".into(),
                outcome: CommissioningOutcome::Programmed {
                    established: artifact(value),
                    commissioning: None,
                    fully_verified: false,
                },
            });
        }

        assert_eq!(state.deployments["relay"].manifest, artifact(2));
    }

    #[test]
    fn application_unload_preserves_address_and_configuration_only() {
        let mut manifest = ProgrammingManifest::default();
        for section in [
            ProgrammingSection::Address,
            ProgrammingSection::ApplicationProgram1,
            ProgrammingSection::Parameters,
            ProgrammingSection::GroupCommunication,
            ProgrammingSection::Configuration,
        ] {
            manifest.insert(section, [1; 32]);
        }
        let mut state = MutableProjectState::new("test-state".into());
        state.apply(&ProjectEvent::RecordCommissioningOutcome {
            device: "relay".into(),
            outcome: CommissioningOutcome::Programmed {
                established: manifest,
                commissioning: None,
                fully_verified: true,
            },
        });

        state.apply(&ProjectEvent::RecordCommissioningOutcome {
            device: "relay".into(),
            outcome: CommissioningOutcome::Unloaded { preserve_network_configuration: true, serial: None },
        });

        let remaining = &state.deployments["relay"].manifest.sections;
        assert_eq!(remaining.len(), 2);
        assert!(remaining.contains_key(&ProgrammingSection::Address));
        assert!(remaining.contains_key(&ProgrammingSection::Configuration));
    }

    #[test]
    fn failed_partial_invalidates_only_its_programming_sections() {
        let mut manifest = ProgrammingManifest::default();
        for section in [
            ProgrammingSection::Address,
            ProgrammingSection::ApplicationProgram1,
            ProgrammingSection::Parameters,
            ProgrammingSection::GroupCommunication,
            ProgrammingSection::Configuration,
        ] {
            manifest.insert(section, [1; 32]);
        }
        let mut state = MutableProjectState::new("test-state".into());
        state.deployments.insert("button".into(), DeviceDeploymentEvidence {
            manifest,
            application_unloaded: false,
            commissioning: Some(CommissioningDeploymentRecord {
                version: COMMISSIONING_DEPLOYMENT_RECORD_VERSION,
                mask: MaskIdentity { full_id: "MV-0705".into(), dd0: 0x0705, management_descriptor_01: None },
                variant: CommissioningProfileVariant {
                    source_index: 0,
                    legacy_version: None,
                    ets3_system_plugin: None,
                },
                master_data_fingerprint: [1; 32],
                product_fingerprint: [2; 32],
                image_fingerprint: [3; 32],
                image_segments: Vec::new(),
                device_stamps: Vec::new(),
                association_table_entry_size: None,
                observed_property_types: Vec::new(),
                data_security_enabled: None,
            }),
        });

        state.apply(&ProjectEvent::RecordCommissioningOutcome {
            device: "button".into(),
            outcome: CommissioningOutcome::Indeterminate {
                sections: vec![ProgrammingSection::Parameters],
                exposed_group_keys: Vec::new(),
            },
        });

        let deployment = &state.deployments["button"];
        assert!(!deployment.manifest.sections.contains_key(&ProgrammingSection::Parameters));
        assert!(deployment.manifest.sections.contains_key(&ProgrammingSection::Address));
        assert!(deployment.manifest.sections.contains_key(&ProgrammingSection::Configuration));
        assert!(deployment.commissioning.is_none());
    }

    #[test]
    fn complete_unload_clears_evidence_and_sender_observations() {
        let serial = "00FA:00000001";
        let identity = SenderIdentity::ManagedSerial(serial.into());
        let mut state = MutableProjectState::new("test-state".into());
        state.deployments.insert("relay".into(), DeviceDeploymentEvidence::default());
        state.devices.insert(serial.into(), DeviceSequenceObservation { outgoing_next: 42, ..Default::default() });
        state.sender_floors.insert(identity.clone(), 41);

        state.apply(&ProjectEvent::RecordCommissioningOutcome {
            device: "relay".into(),
            outcome: CommissioningOutcome::Unloaded {
                preserve_network_configuration: false,
                serial: Some(serial.into()),
            },
        });

        assert_eq!(
            state.deployments.get("relay"),
            Some(&DeviceDeploymentEvidence { application_unloaded: true, ..Default::default() })
        );
        assert!(!state.devices.contains_key(serial));
        assert!(!state.sender_floors.contains_key(&identity));
    }
}
