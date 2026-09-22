//! Section comparison and deployed credentials have different lifetimes.
//! Invalidating image evidence must never forget which group key may be deployed.

use super::ProgrammingSection;
use crate::keys::{KeyEpoch, KeyId, KeyKind, KeyMetadata, KeyScope};
use serde::{Deserialize, Deserializer, Serialize, de};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CredentialCommitment {
    pub id: KeyId,
    pub epoch: Option<KeyEpoch>,
    pub commitment: [u8; 32],
}

impl CredentialCommitment {
    pub fn from_metadata(metadata: &KeyMetadata) -> Option<Self> {
        if metadata.id.kind == KeyKind::Fdsk {
            return None;
        }
        let mut proof = Self { id: metadata.id.clone(), epoch: metadata.epoch, commitment: [0; 32] };
        proof.commitment = semantic_fingerprint("credential", &proof.identity(), &metadata.fingerprint);
        Some(proof)
    }

    pub fn section(&self) -> ProgrammingSection {
        match self.id.kind {
            KeyKind::Fdsk | KeyKind::ToolKey | KeyKind::GroupKey => ProgrammingSection::GroupCommunication,
            _ => ProgrammingSection::Configuration,
        }
    }

    // This spelling is part of the old commitment domain. Keep it unchanged:
    // persisted commitments cannot be converted back into key fingerprints.
    pub fn identity(&self) -> String {
        let kind = match self.id.kind {
            KeyKind::Fdsk => "fdsk",
            KeyKind::ToolKey => "tool-key",
            KeyKind::GroupKey => "group-key",
            KeyKind::DeviceAuthenticationCode => "device-authentication-code",
            KeyKind::BackboneKey => "backbone-key",
            KeyKind::IpPasswordHash => "ip-password-hash",
            KeyKind::TunnellingKey => "tunnelling-key",
        };
        let scope = match &self.id.scope {
            KeyScope::Project => "project".into(),
            KeyScope::Device(id) => format!("device:{id}"),
            KeyScope::Group(id) => format!("group:{id}"),
            KeyScope::IpBackbone => "ip-backbone".into(),
            KeyScope::IpInterface(id) => format!("ip-interface:{id}"),
            KeyScope::IpUser { interface, user_id } => format!("ip-user:{interface}:{user_id}"),
        };
        let epoch = self.epoch.map_or_else(|| "active".into(), |epoch| epoch.0.to_string());
        format!("{kind}:{scope}:{epoch}")
    }

    fn legacy(encoded: &str, commitment: [u8; 32]) -> Result<Self, String> {
        let invalid = || format!("malformed deployed credential identity {encoded:?}");
        let (identity, epoch) = encoded.rsplit_once(':').ok_or_else(invalid)?;
        let epoch = match epoch {
            "active" => None,
            value => Some(KeyEpoch(value.parse().map_err(|_| invalid())?)),
        };
        let (kind, scope) = identity.split_once(':').ok_or_else(invalid)?;
        let kind = match kind {
            "tool-key" => KeyKind::ToolKey,
            "group-key" => KeyKind::GroupKey,
            "device-authentication-code" => KeyKind::DeviceAuthenticationCode,
            "backbone-key" => KeyKind::BackboneKey,
            "ip-password-hash" => KeyKind::IpPasswordHash,
            "tunnelling-key" => KeyKind::TunnellingKey,
            _ => return Err(invalid()),
        };
        let scope = if scope == "project" {
            KeyScope::Project
        } else if scope == "ip-backbone" {
            KeyScope::IpBackbone
        } else {
            let (scope, id) = scope.split_once(':').ok_or_else(invalid)?;
            if id.is_empty() {
                return Err(invalid());
            }
            match scope {
                "device" => KeyScope::Device(id.into()),
                "group" => KeyScope::Group(id.into()),
                "ip-interface" => KeyScope::IpInterface(id.into()),
                "ip-user" => {
                    let (interface, user_id) = id.rsplit_once(':').ok_or_else(invalid)?;
                    if interface.is_empty() {
                        return Err(invalid());
                    }
                    KeyScope::IpUser { interface: interface.into(), user_id: user_id.parse().map_err(|_| invalid())? }
                }
                _ => return Err(invalid()),
            }
        };
        let proof = Self { id: KeyId { kind, scope }, epoch, commitment };
        if proof.identity() != encoded {
            return Err(invalid());
        }
        Ok(proof)
    }
}

/// Canonical image digests and independent, non-secret deployed-key proofs.
/// Credentials are sorted by key identity, with exactly one version per key.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct ProgrammingManifest {
    pub sections: BTreeMap<ProgrammingSection, [u8; 32]>,
    pub credentials: Vec<CredentialCommitment>,
}

pub type DesiredProgrammingManifest = ProgrammingManifest;

impl ProgrammingManifest {
    pub fn section(&self, section: ProgrammingSection) -> Option<&[u8; 32]> {
        self.sections.get(&section)
    }

    pub fn insert(&mut self, section: ProgrammingSection, digest: [u8; 32]) {
        self.sections.insert(section, digest);
    }

    /// Add one semantic input in the compiler's fixed producer order.
    pub fn mix(&mut self, section: ProgrammingSection, namespace: &str, identity: &str, value: &[u8]) {
        let mut hash = Sha256::new();
        hash.update(b"zweidraehte-programming-section-v2\0");
        hash.update([u8::from(self.sections.contains_key(&section))]);
        if let Some(previous) = self.sections.get(&section) {
            hash.update(previous);
        }
        for bytes in [namespace.as_bytes(), identity.as_bytes(), value] {
            hash.update((bytes.len() as u64).to_be_bytes());
            hash.update(bytes);
        }
        self.sections.insert(section, hash.finalize().into());
    }

    pub fn retain_sections(&self, sections: impl IntoIterator<Item = ProgrammingSection>) -> Self {
        let selected: BTreeSet<_> = sections.into_iter().collect();
        Self {
            sections: self
                .sections
                .iter()
                .filter(|(section, _)| selected.contains(section))
                .map(|(&s, &d)| (s, d))
                .collect(),
            credentials: self.credentials.iter().filter(|proof| selected.contains(&proof.section())).cloned().collect(),
        }
    }

    pub fn validate(&self) -> Result<(), String> {
        CredentialCommitment::validate_set(&self.credentials)
    }
}

impl CredentialCommitment {
    pub(crate) fn validate_set(proofs: &[Self]) -> Result<(), String> {
        for proof in proofs {
            if proof.id.kind == KeyKind::Fdsk
                || matches!(&proof.id.scope, KeyScope::Device(id) | KeyScope::Group(id) | KeyScope::IpInterface(id) if id.is_empty())
                || matches!(&proof.id.scope, KeyScope::IpUser { interface, .. } if interface.is_empty())
                || proof.id.kind == KeyKind::GroupKey && !matches!(proof.id.scope, KeyScope::Group(_))
            {
                return Err("malformed deployed credential proof".into());
            }
        }
        if proofs.windows(2).any(|pair| pair[0].id >= pair[1].id) {
            return Err("deployed credential proofs must be sorted and unique".into());
        }
        Ok(())
    }
}

// Decode legacy snapshots and journal outcomes at their shared boundary. Old
// image artifacts become unknown; credential commitments survive unchanged.
impl<'de> Deserialize<'de> for ProgrammingManifest {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum Section {
            Digest([u8; 32]),
            Legacy(#[serde(deserialize_with = "unique_map")] BTreeMap<String, [u8; 32]>),
        }
        #[derive(Deserialize)]
        struct Stored {
            #[serde(default, deserialize_with = "unique_map")]
            sections: BTreeMap<ProgrammingSection, Section>,
            #[serde(default)]
            credentials: Vec<CredentialCommitment>,
        }
        let stored = Stored::deserialize(deserializer)?;
        let mut modern = !stored.credentials.is_empty();
        let mut result = Self { sections: BTreeMap::new(), credentials: stored.credentials };
        let mut legacy = false;
        for (section, value) in stored.sections {
            match value {
                Section::Digest(digest) => {
                    modern = true;
                    result.sections.insert(section, digest);
                }
                Section::Legacy(artifacts) => {
                    legacy = true;
                    for (id, commitment) in artifacts {
                        if id == "semantic:credential" {
                            return Err(de::Error::custom("missing deployed credential identity"));
                        }
                        if let Some(identity) = id.strip_prefix("semantic:credential:") {
                            let proof =
                                CredentialCommitment::legacy(identity, commitment).map_err(de::Error::custom)?;
                            if proof.section() != section {
                                return Err(de::Error::custom("credential stored under wrong section"));
                            }
                            result.credentials.push(proof);
                        }
                    }
                }
            }
        }
        if legacy {
            if modern {
                return Err(de::Error::custom("mixed legacy and current programming evidence"));
            }
            result.sections.clear();
            result.credentials.sort_by(|a, b| a.id.cmp(&b.id));
        }
        result.validate().map_err(de::Error::custom)?;
        Ok(result)
    }
}

// Serde's ordinary map decoder keeps the last duplicate JSON key. That would
// let conflicting old credential records disappear before migration sees them.
fn unique_map<'de, D, K, V>(deserializer: D) -> Result<BTreeMap<K, V>, D::Error>
where
    D: Deserializer<'de>,
    K: Deserialize<'de> + Ord,
    V: Deserialize<'de>,
{
    struct Unique<K, V>(std::marker::PhantomData<(K, V)>);
    impl<'de, K: Deserialize<'de> + Ord, V: Deserialize<'de>> de::Visitor<'de> for Unique<K, V> {
        type Value = BTreeMap<K, V>;
        fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            formatter.write_str("a map with unique evidence identities")
        }
        fn visit_map<A: de::MapAccess<'de>>(self, mut entries: A) -> Result<Self::Value, A::Error> {
            let mut result = BTreeMap::new();
            while let Some((key, value)) = entries.next_entry()? {
                if result.insert(key, value).is_some() {
                    return Err(de::Error::custom("duplicate programming evidence identity"));
                }
            }
            Ok(result)
        }
    }
    deserializer.deserialize_map(Unique(std::marker::PhantomData))
}

/// The existing credential commitment domain is deliberately stable across
/// image-format migrations. This function never receives raw secret bytes.
pub fn semantic_fingerprint(namespace: &str, identity: &str, value: &[u8]) -> [u8; 32] {
    let id = format!("semantic:{namespace}:{identity}");
    let mut hash = Sha256::new();
    hash.update(b"zweidraehte-programming-manifest-v1\0");
    hash.update(id.as_bytes());
    hash.update([0]);
    hash.update((value.len() as u64).to_be_bytes());
    hash.update(value);
    hash.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn legacy(entries: &[(&str, [u8; 32])]) -> serde_json::Value {
        json!({"sections": {"group_communication": entries.iter()
            .map(|(id, digest)| (id.to_string(), *digest)).collect::<BTreeMap<_, _>>()}})
    }

    #[test]
    fn legacy_migration_keeps_colons_and_exact_commitment_bytes() {
        assert_eq!(semantic_fingerprint("credential", "group-key:group:floor:room:7", &[9; 32]), [
            153, 31, 11, 6, 121, 181, 30, 136, 75, 235, 214, 236, 8, 24, 3, 236, 234, 185, 77, 34, 22, 165, 136, 137,
            114, 14, 55, 187, 104, 28, 184, 70,
        ]);
        let value =
            legacy(&[("semantic:credential:group-key:group:floor:room:7", [13; 32]), ("image:memory", [42; 32])]);
        let migrated: ProgrammingManifest = serde_json::from_value(value).expect("legacy manifest migrates");
        assert!(migrated.sections.is_empty());
        assert_eq!(migrated.credentials, vec![CredentialCommitment {
            id: KeyId { kind: KeyKind::GroupKey, scope: KeyScope::Group("floor:room".into()) },
            epoch: Some(KeyEpoch(7)),
            commitment: [13; 32],
        }]);
        let encoded = serde_json::to_string(&migrated).expect("current manifest serializes");
        assert_eq!(serde_json::from_str::<ProgrammingManifest>(&encoded).expect("current manifest decodes"), migrated);

        let user = CredentialCommitment::legacy("tunnelling-key:ip-user:floor:router:3:active", [5; 32])
            .expect("interface identity retains colon");
        assert_eq!(user.identity(), "tunnelling-key:ip-user:floor:router:3:active");
    }

    #[test]
    fn malformed_and_conflicting_legacy_credentials_are_rejected() {
        let digest = serde_json::to_string(&[1; 32]).expect("digest serializes");
        let duplicate = format!(
            r#"{{"sections":{{"group_communication":{{"semantic:credential:group-key:group:light:1":{digest},"semantic:credential:group-key:group:light:1":{digest}}}}}}}"#
        );
        assert!(serde_json::from_str::<ProgrammingManifest>(&duplicate).is_err());
        for id in [
            "semantic:credential",
            "semantic:credential:unknown:group:light:active",
            "semantic:credential:group-key:group:light",
            "semantic:credential:group-key:group::active",
            "semantic:credential:group-key:group:light:01",
            "semantic:credential:group-key:device:button:1",
        ] {
            assert!(serde_json::from_value::<ProgrammingManifest>(legacy(&[(id, [1; 32])])).is_err(), "{id}");
        }
        assert!(
            serde_json::from_value::<ProgrammingManifest>(legacy(&[
                ("semantic:credential:group-key:group:light:1", [1; 32]),
                ("semantic:credential:group-key:group:light:2", [2; 32]),
            ]))
            .is_err()
        );
    }

    #[test]
    fn current_proofs_are_strictly_ordered_and_unique() {
        let proof = CredentialCommitment::legacy("group-key:group:light:1", [1; 32]).expect("proof parses");
        let manifest = ProgrammingManifest { credentials: vec![proof.clone(), proof], ..Default::default() };
        assert!(
            serde_json::from_value::<ProgrammingManifest>(serde_json::to_value(manifest).expect("serializes")).is_err()
        );
        let mixed = json!({"sections": {"parameters": vec![0; 32], "group_communication": {"old": vec![0; 32]}}});
        assert!(serde_json::from_value::<ProgrammingManifest>(mixed).is_err());
    }
}
