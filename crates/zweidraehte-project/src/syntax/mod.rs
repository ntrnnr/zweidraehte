//! Lossless authored documents, their syntax and topology validation.

mod parser;
mod render;
mod validate;

pub use parser::ParseError;
pub use render::{DraftNet, ProjectDeviceDraft, RenderError, render_single_device_project};
pub use validate::{Download, ValidatedProject, ValidationError};

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;

use zweidraehte_proto::address::{GroupAddress, IndividualAddress};

use crate::model::{
    CouplerRole, CouplerRoutingPolicy, DomainAddress, ExternalSender, IpLineConfiguration, LineTopology, Medium, Net,
    NetId, NetSecurityPolicy, ProjectDevice, ProjectDeviceId, SourceSpan, TopologyError,
};
use parser::parse_project;

/// Parsed desired state plus its unchanged source text.
///
/// Keeping the source is intentional: parsing and checking a project is
/// byte-for-byte lossless. Focused editor commands can later replace the
/// recorded spans without normalising unrelated comments or whitespace.
#[derive(Debug, Clone)]
pub struct AuthoredProject {
    pub(crate) source: String,
    pub(crate) project_path: Option<PathBuf>,
    /// Preferred product-editor translation for the whole project.
    /// Products which do not provide it retain their own default language.
    pub language: Option<String>,
    pub(crate) language_decl_span: Option<SourceSpan>,
    pub(crate) language_value_span: Option<SourceSpan>,
    pub nets: BTreeMap<NetId, Net>,
    pub devices: BTreeMap<ProjectDeviceId, ProjectDevice>,
    pub external_senders: BTreeMap<String, ExternalSender>,
    pub(crate) areas: Vec<AuthoredArea>,
}

#[derive(Debug, Clone)]
pub(crate) struct AuthoredArea {
    pub number: u8,
    pub span: SourceSpan,
    pub lines: Vec<AuthoredLine>,
}

#[derive(Debug, Clone)]
pub(crate) struct AuthoredLine {
    pub number: u8,
    pub medium: Medium,
    pub domain: Option<DomainAddress>,
    pub domain_span: Option<SourceSpan>,
    pub ip: Option<IpLineConfiguration>,
    pub span: SourceSpan,
}

impl AuthoredProject {
    pub fn parse(source: impl Into<String>) -> Result<Self, ParseError> {
        Self::parse_at(source.into(), None)
    }

    /// Parse staged source while retaining this project's filesystem identity.
    ///
    /// Editors use this after a pure rendering operation so subsequent package
    /// resolution still points at the same project-local store. No file is
    /// read or written here.
    pub fn reparse(&self, source: impl Into<String>) -> Result<Self, ParseError> {
        Self::parse_at(source.into(), self.project_path.clone())
    }

    pub(crate) fn parse_at(source: String, path: Option<PathBuf>) -> Result<Self, ParseError> {
        parse_project(source, path)
    }

    pub fn source(&self) -> &str {
        &self.source
    }

    pub fn project_path(&self) -> Option<&std::path::Path> {
        self.project_path.as_deref()
    }

    pub fn project_directory(&self) -> Option<&std::path::Path> {
        self.project_path.as_deref().and_then(std::path::Path::parent)
    }

    /// Project-local immutable package store.
    ///
    /// Source-only parses have no filesystem authority, so this deliberately
    /// returns `None` instead of guessing the process working directory.
    pub fn package_store_directory(&self) -> Option<PathBuf> {
        Some(self.project_directory()?.join(".zweidraehte").join("packages"))
    }

    /// Return the unique authored line at an individual-address prefix.
    ///
    /// Download validation rejects duplicate area/line declarations. Before
    /// validation an ambiguous lookup deliberately returns `None` rather than
    /// selecting the first declaration and hiding a malformed topology.
    pub fn line_topology(&self, area: u8, line: u8) -> Option<LineTopology> {
        let mut areas = self.areas.iter().filter(move |candidate| candidate.number == area);
        let area = areas.next()?;
        if areas.next().is_some() {
            return None;
        }

        let mut lines = area.lines.iter().filter(move |candidate| candidate.number == line);
        let matched = lines.next()?;
        if lines.next().is_some() {
            return None;
        }

        Some(LineTopology { area: area.number, line, medium: matched.medium, domain: matched.domain, ip: matched.ip })
    }

    pub fn topology_lines(&self) -> impl Iterator<Item = LineTopology> + '_ {
        self.areas.iter().flat_map(|area| {
            area.lines.iter().map(|line| LineTopology {
                area: area.number,
                line: line.number,
                medium: line.medium,
                domain: line.domain,
                ip: line.ip,
            })
        })
    }

    /// Resolve one net's authored security policy against the complete active
    /// topology.
    ///
    /// `Automatic` protects the net only when it has at least one participant
    /// and every active managed or declared external participant uses Data
    /// Secure. The result is therefore always an executable policy and never
    /// depends on whether an old group key happens to exist in the key store.
    pub fn effective_net_security(&self, net_id: &NetId) -> Option<NetSecurityPolicy> {
        let net = self.nets.get(net_id)?;
        if net.security != NetSecurityPolicy::Automatic {
            return Some(net.security);
        }

        let mut has_participant = false;
        for device in self.devices.values().filter(|device| device.active) {
            let participates = device
                .objects
                .values()
                .any(|object| object.memberships.iter().any(|membership| &membership.net == net_id));
            if !participates {
                continue;
            }

            has_participant = true;
            if !device.data_secure.is_enabled() {
                return Some(NetSecurityPolicy::Plain);
            }
        }

        for sender in self.external_senders.values() {
            if !sender.nets.contains(net_id) {
                continue;
            }

            has_participant = true;
            if !sender.data_secure.is_enabled() {
                return Some(NetSecurityPolicy::Plain);
            }
        }

        Some(if has_participant { NetSecurityPolicy::AuthenticationConfidentiality } else { NetSecurityPolicy::Plain })
    }

    /// Group addresses which need to cross a filtering coupler's boundary.
    ///
    /// A net crosses when at least one active member is on each side. This
    /// common derivation feeds both deployment fingerprints and filter-table
    /// compilation, preventing those two views of topology from drifting.
    pub fn coupler_filter_addresses(
        &self,
        device_id: &ProjectDeviceId,
    ) -> Result<Option<BTreeSet<GroupAddress>>, TopologyError> {
        let coupler = self.devices.get(device_id).ok_or_else(|| TopologyError::UnknownDevice(device_id.clone()))?;
        let Some(role) = coupler.coupler_role() else {
            return Ok(None);
        };
        if coupler.routing != Some(CouplerRoutingPolicy::Filter) {
            return Ok(None);
        }

        let area_count = self.areas.iter().filter(|area| area.number == coupler.area).count();
        match area_count {
            0 => return Err(TopologyError::MissingArea { area: coupler.area }),
            1 => {}
            _ => return Err(TopologyError::AmbiguousArea { area: coupler.area }),
        }

        let line_count = self
            .areas
            .iter()
            .find(|area| area.number == coupler.area)
            .expect("the unique area exists")
            .lines
            .iter()
            .filter(|line| line.number == coupler.line)
            .count();
        match line_count {
            0 => return Err(TopologyError::MissingLine { area: coupler.area, line: coupler.line }),
            1 => {}
            _ => return Err(TopologyError::AmbiguousLine { area: coupler.area, line: coupler.line }),
        }

        let on_secondary_side = |address: IndividualAddress| match role {
            CouplerRole::Line => address.area() == coupler.area && address.line() == coupler.line,
            CouplerRole::Backbone => address.area() == coupler.area,
        };
        let mut filtered = BTreeSet::new();

        for net in self.nets.values() {
            let mut secondary_member = false;
            let mut primary_member = false;

            for device in self.devices.values().filter(|device| device.active && device.id != coupler.id) {
                let is_member = device
                    .objects
                    .values()
                    .any(|object| object.memberships.iter().any(|membership| membership.net == net.id));
                if !is_member {
                    continue;
                }

                if on_secondary_side(device.address) {
                    secondary_member = true;
                } else {
                    primary_member = true;
                }
            }

            for sender in self.external_senders.values().filter(|sender| sender.nets.contains(&net.id)) {
                if on_secondary_side(sender.address) {
                    secondary_member = true;
                } else {
                    primary_member = true;
                }
            }

            if secondary_member && primary_member {
                filtered.insert(net.address);
            }
        }

        Ok(Some(filtered))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn package_store_directory_requires_an_authored_project_path() {
        let source = concat!(
            "area 1 a { line 1 l { medium tp1 device d { ",
            "product package:\"sha256:0000000000000000000000000000000000000000000000000000000000000000\" ",
            "catalog_item \"M-00FA_H-1_P-1_CI-1\" address 1.1.1 } } }",
        );
        let source_only = AuthoredProject::parse(source).expect("source parses");
        assert_eq!(source_only.package_store_directory(), None);

        let authored = AuthoredProject::parse_at(source.to_owned(), Some(PathBuf::from("bench/project.knx")))
            .expect("path-backed source parses");
        assert_eq!(authored.package_store_directory(), Some(PathBuf::from("bench/.zweidraehte/packages")));
    }

    #[test]
    fn reparsing_staged_source_preserves_the_project_path_without_writing() {
        let source = concat!(
            "area 1 a { line 1 l { medium tp1 device d { ",
            "product package:\"sha256:0000000000000000000000000000000000000000000000000000000000000000\" ",
            "catalog_item \"M-00FA_H-1_P-1_CI-1\" address 1.1.1 } } }",
        );
        let authored = AuthoredProject::parse_at(source.to_owned(), Some(PathBuf::from("bench/project.knx")))
            .expect("path-backed source parses");
        let staged_source = source.replace("address 1.1.1", "address 1.1.2");

        let staged = authored.reparse(staged_source.clone()).expect("staged source reparses");

        assert_eq!(staged.source(), staged_source);
        assert_eq!(staged.project_path(), Some(std::path::Path::new("bench/project.knx")));
        assert_eq!(staged.package_store_directory(), authored.package_store_directory());

        let source_only = AuthoredProject::parse(source).expect("source-only project parses");
        assert_eq!(source_only.reparse(staged_source).expect("source reparses").project_path(), None);
    }
}
