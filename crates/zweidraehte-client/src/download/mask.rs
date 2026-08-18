//! The mask layer: per-mask-version facts, read from the ETS master
//! data (`knx_master.xml`).
//!
//! This is the bottom of the three layers a download draws on (mask →
//! product → project), and it is *always* present, exactly as in ETS.
//! There is deliberately no built-in mask table: MV-07B0 alone carries
//! 145 load-control instructions across six procedure templates plus
//! 40 resources, and hand-transcribing that invites precisely the
//! drift the conformance transcriptions already suffered. The file is
//! the source of truth; we read it.
//!
//! Where it comes from, in the order [`MaskDb::resolve`] tries:
//!
//! 1. an explicit path or string ([`MaskDb::from_file`] /
//!    [`MaskDb::from_str`]), or a `.knxprod` that bundles one
//!    ([`MaskDb::from_knxprod`]),
//! 2. the `KNX_MASTER_DATA` environment variable,
//! 3. the on-disk cache, then a download from `update.knx.org`
//!    (feature `master-data-download` — what ETS does).

use std::collections::HashMap;
use std::path::Path;

use zweidraehte_knxprod::MasterData;
use zweidraehte_knxprod::runtime::KnxprodArchive;
use zweidraehte_knxprod::runtime::master_data::{MaskVersion as MasterMaskVersion, Procedure};
use zweidraehte_proto::device::MaskVersion;
use zweidraehte_proto::messages::apdu::load_control::LsmMachine;

use crate::error::{Error, Result};

/// Environment variable naming a `knx_master.xml` to use.
pub const MASTER_DATA_ENV: &str = "KNX_MASTER_DATA";

/// Every mask version the master data defines, queryable by the mask
/// version a device reports in its device descriptor.
pub struct MaskDb {
    master: MasterData,
}

impl MaskDb {
    /// Parse master data held in a string.
    pub fn from_str(xml: &str) -> Result<Self> {
        let master = xml.parse::<MasterData>().map_err(|e| Error::MasterData(e.to_string()))?;
        Ok(Self { master })
    }

    /// Parse a `knx_master.xml` from disk.
    pub fn from_file(path: impl AsRef<Path>) -> Result<Self> {
        let xml = std::fs::read_to_string(path)?;
        Self::from_str(&xml)
    }

    /// Take the master data a `.knxprod` archive bundles.
    ///
    /// A product package carries `knx_master.xml` alongside its
    /// application programs, so one file can supply both the mask and
    /// the product layer.
    pub fn from_knxprod(archive: &KnxprodArchive) -> Result<Self> {
        let xml = archive
            .master_data_xml()
            .ok_or(Error::MasterData("the .knxprod archive bundles no knx_master.xml".to_string()))?;
        Self::from_str(xml)
    }

    /// Resolve master data the way ETS does, trying in order: the
    /// `KNX_MASTER_DATA` environment variable, then (with feature
    /// `master-data-download`) the on-disk cache and a download from
    /// `update.knx.org`.
    pub fn resolve() -> Result<Self> {
        if let Ok(path) = std::env::var(MASTER_DATA_ENV) {
            return Self::from_file(&path);
        }

        #[cfg(feature = "master-data-download")]
        {
            use zweidraehte_knxprod::signing::{MasterDataSource, get_master_data};
            let xml = get_master_data(&MasterDataSource::Download).map_err(|e| Error::MasterData(e.to_string()))?;
            return Self::from_str(&xml);
        }

        #[cfg(not(feature = "master-data-download"))]
        Err(Error::MasterData(format!(
            "no master data: set {MASTER_DATA_ENV}, pass a file explicitly, or build with the \
             `master-data-download` feature to fetch it from update.knx.org"
        )))
    }

    /// The facts for one mask version, or `None` when the master data
    /// does not describe it.
    pub fn mask(&self, version: MaskVersion) -> Option<MaskData<'_>> {
        self.master.get_mask_version_by_code(version.as_u16()).map(|mv| MaskData { version, inner: mv })
    }

    /// How many mask versions the loaded data describes (34 in the
    /// current published file).
    pub fn len(&self) -> usize {
        self.master.mask_version_count()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// The mask a download must be compiled for — ETS's rule, watched in
/// a Hawk log (`VerifyCompatibleMaskVersionTask`): the **device's own
/// DD0** decides, and a product written for an older mask is accepted
/// when the device's mask lists it as downward compatible (a BCU2
/// runs BCU1 programs). The device is then programmed per *its own*
/// management model — there is no "compat mode" to switch, the log
/// shows ETS reading ManagementStyle (0115h) once and never writing
/// it — while the product supplies the content.
///
/// Callers read DD0 (`DeviceDescriptor_Read Type=0`) after
/// connecting and hand it in; a mismatched, incompatible device fails
/// here before anything is written to it.
pub fn select_download_mask(db: &MaskDb, product_mask: MaskVersion, device_mask: MaskVersion) -> Result<MaskData<'_>> {
    let device = db.mask(device_mask).ok_or_else(|| {
        Error::MasterData(format!("the master data does not describe the device's mask {device_mask:?}"))
    })?;

    if device_mask == product_mask || device.is_downward_compatible_with(product_mask) {
        return Ok(device);
    }
    Err(Error::MasterData(format!(
        "the device is {device_mask:?}, which does not run {product_mask:?} programs \
         (not listed in its DownwardCompatibleMasks)"
    )))
}

/// One mask version's download-relevant facts.
pub struct MaskData<'a> {
    version: MaskVersion,
    inner: &'a MasterMaskVersion,
}

impl<'a> MaskData<'a> {
    pub fn version(&self) -> MaskVersion {
        self.version
    }

    /// The mask's management model (`"BimM112"`, `"SystemB"`, …) as
    /// the master data spells it.
    pub fn management_model(&self) -> &str {
        &self.inner.management_model
    }

    /// Whether this mask runs programs written for `mask` — itself,
    /// or one of its `DownwardCompatibleMasks` (MV-0020 lists
    /// MV-0010/0011/0012: a BCU2 executes BCU1 applications).
    pub fn is_downward_compatible_with(&self, mask: MaskVersion) -> bool {
        self.inner.is_downward_compatible_with(mask.as_u16())
    }

    /// The address of a mask OS entry point, by the `_ME-…` id suffix
    /// a program's fixups reference — see
    /// [`MaskVersion::mask_entry_address`](zweidraehte_knxprod::runtime::master_data::MaskVersion::mask_entry_address).
    pub fn mask_entry_address(&self, me_suffix: &str) -> Option<u32> {
        self.inner.mask_entry_address(me_suffix)
    }

    /// The address of a named resource, when the mask locates it in
    /// plain device memory (`AddressSpace="StandardMemory"`) — e.g.
    /// `"RunError"` (010Dh on the BCU-era masks) or
    /// `"ProgrammingMode"`.
    ///
    /// Searched over the resource list rather than through
    /// `resource_map`: a mask may realize the same name in several
    /// address spaces (MV-0021 carries `GroupAssociationTablePtr` both
    /// as StandardMemory 0111h, `MgmtStyle="simple"`, and as a system
    /// property, `MgmtStyle="lsm"`), and the by-name map keeps only
    /// one of them.
    pub fn standard_memory_address(&self, name: &str) -> Option<u16> {
        let resources = &self.inner.hawk_config()?.resources.as_ref()?.resources;
        let resource = resources.iter().find(|r| r.name == name && r.is_standard_memory())?;
        u16::try_from(resource.start_address()?).ok()
    }

    /// A procedure template by type and subtype, e.g.
    /// `("Unload", "all")` or `("Load", "all")`. System 7 masks carry
    /// only `Unload`; their Load procedures are product-supplied.
    pub fn procedure(&self, procedure_type: &str, sub_type: &str) -> Option<&'a Procedure> {
        self.inner.find_procedure(procedure_type, sub_type)
    }

    /// Every procedure template the mask defines.
    pub fn procedures(&self) -> &'a [Procedure] {
        self.inner.procedures()
    }

    /// Resource locations for the memory-mapped download path.
    ///
    /// `None` for masks that do not expose these as fixed
    /// `StandardMemory` addresses — System B locates its tables
    /// through interface-object properties instead, and drives its
    /// load state machines through `PID_LOAD_STATE_CONTROL`.
    pub fn memory_resources(&self) -> Option<MemoryResources> {
        let addr = |name: &str| -> Option<u16> {
            let resources = self.inner.resource_map();
            let resource = resources.get(name).copied()?;
            if !resource.is_standard_memory() {
                return None;
            }
            u16::try_from(resource.start_address()?).ok()
        };

        Some(MemoryResources {
            programming_mode_addr: addr("ProgrammingMode")?,
            load_control_addr: addr("GroupAddressTableLoadControl")?,
            load_status_addr: addr("GroupAddressTableLoadStatus")?,
            address_table_addr: addr("GroupAddressTable")?,
        })
    }

    /// The mask's load-state-machine model, read from its resource
    /// declarations.
    ///
    /// This is the authoritative answer to "which machines does this
    /// mask have, and how are they driven" — the master data declares
    /// a `<Role>LoadControl` / `<Role>LoadStatus` resource pair per
    /// machine, and the pair's `AddressSpace` says whether the machine
    /// is memory-mapped or property-driven. Deriving it here instead
    /// of from the mask *family* matters because the family does not
    /// determine the realization: MV-2705 (System 7 RF) is
    /// `BimM112`-managed yet drives its machines through properties,
    /// and BCU2 masks do the same.
    pub fn lsm_model(&self) -> LsmModel {
        let resources = self.inner.resource_map();
        let mut machines = Vec::new();

        for (name, resource) in &resources {
            let Some(prefix) = name.strip_suffix("LoadControl") else { continue };
            let Some(role) = MachineRole::from_resource_prefix(prefix) else { continue };

            let access = if resource.is_standard_memory() {
                // The status byte lives in its own sibling resource;
                // a machine we could drive but never poll is useless,
                // so both must be present.
                let status = resources
                    .get(format!("{prefix}LoadStatus").as_str())
                    .filter(|r| r.is_standard_memory())
                    .and_then(|r| r.start_address());

                let control = resource.start_address();
                match (control, status) {
                    (Some(control), Some(status)) => match (u16::try_from(control), u16::try_from(status)) {
                        (Ok(control), Ok(status)) => LsmAccess::Memory { control, status },
                        _ => continue,
                    },
                    _ => continue,
                }
            } else if is_property_space(resource.address_space().unwrap_or_default()) {
                let Some(object) = resource.interface_object_ref() else { continue };
                // PID_LOAD_STATE_CONTROL is spec-fixed (03/05/01,
                // PID 5); the declaration carries it anyway.
                let pid = resource.property_id().unwrap_or(5);
                LsmAccess::Property { object, pid }
            } else {
                continue;
            };

            machines.push(LsmResource { role, access });
        }

        // The resource map iterates in hash order; sort by role so the
        // model reads in roster order and compares stably in tests.
        machines.sort_by_key(|m| m.role);
        LsmModel { machines }
    }

    /// A `HawkConfigurationData` feature value, e.g.
    /// `"AuthorizeLevels"` or `"FirstAppObjectIdx"`.
    pub fn feature(&self, name: &str) -> Option<&'a str> {
        self.inner.get_feature(name)
    }

    /// Interface-object index of the first application program object.
    pub fn first_app_object_idx(&self) -> u8 {
        self.inner.first_app_object_idx()
    }

    /// All resource locations by name, for callers that need one this
    /// type does not surface.
    pub fn resources(&self) -> HashMap<&'a str, &'a zweidraehte_knxprod::runtime::master_data::Resource> {
        self.inner.resource_map()
    }
}

/// The fixed memory addresses a memory-mapped download needs
/// (System 7 / BIM M112), read from the mask's resource list rather
/// than hardcoded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MemoryResources {
    /// Programming-mode byte (0705: 0060h).
    pub programming_mode_addr: u16,
    /// Memory-mapped load-control write window (0705: 0104h) —
    /// `DM_LoadStateMachineWrite_RCo_Mem` records go here.
    pub load_control_addr: u16,
    /// First load-state byte (0705: B6EAh); the four machines' states
    /// follow consecutively in [`LsmMachine`] order (ADT, AST, APP,
    /// PEI/APP2).
    pub load_status_addr: u16,
    /// Fixed location of the RT8 group address table (0705: 4000h).
    pub address_table_addr: u16,
}

impl MemoryResources {
    /// Where the given machine's load-state byte lives.
    pub fn load_status_of(&self, machine: LsmMachine) -> u16 {
        self.load_status_addr + (machine as u16 - 1)
    }
}

// ============================================================================
// The load-state-machine model
// ============================================================================

/// A load state machine's role, parsed from its resource-name prefix
/// (`GroupAddressTableLoadControl` → `GroupAddressTable`, …).
///
/// The spellings are the master data's, verbatim — in particular
/// `Application` (not `ApplicationProgram`) and `Peiprog`.
/// `GroupFilterTable` exists for model completeness (couplers declare
/// it); no content generation uses it yet.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum MachineRole {
    GroupAddressTable,
    GroupAssociationTable,
    GroupObjectTable,
    Application,
    PeiProgram,
    GroupFilterTable,
}

impl MachineRole {
    fn from_resource_prefix(prefix: &str) -> Option<Self> {
        Some(match prefix {
            "GroupAddressTable" => Self::GroupAddressTable,
            "GroupAssociationTable" => Self::GroupAssociationTable,
            "GroupObjectTable" => Self::GroupObjectTable,
            "Application" => Self::Application,
            "Peiprog" => Self::PeiProgram,
            "GroupFilterTable" => Self::GroupFilterTable,
            // Unknown roles are skipped, not errors: a future master
            // data may declare machines this version does not drive.
            _ => return None,
        })
    }
}

/// How the mask declares one machine to be driven.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LsmAccess {
    /// `AddressSpace="StandardMemory"`: records go to a control
    /// window, the state is read from a status byte.
    Memory { control: u16, status: u16 },
    /// `AddressSpace="SystemProperty"` — or plain `"Property"`, which
    /// the coupler masks use — the machine is the object's
    /// load-control property.
    Property { object: u8, pid: u8 },
}

/// Both property-flavored address spaces mean "(object, PID)"; knxprod's
/// `is_system_property()` matches only the first, so don't use it here.
fn is_property_space(space: &str) -> bool {
    space == "SystemProperty" || space == "Property"
}

/// One machine of a mask's [`LsmModel`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LsmResource {
    pub role: MachineRole,
    pub access: LsmAccess,
}

/// Which access realization a mask's machines share.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LsmRealization {
    /// `DM_LoadStateMachineWrite_RCo_Mem` — System 7 / BIM M112 TP.
    Memory,
    /// `DM_LoadStateMachineWrite_RCo_IO` — System B, BCU2, 2705.
    Property,
}

/// Everything a mask declares about its load state machines, in
/// roster order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LsmModel {
    pub machines: Vec<LsmResource>,
}

impl LsmModel {
    /// The realization all machines share — `None` when the mask
    /// declares no machines (BCU1: downloads are plain memory writes)
    /// or, theoretically, when they disagree; no published mask mixes,
    /// and the interpreter drives one path per run. Distinguish the
    /// two `None` causes with [`is_empty`](Self::is_empty).
    pub fn realization(&self) -> Option<LsmRealization> {
        let mut realizations = self.machines.iter().map(|m| match m.access {
            LsmAccess::Memory { .. } => LsmRealization::Memory,
            LsmAccess::Property { .. } => LsmRealization::Property,
        });
        let first = realizations.next()?;
        realizations.all(|r| r == first).then_some(first)
    }

    pub fn is_empty(&self) -> bool {
        self.machines.is_empty()
    }

    /// The interface object index driving `role`, for property-realized
    /// machines.
    pub fn object_of(&self, role: MachineRole) -> Option<u8> {
        self.machines.iter().find(|m| m.role == role).and_then(|m| match m.access {
            LsmAccess::Property { object, .. } => Some(object),
            LsmAccess::Memory { .. } => None,
        })
    }
}

#[cfg(test)]
pub(crate) mod fixtures {
    /// A master-data document carrying just MV-0705's download-relevant
    /// content, in the real file's shape.
    ///
    /// Unit tests need mask data and the licensed `knx_master.xml`
    /// stays out of the repository; the presence-gated tests below
    /// hold this fixture against the real file.
    pub const MV_0705: &str = r#"<KNX xmlns="http://knx.org/xml/project/23">
  <MasterData Id="MD-1" Version="278">
    <MaskVersions>
      <MaskVersion Id="MV-0705" MaskVersion="1797" Name="7.5" ManagementModel="BimM112">
        <HawkConfigurationData>
          <Features>
            <Feature Name="FirstAppObjectIdx" Value="5" />
            <Feature Name="AuthorizeLevels" Value="16" />
          </Features>
          <Resources>
            <Resource Name="ProgrammingMode" Access="remote">
              <Location AddressSpace="StandardMemory" StartAddress="96" />
              <ResourceType Length="1" Flavour="ProgrammingMode_Bcu1" />
            </Resource>
            <Resource Name="GroupAddressTableLoadControl" Access="remote">
              <Location AddressSpace="StandardMemory" StartAddress="260" />
              <ResourceType Length="12" Flavour="LoadControl_M112" />
            </Resource>
            <Resource Name="GroupAddressTableLoadStatus" Access="remote">
              <Location AddressSpace="StandardMemory" StartAddress="46826" />
              <ResourceType Length="1" Flavour="LoadControl_M112" />
            </Resource>
            <Resource Name="GroupAssociationTableLoadControl" Access="remote">
              <Location AddressSpace="StandardMemory" StartAddress="260" />
              <ResourceType Length="12" Flavour="LoadControl_M112" />
            </Resource>
            <Resource Name="GroupAssociationTableLoadStatus" Access="remote">
              <Location AddressSpace="StandardMemory" StartAddress="46827" />
              <ResourceType Length="1" Flavour="LoadControl_M112" />
            </Resource>
            <Resource Name="ApplicationLoadControl" Access="remote">
              <Location AddressSpace="StandardMemory" StartAddress="260" />
              <ResourceType Length="12" Flavour="LoadControl_M112" />
            </Resource>
            <Resource Name="ApplicationLoadStatus" Access="remote">
              <Location AddressSpace="StandardMemory" StartAddress="46828" />
              <ResourceType Length="1" Flavour="LoadControl_M112" />
            </Resource>
            <Resource Name="PeiprogLoadControl" Access="remote">
              <Location AddressSpace="StandardMemory" StartAddress="260" />
              <ResourceType Length="12" Flavour="LoadControl_M112" />
            </Resource>
            <Resource Name="PeiprogLoadStatus" Access="remote">
              <Location AddressSpace="StandardMemory" StartAddress="46829" />
              <ResourceType Length="1" Flavour="LoadControl_M112" />
            </Resource>
            <Resource Name="GroupAddressTable" Access="remote">
              <Location AddressSpace="StandardMemory" StartAddress="16384" />
              <ResourceType Length="1" Flavour="AddressTable_Bcu1" />
            </Resource>
          </Resources>
          <Procedures>
            <Procedure ProcedureType="Unload" ProcedureSubType="all" Access="remote">
              <LdCtrlConnect />
              <LdCtrlUnload LsmIdx="1" />
              <LdCtrlUnload LsmIdx="2" />
              <LdCtrlUnload LsmIdx="3" />
              <LdCtrlUnload LsmIdx="4" />
              <LdCtrlDisconnect />
            </Procedure>
          </Procedures>
        </HawkConfigurationData>
      </MaskVersion>
    </MaskVersions>
  </MasterData>
</KNX>"#;

    /// MV-0012's download-relevant content, in the real file's shape:
    /// no load-control resources at all (BCU1 has no load state
    /// machines), a memory-mapped `ProgrammingMode`, and the Load/all
    /// + Unload/all procedures copied verbatim from the published
    /// master data — direct memory writes bracketed by the RunError
    /// halt (010Dh ← 00) and the GA-table mute (0116h ← 01).
    pub const MV_0012: &str = r#"<KNX xmlns="http://knx.org/xml/project/23">
  <MasterData Id="MD-1" Version="278">
    <MaskVersions>
      <MaskVersion Id="MV-0012" MaskVersion="18" Name="1.2" ManagementModel="Bcu1">
        <HawkConfigurationData>
          <Resources>
            <Resource Name="ProgrammingMode" Access="remote local1">
              <Location AddressSpace="StandardMemory" StartAddress="96" />
              <ResourceType Length="1" Flavour="ProgrammingMode_Bcu1" />
            </Resource>
            <Resource Name="GroupAddressTable" Access="remote local1">
              <Location AddressSpace="StandardMemory" StartAddress="278" />
              <ResourceType Length="1" Flavour="AddressTable_Bcu1" />
            </Resource>
            <Resource Name="GroupAssociationTablePtr" Access="remote local1">
              <Location AddressSpace="StandardMemory" StartAddress="273" />
              <ResourceType Length="1" Flavour="Ptr_StandardMemory100" />
            </Resource>
          </Resources>
          <Procedures>
            <Procedure ProcedureType="Load" ProcedureSubType="all">
              <LdCtrlConnect />
              <LdCtrlSetControlVariable Name="EnableVerifyOnWriteDirect" Value="true" />
              <LdCtrlWriteMem Address="269" Size="1" Verify="true" InlineData="00" />
              <LdCtrlLoadImageMem Address="278" Size="1" />
              <LdCtrlWriteMem Address="278" Size="1" Verify="true" InlineData="01" />
              <LdCtrlWriteMem Address="256" Size="1" Verify="true" />
              <LdCtrlWriteMem Address="260" Size="9" Verify="true" />
              <LdCtrlWriteMem Address="270" Size="8" Verify="true" />
              <LdCtrlWriteMem Address="281" Size="230" Verify="true" />
              <LdCtrlWriteMem Address="206" Size="9" Verify="true" InlineData="000000000000000000" />
              <LdCtrlWriteMem Address="215" Size="9" Verify="true" InlineData="000000000000000000" />
              <LdCtrlWriteMem Address="278" Size="1" Verify="true" />
              <LdCtrlWriteMem Address="269" Size="1" Verify="true" InlineData="FF" />
              <LdCtrlRestart />
            </Procedure>
            <Procedure ProcedureType="Unload" ProcedureSubType="all">
              <LdCtrlConnect />
              <LdCtrlSetControlVariable Name="EnableVerifyOnWriteDirect" Value="true" />
              <LdCtrlWriteMem Address="269" Size="1" Verify="true" InlineData="00" />
              <LdCtrlWriteMem Address="278" Size="1" Verify="true" InlineData="01" />
              <LdCtrlWriteMem Address="261" Size="3" Verify="true" InlineData="000000" />
              <LdCtrlDisconnect />
            </Procedure>
          </Procedures>
        </HawkConfigurationData>
        <MaskEntries>
          <MaskEntry Id="MV-0012_ME-U.5Fdeb30" Name="U_deb30" Address="3183" />
          <MaskEntry Id="MV-0012_ME-U.5FGetTMx" Name="U_GetTMx" Address="3436" />
          <MaskEntry Id="MV-0012_ME-U.5FioAST" Name="U_ioAST" Address="3535" />
          <MaskEntry Id="MV-0012_ME-U.5FtransRequest" Name="U_transRequest" Address="3513" />
        </MaskEntries>
      </MaskVersion>
    </MaskVersions>
  </MasterData>
</KNX>"#;

    /// MV-0020's download-relevant content, in the real file's shape:
    /// property-mapped machines 1–3, the `DownwardCompatibleMasks`
    /// naming the BCU1 masks whose programs a BCU2 runs, and the
    /// remote `Load/all` + `Unload/all` templates copied verbatim —
    /// LSM cycling with the task records, `EnableSegmentWrite=false`
    /// (the template carries its own explicit data phase), and the
    /// BCU1-style memory phase.
    pub const MV_0020: &str = r#"<KNX xmlns="http://knx.org/xml/project/23">
  <MasterData Id="MD-1" Version="278">
    <MaskVersions>
      <MaskVersion Id="MV-0020" MaskVersion="32" Name="2.0" ManagementModel="Bcu2">
        <DownwardCompatibleMasks>
          <DownwardCompatibleMask RefId="MV-0010" />
          <DownwardCompatibleMask RefId="MV-0011" />
          <DownwardCompatibleMask RefId="MV-0012" />
        </DownwardCompatibleMasks>
        <HawkConfigurationData>
          <Features>
            <Feature Name="FirstAppObjectIdx" Value="4" />
            <Feature Name="AuthorizeLevels" Value="4" />
          </Features>
          <Resources>
            <Resource Name="ProgrammingMode" Access="remote local1">
              <Location AddressSpace="StandardMemory" StartAddress="96" />
              <ResourceType Length="1" Flavour="ProgrammingMode_Bcu1" />
            </Resource>
            <Resource Name="RunError" Access="remote local1">
              <Location AddressSpace="StandardMemory" StartAddress="269" />
              <ResourceType Length="1" Flavour="Runerror_Bcu1" />
            </Resource>
            <Resource Name="GroupAssociationTablePtr" Access="remote local1">
              <Location AddressSpace="StandardMemory" StartAddress="273" />
              <ResourceType Length="1" Flavour="Ptr_StandardMemory100" />
            </Resource>
            <Resource Name="GroupAddressTableLoadControl" Access="remote local2">
              <Location AddressSpace="SystemProperty" InterfaceObjectRef="1" PropertyID="5" StartAddress="0" />
              <ResourceType Length="10" Flavour="LoadControl_Bcu2" />
            </Resource>
            <Resource Name="GroupAddressTableLoadStatus" Access="remote local2">
              <Location AddressSpace="SystemProperty" InterfaceObjectRef="1" PropertyID="5" StartAddress="0" />
              <ResourceType Length="1" Flavour="LoadControl_Bcu2" />
            </Resource>
            <Resource Name="GroupAssociationTableLoadControl" Access="remote local2">
              <Location AddressSpace="SystemProperty" InterfaceObjectRef="2" PropertyID="5" StartAddress="0" />
              <ResourceType Length="10" Flavour="LoadControl_Bcu2" />
            </Resource>
            <Resource Name="GroupAssociationTableLoadStatus" Access="remote local2">
              <Location AddressSpace="SystemProperty" InterfaceObjectRef="2" PropertyID="5" StartAddress="0" />
              <ResourceType Length="1" Flavour="LoadControl_Bcu2" />
            </Resource>
            <Resource Name="ApplicationLoadControl" Access="remote local2">
              <Location AddressSpace="SystemProperty" InterfaceObjectRef="3" PropertyID="5" StartAddress="0" />
              <ResourceType Length="10" Flavour="LoadControl_Bcu2" />
            </Resource>
            <Resource Name="ApplicationLoadStatus" Access="remote local2">
              <Location AddressSpace="SystemProperty" InterfaceObjectRef="3" PropertyID="5" StartAddress="0" />
              <ResourceType Length="1" Flavour="LoadControl_Bcu2" />
            </Resource>
          </Resources>
          <Procedures>
            <Procedure ProcedureType="Load" ProcedureSubType="all" Access="remote local2">
              <LdCtrlConnect />
              <LdCtrlSetControlVariable Name="EnableSegmentWrite" Value="false" />
              <LdCtrlUnload LsmIdx="1" />
              <LdCtrlUnload LsmIdx="2" />
              <LdCtrlUnload LsmIdx="3" />
              <LdCtrlLoad LsmIdx="3" />
              <LdCtrlAbsSegment LsmIdx="3" SegType="0" Address="200" Size="24" Access="51" MemType="1" SegFlags="0" />
              <LdCtrlAbsSegment LsmIdx="3" SegType="0" Address="2418" Size="74" Access="51" MemType="2" SegFlags="0" />
              <LdCtrlAbsSegment LsmIdx="3" SegType="0" Address="282" Size="2" Access="51" MemType="3" SegFlags="0" />
              <LdCtrlAbsSegment LsmIdx="3" SegType="0" Address="256" Size="22" Access="51" MemType="3" SegFlags="0" />
              <LdCtrlAbsSegment LsmIdx="3" SegType="0" Address="284" Size="852" Access="51" MemType="3" SegFlags="128" />
              <LdCtrlTaskSegment LsmIdx="3" Address="286" />
              <LdCtrlTaskPtr LsmIdx="3" InitPtr="284" SavePtr="285" SerialPtr="0" />
              <LdCtrlTaskCtrl1 LsmIdx="3" Address="0" Count="0" />
              <LdCtrlTaskCtrl2 LsmIdx="3" Callback="20609" Address="282" Seg0="208" Seg1="208" />
              <LdCtrlLoadCompleted LsmIdx="3" />
              <LdCtrlSetControlVariable Name="EnableSegmentWrite" Value="true" />
              <LdCtrlSetControlVariable Name="EnableVerifyOnWriteDirect" Value="true" />
              <LdCtrlWriteMem Address="269" Size="1" Verify="true" InlineData="00" />
              <LdCtrlDelay MilliSeconds="1000" />
              <LdCtrlLoadImageMem Address="278" Size="1" />
              <LdCtrlWriteMem Address="278" Size="1" Verify="true" InlineData="01" />
              <LdCtrlWriteMem Address="256" Size="1" Verify="true" />
              <LdCtrlWriteMem Address="259" Size="10" Verify="true" />
              <LdCtrlWriteMem Address="270" Size="8" Verify="true" />
              <LdCtrlWriteMem Address="281" Size="230" Verify="true" />
              <LdCtrlWriteMem Address="512" Size="624" Verify="true" />
              <LdCtrlWriteMem Address="278" Size="1" Verify="true" />
              <LdCtrlSetControlVariable Name="EnableVerifyOnWriteDirect" Value="false" />
              <LdCtrlWriteMem Address="269" Size="1" Verify="false" InlineData="FF" />
              <LdCtrlCompareMem Address="269" Size="1" InlineData="FF" />
              <LdCtrlRestart />
            </Procedure>
            <Procedure ProcedureType="Unload" ProcedureSubType="all" Access="remote local2">
              <LdCtrlConnect />
              <LdCtrlUnload LsmIdx="1" />
              <LdCtrlUnload LsmIdx="2" />
              <LdCtrlUnload LsmIdx="3" />
              <LdCtrlDelay MilliSeconds="1000" />
              <LdCtrlDisconnect />
            </Procedure>
          </Procedures>
        </HawkConfigurationData>
        <MaskEntries>
          <MaskEntry Id="MV-0020_ME-U.5Fdeb30" Name="U_deb30" Address="20558" />
          <MaskEntry Id="MV-0020_ME-U.5FGetTMx" Name="U_GetTMx" Address="20579" />
          <MaskEntry Id="MV-0020_ME-U.5FioAST" Name="U_ioAST" Address="20582" />
          <MaskEntry Id="MV-0020_ME-U.5FtransRequest" Name="U_transRequest" Address="20606" />
        </MaskEntries>
      </MaskVersion>
    </MaskVersions>
  </MasterData>
</KNX>"#;

    /// MV-07B0's resource declarations, in the real file's shape:
    /// every machine is `SystemProperty` at its interface object's
    /// `PID_LOAD_STATE_CONTROL`. No procedures — this fixture is for
    /// the LSM model; the merge/procedure fixtures live in the
    /// assemble/interpreter tests.
    pub const MV_07B0_RESOURCES: &str = r#"<KNX xmlns="http://knx.org/xml/project/23">
  <MasterData Id="MD-1" Version="278">
    <MaskVersions>
      <MaskVersion Id="MV-07B0" MaskVersion="1968" Name="System B" ManagementModel="SystemB">
        <HawkConfigurationData>
          <Resources>
            <Resource Name="GroupAddressTableLoadControl" Access="remote">
              <Location AddressSpace="SystemProperty" InterfaceObjectRef="1" PropertyID="5" />
              <ResourceType Length="10" Flavour="LoadControl_Bcu2" />
            </Resource>
            <Resource Name="GroupAddressTableLoadStatus" Access="remote">
              <Location AddressSpace="SystemProperty" InterfaceObjectRef="1" PropertyID="5" />
              <ResourceType Length="1" Flavour="LoadControl_Bcu2" />
            </Resource>
            <Resource Name="GroupAssociationTableLoadControl" Access="remote">
              <Location AddressSpace="SystemProperty" InterfaceObjectRef="2" PropertyID="5" />
              <ResourceType Length="10" Flavour="LoadControl_Bcu2" />
            </Resource>
            <Resource Name="GroupAssociationTableLoadStatus" Access="remote">
              <Location AddressSpace="SystemProperty" InterfaceObjectRef="2" PropertyID="5" />
              <ResourceType Length="1" Flavour="LoadControl_Bcu2" />
            </Resource>
            <Resource Name="GroupObjectTableLoadControl" Access="remote">
              <Location AddressSpace="SystemProperty" InterfaceObjectRef="3" PropertyID="5" />
              <ResourceType Length="10" Flavour="LoadControl_Bcu2" />
            </Resource>
            <Resource Name="GroupObjectTableLoadStatus" Access="remote">
              <Location AddressSpace="SystemProperty" InterfaceObjectRef="3" PropertyID="5" />
              <ResourceType Length="1" Flavour="LoadControl_Bcu2" />
            </Resource>
            <Resource Name="ApplicationLoadControl" Access="remote">
              <Location AddressSpace="SystemProperty" InterfaceObjectRef="4" PropertyID="5" />
              <ResourceType Length="10" Flavour="LoadControl_Bcu2" />
            </Resource>
            <Resource Name="ApplicationLoadStatus" Access="remote">
              <Location AddressSpace="SystemProperty" InterfaceObjectRef="4" PropertyID="5" />
              <ResourceType Length="1" Flavour="LoadControl_Bcu2" />
            </Resource>
            <Resource Name="PeiprogLoadControl" Access="remote">
              <Location AddressSpace="SystemProperty" InterfaceObjectRef="5" PropertyID="5" />
              <ResourceType Length="10" Flavour="LoadControl_Bcu2" />
            </Resource>
            <Resource Name="PeiprogLoadStatus" Access="remote">
              <Location AddressSpace="SystemProperty" InterfaceObjectRef="5" PropertyID="5" />
              <ResourceType Length="1" Flavour="LoadControl_Bcu2" />
            </Resource>
          </Resources>
        </HawkConfigurationData>
      </MaskVersion>
    </MaskVersions>
  </MasterData>
</KNX>"#;

    /// MV-2705's shape — the mask that proves realization is not a
    /// family property: `BimM112`-managed, yet its machines are
    /// property-driven, with `Application` at object **3** (no group
    /// object table on System 7).
    pub const MV_2705_RESOURCES: &str = r#"<KNX xmlns="http://knx.org/xml/project/23">
  <MasterData Id="MD-1" Version="278">
    <MaskVersions>
      <MaskVersion Id="MV-2705" MaskVersion="9989" Name="7.5 RF" ManagementModel="BimM112">
        <HawkConfigurationData>
          <Resources>
            <Resource Name="GroupAddressTableLoadControl" Access="remote">
              <Location AddressSpace="SystemProperty" InterfaceObjectRef="1" PropertyID="5" />
              <ResourceType Length="10" Flavour="LoadControl_Bcu2" />
            </Resource>
            <Resource Name="GroupAddressTableLoadStatus" Access="remote">
              <Location AddressSpace="SystemProperty" InterfaceObjectRef="1" PropertyID="5" />
              <ResourceType Length="1" Flavour="LoadControl_Bcu2" />
            </Resource>
            <Resource Name="GroupAssociationTableLoadControl" Access="remote">
              <Location AddressSpace="SystemProperty" InterfaceObjectRef="2" PropertyID="5" />
              <ResourceType Length="10" Flavour="LoadControl_Bcu2" />
            </Resource>
            <Resource Name="GroupAssociationTableLoadStatus" Access="remote">
              <Location AddressSpace="SystemProperty" InterfaceObjectRef="2" PropertyID="5" />
              <ResourceType Length="1" Flavour="LoadControl_Bcu2" />
            </Resource>
            <Resource Name="ApplicationLoadControl" Access="remote">
              <Location AddressSpace="SystemProperty" InterfaceObjectRef="3" PropertyID="5" />
              <ResourceType Length="10" Flavour="LoadControl_Bcu2" />
            </Resource>
            <Resource Name="ApplicationLoadStatus" Access="remote">
              <Location AddressSpace="SystemProperty" InterfaceObjectRef="3" PropertyID="5" />
              <ResourceType Length="1" Flavour="LoadControl_Bcu2" />
            </Resource>
            <Resource Name="PeiprogLoadControl" Access="remote">
              <Location AddressSpace="SystemProperty" InterfaceObjectRef="4" PropertyID="5" />
              <ResourceType Length="10" Flavour="LoadControl_Bcu2" />
            </Resource>
            <Resource Name="PeiprogLoadStatus" Access="remote">
              <Location AddressSpace="SystemProperty" InterfaceObjectRef="4" PropertyID="5" />
              <ResourceType Length="1" Flavour="LoadControl_Bcu2" />
            </Resource>
          </Resources>
        </HawkConfigurationData>
      </MaskVersion>
    </MaskVersions>
  </MasterData>
</KNX>"#;
}

#[cfg(test)]
mod tests {
    use super::*;

    fn db() -> MaskDb {
        MaskDb::from_str(fixtures::MV_0705).expect("the fixture parses")
    }

    #[test]
    fn looks_up_a_mask_by_the_version_a_device_reports() {
        let db = db();
        let mask = db.mask(MaskVersion::System7Tp1).expect("MV-0705 is present");
        assert_eq!(mask.management_model(), "BimM112");
        assert_eq!(mask.first_app_object_idx(), 5);
        assert_eq!(mask.feature("AuthorizeLevels"), Some("16"));
        assert!(db.mask(MaskVersion::SystemBTp1).is_none(), "the fixture defines only 0705");
    }

    #[test]
    fn reads_memory_resources_from_the_resource_list() {
        let db = db();
        let mask = db.mask(MaskVersion::System7Tp1).expect("MV-0705 is present");
        let resources = mask.memory_resources().expect("0705 locates all four in StandardMemory");
        assert_eq!(resources.programming_mode_addr, 0x0060);
        assert_eq!(resources.load_control_addr, 0x0104);
        assert_eq!(resources.load_status_addr, 0xB6EA);
        assert_eq!(resources.address_table_addr, 0x4000);

        // Load-state bytes run consecutively in machine order.
        assert_eq!(resources.load_status_of(LsmMachine::AddressTable), 0xB6EA);
        assert_eq!(resources.load_status_of(LsmMachine::PeiProgram), 0xB6ED);
    }

    #[test]
    fn system_7_carries_only_an_unload_template() {
        let db = db();
        let mask = db.mask(MaskVersion::System7Tp1).expect("MV-0705 is present");
        assert!(mask.procedure("Unload", "all").is_some());
        assert!(
            mask.procedure("Load", "all").is_none(),
            "System 7 Load procedures are product-supplied, not in the master data"
        );
    }

    #[test]
    fn derives_a_property_model_from_system_b_resources() {
        let db = MaskDb::from_str(fixtures::MV_07B0_RESOURCES).expect("fixture parses");
        let mask = db.mask(MaskVersion::SystemBTp1).expect("MV-07B0");
        let model = mask.lsm_model();

        assert_eq!(model.realization(), Some(LsmRealization::Property));
        assert_eq!(model.machines.len(), 5);
        assert_eq!(model.object_of(MachineRole::GroupAddressTable), Some(1));
        assert_eq!(model.object_of(MachineRole::GroupObjectTable), Some(3));
        assert_eq!(model.object_of(MachineRole::Application), Some(4));
        assert_eq!(model.object_of(MachineRole::PeiProgram), Some(5));
    }

    #[test]
    fn realization_is_not_a_family_property() {
        // The 2705 shape: BimM112-managed, property-driven machines,
        // Application at object 3 (no group object table). A
        // family-keyed path choice gets this mask wrong; the model
        // reads what the mask declares.
        let db = MaskDb::from_str(fixtures::MV_2705_RESOURCES).expect("fixture parses");
        let mask = db.mask(MaskVersion::Other(0x2705)).expect("MV-2705");
        assert_eq!(mask.management_model(), "BimM112");

        let model = mask.lsm_model();
        assert_eq!(model.realization(), Some(LsmRealization::Property));
        assert_eq!(model.machines.len(), 4);
        assert_eq!(model.object_of(MachineRole::Application), Some(3));
        assert_eq!(model.object_of(MachineRole::GroupObjectTable), None);
    }

    #[test]
    fn derives_a_memory_model_from_system_7_resources() {
        let db = db();
        let mask = db.mask(MaskVersion::System7Tp1).expect("MV-0705");
        let model = mask.lsm_model();

        assert_eq!(model.realization(), Some(LsmRealization::Memory));
        assert_eq!(model.machines.len(), 4);
        // In roster order, statuses consecutive from B6EA — the
        // assumption MemoryResources::load_status_of arithmetizes.
        let statuses: Vec<u16> = model
            .machines
            .iter()
            .map(|m| match m.access {
                LsmAccess::Memory { status, .. } => status,
                LsmAccess::Property { .. } => panic!("0705 machines are memory-mapped"),
            })
            .collect();
        assert_eq!(statuses, [0xB6EA, 0xB6EB, 0xB6EC, 0xB6ED]);
        assert_eq!(model.object_of(MachineRole::Application), None, "memory machines have no object index");
    }

    #[test]
    fn plain_property_address_space_counts_as_property() {
        // Coupler masks spell the space "Property", not
        // "SystemProperty"; both are (object, PID) access.
        let xml = r#"<KNX xmlns="http://knx.org/xml/project/23">
  <MasterData Id="MD-1" Version="278"><MaskVersions>
    <MaskVersion Id="MV-2920" MaskVersion="10528" Name="coupler" ManagementModel="SystemB">
      <HawkConfigurationData><Resources>
        <Resource Name="GroupFilterTableLoadControl" Access="remote">
          <Location AddressSpace="Property" InterfaceObjectRef="6" PropertyID="5" />
          <ResourceType Length="10" Flavour="LoadControl_Bcu2" />
        </Resource>
        <Resource Name="GroupFilterTableLoadStatus" Access="remote">
          <Location AddressSpace="Property" InterfaceObjectRef="6" PropertyID="5" />
          <ResourceType Length="1" Flavour="LoadControl_Bcu2" />
        </Resource>
      </Resources></HawkConfigurationData>
    </MaskVersion>
  </MaskVersions></MasterData>
</KNX>"#;
        let db = MaskDb::from_str(xml).expect("parses");
        let mask = db.mask(MaskVersion::Other(0x2920)).expect("MV-2920");
        let model = mask.lsm_model();
        assert_eq!(model.realization(), Some(LsmRealization::Property));
        assert_eq!(model.object_of(MachineRole::GroupFilterTable), Some(6));
    }

    /// Mask selection is the device's DD0, gated by
    /// `DownwardCompatibleMasks` — ETS's `VerifyCompatibleMaskVersionTask`.
    #[test]
    fn download_mask_selection_follows_the_device() {
        let db = MaskDb::from_str(fixtures::MV_0020).expect("fixture parses");
        let bcu2 = MaskVersion::Other(0x0020);

        // Identical masks: the ordinary download.
        assert_eq!(select_download_mask(&db, bcu2, bcu2).expect("identity").version(), bcu2);

        // A BCU1 product on a BCU2 device: compatible, and the
        // *device's* mask wins.
        let selected = select_download_mask(&db, MaskVersion::Bcu1Tp1, bcu2).expect("downward compatible");
        assert_eq!(selected.version(), bcu2);
        assert_eq!(selected.management_model(), "Bcu2");

        // A System 7 product on a BCU2: not in its compatibility list.
        assert!(select_download_mask(&db, MaskVersion::System7Tp1, bcu2).is_err());

        // A device whose mask the master data does not describe.
        assert!(select_download_mask(&db, MaskVersion::Bcu1Tp1, MaskVersion::SystemBTp1).is_err());
    }

    #[test]
    fn a_mask_without_machines_yields_an_empty_model() {
        // BCU1 masks declare no LoadControl resources: downloads there
        // are plain memory writes with no state machines.
        let xml = r#"<KNX xmlns="http://knx.org/xml/project/23">
  <MasterData Id="MD-1" Version="278"><MaskVersions>
    <MaskVersion Id="MV-0012" MaskVersion="18" Name="1.2" ManagementModel="Bcu1">
      <HawkConfigurationData><Resources>
        <Resource Name="ProgrammingMode" Access="remote">
          <Location AddressSpace="StandardMemory" StartAddress="96" />
          <ResourceType Length="1" Flavour="ProgrammingMode_Bcu1" />
        </Resource>
      </Resources></HawkConfigurationData>
    </MaskVersion>
  </MaskVersions></MasterData>
</KNX>"#;
        let db = MaskDb::from_str(xml).expect("parses");
        let model = db.mask(MaskVersion::Other(0x0012)).expect("MV-0012").lsm_model();
        assert!(model.is_empty());
        assert_eq!(model.realization(), None);
    }

    /// The fixture must match the real ETS master data. The licensed
    /// file stays out of the repository, so this runs only where a
    /// copy is present:
    /// `cargo test -p zweidraehte-client -- --ignored`.
    #[test]
    #[ignore = "requires a local knx_master.xml under manuf_tool_data/"]
    fn fixture_matches_the_real_master_data() {
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../manuf_tool_data/VC-EASY-03_MDT_KP_V35/knx_master.xml");
        let real = MaskDb::from_file(path).expect("the real master data parses");
        let real_mask = real.mask(MaskVersion::System7Tp1).expect("the real file defines MV-0705");
        let fixture_mask = db();
        let fixture_mask = fixture_mask.mask(MaskVersion::System7Tp1).expect("fixture");

        assert_eq!(real_mask.memory_resources(), fixture_mask.memory_resources());
        assert_eq!(real_mask.management_model(), fixture_mask.management_model());
        assert_eq!(real_mask.first_app_object_idx(), fixture_mask.first_app_object_idx());
        assert_eq!(real_mask.feature("AuthorizeLevels"), fixture_mask.feature("AuthorizeLevels"));

        // The Unload-all template must agree instruction for instruction.
        let real_unload = real_mask.procedure("Unload", "all").expect("real Unload all");
        let fixture_unload = fixture_mask.procedure("Unload", "all").expect("fixture Unload all");
        let convert = |p: &Procedure| crate::download::ir::controls_to_instructions(&p.controls, Default::default());
        assert_eq!(convert(real_unload).expect("real converts"), convert(fixture_unload).expect("fixture converts"));

        // The LSM models the real file yields, pinned per family —
        // including the mask that proves realization is not a family
        // property (2705: BimM112, property machines, Application at
        // object 3) and BCU2 (property machines at objects 1-3).
        let model = |code: u16| real.mask(MaskVersion::from(code)).expect("mask present").lsm_model();

        let m0705 = model(0x0705);
        assert_eq!(m0705.realization(), Some(LsmRealization::Memory));
        assert_eq!(m0705.machines.len(), 4);
        assert_eq!(m0705, fixture_mask.lsm_model(), "the 0705 fixture model matches the real file");

        let m07b0 = model(0x07B0);
        assert_eq!(m07b0.realization(), Some(LsmRealization::Property));
        assert_eq!(m07b0.machines.len(), 5);
        assert_eq!(m07b0.object_of(MachineRole::GroupObjectTable), Some(3));
        assert_eq!(m07b0.object_of(MachineRole::Application), Some(4));
        {
            let fixture = MaskDb::from_str(fixtures::MV_07B0_RESOURCES).expect("fixture parses");
            assert_eq!(m07b0, fixture.mask(MaskVersion::SystemBTp1).expect("07B0").lsm_model());
        }

        let m2705 = model(0x2705);
        assert_eq!(m2705.realization(), Some(LsmRealization::Property));
        assert_eq!(m2705.machines.len(), 4);
        assert_eq!(m2705.object_of(MachineRole::Application), Some(3));
        {
            let fixture = MaskDb::from_str(fixtures::MV_2705_RESOURCES).expect("fixture parses");
            assert_eq!(m2705, fixture.mask(MaskVersion::Other(0x2705)).expect("2705").lsm_model());
        }

        let m0020 = model(0x0020);
        assert_eq!(m0020.realization(), Some(LsmRealization::Property), "BCU2 machines are property-driven");
        assert_eq!(m0020.machines.len(), 3);

        assert!(model(0x0012).is_empty(), "BCU1 declares no load state machines");
        {
            let real_bcu1 = real.mask(MaskVersion::Bcu1Tp1).expect("MV-0012 present");
            let fixture = MaskDb::from_str(fixtures::MV_0012).expect("fixture parses");
            let fixture_bcu1 = fixture.mask(MaskVersion::Bcu1Tp1).expect("MV-0012");
            for (kind, sub) in [("Load", "all"), ("Unload", "all")] {
                let real_proc = real_bcu1.procedure(kind, sub).expect("real procedure");
                let fixture_proc = fixture_bcu1.procedure(kind, sub).expect("fixture procedure");
                assert_eq!(
                    convert(real_proc).expect("real converts"),
                    convert(fixture_proc).expect("fixture converts"),
                    "MV-0012 {kind}/{sub}"
                );
            }
        }
        {
            let real_bcu2 = real.mask(MaskVersion::Other(0x0020)).expect("MV-0020 present");
            let fixture = MaskDb::from_str(fixtures::MV_0020).expect("fixture parses");
            let fixture_bcu2 = fixture.mask(MaskVersion::Other(0x0020)).expect("MV-0020");
            for (kind, sub) in [("Load", "all"), ("Unload", "all")] {
                let real_proc = real_bcu2.procedure(kind, sub).expect("real procedure");
                let fixture_proc = fixture_bcu2.procedure(kind, sub).expect("fixture procedure");
                assert_eq!(
                    convert(real_proc).expect("real converts"),
                    convert(fixture_proc).expect("fixture converts"),
                    "MV-0020 {kind}/{sub}"
                );
            }
            for mask in [0x0010, 0x0011, 0x0012] {
                assert!(
                    real_bcu2.is_downward_compatible_with(MaskVersion::from(mask)),
                    "MV-0020 runs {mask:04X} programs"
                );
            }
            assert!(!real_bcu2.is_downward_compatible_with(MaskVersion::System7Tp1));

            // The fixture's MaskEntries carry the real addresses (the
            // Merten fixup set, confirmed on the wire by the ETS
            // trace of a 0020 download).
            let real_bcu1 = real.mask(MaskVersion::Bcu1Tp1).expect("MV-0012 present");
            for (entry, on_0012, on_0020) in [
                ("U.5Fdeb30", 3183, 20558),
                ("U.5FGetTMx", 3436, 20579),
                ("U.5FioAST", 3535, 20582),
                ("U.5FtransRequest", 3513, 20606),
            ] {
                assert_eq!(real_bcu1.mask_entry_address(entry), Some(on_0012), "{entry} on MV-0012");
                assert_eq!(real_bcu2.mask_entry_address(entry), Some(on_0020), "{entry} on MV-0020");
            }
        }

        // And the real file must describe far more masks than we would
        // ever hand-curate — which is the whole argument for reading it.
        // project-20 defines 32, project-23 adds MV-6800 and MV-6900;
        // the lower bound holds for either.
        assert!(real.len() >= 32, "the published master data defines at least 32 masks, got {}", real.len());
    }
}
