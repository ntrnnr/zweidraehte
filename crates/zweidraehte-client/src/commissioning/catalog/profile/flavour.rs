//! Closed vocabulary of supported resource realizations.

use super::UnknownProfileToken;
use std::fmt;

/// Supported resource realization, parsed before image or procedure compilation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum ResourceFlavour {
    /// Master Data token `AddressTable_Bcu1`.
    AddressTableBcu1,
    /// Master Data token `AddressTable_Bcu1PL`.
    AddressTableBcu1Pl,
    /// Master Data token `AddressTable_SystemB`.
    AddressTableSystemB,
    /// Master Data token `AssociationTable_Bcu1`.
    AssociationTableBcu1,
    /// Master Data token `AssociationTable_Bcu2`.
    AssociationTableBcu2,
    /// Master Data token `AssociationTable_M112`.
    AssociationTableM112,
    /// Master Data token `AssociationTable_SystemB`.
    AssociationTableSystemB,
    /// Master Data token `AssociationTable_SystemBSmall`.
    AssociationTableSystemBSmall,
    /// Master Data token `AssociationTable_SystemBBig`.
    AssociationTableSystemBBig,
    /// Master Data token `FrequencyChannel_Bcu1PL`.
    FrequencyChannelBcu1Pl,
    /// Master Data token `GroupObjectTable_Bcu10`.
    GroupObjectTableBcu10,
    /// Master Data token `GroupObjectTable_Bcu11`.
    GroupObjectTableBcu11,
    /// Master Data token `GroupObjectTable_Bcu1PL`.
    GroupObjectTableBcu1Pl,
    /// Master Data token `GroupObjectTable_Bcu2`.
    GroupObjectTableBcu2,
    /// Master Data token `GroupObjectTable_M112`.
    GroupObjectTableM112,
    /// Master Data token `GroupObjectTable_System300`.
    GroupObjectTableSystem300,
    /// Master Data token `GroupObjectTable_SystemB`.
    GroupObjectTableSystemB,
    /// Master Data token `HardwareConfig_Identical`.
    HardwareConfigIdentical,
    /// Master Data token `HardwareConfig_Version`.
    HardwareConfigVersion,
    /// Master Data token `Lc_10`.
    Lc10,
    /// Master Data token `Lc_11`.
    Lc11,
    /// Master Data token `Lc_12`.
    Lc12,
    /// Master Data token `LoadControl_Bcu2`.
    LoadControlBcu2,
    /// Master Data token `LoadControl_M112`.
    LoadControlM112,
    /// Master Data token `ManagementStyle_Bcu2`.
    ManagementStyleBcu2,
    /// Master Data token `PeiType_Adc`.
    PeiTypeAdc,
    /// Master Data token `PeiType_Prop`.
    PeiTypeProp,
    /// Master Data token `PlMc`.
    PlMc,
    /// Master Data token `ProgrammingMode_Bcu1`.
    ProgrammingModeBcu1,
    /// Master Data token `ProgrammingMode_Prop`.
    ProgrammingModeProp,
    /// Master Data token `Ptr_StandardMemory`.
    PtrStandardMemory,
    /// Master Data token `Ptr_StandardMemory100`.
    PtrStandardMemory100,
    /// Master Data token `ReConfig_Bcu1PL`.
    ReconfigurationBcu1Pl,
    /// Master Data token `ReConfig_Rf`.
    ReconfigurationRf,
    /// Master Data token `RunControl_Bcu1`.
    RunControlBcu1,
    /// Master Data token `Runerror_Bcu1`.
    RunerrorBcu1,
    /// Master Data token `Sensitivity_Bcu1PL`.
    SensitivityBcu1Pl,
    /// Master Data token `Stamp_SystemB`.
    StampSystemB,
    /// Master Data token `Voltage_Adc`.
    VoltageAdc,
}

impl ResourceFlavour {
    /// Canonical Master Data spelling for diagnostics and serialization.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::AddressTableBcu1 => "AddressTable_Bcu1",
            Self::AddressTableBcu1Pl => "AddressTable_Bcu1PL",
            Self::AddressTableSystemB => "AddressTable_SystemB",
            Self::AssociationTableBcu1 => "AssociationTable_Bcu1",
            Self::AssociationTableBcu2 => "AssociationTable_Bcu2",
            Self::AssociationTableM112 => "AssociationTable_M112",
            Self::AssociationTableSystemB => "AssociationTable_SystemB",
            Self::AssociationTableSystemBSmall => "AssociationTable_SystemBSmall",
            Self::AssociationTableSystemBBig => "AssociationTable_SystemBBig",
            Self::FrequencyChannelBcu1Pl => "FrequencyChannel_Bcu1PL",
            Self::GroupObjectTableBcu10 => "GroupObjectTable_Bcu10",
            Self::GroupObjectTableBcu11 => "GroupObjectTable_Bcu11",
            Self::GroupObjectTableBcu1Pl => "GroupObjectTable_Bcu1PL",
            Self::GroupObjectTableBcu2 => "GroupObjectTable_Bcu2",
            Self::GroupObjectTableM112 => "GroupObjectTable_M112",
            Self::GroupObjectTableSystem300 => "GroupObjectTable_System300",
            Self::GroupObjectTableSystemB => "GroupObjectTable_SystemB",
            Self::HardwareConfigIdentical => "HardwareConfig_Identical",
            Self::HardwareConfigVersion => "HardwareConfig_Version",
            Self::Lc10 => "Lc_10",
            Self::Lc11 => "Lc_11",
            Self::Lc12 => "Lc_12",
            Self::LoadControlBcu2 => "LoadControl_Bcu2",
            Self::LoadControlM112 => "LoadControl_M112",
            Self::ManagementStyleBcu2 => "ManagementStyle_Bcu2",
            Self::PeiTypeAdc => "PeiType_Adc",
            Self::PeiTypeProp => "PeiType_Prop",
            Self::PlMc => "PlMc",
            Self::ProgrammingModeBcu1 => "ProgrammingMode_Bcu1",
            Self::ProgrammingModeProp => "ProgrammingMode_Prop",
            Self::PtrStandardMemory => "Ptr_StandardMemory",
            Self::PtrStandardMemory100 => "Ptr_StandardMemory100",
            Self::ReconfigurationBcu1Pl => "ReConfig_Bcu1PL",
            Self::ReconfigurationRf => "ReConfig_Rf",
            Self::RunControlBcu1 => "RunControl_Bcu1",
            Self::RunerrorBcu1 => "Runerror_Bcu1",
            Self::SensitivityBcu1Pl => "Sensitivity_Bcu1PL",
            Self::StampSystemB => "Stamp_SystemB",
            Self::VoltageAdc => "Voltage_Adc",
        }
    }
}

/// Supported management behavior; exact resources remain profile data.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum ManagementModel {
    /// Master Data token `Bcu1`.
    Bcu1,
    /// Master Data token `Bcu2`.
    Bcu2,
    /// Master Data token `BimM112`.
    System7,
    /// Master Data token `PropertyBased`.
    PropertyBased,
    /// Master Data token `SystemB`.
    SystemB,
    /// Master Data token `None`.
    None,
}

impl ManagementModel {
    /// Canonical Master Data spelling for diagnostics and serialization.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Bcu1 => "Bcu1",
            Self::Bcu2 => "Bcu2",
            Self::System7 => "BimM112",
            Self::PropertyBased => "PropertyBased",
            Self::SystemB => "SystemB",
            Self::None => "None",
        }
    }
}

impl fmt::Display for ManagementModel {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl std::str::FromStr for ManagementModel {
    type Err = UnknownProfileToken;

    fn from_str(token: &str) -> Result<Self, Self::Err> {
        match token {
            "Bcu1" => Ok(Self::Bcu1),
            "Bcu2" => Ok(Self::Bcu2),
            "BimM112" => Ok(Self::System7),
            "PropertyBased" => Ok(Self::PropertyBased),
            "SystemB" => Ok(Self::SystemB),
            "None" => Ok(Self::None),
            _ => Err(UnknownProfileToken { category: "ManagementModel", token: token.to_owned() }),
        }
    }
}

impl fmt::Display for ResourceFlavour {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl std::str::FromStr for ResourceFlavour {
    type Err = UnknownProfileToken;

    fn from_str(token: &str) -> Result<Self, Self::Err> {
        match token {
            "AddressTable_Bcu1" => Ok(Self::AddressTableBcu1),
            "AddressTable_Bcu1PL" => Ok(Self::AddressTableBcu1Pl),
            "AddressTable_SystemB" => Ok(Self::AddressTableSystemB),
            "AssociationTable_Bcu1" => Ok(Self::AssociationTableBcu1),
            "AssociationTable_Bcu2" => Ok(Self::AssociationTableBcu2),
            "AssociationTable_M112" => Ok(Self::AssociationTableM112),
            "AssociationTable_SystemB" => Ok(Self::AssociationTableSystemB),
            "AssociationTable_SystemBSmall" => Ok(Self::AssociationTableSystemBSmall),
            "AssociationTable_SystemBBig" => Ok(Self::AssociationTableSystemBBig),
            "FrequencyChannel_Bcu1PL" => Ok(Self::FrequencyChannelBcu1Pl),
            "GroupObjectTable_Bcu10" => Ok(Self::GroupObjectTableBcu10),
            "GroupObjectTable_Bcu11" => Ok(Self::GroupObjectTableBcu11),
            "GroupObjectTable_Bcu1PL" => Ok(Self::GroupObjectTableBcu1Pl),
            "GroupObjectTable_Bcu2" => Ok(Self::GroupObjectTableBcu2),
            "GroupObjectTable_M112" => Ok(Self::GroupObjectTableM112),
            "GroupObjectTable_System300" => Ok(Self::GroupObjectTableSystem300),
            "GroupObjectTable_SystemB" => Ok(Self::GroupObjectTableSystemB),
            "HardwareConfig_Identical" => Ok(Self::HardwareConfigIdentical),
            "HardwareConfig_Version" => Ok(Self::HardwareConfigVersion),
            "Lc_10" => Ok(Self::Lc10),
            "Lc_11" => Ok(Self::Lc11),
            "Lc_12" => Ok(Self::Lc12),
            "LoadControl_Bcu2" => Ok(Self::LoadControlBcu2),
            "LoadControl_M112" => Ok(Self::LoadControlM112),
            "ManagementStyle_Bcu2" => Ok(Self::ManagementStyleBcu2),
            "PeiType_Adc" => Ok(Self::PeiTypeAdc),
            "PeiType_Prop" => Ok(Self::PeiTypeProp),
            "PlMc" => Ok(Self::PlMc),
            "ProgrammingMode_Bcu1" => Ok(Self::ProgrammingModeBcu1),
            "ProgrammingMode_Prop" => Ok(Self::ProgrammingModeProp),
            "Ptr_StandardMemory" => Ok(Self::PtrStandardMemory),
            "Ptr_StandardMemory100" => Ok(Self::PtrStandardMemory100),
            "ReConfig_Bcu1PL" => Ok(Self::ReconfigurationBcu1Pl),
            "ReConfig_Rf" => Ok(Self::ReconfigurationRf),
            "RunControl_Bcu1" => Ok(Self::RunControlBcu1),
            "Runerror_Bcu1" => Ok(Self::RunerrorBcu1),
            "Sensitivity_Bcu1PL" => Ok(Self::SensitivityBcu1Pl),
            "Stamp_SystemB" => Ok(Self::StampSystemB),
            "Voltage_Adc" => Ok(Self::VoltageAdc),
            _ => Err(UnknownProfileToken { category: "ResourceFlavour", token: token.to_owned() }),
        }
    }
}
