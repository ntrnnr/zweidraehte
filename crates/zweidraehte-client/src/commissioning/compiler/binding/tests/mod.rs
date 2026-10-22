use crate::bus::access::ManagementCredential;
use crate::commissioning::input::ProgrammingInput;
use std::collections::{BTreeMap, BTreeSet};
use zweidraehte_proto::messages::apdu::load_control::LoadEvent;

use zweidraehte_ets_files::product::{
    ApplicationIdentity, ApplicationProgram2Binding, ApplicationProgramRelationIdentity, LoadProcedureStyle,
    ProductData, Segment, fixtures::SYSTEM7_MTXML,
};
use zweidraehte_ets_files::schema::{
    LdCtrlDelay, LdCtrlRelSegment, LdCtrlWriteMem, LdCtrlWriteRelMem, LoadControl, LoadProcedure,
};
use zweidraehte_proto::address::IndividualAddress;

use crate::commissioning::catalog::rules::lifecycle::validate_download_stamp_output;
use crate::commissioning::compiler::application_identity::validate_application_metadata;
use crate::commissioning::compiler::binding::facts::initial_tool_state;
use crate::commissioning::compiler::compile_fixture as compile_program_fixture;
use crate::commissioning::compiler::selection::sources::primary_application_program_sections;
use crate::commissioning::error::{CompileError, CompileErrorKind};
use crate::commissioning::input::CompileOptions;

use crate::commissioning::compiler::binding::procedure::{ProcedureInput, lower_procedure};
use crate::commissioning::compiler::selection::{ProcedureApplicability, ProcedureComposition};
use crate::commissioning::image::ImageSpace;
use crate::commissioning::procedure::operands::StandardMemoryService;

use crate::commissioning::catalog::profile::testing::{append_xml, fixture_profile};
use crate::commissioning::catalog::profile::{ObjectSelector, ResourceFlavour};
use crate::commissioning::procedure::{
    Comparison, ComparisonPadding, ControlPath, DownloadStampOutput, ErrorAction, ErrorHandler, LoadControlCause,
    NormalizedProcedure, OperationData, OperationExtent, OperationTarget, ProcedureOperation, ProcedureSourceId,
    ProcedureStep, RestartKind, ToolState,
};
use crate::commissioning::{
    CommissioningIntent, DownloadMode, ImageLocation, ProgramSections, SparseDeviceImage, TargetSelection, UnloadMode,
};
use crate::configuration::ResolvedKeyMaterial;
use crate::configuration::{MaterializedDevice, ProcedureParameter, ProcedureParameterValue};

mod fixtures;
use fixtures::*;

mod application_identity;
mod controls;
mod operation_scope;
mod selection;
mod stamps;
mod unload;

mod catalogs;
use catalogs::*;

use crate::commissioning::procedure::operands::PropertyAddress;

mod profiles;

mod baseline_coverage;
mod baseline_deployment;
mod baseline_stamps;
mod installed_contract;
mod preparation_policy;
pub(in crate::commissioning) mod preparation_support;
mod sealing;
