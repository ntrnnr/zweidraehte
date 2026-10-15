//! Read-only compiler vocabulary for diagnostics, conformance and compatibility tools.
//!
//! These types describe compiled programs. Constructing or modifying a procedure
//! does not grant access to execution; only a live-bound PreparedProgram can run.

pub use super::procedure::operands::{
    MemoryAddress, MemoryService, PointerEncoding, PropertyAddress, StandardMemoryService, pure_property_address,
    required_plaintext_apdu,
};
pub use super::procedure::{
    CachePolicy, Comparison, ComparisonPadding, ControlPath, ControlVariable, DescribedPropertyAction,
    DescribedPropertyOperation, DownloadStampOutput, ErrorAction, ErrorHandler, FunctionPropertyOperation,
    LoadControlCause, LoadEffect, LoadMachineTarget, LoadRecord, MemoryByteOrder, MemoryTransfer, NormalizedProcedure,
    OperationData, OperationExtent, OperationTarget, ProcedureOperation, ProcedureSourceId, ProcedureStep, RangeBound,
    RestartKind, ServiceRead, StampDescriptor, ToolState, WriteIntent, WritePolicy,
};

/// An offline compilation with the exact payload bytes needed to inspect writes.
///
/// The ordinary compiled program still omits these bytes. Use this result when
/// recording a complete operation sequence, including key-bearing writes.
#[derive(Debug)]
pub struct CompiledInspection {
    plan: super::CompiledProgram,
    payloads: super::compiler::secrets::SecretCommissioningPayload,
}

impl CompiledInspection {
    pub(in crate::commissioning) fn new(output: super::compiler::CompilationOutput) -> Self {
        Self { plan: output.program, payloads: output.secret_payload }
    }

    /// Return the public plan compiled alongside these payloads.
    pub fn plan(&self) -> &super::CompiledProgram {
        &self.plan
    }

    /// Resolve a write's payload reference from this compilation.
    /// References from another compilation return an error.
    pub fn payload_bytes(
        &self,
        reference: super::SecretPayloadReference,
    ) -> Result<&[u8], super::error::SecretPayloadError> {
        self.payloads.resolve(reference)
    }
}
