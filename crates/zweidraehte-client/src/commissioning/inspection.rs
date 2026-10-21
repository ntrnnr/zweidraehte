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
    IndexedPropertyDataTypeSeed, LoadControlCause, LoadEffect, LoadMachineTarget, LoadRecord, MemoryByteOrder,
    MemoryTransfer, NormalizedProcedure, NumericEncoding, NumericRange, NumericSignExtension, OperationData,
    OperationExtent, OperationTarget, ProcedureOperation, ProcedureSourceId, ProcedureStep, PropertyDataTypeLookup,
    RestartKind, ServiceRead, StampDescriptor, ToolState, WriteIntent, WritePolicy,
};
