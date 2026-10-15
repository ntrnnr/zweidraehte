//! Preflight is the maximum of prepared operands, using runtime service sizing.
use super::*;
use crate::commissioning::procedure::{
    ControlVariable, FunctionPropertyOperation, NormalizedProcedure, ProcedureOperation,
};

pub fn required_plaintext_apdu(
    procedure: &NormalizedProcedure,
    verify_mode: bool,
) -> Result<Option<u16>, CompileError> {
    let mut required = 0;
    let mut transfer = |target: &OperationTarget, extent: OperationExtent, write: bool| -> Result<(), CompileError> {
        required = required.max(target.minimum_apdu(extent)?);
        if verify_mode
            && write
            && matches!(target,OperationTarget::Memory {service,..} if *service!=MemoryService::Extended)
        {
            required = required.max(6);
        }
        Ok(())
    };
    for step in &procedure.steps {
        match &step.operation {
            ProcedureOperation::ReadIntoImage { target, extent, .. }
            | ProcedureOperation::LoadImage { target, extent, .. }
            | ProcedureOperation::Compare { target, extent, .. } => transfer(target, *extent, false)?,
            ProcedureOperation::Write { target, extent, .. } => transfer(target, *extent, true)?,
            // Its element width is known only when the control executes; the
            // transfer then checks that one element fits the negotiated APDU.
            ProcedureOperation::DescribedProperty(_) => {}
            // The record write's own size, including the indexed fallback of
            // a property record, is counted by `LoadRecord::minimum_apdu`
            // below. Only a memory record adds the verify-mode requirement.
            ProcedureOperation::LoadRecord(record) => {
                if matches!(record.write.target, OperationTarget::Memory { .. }) {
                    transfer(&record.write.target, record.write.extent, true)?;
                }
                if let Some((read, _)) = &record.poll {
                    transfer(&read.target, read.extent, false)?;
                }
            }
            ProcedureOperation::AbsoluteSegment { record, transfers } => {
                if matches!(record.write.target, OperationTarget::Memory { .. }) {
                    transfer(&record.write.target, record.write.extent, true)?;
                }
                if let Some((read, _)) = &record.poll {
                    transfer(&read.target, read.extent, false)?;
                }
                for write in transfers {
                    transfer(&write.target, write.extent, true)?;
                }
            }
            _ => {}
        }
    }
    for step in &procedure.steps {
        let size =
            match &step.operation {
                ProcedureOperation::Connect if verify_mode && procedure.initial_state.memory_auto_verify.is_some() => 6,
                ProcedureOperation::LoadRecord(record) | ProcedureOperation::AbsoluteSegment { record, .. } => {
                    record.minimum_apdu()?
                }
                ProcedureOperation::Restart { kind: crate::commissioning::procedure::RestartKind::Basic } => 1,
                ProcedureOperation::Restart { .. } | ProcedureOperation::MasterReset { .. } => 6,
                ProcedureOperation::SetControlVariable {
                    variable: ControlVariable::EnableMemoryAutoVerify, ..
                } if verify_mode => 6,
                ProcedureOperation::FunctionProperty(operation) => {
                    let (address, request) = match operation {
                        FunctionPropertyOperation::Invoke { address, data, .. } => (*address, data.len()),
                        FunctionPropertyOperation::ReadResult { address } => (*address, 0),
                    };
                    function_apdu(address, request)?
                }
                ProcedureOperation::ClearLineCouplerFilter { address: Some(address) } => function_apdu(*address, 2)?,
                ProcedureOperation::ClearLineCouplerFilter { address: None } => 4,
                _ => 0,
            };
        required = required.max(size);
    }
    Ok((required != 0).then_some(required))
}
fn function_apdu(address: PropertyAddress, request: usize) -> Result<u16, CompileError> {
    let overhead = match address {
        PropertyAddress::Indexed { .. } => 3,
        PropertyAddress::Extended { .. } => 6,
    };
    u16::try_from(overhead + request.max(1)).map_err(|_| required_apdu_error("function payload exceeds APDU length"))
}
