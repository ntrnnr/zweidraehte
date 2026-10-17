use super::{
    ControlPath, ControlVariable, MemoryByteOrder, NormalizedProcedure, ProcedureOperation, ProcedureSourceId,
    ProcedureStep, RestartKind, ToolState,
};
use crate::commissioning::catalog::profile::ProcedureId;

#[test]
fn clipped_secret_property_writes_are_rejected_before_execution() {
    use super::{OperationData, OperationExtent, OperationTarget, WriteIntent};
    use crate::commissioning::compiler::secrets::SecretCommissioningPayload;
    use crate::commissioning::procedure::operands::PropertyAddress;

    let mut payload = SecretCommissioningPayload::default();
    let reference = payload.insert_for_test(vec![1, 2, 3].into());
    for (extent, clipped) in [
        (OperationExtent::property_window(3, 2).expect("clipped window"), true),
        (OperationExtent::property(3, 1), false),
    ] {
        let controls = procedure(vec![
            ProcedureOperation::Connect,
            ProcedureOperation::Write {
                target: OperationTarget::Property {
                    address: PropertyAddress::Indexed { object_index: 4, property_id: 78 },
                    start_element: 1,
                },
                data: OperationData::Secret(reference),
                extent,
                policy: WriteIntent::Property { verify: false },
            },
            ProcedureOperation::Disconnect,
        ]);
        if clipped {
            let error = controls.validate().expect_err("secret writes cannot use public padding readback");
            assert_eq!(error.message, "secret property writes require complete elements");
            assert_eq!(error.path.as_deref(), Some(&controls.steps[1].path));
        } else {
            controls.validate().expect("complete secret rows retain their ordinary geometry");
        }
    }
}

#[test]
fn tool_state_changes_are_ordered_and_typed() {
    let mut state = ToolState { memory_byte_order: MemoryByteOrder::LittleEndian, ..ToolState::default() };
    state.set(ControlVariable::EnableSegmentWrite, false);
    state.set(ControlVariable::EnableMemoryAutoVerify, true);

    assert!(!state.segment_write);
    assert_eq!(state.memory_byte_order, MemoryByteOrder::LittleEndian);
    assert_eq!(state.memory_auto_verify, Some(true));
}

#[test]
fn restart_and_master_reset_close_their_open_sessions() {
    for operation in [ProcedureOperation::Restart { kind: RestartKind::Confirmed }, ProcedureOperation::MasterReset {
        erase_code: 2,
        channel: 0,
    }] {
        let procedure = procedure(vec![ProcedureOperation::Connect, operation]);

        procedure.validate().expect("terminating service closes the open session");
    }
}

#[test]
fn terminating_services_require_an_open_session() {
    let restart = procedure(vec![ProcedureOperation::Restart { kind: RestartKind::Basic }]);
    let reset = procedure(vec![ProcedureOperation::MasterReset { erase_code: 2, channel: 0 }]);

    for (procedure, restart) in [(&restart, true), (&reset, false)] {
        let error = procedure.validate().expect_err("terminating service requires a connection");
        assert_eq!(error.kind, crate::commissioning::error::CompileErrorKind::InvalidInput);
        assert_eq!(
            error.message,
            if restart {
                "procedure restarts without an open connection"
            } else {
                "procedure performs a master reset without an open connection"
            }
        );
        assert_eq!(error.path.as_deref(), Some(&procedure.steps[0].path));
    }
}

fn procedure(operations: Vec<ProcedureOperation>) -> NormalizedProcedure {
    let id = ProcedureSourceId::MasterData(ProcedureId {
        procedure_type: "Load".to_owned(),
        subtype: Some("all".to_owned()),
        management_style: None,
        source_index: 0,
    });
    let steps = operations
        .into_iter()
        .enumerate()
        .map(|(index, operation)| ProcedureStep {
            path: ControlPath {
                mask_id: "MV-TEST".to_owned(),
                variant_index: 0,
                procedure: id.clone(),
                contribution: None,
                control_indices: vec![index],
            },
            source_control_code: Some(0xf0),
            sections: Default::default(),
            operation,
            on_error: Vec::new(),
            secure_only: false,
        })
        .collect();

    NormalizedProcedure { id, initial_state: ToolState::default(), steps, stamp_output: Default::default() }
}
