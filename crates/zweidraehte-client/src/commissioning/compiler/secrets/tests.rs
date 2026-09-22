use super::*;
use crate::commissioning::procedure::operands::{MemoryAddress, MemoryService};
use crate::commissioning::procedure::{
    OperationData, OperationExtent, OperationTarget, ProcedureOperation, WriteIntent, WritePolicy,
};
use crate::commissioning::test_support::preflight::procedure;

#[test]
fn secret_references_cannot_select_another_compilation_payload() {
    let mut earlier = SecretCommissioningPayload::default();
    let stale = earlier
        .insert_with_transitions([0x23; 16].into(), vec![CredentialTransition::ToolKey])
        .expect("first secret fits");
    let mut current = SecretCommissioningPayload::default();
    let current_reference = current.insert([0x57; 16].into()).expect("current secret fits");

    // Structural previews remain repeatable, but equal lengths do not
    // establish that a reference belongs to this private compilation.
    assert_eq!(format!("{stale:?}"), format!("{current_reference:?}"));
    assert_ne!(stale, current_reference);
    assert!(matches!(current.resolve(stale), Err(SecretPayloadError::MissingSecretPayload(_))));
    assert!(matches!(current.transitions(stale), Err(SecretPayloadError::MissingSecretPayload(_))));
    assert_eq!(current.resolve(current_reference).expect("own reference resolves"), [0x57; 16]);
}

#[test]
fn cloned_payloads_preserve_existing_references_without_aliasing_new_entries() {
    let mut original = SecretCommissioningPayload::default();
    let retained = original.insert([0x23; 16].into()).expect("first secret fits");
    let mut cloned = original.clone();
    let original_next = original.insert([0x45; 16].into()).expect("next secret fits");
    let cloned_next = cloned.insert([0x67; 16].into()).expect("cloned secret fits");

    assert_eq!(cloned.resolve(retained).expect("cloned reference resolves"), [0x23; 16]);
    assert!(original.resolve(cloned_next).is_err());
    assert!(cloned.resolve(original_next).is_err());
    assert_eq!(cloned.resolve(cloned_next).expect("own new reference resolves"), [0x67; 16]);
}

#[test]
fn secret_payload_debug_never_contains_key_material() {
    let key = [0xA7; 16];
    let mut payload = SecretCommissioningPayload::default();
    let reference = payload.insert(key.into()).expect("secret fits");

    let debug = format!("{payload:?} {reference:?}");

    assert!(!debug.contains("a7"));
    assert!(!debug.contains("A7"));
    assert!(!debug.contains("167"));
    assert_eq!(payload.resolve(reference).expect("payload resolves"), key);
}

#[test]
fn private_payload_bindings_are_complete_before_any_wire_operation() {
    use crate::commissioning::compiler::secrets::{SecretCommissioningPayload, validate_secret_bindings};
    use crate::commissioning::error::CompileErrorKind;
    use zweidraehte_util::secret::SecretBytes;
    let mut payload = SecretCommissioningPayload::default();
    let reference = payload.insert_for_test(SecretBytes::new(vec![0xa7; 18]));
    let mut procedure = procedure(vec![
        ProcedureOperation::Connect,
        ProcedureOperation::Write {
            target: OperationTarget::Memory { service: MemoryService::Classic, address: MemoryAddress::Fixed(0x1200) },
            data: OperationData::Secret(reference),
            extent: OperationExtent::bytes(18),
            policy: WriteIntent::Explicit(WritePolicy::NoVerification),
        },
        ProcedureOperation::Disconnect,
    ]);
    let error = validate_secret_bindings(&procedure, None).expect_err("public plan has no private bytes");
    assert_eq!(error.kind, CompileErrorKind::InvalidInput);
    assert_eq!(error.path.expect("control attribution").control_indices, vec![1]);
    validate_secret_bindings(&procedure, Some(&payload)).expect("prepared payload matches");
    let ProcedureOperation::Write { extent, .. } = &mut procedure.steps[1].operation else {
        unreachable!("write fixture")
    };
    extent.byte_length = 17;
    assert_eq!(
        validate_secret_bindings(&procedure, Some(&payload)).expect_err("extent mismatch").kind,
        CompileErrorKind::InvalidInput
    );
}
