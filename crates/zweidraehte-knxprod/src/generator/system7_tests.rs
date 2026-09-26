//! System 7 task addresses must follow the declared product layout.

use super::*;
use crate::generator::System7Segment;

fn layout() -> System7MemoryLayout {
    System7MemoryLayout {
        segments: [("4000", 0x4000), ("4100", 0x4100), ("4200", 0x4200)]
            .into_iter()
            .map(|(name, address)| System7Segment {
                name,
                address,
                size: 64,
                memory_type: Some("EEPROM"),
                data: None,
                mask: None,
            })
            .collect(),
        address_table_segment: "4000",
        association_table_segment: "4100",
        address_table_offset: 0,
        association_table_offset: 0,
        address_table_max_entries: 8,
        association_table_max_entries: 8,
        serial_number: [0; 6],
    }
}

#[test]
fn task_segment_uses_declared_cot_address_for_both_memory_annotations() {
    for memory_type in [None, Some("EEPROM")] {
        let mut layout = layout();
        layout.segments[2].memory_type = memory_type;

        let procedures = MtxmlGenerator::build_system_7_load_procedures(&layout).expect("valid COT segment");
        let tasks: Vec<_> = procedures.procedures[0]
            .controls
            .iter()
            .filter_map(|control| match control {
                LoadControl::LdCtrlTaskSegment(task) => Some((task.lsm_idx, task.address)),
                _ => None,
            })
            .collect();

        assert_eq!(tasks, [(1, 0x4000), (2, 0x4100), (3, 0x4200)]);
    }
}

#[test]
fn missing_cot_segment_is_rejected() {
    let mut layout = layout();
    layout.segments.pop();

    assert!(matches!(
        MtxmlGenerator::build_system_7_load_procedures(&layout),
        Err(GeneratorError::MissingSystem7ComObjectTableSegment)
    ));
}

#[test]
fn ram_or_address_table_cannot_substitute_for_cot() {
    for (name, memory_type) in [("4200", Some("RAM")), ("4000", None), ("4100", None)] {
        let mut layout = layout();
        layout.segments[2].name = name;
        layout.segments[2].memory_type = memory_type;

        assert!(matches!(
            MtxmlGenerator::build_system_7_load_procedures(&layout),
            Err(GeneratorError::MissingSystem7ComObjectTableSegment)
        ));
    }
}
