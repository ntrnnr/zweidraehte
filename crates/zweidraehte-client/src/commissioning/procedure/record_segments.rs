//! Adapt complete compiler-owned load records to the protocol body codecs.
//!
//! Placement changes typed fields. This boundary alone handles the additional
//! event/machine header and the memory form's single-segment ID.

use super::{LoadRecord, OperationTarget};
use crate::commissioning::error::CompileError;
use zweidraehte_proto::messages::apdu::load_control::{
    AbsSegment, LoadControlRecord, LoadEvent, LoadSegment, LsmMachine, MemLoadControlRecord, TaskSegment,
};

const SINGLE_SEGMENT_ID: u8 = 0;

enum SegmentEncoding {
    Property,
    Memory(LsmMachine),
}

impl SegmentEncoding {
    fn decode(record: &LoadRecord) -> Option<(Self, [u8; AbsSegment::RECORD_LEN])> {
        match &record.write.target {
            OperationTarget::Property { .. } => {
                let (&event, body) = record.bytes.split_first()?;
                if LoadEvent::from(event) != LoadEvent::AdditionalLoadControls {
                    return None;
                }
                Some((Self::Property, body.try_into().ok()?))
            }
            OperationTarget::Memory { .. } => {
                if record.bytes.len() != MemLoadControlRecord::RECORD_LEN {
                    return None;
                }
                let [tag, segment_type, segment_id, payload @ ..] = record.bytes.as_slice() else { return None };
                let (machine, event) = MemLoadControlRecord::split_tag(*tag);
                if event != LoadEvent::AdditionalLoadControls || *segment_id != SINGLE_SEGMENT_ID {
                    return None;
                }
                let mut body = [0; AbsSegment::RECORD_LEN];
                let (body_type, body_payload) = body.split_first_mut()?;
                *body_type = *segment_type;
                body_payload.copy_from_slice(payload);
                Some((Self::Memory(LsmMachine::try_from(machine).ok()?), body))
            }
            _ => None,
        }
    }
}

impl LoadRecord {
    pub(in crate::commissioning) fn task_segment(&self) -> Option<TaskSegment> {
        let (_, body) = SegmentEncoding::decode(self)?;
        TaskSegment::parse(&body)
    }

    pub(in crate::commissioning) fn set_task_segment(&mut self, segment: TaskSegment) -> Result<(), CompileError> {
        let (encoding, _) = SegmentEncoding::decode(self)
            .ok_or_else(|| CompileError::invalid("task segment has invalid load-record framing"))?;
        self.bytes = match encoding {
            SegmentEncoding::Property => {
                LoadControlRecord::task_segment(segment.start_address, segment.pei_type, segment.application_id)
                    .to_vec()
            }
            SegmentEncoding::Memory(machine) => MemLoadControlRecord::task_segment(
                machine,
                segment.start_address,
                segment.pei_type,
                segment.application_id,
            )
            .to_vec(),
        };
        Ok(())
    }

    pub(in crate::commissioning) fn absolute_segment(&self) -> Option<AbsSegment> {
        let (_, body) = SegmentEncoding::decode(self)?;
        let segment = AbsSegment::parse(&body)?;
        // The protocol parser deliberately accepts truncated device input and
        // unknown selectors. Compiler allocations must instead be complete and
        // canonical, so re-encoding cannot silently discard reserved data.
        (matches!(segment.segment_type, LoadSegment::AbsoluteData | LoadSegment::AbsoluteStack)
            && segment.write() == body)
            .then_some(segment)
    }

    pub(in crate::commissioning) fn set_absolute_segment(&mut self, segment: AbsSegment) -> Result<(), CompileError> {
        let (encoding, _) = SegmentEncoding::decode(self)
            .ok_or_else(|| CompileError::invalid("absolute segment has invalid load-record framing"))?;
        self.bytes = match encoding {
            SegmentEncoding::Property => LoadControlRecord::abs_segment(&segment).to_vec(),
            SegmentEncoding::Memory(machine) => MemLoadControlRecord::abs_segment(machine, &segment).to_vec(),
        };
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commissioning::compiler::binding::procedure::test_support::compile_fixture;
    use crate::commissioning::procedure::ProcedureOperation;
    use crate::commissioning::procedure::operands::{MemoryAddress, MemoryService};
    use zweidraehte_ets_files::schema::{LdCtrlTaskSegment, LoadControl, LoadProcedure};

    fn task_record(memory: bool) -> LoadRecord {
        let procedure = compile_fixture(
            LoadProcedure {
                merge_id: None,
                controls: vec![LoadControl::LdCtrlTaskSegment(LdCtrlTaskSegment {
                    lsm_idx: Some(2),
                    address: 0x4100,
                    ..Default::default()
                })],
            },
            Vec::new(),
        )
        .expect("task fixture compiles");
        let ProcedureOperation::LoadRecord(mut record) =
            procedure.steps.into_iter().next().expect("one step").operation
        else {
            panic!("task record")
        };
        if memory {
            record.write.target =
                OperationTarget::Memory { service: MemoryService::Classic, address: MemoryAddress::Fixed(0x104) };
            record.bytes =
                MemLoadControlRecord::task_segment(LsmMachine::AssociationTable, 0x4100, 7, [1, 2, 3, 4, 5]).to_vec();
        } else {
            record.bytes = LoadControlRecord::task_segment(0x4100, 7, [1, 2, 3, 4, 5]).to_vec();
        }
        record
    }

    #[test]
    fn segment_codecs_preserve_both_endpoints_and_all_payload_fields() {
        for memory in [false, true] {
            let mut record = task_record(memory);
            let before = record.clone();
            let mut task = record.task_segment().expect("task decodes");
            assert_eq!(task, TaskSegment { start_address: 0x4100, pei_type: 7, application_id: [1, 2, 3, 4, 5] });
            record.set_task_segment(task).expect("task encodes");
            assert_eq!(record, before);
            task.start_address = 0x4009;
            record.set_task_segment(task).expect("task relocates");
            assert_eq!(record.task_segment(), Some(task));

            for segment_type in [LoadSegment::AbsoluteData, LoadSegment::AbsoluteStack] {
                let mut segment = AbsSegment {
                    segment_type,
                    start_address: 0x4100,
                    length: 31,
                    access_attributes: 0xf2,
                    memory_type: 3,
                    memory_attributes: 0x80,
                };
                record.bytes = if memory {
                    MemLoadControlRecord::abs_segment(LsmMachine::AssociationTable, &segment).to_vec()
                } else {
                    LoadControlRecord::abs_segment(&segment).to_vec()
                };
                let before = record.clone();
                assert_eq!(record.absolute_segment(), Some(segment));
                assert_eq!(record.task_segment(), None);
                record.set_absolute_segment(segment).expect("allocation encodes");
                assert_eq!(record, before);
                segment.start_address = 0x4009;
                segment.length = 277;
                record.set_absolute_segment(segment).expect("allocation relocates");
                assert_eq!(record.absolute_segment(), Some(segment));
                let expected = if memory {
                    MemLoadControlRecord::abs_segment(LsmMachine::AssociationTable, &segment).to_vec()
                } else {
                    LoadControlRecord::abs_segment(&segment).to_vec()
                };
                assert_eq!(record.bytes, expected);
            }
        }
    }

    #[test]
    fn compiler_records_require_complete_correct_endpoint_framing() {
        for memory in [false, true] {
            let record = task_record(memory);
            for length in 0..record.bytes.len() {
                let mut truncated = record.clone();
                truncated.bytes.truncate(length);
                assert!(truncated.task_segment().is_none());
                assert!(truncated.absolute_segment().is_none());
            }
            let mut extended = record.clone();
            extended.bytes.push(0);
            assert!(extended.task_segment().is_none());
            let mut other_event = record.clone();
            other_event.bytes = if memory {
                MemLoadControlRecord::event(LsmMachine::AssociationTable, LoadEvent::Unload).to_vec()
            } else {
                LoadControlRecord::event(LoadEvent::Unload).to_vec()
            };
            assert!(other_event.task_segment().is_none());
            assert!(other_event.absolute_segment().is_none());
        }
        let mut record = task_record(true);
        let [_, _, segment_id, ..] = record.bytes.as_mut_slice() else { panic!("memory framing") };
        *segment_id = SINGLE_SEGMENT_ID + 1;
        assert!(record.task_segment().is_none());

        let mut wrong_endpoint = task_record(false);
        wrong_endpoint.bytes = task_record(true).bytes;
        assert!(wrong_endpoint.task_segment().is_none());
    }
}
