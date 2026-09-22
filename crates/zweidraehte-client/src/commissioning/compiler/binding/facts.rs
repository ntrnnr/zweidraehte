//! Initial interpreter state from authored product options.

use crate::commissioning::error::CompileError;
use crate::commissioning::procedure::{MemoryByteOrder, ToolState};
use zweidraehte_ets_files::product::{ParameterByteOrder, ProductData};

pub(crate) fn initial_tool_state(product: &ProductData) -> Result<ToolState, CompileError> {
    let options = product.programming_options();

    // The load-control context's memory-data byte order is the effective
    // MTXML `Options/@ParameterByteOrder`; an absent option takes the schema's
    // BigEndian default. This affects how later controls interpret image data,
    // so it must be fixed before the ordered control stream is lowered.
    let memory_byte_order = match options.parameter_byte_order().value {
        ParameterByteOrder::BigEndian => MemoryByteOrder::BigEndian,
        ParameterByteOrder::LittleEndian => MemoryByteOrder::LittleEndian,
        ParameterByteOrder::Unknown(value) => {
            return Err(CompileError::invalid(format!("unknown parameter byte order {value:?}")));
        }
    };

    Ok(ToolState {
        segment_write: true,
        verify_direct_writes: false,
        optimistic_writes: !options.legacy_no_optimistic_write().value,
        memory_auto_verify: options.legacy_no_memory_verify_mode().value.then_some(false),
        memory_byte_order,
    })
}
