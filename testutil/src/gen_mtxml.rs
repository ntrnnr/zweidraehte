//! Generate MTXML from Rust device definitions.
//!
//! This binary generates a complete ApplicationProgram MTXML file from
//! the demo device definitions.

use std::fs;

use const_default::ConstDefault;

use testutil::devices::{DEVICE_DESCRIPTOR, DemoParams, comm_objs};
use testutil::mtxml_gen::{ApplicationProgramConfig, MtxmlGenerator};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();

    // Get default parameter values as bytes
    let defaults = DemoParams::DEFAULT;
    let param_bytes = unsafe {
        core::slice::from_raw_parts(
            &defaults as *const DemoParams as *const u8,
            core::mem::size_of::<DemoParams>(),
        )
    };

    let config = ApplicationProgramConfig {
        name: "Demo Device",
        device: &DEVICE_DESCRIPTOR,
        params: DemoParams::ETS_PARAMS_EXT,
        param_defaults: param_bytes,
        comm_objects: &comm_objs::ETS_COMM_OBJECTS,
        union_fields: Some(DemoParams::ETS_UNIONS),
        channel_name: "General",
        absolute_segment_address: None, // System B uses relative segments
    };

    let xml = MtxmlGenerator::generate(&config)?;

    // Write to file
    let output_path = "generated_application.mtxml";
    fs::write(output_path, &xml)?;
    println!("Generated: {}", output_path);
    println!("\nPreview (first 2000 chars):\n{}", &xml[..xml.len().min(2000)]);

    Ok(())
}
