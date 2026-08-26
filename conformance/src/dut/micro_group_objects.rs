//! The vendor Group Objects template's sample application for micro DUTs.
//!
//! GO1, GO2 and GO3 are deliberately ordinary communication objects. The
//! application mirrors GO0's RAM flags, live table configuration and value
//! into them before the stack handles a bus read, then applies accepted bus
//! writes after the stack returns. Nothing in the protocol stack knows about
//! the certification-only group addresses or synthesises expected telegrams.

use zweidraehte_microdevice::device::{Microdevice, PollInput, PollOutput};
use zweidraehte_microdevice::family::MicroDeviceFamily;
use zweidraehte_microdevice::security::SecurityModule;

/// Wire ASAPs of the five-object sample application.
#[derive(Debug, Clone, Copy)]
pub struct GroupObjectSampleApplication {
    pub main: u8,
    pub communication_flags: u8,
    pub configuration_flags: u8,
    pub value: u8,
}

/// The wire numbering shared by the micro conformance fixtures.
#[rustfmt::skip]
pub const UINT1_SAMPLE_APPLICATION: GroupObjectSampleApplication = GroupObjectSampleApplication {
    main: 1,
    communication_flags: 2,
    configuration_flags: 3,
    value: 4,
};

impl GroupObjectSampleApplication {
    /// Poll the stack with the sample application's shadow behavior around it.
    pub fn poll<F, const FRAME_CAP: usize, SEC>(
        self,
        device: &mut Microdevice<F, FRAME_CAP, SEC>,
        input: PollInput<'_>,
        now_ms: u32,
    ) -> PollOutput<FRAME_CAP>
    where
        F: MicroDeviceFamily,
        SEC: SecurityModule,
    {
        self.prepare_reads(device);

        let output = device.poll(input, now_ms);

        self.apply_writes(device);

        output
    }

    fn prepare_reads<F, const FRAME_CAP: usize, SEC>(self, device: &mut Microdevice<F, FRAME_CAP, SEC>)
    where
        F: MicroDeviceFamily,
        SEC: SecurityModule,
    {
        let communication_flags = device.object_flags(self.main) & 0x0F;
        device.write_value(self.communication_flags, &[communication_flags]);

        if let Some(config) = device.object_config(self.main) {
            device.write_value(self.configuration_flags, &[config]);
        }

        let mut value = [0];
        if device.read_value(self.main, &mut value) == value.len() {
            device.write_value(self.value, &value);
        }
    }

    fn apply_writes<F, const FRAME_CAP: usize, SEC>(self, device: &mut Microdevice<F, FRAME_CAP, SEC>)
    where
        F: MicroDeviceFamily,
        SEC: SecurityModule,
    {
        let shadows = [self.communication_flags, self.configuration_flags, self.value];

        for shadow in shadows {
            if device.object_flags(shadow) & zweidraehte_microdevice::co_flags::UPDATE == 0 {
                continue;
            }

            let mut value = [0];
            if device.read_value(shadow, &mut value) != value.len() {
                device.clear_update_flag(shadow);
                continue;
            }

            if shadow == self.communication_flags {
                let _ = device.set_object_flags(self.main, value[0] & 0x0F);
            } else if shadow == self.configuration_flags {
                let _ = device.set_object_config(self.main, value[0]);
            } else {
                device.write_value(self.main, &value);
            }

            device.clear_update_flag(shadow);
        }
    }
}
