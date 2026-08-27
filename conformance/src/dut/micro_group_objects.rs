//! The vendor Group Objects and Management sample application for micro DUTs.
//!
//! GO1, GO2 and GO3 are deliberately ordinary communication objects. The
//! application mirrors GO0's RAM flags, live table configuration and value
//! into them before the stack handles a bus read, then applies accepted bus
//! writes after the stack returns.
//!
//! The Management association-table collection uses two further 1-bit inputs
//! and two status objects. The application copies an accepted input update to
//! its status object and requests a real group write. Nothing in the protocol
//! stack knows about the certification-only behavior or synthesises expected
//! telegrams.

use zweidraehte_microdevice::device::{Microdevice, PollInput, PollOutput};
use zweidraehte_microdevice::family::MicroDeviceFamily;
use zweidraehte_microdevice::security::SecurityModule;

/// Wire ASAPs used by the conformance application.
#[derive(Debug, Clone, Copy)]
pub struct MicroConformanceApplication {
    pub main: u8,
    pub communication_flags: u8,
    pub configuration_flags: u8,
    pub value: u8,
    pub association_inputs: [u8; 2],
    pub association_status: [u8; 2],
}

/// The wire numbering shared by the micro conformance fixtures.
#[rustfmt::skip]
pub const MICRO_CONFORMANCE_APPLICATION: MicroConformanceApplication = MicroConformanceApplication {
    main: 1,
    communication_flags: 2,
    configuration_flags: 3,
    value: 4,
    association_inputs: [8, 9],
    association_status: [10, 11],
};

impl MicroConformanceApplication {
    /// Poll the stack with the conformance application's behavior around it.
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

    /// Model a local stimulus before requesting an application group write.
    ///
    /// The Management template asks an operator to toggle its status objects,
    /// but our DUT process has no physical input. Its existing `TriggerWrite`
    /// side channel is that local stimulus. Other ASAPs retain the ordinary
    /// behavior used by the Group Objects template.
    pub fn trigger_write<F, const FRAME_CAP: usize, SEC>(
        self,
        device: &mut Microdevice<F, FRAME_CAP, SEC>,
        asap: u8,
        now_ms: u32,
    ) -> PollOutput<FRAME_CAP>
    where
        F: MicroDeviceFamily,
        SEC: SecurityModule,
    {
        if self.association_status.contains(&asap) {
            let mut value = [0];
            let length = device.read_value(asap, &mut value);

            assert_eq!(length, value.len(), "association status object holds one byte");

            value[0] ^= 1;
            device.write_value(asap, &value);
        }

        device.set_transmit_request(asap);

        self.poll(device, PollInput::Timer, now_ms)
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

        for (input, status) in self.association_inputs.into_iter().zip(self.association_status) {
            if device.object_flags(input) & zweidraehte_microdevice::co_flags::UPDATE == 0 {
                continue;
            }

            let mut value = [0];
            let length = device.read_value(input, &mut value);

            assert_eq!(length, value.len(), "association input object holds one byte");

            device.write_value(status, &value);
            device.set_transmit_request(status);

            device.clear_update_flag(input);
        }
    }
}
