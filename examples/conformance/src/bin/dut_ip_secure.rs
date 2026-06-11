//! Conformance DUT child process — KNX IP Secure tunnelling interface.
//!
//! Unlike the TP1 DUTs there is no IPC/SHM channel: the device runs a
//! real KNX/IP stack on loopback sockets and the runner drives it as a
//! KNXnet/IP secure client over TCP. The harness spawns one DUT per
//! test (state isolation by process lifetime) and kills it afterwards.
//!
//! Environment:
//! - `KNX_IPS_PORT` — KNXnet/IP control endpoint port (default 3671)
//! - `KNX_TIME_DIVISOR` — compresses `timeoutAuthentication` /
//!   `timeoutSession` (conformance feature)
//!
//! Usage: `conformance-dut-ip-secure`

use embassy_executor::Spawner;
use embassy_time::{Duration, Timer};
use static_cell::StaticCell;

use zweidraehte_conformance::harness::ip_secure_stack::{
    IP_SECURE_SERIAL_NUMBER, IpSecureDutStack, LoopbackIpPlatform, default_dut_config, dut_control_endpoint,
};
use zweidraehte_device::bcus::system_b::{IpSecureResources, SystemBStackDefinition, SystemBStateInit};
use zweidraehte_device::layers::linklayers::knxip::KnxNetIpBuilder;
use zweidraehte_device::{Runner, StackResources, prelude::*};

// The FDSK doubles as the factory-default Device Authentication Code.
use zweidraehte_conformance::harness::ip_secure_stack::DUT_DEVICE_AUTH_CODE;

static STACK_RESOURCES: StaticCell<
    StackResources<
        IpSecureDutStack,
        { zweidraehte_device::config::buffer_size_for_apdu(<IpSecureDutStack as StackDefinition>::MAX_APDU_LENGTH) },
    >,
> = StaticCell::new();

#[embassy_executor::task]
async fn run_stack(runner: Runner<'static, IpSecureDutStack>) {
    runner.run().await;
}

#[embassy_executor::main]
async fn main(spawner: Spawner) {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    let control_endpoint = dut_control_endpoint();
    log::info!("IP Secure DUT starting on {}", control_endpoint);

    let state_init = SystemBStateInit {
        identity: StaticIdentity::new(IP_SECURE_SERIAL_NUMBER),
        loaded_config: Some(default_dut_config()),
        resources: IpSecureResources { fdsk: DUT_DEVICE_AUTH_CODE },
    };

    let link_layer_builder =
        KnxNetIpBuilder::<IpSecureDutStack>::new("lo", *control_endpoint.ip(), control_endpoint, ());

    let (_stack, runner) = zweidraehte_device::new(
        STACK_RESOURCES.init(StackResources::new()),
        link_layer_builder,
        state_init,
        LoopbackIpPlatform,
        IpSecureDutStack::memory_map(),
    );

    spawner.spawn(run_stack(runner)).expect("spawn stack runner");

    loop {
        Timer::after(Duration::from_secs(3600)).await;
    }
}
