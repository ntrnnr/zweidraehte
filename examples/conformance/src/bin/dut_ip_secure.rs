//! Conformance DUT child process — KNX IP Secure tunnelling interface.
//!
//! Unlike the TP1 DUTs there is no IPC/SHM channel: the device runs a
//! real KNX/IP stack on loopback sockets and the runner drives it as a
//! KNXnet/IP secure client over TCP. The harness spawns one DUT per
//! test (state isolation by process lifetime) and kills it afterwards.
//!
//! Environment:
//! - `KNX_IPS_PORT` — KNXnet/IP control endpoint port (default 3671)
//! - `KNX_IPS_MCAST` — routing multicast group (default 224.0.23.12;
//!   the harness derives a per-spawn 239.250.x.y group)
//! - `KNX_IPS_SECURE_ROUTING` — `1` secures the Routing family and
//!   provisions the Appendix A backbone key (secure-routing tests)
//! - `KNX_TIME_DIVISOR` — compresses `timeoutAuthentication` /
//!   `timeoutSession` and the timer-sync notify windows (conformance
//!   feature)
//!
//! Usage: `conformance-dut-ip-secure`

use embassy_executor::Spawner;
use static_cell::StaticCell;

use zweidraehte_conformance::harness::ip_secure_stack::{
    IP_SECURE_SERIAL_NUMBER, IpSecureDutStack, LoopbackIpPlatform, apply_secure_routing_config, default_dut_config,
    dut_control_endpoint, dut_multicast_group, secure_routing_enabled,
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
    let multicast_group = dut_multicast_group();
    log::info!("IP Secure DUT starting on {} (routing group {})", control_endpoint, multicast_group);

    let mut config = default_dut_config();
    if secure_routing_enabled() {
        apply_secure_routing_config(&mut config, multicast_group);
    }

    let state_init = SystemBStateInit {
        identity: StaticIdentity::new(IP_SECURE_SERIAL_NUMBER),
        loaded_config: Some(config),
        resources: IpSecureResources { fdsk: DUT_DEVICE_AUTH_CODE },
    };

    let link_layer_builder =
        KnxNetIpBuilder::<IpSecureDutStack>::new("lo", *control_endpoint.ip(), control_endpoint, ())
            .routing_multicast_addr(multicast_group);

    let (_stack, runner) = zweidraehte_device::new(
        STACK_RESOURCES.init(StackResources::new()),
        link_layer_builder,
        state_init,
        LoopbackIpPlatform,
        IpSecureDutStack::memory_map(),
        (),
    );

    spawner.spawn(run_stack(runner)).expect("spawn stack runner");

    // The DUT keeps no persistent storage (`Storage = ()`): the IP Secure
    // mc_timer watermark reads 0 and its writes vanish through the `()`
    // storage hooks — safe here, because process-per-test isolation means
    // no timer state survives to be replayed. The advisory persist channel
    // needs no draining; an unread notification is simply dropped.
    core::future::pending::<()>().await;
    unreachable!("pending() never resolves");
}
