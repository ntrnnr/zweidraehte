//! Wrapper access must preserve both the concrete provider and live state.
#![cfg(feature = "knxip")]

use core::{convert::Infallible, net::Ipv4Addr};

use zweidraehte_device::bcus::system_b::{ExtensionState, IpExtensionState, IpInterfaceExtension};
use zweidraehte_device::security::{SecureExtensionState, SecureResources};
use zweidraehte_device::{HasIpExtensionState, HasIpSecureView, IpStateView};

// The equality bound proves that wrapping the IP extension in Data Secure
// preserves its capabilities in the type, not just its observable methods.
fn configured_ip<E: HasIpExtensionState<IpState = IpExtensionState<0>>>(extension: &E) -> &IpExtensionState<0> {
    extension.ip_state()
}

#[test]
fn data_secure_wrapper_keeps_live_ip_state_and_typed_ip_secure_absence() {
    type Extension = SecureExtensionState<IpInterfaceExtension<2, 0>, 4, 4, 4>;
    let extension = Extension::from_config(Default::default(), SecureResources::simple([0x11; 16]));
    let ip = configured_ip(&extension);

    // Data Secure does not imply IP Secure. Absence survives the wrapper and
    // needs neither fabricated secrets nor an unused channel.
    let absent: Option<&Infallible> = extension.ip_secure_view();
    assert!(absent.is_none());

    extension.inner.ip.set_configured_ip_address(Ipv4Addr::new(192, 168, 1, 42));
    assert_eq!(ip.configured_ip_address(), Ipv4Addr::new(192, 168, 1, 42));
    ip.set_friendly_name(b"Living room interface");
    assert_eq!(&extension.inner.ip.friendly_name()[..21], b"Living room interface");
}

#[cfg(feature = "ip-secure")]
#[test]
fn nested_secure_wrapper_keeps_live_secrets_through_factory_reset() {
    use zweidraehte_device::IpSecureStateView;
    use zweidraehte_device::bcus::system_b::{IpSecureExtensionState, IpSecureInterfaceExtension, IpSecureResources};
    use zweidraehte_device::restart::EraseCode;
    use zweidraehte_proto::messages::knxip::substructs::ServiceFamily;

    type Extension = SecureExtensionState<IpSecureInterfaceExtension<2, 0, 3, 2>, 4, 4, 4>;
    let mut config = <Extension as ExtensionState>::Config::default();
    config.inner.1.backbone_key = [0x22; 16];
    config.inner.1.secured_routing = 1;
    let extension = Extension::from_config(config, SecureResources {
        inner: IpSecureResources { fdsk: [0x33; 16] },
        fdsk: [0x11; 16],
    });

    let _ip = configured_ip(&extension);
    let view: &IpSecureExtensionState<3, 2> = extension.ip_secure_view().expect("extension carries IP Secure");
    assert_eq!(view.backbone_key(), [0x22; 16]);
    assert_eq!(view.secured_service_family(ServiceFamily::Routing), 1);
    extension.inner.ip_secure.set_persisted_mc_timer(1234);
    assert_eq!(view.persisted_mc_timer(), 1234);

    // Retain the same borrow across reset: accessors must expose the live
    // backing storage even when its key and service policy change.
    extension.on_erase(EraseCode::FactoryReset);
    assert_eq!(view.backbone_key(), [0; 16]);
    assert_eq!(view.device_authentication_code(), [0x33; 16]);
    assert_eq!(view.secured_service_family(ServiceFamily::Routing), 0);
    assert_eq!(view.persisted_mc_timer(), 0);
}
