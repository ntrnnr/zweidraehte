//! Translate authored project overrides into the ETS runtime's settings.
//!
//! The project adapter owns this boundary so editors and commissioning apply
//! the same overrides without teaching the ETS model about project syntax.

use zweidraehte_ets_files::runtime::configuration::{
    ObjectFlagOverrides as ProductFlagOverrides, ObjectSetting, ParameterSetting, ProductConfiguration,
};
use zweidraehte_ets_files::runtime::model::ParameterValue;
use zweidraehte_project::{ObjectFlagOverrides, ObjectPriority, ParamValue, ProjectDevice};
use zweidraehte_proto::messages::knx::Priority;

/// Copy a device's authored parameter and object overrides into product settings.
///
/// These settings retain inheritance (`None`) and explicit disabling (`Some(false)`).
/// Group memberships, topology and security remain project-level concerns.
pub fn product_configuration(device: &ProjectDevice) -> ProductConfiguration {
    ProductConfiguration {
        parameters: device
            .parameters
            .iter()
            .map(|parameter| ParameterSetting {
                id: parameter.id.clone(),
                value: match &parameter.value {
                    ParamValue::Integer(value) => ParameterValue::Integer(*value),
                    ParamValue::Float(value) => ParameterValue::Float(*value),
                    ParamValue::Text(value) => ParameterValue::Text(value.clone()),
                },
            })
            .collect(),
        objects: device
            .objects
            .values()
            .map(|object| ObjectSetting { com_object: object.com_object, flags: product_object_flags(object.flags) })
            .collect(),
    }
}

/// Translate object overrides without resolving inherited product/ref defaults.
pub fn product_object_flags(flags: ObjectFlagOverrides) -> ProductFlagOverrides {
    ProductFlagOverrides {
        read: flags.read,
        write: flags.write,
        communication: flags.communication,
        transmit: flags.transmit,
        update: flags.update,
        read_on_init: flags.read_on_init,
        priority: flags.priority.map(|priority| match priority {
            ObjectPriority::Low => Priority::Low,
            ObjectPriority::High => Priority::High,
            ObjectPriority::Alarm => Priority::Alarm,
            ObjectPriority::System => Priority::System,
        }),
    }
}
