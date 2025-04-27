use const_default::ConstDefault;

use crate::{
    address::IndividualAddress as KNXIndividualAddress,
    objects::{
        comm::ComObjects,
        tables::{addr7::AddrTab7, app::Application, asso6::AssoTab6, co7::CoTab7},
    },
};

#[derive(Debug)]
pub struct StackResources<P: ConstDefault, R: ComObjects> {
    pub ind_addr: KNXIndividualAddress,
    pub adt: AddrTab7<30>,
    pub ast: AssoTab6<30>,
    pub cot: CoTab7<30>,
    pub app: Application<P>,
    pub ram: R,
}

impl<P: ConstDefault, R: ComObjects> StackResources<P, R> {
    pub fn new() -> Self {
        Self {
            ind_addr: KNXIndividualAddress::new(15, 15, 255),
            adt: AddrTab7::new(),
            ast: AssoTab6::new(),
            cot: CoTab7::new(),
            app: Application::new(),
            ram: R::new(),
        }
    }
}

// #[cfg(test)]
// mod tests {
//     use super::StackResources;
//     use const_default::ConstDefault;

//     #[derive(Debug, ConstDefault)]
//     pub struct AppParameter {
//         delay_time: u16,
//     }

//     use crate::dpt::DPT_Switch;
//     use crate::objects::comm::*;

//     use embassy_sync::blocking_mutex::raw::NoopRawMutex;
//     use embassy_sync::mutex::Mutex;

//     crate::define_com_objects! {
//         pub struct AppComObjects {
//             0 => pub co_in0: DPT_Switch = DPT_Switch::from(false),
//             1 => pub co_in1: DPT_Switch = DPT_Switch::from(false),
//             2 => pub co_in2: DPT_Switch = DPT_Switch::from(false),
//             3 => pub co_in3: DPT_Switch = DPT_Switch::from(false),
//             4 => pub co_out0: DPT_Switch = DPT_Switch::from(false),
//             5 => pub co_out1: DPT_Switch = DPT_Switch::from(false),
//             6 => pub co_out2: DPT_Switch = DPT_Switch::from(false),
//             7 => pub co_out3: DPT_Switch = DPT_Switch::from(false),
//         }
//     }

//     #[test]
//     fn test_dev() {
//         //let stack_resources =
//         //    mk_static!(StackResources<AppParameter, AppComObjects>, StackResources::new());
//     }
// }
