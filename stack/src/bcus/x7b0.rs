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
