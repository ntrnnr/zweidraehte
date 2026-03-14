#![cfg_attr(not(any(test, feature = "knxprod")), no_std)]
#![feature(adt_const_params)]

pub mod ip_interface;
pub mod light_switch;
