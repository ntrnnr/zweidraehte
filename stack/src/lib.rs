#![feature(slice_as_array)]
#![feature(const_trait_impl)]
#![feature(adt_const_params)]
#![feature(generic_const_exprs)]
#![feature(generic_arg_infer)]

#[macro_use]
mod macros;

pub mod address;
pub mod bcus;
pub mod buffers;
pub mod dpt;
pub mod error;
pub mod objects;
pub mod util;
