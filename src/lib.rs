//! An implementation of the double ratchet algorithm.
//! 
//! Author -- daniel.bechaz@gmail.com  
//! Last Moddified --- 2019-05-04

#![deny(missing_docs,)]
#![feature(const_fn, maybe_uninit, trusted_len,)]

pub use digest::generic_array;
pub use digest::generic_array::typenum;

mod ratchet;
pub mod message;
mod client;

pub use self::{ratchet::*, client::*,};
