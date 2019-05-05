//! An implementation of the double ratchet algorithm.
//! 
//! Author -- daniel.bechaz@gmail.com  
//! Last Moddified --- 2019-05-05

#![deny(missing_docs,)]
#![feature(const_fn, maybe_uninit, trusted_len,)]

pub use ratchet;
pub use ratchet::{digest, typenum, generic_array,};

pub mod message;
mod client;

pub use self::client::*;
