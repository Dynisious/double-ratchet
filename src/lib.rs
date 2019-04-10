//! An implementation of the double ratchet algorithm.
//! 
//! Author -- daniel.bechaz@gmail.com  
//! Last Moddified --- 2019-04-10

#![deny(missing_docs,)]

#[macro_use]
extern crate maybe;

mod ratchet;
pub mod message;

pub use self::ratchet::*;
