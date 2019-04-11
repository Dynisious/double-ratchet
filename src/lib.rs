//! An implementation of the double ratchet algorithm.
//! 
//! Author -- daniel.bechaz@gmail.com  
//! Last Moddified --- 2019-04-11

#![deny(missing_docs,)]

#[macro_use]
extern crate maybe;

mod ratchet;
pub mod message;
mod client;

pub use self::{ratchet::*, client::*,};
