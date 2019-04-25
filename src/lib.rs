//! An implementation of the double ratchet algorithm.
//! 
//! Author -- daniel.bechaz@gmail.com  
//! Last Moddified --- 2019-04-19

#![deny(missing_docs,)]
#![feature(const_fn,)]

mod ratchet;
pub mod message;
mod client;

pub use self::{ratchet::*, client::*,};
