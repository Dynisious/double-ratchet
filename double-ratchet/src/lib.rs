//! An implementation of the double ratchet algorithm.
//! 
//! # Example
//! 
//! ```rust
//! use double_ratchet::{Client, StaticSecret, typenum::consts::U200,};
//! use sha1::Sha1;
//! 
//! let private1: StaticSecret = [1; 32].into();
//! let private2: StaticSecret = [2; 32].into();
//! let mut client1 = Client::<Sha1, U200,>::connect((&private2).into(), private1.clone(),);
//! let mut client2 = Client::<Sha1, U200,>::accept((&private1).into(), private2,);
//! 
//! let message1 = client1.lock(&mut [1; 100],)
//!   .expect("Locked the first message");
//! let message2 = client1.lock(&mut [2; 100],)
//!   .expect("Locked the second message");
//! let message3 = client2.lock(&mut [3; 100],)
//!   .expect("Locked the third message");
//! 
//! let message2 = client2.open(message2,).expect("Opened the second message");
//! let message3 = client1.open(message3,).expect("Opened the third message");
//! let message1 = client2.open(message1,).expect("Opened the first message");
//! ```
//! 
//! Author -- daniel.bechaz@gmail.com  
//! Last Moddified --- 2019-05-11

#![deny(missing_docs,)]
#![feature(const_fn,)]

pub use ratchet;
pub use ratchet::{digest, typenum, generic_array,};
pub use x25519_dalek::{PublicKey, StaticSecret,};

pub mod message;
mod client;

pub use self::client::*;
