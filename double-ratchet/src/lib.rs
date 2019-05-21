//! An implementation of the double ratchet algorithm.
//! 
//! # Example
//! 
//! ```rust
//! use double_ratchet::{
//!   Client, LocalClient, RemoteClient,
//!   x25519_dalek::StaticSecret,
//!   typenum::consts::U200,
//! };
//! use sha1::Sha1;
//! 
//! let private1: StaticSecret = [1; 32].into();
//! let private2: StaticSecret = [2; 32].into();
//! let mut client1 = LocalClient::<Sha1, U200,>::connect(&(&private2).into(), &private1,);
//! let mut client2 = RemoteClient::<Sha1, U200,>::accept(&(&private1).into(), &private2,);
//! 
//! let message1 = client1.lock(&mut [1; 100],)
//!   .expect("Locked the first message");
//! let message2 = client1.lock(&mut [2; 100],)
//!   .expect("Locked the second message");
//! let message3 = client2.lock(&mut [3; 100],)
//!   .expect("Locked the third message");
//! 
//! let mut buffer = Vec::new();
//! let message2 = client2.open(message2, &mut buffer,).expect("Opened the second message");
//! let message3 = client1.open(message3, &mut buffer,).expect("Opened the third message");
//! let message1 = client2.open(message1, &mut buffer,).expect("Opened the first message");
//! ```
//! 
//! Author -- daniel.bechaz@gmail.com  
//! Last Moddified --- 2019-05-21

#![deny(missing_docs,)]
#![feature(const_fn, maybe_uninit, maybe_uninit_ref, bind_by_move_pattern_guards, const_vec_new,)]

#[macro_use]
extern crate serde_derive;

pub use ratchet;
pub use ratchet::{digest, typenum, generic_array,};
pub use x25519_dalek;

pub mod message;
pub mod client;
pub mod framed;

pub use self::client::{Client, LocalClient, RemoteClient,};
