//! Defines `Message` types.
//! 
//! Author -- daniel.bechaz@gmail.com  
//! Last Moddified --- 2019-04-25

mod header;

pub use self::header::*;

/// A `Message` is a message [Header] and associated data.
#[derive(PartialEq, Eq, Clone, Debug,)]
pub struct Message {
  /// The `Message` [Header].
  pub header: Header,
  /// The `Message` data.
  pub data: Box<[u8]>,
}
