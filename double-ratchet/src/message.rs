//! Defines `Message` types.
//! 
//! Author -- daniel.bechaz@gmail.com  
//! Last Moddified --- 2019-05-12

mod serde;

/// A `Message` is a message [Header] and associated data.
#[derive(PartialEq, Eq, Clone, Debug,)]
pub struct Message {
  /// The `Message` [Header].
  pub header: Header,
  /// The `Message` data.
  pub data: Box<[u8]>,
}

/// The headers tagged with a message.
#[derive(PartialEq, Eq, Clone, Copy, Debug, Default,)]
pub struct Header {
  /// The `PublicKey` of the communication partner.
  pub public_key: [u8; 32],
  /// The index of this message in the current step.
  pub message_index: u32,
  /// The number of messages in the previous step.
  pub previous_step: u32,
}
