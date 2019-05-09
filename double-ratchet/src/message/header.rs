//! Defines [Message] types.
//! 
//! Author -- daniel.bechaz@gmail.com  
//! Last Moddified --- 2019-04-19

use x25519_dalek::PublicKey;

mod serde;

/// The headers tagged with a message.
#[derive(Clone, Copy, Debug,)]
pub struct Header {
  /// The `PublicKey` of the communication partner.
  pub public_key: PublicKey,
  /// The index of this message in the current step.
  pub message_index: u32,
  /// The number of messages in the previous step.
  pub previous_step: u32,
}

impl PartialEq for Header {
  fn eq(&self, rhs: &Self,) -> bool {
    self.message_index == rhs.message_index
    && self.previous_step == self.previous_step
    && self.public_key.as_bytes() == rhs.public_key.as_bytes()
  }
}

impl Eq for Header {}

impl Default for Header {
  #[inline]
  fn default() -> Self {
    Self {
      public_key: [0; 32].into(),
      message_index: 0,
      previous_step: 0,
    }
  }
}
