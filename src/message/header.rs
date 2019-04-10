//! Defines [Message] types.
//! 
//! Author -- daniel.bechaz@gmail.com  
//! Last Moddified --- 2019-04-10

use x25519_dalek::PublicKey;
use std::{io::{self, Write,}, convert::TryInto,};

/// The headers tagged with a message.
pub struct Header {
  /// The `PublicKey` of the communication partner.
  pub public_key: PublicKey,
  /// The index of this message in the current step.
  pub message_index: usize,
  /// The number of messages in the previous step.
  pub previous_step: usize,
}

impl Header {
  /// The size of a `Header` struct once serialised.
  pub(super) const SERIALISED_SIZE: usize = 32 + 4 + 4;

  /// Try to decode a `Messsage` from bytes.
  /// 
  /// Returns the `Message` and the number of bytes used to decode the `Message`.
  /// 
  /// If there is not enough data to decode a `Message` `None` is returned.
  /// 
  /// # Params
  /// 
  /// bytes --- The bytes to decode the message from.  
  pub(super) fn deserialise(bytes: &[u8],) -> Option<Header> {
    let (public_key, bytes,) = {
      if bytes.len() < 32 { return None }

      let (public_key, bytes,) = bytes.split_at(32,);
      let public_key = unsafe { *(public_key.as_ptr() as *const [u8; 32]) };
      
      (public_key.into(), bytes,)
    };
    let (message_index, bytes,) = {
      if bytes.len() < 4 { return None }

      let (message_index, bytes,) = bytes.split_at(4,);
      let message_index = unsafe { *(message_index.as_ptr() as *const [u8; 4]) };
      let message_index = u32::from_be_bytes(message_index,);
      let message_index = message_index.try_into().ok()?;

      (message_index, bytes,)
    };
    let previous_step = {
      if bytes.len() < 4 { return None }

      let previous_step = bytes.split_at(4,).0;
      let previous_step = unsafe { *(previous_step.as_ptr() as *const [u8; 4]) };
      let previous_step = u32::from_be_bytes(previous_step,);
      let previous_step = previous_step.try_into().ok()?;

      previous_step
    };

    Some(Self { public_key, message_index, previous_step, })
  }
  /// Encodes a `Header` as bytes.
  /// 
  /// # Params
  /// 
  /// writer --- The writer to write too.  
  pub(super) fn serialise(&self, writer: &mut dyn Write,) -> io::Result<()> {
    writer.write_all(self.public_key.as_bytes(),)?;

    let message_index: u32 = self.message_index.try_into()
      .or::<io::Error>(Err(io::ErrorKind::Other.into()),)?;
    writer.write_all(&message_index.to_be_bytes(),)?;
    
    let previous_step: u32 = self.previous_step.try_into()
      .or::<io::Error>(Err(io::ErrorKind::Other.into()),)?;
    writer.write_all(&previous_step.to_be_bytes(),)?;

    Ok(())
  }
}
