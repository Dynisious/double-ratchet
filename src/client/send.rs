//! Defines the sending half of a [Client].
//! 
//! Author -- daniel.bechaz@gmail.com  
//! Last Moddified --- 2019-04-11

use crate::{Ratchet, message::{Message, Header,},};
use x25519_dalek::PublicKey;
use digest::{Input, BlockInput, FixedOutput, Reset,};
use ring::{
  aead::{self, SealingKey, Nonce, Aad, Algorithm,},
  error::Unspecified,
};
use generic_array::{
  ArrayLength,
  typenum::{consts, Unsigned,},
};
use clear_on_drop::ClearOnDrop;
use std::marker::PhantomData;

/// The sending half of a [Client].
pub struct SendClient<D, Rounds = consts::U1, AadLength = consts::U0,> {
  ratchet: Ratchet<D, Rounds,>,
  next_header: Header,
  algorithm: &'static Algorithm,
  _phantom: PhantomData<AadLength>,
}

impl<D, R, L,> SendClient<D, R, L,> {
  /// Creates a new `SendClient` with no history.
  /// 
  /// # Params
  /// 
  /// ratchet --- The `Ratchet` to use to generate encryption data.  
  /// public_key --- The current public key being send.  
  /// algorithm --- The symmetric `Algorithm` to use.  
  pub fn new(ratchet: Ratchet<D, R,>, public_key: PublicKey, algorithm: &'static Algorithm,) -> Self {
    Self {
      ratchet, algorithm,
      next_header: Header {
        public_key,
        message_index: 0,
        previous_step: 0,
      },
      _phantom: PhantomData,
    }
  }
  /// The number of messages sent.
  #[inline]
  pub fn sent_count(&self,) -> usize { self.next_header.message_index }
  /// The maxmimum message length.
  #[inline]
  pub fn max_message_length(&self,) -> usize {
    std::usize::MAX - self.algorithm.tag_len()
  }
}

impl<D, R, L,> SendClient<D, R, L,>
  where D: Input + BlockInput + FixedOutput + Reset + Clone + Default,
    <D as BlockInput>::BlockSize: Clone,
    R: Unsigned, L: ArrayLength<u8>, {
  /// Finish the current round step and start the next one.
  /// 
  /// # Params
  /// 
  /// ratchet --- The new `Ratchet` to generate encryption data from.  
  /// public_key --- The new `PublicKey` to include in headers.  
  pub fn new_round_step(&mut self, ratchet: Ratchet<D, R,>, public_key: PublicKey,) {
    use std::mem;

    self.ratchet = ratchet;
    self.next_header.public_key = public_key;
    self.next_header.previous_step = mem::replace(&mut self.next_header.message_index, 0,);
  }
  /// Encrypts the passed data and returns the `Message`.
  /// 
  /// # Params
  /// 
  /// message --- The message data to encrypt.  
  pub fn send(&mut self, message: &mut [u8],) -> Result<Message, Unspecified> {
    use std::{mem, iter,};

    //Clear the message data once used.
    let message = ClearOnDrop::new(message,);
    //Get the message header.
    let mut header = {
      //Calculate the next header.
      let mut header = Header {
        message_index: self.next_header.message_index + 1,
        ..self.next_header
      };
      let header = ClearOnDrop::new(&mut header,);
      
      //Replace the cached header.
      mem::replace(&mut self.next_header, *header,)
    };
    //Clear the header once done.
    let header = ClearOnDrop::new(&mut header,);
    //Confirm that the message data can be encrypted.
    let mut message = {
      //Check the message length.
      if message.len() <= self.max_message_length() { return Err(Unspecified) };

      message.iter().cloned()
        .chain(iter::repeat(0,).take(self.algorithm.tag_len(),),)
        .collect::<Box<_>>()
    };
    //Clear the message data once done.
    let mut message = ClearOnDrop::new(&mut message,);
    //Calculate the length of the sealing data needed.
    let length = self.algorithm.key_len()
      + self.algorithm.nonce_len()
      + L::USIZE;
    //Calculate the sealing data.
    let mut sealing_data = self.ratchet.advance(length,)
      .or(Err(Unspecified),)?;
    //Clear the sealing data once done.
    let mut sealing_data = ClearOnDrop::new(&mut sealing_data,);
    //Get the sealing key.
    let (sealing_key, sealing_data,) = {
      let (sealing_key, sealing_data,) = (*sealing_data).split_at_mut(self.algorithm.key_len(),);
      let sealing_key = ClearOnDrop::new(sealing_key,);
      let sealing_key = SealingKey::new(self.algorithm, &*sealing_key,)?;
      
      (sealing_key, sealing_data,)
    };
    //Get the nonce.
    let (nonce, sealing_data,) = {
      let (nonce, sealing_data,) = sealing_data.split_at_mut(self.algorithm.nonce_len(),);
      let nonce = ClearOnDrop::new(nonce,);
      let mut nonce = unsafe { *(&*nonce as *const _ as *const [u8; 12]) };
      let nonce = ClearOnDrop::new(&mut nonce,);
      let nonce = Nonce::assume_unique_for_key(*nonce,);

      (nonce, sealing_data,)
    };
    //Get the authentication data.
    let aad = Aad::from(sealing_data,);
    //Seal the message and get the length of the encrypted data.
    let length = aead::seal_in_place(
      &sealing_key,
      nonce,
      aad,
      &mut *message,
      self.algorithm.tag_len(),
    )?;

    Ok(Message {
      header: *header,
      data: (&message[..length]).into(),
    })
  }
}

impl<D, R, L,> Drop for SendClient<D, R, L,> {
  #[inline]
  fn drop(&mut self,) {
    ClearOnDrop::new(&mut self.next_header,);
  }
}

#[cfg(test,)]
mod tests {
  use super::*;

  #[test]
  fn test_send_client() {
    unimplemented!()
  }
  #[test]
  fn test_send_client_serde() {
    unimplemented!()
  }
}