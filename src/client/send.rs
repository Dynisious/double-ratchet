//! Defines the sending half of a [Client].
//! 
//! Author -- daniel.bechaz@gmail.com  
//! Last Moddified --- 2019-04-28

use super::aead::Algorithm;
use crate::{Ratchet, message::{Message, Header,},};
use digest::{Input, BlockInput, FixedOutput, Reset,};
use x25519_dalek::PublicKey;
use ring::{aead::{self, SealingKey, Nonce, Aad,},};
use generic_array::{ArrayLength, typenum::{consts, Unsigned,},};
use clear_on_drop::ClearOnDrop;
use std::marker::PhantomData;

mod serde;

/// The sending half of a Client.
pub(crate) struct SendClient<Algorithm, Digest, Rounds = consts::U1, AadLength = consts::U0,> {
  /// The Ratchet used to get the sealing data.
  ratchet: Ratchet<Digest, Rounds,>,
  /// The Header for the next message encrypted.
  next_header: Header,
  _phantom: PhantomData<(Algorithm, AadLength,)>,
}

impl<A, D, R, L,> SendClient<A, D, R, L,>
  where A: Algorithm, {
  /// Creates a new `SendClient` with no history.
  /// 
  /// # Params
  /// 
  /// ratchet --- The `Ratchet` to use to generate encryption data.  
  /// public_key --- The current public key being send.  
  pub fn new(ratchet: Ratchet<D, R,>, public_key: PublicKey,) -> Self {
    let next_header = Header {
      public_key,
      message_index: 0,
      previous_step: 0,
    };
    
    Self {
      ratchet, next_header,
      _phantom: PhantomData,
    }
  }
  /// The number of messages sent during this round.
  #[inline]
  pub fn sent_count(&self,) -> u32 { self.next_header.message_index }
  /// The maxmimum length of a message which can be successfully encrypted.
  #[inline]
  pub const fn max_message_length(&self,) -> usize {
    (
      (std::usize::MAX - A::TagLength::USIZE)
      / A::BlockSize::USIZE
    ) * A::BlockSize::USIZE
  }
}

impl<A, D, R, L,> SendClient<A, D, R, L,>
  where A: Algorithm, D: Input + BlockInput + FixedOutput + Reset + Clone + Default,
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
  /// The buffer will be cleared if the message is encrypted successfully.
  /// 
  /// # Params
  /// 
  /// message --- The message data to encrypt.  
  pub fn send(&mut self, message: &mut [u8],) -> Option<Message> {
    use std::{mem, iter,};

    //The encryption algorithm.
    let algorithm = A::algorithm();
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
      if message.len() > self.max_message_length() { return None };

      message.iter().cloned()
        .chain(iter::repeat(0,).take(algorithm.tag_len(),),)
        .collect::<Box<_>>()
    };
    //Clear the message data once done.
    let mut message = ClearOnDrop::new(&mut message,);
    //Calculate the length of the sealing data needed.
    let length = algorithm.key_len()
      + algorithm.nonce_len()
      + L::USIZE;
    
    //Calculate the sealing data.
    let mut sealing_data = self.ratchet.advance(length,)?;
    //Clear the sealing data once done.
    let mut sealing_data = ClearOnDrop::new(&mut sealing_data,);
    //Get the sealing key.
    let (sealing_key, sealing_data,) = {
      let (sealing_key, sealing_data,) = (*sealing_data).split_at_mut(algorithm.key_len(),);
      let sealing_key = ClearOnDrop::new(sealing_key,);
      let sealing_key = SealingKey::new(algorithm, &*sealing_key,).ok()?;
      
      (sealing_key, sealing_data,)
    };
    //Get the nonce.
    let (nonce, sealing_data,) = {
      let (nonce, sealing_data,) = sealing_data.split_at_mut(algorithm.nonce_len(),);
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
      algorithm.tag_len(),
    ).ok()?;

    Some(Message {
      header: *header,
      data: (&message[..length]).into(),
    })
  }
}

impl<A, D, R, L,> Drop for SendClient<A, D, R, L,> {
  #[inline]
  fn drop(&mut self,) {
    ClearOnDrop::new(&mut self.next_header,);
  }
}

#[cfg(test,)]
pub(crate) fn cmp<A, D, R, L,>(lhs: &SendClient<A, D, R, L,>, rhs: &SendClient<A, D, R, L,>,) -> bool {
  use crate::ratchet;

  ratchet::cmp(&lhs.ratchet, &rhs.ratchet,)
  && lhs.next_header == rhs.next_header
}

#[cfg(test,)]
mod tests {
  use super::*;
  use crate::client::aead::Aes256Gcm;
  use sha1::Sha1;

  #[test]
  fn test_send_client() {
    let ratchet = Ratchet::from_bytes(&mut [1; 128],);
    let mut client = SendClient::<Aes256Gcm, Sha1, consts::U3, consts::U100,>::new(ratchet, [1; 32].into(),);
    let msg_length = (std::usize::MAX - 16)
      / <Aes256Gcm as Algorithm>::BlockSize::USIZE
      * <Aes256Gcm as Algorithm>::BlockSize::USIZE;

    assert_eq!(client.max_message_length(), msg_length, "Bad max message length",);

    let msg = Message {
      header: Header {
        public_key: [1; 32].into(),
        message_index: 0,
        previous_step: 0,
      },
      data: Box::new([90, 50, 145, 70, 247, 47, 51, 220, 88, 148, 60, 45, 8, 167, 150, 75, 18, 84, 252, 224, 134, 218, 7, 15, 87, 15, 182, 177, 36, 138, 235, 95, 254, 105, 218, 99, 46, 231, 214, 173, 158, 204, 78, 218, 162, 194, 220, 151, 224, 45, 195, 192, 158, 156, 196, 24, 13, 59, 153, 184, 19, 96, 213, 165, 84, 106, 241, 121, 64, 21, 240, 84, 91, 236, 9, 27, 223, 15, 247, 16, 30, 236, 186, 116, 9, 236, 186, 223, 133, 199, 167, 248, 127, 143, 157, 132, 151, 195, 142, 9, 225, 47, 67, 66, 182, 119, 167, 225, 179, 8, 114, 231, 239, 112, 204, 108],),
    };
    let mut other = [1; 100];
    let other = client.send(&mut other,)
      .expect("Error encrpyting message");
    
    assert_eq!(msg, other, "Encrypted message does not match",);
    assert_eq!(client.sent_count(), 1, "Sent count failed to update",);
  }
}
