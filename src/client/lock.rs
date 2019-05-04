//! Defines the locking half of a [Client].
//! 
//! Author -- daniel.bechaz@gmail.com  
//! Last Moddified --- 2019-05-04

use super::{aead::{Algorithm, Aes256Gcm,}, OpenData,};
use crate::{Ratchet, message::{Message, Header,}, typenum::{Unsigned, consts,},};
use digest::BlockInput;
use x25519_dalek::PublicKey;
use ring::{aead::{self, SealingKey, Nonce, Aad,},};
use digest::generic_array::ArrayLength;
use clear_on_drop::ClearOnDrop;
use std::{iter::{Iterator, FromIterator,}, marker::PhantomData,};

mod serde;

/// The locking half of a Client.
pub(crate) struct LockClient<Digest, State, Algorithm = Aes256Gcm, Rounds = consts::U1, AadLength = consts::U0,>
  where State: ArrayLength<u8>, {
  /// The Ratchet used to get the sealing data.
  pub ratchet: Ratchet<Digest, State, Rounds,>,
  /// The Header for the next message encrypted.
  pub next_header: Header,
  pub _data: PhantomData<(Algorithm, AadLength,)>,
}

impl<D, S, A, R, L,> LockClient<D, S, A, R, L,>
  where A: Algorithm,
    S: ArrayLength<u8>, {
  /// Creates a new `LockClient` with no history.
  /// 
  /// # Params
  /// 
  /// ratchet --- The `Ratchet` to use to generate encryption data.  
  /// public_key --- The current public key being used.  
  pub fn new(ratchet: Ratchet<D, S, R,>, public_key: PublicKey,) -> Self {
    let next_header = Header {
      public_key,
      message_index: 0,
      previous_step: 0,
    };
    
    Self {
      ratchet, next_header,
      _data: PhantomData,
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

impl<D, S, A, R, L,> LockClient<D, S, A, R, L,>
  where D: BlockInput,
    S: ArrayLength<u8>,
    A: Algorithm, {
  /// Finish the current round step and start the next one.
  /// 
  /// # Params
  /// 
  /// ratchet --- The new `Ratchet` to generate encryption data from.  
  /// public_key --- The new `PublicKey` to include in headers.  
  pub fn new_round_step(&mut self, ratchet: Ratchet<D, S, R,>, public_key: PublicKey,) {
    use std::mem;

    self.ratchet = ratchet;
    self.next_header.public_key = public_key;
    self.next_header.previous_step = mem::replace(&mut self.next_header.message_index, 0,);
  }
}

impl<D, S, A, R, L,> LockClient<D, S, A, R, L,>
  where S: ArrayLength<u8>,
    A: Algorithm,
    L: ArrayLength<u8>,
    Ratchet<D, S, R,>: Iterator<Item = u8>,
    Box<OpenData<A, L,>>: FromIterator<u8>, {
  /// Encrypts the passed data and returns the `Message`.
  /// 
  /// The buffer will be cleared if the message is encrypted successfully.
  /// 
  /// # Params
  /// 
  /// buffer --- The message data to encrypt.  
  pub fn lock(&mut self, buffer: &mut [u8],) -> Option<Message> {
    use std::{mem, iter,};
    
    //Check the message length is valid.
    if buffer.len() > self.max_message_length() { return None };

    //The encryption algorithm.
    let algorithm = A::algorithm();
    //Get the message header.
    let header = {
      //Calculate the next header.
      let mut header = Header {
        message_index: self.next_header.message_index + 1,
        ..self.next_header
      };

      //Replace the cached header.
      mem::replace(&mut self.next_header, header,)
    };
    let mut message = {
      //Clear the message data once done.
      let mut message = buffer.iter().cloned()
        .chain(iter::repeat(0,).take(algorithm.tag_len(),),)
        .collect::<Box<[u8]>>();

      ClearOnDrop::new(message,)
    };
    //Calculate the sealing data.
    let sealing_data = Box::<OpenData<A, L,>>::from_iter(&mut self.ratchet,);
    //Get the sealing key.
    let sealing_key = SealingKey::new(algorithm, &sealing_data.key,).ok()?;
    //Get the nonce.
    let nonce = {
      let nonce = unsafe { &*(sealing_data.nonce.as_slice() as *const _ as *const [u8; 12]) };
      
      Nonce::assume_unique_for_key(*nonce,)
    };
    //Get the authentication data.
    let aad = Aad::from(&sealing_data.aad,);
    //Seal the message and get the length of the encrypted data.
    let length = aead::seal_in_place(
      &sealing_key,
      nonce,
      aad,
      message.as_mut(),
      A::TagLength::USIZE,
    ).ok()?;

    //Clear the buffer.
    ClearOnDrop::new(buffer,);

    Some(Message {
      header,
      data: (&message[..length]).into(),
    })
  }
}

impl<D, S: ArrayLength<u8>, A, R, L,> Drop for LockClient<D, S, A, R, L,> {
  #[inline]
  fn drop(&mut self,) {
    ClearOnDrop::new(&mut self.next_header,);
  }
}

#[cfg(test,)]
impl<D, S, A, R, L,> PartialEq for LockClient<D, S, A, R, L,>
  where S: ArrayLength<u8>, {
  #[inline]
  fn eq(&self, rhs: &Self,) -> bool {
    self.ratchet == rhs.ratchet
    && self.next_header == rhs.next_header
  }
}

#[cfg(test,)]
impl<D, S, A, R, L,> Eq for LockClient<D, S, A, R, L,>
  where S: ArrayLength<u8>, {}

#[cfg(test,)]
mod tests {
  use super::*;
  use crate::client::aead::Aes256Gcm;
  use sha1::Sha1;

  #[test]
  fn test_lock_client() {
    let ratchet = Ratchet::new(&mut [1; 128],);
    let mut lock = LockClient::<Sha1, consts::U500, Aes256Gcm, consts::U1,>::new(ratchet, [1; 32].into(),);
    let msg_length = (std::usize::MAX - 16)
      / <Aes256Gcm as Algorithm>::BlockSize::USIZE
      * <Aes256Gcm as Algorithm>::BlockSize::USIZE;

    assert_eq!(lock.max_message_length(), msg_length, "Bad max message length",);

    let msg = Message {
      header: Header {
        public_key: [1; 32].into(),
        message_index: 0,
        previous_step: 0,
      },
      data: Box::new([112, 116, 173, 228, 215, 157, 5, 3, 255, 188, 104, 98, 149, 169, 77, 122, 210, 88, 105, 139, 216, 176, 175, 161, 34, 242, 216, 148, 66, 80, 55, 82, 109, 61, 221, 194],),
    };
    let mut other = [1; 20];
    let other = lock.lock(&mut other,)
      .expect("Error encrpyting message");
    
    assert_eq!(msg, other, "Encrypted message does not match",);
    assert_eq!(lock.sent_count(), 1, "Sent count failed to update",);
  }
}
