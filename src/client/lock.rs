//! Defines the locking half of a [Client].
//! 
//! Author -- daniel.bechaz@gmail.com  
//! Last Moddified --- 2019-05-04

use super::{aead::{Algorithm, Aes256Gcm,}, OpenData,};
use crate::{Ratchet, message::{Message, Header,}, typenum::{Unsigned, consts,},};
use x25519_dalek::PublicKey;
use ring::{aead::{self, SealingKey, Nonce, Aad,},};
use digest::generic_array::ArrayLength;
use clear_on_drop::ClearOnDrop;
use std::{iter::TrustedLen, marker::PhantomData,};

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
  where S: ArrayLength<u8>,
    A: Algorithm,
    L: ArrayLength<u8>,
    Ratchet<D, S, R,>: TrustedLen<Item = u8>, {
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
      let header = Header {
        message_index: self.next_header.message_index + 1,
        ..self.next_header
      };

      //Replace the cached header.
      mem::replace(&mut self.next_header, header,)
    };
    //Pad the message data to fit the output.
    let mut data = {
      //Clear the message data once done.
      let data = ClearOnDrop::new(buffer,).iter().cloned()
        .chain(iter::repeat(0,).take(A::TagLength::USIZE,),)
        .take(std::usize::MAX,)
        .collect::<Box<[u8]>>();

      ClearOnDrop::new(data,)
    };
    //Calculate the sealing data.
    let sealing_data = OpenData::<A, L,>::from_iter(&mut self.ratchet,);
    //Get the sealing key.
    let sealing_key = &SealingKey::new(algorithm, &sealing_data.key,).ok()?;
    //Get the nonce.
    let nonce = {
      let nonce = unsafe { &*(sealing_data.nonce.as_slice() as *const _ as *const [u8; 12]) };
      
      Nonce::assume_unique_for_key(*nonce,)
    };
    //Get the authentication data.
    let aad = Aad::from(&sealing_data.aad,);
    //Seal the message and get the length of the encrypted data.
    let length = aead::seal_in_place(
      sealing_key,
      nonce,
      aad,
      data.as_mut(),
      A::TagLength::USIZE,
    ).ok()?;

    Some(Message {
      header,
      data: (&data[..length]).into(),
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
    let msg_length = (std::usize::MAX - <Aes256Gcm as Algorithm>::TagLength::USIZE)
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
    assert_eq!(lock.next_header.message_index, 1, "Sent count failed to update",);
  }
}
