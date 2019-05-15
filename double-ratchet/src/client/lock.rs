//! Defines the locking half of a [Client].
//! 
//! Author -- daniel.bechaz@gmail.com  
//! Last Moddified --- 2019-05-15

use super::{aead::Algorithm, OpenData, Error,};
use crate::{
  ratchet::Ratchet,
  message::{Message, Header,},
  generic_array::ArrayLength,
  typenum::Unsigned,
};
use clear_on_drop::ClearOnDrop;
use ring::{aead::{self, SealingKey, Nonce, Aad,},};
use rand::{RngCore, CryptoRng,};
use std::marker::PhantomData;

mod serde;

/// The locking half of a Client.
pub(crate) struct LockClient<Digest, State, Algorithm, Rounds, AadLength,>
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
    Ratchet<D, S, R,>: RngCore + CryptoRng, {
  /// Encrypts the passed data and returns the `Message`.
  /// 
  /// The buffer will be cleared if the message is encrypted successfully.
  /// 
  /// # Params
  /// 
  /// buffer --- The message data to encrypt.  
  pub fn lock(&mut self, buffer: &mut [u8],) -> Result<Message, Error> {
    use std::{mem, iter, hint,};
    
    //Check the message length is valid.
    if buffer.len() > self.max_message_length() { return Err(Error::MessageLength) };

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
    //Pad the message data to fit the encrypted output and auth tag.
    let mut data = ClearOnDrop::new(buffer.iter().copied()
      .chain(iter::repeat(0,).take(A::TagLength::USIZE,),)
      .collect::<Box<[u8]>>(),
    );
    //Calculate the sealing data.
    let sealing_data = OpenData::<A, L,>::new(&mut self.ratchet,);

    //Encrypt the data.
    clear_on_drop::clear_stack_on_return_fnonce(1, || {
      use clear_on_drop::clear::Clear;

      let sealing_key = SealingKey::new(algorithm, &sealing_data.key,);
      //Get the sealing key.
      let sealing_key = match sealing_key.as_ref() {
        Ok(v) => v,
        //Safe because we got this from OpenData.
        _ => unsafe { hint::unreachable_unchecked() },
      };
      //Get the nonce.
      let nonce = match Nonce::try_assume_unique_for_key(&sealing_data.nonce,) {
        Ok(v) => v,
        //Safe because we got this value from OpenData.
        _ => unsafe { hint::unreachable_unchecked() }
      };
      //Get the authentication data.
      let aad = Aad::from(&sealing_data.aad,);
      //Seal the message and get the length of the encrypted data.
      let length = aead::seal_in_place(sealing_key, nonce, aad, data.as_mut(), A::TagLength::USIZE,).ok()
        .ok_or(Error::Encryption,)?;
      //Get the encrypted data.
      let data = data[..length].into();

      buffer.clear();

      Ok(Message { header, data, })
    },)
  }
}

impl<D, S, A, R, L,> Default for LockClient<D, S, A, R, L,>
  where S: ArrayLength<u8>,
    A: Algorithm,
    L: ArrayLength<u8>, {
  #[inline]
  fn default() -> Self {
    Self {
      ratchet: Ratchet::default(),
      next_header: Header::default(),
      _data: PhantomData,
    }
  }
}

impl<D, S, A, R, L,> Drop for LockClient<D, S, A, R, L,>
  where S: ArrayLength<u8>, {
  #[inline]
  fn drop(&mut self,) { ClearOnDrop::new(&mut self.next_header,); }
}

#[cfg(test,)]
mod tests {
  use super::*;
  use crate::{client::{aead::Aes256Gcm, open::OpenClient,}, typenum::consts,};
  use sha1::Sha1;

  #[test]
  fn test_lock_client() {
    let mut ratchet = Ratchet::new(&mut rand::thread_rng(),);
    let mut lock = LockClient::<Sha1, consts::U500, Aes256Gcm, consts::U1, consts::U100,> {
      ratchet: ratchet.clone(),
      next_header: Header {
        public_key: [1; 32].into(),
        ..Header::default()
      },
      _data: PhantomData,
    };
    let mut open = OpenClient::<Sha1, consts::U500, Aes256Gcm, consts::U1, consts::U100,> {
      current_public_key: ClearOnDrop::new([1; 32].into(),),
      sent_count: 1,
      current_keys: vec![(0, OpenData::new(&mut ratchet,),),].into_iter().collect(),
      ratchet,
      previous_keys: Default::default(),
    };
    let msg_length = (std::usize::MAX - <Aes256Gcm as Algorithm>::TagLength::USIZE)
      / <Aes256Gcm as Algorithm>::BlockSize::USIZE
      * <Aes256Gcm as Algorithm>::BlockSize::USIZE;

    assert_eq!(lock.max_message_length(), msg_length, "Bad max message length",);

    let msg = [1; 20];
    let other = lock.lock(&mut msg.clone(),)
      .expect("Error encrpyting message");
    let mut buffer = Vec::new();
    let other = open.open(other, &mut buffer,)
      .expect("Error decrypting message");
    
    assert_eq!(lock.next_header.message_index, 1, "Sent count failed to update",);
    assert_eq!(msg.as_ref(), other, "Message does not match",);
  }
}
