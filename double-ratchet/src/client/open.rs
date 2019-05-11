//! Defines the opening half of a [Client].
//! 
//! Author -- daniel.bechaz@gmail.com  
//! Last Moddified --- 2019-05-11

use super::{aead::Algorithm, OpenData,};
use crate::{
  ratchet::Ratchet,
  message::Message,
  typenum::consts::U32,
  generic_array::{ArrayLength, GenericArray,},
};
use clear_on_drop::ClearOnDrop;
use x25519_dalek::PublicKey;
use std::{ops, collections::HashMap,};

mod serde;

/// The opening half of a Client.
pub(crate) struct OpenClient<Digest, State, Algorithm, Rounds, AadLength,>
  where State: ArrayLength<u8>,
    Algorithm: super::aead::Algorithm,
    AadLength: ArrayLength<u8>, {
  /// The Ratchet used to generate opening data.
  pub ratchet: Ratchet<Digest, State, Rounds,>,
  /// The number of messages sent under the current PublicKey.
  pub sent_count: u32,
  /// The current PublicKey of the remote Client.
  pub current_public_key: ClearOnDrop<KeyBytes>,
  /// The previous OpenData under the current PublicKey.
  pub current_keys: HashMap<u32, OpenData<Algorithm, AadLength,>>,
  /// The OpenData under the previous PublicKeys.
  pub previous_keys: HashMap<KeyBytes, HashMap<u32, OpenData<Algorithm, AadLength,>>>,
}

impl<D, S, A, R, L,> OpenClient<D, S, A, R, L,>
  where S: ArrayLength<u8>,
    A: Algorithm,
    L: ArrayLength<u8>, {
  /// Returns a new OpenClient using the passed ratchet and public key.
  /// 
  /// # Params
  /// 
  /// ratchet --- The Ratchet to produce opening data.  
  /// public_key --- The PublicKey of the partner Client.  
  pub fn new(ratchet: Ratchet<D, S, R,>, public_key: PublicKey,) -> Self {
    let current_public_key = ClearOnDrop::new(public_key.as_bytes().clone().into(),);

    Self {
      ratchet,
      current_public_key,
      sent_count: 0,
      current_keys: HashMap::new(),
      previous_keys: HashMap::new(),
    }
  }
  /// Opens the passed message returning the message data.
  /// 
  /// If the message cannot be opened it is returned.
  /// 
  /// # Params
  /// 
  /// message --- The message to open.  
  pub fn open(&mut self, message: Message,) -> Result<Box<[u8]>, Message> {
    use ring::aead::{self, OpeningKey, Nonce, Aad,};
    use std::hint;
    
    clear_on_drop::clear_stack_on_return_fnonce(1, move || {
      //The data to open this message.
      let open_data = match self.current_keys.remove(&message.header.message_index,) {
        Some(v) => v,
        _ => return Err(message),
      };
      let key = match OpeningKey::new(A::algorithm(), &open_data.key,) {
        Ok(v) => v,
        _ => unsafe { hint::unreachable_unchecked() },
      };
      let nonce = match Nonce::try_assume_unique_for_key(&open_data.nonce,) {
        Ok(v) => v,
        _ => unsafe { hint::unreachable_unchecked() },
      };
      let aad = Aad::from(open_data.aad.as_ref(),);
      let mut data = ClearOnDrop::new(message.data.clone(),);
      
      //Open the message.
      aead::open_in_place(&key, nonce, aad, 0, data.as_mut(),).ok()
      .map(|data,| data.as_ref().into(),)
      .ok_or_else(move || {
        self.current_keys.insert(message.header.message_index, open_data,); 
      
        message
      },)
    },)
  }
}

#[derive(PartialEq, Eq, Clone, Copy, Default, Hash,)]
pub(crate) struct KeyBytes(pub GenericArray<u8, U32>,);

impl ops::Deref for KeyBytes {
  type Target = GenericArray<u8, U32>;

  #[inline]
  fn deref(&self,) -> &GenericArray<u8, U32> { &self.0 }
}

impl ops::DerefMut for KeyBytes {
  #[inline]
  fn deref_mut(&mut self,) -> &mut GenericArray<u8, U32> { &mut self.0 }
}

impl From<[u8; 32]> for KeyBytes {
  #[inline]
  fn from(from: [u8; 32],) -> Self { KeyBytes(from.into(),) }
}

impl From<GenericArray<u8, U32>> for KeyBytes {
  #[inline]
  fn from(from: GenericArray<u8, U32>,) -> Self { KeyBytes(from,) }
}

#[cfg(test,)]
mod tests {
  use super::*;
  use crate::{client::{LockClient, aead::Aes256Gcm,}, typenum::consts,};
  use sha1::Sha1;

  #[test]
  fn test_open_client() {
    let ratchet = Ratchet::new(&mut rand::thread_rng(),);
    let public_key = [1; 32].into();
    let mut lock = LockClient::<Sha1, consts::U500, Aes256Gcm, consts::U1, consts::U100,>::new(ratchet.clone(), public_key,);
    let mut open = {
      let mut open = OpenClient::<Sha1, consts::U500, Aes256Gcm, consts::U1, consts::U100,>::new(ratchet, public_key,);

      open.sent_count = 1;
      open.current_keys.insert(0, OpenData::new(&mut open.ratchet,),);

      open
    };
    let msg = [1; 20];
    let locked_msg = lock.lock(&mut msg.clone(),)
      .expect("Error locking message");
    
    open.open(Message {
      data: [1; 100].as_ref().into(),
      ..locked_msg
    },).expect_err("Opened a corrupted message");

    let other_msg = open.open(locked_msg.clone(),)
      .expect("Error opening message");

    assert_eq!(&other_msg[..], &msg[..], "Opened message corrupted",);

    open.open(locked_msg,).expect_err("Opened a message twice");
  }
}
