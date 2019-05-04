//! Defines the opening half of a [Client].
//! 
//! Author -- daniel.bechaz@gmail.com  
//! Last Moddified --- 2019-05-04

use super::{aead::{Algorithm, Aes256Gcm,}, OpenData,};
use crate::{Ratchet, message::Message,
  generic_array::ArrayLength,
  typenum::consts,
};
use clear_on_drop::ClearOnDrop;
use x25519_dalek::PublicKey;
use std::{iter::TrustedLen, collections::HashMap,};

mod serde;

/// The opening half of a Client.
pub(crate) struct OpenClient<Digest, State, Algorithm = Aes256Gcm, Rounds = consts::U1, AadLength = consts::U0,>
  where State: ArrayLength<u8>,
    Algorithm: super::aead::Algorithm,
    AadLength: ArrayLength<u8>, {
  /// The Ratchet used to generate opening data.
  pub ratchet: Ratchet<Digest, State, Rounds,>,
  /// The number of messages sent under the current PublicKey.
  pub sent_count: u32,
  /// The current PublicKey of the remote Client.
  pub current_public_key: PublicKey,
  /// The previous OpenData under the current PublicKey.
  pub current_keys: HashMap<u32, Box<OpenData<Algorithm, AadLength,>>>,
  /// The OpenData under the previous PublicKeys.
  pub previous_keys: HashMap<KeyArray, HashMap<u32, Box<OpenData<Algorithm, AadLength,>>>>,
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
    Self {
      ratchet,
      current_public_key: public_key,
      sent_count: 0,
      current_keys: HashMap::new(),
      previous_keys: HashMap::new(),
    }
  }
}

impl<D, S, A, R, L,> OpenClient<D, S, A, R, L,>
  where S: ArrayLength<u8>,
    A: Algorithm,
    L: ArrayLength<u8>,
    Ratchet<D, S, R,>: TrustedLen<Item = u8>, {
  /// Opens the passed message returning the message data.
  /// 
  /// If the message cannot be opened it is returned.
  /// 
  /// # Params
  /// 
  /// message --- The message to open.
  pub fn open(&mut self, message: Message,) -> Result<Box<[u8]>, Message> {
    use ring::aead::{self, OpeningKey, Nonce, Aad,};
    
    //The index of this message in the current ratchet step.
    let message_index = message.header.message_index;
    //The data to open this message.
    let open_data = if message.header.public_key.as_bytes() != self.current_public_key.as_bytes() {
      let key_group = match self.previous_keys.get_mut(message.header.public_key.as_bytes(),) {
        Some(key_group) => key_group,
        None => return Err(message),
      };
      
      match key_group.remove(&message.header.message_index,) {
        Some(data) => data,
        None => return Err(message),
      }
    } else if message_index >= self.sent_count {
      //Generate skipped keys.
      for index in self.sent_count..message.header.message_index {
        self.current_keys.insert(index, OpenData::from_iter(&mut self.ratchet,),);
      }

      //Update the count of sent messages.
      self.sent_count = message.header.message_index + 1;
      //Generate the opening key data.
      OpenData::from_iter(&mut self.ratchet,)
    } else {
      //Remove the skipped key
      match self.current_keys.remove(&message_index,) {
        Some(data) => data,
        None => return Err(message),
      }
    };
    let key = match OpeningKey::new(A::algorithm(), &open_data.key,) {
      Ok(key) => key,
      Err(_) => return Err(message),
    };
    let nonce = match Nonce::try_assume_unique_for_key(open_data.nonce.as_slice(),) {
      Ok(nonce) => nonce,
      Err(_) => return Err(message),
    };
    let aad = Aad::from(open_data.aad.as_slice(),);
    let res = aead::open_in_place(&key, nonce, aad, 0, ClearOnDrop::new(message.data.clone(),).as_mut(),)
      .map(|data,| (&*data).into(),)
      .or(Err(message),);
    
    //If there was an error store the opening data.
    if res.is_err() { self.current_keys.insert(message_index, open_data,); }

    res
  }
}

type KeyArray = [u8; 32];

#[cfg(test,)]
impl<D, S, A, R, L,> PartialEq for OpenClient<D, S, A, R, L,>
  where S: ArrayLength<u8>,
    A: Algorithm,
    L: ArrayLength<u8>, {
  fn eq(&self, rhs: &Self,) -> bool {
    use std::hash::Hash;

    fn cmp_hashmap<K, V, Cmp,>(lhs: &HashMap<K, V>, rhs: &HashMap<K, V>, mut cmp: Cmp,) -> bool
      where K: Eq + Hash, Cmp: FnMut(&V, &V,) -> bool, {
      lhs.len() == rhs.len()
      && lhs.iter().all(move |(k, v_lhs,)| rhs.get(k,)
        .filter(|v_rhs,| cmp(v_lhs, v_rhs,),)
        .is_some(),
      )
    }

    self.ratchet == rhs.ratchet
    && self.sent_count == rhs.sent_count
    && self.current_public_key.as_bytes() == rhs.current_public_key.as_bytes()
    && cmp_hashmap(&self.current_keys, &rhs.current_keys, PartialEq::eq,)
    && cmp_hashmap(&self.previous_keys, &rhs.previous_keys,
      |lhs, rhs,| cmp_hashmap(lhs, rhs, PartialEq::eq,),
    )
  }
}

#[cfg(test,)]
impl<D, S, A, R, L,> Eq for OpenClient<D, S, A, R, L,>
  where S: ArrayLength<u8>,
    A: Algorithm,
    L: ArrayLength<u8>, {}

#[cfg(test,)]
mod tests {
  use super::*;
  use crate::client::LockClient;
  use sha1::Sha1;

  #[test]
  fn test_open_client() {
    let ratchet = Ratchet::new(&mut [],);
    let public_key = [1; 32].into();
    let mut lock = LockClient::<Sha1, consts::U500, Aes256Gcm, consts::U1,>::new(ratchet.clone(), public_key,);
    let mut open = OpenClient::<Sha1, consts::U500, Aes256Gcm, consts::U1,>::new(ratchet, public_key,);
    let msg = [1; 20];
    let other = lock.lock(&mut msg.clone(),)
      .expect("Error locking message");
    let other = open.open(other,)
      .expect("Error opening message");

    assert_eq!(&other[..], &msg[..], "Opened message corrupted",);
  }
}
