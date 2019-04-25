//! Defines the receiving half of a [Client].
//! 
//! Author -- daniel.bechaz@gmail.com  
//! Last Moddified --- 2019-04-25

use super::aead::Algorithm;
use crate::Ratchet;
use generic_array::{GenericArray, ArrayLength, typenum::consts,};
use x25519_dalek::PublicKey;

use clear_on_drop::ClearOnDrop;
use std::{collections::HashMap, ops::{Deref, DerefMut},};

mod serde;

/// The array type for a Diffie-Hellman PublicKey.
type KeyArray = [u8; 32];

/// The receiving half of a Client.
pub(crate) struct ReceiveClient<Algorithm, Digest, Rounds = consts::U1, AadLength = consts::U0,> 
  where Algorithm: super::aead::Algorithm,
    AadLength: ArrayLength<u8>, {
  ratchet: Ratchet<Digest, Rounds,>,
  sent_count: usize,
  current_public_key: PublicKey,
  current_keys: HashMap<usize, OpenData<Algorithm, AadLength,>>,
  previous_keys: HashMap<KeyArray, HashMap<usize, OpenData<Algorithm, AadLength,>>>,
}

struct OpenData<Algorithm, AadLength = consts::U0,>
  where Algorithm: super::aead::Algorithm,
    AadLength: ArrayLength<u8>, {
  opening_key: Algorithm::KEY_BYTES,
  nonce: Algorithm::NONCE_BYTES,
  aad: GenericArray<u8, AadLength>,
}

impl<A, L,> PartialEq for OpenData<A, L,>
  where A: Algorithm, L: ArrayLength<u8>, {
  fn eq(&self, rhs: &Self,) -> bool {
    self.opening_key.as_ref() == rhs.opening_key.as_ref()
    && self.nonce.as_ref() == rhs.nonce.as_ref()
    && self.aad.as_ref() == rhs.aad.as_ref()
  }
}

impl<A, L,> Eq for OpenData<A, L,>
  where A: Algorithm, L: ArrayLength<u8>, {}

impl<A, L,> Drop for OpenData<A, L,>
  where A: Algorithm, L: ArrayLength<u8>, {
  fn drop(&mut self,) {
    ClearOnDrop::new(self.opening_key.as_mut(),);
    ClearOnDrop::new(self.nonce.as_mut(),);
    ClearOnDrop::new(self.aad.as_mut(),);
  }
}

pub(crate) fn cmp<A, D, R, L,>(lhs: &ReceiveClient<A, D, R, L,>, rhs: &ReceiveClient<A, D, R, L,>,) -> bool
  where A: Algorithm,
    A::KEY_BYTES: PartialEq,
    A::NONCE_BYTES: PartialEq,
    L: ArrayLength<u8>, {
  use crate::ratchet;
  use std::hash::Hash;

  fn cmp_hashmap<K, V, Cmp,>(lhs: &HashMap<K, V>, rhs: &HashMap<K, V>, mut cmp: Cmp,) -> bool
    where K: Eq + Hash, Cmp: FnMut(&V, &V,) -> bool, {
    lhs.len() == rhs.len()
    && lhs.iter().all(move |(k, v_lhs,)| rhs.get(k,)
      .filter(|v_rhs,| cmp(v_lhs, v_rhs,),)
      .is_some(),
    )
  }

  ratchet::cmp(&lhs.ratchet, &rhs.ratchet,)
  && lhs.sent_count == rhs.sent_count
  && lhs.current_public_key.as_bytes() == rhs.current_public_key.as_bytes()
  && cmp_hashmap(&lhs.current_keys, &rhs.current_keys, PartialEq::eq,)
  && cmp_hashmap(&lhs.previous_keys, &rhs.previous_keys,
    |lhs, rhs,| cmp_hashmap(lhs, rhs, PartialEq::eq,),
  )
}

#[cfg(test,)]
mod tests {
  use super::*;

  #[test]
  fn test_receive_client() {
    unimplemented!()
  }
}
