//! Defines the receiving half of a [Client].
//! 
//! Author -- daniel.bechaz@gmail.com  
//! Last Moddified --- 2019-04-25

use super::aead::Algorithm;
use crate::Ratchet;
use generic_array::{GenericArray, ArrayLength, typenum::consts,};
use x25519_dalek::PublicKey;
use ring::aead::{self, OpeningKey, Nonce, Aad,};
use clear_on_drop::ClearOnDrop;
use std::{collections::HashMap, ops::{Deref, DerefMut},};

// mod serde;

/// The array type for a Diffie-Hellman PublicKey.
type KeyArray = [u8; 32];

/// The receiving half of a Client.
pub(crate) struct ReceiveClient<Algorithm, Digest, Rounds = consts::U1, AadLength = consts::U0,> 
  where Algorithm: super::aead::Algorithm,
    Algorithm::KEY_BYTES: DerefMut,
    <Algorithm::KEY_BYTES as Deref>::Target: Default,
    Algorithm::NONCE_BYTES: DerefMut,
    <Algorithm::NONCE_BYTES as Deref>::Target: Default,
    AadLength: ArrayLength<u8>, {
  ratchet: Ratchet<Digest, Rounds,>,
  sent_count: usize,
  current_public_key: PublicKey,
  current_keys: HashMap<usize, OpenData<Algorithm, AadLength,>>,
  previous_keys: HashMap<KeyArray, HashMap<usize, OpenData<Algorithm, AadLength,>>>,
}

struct OpenData<Algorithm, AadLength,>
  where Algorithm: super::aead::Algorithm,
    Algorithm::KEY_BYTES: DerefMut,
    <Algorithm::KEY_BYTES as Deref>::Target: Default,
    Algorithm::NONCE_BYTES: DerefMut,
    <Algorithm::NONCE_BYTES as Deref>::Target: Default,
    AadLength: ArrayLength<u8>, {
  opening_key: ClearOnDrop<Algorithm::KEY_BYTES>,
  nonce: ClearOnDrop<Algorithm::NONCE_BYTES>,
  aad: ClearOnDrop<GenericArray<u8, AadLength>>,
}

impl<A, L,> PartialEq for OpenData<A, L,>
  where A: super::aead::Algorithm,
    A::KEY_BYTES: DerefMut,
    <A::KEY_BYTES as Deref>::Target: PartialEq + Default,
    A::NONCE_BYTES: DerefMut,
    <A::NONCE_BYTES as Deref>::Target: PartialEq + Default,
    L: ArrayLength<u8>, {
  fn eq(&self, rhs: &Self,) -> bool {
    *self.opening_key == *rhs.opening_key
    && *self.nonce == *rhs.nonce
    && *self.aad == *rhs.aad
  }
}

impl<A, L,> Eq for OpenData<A, L,>
  where A: super::aead::Algorithm,
    A::KEY_BYTES: DerefMut,
    <A::KEY_BYTES as Deref>::Target: Eq + Default,
    A::NONCE_BYTES: DerefMut,
    <A::NONCE_BYTES as Deref>::Target: Eq + Default,
    L: ArrayLength<u8>, {}

pub(crate) fn cmp<A, D, R, L,>(lhs: &ReceiveClient<A, D, R, L,>, rhs: &ReceiveClient<A, D, R, L,>,) -> bool
  where A: super::aead::Algorithm,
    A::KEY_BYTES: DerefMut,
    <A::KEY_BYTES as Deref>::Target: PartialEq + Default,
    A::NONCE_BYTES: DerefMut,
    <A::NONCE_BYTES as Deref>::Target: PartialEq + Default,
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
