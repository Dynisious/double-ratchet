//! Defines the receiving half of a [Client].
//! 
//! Author -- daniel.bechaz@gmail.com  
//! Last Moddified --- 2019-04-11

use crate::Ratchet;
use generic_array::{ArrayLength, typenum::consts,};
use x25519_dalek::PublicKey;
use ring::aead::{self, OpeningKey, Nonce, Aad, Algorithm,};
use std::collections::HashMap;

/// The array type for a Diffie-Hellman PublicKey.
type KeyArray = [u8; 32];

/// The receiving half of a [Client].
pub struct ReceiveClient<D, Rounds = consts::U1, AadLength = consts::U0,> 
  where AadLength: ArrayLength<u8>, {
  ratchet: Ratchet<D, Rounds,>,
  algorithm: &'static Algorithm,
  sent_count: usize,
  current_public_key: PublicKey,
  current_keys: HashMap<usize, (OpeningKey, Nonce, AadLength::ArrayType,)>,
  previous_keys: HashMap<KeyArray, HashMap<usize, (OpeningKey, Nonce, AadLength::ArrayType,)>>,
}

#[cfg(test,)]
mod tests {
  use super::*;

  #[test]
  fn test_receive_client() {
    unimplemented!()
  }
  #[test]
  fn test_receive_client_serde() {
    unimplemented!()
  }
}
