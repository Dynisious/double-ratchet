//! Defines types for performing message encryption.
//! 
//! Author -- daniel.bechaz@gmail.com  
//! Last Moddified --- 2019-04-28

use ring::aead;
use crate::{generic_array::ArrayLength, typenum::consts,};

/// A trait for message encryption algorithms.
pub trait Algorithm {
  /// The length of the keys.
  type KeyLength: ArrayLength<u8>;
  /// The length of the nonce.
  type NonceLength: ArrayLength<u8>;
  /// The length of the authentication tag.
  type TagLength: ArrayLength<u8>;
  /// The size of the encryption block in bytes.
  type BlockSize: ArrayLength<u8>;

  /// Returns the ring Algorithm instance.
  fn algorithm() -> &'static aead::Algorithm;
}

/// AES128 encryption in GCM mode.
pub struct Aes128Gcm;

impl Algorithm for Aes128Gcm {
  type KeyLength = consts::U16;
  type NonceLength = consts::U12;
  type TagLength = consts::U16;
  type BlockSize = consts::U16;

  #[inline]
  fn algorithm() -> &'static aead::Algorithm { &aead::AES_128_GCM }
}

/// AES256 encryption in GCM mode.
pub struct Aes256Gcm;

impl Algorithm for Aes256Gcm {
  type KeyLength = consts::U32;
  type NonceLength = consts::U12;
  type TagLength = consts::U16;
  type BlockSize = consts::U16;

  #[inline]
  fn algorithm() -> &'static aead::Algorithm { &aead::AES_256_GCM }
}

/// CHACHA20 encryption using Poly1305 authentication.
pub struct ChaCha20Poly1305;

impl Algorithm for ChaCha20Poly1305 {
  type KeyLength = consts::U32;
  type NonceLength = consts::U12;
  type TagLength = consts::U16;
  type BlockSize = consts::U1;

  #[inline]
  fn algorithm() -> &'static aead::Algorithm { &aead::CHACHA20_POLY1305 }
}
