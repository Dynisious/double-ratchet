//! Defines types for performing message encryption.
//! 
//! Author -- daniel.bechaz@gmail.com  
//! Last Moddified --- 2019-04-25

use ring::aead;

/// A trait for message encryption.
pub trait Algorithm {
  /// The bytes which make up the keys.
  type KEY_BYTES: AsRef<[u8]> + AsMut<[u8]>;
  /// The bytes which make up the nonce.
  type NONCE_BYTES: AsRef<[u8]> + AsMut<[u8]>;
  /// The bytes which make up the authentication tag.
  type TAG_BYTES: AsRef<[u8]> + AsMut<[u8]>;

  /// Returns the ring Algorithm instance.
  fn algorithm() -> &'static aead::Algorithm;
}

/// AES128 encryption in GCM mode.
pub struct Aes128Gcm;

impl Algorithm for Aes128Gcm {
  type KEY_BYTES = [u8; 16];
  type NONCE_BYTES = [u8; 12];
  type TAG_BYTES = [u8; 16];

  #[inline]
  fn algorithm() -> &'static aead::Algorithm { &aead::AES_128_GCM }
}

/// AES256 encryption in GCM mode.
pub struct Aes256Gcm;

impl Algorithm for Aes256Gcm {
  type KEY_BYTES = [u8; 32];
  type NONCE_BYTES = [u8; 12];
  type TAG_BYTES = [u8; 16];

  #[inline]
  fn algorithm() -> &'static aead::Algorithm { &aead::AES_256_GCM }
}

/// CHACHA20 encryption using Poly1305 authentication.
pub struct ChaCha20Poly1305;

impl Algorithm for ChaCha20Poly1305 {
  type KEY_BYTES = [u8; 32];
  type NONCE_BYTES = [u8; 12];
  type TAG_BYTES = [u8; 16];

  #[inline]
  fn algorithm() -> &'static aead::Algorithm { &aead::CHACHA20_POLY1305 }
}
