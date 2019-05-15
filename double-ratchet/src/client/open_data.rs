//! Defines the OpenData type.
//! 
//! Author -- daniel.bechaz@gmail.com  
//! Last Moddified --- 2019-05-12

use super::Algorithm;
use crate::generic_array::{GenericArray, ArrayLength,};
use rand::{RngCore, CryptoRng,};
use clear_on_drop::ClearOnDrop;

mod serde;

/// The data used to seal and open messages.
pub(crate) struct OpenData<Algorithm, AadLength,>
  where Algorithm: super::aead::Algorithm,
    AadLength: ArrayLength<u8>, {
  /// The key data for the key.
  pub key: ClearOnDrop<GenericArray<u8, Algorithm::KeyLength>>,
  /// The data for the Nonce.
  pub nonce: ClearOnDrop<GenericArray<u8, Algorithm::NonceLength>>,
  /// The Auth data.
  pub aad: ClearOnDrop<GenericArray<u8, AadLength>>,
}

impl<A, L,> OpenData<A, L,>
  where A: Algorithm,
    L: ArrayLength<u8>, {
  /// Constructs a new OpenData from RNG.
  /// 
  /// # Params
  /// 
  /// rand --- The source of randomness to use.  
  #[inline]
  pub fn new<Rand,>(rand: &mut Rand,) -> Self
    where Rand: CryptoRng + RngCore, {
    let mut res = Self::default();

    //Initialise the key.
    rand.fill_bytes(&mut res.key,);
    //Initialise the nonce.
    rand.fill_bytes(&mut res.nonce,);
    //Initialise the aad.
    rand.fill_bytes(&mut res.aad,);
    
    res
  }
}

#[cfg(test,)]
impl<A, L,> PartialEq for OpenData<A, L,>
  where A: Algorithm,
    L: ArrayLength<u8>, {
  fn eq(&self, rhs: &Self,) -> bool {
    self.key.as_ref() == rhs.key.as_ref()
    && self.nonce.as_ref() == rhs.nonce.as_ref()
    && self.aad.as_ref() == rhs.aad.as_ref()
  }
}

#[cfg(test,)]
impl<A, L,> Eq for OpenData<A, L,>
  where A: Algorithm,
    L: ArrayLength<u8>, {}

impl<A, L,> Default for OpenData<A, L,>
  where A: Algorithm,
    L: ArrayLength<u8>, {
  #[inline]
  fn default() -> Self {
    Self {
      key: ClearOnDrop::new(GenericArray::default(),),
      nonce: ClearOnDrop::new(GenericArray::default(),),
      aad: ClearOnDrop::new(GenericArray::default(),),
    }
  }
}
