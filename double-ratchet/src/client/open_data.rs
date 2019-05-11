//! Defines the OpenData type.
//! 
//! Author -- daniel.bechaz@gmail.com  
//! Last Moddified --- 2019-05-11

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

impl<A, L,> Default for OpenData<A, L,>
  where A: Algorithm,
    L: ArrayLength<u8>, {
  fn default() -> Self {
    let key = ClearOnDrop::new(GenericArray::default(),);
    let nonce = ClearOnDrop::new(GenericArray::default(),);
    let aad = ClearOnDrop::new(GenericArray::default(),);

    Self { key, nonce, aad, }
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

#[cfg(test,)]
mod tests {
  use super::*;
  use crate::{ratchet::Ratchet, client::aead::Aes256Gcm, typenum::consts,};
  use sha1::Sha1;

  #[test]
  fn test_open_data() {
    let mut ratchet = Ratchet::<Sha1, consts::U500,>::default();
    let open_data = {
      let mut open_data = OpenData::<Aes256Gcm, consts::U10,>::default();
      
      open_data.key = ClearOnDrop::new([96, 149, 164, 51, 173, 213, 159, 182, 206, 187, 58, 123, 215, 152, 83, 152, 92, 169, 226, 107, 227, 4, 27, 148, 3, 112, 214, 244, 31, 84, 114, 224].into(),);
      open_data.nonce = ClearOnDrop::new([65, 41, 58, 133, 81, 205, 95, 163, 184, 167, 212, 199].into(),);
      open_data.aad = ClearOnDrop::new([34, 34, 218, 186, 162, 98, 66, 92, 136, 238].into(),);
      open_data
    };
    let other = OpenData::<Aes256Gcm, consts::U10,>::new(&mut ratchet,);

    assert!(other == open_data, "OpenData::new produced unexpected result",);
  }
}
