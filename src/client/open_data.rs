//! Defines the OpenData type.
//! 
//! Author -- daniel.bechaz@gmail.com  
//! Last Moddified --- 2019-05-04

use super::Algorithm;
use crate::typenum::{Unsigned, Sum,};
use digest::generic_array::{GenericArray, ArrayLength,};
use clear_on_drop::ClearOnDrop;
use std::{ops, iter::{FromIterator, IntoIterator,}, marker::PhantomPinned,};

mod serde;

/// The data used to seal and open messages.
pub(crate) struct OpenData<Algorithm, AadLength,>
  where Algorithm: super::aead::Algorithm,
    AadLength: ArrayLength<u8>, {
  /// The key data for the key.
  pub key: GenericArray<u8, Algorithm::KeyLength>,
  /// The data for the Nonce.
  pub nonce: GenericArray<u8, Algorithm::NonceLength>,
  /// The Auth data.
  pub aad: GenericArray<u8, AadLength>,
  _pin: PhantomPinned,
}

impl<A, L,> FromIterator<u8> for Box<OpenData<A, L,>>
  where A: Algorithm,
    L: ArrayLength<u8>,
    A::KeyLength: ops::Add<A::NonceLength>,
    <A::KeyLength as ops::Add<A::NonceLength>>::Output: ops::Add<L>,
    <<A::KeyLength as ops::Add<A::NonceLength>>::Output as ops::Add<L>>::Output: ArrayLength<u8>, {
  fn from_iter<Iter,>(iter: Iter,) -> Self
    where Iter: IntoIterator<Item = u8>, {
    let mut data = GenericArray::<u8, Sum<Sum<A::KeyLength, A::NonceLength>, L>>::from_iter(iter.into_iter(),);
    let data = ClearOnDrop::new(data,);
    let mut res = Self::default();

    //Initialise the key.
    let data = {
      let (key, data,) = data.split_at(A::KeyLength::USIZE,);
      
      for (i, b,) in key.iter().cloned().enumerate() { res.key[i] = b  }
      data
    };
    //Initialise the nonce.
    let data = {
      let (nonce, data,) = data.split_at(A::NonceLength::USIZE,);
      
      for (i, b,) in nonce.iter().cloned().enumerate() { res.nonce[i] = b  }
      data
    };
    //Initialise the aad.
    for (i, b,) in data.iter().cloned().enumerate() { res.aad[i] = b  }
    
    res
  }
}

impl<A, L,> Default for OpenData<A, L,>
  where A: Algorithm,
    L: ArrayLength<u8>, {
  fn default() -> Self {
    let key = GenericArray::default();
    let nonce = GenericArray::default();
    let aad = GenericArray::default();

    Self { key, nonce, aad, _pin: PhantomPinned, }
  }
}

impl<A, L,> Drop for OpenData<A, L,>
  where A: Algorithm,
    L: ArrayLength<u8>, {
  fn drop(&mut self,) {
    ClearOnDrop::new(self.key.as_mut_slice(),);
    ClearOnDrop::new(self.nonce.as_mut_slice(),);
    ClearOnDrop::new(self.aad.as_mut_slice(),);
  }
}

#[cfg(test,)]
impl<A, L,> PartialEq for OpenData<A, L,>
  where A: Algorithm, L: ArrayLength<u8>, {
  fn eq(&self, rhs: &Self,) -> bool {
    self.key.as_ref() == rhs.key.as_ref()
    && self.nonce.as_ref() == rhs.nonce.as_ref()
    && self.aad.as_ref() == rhs.aad.as_ref()
  }
}

#[cfg(test,)]
impl<A, L,> Eq for OpenData<A, L,>
  where A: Algorithm, L: ArrayLength<u8>, {}

#[cfg(test,)]
use std::fmt;

#[cfg(test,)]
impl<A, L,> fmt::Debug for OpenData<A, L,>
  where A: Algorithm, L: ArrayLength<u8>, {
  fn fmt(&self, fmt: &mut fmt::Formatter,) -> fmt::Result {
    write!(fmt, "OpenData {{ key: {:?}, nonce: {:?}, aad: {:?}, }}", self.key, self.nonce, self.aad,)
  }
}

#[cfg(test,)]
mod tests {
  use super::*;
  use crate::{ratchet::Ratchet, client::aead::Aes256Gcm, typenum::consts::{U500, U10,},};
  use sha1::Sha1;

  #[test]
  fn test_open_data() {
    let mut ratchet = Ratchet::<Sha1, U500,>::default();
    let open_data = {
      let mut open_data = Box::<OpenData<Aes256Gcm, U10,>>::default();
      
      open_data.key = [96, 149, 164, 51, 173, 213, 159, 182, 206, 187, 58, 123, 215, 152, 83, 152, 92, 169, 226, 107, 227, 4, 27, 148, 3, 112, 214, 244, 31, 84, 114, 224].into();
      open_data.nonce = [65, 41, 58, 133, 81, 205, 95, 163, 184, 167, 212, 199].into();
      open_data.aad = [34, 34, 218, 186, 162, 98, 66, 92, 136, 238].into();
      open_data
    };
    let other = Box::<OpenData<Aes256Gcm, U10,>>::from_iter(&mut ratchet,);

    assert_eq!(other, open_data, "OpenData::from_iter produced unexpected result",);
  }
}
