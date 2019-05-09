//! Defines the [Ratchet] struct.
//! 
//! A [Ratchet] is a cryptographically secure sudo random number generator.
//! 
//! use `--features ratchet-serde` to provide serialisation.
//! 
//! Author -- daniel.bechaz@gmail.com  
//! Last Moddified --- 2019-05-04

#![feature(trusted_len,)]

use hkdf::Hkdf;
use digest::{Input, BlockInput, FixedOutput, Reset,};
use rand_core::{RngCore, SeedableRng, CryptoRng, Error,};
use std::{ops, iter::TrustedLen, marker::PhantomData,};

pub use digest;
pub use digest::generic_array;
pub use generic_array::typenum;

use typenum::{Unsigned, Add1, Diff, bit::B1, consts,};
use generic_array::{GenericArray, ArrayLength,};

#[cfg(feature = "serde")]
mod serde;

/// A HKDF Ratchet which can be used to produce cyptographically secure sudo random bytes.
pub struct Ratchet<Digest, State, Rounds = consts::U1,>
  where State: ArrayLength<u8>, {
  /// The internal state used to produce the next sudo random bytes.
  state: Box<GenericArray<u8, State>>,
  _data: PhantomData<(Digest, Rounds,)>,
}

impl<D, S, R,> Ratchet<D, S, R,>
  where S: ArrayLength<u8>, {
  /// Creates a new `Ratchet` from random state.
  /// 
  /// # Params
  /// 
  /// rand --- The source of random state.  
  pub fn new(rand: &mut dyn RngCore,) -> Self {
    //Allocate the state.
    let mut res = Self::default();

    //Initialise the state.
    rand.fill_bytes(&mut res.state,);

    res
  }
}

impl<'a, D, S, R,> From<&'a mut [u8]> for Ratchet<D, S, R,>
  where S: ArrayLength<u8>, {
  /// Creates a new `Ratchet` from state bytes.
  /// 
  /// If `state` is too short it will be padded.  
  /// `state` will be cleared after creation.  
  /// 
  /// # Params
  /// 
  /// state --- The initial state data.  
  fn from(state: &'a mut [u8],) -> Self {
    //Allocate the state.
    let mut res = Self::default();

    //Initialise the state.
    for (a, b,) in res.state.iter_mut().zip(state.iter().cloned(),) { *a = b }
    //Clear the input bytes.
    for b in state.iter_mut() { *b = 0 }

    res
  }
}

impl<D, S, R,> Default for Ratchet<D, S, R,>
  where S: ArrayLength<u8>, {
  #[inline]
  fn default() -> Self {
    let state = Box::new(GenericArray::default(),);

    Self { state, _data: PhantomData, }
  }
}

impl<D, S, R,> Clone for Ratchet<D, S, R,>
  where S: ArrayLength<u8>, {
  #[inline]
  fn clone(&self,) -> Self {
    let state = self.state.clone();

    Self { state, _data: PhantomData, }
  }
}

impl<D, S, R,> Iterator for Ratchet<D, S, R,>
  where D: Input + BlockInput + FixedOutput + Reset + Default + Clone,
    S: ArrayLength<u8> + ops::Sub<D::BlockSize> + ops::Add<B1> + ops::Sub<B1>,
    R: Unsigned,
    D::BlockSize: Clone,
    <S as ops::Sub<D::BlockSize>>::Output: Unsigned,
    <S as ops::Add<B1>>::Output: ArrayLength<u8>,
    <S as ops::Sub<B1>>::Output: Unsigned, {
  type Item = u8;
  
  #[inline]
  fn size_hint(&self,) -> (usize, Option<usize>,) { (std::usize::MAX, None,) }
  fn next(&mut self,) -> Option<Self::Item> {
    //The output from the hashing.
    let mut okm = GenericArray::<u8, Add1<S>>::default();

    for _ in  0..R::USIZE {
      let (salt, ikm,) = self.state.split_at(Diff::<S, D::BlockSize>::USIZE,);

      //Perform the hash.
      Hkdf::<D>::extract(None, ikm,).expand(salt, &mut okm,)
        .expect("Failed to expand data");
      //Update the internal state.
      self.state.copy_from_slice(&okm[..S::USIZE],);
    }

    //Return the output.
    let res = Some(okm[Diff::<S, B1>::USIZE]);

    //Clear the stack.
    for b in okm.iter_mut() { *b = 0 }

    res
  }
}

unsafe impl<D, S, R,> TrustedLen for Ratchet<D, S, R,>
  where S: ArrayLength<u8>,
    Self: Iterator<Item = u8>, {}

impl<D, S: ArrayLength<u8>, R,> Drop for Ratchet<D, S, R,> {
  #[inline]
  fn drop(&mut self,) { for b in self.state.iter_mut() { *b = 0 } }
}

impl<D, S, R,> RngCore for Ratchet<D, S, R,>
  where S: ArrayLength<u8>,
    Self: TrustedLen<Item = u8>, {
  #[inline]
  fn next_u32(&mut self,) -> u32 { self.next_u64() as u32 }
  #[inline]
  fn next_u64(&mut self,) -> u64 {
    let mut bytes = [0; 8];

    self.fill_bytes(&mut bytes,);
    u64::from_ne_bytes(bytes,)
  }
  #[inline]
  fn fill_bytes(&mut self, dest: &mut [u8],) {
    for (a, b,) in dest.iter_mut().zip(self,) { *a = b }
  }
  #[inline]
  fn try_fill_bytes(&mut self, dest: &mut [u8],) -> Result<(), Error> {
    Ok(self.fill_bytes(dest,))
  }
}

impl<D, S, R,> SeedableRng for Ratchet<D, S, R,>
  where S: ArrayLength<u8>,
    Self: TrustedLen<Item = u8>, {
  type Seed = GenericArray<u8, S>;

  #[inline]
  fn from_seed(mut seed: Self::Seed,) -> Self { seed.as_mut_slice().into() }
}

impl<D, S, R,> CryptoRng for Ratchet<D, S, R,>
  where S: ArrayLength<u8>,
    Self: TrustedLen<Item = u8>, {}

#[cfg(test,)]
impl<D, S, R,> PartialEq for Ratchet<D, S, R,>
  where S: ArrayLength<u8>, {
  #[inline]
  fn eq(&self, rhs: &Self,) -> bool { self.state == rhs.state }
}

#[cfg(test,)]
impl<D, S, R,> Eq for Ratchet<D, S, R,>
  where S: ArrayLength<u8>, {}

#[cfg(test,)]
mod tests {
  use super::*;
  use sha1::Sha1;

  #[test]
  fn test_ratchet_drop() {
    use std::{slice, mem,};

    let mut bytes = {
      let mut bytes = GenericArray::<u8, consts::U500>::default();

      rand::thread_rng().fill_bytes(&mut bytes,);
      
      bytes
    };
    let ratchet = Ratchet::<Sha1, consts::U200,>::from(bytes.as_mut_slice(),);

    assert_eq!(vec![0; bytes.len()], bytes.as_mut_slice(), "Input bytes was not cleared",);

    //Keep a pointer to the state to check that it is cleared on drop.
    let slice = {
      let ptr = &*ratchet.state as *const _ as *const u8;
      let size = ratchet.state.len();
      
      unsafe { slice::from_raw_parts(ptr, size,) }
    };

    mem::drop(ratchet,);

    assert_eq!(vec![0; slice.len()], slice, "Inner state was not cleared",);
  }
  #[test]
  fn test_ratchet_output() {
    use std::collections::HashSet;

    const ROUNDS: usize = 3000;
    let bytes = Ratchet::<Sha1, consts::U64,>::new(&mut rand::thread_rng(),)
      .take(ROUNDS,)
      .collect::<HashSet<_>>();
    
    assert_eq!(256, bytes.len(), "Ratchet is not random",);

    let mut ratchet1 = Ratchet::<Sha1, consts::U64,>::new(&mut rand::thread_rng(),);
    let mut ratchet2 = Ratchet::<Sha1, consts::U64,>::from(ratchet1.state.clone().as_mut_slice(),);
    let out1 = (&mut ratchet1).take(ROUNDS,).collect::<Box<_>>();
    let out2 = (&mut ratchet2).take(ROUNDS,).collect::<Box<_>>();
    
    assert_eq!(&ratchet1.state, &ratchet2.state, "States are not the same",);
    assert_eq!(out1, out2, "Ratchets gave different output.",);
    assert_ne!(ratchet1.next(), None, "Iterator finished",);

    let ratchet2 = Ratchet::<Sha1, consts::U64,>::new(&mut rand::thread_rng(),);
    let out1 = (&mut ratchet1).take(ROUNDS,).collect::<Box<_>>();
    let out2 = ratchet2.take(ROUNDS,).collect::<Box<_>>();
    
    assert_ne!(out1, out2, "Ratchets gave same output.",);
    assert_ne!(ratchet1.next(), None, "Iterator finished",);
  }
}
