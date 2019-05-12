//! Defines the [Ratchet] struct.
//! 
//! A [Ratchet] is a cryptographically secure pseudo random number generator.
//! 
//! use `--features serde` to provide serde implementations.
//! 
//! # Examples
//! 
//! ```rust
//! use ratchet::typenum::consts;
//! use sha1::Sha1;
//! use rand_core::RngCore;
//! 
//! let mut ratchet = ratchet::Ratchet::<Sha1, consts::U100, consts::U5,>::default();
//! let mut bytes = [0; 1024];
//! 
//! ratchet.fill_bytes(&mut bytes,);
//! ```
//! 
//! Author -- daniel.bechaz@gmail.com  
//! Last Moddified --- 2019-05-12

#![feature(trusted_len, generator_trait, never_type,)]
#![deny(missing_docs,)]

use hkdf::Hkdf;
use digest::{Input, BlockInput, FixedOutput, Reset,};
use rand_core::{RngCore, SeedableRng, CryptoRng, Error,};
use clear_on_drop::ClearOnDrop;
use std::{ops, pin::Pin, iter::TrustedLen, marker::{PhantomData, Unpin,},};

pub use digest;
pub use digest::generic_array;
pub use generic_array::typenum;

use typenum::{Unsigned, Add1, Diff, NonZero, bit::B1, consts,};
use generic_array::{GenericArray, ArrayLength,};

#[cfg(feature = "serde")]
mod serde;

/// A HKDF Ratchet which can be used to produce cyptographically secure pseudo random bytes.
pub struct Ratchet<Digest, State, Rounds = consts::U1,>
  where State: ArrayLength<u8>, {
  /// The internal state used to produce the next pseudo random bytes.
  state: ClearOnDrop<GenericArray<u8, State>>,
  _data: PhantomData<(Digest, Rounds,)>,
}

impl<D, S, R,> Ratchet<D, S, R,>
  where S: ArrayLength<u8>, {
  /// Creates a new `Ratchet` from random state.
  /// 
  /// # Params
  /// 
  /// rand --- The source of random state.  
  #[inline]
  pub fn new<Rand,>(rand: &mut Rand,) -> Self
    where Rand: RngCore + CryptoRng, {
    //Allocate the state.
    let mut res = Self::default();

    res.reseed(rand,);

    res
  }
  /// Reseeds the `Ratchet` with random state.
  /// 
  /// # Params
  /// 
  /// rand --- The source of randomness.  
  #[inline]
  pub fn reseed<Rand,>(&mut self, rand: &mut Rand,)
    where Rand: RngCore + CryptoRng, {
    rand.fill_bytes(&mut self.state,)
  }
}

impl<D, S, R,> Ratchet<D, S, R,>
  where D: Input + BlockInput + FixedOutput + Reset + Default + Clone,
    S: ArrayLength<u8> + ops::Sub<D::BlockSize> + ops::Add<B1> + ops::Sub<B1>,
    R: Unsigned + NonZero,
    D::BlockSize: Clone,
    <S as ops::Sub<D::BlockSize>>::Output: Unsigned,
    <S as ops::Add<B1>>::Output: ArrayLength<u8>,
    <S as ops::Sub<B1>>::Output: Unsigned, {
  /// Generates the next pseudo random byte.
  pub fn next(&mut self,) -> u8 {
    //The output from the hashing round.
    let mut okm = GenericArray::<u8, Add1<S>>::default();
    let mut okm = ClearOnDrop::new(okm.as_mut(),);

    for _ in  0..R::USIZE {
      let (salt, ikm,) = self.state.split_at(Diff::<S, D::BlockSize>::USIZE,);

      //Perform the hash.
      Hkdf::<D>::extract(None, ikm,).expand(salt, &mut okm,)
        .expect("Failed to expand data");
      //Update the internal state.
      self.state.copy_from_slice(&okm[..S::USIZE],);
    }

    //Return the output.
    okm[Diff::<S, B1>::USIZE]
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
  #[inline]
  fn from(state: &'a mut [u8],) -> Self {
    let state = ClearOnDrop::new(state,);
    let mut res = Self::default();
    let len = usize::min(state.len(), res.state.len(),);
    
    res.state[..len].copy_from_slice(&state,);

    res
  }
}

impl<D, S, R,> Default for Ratchet<D, S, R,>
  where S: ArrayLength<u8>, {
  #[inline]
  fn default() -> Self {
    Self {
      state: ClearOnDrop::new(GenericArray::default(),),
      _data: PhantomData,
    }
  }
}

impl<D, S, R,> Clone for Ratchet<D, S, R,>
  where S: ArrayLength<u8>, {
  #[inline]
  fn clone(&self,) -> Self {
    let mut res = Self::default();

    res.state.copy_from_slice(&self.state,);

    res
  }
}

impl<D, S, R,> Iterator for Ratchet<D, S, R,>
  where D: Input + BlockInput + FixedOutput + Reset + Default + Clone,
    S: ArrayLength<u8> + ops::Sub<D::BlockSize> + ops::Add<B1> + ops::Sub<B1>,
    R: Unsigned + NonZero,
    D::BlockSize: Clone,
    <S as ops::Sub<D::BlockSize>>::Output: Unsigned,
    <S as ops::Add<B1>>::Output: ArrayLength<u8>,
    <S as ops::Sub<B1>>::Output: Unsigned, {
  type Item = u8;
  
  #[inline]
  fn size_hint(&self,) -> (usize, Option<usize>,) { (std::usize::MAX, None,) }
  #[inline]
  fn next(&mut self,) -> Option<Self::Item> { Some(self.next()) }
}

unsafe impl<D, S, R,> TrustedLen for Ratchet<D, S, R,>
  where S: ArrayLength<u8>,
    Self: Iterator<Item = u8>, {}

impl<D, S, R,> RngCore for Ratchet<D, S, R,>
  where S: ArrayLength<u8>,
    Self: TrustedLen<Item = u8>, {
  #[inline]
  fn next_u32(&mut self,) -> u32 { self.next_u64() as u32 }
  #[inline]
  fn next_u64(&mut self,) -> u64 {
    let mut bytes = [0; 8];

    self.fill_bytes(bytes.as_mut(),);
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
  fn from_seed(mut seed: Self::Seed,) -> Self { seed.as_mut().into() }
}

impl<D, S, R,> CryptoRng for Ratchet<D, S, R,>
  where S: ArrayLength<u8>,
    Self: TrustedLen<Item = u8>, {}

impl<D, S, R,> ops::Generator for Ratchet<D, S, R,>
  where S: ArrayLength<u8>,
    Self: TrustedLen<Item = u8> + Unpin, {
  type Yield = u8;
  type Return = !;

  #[inline]
  fn resume(self: Pin<&mut Self>,) -> ops::GeneratorState<Self::Yield, Self::Return> {
    use std::slice;

    let mut byte = 0;

    self.get_mut().fill_bytes(slice::from_mut(&mut byte,),);

    ops::GeneratorState::Yielded(byte,)
  }
}

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
  fn test_ratchet_output() {
    use std::collections::HashSet;

    const ROUNDS: usize = 3000;
    let bytes = Ratchet::<Sha1, consts::U64,>::new(&mut rand::thread_rng(),)
      .take(ROUNDS,)
      .collect::<HashSet<_>>();
    
    assert_eq!(256, bytes.len(), "Ratchet is not random",);

    let mut ratchet1 = Ratchet::<Sha1, consts::U64,>::new(&mut rand::thread_rng(),);
    let mut ratchet2 = Ratchet::<Sha1, consts::U64,>::from((*ratchet1.state.clone()).as_mut(),);
    let out1 = (&mut ratchet1).take(ROUNDS,).collect::<Box<_>>();
    let out2 = (&mut ratchet2).take(ROUNDS,).collect::<Box<_>>();
    
    assert_eq!(&ratchet1.state, &ratchet2.state, "States are not the same",);
    assert_eq!(out1, out2, "Ratchets gave different output.",);
    
    let ratchet2 = Ratchet::<Sha1, consts::U64,>::new(&mut rand::thread_rng(),);
    let out1 = (&mut ratchet1).take(ROUNDS,).collect::<Box<_>>();
    let out2 = ratchet2.take(ROUNDS,).collect::<Box<_>>();
    
    assert_ne!(out1, out2, "Ratchets gave same output.",);
  }
}
