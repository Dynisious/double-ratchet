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
//! Author -- DMorgan  
//! Last Moddified --- 2020-03-11

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

use typenum::{Unsigned, Diff, Sum, NonZero, consts,};
use generic_array::{GenericArray, ArrayLength,};

mod serde;

/// A HKDF Ratchet which can be used to produce cyptographically secure pseudo random bytes.
pub struct Ratchet<Digest, StateSize, OutputSize, Rounds = consts::U1,>
  where StateSize: ArrayLength<u8>,
    OutputSize: ArrayLength<u8>, {
  /// The internal state used to produce the next pseudo random bytes.
  state: ClearOnDrop<GenericArray<u8, StateSize>>,
  _data: PhantomData<(Digest, OutputSize, Rounds,)>,
}

impl<D, S, O, R,> Ratchet<D, S, O, R,>
  where S: ArrayLength<u8>,
    O: ArrayLength<u8>, {
  /// Creates a new `Ratchet` from random state.
  /// 
  /// # Params
  /// 
  /// rand --- The source of random state.  
  #[inline]
  pub fn new<Rand,>(rand: &mut Rand,) -> Self
    where Rand: RngCore + CryptoRng, {
    //Allocate the state.
    let mut new = Self::default();

    new.reseed(rand,);

    new
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

impl<D, S, O, R,> Ratchet<D, S, O, R,>
  where D: Input + BlockInput + FixedOutput + Reset + Default + Clone,
    S: ArrayLength<u8> + ops::Sub<D::BlockSize> + ops::Add<O>,
    O: ArrayLength<u8>,
    R: Unsigned + NonZero,
    D::BlockSize: Clone,
    Sum<S, O>: ArrayLength<u8>,
    Diff<S, D::BlockSize>: Unsigned, {
  /// Generates the next pseudo random byte.
  pub fn next(&mut self,) -> GenericArray<u8, O> {
    //The output from the hashing round.
    let mut okm = GenericArray::<u8, Sum<S, O>>::default();
    let mut okm = ClearOnDrop::new(okm.as_mut(),);

    for _ in  0..R::USIZE {
      let (salt, ikm,) = self.state.split_at(Diff::<S, D::BlockSize>::USIZE,);

      //Perform the hash.
      Hkdf::<D>::extract(None, ikm,).1.expand(salt, &mut okm,)
        .expect("Failed to expand data");
      //Update the internal state.
      self.state.copy_from_slice(&okm[..S::USIZE],);
    }

    //Return the output.
    GenericArray::clone_from_slice(&okm[S::USIZE..],)
  }
}

impl<D, S, O, R,> Iterator for Ratchet<D, S, O, R,>
  where D: Input + BlockInput + FixedOutput + Reset + Default + Clone,
    S: ArrayLength<u8> + ops::Sub<D::BlockSize> + ops::Add<O>,
    O: ArrayLength<u8>,
    R: Unsigned + NonZero,
    D::BlockSize: Clone,
    Sum<S, O>: ArrayLength<u8>,
    Diff<S, D::BlockSize>: Unsigned, {
  type Item = GenericArray<u8, O>;

  #[inline]
  fn size_hint(&self,) -> (usize, Option<usize>,) { (usize::max_value(), None,) }
  #[inline]
  fn next(&mut self,) -> Option<Self::Item> { Some(Ratchet::next(self,)) }
}

unsafe impl<D, S, O, R,> TrustedLen for Ratchet<D, S, O, R,>
  where S: ArrayLength<u8>,
    O: ArrayLength<u8>,
    Self: Iterator, {}

impl<'a, D, S, O, R,> From<&'a mut [u8]> for Ratchet<D, S, O, R,>
  where S: ArrayLength<u8>,
    O: ArrayLength<u8>, {
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
    let mut new = Self::default();
    let len = usize::min(state.len(), new.state.len(),);
    
    new.state[..len].copy_from_slice(&state,);

    new
  }
}

impl<D, S, O, R,> Default for Ratchet<D, S, O, R,>
  where S: ArrayLength<u8>,
    O: ArrayLength<u8>, {
  #[inline]
  fn default() -> Self {
    Self {
      state: ClearOnDrop::new(GenericArray::default(),),
      _data: PhantomData,
    }
  }
}

impl<D, S, O, R,> Clone for Ratchet<D, S, O, R,>
  where S: ArrayLength<u8>,
    O: ArrayLength<u8>, {
  #[inline]
  fn clone(&self,) -> Self {
    let mut new = Self::default();

    new.clone_from(self,); new
  }
  #[inline]
  fn clone_from(&mut self, source: &Self,) {
    self.state.copy_from_slice(&source.state,)
  }
}

impl<D, S, O, R,> RngCore for Ratchet<D, S, O, R,>
  where S: ArrayLength<u8>,
    O: ArrayLength<u8>,
    Self: Iterator<Item = GenericArray<u8, O>>, {
  #[inline]
  fn next_u32(&mut self,) -> u32 { self.next_u64() as u32 }
  fn next_u64(&mut self,) -> u64 {
    let mut bytes = [0; 8];

    self.fill_bytes(bytes.as_mut(),);
    u64::from_ne_bytes(bytes,)
  }
  fn fill_bytes(&mut self, dest: &mut [u8],) {
    for (a, b,) in dest.iter_mut().zip(self.flatten(),) { *a = b }
  }
  #[inline]
  fn try_fill_bytes(&mut self, dest: &mut [u8],) -> Result<(), Error> {
    Ok(self.fill_bytes(dest,))
  }
}

impl<D, S, O, R,> SeedableRng for Ratchet<D, S, O, R,>
  where S: ArrayLength<u8>,
    O: ArrayLength<u8>, {
  type Seed = GenericArray<u8, S>;

  #[inline]
  fn from_seed(mut seed: Self::Seed,) -> Self { seed.as_mut().into() }
}

impl<D, S, O, R,> CryptoRng for Ratchet<D, S, O, R,>
  where S: ArrayLength<u8>,
    O: ArrayLength<u8>, {}

impl<D, S, O, R, A,> ops::Generator<A,> for Ratchet<D, S, O, R,>
  where S: ArrayLength<u8>,
    O: ArrayLength<u8>,
    Self: Iterator<Item = GenericArray<u8, O>> + Unpin, {
  type Yield = GenericArray<u8, O>;
  type Return = !;

  fn resume(self: Pin<&mut Self>, _: A,) -> ops::GeneratorState<Self::Yield, Self::Return> {
    match self.get_mut().next() {
      Some(v) => ops::GeneratorState::Yielded(v,),
      None => unsafe { core::hint::unreachable_unchecked() },
    }
  }
}

#[cfg(test,)]
impl<D, S, O, R,> PartialEq for Ratchet<D, S, O, R,>
  where S: ArrayLength<u8>,
    O: ArrayLength<u8>, {
  #[inline]
  fn eq(&self, rhs: &Self,) -> bool { self.state == rhs.state }
}

#[cfg(test,)]
impl<D, S, O, R,> Eq for Ratchet<D, S, O, R,>
  where S: ArrayLength<u8>,
    O: ArrayLength<u8>, {}

#[cfg(test,)]
mod tests {
  use super::*;
  use sha1::Sha1;

  #[test]
  fn test_ratchet_output() {
    const ROUNDS: usize = 3000;

    let mut ratchet1 = Ratchet::<Sha1, consts::U64, consts::U64,>::new(&mut rand::thread_rng(),);
    let mut ratchet2 = Ratchet::<Sha1, consts::U64, consts::U64,>::from((*ratchet1.state.clone()).as_mut(),);
    let out1 = (&mut ratchet1).take(ROUNDS,).collect::<Box<_>>();
    let out2 = (&mut ratchet2).take(ROUNDS,).collect::<Box<_>>();
    
    assert_eq!(&ratchet1.state, &ratchet2.state, "States are not the same",);
    assert_eq!(out1, out2, "Ratchets gave different output.",);
    
    let ratchet2 = Ratchet::<Sha1, consts::U64, consts::U64,>::new(&mut rand::thread_rng(),);
    let out1 = (&mut ratchet1).take(ROUNDS,).collect::<Box<_>>();
    let out2 = ratchet2.take(ROUNDS,).collect::<Box<_>>();
    
    assert_ne!(out1, out2, "Ratchets gave same output.",);
  }
}
