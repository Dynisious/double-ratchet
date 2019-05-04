//! Defines the [Ratchet] struct.
//! 
//! Author -- daniel.bechaz@gmail.com  
//! Last Moddified --- 2019-05-04

use crate::typenum::{Unsigned, Add1, Diff, bit::B1, consts,};
use hkdf::Hkdf;
use digest::{Input, BlockInput, FixedOutput, Reset,};
use digest::generic_array::{GenericArray, ArrayLength,};
use clear_on_drop::ClearOnDrop;
use std::{ops, iter::TrustedLen, marker::PhantomData,};

mod serde;

/// A HKDF Ratchet which can be used to produce cyptographically secure sudo random bytes.
pub struct Ratchet<Digest, State, Rounds = consts::U1,>
  where State: ArrayLength<u8>, {
  /// The internal state used to produce the next sudo random bytes.
  state: Box<GenericArray<u8, State>>,
  _data: PhantomData<(Digest, Rounds,)>,
}

impl<D, S, R,> Ratchet<D, S, R,>
  where D: BlockInput,
    S: ArrayLength<u8> + ops::Sub<D::BlockSize>,
    <S as ops::Sub<D::BlockSize>>::Output: Unsigned, {
  /// Creates a new `Ratchet` from state bytes.
  /// 
  /// If `state` is too short it will be padded.  
  /// `state` will be cleared after creation.  
  /// 
  /// # Params
  /// 
  /// state --- The initial state data.  
  pub fn new(state: &mut [u8],) -> Self {
    //Iterate over the input bytes.
    let state = ClearOnDrop::new(state,);
    //Allocate the state.
    let mut res = Self::default();

    //Initialise the state.
    for (a, b,) in res.state.iter_mut().zip(state.iter().cloned(),) { *a = b }

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

impl<D, S: ArrayLength<u8>, R,> Clone for Ratchet<D, S, R,> {
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
    let mut okm = ClearOnDrop::new(&mut okm,);

    for _ in  0..R::USIZE {
      let (salt, ikm,) = self.state.split_at(Diff::<S, D::BlockSize>::USIZE,);

      //Perform the hash.
      Hkdf::<D>::extract(None, ikm,).expand(salt, &mut okm,)
        .expect("Failed to expand data");
      //Update the internal state.
      self.state.copy_from_slice(&okm[..S::USIZE],);
    }

    //Return the output.
    Some(okm[Diff::<S, B1>::USIZE])
  }
}

unsafe impl<D, S, R,> TrustedLen for Ratchet<D, S, R,>
  where D: Input + BlockInput + FixedOutput + Reset + Default + Clone,
    S: ArrayLength<u8> + ops::Sub<D::BlockSize> + ops::Add<B1> + ops::Sub<B1>,
    R: Unsigned,
    D::BlockSize: Clone,
    <S as ops::Sub<D::BlockSize>>::Output: Unsigned,
    <S as ops::Add<B1>>::Output: ArrayLength<u8>,
    <S as ops::Sub<B1>>::Output: Unsigned, {}

impl<D, S: ArrayLength<u8>, R,> Drop for Ratchet<D, S, R,> {
  #[inline]
  fn drop(&mut self,) {
    ClearOnDrop::new(self.state.as_mut_slice(),);
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
  fn test_ratchet_drop() {
    use std::{slice, mem,};

    let mut bytes = [1; 20];
    let ratchet = Ratchet::<Sha1, consts::U500,>::new(&mut bytes,);

    assert_eq!(bytes, [0; 20], "Input bytes was not cleared",);

    //Keep a pointer to the state to check that it is cleared on drop.
    let slice = {
      let ptr = &*ratchet.state as *const _ as *const u8;
      let size = ratchet.state.len();
      
      unsafe { slice::from_raw_parts(ptr, size,) }
    };

    mem::drop(ratchet,);

    assert_eq!(vec![0u8; slice.len()].as_slice(), slice, "Inner state was not cleared",);
  }
  #[test]
  fn test_ratchet_output() {
    use std::collections::HashSet;

    let rounds = if cfg!(features = "test-large-output",) { 10000 } else { 100 };
    let bytes = Ratchet::<Sha1, consts::U500,>::default()
      .take(2048,)
      .collect::<HashSet<_>>();
    
    assert_eq!(256, bytes.len(), "Ratchet is not random unexpected",);

    let mut ratchet1 = Ratchet::<Sha1, consts::U500,>::default();
    let ratchet2 = Ratchet::<Sha1, consts::U500,>::new([0; consts::U500::USIZE].as_mut(),);

    assert_eq!(&ratchet1.state, &ratchet2.state, "Initial states are not the same",);

    let iter = (&mut ratchet1).zip(ratchet2,)
      .map(|(a, b,),| a == b,)
      .enumerate()
      .take(rounds,);

    for (round, check,) in iter {
      assert!(check, "Ratchets diverged on round {}", round,);
    }

    assert_ne!(ratchet1.next(), None, "Iterator finished",);

    let ratchet2 = Ratchet::<Sha1, consts::U500,>::new([1; consts::U500::USIZE].as_mut(),);
    let iter = (&mut ratchet1).zip(ratchet2,)
      .map(|(a, b,),| a != b,)
      .enumerate()
      .take(rounds,);

    for (round, check,) in iter {
      assert!(check, "Ratchets converged on round {}", round,);
    }

    assert_ne!(ratchet1.next(), None, "Iterator finished",);
  }
}
