//! Defines the [Ratchet] struct.
//! 
//! Author -- daniel.bechaz@gmail.com  
//! Last Moddified --- 2019-04-20

use hkdf::Hkdf;
use digest::{Input, BlockInput, FixedOutput, Reset,};
use generic_array::typenum::{consts, Unsigned,};
use clear_on_drop::ClearOnDrop;
use std::{iter, marker::PhantomData,};

mod serde;

/// A HKDF Ratchet which can be used to produce cyptographically secure sudo random bytes.
pub struct Ratchet<Digest, Rounds = consts::U1,> {
  /// The internal state used to produce the next sudo random bytes.
  state: ClearOnDrop<Box<[u8]>>,
  _phantom: PhantomData<(Digest, Rounds,)>,
}

impl<D, R,> Ratchet<D, R,>
  where D: Input + BlockInput + FixedOutput + Reset + Clone + Default,
    <D as BlockInput>::BlockSize: Clone,
    R: Unsigned, {
  /// Creates a new `Ratchet` from raw state bytes.
  /// 
  /// The `state` must be at least `D::BlockSize` bytes; any extra bytes are used as salt
  /// in the `Hash Key Derivation` rounds.
  /// 
  /// # Params
  /// 
  /// state --- The initial state data.  
  /// 
  /// # Panics
  /// 
  /// * If `state.len() < D::BlockSize` because there is not enough data to form a full hash input.
  pub fn new(state: Box<[u8]>,) -> Self {
    assert!(state.len() >= <D as BlockInput>::BlockSize::USIZE, "state.len() < D::BlockSize",);

    let state = ClearOnDrop::new(state,);

    Self { state, _phantom: PhantomData, }
  }
  /// Creates a new `Ratchet` from bytes.
  /// 
  /// Applies padding if the input state is too small.
  /// 
  /// # Params
  /// 
  /// bytes --- The initial byte data.  
  /// 
  /// # Warning
  /// 
  /// `bytes` will be cleared when this function returns.
  pub fn from_bytes(bytes: &mut [u8],) -> Self {
    //Pad the input bytes, create the state, and clear the input.
    let state = ClearOnDrop::new(
      ClearOnDrop::new(bytes,).iter()
      .cloned()
      .chain(iter::repeat(0,)
        .take(<D as BlockInput>::BlockSize::USIZE,),
      )
      .collect(),
    );

    Self { state, _phantom: PhantomData, }
  }
  /// Produces the next output from the `Ratchet`.
  /// 
  /// # Prams
  /// 
  /// out_len --- The length of the byte sequence output.  
  pub fn advance(&mut self, out_len: usize,) -> Result<Vec<u8>, ()> {
    use std::io::Write;

    //Allocate memory for the output.
    let mut data = {
      //Check that the length of the output wont overflow a usize.
      let len = self.state.len().checked_add(out_len,)
        .ok_or(())?;
      //Allocate enough capacity.
      let mut data = Vec::with_capacity(len,);

      //Allocate the initial space.
      data.extend(iter::repeat(0,).take(self.state.len(),),);
      data
    };

    //---Perform rounds of hashing---
    //Initialise the input fields. 
    let (ikm, salt,) = self.state.split_at_mut(<D::BlockSize as Unsigned>::USIZE,);
    let mut msalt = if salt.is_empty() { None }
      else { Some(&*salt) };

    //Perform hashing rounds.
    for _ in 0..R::USIZE {
      //Perform the HKDF round.
      Hkdf::<D>::extract(msalt.take().map(move |v,| &*v,), ikm,)
        .expand(salt, &mut data,)
        .or(Err(()),)?;
      
      //Update the inputs.
      ikm.copy_from_slice(&data[..ikm.len()],);
      salt.copy_from_slice(&data[ikm.len()..],);
      msalt = if salt.is_empty() { None }
        else { Some(salt) };
    }

    //Allocate extra data such that there will be `out_len` extra bytes.
    data.extend(iter::repeat(0,).take(out_len,),);
    //Perform the final extract and expand round.
    Hkdf::<D>::extract(msalt.take().map(move |v,| &*v,), ikm,)
      .expand(&salt, &mut data,)
      .or(Err(()),)?;
    
    //Move the data needed for the internal state and clear the original data.
    (&mut *self.state).write_all(&ClearOnDrop::new(data.split_at_mut(out_len,).1,),)
      .or(Err(()),)?;
    
    //Truncate the zeroed state data off of the end of `data`.
    data.truncate(out_len,);
    Ok(data)
  }
}

#[cfg(test,)]
#[inline]
pub(crate) fn cmp<D, R,>(lhs: &Ratchet<D, R,>, rhs: &Ratchet<D, R,>,) -> bool {
  lhs.state == rhs.state
}

#[cfg(test,)]
mod tests {
  use super::*;
  use sha1::Sha1;

  #[test]
  fn test_ratchet_drop() {
    use std::{slice, mem,};

    let mut bytes = [1; 20];
    let ratchet = Ratchet::<Sha1,>::from_bytes(&mut bytes,);

    assert_eq!(bytes, [0; 20], "Input bytes was not cleared",);

    let ptr = &*ratchet.state as *const _ as *const u8;
    let size = ratchet.state.len();
    let slice = unsafe { slice::from_raw_parts(ptr, size,) };

    mem::drop(ratchet,);

    assert_eq!(slice, vec![0u8; size].as_slice(), "Inner state was not cleared",);
  }
  #[test]
  fn test_ratchet_output() {
    use std::collections::HashSet;

    const OUT_LEN: usize = 256;

    let mut ratchet1 = Ratchet::<Sha1,>::from_bytes(&mut [],);
    let mut ratchet2 = Ratchet::<Sha1,>::new(
      vec![0; <Sha1 as BlockInput>::BlockSize::USIZE].into_boxed_slice(),
    );

    assert_eq!(&ratchet1.state, &ratchet2.state, "Initial states are not the same",);

    let mut outputs = HashSet::new();
    #[cfg(features = "test-large-output",)]
    const ROUNDS: usize = 10000;
    #[cfg(not(features = "test-output",),)]
    const ROUNDS: usize = 100;

    for _ in 1..=ROUNDS {
      let out1 = ratchet1.advance(OUT_LEN,)
        .expect("Error advancing ratchet1");
      let out2 = ratchet2.advance(OUT_LEN,)
        .expect("Error advancing ratchet2");

      assert_eq!(out1, out2, "Ratchet output is not identical",);
      assert!(outputs.insert(out1.clone(),), "Ratchet output has been produced before",);
    }
  }
}
