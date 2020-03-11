//! Defines serde for the [Ratchet] struct.
//! 
//! Author -- daniel.bechaz@gmail.com  
//! Last Moddified --- 2020-03-11

#![cfg(feature = "serde")]

use super::*;
use ::serde::{
  ser::{Serialize, Serializer,},
  de::{Deserialize, Deserializer, SeqAccess, Visitor,},
};

impl<D, S, O, R,> Serialize for Ratchet<D, S, O, R,>
  where S: ArrayLength<u8>,
    O: ArrayLength<u8>, {
  fn serialize<Ser,>(&self, serializer: Ser,) -> Result<Ser::Ok, Ser::Error>
    where Ser: Serializer, {
    Serialize::serialize(self.state.as_ref(), serializer,)
  }
}

impl<'de, D, S: 'de, O, R,> Deserialize<'de> for Ratchet<D, S, O, R,>
  where S: ArrayLength<u8>,
    O: ArrayLength<u8>, {
  fn deserialize<Des,>(deserializer: Des,) -> Result<Self, Des::Error>
    where Des: Deserializer<'de>, {
    use ::serde::de::Error;
    use std::fmt;

    struct RatchetVisitor<D, S, O, R,>(PhantomData<(D, S, O, R,)>,);

    impl<'de, D, S, O, R,> Visitor<'de> for RatchetVisitor<D, S, O, R,>
      where S: ArrayLength<u8>,
        O: ArrayLength<u8>, {
      type Value = Ratchet<D, S, O, R,>;

      #[inline]
      fn expecting(&self, fmt: &mut fmt::Formatter,) -> fmt::Result {
        write!(fmt, "a byte sequence of length {}", S::USIZE,)
      }
      fn visit_bytes<E,>(self, v: &[u8],) -> Result<Self::Value, E>
        where E: Error, {
        //Check that the length of the bytes is correct.
        if v.len() != S::USIZE { return Err(E::invalid_length(v.len(), &self,)) }

        let mut new = Self::Value::default();

        //Copy the bytes out.
        new.state.copy_from_slice(v,);

        Ok(new,)
      }
      fn visit_seq<A,>(self, mut seq: A,) -> Result<Self::Value, A::Error>
        where A: SeqAccess<'de>, {
        let mut new = Self::Value::default();

        //Read out all of the bytes from the sequence.
        for index in 0..S::USIZE {
          new.state[index] = match seq.next_element()? {
            Some(v) => v,
            None => return Err(Error::invalid_length(index, &self,)),
          }
        }

        Ok(new,)
      }
    }

    deserializer.deserialize_bytes(RatchetVisitor(PhantomData,),)
  }
}

#[cfg(test,)]
pub mod tests {
  use super::*;
  use sha1::Sha1;

  #[test]
  fn test_ratchet_serde() {
    let ratchet = Ratchet::<Sha1, consts::U32, consts::U32,>::new(&mut rand::thread_rng(),);
    let mut serialised = [0u8; 1024];
    let serialised = {
      let mut writer = &mut serialised.as_mut();

      serde_cbor::ser::to_writer(&mut writer, &ratchet,)
        .expect("Error serialising the Client");
      
      let len = writer.len();
      let len = serialised.len() - len;

      &serialised[..len]
    };
    let other = serde_cbor::de::from_reader(serialised,)
      .expect("Error deserialising the Ratchet");

    assert!(ratchet == other, "Ratchet deserialised incorrectly",);
  }
}
