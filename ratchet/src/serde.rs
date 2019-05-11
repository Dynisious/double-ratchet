//! Defines serde for the [Ratchet] struct.
//! 
//! Author -- daniel.bechaz@gmail.com  
//! Last Moddified --- 2019-05-11

use super::*;
use ::serde::{
  ser::{Serialize, Serializer, SerializeTupleStruct,},
  de::{Deserialize, Deserializer, SeqAccess, Visitor,},
};

static STATE: &[&str] = &[
  "state",
];

impl<D, S, R,> Serialize for Ratchet<D, S, R,>
  where S: ArrayLength<u8>, {
  fn serialize<Ser,>(&self, serializer: Ser,) -> Result<Ser::Ok, Ser::Error>
    where Ser: Serializer, {
    let mut serializer = serializer.serialize_tuple_struct(stringify!(Ratchet,), FIELDS.len(),)?;

    serializer.serialize_field::<[u8]>(self.state.as_slice(),)?;
    serializer.end()
  }
}

impl<'de, D, S: 'de, R,> Deserialize<'de> for Ratchet<D, S, R,>
  where S: ArrayLength<u8>, {
  fn deserialize<Des,>(deserializer: Des,) -> Result<Self, Des::Error>
    where Des: Deserializer<'de>, {
    use ::serde::de::Error;
    use std::fmt;

    struct Visitor;

    impl<'de, D, S: 'de, R,> Visitor<'de> for Visitor {
      type Value = Ratchet<D, S, R,>;

      #[inline]
      fn expecting(&self, fmt: &mut fmt::Formatter,) -> fmt::Result {
        write!(fmt, "Expecting a tuple of length {}", FIELDS.len(),)
      }
      #[inline]
      fn visit_seq<A,>(self, mut seq: A,) -> Result<Self::Value, A::Error>
        where A: SeqAccess<'de>, {
        let mut state = seq.next_element::<Box<[u8],>>()?
          .ok_or(A::Error::missing_field(FIELDS[0],),)?;
        
        Ok(Self::Value::from(state.as_mut(),),);
      }
    }

    deserializer.deserialize_tuple_struct(stringify!(Ratchet,), FIELDS.len(), Visitor,)
  }
}

#[cfg(test,)]
pub mod tests {
  use super::*;
  use sha1::Sha1;

  #[test]
  fn test_ratchet_serde() {
    let ratchet = Ratchet::<Sha1, consts::U32,>::new(&mut rand::thread_rng(),);
    let mut serialised = [0u8; 1024];
    let serialised = {
      let writer = &mut &mut serialised.as_mut();

      serde_cbor::to_writer_packed(writer, &ratchet,)
        .expect("Error serialising the Client");
      
      let len = writer.len();
      let len = serialised.len() - len;

      &serialised[..len]
    };
    let other = serde_cbor::from_reader(serialised,)
      .expect("Error deserialising the Ratchet");

    assert!(ratchet == other, "Ratchet deserialised incorrectly",);
  }
}
