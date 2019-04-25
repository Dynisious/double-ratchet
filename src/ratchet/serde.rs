//! Defines serde for the [Ratchet] struct.
//! 
//! Author -- daniel.bechaz@gmail.com  
//! Last Moddified --- 2019-04-25

use super::*;
use ::serde::{
  ser::{Serialize, Serializer, SerializeTupleStruct,},
  de::{Deserialize, Deserializer, SeqAccess, Visitor,},
};

static FIELDS: &[&str] = &[
  "state",
];

impl<D, R,> Serialize for Ratchet<D, R,> {
  fn serialize<S,>(&self, serializer: S,) -> Result<S::Ok, S::Error>
    where S: Serializer, {
    let mut serializer = serializer.serialize_tuple_struct(stringify!(Ratchet,), FIELDS.len(),)?;

    serializer.serialize_field(&*self.state,)?;
    serializer.end()
  }
}

impl<'de, D, R,> Deserialize<'de> for Ratchet<D, R,> {
  fn deserialize<Des,>(deserializer: Des,) -> Result<Self, Des::Error>
    where Des: Deserializer<'de>, {
    use ::serde::de::Error;
    use std::fmt;

    struct RatchetVisitor<D, R,> {
      _phantom: PhantomData<(D, R,)>,
    };

    impl<'de, D, R,> Visitor<'de> for RatchetVisitor<D, R,> {
      type Value = Ratchet<D, R,>;

      fn expecting(&self, fmt: &mut fmt::Formatter,) -> fmt::Result {
        write!(fmt, "Expecting a `Ratchet` instance",)
      }
      fn visit_seq<A,>(self, mut seq: A,) -> Result<Self::Value, A::Error>
        where A: SeqAccess<'de>, {
        let state = {
          let state = seq.next_element()?
            .ok_or(A::Error::missing_field(FIELDS[0],),)?;
          
          ClearOnDrop::new(state,)
        };
        let _phantom = PhantomData;

        Ok(Ratchet { state, _phantom, })
      }
    }

    let visitor = RatchetVisitor { _phantom: PhantomData, };

    deserializer.deserialize_tuple_struct(stringify!(Ratchet,), FIELDS.len(), visitor,)
  }
}

#[cfg(test,)]
pub(crate) mod tests {
  use super::*;
  use sha1::Sha1;

  #[test]
  fn test_ratchet_serde() {
    let ratchet = Ratchet::<Sha1,>::from_bytes(&mut [1; 100],);
    let mut serialised = [0u8; 1024];
    let serialised = {
      let writer = &mut serialised.as_mut();

      serde_cbor::to_writer(writer, &ratchet,)
        .expect("Error serialising the Client");
      
      let len = writer.len();
      let len = serialised.len() - len;

      &serialised[..len]
    };
    let other = serde_cbor::from_reader(serialised,)
      .expect("Error deserialising the Client");

    assert!(cmp(&ratchet, &other,), "Client deserialised incorrectly",);
  }
}
