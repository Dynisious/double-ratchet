//! Defines serde for OpenClient.
//! 
//! Author -- daniel.bechaz@gmail.com  
//! Last Moddified --- 2019-05-11

use super::*;
use ::serde::{
  ser::{Serialize, Serializer, SerializeTupleStruct,},
  de::{Deserialize, Deserializer, SeqAccess, Visitor,},
};
use std::marker::PhantomData;

static FIELDS: &[&str] = &[
  "ratchet",
  "sent_count",
  "current_public_key",
  "current_keys",
  "previous_keys",
];

impl<D, S, A, R, L,> Serialize for OpenClient<D, S, A, R, L,>
  where S: ArrayLength<u8>,
    A: Algorithm,
    L: ArrayLength<u8>, {
  fn serialize<Ser,>(&self, serializer: Ser,) -> Result<Ser::Ok, Ser::Error>
    where Ser: Serializer, {
    let mut serializer = serializer.serialize_tuple_struct(stringify!(OpenClient,), FIELDS.len(),)?;

    serializer.serialize_field(&self.ratchet,)?;
    serializer.serialize_field(&self.sent_count,)?;
    serializer.serialize_field(self.current_public_key.as_ref(),)?;
    serializer.serialize_field(&self.current_keys,)?;
    serializer.serialize_field(&self.previous_keys,)?;
    serializer.end()
  }
}

impl<'de, D, S: 'de, A, R, L,> Deserialize<'de> for OpenClient<D, S, A, R, L,>
  where S: ArrayLength<u8>,
    A: Algorithm,
    L: ArrayLength<u8>, {
  fn deserialize<Des,>(deserializer: Des,) -> Result<Self, Des::Error>
    where Des: Deserializer<'de>, {
    use ::serde::de::Error;
    use std::fmt;

    struct ClientVisitor<D, S, A, R, L,>(PhantomData<(D, S, A, R, L,)>,);

    impl<'de, D, S: 'de, A, R, L,> Visitor<'de> for ClientVisitor<D, S, A, R, L,>
      where S: ArrayLength<u8>,
        A: Algorithm,
        L: ArrayLength<u8>, {
      type Value = OpenClient<D, S, A, R, L,>;

      fn expecting(&self, fmt: &mut fmt::Formatter,) -> fmt::Result {
        write!(fmt, "a tupel of length {}", FIELDS.len(),)
      }
      fn visit_seq<Acc,>(self, mut seq: Acc,) -> Result<Self::Value, Acc::Error>
        where Acc: SeqAccess<'de>, {
        let ratchet = seq.next_element()?
          .ok_or(Acc::Error::missing_field(FIELDS[0],))?;
        let sent_count = seq.next_element()?
          .ok_or(Acc::Error::missing_field(FIELDS[1],))?;
        let current_public_key = ClearOnDrop::new(
          seq.next_element::<[u8; 32]>()?
          .ok_or(Acc::Error::missing_field(FIELDS[2],))?.into(),
        );
        let current_keys = seq.next_element()?
          .ok_or(Acc::Error::missing_field(FIELDS[3],))?;
        let previous_keys = seq.next_element()?
          .ok_or(Acc::Error::missing_field(FIELDS[4],))?;

        Ok(OpenClient { ratchet, sent_count, current_public_key, current_keys, previous_keys, })
      }
    }

    deserializer.deserialize_tuple_struct(stringify!(OpenClient,), FIELDS.len(), ClientVisitor(PhantomData,),)
  }
}

impl Serialize for KeyBytes {
  fn serialize<S,>(&self, serializer: S,) -> Result<S::Ok, S::Error>
    where S: Serializer, {
    let mut serializer = serializer.serialize_tuple_struct(stringify!(KeyBytes,), 1,)?;

    serializer.serialize_field(self.0.as_ref(),)?;
    serializer.end()
  }
}

impl<'de,> Deserialize<'de> for KeyBytes {
  fn deserialize<D,>(deserializer: D,) -> Result<Self, D::Error>
    where D: Deserializer<'de>, {
    use ::serde::de::Error;
    use std::fmt;
    
    struct KeyBytesVisitor;

    impl<'de,> Visitor<'de> for KeyBytesVisitor {
      type Value = KeyBytes;

      fn expecting(&self, fmt: &mut fmt::Formatter,) -> fmt::Result {
        write!(fmt, "a tuple of length 1",)
      }
      fn visit_seq<A,>(self, mut seq: A,) -> Result<Self::Value, A::Error>
        where A: SeqAccess<'de>, {
        Ok(KeyBytes(seq.next_element::<[u8; 32]>()?
          .ok_or(Error::invalid_length(0, &format!("a tuple of length 1",).as_str(),),)?.into(),
        ))
      }
    }

    deserializer.deserialize_tuple_struct(stringify!(KeyBytes,), 1, KeyBytesVisitor,)
  }
}

#[cfg(test,)]
mod tests {
  use super::*;
  use crate::{client::aead::Aes256Gcm, typenum::consts,};
  use sha1::Sha1;
  
  #[test]
  fn test_open_client_serde() {
    let ratchet = Ratchet::new(&mut rand::thread_rng(),);
    let sent_count = 1;
    let current_public_key = ClearOnDrop::new([1; 32].into(),);
    let current_keys = HashMap::new();
    let previous_keys = HashMap::new();
    let client = OpenClient::<Sha1, consts::U500, Aes256Gcm, consts::U1, consts::U100,> {
      ratchet,
      sent_count,
      current_public_key,
      current_keys,
      previous_keys,
    };
    let mut serialised = [0u8; 1024];
    let serialised = {
      let writer = &mut serialised.as_mut();

      serde_cbor::ser::to_writer_packed(writer, &client,)
        .expect("Error serialising the OpenClient");
      
      let len = writer.len();
      let len = serialised.len() - len;

      &serialised[..len]
    };
    let other: OpenClient<Sha1, consts::U500, Aes256Gcm, consts::U1, consts::U100,> = serde_cbor::from_reader(serialised,)
      .expect("Error deserialising the OpenClient");
    let mut other_serialised = [0u8; 1024];
    let other_serialised = {
      let writer = &mut other_serialised.as_mut();

      serde_cbor::ser::to_writer_packed(writer, &other,)
        .expect("Error serialising the OpenClient");
      
      let len = writer.len();
      let len = other_serialised.len() - len;

      &other_serialised[..len]
    };

    assert!(serialised == other_serialised, "OpenClient deserialised incorrectly",);
  }
}
