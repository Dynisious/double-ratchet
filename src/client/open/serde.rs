//! Defines serde for OpenClient.
//! 
//! Author -- daniel.bechaz@gmail.com  
//! Last Moddified --- 2019-05-04

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
    serializer.serialize_field(self.current_public_key.as_bytes(),)?;
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

    struct ClientVisitor<D, S, A, R, L,> {
      _data: PhantomData<(D, S, A, R, L,)>,
    }

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
        let current_public_key = {
          let current_public_key = seq.next_element::<[u8; 32]>()?
            .ok_or(Acc::Error::missing_field(FIELDS[2],))?;
          
          current_public_key.into()
        };
        let current_keys = seq.next_element()?
          .ok_or(Acc::Error::missing_field(FIELDS[3],))?;
        let previous_keys = seq.next_element()?
          .ok_or(Acc::Error::missing_field(FIELDS[4],))?;

        Ok(OpenClient {
          ratchet,
          sent_count,
          current_public_key,
          current_keys,
          previous_keys,
        })
      }
    }

    let visitor = ClientVisitor { _data: PhantomData, };
    
    deserializer.deserialize_tuple_struct(stringify!(OpenClient,), FIELDS.len(), visitor,)
  }
}

#[cfg(test,)]
mod tests {
  use super::*;
  use crate::client::aead::Aes256Gcm;
  use sha1::Sha1;
  
  #[test]
  fn test_open_client_serde() {
    let ratchet = Ratchet::new(&mut [1; 100],);
    let sent_count = 1;
    let current_public_key = [1; 32].into();
    let current_keys = HashMap::new();
    let previous_keys = HashMap::new();
    let client = OpenClient::<Sha1, consts::U500, Aes256Gcm, consts::U1,> {
      ratchet,
      sent_count,
      current_public_key,
      current_keys,
      previous_keys,
    };
    let mut serialised = [0u8; 1024];
    let serialised = {
      let writer = &mut serialised.as_mut();

      serde_cbor::to_writer(writer, &client,)
        .expect("Error serialising the OpenClient");
      
      let len = writer.len();
      let len = serialised.len() - len;

      &serialised[..len]
    };
    let other = serde_cbor::from_reader(serialised,)
      .expect("Error deserialising the OpenClient");

    assert!(client == other, "OpenClient deserialised incorrectly",);
  }
}
