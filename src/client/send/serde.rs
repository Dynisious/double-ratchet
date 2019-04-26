//! Defines serde for SendClient.
//! 
//! Author -- daniel.bechaz@gmail.com  
//! Last Moddified --- 2019-04-25

use super::*;
use ::serde::{
  ser::{Serialize, Serializer, SerializeTupleStruct,},
  de::{Deserialize, Deserializer, SeqAccess, Visitor,},
};

static FIELDS: &[&str] = &[
  "ratchet",
  "next_header",
];

impl<A, D, R, L,> Serialize for SendClient<A, D, R, L,> {
  fn serialize<S,>(&self, serializer: S,) -> Result<S::Ok, S::Error>
    where S: Serializer, {
    let mut serializer = serializer.serialize_tuple_struct(stringify!(SendClient,), FIELDS.len(),)?;

    serializer.serialize_field(&self.ratchet,)?;
    serializer.serialize_field(&self.next_header,)?;
    serializer.end()
  }
}

impl<'de, A, D, R, L,> Deserialize<'de> for SendClient<A, D, R, L,> {
  fn deserialize<Des,>(deserializer: Des,) -> Result<Self, Des::Error>
    where Des: Deserializer<'de>, {
    use ::serde::de::Error;
    use std::fmt;

    struct ClientVisitor<A, D, R, L,> {
      _phantom: PhantomData<(A, D, R, L,)>,
    }

    impl<'de, A, D, R, L,> Visitor<'de> for ClientVisitor<A, D, R, L,> {
      type Value = SendClient<A, D, R, L,>;

      fn expecting(&self, fmt: &mut fmt::Formatter,) -> fmt::Result {
        write!(fmt, "Expected `SendClient` instance",)
      }
      fn visit_seq<Acc,>(self, mut seq: Acc,) -> Result<Self::Value, Acc::Error>
        where Acc: SeqAccess<'de>, {
        
        let ratchet = seq.next_element()?
          .ok_or(Acc::Error::missing_field(FIELDS[0],),)?;
        let next_header = seq.next_element()?
          .ok_or(Acc::Error::missing_field(FIELDS[1],),)?;
        let _phantom = PhantomData;

        Ok(SendClient { ratchet, next_header, _phantom, })
      }
    }

    let visitor = ClientVisitor {
      _phantom: PhantomData,
    };

    deserializer.deserialize_tuple_struct(stringify!(SendClient,), FIELDS.len(), visitor,)
  }
}

#[cfg(test,)]
mod tests {
  use super::*;
  use crate::client::aead::Aes256Gcm;
  use sha1::Sha1;

  #[test]
  fn test_send_client_serde() {
    let ratchet = Ratchet::<Sha1,>::from_bytes(&mut [1; 100],);
    let public_key = [1; 32].into();
    let _algorithm = &aead::AES_256_GCM;
    let client = SendClient::<Aes256Gcm, Sha1,>::new(ratchet, public_key,);
    let mut serialised = [0u8; 1024];
    let serialised = {
      let writer = &mut serialised.as_mut();

      serde_cbor::to_writer(writer, &client,)
        .expect("Error serialising the SendClient");
      
      let len = writer.len();
      let len = serialised.len() - len;

      &serialised[..len]
    };
    let other = serde_cbor::from_reader(serialised,)
      .expect("Error deserialising the SendClient");

    assert!(cmp(&client, &other,), "SendClient deserialised incorrectly",);
  }
}
