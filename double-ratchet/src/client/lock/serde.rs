//! Defines serde for LockClient.
//! 
//! Author -- daniel.bechaz@gmail.com  
//! Last Moddified --- 2019-05-12

use super::*;
use ::serde::{
  ser::{Serialize, Serializer, SerializeTupleStruct,},
  de::{Deserialize, Deserializer, SeqAccess, Visitor,},
};

static FIELDS: &[&str] = &[
  "ratchet",
  "next_header",
];

impl<D, S, A, R, L,> Serialize for LockClient<D, S, A, R, L,>
  where S: ArrayLength<u8>, {
  fn serialize<Ser,>(&self, serializer: Ser,) -> Result<Ser::Ok, Ser::Error>
    where Ser: Serializer, {
    let mut serializer = serializer.serialize_tuple_struct(stringify!(LockClient,), FIELDS.len(),)?;

    serializer.serialize_field(&self.ratchet,)?;
    serializer.serialize_field(&self.next_header,)?;
    serializer.end()
  }
}

impl<'de, D, S: 'de, A, R, L,> Deserialize<'de> for LockClient<D, S, A, R, L,>
  where S: ArrayLength<u8>, {
  fn deserialize<Des,>(deserializer: Des,) -> Result<Self, Des::Error>
    where Des: Deserializer<'de>, {
    use ::serde::de::Error;
    use std::fmt;

    struct ClientVisitor<D, S, A, R, L,>(PhantomData<(D, S, A, R, L,)>,);

    impl<'de, D, S: 'de, A, R, L,> Visitor<'de> for ClientVisitor<D, S, A, R, L,>
      where S: ArrayLength<u8>, {
      type Value = LockClient<D, S, A, R, L,>;

      fn expecting(&self, fmt: &mut fmt::Formatter,) -> fmt::Result {
        write!(fmt, "a tuple of length {}", FIELDS.len(),)
      }
      fn visit_seq<Acc,>(self, mut seq: Acc,) -> Result<Self::Value, Acc::Error>
        where Acc: SeqAccess<'de>, {
        let ratchet = seq.next_element()?
          .ok_or(Acc::Error::missing_field(FIELDS[0],),)?;
        let next_header = seq.next_element()?
          .ok_or(Acc::Error::missing_field(FIELDS[1],),)?;
        
        Ok(LockClient { ratchet, next_header, _data: PhantomData, })
      }
    }

    deserializer.deserialize_tuple_struct(stringify!(LockClient,), FIELDS.len(), ClientVisitor(PhantomData,),)
  }
}

#[cfg(test,)]
mod tests {
  use super::*;
  use crate::{client::aead::Aes256Gcm, typenum::consts,};
  use sha1::Sha1;

  #[test]
  fn test_lock_client_serde() {
    let ratchet = Ratchet::new(&mut rand::thread_rng(),);
    let public_key = [1; 32].into();
    let client = LockClient::<Sha1, consts::U500, Aes256Gcm, consts::U1, consts::U100,> {
      ratchet,
      next_header: Header {
        public_key,
        ..Header::default()
      },
      ..LockClient::default()
    };
    let mut serialised = [0; 1024];
    let serialised = {
      let writer = &mut serialised.as_mut();

      serde_cbor::ser::to_writer_packed(writer, &client,)
        .expect("Error serialising the LockClient");
      
      let len = writer.len();
      let len = serialised.len() - len;

      &serialised[..len]
    };
    let other: LockClient<Sha1, consts::U500, Aes256Gcm, consts::U1, consts::U100,> = serde_cbor::from_reader(serialised,)
      .expect("Error deserialising the LockClient");
    let mut other_serialised = [0; 1024];
    let other_serialised = {
      let writer = &mut other_serialised.as_mut();

      serde_cbor::ser::to_writer_packed(writer, &other,)
        .expect("Error serialising the LockClient");
      
      let len = writer.len();
      let len = other_serialised.len() - len;

      &other_serialised[..len]
    };

    assert!(serialised == other_serialised, "LockClient deserialised incorrectly",);
  }
}
