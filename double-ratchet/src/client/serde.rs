//! Defines serde for Client.
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
  "lock",
  "open",
  "private_key",
  "local",
];

impl<D, S, A, R, L,> Serialize for Client<D, S, A, R, L,>
  where S: ArrayLength<u8>,
    A: aead::Algorithm,
    L: ArrayLength<u8>, {
  fn serialize<Ser,>(&self, serializer: Ser,) -> Result<Ser::Ok, Ser::Error>
    where Ser: Serializer, {
    let mut serializer = serializer.serialize_tuple_struct(stringify!(Client,), FIELDS.len(),)?;

    serializer.serialize_field(&self.lock,)?;
    serializer.serialize_field(&self.open,)?;
    serializer.serialize_field(self.private_key.as_ref(),)?;
    serializer.serialize_field(&self.local,)?;
    serializer.end()
  }
}

impl<'de, D, S: 'de, A, R, L,> Deserialize<'de> for Client<D, S, A, R, L,>
  where S: ArrayLength<u8>,
    A: aead::Algorithm,
    L: ArrayLength<u8>, {
  fn deserialize<Des,>(deserializer: Des,) -> Result<Self, Des::Error>
    where Des: Deserializer<'de>, {
    use ::serde::de::Error;
    use std::fmt;

    struct ClientVisitor<D, S, A, R, L,>(PhantomData<(D, S, A, R, L,)>,);

    impl<'de, D, S: 'de, A, R, L,> Visitor<'de> for ClientVisitor<D, S, A, R, L,>
      where S: ArrayLength<u8>,
        A: aead::Algorithm,
        L: ArrayLength<u8>, {
      type Value = Client<D, S, A, R, L,>;

      fn expecting(&self, fmt: &mut fmt::Formatter,) -> fmt::Result {
        write!(fmt, "a tuple of length {}", FIELDS.len(),)
      }
      fn visit_seq<Acc,>(self, mut seq: Acc,) -> Result<Self::Value, Acc::Error>
        where Acc: SeqAccess<'de>, {
        let lock = seq.next_element()?
          .ok_or(Acc::Error::missing_field(FIELDS[0],),)?;
        let open = seq.next_element()?
          .ok_or(Acc::Error::missing_field(FIELDS[1],),)?;
        let private_key = ClearOnDrop::new(seq.next_element::<[u8; 32]>()?
          .ok_or(Acc::Error::missing_field(FIELDS[2],),)?.into(),);
        let local = seq.next_element()?
          .ok_or(Acc::Error::missing_field(FIELDS[3],),)?;

        Ok(Client { lock, open, private_key, local, })
      }
    }

    deserializer.deserialize_tuple_struct(stringify!(Client,), FIELDS.len(), ClientVisitor(PhantomData,),)
  }
}

#[cfg(test,)]
mod tests {
  use super::*;
  use crate::{message::Header, client::aead::Aes256Gcm, typenum::consts,};
  use sha1::Sha1;
  use std::collections::HashMap;

  #[test]
  fn test_client_serde() {
    let lock = {
      let ratchet = Ratchet::new(&mut rand::thread_rng(),);
      let next_header = Header::default();

      LockClient {
        ratchet,
        next_header,
        _data: PhantomData,
      }
    };
    let open = {
      let ratchet = Ratchet::new(&mut rand::thread_rng(),);
      let sent_count = 1;
      let current_public_key = ClearOnDrop::new([1; 32].into(),);
      let current_keys = HashMap::new();
      let previous_keys = HashMap::new();

      OpenClient {
        ratchet,
        sent_count,
        current_public_key,
        current_keys,
        previous_keys,
      }
    };
    let private_key = ClearOnDrop::new([2; 32].into(),);
    let client = Client::<Sha1, consts::U500, Aes256Gcm, consts::U1,> { lock, open, private_key, local: true, };
    let mut serialised = [0u8; 2048];
    let serialised = {
      let writer = &mut serialised.as_mut();

      serde_cbor::ser::to_writer_packed(writer, &client,)
        .expect("Error serialising the Client");
      
      let len = writer.len();
      let len = serialised.len() - len;

      &serialised[..len]
    };
    let other: Client<Sha1, consts::U500, Aes256Gcm, consts::U1,> = serde_cbor::from_reader(serialised,)
      .expect("Error deserialising the Client");
    let mut other_serialised = [0u8; 2048];
    let other_serialised = {
      let writer = &mut other_serialised.as_mut();

      serde_cbor::ser::to_writer_packed(writer, &other,)
        .expect("Error serialising the Client");
      
      let len = writer.len();
      let len = other_serialised.len() - len;

      &other_serialised[..len]
    };

    assert!(serialised == other_serialised, "Client deserialised incorrectly",);
  }
}