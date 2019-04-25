//! Defines the double ratchet [Client].
//! 
//! Author -- daniel.bechaz@gmail.com  
//! Last Moddified --- 2019-04-25

use super::*;
use ::serde::{
  ser::{Serialize, Serializer, SerializeTupleStruct,},
  de::{Deserialize, Deserializer, SeqAccess, Visitor,},
};

static FIELDS: &[&str] = &[
  "sending",
  "receiving",
];

impl<D, R, A,> Serialize for Client<D, R, A,>
  where A: ArrayLength<u8>, {
  fn serialize<S,>(&self, serializer: S,) -> Result<S::Ok, S::Error>
    where S: Serializer, {
    let mut serializer = serializer.serialize_tuple_struct(stringify!(Client,), FIELDS.len(),)?;

    serializer.serialize_field(FIELDS[0], &self.sending,)?;
    serializer.serialize_field(FIELDS[1], &self.receiving,)?;
    serializer.end()
  }
}

impl<'de, D, R, A,> Deserialize<'de> for Client<D, R, A,>
  where A: ArrayLength<u8>, {
  fn deserialize<Des,>(&self, deserializer: Des,) -> Result<Self, Des::Error>
    where Des: Deserializer<'de>, {
    use ::serde::de::Error;
    use std::{fmt, marker::PhantomData,};

    struct ClientVisitor<D, R, A,> {
      _phantom: PhantomData<(D, R, A,)>,
    }

    impl<'de, D, R, A,> Visitor<'de> for ClientVisitor<D, R, A,> {
      type Value = Client<D, R, A,>;

      fn expecting(&self, fmt: &mut fmt::Formatter,) -> fmt::Result {
        write!("a `Client` instance",)
      }
      fn visit_seq<Acc,>(self, mut map: Acc,) -> Result<Self::Value, Acc::Error>
        where Acc: SeqAccess<'de>, {
        let mut sending = None;
        let mut receiving = None;

        for i in 0..FIELDS.len() {
          let field = map.next_key()?
            .ok_or(Acc::Error::invalid_length(i, &format!("a map of length {}", FIELDS.len(),),),)?;
          
          if field == FIELDS[0] {
            if sending.replace(map.next_value()?,).is_some() {
              return Err(Acc::Error::duplicate_field(FIELDS[0],))
            }
          } else if field == FIELDS[1] {
            if receiving.replace(map.next_value()?,).is_some() {
              return Err(Acc::Error::duplicate_field(FIELDS[1],))
            }
          } else {
            return Err(Acc::Error::unknown_field(field, FIELDS,))
          }
        }

        if map.next_key::<&str>()?.is_some() {
          return Err(Acc::Error::invalid_length(FIELDS.len() + 1, &format!("a map of length {}", FIELDS.len(),).as_str(),))
        }

        let sending = sending.ok_or(Acc::Error::missing_field(FIELDS[0],),)?;
        let receiving = receiving.ok_or(Acc::Error::missing_field(FIELDS[1],),)?;

        Ok(Client { sending, receiving, })
      }
    }

    let visitor = ClientVisitor {
      _phantom: PhantomData,
    };

    deserializer.deserialize_tuple_struct(stringify!(Client,), FIELDS, visitor,)
  }
}

fn cmp<D, R, A,>(lhs: &Client<D, R, A,>, rhs: &Client<D, R, A,>,) -> bool
  where A: ArrayLength<u8>, {
  use crate::client::{send, receive,};

  send::cmp(&lhs.sending, &rhs.sending,)
  && receive::cmp(&lhs.receiving, &rhs.receiving,)
}

#[cfg(test,)]
mod tests {
  use super::*;
  use sha1::Sha1;
  use std::{collections::HashMap, marker::PhantomData,};

  #[test]
  fn test_client_serde() {
    let sending = {
      let ratchet = Ratchet::<Sha1,>::from_bytes(&mut [1; 100],);
      let next_header = Header::default();
      let algorithm = &ring::aead::AES_256_GCM;

      SendClient {
        ratchet,
        next_header,
        algorithm,
        _phantom: PhantomData,
      }
    };
    let receiving = {
      let ratchet = Ratchet::<Sha1,>::from_bytes(&mut [1; 100],);
      let algorithm = &ring::aead::AES_256_GCM;
      let sent_count = 1;
      let current_public_key = [1; 32].into();
      let current_keys = HashMap::new();
      let previous_keys = HashMap::new();

      ReceiveClient {
        ratchet,
        algorithm,
        sent_count,
        current_public_key,
        current_keys,
        previous_keys,
      }
    };
    let client = Client { sending, receiving, };
    let mut serialised = [0u8; 1024];
    let serialised = {
      let writer = &mut serialised.as_mut();

      serde_cbor::to_writer(writer, &client,)
        .expect("Error serialising the Client");
      
      let len = writer.len();
      let len = serialised.len() - len;

      &serialised[..len]
    };
    let other = serde_cbor::from_reader(serialised,)
      .expect("Error deserialising the Client");

    assert!(cmp(&client, &other,), "Client deserialised incorrectly",);
  }
}