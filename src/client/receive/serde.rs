//! Defines the receiving half of a [Client].
//! 
//! Author -- daniel.bechaz@gmail.com  
//! Last Moddified --- 2019-04-25

use super::*;
use ::serde::{
  ser::{Serialize, Serializer, SerializeTupleStruct,},
  de::{Deserialize, Deserializer, SeqAccess, Visitor, Unexpected,},
};
use std::marker::PhantomData;

static CLIENT_FIELDS: &[&str] = &[
  "ratchet",
  "sent_count",
  "current_public_key",
  "current_keys",
  "previous_keys",
];
static OPENDATA_FIELDS: &[&str] = &[
  "opening_key",
  "nonce",
  "aad",
];

impl<A, D, R, L,> Serialize for ReceiveClient<A, D, R, L,>
  where A: Algorithm,
    A::KEY_BYTES: Serialize,
    A::NONCE_BYTES: Serialize,
    L: ArrayLength<u8>, {
  fn serialize<S,>(&self, serializer: S,) -> Result<S::Ok, S::Error>
    where S: Serializer, {
    let mut serializer = serializer.serialize_tuple_struct(stringify!(ReceiveClient,), CLIENT_FIELDS.len(),)?;

    serializer.serialize_field(&self.ratchet,)?;
    serializer.serialize_field(&self.sent_count,)?;
    serializer.serialize_field(self.current_public_key.as_bytes(),)?;
    serializer.serialize_field(&self.current_keys,)?;
    serializer.serialize_field(&self.previous_keys,)?;
    serializer.end()
  }
}

impl<'de, A, D, R, L,> Deserialize<'de> for ReceiveClient<A, D, R, L,>
  where A: Algorithm,
    A::KEY_BYTES: Deserialize<'de>,
    A::NONCE_BYTES: Deserialize<'de>,
    L: ArrayLength<u8>, L::ArrayType: Copy, {
  fn deserialize<Des,>(deserializer: Des,) -> Result<Self, Des::Error>
    where Des: Deserializer<'de>, {
    use ::serde::de::Error;
    use std::fmt;

    struct ClientVisitor<A, D, R, L,> {
      _phantom: PhantomData<(A, D, R, L,)>,
    }

    impl<'de, A, D, R, L,> Visitor<'de> for ClientVisitor<A, D, R, L,>
      where A: Algorithm,
        A::KEY_BYTES: Deserialize<'de>,
        A::NONCE_BYTES: Deserialize<'de>,
        L: ArrayLength<u8>, L::ArrayType: Copy, {
      type Value = ReceiveClient<A, D, R, L,>;

      fn expecting(&self, fmt: &mut fmt::Formatter,) -> fmt::Result {
        write!(fmt, "a tuple of {} values", CLIENT_FIELDS.len(),)
      }
      fn visit_seq<Acc,>(self, mut seq: Acc,) -> Result<Self::Value, Acc::Error>
        where Acc: SeqAccess<'de>, {
        let ratchet = seq.next_element()?
          .ok_or(Acc::Error::missing_field(CLIENT_FIELDS[0],))?;
        let sent_count = seq.next_element()?
          .ok_or(Acc::Error::missing_field(CLIENT_FIELDS[1],))?;
        let current_public_key = {
          let current_public_key = seq.next_element::<[u8; 32]>()?
            .ok_or(Acc::Error::missing_field(CLIENT_FIELDS[2],))?;
          
          current_public_key.into()
        };
        let current_keys = seq.next_element()?
          .ok_or(Acc::Error::missing_field(CLIENT_FIELDS[3],))?;
        let previous_keys = seq.next_element()?
          .ok_or(Acc::Error::missing_field(CLIENT_FIELDS[4],))?;

        Ok(ReceiveClient {
          ratchet,
          sent_count,
          current_public_key,
          current_keys,
          previous_keys,
        })
      }
    }

    let visitor = ClientVisitor {
      _phantom: PhantomData,
    };
    
    deserializer.deserialize_tuple_struct(stringify!(ReceiveClient,), CLIENT_FIELDS.len(), visitor,)
  }
}

impl<A, L,> Serialize for OpenData<A, L,>
  where A: Algorithm,
    A::KEY_BYTES: Serialize,
    A::NONCE_BYTES: Serialize,
    L: ArrayLength<u8>, {
  fn serialize<S,>(&self, serializer: S,) -> Result<S::Ok, S::Error>
    where S: Serializer, {
    let mut serializer = serializer.serialize_tuple_struct(stringify!(OpenData,), OPENDATA_FIELDS.len(),)?;

    serializer.serialize_field(self.opening_key.as_ref(),)?;
    serializer.serialize_field(self.nonce.as_ref(),)?;
    serializer.serialize_field(self.aad.as_ref(),)?;
    serializer.end()
  }
}

impl<'de, A, L,> Deserialize<'de> for OpenData<A, L,>
  where A: Algorithm,
    A::KEY_BYTES: Deserialize<'de>,
    A::NONCE_BYTES: Deserialize<'de>,
    L: ArrayLength<u8>, L::ArrayType: Copy, {
  fn deserialize<D,>(deserializer: D,) -> Result<Self, D::Error>
    where D: Deserializer<'de>, {
    use ::serde::de::Error;
    use std::fmt;

    struct OpenDataVisitor<A, L,> {
      _phantom: PhantomData<(A, L,)>,
    };

    impl<'de, A, L,> Visitor<'de> for OpenDataVisitor<A, L,>
      where A: Algorithm,
        A::KEY_BYTES: Deserialize<'de>,
        A::NONCE_BYTES: Deserialize<'de>,
        L: ArrayLength<u8>, L::ArrayType: Copy, {
      type Value = OpenData<A, L,>;

      fn expecting(&self, fmt: &mut fmt::Formatter,) -> fmt::Result {
        write!(fmt, "a tuple of length {}", OPENDATA_FIELDS.len(),)
      }
      fn visit_seq<Acc,>(self, mut seq: Acc,) -> Result<Self::Value, Acc::Error>
        where Acc: SeqAccess<'de>, {
        let opening_key = seq.next_element()?
          .ok_or(Acc::Error::missing_field(OPENDATA_FIELDS[0],),)?;
        let nonce = seq.next_element()?
          .ok_or(Acc::Error::missing_field(OPENDATA_FIELDS[1],),)?;
        let aad = {
          let aad = seq.next_element::<&[u8]>()?
            .ok_or(Acc::Error::missing_field(OPENDATA_FIELDS[2],),)?;
          
          if aad.len() != L::USIZE { return Err(Acc::Error::invalid_value(
            Unexpected::Seq, &format!("an array of {} bytes", L::USIZE,).as_ref(),
          )) }
          
          *<&GenericArray<u8, _>>::from(aad,)
        };
        
        Ok(OpenData { opening_key, nonce, aad, })
      }
    }

    let visitor = OpenDataVisitor {
      _phantom: PhantomData,
    };

    deserializer.deserialize_tuple_struct(stringify!(OpenData,), OPENDATA_FIELDS.len(), visitor,)
  }
}

#[cfg(test,)]
mod tests {
  use super::*;
  use crate::client::aead::Aes256Gcm;
  use sha1::Sha1;
  
  #[test]
  fn test_receive_client_serde() {
    let ratchet = Ratchet::<Sha1,>::from_bytes(&mut [1; 100],);
    let sent_count = 1;
    let current_public_key = [1; 32].into();
    let current_keys = HashMap::<_, OpenData<Aes256Gcm,>>::new();
    let previous_keys = HashMap::new();
    let client = ReceiveClient {
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
        .expect("Error serialising the ReceiveClient");
      
      let len = writer.len();
      let len = serialised.len() - len;

      &serialised[..len]
    };
    let other = serde_cbor::from_reader(serialised,)
      .expect("Error deserialising the ReceiveClient");

    assert!(cmp(&client, &other,), "ReceiveClient deserialised incorrectly",);
  }
}
