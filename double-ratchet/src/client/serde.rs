//! Defines serde for Client.
//! 
//! Author -- daniel.bechaz@gmail.com  
//! Last Moddified --- 2019-05-21

use super::*;
use ::serde::{
  ser::{Serialize, Serializer, SerializeTupleStruct,},
  de::{Deserialize, Deserializer, SeqAccess, Visitor,},
};
use std::marker::PhantomData;

impl<D, S, A, R, L,> Serialize for LocalClient<D, S, A, R, L,>
  where S: ArrayLength<u8>,
    A: aead::Algorithm,
    L: ArrayLength<u8>, {
  fn serialize<Ser,>(&self, serializer: Ser,) -> Result<Ser::Ok, Ser::Error>
    where Ser: Serializer, {
    let mut serializer = serializer.serialize_tuple_struct(stringify!(LocalClient,), 2,)?;

    serializer.serialize_field(&true,)?;
    serializer.serialize_field(&self.0,)?;
    serializer.end()
  }
}

impl<'de, D, S, A, R, L,> Deserialize<'de> for LocalClient<D, S, A, R, L,>
  where S: ArrayLength<u8>,
    A: aead::Algorithm,
    L: ArrayLength<u8>, {
  fn deserialize<Des,>(deserializer: Des,) -> Result<Self, Des::Error>
    where Des: Deserializer<'de>, {
    use std::fmt;
    
    struct ClientVisitor<D, S, A, R, L,>(PhantomData<(D, S, A, R, L,)>,);

    impl<'de, D, S, A, R, L,> Visitor<'de> for ClientVisitor<D, S, A, R, L,>
      where S: 'static + ArrayLength<u8>,
        A: aead::Algorithm,
        L: 'static + ArrayLength<u8>, {
      type Value = LocalClient<D, S, A, R, L,>;

      #[inline]
      fn expecting(&self, fmt: &mut fmt::Formatter,) -> fmt::Result {
        write!(fmt, "a tuple of length 2",)
      }
      fn visit_seq<Acc,>(self, mut seq: Acc,) -> Result<Self::Value, Acc::Error,>
        where Acc: SeqAccess<'de>, {
        use ::serde::de::{Unexpected, Error,};

        if !seq.next_element::<bool>()?.ok_or(Acc::Error::missing_field("check",),)? {
          return Err(Acc::Error::invalid_value(Unexpected::Bool(false), &"a `true` value",))
        }

        Ok(LocalClient(seq.next_element()?.ok_or(Acc::Error::missing_field("client",),)?,))
      }
    }

    deserializer.deserialize_tuple_struct(stringify!(LocalClient), 2, ClientVisitor(PhantomData,),)
  }
}

impl<D, S, A, R, L,> Serialize for RemoteClient<D, S, A, R, L,>
  where S: ArrayLength<u8>,
    A: aead::Algorithm,
    L: ArrayLength<u8>, {
  fn serialize<Ser,>(&self, serializer: Ser,) -> Result<Ser::Ok, Ser::Error>
    where Ser: Serializer, {
    let mut serializer = serializer.serialize_tuple_struct(stringify!(RemoteClient,), 2,)?;

    serializer.serialize_field(&false,)?;
    serializer.serialize_field(&self.0,)?;
    serializer.end()
  }
}

impl<'de, D, S, A, R, L,> Deserialize<'de> for RemoteClient<D, S, A, R, L,>
  where S: ArrayLength<u8>,
    A: aead::Algorithm,
    L: ArrayLength<u8>, {
  fn deserialize<Des,>(deserializer: Des,) -> Result<Self, Des::Error>
    where Des: Deserializer<'de>, {
    use std::fmt;
    
    struct ClientVisitor<D, S, A, R, L,>(PhantomData<(D, S, A, R, L,)>,);

    impl<'de, D, S, A, R, L,> Visitor<'de> for ClientVisitor<D, S, A, R, L,>
      where S: 'static + ArrayLength<u8>,
        A: aead::Algorithm,
        L: 'static + ArrayLength<u8>, {
      type Value = RemoteClient<D, S, A, R, L,>;

      #[inline]
      fn expecting(&self, fmt: &mut fmt::Formatter,) -> fmt::Result {
        write!(fmt, "a tuple of length 2",)
      }
      fn visit_seq<Acc,>(self, mut seq: Acc,) -> Result<Self::Value, Acc::Error,>
        where Acc: SeqAccess<'de>, {
        use ::serde::de::{Unexpected, Error,};

        if seq.next_element::<bool>()?.ok_or(Acc::Error::missing_field("check",),)? {
          return Err(Acc::Error::invalid_value(Unexpected::Bool(false), &"a `true` value",))
        }

        Ok(RemoteClient(seq.next_element()?.ok_or(Acc::Error::missing_field("client",),)?,))
      }
    }

    deserializer.deserialize_tuple_struct(stringify!(RemoteClient), 2, ClientVisitor(PhantomData,),)
  }
}

static FIELDS: &[&str] = &[
  "lock",
  "open",
  "private_key",
];

impl<D, S, A, R, L,> Serialize for InnerClient<D, S, A, R, L,>
  where S: ArrayLength<u8>,
    A: aead::Algorithm,
    L: ArrayLength<u8>, {
  fn serialize<Ser,>(&self, serializer: Ser,) -> Result<Ser::Ok, Ser::Error>
    where Ser: Serializer, {
    let mut serializer = serializer.serialize_tuple_struct(stringify!(Client,), FIELDS.len(),)?;

    serializer.serialize_field(&self.lock,)?;
    serializer.serialize_field(&self.open,)?;
    serializer.serialize_field(self.private_key.as_ref(),)?;
    serializer.end()
  }
}

impl<'de, D, S: 'de, A, R, L,> Deserialize<'de> for Box<InnerClient<D, S, A, R, L,>>
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
      type Value = Box<InnerClient<D, S, A, R, L,>>;

      fn expecting(&self, fmt: &mut fmt::Formatter,) -> fmt::Result {
        write!(fmt, "a tuple of length {}", FIELDS.len(),)
      }
      fn visit_seq<Acc,>(self, mut seq: Acc,) -> Result<Self::Value, Acc::Error>
        where Acc: SeqAccess<'de>, {
        use std::mem;

        let mut lock = seq.next_element()?
          .ok_or(Acc::Error::missing_field(FIELDS[0],),)?;
        let mut open = seq.next_element()?
          .ok_or(Acc::Error::missing_field(FIELDS[1],),)?;
        let mut private_key = ClearOnDrop::new(seq.next_element::<[u8; 32]>()?
          .ok_or(Acc::Error::missing_field(FIELDS[2],),)?.into(),);
        let mut client = Self::Value::default();

        mem::swap(&mut client.lock, &mut lock,);
        mem::swap(&mut client.open, &mut open,);
        mem::swap(&mut client.private_key, &mut private_key,);

        Ok(client)
      }
    }

    deserializer.deserialize_tuple_struct(stringify!(Box<Client>,), FIELDS.len(), ClientVisitor(PhantomData,),)
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
    let client = InnerClient::<Sha1, consts::U500, Aes256Gcm, consts::U1, consts::U100,> { lock, open, private_key, };
    let mut serialised = [0u8; 2048];
    let serialised = {
      let writer = &mut serialised.as_mut();

      serde_cbor::ser::to_writer_packed(writer, &client,)
        .expect("Error serialising the Client");
      
      let len = writer.len();
      let len = serialised.len() - len;

      &serialised[..len]
    };
    let other: Box<InnerClient<Sha1, consts::U500, Aes256Gcm, consts::U1, consts::U100,>> = serde_cbor::from_reader(serialised,)
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