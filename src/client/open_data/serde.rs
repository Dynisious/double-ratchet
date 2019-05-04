//! Defines serde for OpenData.
//! 
//! Author -- daniel.bechaz@gmail.com  
//! Last Moddified --- 2019-05-04

use super::*;
use ::serde::{
  ser::{Serialize, Serializer, SerializeTupleStruct,},
  de::{Deserialize, Deserializer, SeqAccess, Visitor, Unexpected,},
};
use std::marker::PhantomData;

static FIELDS: &[&str] = &[
  "key",
  "nonce",
  "aad",
];

impl<A, L,> Serialize for Box<OpenData<A, L,>>
  where A: Algorithm,
    L: ArrayLength<u8>, {
  fn serialize<S,>(&self, serializer: S,) -> Result<S::Ok, S::Error>
    where S: Serializer, {
    let mut serializer = serializer.serialize_tuple_struct(stringify!(OpenData,), FIELDS.len(),)?;

    serializer.serialize_field(self.key.as_ref(),)?;
    serializer.serialize_field(self.nonce.as_ref(),)?;
    serializer.serialize_field(self.aad.as_ref(),)?;
    serializer.end()
  }
}

impl<'de, A, L,> Deserialize<'de> for Box<OpenData<A, L,>>
  where A: Algorithm,
    L: ArrayLength<u8>, {
  fn deserialize<D,>(deserializer: D,) -> Result<Self, D::Error>
    where D: Deserializer<'de>, {
    use ::serde::de::Error;
    use std::fmt;

    struct OpenDataVisitor<A, L,> {
      _data: PhantomData<(A, L,)>,
    };

    impl<'de, A, L,> Visitor<'de> for OpenDataVisitor<A, L,>
      where A: Algorithm,
        L: ArrayLength<u8>, {
      type Value = Box<OpenData<A, L,>>;

      fn expecting(&self, fmt: &mut fmt::Formatter,) -> fmt::Result {
        write!(fmt, "a tuple of length {}", FIELDS.len(),)
      }
      fn visit_seq<Acc,>(self, mut seq: Acc,) -> Result<Self::Value, Acc::Error>
        where Acc: SeqAccess<'de>, {
        let mut res = Self::Value::default();
        
        //Initialise the key.
        let key = seq.next_element::<Box<[u8]>>()?
          .ok_or(Acc::Error::missing_field(FIELDS[0],),)?;
        if key.len() != A::KeyLength::USIZE {
          let unexp = format!("an array of {} bytes", key.len(),);
          let unexp = Unexpected::Other(unexp.as_str());
          let exp = format!("an array of {} bytes", A::KeyLength::USIZE,);
          let exp = &exp.as_str();

          return Err(Acc::Error::invalid_value(unexp, exp,));
        }
        for (i, b,) in key.iter().cloned().enumerate() { res.key[i] = b }
        
        //Initialise the nonce.
        let nonce = seq.next_element::<Box<[u8]>>()?
          .ok_or(Acc::Error::missing_field(FIELDS[1],),)?;
        if nonce.len() != A::NonceLength::USIZE {
          let unexp = format!("an array of {} bytes", nonce.len(),);
          let unexp = Unexpected::Other(unexp.as_str());
          let exp = format!("an array of {} bytes", A::NonceLength::USIZE,);
          let exp = &exp.as_str();

          return Err(Acc::Error::invalid_value(unexp, exp,));
        }
        for (i, b,) in nonce.iter().cloned().enumerate() { res.nonce[i] = b }
        
        //Initialise the aad.
        let aad = seq.next_element::<Box<[u8]>>()?
          .ok_or(Acc::Error::missing_field(FIELDS[2],),)?;
        if aad.len() != L::USIZE {
          let unexp = format!("an array of {} bytes", aad.len(),);
          let unexp = Unexpected::Other(unexp.as_str());
          let exp = format!("an array of {} bytes", L::USIZE,);
          let exp = &exp.as_str();

          return Err(Acc::Error::invalid_value(unexp, exp,));
        }
        for (i, b,) in aad.iter().cloned().enumerate() { res.aad[i] = b }
        
        Ok(res)
      }
    }

    let visitor = OpenDataVisitor { _data: PhantomData, };

    deserializer.deserialize_tuple_struct(stringify!(OpenData,), FIELDS.len(), visitor,)
  }
}

#[cfg(test,)]
mod tests {
  use super::*;
  use crate::{client::aead::Aes256Gcm, typenum::consts::U10,};
  
  #[test]
  fn test_open_data_serde() {
    let data = {
      let mut data = Box::<OpenData<Aes256Gcm, U10,>>::default();
      
      data.key = [1; 32].into();
      data.nonce = [2; 12].into();
      data.aad = [3; 10].into();
      data
    };
    let mut serialised = [0u8; 1024];
    let serialised = {
      let writer = &mut serialised.as_mut();

      serde_cbor::to_writer(writer, &data,)
        .expect("Error serialising the OpenData");
      
      let len = writer.len();
      let len = serialised.len() - len;

      &serialised[..len]
    };
    let other = serde_cbor::from_reader(serialised,)
      .expect("Error deserialising the OpenData");

    assert!(data == other, "OpenData deserialised incorrectly",);
  }
}
