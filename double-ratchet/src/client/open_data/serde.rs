//! Defines serde for OpenData.
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
  "key",
  "nonce",
  "aad",
];

impl<A, L,> Serialize for OpenData<A, L,>
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

impl<'de, A, L,> Deserialize<'de> for OpenData<A, L,>
  where A: Algorithm,
    L: ArrayLength<u8>, {
  fn deserialize<D,>(deserializer: D,) -> Result<Self, D::Error>
    where D: Deserializer<'de>, {
    use crate::typenum::Unsigned;
    use ::serde::de::{Error, Unexpected,};
    use std::fmt;

    struct OpenDataVisitor<A, L,>(PhantomData<(A, L,)>,);

    impl<'de, A, L,> Visitor<'de> for OpenDataVisitor<A, L,>
      where A: Algorithm,
        L: ArrayLength<u8>, {
      type Value = OpenData<A, L,>;

      fn expecting(&self, fmt: &mut fmt::Formatter,) -> fmt::Result {
        write!(fmt, "a tuple of length {}", FIELDS.len(),)
      }
      fn visit_seq<Acc,>(self, mut seq: Acc,) -> Result<Self::Value, Acc::Error>
        where Acc: SeqAccess<'de>, {
        let key = seq.next_element::<Box<[u8]>>()?
          .ok_or(Acc::Error::missing_field(FIELDS[0],),)
          .and_then(|key,| {
            let key = ClearOnDrop::new(key,);

            GenericArray::from_exact_iter(key.iter().copied(),)
            .map(ClearOnDrop::new,)
            .ok_or_else(|| Error::invalid_value(Unexpected::Seq, &format!("a slice of length {}", A::KeyLength::USIZE,).as_str()),)
          },)?;
        let nonce = seq.next_element::<Box<[u8]>>()?
          .ok_or(Acc::Error::missing_field(FIELDS[1],),)
          .and_then(|nonce,| {
            let nonce = ClearOnDrop::new(nonce,);

            GenericArray::from_exact_iter(nonce.iter().copied(),)
            .map(ClearOnDrop::new,)
            .ok_or_else(|| Error::invalid_value(Unexpected::Seq, &format!("a slice of length {}", A::NonceLength::USIZE,).as_str()),)
          },)?;
        let aad = seq.next_element::<Box<[u8]>>()?
          .ok_or(Acc::Error::missing_field(FIELDS[2],),)
          .and_then(|aad,| {
            let aad = ClearOnDrop::new(aad,);

            GenericArray::from_exact_iter(aad.iter().copied(),)
            .map(ClearOnDrop::new,)
            .ok_or_else(|| Error::invalid_value(Unexpected::Seq, &format!("a slice of length {}", L::USIZE,).as_str()),)
          },)?;
        
        Ok(OpenData { key, nonce, aad, })
      }
    }

    deserializer.deserialize_tuple_struct(stringify!(OpenData,), FIELDS.len(), OpenDataVisitor(PhantomData,),)
  }
}

#[cfg(test,)]
mod tests {
  use super::*;
  use crate::{client::aead::Aes256Gcm, typenum::consts::U10,};
  
  #[test]
  fn test_open_data_serde() {
    let data = OpenData::<Aes256Gcm, U10,> {
      key: ClearOnDrop::new([1; 32].into(),),
      nonce: ClearOnDrop::new([2; 12].into(),),
      aad: ClearOnDrop::new([3; 10].into(),),
    };
    let mut serialised = [0u8; 1024];
    let serialised = {
      let writer = &mut serialised.as_mut();

      serde_cbor::ser::to_writer_packed(writer, &data,)
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
