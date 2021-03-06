//! Defines serde for the Message type.
//! 
//! Author -- daniel.bechaz@gmail.com  
//! Last Moddified --- 2019-05-11

use super::*;
use ::serde::{
  ser::{Serialize, Serializer, SerializeTupleStruct,},
  de::{Deserialize, Deserializer, SeqAccess, Visitor,},
};

mod message {
  use super::*;

  static FIELDS: &[&str] = &[
    "header",
    "data",
  ];

  impl Serialize for Message {
    fn serialize<S>(&self, serializer: S,) -> Result<S::Ok, S::Error>
      where S: Serializer, {
      let mut serializer = serializer.serialize_tuple_struct(stringify!(Message,), FIELDS.len(),)?;

      serializer.serialize_field(&self.header,)?;
      serializer.serialize_field(&self.data,)?;
      serializer.end()
    }
  }

  impl<'de,> Deserialize<'de> for Message {
    fn deserialize<D>(deserializer: D,) -> Result<Self, D::Error>
      where D: Deserializer<'de>, {
      use ::serde::de::Error;
      use std::fmt;

      struct MessageVisitor;

      impl<'de,> Visitor<'de> for MessageVisitor {
        type Value = Message;

        fn expecting(&self, fmt: &mut fmt::Formatter,) -> fmt::Result {
          write!(fmt, "a tuple of length {}", FIELDS.len(),)
        }
        fn visit_seq<A,>(self, mut seq: A,) -> Result<Self::Value, A::Error>
          where A: SeqAccess<'de>, {
          let header = seq.next_element()?
            .ok_or(Error::missing_field(FIELDS[0],),)?;
          let data = seq.next_element()?
            .ok_or(Error::missing_field(FIELDS[1],),)?;

          Ok(Message { header, data, })
        }
      }
      
      deserializer.deserialize_tuple_struct(stringify!(Message,), FIELDS.len(), MessageVisitor,)
    }
  }

  #[cfg(test,)]
  mod tests {
    use super::*;

    #[test]
    fn test_message_serde() {
      let public_key = [1; 32].into();
      let message_index = 1;
      let previous_step = 2;
      let header = Header { public_key, message_index, previous_step, };
      let data = vec![1, 2, 3, 4,].into_boxed_slice();
      let message = Message { header, data, };
      let mut serialised = [0u8; 1024];
      let serialised = {
        let writer = &mut serialised.as_mut();

        serde_cbor::ser::to_writer_packed(writer, &message,)
          .expect("Error serialising Message");
        
        let len = writer.len();
        let len = serialised.len() - len;

        &serialised[..len]
      };
      let other = serde_cbor::from_reader(serialised,)
        .expect("Error deserialising the Message");
        
      assert_eq!(message, other, "Message deserialised incorrectly",);
    }
  }
}

mod header {
  use super::*;
  
  static FIELDS: &[&str] = &[
    "public_key",
    "message_index",
    "previous_step",
  ];

  impl Serialize for Header {
    fn serialize<S,>(&self, serializer: S,) -> Result<S::Ok, S::Error>
      where S: Serializer, {
      let mut serializer = serializer.serialize_tuple_struct(stringify!(Header), FIELDS.len(),)?;

      serializer.serialize_field(self.public_key.as_ref(),)?;
      serializer.serialize_field(&self.message_index,)?;
      serializer.serialize_field(&self.previous_step,)?;
      serializer.end()
    }
  }

  impl<'de,> Deserialize<'de> for Header {
    #[inline]
    fn deserialize<D>(deserializer: D,) -> Result<Self, D::Error>
      where D: Deserializer<'de>, {
      use ::serde::de::Error;
      use std::fmt;

      struct HeaderVisitor;

      impl<'de,> Visitor<'de> for HeaderVisitor {
        type Value = Header;

        #[inline]
        fn expecting(&self, fmt: &mut fmt::Formatter,) -> fmt::Result {
          write!(fmt, "a tuple of length {}", FIELDS.len(),)
        }
        fn visit_seq<A>(self, mut seq: A,) -> Result<Self::Value, A::Error>
          where A: SeqAccess<'de>, {
          let public_key = {
            let public_key = seq.next_element::<[u8; 32]>()?
              .ok_or(Error::missing_field(FIELDS[0],),)?;
            
            public_key.into()
          };
          let message_index = seq.next_element()?
            .ok_or(Error::missing_field(FIELDS[1],),)?;
          let previous_step = seq.next_element()?
            .ok_or(Error::missing_field(FIELDS[2],),)?;
          
          Ok(Header { public_key, message_index, previous_step, })
        }
      }

      deserializer.deserialize_tuple_struct(stringify!(Header), FIELDS.len(), HeaderVisitor,)
    }  
  }

  #[cfg(test,)]
  mod tests {
    use super::*;

    #[test]
    fn test_header_serde() {
      let public_key = [1; 32].into();
      let message_index = 1;
      let previous_step = 2;
      let header = Header { public_key, message_index, previous_step, };
      let mut serialised = [0u8; 1024];
      let serialised = {
        let writer = &mut serialised.as_mut();

        serde_cbor::ser::to_writer_packed(writer, &header,)
          .expect("Error serialising the Header");
        
        let len = writer.len();
        let len = serialised.len() - len;

        &serialised[..len]
      };
      let other = serde_cbor::from_reader(serialised,)
        .expect("Error deserialising the header");

      assert_eq!(header, other, "Header deserialised incorrectly",);
    }
  }
}