//! Defines `Message` types.
//! 
//! Author -- daniel.bechaz@gmail.com  
//! Last Moddified --- 2019-04-10

use std::{io::{self, Write,}, convert::TryInto,};

mod header;

pub use self::header::*;

/*
 * Definition of a serialised `Message` struct.
 * |-------Size - 44+ bytes------|
 * |header   - 40 bytes          |
 * |data-len - 4 bytes           |
 * |data     - 0-(2^32 - 1) bytes|
 * |-----------------------------|
 */

/// A `Message` is a message [Header] and associated data.
#[derive(PartialEq, Eq, Debug,)]
pub struct Message {
  /// The `Message` [Header].
  pub header: Header,
  /// The `Message` data.
  pub data: Box<[u8]>,
}

impl Message {
  /// Try to decode a `Messsage` from bytes.
  /// 
  /// Returns the `Message` and the number of bytes used to decode the `Message`.
  /// 
  /// If there is not enough data to decode a `Message` `None` is returned.
  /// 
  /// # Params
  /// 
  /// bytes --- The bytes to decode the message from.  
  pub fn deserialise(bytes: &[u8],) -> Option<(Message, usize,)> {
    //Deserialise the header.
    let header = Header::deserialise(bytes,)?;
    //Trim the header bytes.
    let bytes = &bytes[Header::SERIALISED_SIZE..];

    //Get the data length bytes.
    let (data_len, bytes,) = {
      if bytes.len() < 4 { return None }

      let (data_len, bytes,) = bytes.split_at(4,);
      let data_len = unsafe { *(data_len.as_ptr() as *const [u8; 4]) };
      let data_len = u32::from_be_bytes(data_len);
      let data_len = data_len.try_into().ok()?;

      (data_len, bytes,)
    };
    //Get the arbitrarily many data bytes.
    let data = {
      if bytes.len() < data_len { return None }

      let mut data = vec![0; data_len].into_boxed_slice();

      data.copy_from_slice(&bytes[..data_len],);

      data
    };
    //Calclate the bytes used.
    let data_len = data.len() + 4 + Header::SERIALISED_SIZE;
    let message = Self { header, data, };

    Some((message, data_len,))
  }
  /// Encodes a `Messsage` as bytes.
  /// 
  /// # Params
  /// 
  /// writer --- The writer to write too.  
  pub fn serialise(&self, writer: &mut dyn Write,) -> io::Result<()> {
    //Serialise the header bytes.
    self.header.serialise(writer,)?;

    //Write out the datas length.
    let data_len: u32 = self.data.len().try_into()
      .or::<io::Error>(Err(io::ErrorKind::Other.into()),)?;
    writer.write_all(&data_len.to_be_bytes(),)?;
    
    //Write out the data.
    writer.write_all(&*self.data,)
  }
}

#[cfg(test,)]
mod tests {
  use super::*;

  #[test]
  fn test_message_serde() {
    const SERIALISED_SIZE: usize = Header::SERIALISED_SIZE + 8;
    const SERIALISED: [u8; SERIALISED_SIZE] = [
      1, 1, 1, 1, 1, 1, 1, 1,
      1, 1, 1, 1, 1, 1, 1, 1,
      1, 1, 1, 1, 1, 1, 1, 1,
      1, 1, 1, 1, 1, 1, 1, 1,
      0, 0, 0, 1,
      0, 0, 0, 2,
      0, 0, 0, 4,
      1, 2, 3, 4,
    ];

    let public_key = [1; 32].into();
    let message_index = 1;
    let previous_step = 2;
    let header = Header { public_key, message_index, previous_step, };
    let data = vec![1, 2, 3, 4,].into_boxed_slice();
    let message = Message { header, data, };
    let mut bytes = [0; SERIALISED_SIZE];
    let writer = &mut bytes.as_mut();

    message.serialise(writer,)
      .expect("Error serialising the message");
    assert!(writer.is_empty(), "Serialisation did not write expected count",);
    assert_eq!(bytes.as_ref(), SERIALISED.as_ref(), "Message serialised incorrectly",);

    let (other, len,) = Message::deserialise(&bytes,)
      .expect("Error deserialising the header");
    assert_eq!(SERIALISED_SIZE, len, "Header deserialised incorrectly",);
    assert_eq!(other, message, "Header deserialised incorrectly",);
  }
}
