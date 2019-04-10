//! Defines `Message` types.
//! 
//! Author -- daniel.bechaz@gmail.com  
//! Last Moddified --- 2019-04-10

use std::{io::{self, Write,}, convert::TryInto,};

mod header;

pub use self::header::*;

/// A `Message` is a message [Header] and associated data.
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
    let header = Header::deserialise(bytes,)?;
    let bytes = &bytes[Header::SERIALISED_SIZE..];
    let (data_len, bytes,) = {
      if bytes.len() < 4 { return None }

      let (data_len, bytes,) = bytes.split_at(4,);
      let data_len = unsafe { *(data_len.as_ptr() as *const [u8; 4]) };
      let data_len = u32::from_be_bytes(data_len);
      let data_len = data_len.try_into().ok()?;

      (data_len, bytes,)
    };
    let data = {
      if bytes.len() < data_len { return None }

      let mut data = vec![0; data_len].into_boxed_slice();

      data.copy_from_slice(&bytes[..data_len],);

      data
    };
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
    self.header.serialise(writer,)?;

    let data_len: u32 = self.data.len().try_into()
      .or::<io::Error>(Err(io::ErrorKind::Other.into()),)?;
    writer.write_all(&data_len.to_be_bytes(),)?;
    
    writer.write_all(&*self.data,)
  }
}
