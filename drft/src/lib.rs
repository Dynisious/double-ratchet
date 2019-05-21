//! A file transfer and encryption/decryption application.
//! 
//! Author --- daniel.bechaz@gmail.com  
//! Last Moddified --- 2019-05-21

#![deny(missing_docs,)]

use double_ratchet::{Client, generic_array::ArrayLength,};
use std::{io::{self, Read, Write,}, path::Path,};

pub use double_ratchet;
pub use double_ratchet::generic_array;

pub mod config;

use self::config::*;

/// Locks the file at the specified location.
/// 
/// # Params
/// 
/// client --- The double ratchet `Client` to used to encrypt the file.  
/// in_path --- The path to the file to be encrypted.  
/// config --- The configuration for the operation.  
pub fn lock_file_with_config<'a, BlockSize, P,>(client: &mut impl Client, in_path: P, config: FileConfig<'a,>,) -> io::Result<()>
  where BlockSize: ArrayLength<u8>,
    P: AsRef<Path>, {
  use std::fs::OpenOptions;

  //The input file.
  let mut in_file = OpenOptions::new()
    .read(true,)
    .write(config.delete_input,)
    .open(in_path,)?;
  //The output file.
  let mut out_file = {
    let mut out_file = OpenOptions::new();

    out_file.write(true,);
    
    if config.overwrite_existing {
      out_file.create(true,)
      .truncate(true,)
    } else {
      out_file.create_new(true,)
    }.open(config.out_file,)?
  };

  unimplemented!()
}

/// Locks the bytes from `input` in `BlockSize` chunks (other than the final block which
/// may be smaller) and writes them to `output`.
/// 
/// # Params
/// 
/// client --- The `Client` to encrypt blocks using.  
/// input --- The input to read blocks from.  
/// output --- The output to write encrypted blocks too.  
pub fn lock_io<'a, BlockSize,>(client: &'a mut impl Client, mut input: impl Read, mut output: impl Write,) -> io::Result<()>
  where BlockSize: ArrayLength<u8>, {
  unimplemented!()
}

#[cfg(test,)]
mod tests {
  use super::*;

  #[test]
  fn test_lock_file() {
    
  }
}
