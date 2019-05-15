//! Defines the opening half of a [Client].
//! 
//! Author -- daniel.bechaz@gmail.com  
//! Last Moddified --- 2019-05-12

use super::{aead::Algorithm, OpenData,};
use crate::{
  ratchet::Ratchet,
  message::Message,
  generic_array::{ArrayLength, GenericArray,},
  typenum::consts::U32,
};
use clear_on_drop::{ClearOnDrop, clear::Clear,};
use std::collections::HashMap;

mod serde;

/// The opening half of a Client.
pub(crate) struct OpenClient<Digest, State, Algorithm, Rounds, AadLength,>
  where State: ArrayLength<u8>,
    Algorithm: super::aead::Algorithm,
    AadLength: ArrayLength<u8>, {
  /// The Ratchet used to generate opening data.
  pub ratchet: Ratchet<Digest, State, Rounds,>,
  /// The number of messages sent under the current PublicKey.
  pub sent_count: u32,
  /// The current PublicKey of the remote Client.
  pub current_public_key: ClearOnDrop<GenericArray<u8, U32>>,
  /// The previous OpenData under the current PublicKey.
  pub current_keys: HashMap<u32, OpenData<Algorithm, AadLength,>>,
  /// The OpenData under the previous PublicKeys.
  pub previous_keys: HashMap<ClearOnDrop<GenericArray<u8, U32>>, HashMap<u32, OpenData<Algorithm, AadLength,>>>,
}

impl<D, S, A, R, L,> OpenClient<D, S, A, R, L,>
  where S: ArrayLength<u8>,
    A: Algorithm,
    L: ArrayLength<u8>, {
  /// Opens the passed message and appends the data to `buffer`.
  /// 
  /// If the message cannot be opened it is returned.
  /// 
  /// # Params
  /// 
  /// message --- The message to open.  
  /// buffer --- The buffer to append the decrypted message too.  
  /// 
  /// # Warning
  /// 
  /// Only call this function after ensuring that `OpenData` exists for the message.
  pub fn open<'a,>(&mut self, message: Message, buffer: &'a mut Vec<u8>,) -> Result<&'a mut [u8], Message> {
    use ring::aead::{self, OpeningKey, Nonce, Aad,};
    use std::hint;
    
    clear_on_drop::clear_stack_on_return_fnonce(1, move || {
      //The data to open this message.
      let open_data = match self.current_keys.remove(&message.header.message_index,) {
        Some(v) => v,
        None => return Err(message),
      };
      let key = match OpeningKey::new(A::algorithm(), &open_data.key,) {
        Ok(v) => v,
        //This is safe because we get the value from OpenData.
        _ => unsafe { hint::unreachable_unchecked() },
      };
      let nonce = match Nonce::try_assume_unique_for_key(&open_data.nonce,) {
        Ok(v) => v,
        //This is safe because we get the value from OpenData.
        _ => unsafe { hint::unreachable_unchecked() },
      };
      let aad = Aad::from(open_data.aad.as_ref(),);
      //The original length of the buffer.
      let buffer_len = buffer.len();
      //The message data to open.
      let data = {
        buffer.extend(message.data.iter().copied(),);

        &mut buffer[buffer_len..]
      };
      //Open the message.
      let data_len = aead::open_in_place(&key, nonce, aad, 0, data,).ok()
        //Get the length of the unencrypted data.
        .map(|data,| data.len(),)
        .ok_or_else(move || {
          //Store the key for a later attempt.
          self.current_keys.insert(message.header.message_index, open_data,); 
        
          message
        },)?;
      //The length of buffer which is used.
      let len = buffer_len + data_len;

      //Clear the unused data.
      buffer[len..].clear();
      //Remove the unused data.
      buffer.truncate(len,);

      Ok(&mut buffer[buffer_len..])
    },)
  }
}

impl<D, S, A, R, L,> Default for OpenClient<D, S, A, R, L,>
  where S: ArrayLength<u8>,
    A: Algorithm,
    L: ArrayLength<u8>, {
  #[inline]
  fn default() -> Self {
    Self {
      ratchet: Ratchet::default(),
      sent_count: 0,
      current_public_key: ClearOnDrop::new(GenericArray::default(),),
      current_keys: HashMap::default(),
      previous_keys: HashMap::default(),
    }
  }
}

impl<D, S, A, R, L,> Drop for OpenClient<D, S, A, R, L,>
  where S: ArrayLength<u8>,
    A: Algorithm,
    L: ArrayLength<u8>, {
  fn drop(&mut self,) { self.sent_count = 0; }
}

#[cfg(test,)]
mod tests {
  use super::*;
  use crate::{
    typenum::consts,
    message::Header,
    client::{LockClient, aead::Aes256Gcm,},
  };
  use sha1::Sha1;

  #[test]
  fn test_open_client() {
    let mut ratchet = Ratchet::new(&mut rand::thread_rng(),);
    let public_key = [1; 32];
    let mut lock = LockClient::<Sha1, consts::U500, Aes256Gcm, consts::U1, consts::U100,> {
      ratchet: ratchet.clone(),
      next_header: Header {
        public_key,
        ..Header::default()
      },
      ..LockClient::default()
    };
    let mut open = OpenClient::<Sha1, consts::U500, Aes256Gcm, consts::U1, consts::U100,> {
      current_public_key: ClearOnDrop::new(public_key.into(),),
      sent_count: 1,
      current_keys: vec![(0, OpenData::new(&mut ratchet,),),].into_iter().collect(),
      ratchet,
      previous_keys: Default::default(),
    };
    let msg = [1; 20];
    let locked_msg = lock.lock(&mut msg.clone(),)
      .expect("Error locking message");
    let mut buffer = Vec::new();
    
    open.open(Message { data: [1; 100].as_ref().into(), ..locked_msg }, &mut buffer,)
      .expect_err("Opened a corrupted message");

    let other_msg = open.open(locked_msg.clone(), &mut buffer,)
      .expect("Error opening message");

    assert_eq!(other_msg, msg.as_ref(), "Opened message corrupted",);
  }
}
