//! Defines the double ratchet [Client].
//! 
//! Author -- daniel.bechaz@gmail.com  
//! Last Moddified --- 2019-05-11

use crate::{
  ratchet::Ratchet,
  message::Message,
  typenum::consts,
  generic_array::{ArrayLength, GenericArray,},
};
use clear_on_drop::ClearOnDrop;
use rand::{RngCore, CryptoRng,};
use x25519_dalek::{PublicKey, StaticSecret,};
use std::collections::HashMap;

pub mod aead;
mod open_data;
mod lock;
mod open;
mod serde;

use self::{aead::{Algorithm, Aes256Gcm,}, open_data::OpenData, lock::*, open::*,};
pub use self::lock::LockError;

/// A double ratchet Client connected to a partner Client.
/// 
/// Bare in mind that Both Clients must be constructed with the same ADT parameters if
/// they are expected to work correctly.
pub struct Client<Digest, State, Algorithm: aead::Algorithm = Aes256Gcm, Rounds = consts::U1, AadLength = <Algorithm as aead::Algorithm>::TagLength,>
  where State: ArrayLength<u8>,
    AadLength: ArrayLength<u8>, {
  /// The locking half of the `Client`.
  lock: LockClient<Digest, State, Algorithm, Rounds, AadLength,>,
  /// The opening half of the `Client`.
  open: OpenClient<Digest, State, Algorithm, Rounds, AadLength,>,
  /// The private key needed to decrypt messages received from the remote Client in the next ratchet step.
  private_key: ClearOnDrop<GenericArray<u8, consts::U32>>,
  /// Whether this initiator of the communication.
  local: bool,
}

impl<D, S, A, R, L,> Client<D, S, A, R, L,>
  where S: ArrayLength<u8>,
    A: Algorithm,
    L: ArrayLength<u8>,
    Ratchet<D, S, R,>: RngCore + CryptoRng, {
  /// Generates a pair of Ratchet chains.
  /// 
  /// Used to initialise the ratchet steps.
  /// 
  /// # Params
  /// 
  /// remote --- The PublicKey of the partner Client.  
  /// key --- The private key pair of this Client.  
  fn generate_chains(remote: &PublicKey, key: &StaticSecret,) -> (Ratchet<D, S, R,>, Ratchet<D, S, R,>,) {
    //Perform initial Diffie-Hellman exchange.
    let mut ratchet = *key.diffie_hellman(&remote,).as_bytes();
    //Produce a Ratchet to generate state.
    let mut ratchet = Ratchet::<D, S, R,>::from(ratchet.as_mut(),);
    //Generate the first ratchet.
    let fst = Ratchet::new(&mut ratchet,);
    //Generate the first ratchet.
    let snd = Ratchet::new(&mut ratchet,);

    (fst, snd,)
  }
  /// Connects to a remote Client.
  /// 
  /// The function preceeds a call to `accept`.
  /// 
  /// # Params
  /// 
  /// remote --- The public key of the remote Client.  
  /// private_key --- The private key to connect using.  
  pub fn connect(remote: PublicKey, private_key: StaticSecret,) -> Box<Self> {
    let (lock, open,) = Self::generate_chains(&remote, &private_key,);
    let lock = LockClient::new(lock, (&private_key).into(),);
    let open = OpenClient::new(open, remote,);
    let private_key = ClearOnDrop::new(private_key.to_bytes().into(),);

    Box::new(Client { lock, open, private_key, local: true, },)
  }
  /// Accepts a connection from a remote Client.
  /// 
  /// The function is called after a preceeding `connect` call.
  /// 
  /// # Params
  /// 
  /// remote --- The public key of the remote Client.  
  /// private_key --- The private key to connect using.  
  pub fn accept(remote: PublicKey, private_key: StaticSecret,) -> Box<Self> {
    let (open, lock,) = Self::generate_chains(&remote, &private_key,);
    let lock = LockClient::new(lock, (&private_key).into(),);
    let open = OpenClient::new(open, remote,);
    let private_key = ClearOnDrop::new(private_key.to_bytes().into(),);

    Box::new(Client { lock, open, private_key, local: true, },)
  }
  /// Receives a message from the connected Client.
  /// 
  /// If the message is decrypted successfully the message data is returned.
  /// 
  /// # Params
  /// 
  /// message --- The Message to decrypt.  
  pub fn open(&mut self, message: Message,) -> Result<Box<[u8]>, Message> {
    use std::{mem, hint,};

    clear_on_drop::clear_stack_on_return_fnonce(1, move || {
      //Remember the current state for rollback purposes.
      let sent_count = self.open.sent_count;
      let mut ratchet = self.open.ratchet.clone();

      if self.open.current_public_key.as_ref() == message.header.public_key.as_bytes() {
        //Generate any skipped keys,
        if self.open.sent_count <= message.header.message_index {
          //Update the sent count.
          self.open.sent_count = message.header.message_index + 1;
          //Generate the skipped keys.
          for index in sent_count..self.open.sent_count {
            self.open.current_keys.insert(index, OpenData::new(&mut self.open.ratchet,),);
          }
        }

        let res = self.open.open(message,);

        if res.is_err() {
          //Remove the unneeded keys.
          for index in sent_count..self.open.sent_count {
            self.open.current_keys.remove(&index,);
          }
          //Reset the sent count.
          self.open.sent_count = sent_count;
          //Reset the ratchet.
          mem::swap(&mut self.open.ratchet, &mut ratchet,);
        }

        res
      } else {
        //Rememeber how many messages are in this ratchet step.
        let previous_step = message.header.previous_step;
        //Remember the current public key.
        let current_public_key = self.open.current_public_key.clone();
        //Update the sent count.
        self.open.sent_count = message.header.message_index + 1;
        //Generate any skipped keys in the current step.
        for index in sent_count..previous_step {
          self.open.current_keys.insert(index, OpenData::new(&mut self.open.ratchet,),);
        }
        //Update the current keys.
        let current_keys = mem::replace(
          &mut self.open.current_keys,
          HashMap::with_capacity(self.open.sent_count as usize,),
        );
        //Remember the current keys.
        self.open.previous_keys.insert(KeyBytes::from(*current_public_key,), current_keys,);
        //Update the public key.
        self.open.current_public_key.copy_from_slice(message.header.public_key.as_bytes(),);
        
        let res = self.open(message,);

        if res.is_err() {
          //Reset the current keys.
          self.open.current_keys = match self.open.previous_keys.remove(&KeyBytes::from(*current_public_key,),) {
            Some(v) => v,
            _ => unsafe { hint::unreachable_unchecked() },
          };
          //Reset the sent count.
          self.open.sent_count = sent_count;
          //Reset the public key.
          self.open.current_public_key = current_public_key;
          
          //Forget the unused keys.
          for index in sent_count..previous_step {
            self.open.current_keys.remove(&index,);
          }
          //Reset the ratchet.
          mem::swap(&mut self.open.ratchet, &mut ratchet,);
        }

        res
      }
    },)
  }
  /// Encrypts the passed message.
  /// 
  /// The buffer will be cleared if the message is encrypted successfully.
  /// 
  /// # Params
  /// 
  /// message --- The Message to encrypt.  
  pub fn lock(&mut self, message: &mut [u8],) -> Result<Message, LockError> {
    self.lock.lock(message,)
  }
}

#[cfg(test,)]
mod tests {
  use super::*;
  use sha1::Sha1;

  #[test]
  fn test_client() {
    let open = StaticSecret::from([1; 32],);
    let lock = StaticSecret::from([2; 32],);
    let pub_lock = (&lock).into();
    let mut lock = Client::<Sha1, consts::U500, aead::Aes256Gcm, consts::U1,>::connect((&open).into(), lock,);
    let mut open = Client::<Sha1, consts::U500, aead::Aes256Gcm, consts::U1,>::accept(pub_lock, open,);
    let msg = std::iter::successors(Some(1), |&i,| Some(i + 1),)
      .take(100,)
      .collect::<Box<[u8]>>();
    
    //Test sending.
    let mut buffer = msg.clone();
    let message = lock.lock(&mut buffer,)
      .expect("Error locking first message");
    
    assert!(buffer.iter().all(|&i,| i == 0,), "Error clearing buffer",);

    //Test receiving.
    let buffer = open.open(message,)
      .expect("Error opening first message");
    
    assert_eq!(buffer, msg, "First received message corrupted",);
    
    //Test sending other way.
    open.lock(&mut [0; 1024],).expect("Error encrypting throwaway message",);
    let mut buffer = msg.clone();
    let message = open.lock(&mut buffer,)
      .expect("Error locking second message");
    
    assert!(buffer.iter().all(|&i,| i == 0,), "Error clearing buffer",);

    //Test corrupted message.
    lock.open(Message { data: Box::new([1; 100]), ..message },)
      .expect_err("Opened corrupted message");
    //Test corrupted recovery.
    let buffer = lock.open(message,)
      .expect("Error opening second message");
    
    assert_eq!(buffer, msg, "Second received message corrupted",);
  }
}
