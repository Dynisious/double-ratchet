//! Defines the double ratchet [Client].
//! 
//! Author -- daniel.bechaz@gmail.com  
//! Last Moddified --- 2019-05-04

use crate::{message::Message, ratchet::Ratchet, typenum::{Unsigned, consts,},};
use digest::{BlockInput, generic_array::{ArrayLength, GenericArray,},};
use x25519_dalek::{PublicKey, StaticSecret,};
use std::{ops, iter::{TrustedLen, FromIterator,}, collections::HashMap,};

pub mod aead;
mod open_data;
mod lock;
mod open;
mod serde;

use self::{aead::{Algorithm, Aes256Gcm,}, open_data::OpenData, lock::*, open::*,};

/// A double ratchet Client connected to a partner Client.
/// 
/// Bare in mind that Both Clients must be constructed with the same ADT parameters if
/// they are expected to work correctly.
pub struct Client<Digest, State, Algorithm = Aes256Gcm, Rounds = consts::U1, AadLength = consts::U0,>
  where State: ArrayLength<u8>,
    Algorithm: aead::Algorithm,
    AadLength: ArrayLength<u8>, {
  /// The locking half of the `Client`.
  lock: LockClient<Digest, State, Algorithm, Rounds, AadLength,>,
  /// The opening half of the `Client`.
  open: OpenClient<Digest, State, Algorithm, Rounds, AadLength,>,
  /// The private key needed to decrypt messages received from the remote Client in the next ratchet step.
  private_key: StaticSecret,
  /// Whether this initiator of the communication.
  local: bool,
}

impl<D, S, A, R, L,> Client<D, S, A, R, L,>
  where D: BlockInput,
    S: ArrayLength<u8> + ops::Sub<D::BlockSize>,
    A: Algorithm,
    L: ArrayLength<u8>,
    Ratchet<D, S, R,>: TrustedLen<Item = u8>,
    GenericArray<u8, S>: FromIterator<u8>,
    <S as ops::Sub<D::BlockSize>>::Output: Unsigned, {
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
    let mut bytes = *key.diffie_hellman(&remote,).as_bytes();
    //Produce a Ratchet to generate state.
    let mut ratchet = Ratchet::<D, S, R,>::new(&mut bytes,);
    //Generate the first ratchet.
    let fst = {
      let state = &mut GenericArray::<u8, S>::from_iter(&mut ratchet,);
      
      Ratchet::new(state,)
    };
    //Generate the first ratchet.
    let snd = {
      let state = &mut GenericArray::<u8, S>::from_iter(ratchet,);
      
      Ratchet::new(state,)
    };

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
  pub fn connect(remote: PublicKey, private_key: StaticSecret,) -> Self {
    let (lock, open,) = Self::generate_chains(&remote, &private_key,);
    let lock = LockClient::new(lock, (&private_key).into(),);
    let open = OpenClient::new(open, remote,);

    Client { lock, open, private_key, local: true, }
  }
  /// Accepts a connection from a remote Client.
  /// 
  /// The function is called after a preceeding `connect` call.
  /// 
  /// # Params
  /// 
  /// remote --- The public key of the remote Client.  
  /// private_key --- The private key to connect using.  
  pub fn accept(remote: PublicKey, private_key: StaticSecret,) -> Self {
    let (open, lock,) = Self::generate_chains(&remote, &private_key,);
    let lock = LockClient::new(lock, (&private_key).into(),);
    let open = OpenClient::new(open, remote,);

    Client { lock, open, private_key, local: false, }
  }
}

impl<D, S, A, R, L,> Client<D, S, A, R, L,>
  where S: ArrayLength<u8>,
    A: Algorithm,
    L: ArrayLength<u8>,
    Ratchet<D, S, R,>: TrustedLen<Item = u8>, {
  /// Encrypts the passed message.
  /// 
  /// The buffer will be cleared if the message is encrypted successfully.
  /// 
  /// # Params
  /// 
  /// message --- The Message to encrypt.  
  pub fn lock(&mut self, message: &mut [u8],) -> Option<Message> {
    self.lock.lock(message,)
  }
}

impl<D, S, A, R, L,> Client<D, S, A, R, L,>
  where D: BlockInput,
    S: ArrayLength<u8> + ops::Sub<D::BlockSize>,
    A: Algorithm,
    L: ArrayLength<u8>,
    Ratchet<D, S, R,>: TrustedLen<Item = u8>,
    GenericArray<u8, S>: FromIterator<u8>,
    <S as ops::Sub<D::BlockSize>>::Output: Unsigned, {
  /// Receives a message from the connected Client.
  /// 
  /// If successful the decrypted message is returned else the Message is returned with
  /// the error.
  /// 
  /// # Params
  /// 
  /// message --- The Message to decrypt.  
  /// 
  /// # Warning
  /// 
  /// * If `message` is not from the Client paired with this one it will corrupt the state of this Client.
  /// 
  /// # Panics
  /// 
  /// * If previous corruption of state is detected.
  pub fn open(&mut self, message: Message,) -> Result<Box<[u8]>, Message> {
    use std::mem;

    //Check for Ratchet step.
    if message.header.public_key.as_bytes() != self.open.current_public_key.as_bytes()
      && !self.open.previous_keys.contains_key(message.header.public_key.as_bytes(),) {
      //Generate a new private key.
      let private_key = mem::replace(&mut self.private_key, StaticSecret::new(&mut rand::thread_rng(),),);
      //Generate the new ratchets.
      let (lock, open,) = {
        let (local, remote,) = Self::generate_chains(&message.header.public_key, &private_key,);

        if self.local { (local, remote,) }
        else { (remote, local,) }
      };

      self.lock = LockClient::new(lock, (&private_key).into(),);

      //Generate skipped keys.
      for index in self.open.sent_count..message.header.message_index {
        self.open.current_keys.insert(index, OpenData::from_iter(&mut self.open.ratchet,),);
      }
      //Store the skipped keys.
      self.open.previous_keys.insert(
        *self.open.current_public_key.as_bytes(),
        mem::replace(&mut self.open.current_keys, HashMap::new(),),
      );
      //Reset the sent count.
      self.open.sent_count = 0;
      //Update the Ratchet.
      self.open.ratchet = open;
      //Update the public key.
      self.open.current_public_key = message.header.public_key;
    }

    //Open the message.
    self.open.open(message,)
  }
}

#[cfg(test,)]
impl<D, S, A, R, L,> PartialEq for Client<D, S, A, R, L,>
  where S: ArrayLength<u8>,
    A: aead::Algorithm,
    L: ArrayLength<u8>, {
  #[inline]
  fn eq(&self, rhs: &Self,) -> bool {
    self.local == rhs.local
    && self.open == rhs.open
    && self.private_key.to_bytes() == rhs.private_key.to_bytes()
    && self.local == rhs.local
  }
}

#[cfg(test,)]
impl<D, S, A, R, L,> Eq for Client<D, S, A, R, L,>
  where S: ArrayLength<u8>,
    A: aead::Algorithm,
    L: ArrayLength<u8>, {}

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
      .expect("Error locking message");
    
    assert!(buffer.iter().all(|&i,| i == 0,), "Error clearing buffer",);

    //Test receiving.
    let buffer = open.open(message,)
      .expect("Error opening message");
    
    assert_eq!(buffer, msg, "Received message corrupted",);
    
    //Test sending other way.
    open.lock(&mut [0; 1024],).expect("Error encrypting throwaway message",);
    let mut buffer = msg.clone();
    let message = open.lock(&mut buffer,)
      .expect("Error locking message");
    
    assert!(buffer.iter().all(|&i,| i == 0,), "Error clearing buffer",);

    //Test corrupted message.
    lock.open(Message { data: Box::new([1; 100]), ..message },)
      .expect_err("Opened corrupted message");
    //Test corrupted recovery.
    let buffer = lock.open(message,)
      .expect("Error opening message");
    
    assert_eq!(buffer, msg, "Received message corrupted",);
  }
}
