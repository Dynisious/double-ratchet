//! Defines the double ratchet clients [LocalClient] and [RemoteClient].
//! 
//! Author -- daniel.bechaz@gmail.com  
//! Last Moddified --- 2019-05-21

use crate::{
  ratchet::Ratchet,
  message::Message,
  typenum::consts::{self, U32,},
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
use crate::framed::Framed;

/// The initiating end of a Double-Ratchet comunication.
/// 
/// Bare in mind that Both Clients must be constructed with the same ADT parameters if
/// they are expected to work correctly.
#[derive(Serialize, Deserialize,)]
pub struct LocalClient<Digest, State, Algorithm = Aes256Gcm, Rounds = consts::U1, AadLength = consts::U0,>(Box<InnerClient<Digest, State, Algorithm, Rounds, AadLength,>>,)
  where State: 'static + ArrayLength<u8>,
    Algorithm: aead::Algorithm,
    AadLength: 'static + ArrayLength<u8>;

impl<D, S, A, R, L,> LocalClient<D, S, A, R, L,>
  where S: ArrayLength<u8>,
    A: Algorithm,
    L: ArrayLength<u8>,
    Ratchet<D, S, R,>: RngCore + CryptoRng, {
  /// Initiates communication with a remote Client.
  /// 
  /// The function preceeds a call to `accept`.
  /// 
  /// # Params
  /// 
  /// remote --- The public key of the remote Client.  
  /// private_key --- The private key to connect using.  
  pub fn connect(remote: &PublicKey, private_key: &StaticSecret,) -> Self {
    let mut client = Box::<InnerClient<D, S, A, R, L,>>::default();
    let mut ratchet = Ratchet::from(private_key.diffie_hellman(remote,).as_bytes().clone().as_mut(),);

    client.private_key.copy_from_slice(&StaticSecret::new(&mut rand::thread_rng(),).to_bytes().as_ref(),);

    client.lock.ratchet.reseed(&mut ratchet,);
    client.lock.next_header.public_key.copy_from_slice(PublicKey::from(private_key,).as_bytes().as_ref(),);

    client.open.ratchet.reseed(&mut ratchet,);
    client.open.current_public_key.copy_from_slice(remote.as_bytes().as_ref(),);

    LocalClient(client,)
  }
}

impl<D, S, A, R, L,> Client for LocalClient<D, S, A, R, L,>
  where S: ArrayLength<u8>,
    A: Algorithm,
    L: ArrayLength<u8>,
    Ratchet<D, S, R,>: RngCore + CryptoRng, {
  #[inline]
  fn open<'a,>(&mut self, message: Message, buffer: &'a mut Vec<u8>,) -> Result<&'a mut [u8], (Message, Error,)> {
    self.0.open(message, buffer, true,)
  }
  #[inline]
  fn lock(&mut self, message: &mut [u8],) -> Result<Message, Error> {
    self.0.lock(message,)
  }
}

/// The partner end of a Double-Ratchet comunication.
/// 
/// Bare in mind that Both Clients must be constructed with the same ADT parameters if
/// they are expected to work correctly.
#[derive(Serialize, Deserialize,)]
pub struct RemoteClient<Digest, State, Algorithm = Aes256Gcm, Rounds = consts::U1, AadLength = consts::U0,>(Box<InnerClient<Digest, State, Algorithm, Rounds, AadLength,>>,)
  where State: 'static + ArrayLength<u8>,
    Algorithm: aead::Algorithm,
    AadLength: 'static + ArrayLength<u8>;

impl<D, S, A, R, L,> RemoteClient<D, S, A, R, L,>
  where S: ArrayLength<u8>,
    A: Algorithm,
    L: ArrayLength<u8>,
    Ratchet<D, S, R,>: RngCore + CryptoRng, {
  /// Accepts communication from a remote Client.
  /// 
  /// The function follows a call to `connect`.
  /// 
  /// # Params
  /// 
  /// remote --- The public key of the remote Client.  
  /// private_key --- The private key to connect using.  
  pub fn accept(remote: &PublicKey, private_key: &StaticSecret,) -> Self {
    let mut client = Box::<InnerClient<D, S, A, R, L,>>::default();
    let mut ratchet = Ratchet::from(private_key.diffie_hellman(remote,).as_bytes().clone().as_mut(),);

    client.private_key.copy_from_slice(StaticSecret::new(&mut rand::thread_rng(),).to_bytes().as_ref(),);

    client.open.ratchet.reseed(&mut ratchet,);
    client.open.current_public_key.copy_from_slice(remote.as_bytes().as_ref(),);

    client.lock.ratchet.reseed(&mut ratchet,);
    client.lock.next_header.public_key.copy_from_slice(PublicKey::from(private_key,).as_bytes().as_ref(),);

    RemoteClient(client,)
  }
}

impl<D, S, A, R, L,> Client for RemoteClient<D, S, A, R, L,>
  where S: ArrayLength<u8>,
    A: Algorithm,
    L: ArrayLength<u8>,
    Ratchet<D, S, R,>: RngCore + CryptoRng, {
  #[inline]
  fn open<'a,>(&mut self, message: Message, buffer: &'a mut Vec<u8>,) -> Result<&'a mut [u8], (Message, Error,)> {
    self.0.open(message, buffer, false,)
  }
  #[inline]
  fn lock(&mut self, message: &mut [u8],) -> Result<Message, Error> {
    self.0.lock(message,)
  }
}

/// A double ratchet Client connected to a partner Client.
/// 
/// Bare in mind that Both Clients must be constructed with the same ADT parameters if
/// they are expected to work correctly.
pub(crate) struct InnerClient<Digest, State, Algorithm, Rounds, AadLength,>
  where State: ArrayLength<u8>,
    Algorithm: aead::Algorithm,
    AadLength: ArrayLength<u8>, {
  /// The locking half of the `Client`.
  lock: LockClient<Digest, State, Algorithm, Rounds, AadLength,>,
  /// The opening half of the `Client`.
  open: OpenClient<Digest, State, Algorithm, Rounds, AadLength,>,
  /// The private key needed to decrypt messages received from the remote Client in the next ratchet step.
  private_key: ClearOnDrop<GenericArray<u8, U32>>,
}

impl<D, S, A, R, L,> InnerClient<D, S, A, R, L,>
  where S: ArrayLength<u8>,
    A: Algorithm,
    L: ArrayLength<u8>,
    Ratchet<D, S, R,>: RngCore + CryptoRng, {
  /// Receives a message from the connected Client.
  /// 
  /// If the message is decrypted successfully the message data is appended to `buffer`.
  /// 
  /// # Params
  /// 
  /// message --- The Message to decrypt.  
  /// buffer --- The buffer to write the decrypted message too.  
  /// local --- Indicates whether this Client is the initiator of the communication for ratchet steps.  
  pub fn open<'a,>(&mut self, message: Message, buffer: &'a mut Vec<u8>, local: bool,) -> Result<&'a mut [u8], (Message, Error,)> {
    use std::{mem, hint,};

    //Remember the ratchet state.
    let mut ratchet = self.open.ratchet.clone();
    let mut sent_count = self.open.sent_count;
    let sent_count = ClearOnDrop::new(&mut sent_count,);
    //Check if the message is part of the current ratchet step.
    let current_step = self.open.current_public_key.as_ref() == message.header.public_key.as_ref();
    //Check if the message is part of a new ratchet step.
    let new_step = !current_step
      //Check if it is part of a previous step.
      && self.open.previous_keys.keys().all(|key,| key.as_ref() != message.header.public_key.as_ref(),);
    //Ensure that a result is created.
    let res;

    //If the message is part of the next step advance the step.
    if new_step {
      //Update the sent count.
      self.open.sent_count = 0;

      //Update the current public key.
      let current_public_key = self.open.current_public_key.clone();
      self.open.current_public_key.copy_from_slice(&message.header.public_key,);

      //Update the private key.
      let private_key = self.private_key.clone();
      self.private_key.copy_from_slice(
        ClearOnDrop::new(
          &mut StaticSecret::new(&mut rand::thread_rng(),).to_bytes(),
        ).as_ref(),
      );

      //Generate any skipped keys.
      if *sent_count <= message.header.previous_step {
        //Generate the skipped keys.
        for index in *sent_count..message.header.previous_step {
          self.open.current_keys.insert(index, OpenData::new(&mut self.open.ratchet,),);
        }
      }

      //Move the current keys into the previous keys.
      self.open.previous_keys.insert(
        current_public_key.clone(),
        //Update the current keys.
        mem::replace(
          &mut self.open.current_keys,
          HashMap::with_capacity(message.header.message_index as usize + 1,),
        ),
      );

      //Update the lock state.
      let mut lock_client = mem::replace(&mut self.lock, LockClient::default(),);
      self.lock.next_header.public_key.copy_from_slice(&self.private_key,);

      //Reseed the chains.
      let mut step_seed = Ratchet::from(unsafe {
        //These calls are safe because we can only initialise these fields with these
        //types or deserialisation.
        let private = mem::transmute::<_, &StaticSecret>(&self.private_key,);
        let public = mem::transmute::<_, &PublicKey>(&self.open.current_public_key,);

        private.diffie_hellman(public,).as_bytes().clone()
      }.as_mut(),);
      if local {
        self.lock.ratchet.reseed(&mut step_seed,);
        self.open.ratchet.reseed(&mut step_seed,);
      } else {
        self.open.ratchet.reseed(&mut step_seed,);
        self.lock.ratchet.reseed(&mut step_seed,);
      }

      let previous_step = message.header.previous_step;

      res = self.open(message, buffer, local,);

      //Rollback if there was an error.
      if res.is_err() {
        //Rollback the lock state.
        self.lock = mem::replace(&mut lock_client, LockClient::default(),);

        //Rollback the current keys.
        match self.open.previous_keys.remove(&current_public_key,) {
          Some(current_keys) => self.open.current_keys = current_keys,
          //This should always be safe because we are rolling back a previous change.
          None => unsafe { hint::unreachable_unchecked() },
        }

        //Delete generated keys.
        if *sent_count <= previous_step {
          for index in *sent_count..previous_step {
            self.open.current_keys.remove(&index,);
          }
        }

        //Rollback the private key.
        self.private_key = private_key;
        //Rollback the current public key.
        self.open.current_public_key = current_public_key;
      }
    //The message is part of an existing ratchet step.
    } else {
      //If the message is part of the current step make sure we have generated the key for it.
      if current_step {
        //Update the sent count.
        self.open.sent_count = message.header.message_index + 1;

        //Generate any skipped keys.
        if *sent_count <= message.header.message_index {
          //Generate the skipped keys.
          for index in *sent_count..self.open.sent_count {
            self.open.current_keys.insert(index, OpenData::new(&mut self.open.ratchet,),);
          }
        }
      }

      res = self.open.open(message, buffer,);

      //Rollback if there was an error.
      if res.is_err() {
        //Delete the generated keys.
        for index in *sent_count..self.open.sent_count {
          self.open.current_keys.remove(&index,);
        }
      }
    }

    if res.is_err() {
      //Rollback the sent count.
      self.open.sent_count = *sent_count;
      //Rollback the ratchet.
      self.open.ratchet = mem::replace(&mut ratchet, Ratchet::default(),);
    }

    res
  }
  /// Encrypts the passed message.
  /// 
  /// The buffer will be cleared if the message is encrypted successfully.
  /// 
  /// # Params
  /// 
  /// message --- The Message to encrypt.  
  pub fn lock(&mut self, message: &mut [u8],) -> Result<Message, Error> {
    self.lock.lock(message,)
  }
}

impl<D, S, A, R, L,> Default for InnerClient<D, S, A, R, L,>
  where S: ArrayLength<u8>,
    A: Algorithm,
    L: ArrayLength<u8>, {
  #[inline]
  fn default() -> Self {
    Self {
      lock: LockClient::default(),
      open: OpenClient::default(),
      private_key: ClearOnDrop::new(GenericArray::default(),),
    }
  }
}

/// Defines functionality of a Double-Ratchet `Client`.
pub trait Client: Sized {
  /// Receives a message from the connected `Client`.
  /// 
  /// If the message is decrypted successfully the message data is appended to `buffer`.
  /// 
  /// # Params
  /// 
  /// message --- The Message to decrypt.  
  /// buffer --- The buffer to write the decrypted message too.  
  fn open<'a,>(&mut self, message: Message, buffer: &'a mut Vec<u8>,) -> Result<&'a mut [u8], (Message, Error,)>;
  /// Encrypts the passed message.
  /// 
  /// The buffer will be cleared if the message is encrypted successfully.
  /// 
  /// # Params
  /// 
  /// message --- The Message to encrypt.  
  fn lock(&mut self, message: &mut [u8],) -> Result<Message, Error>;
  /// Returns a [Framed] around this `Client`.
  /// 
  /// # Params
  /// 
  /// io --- The `IO` object to read and/or write messages to/from.  
  #[inline]
  fn framed<Io,>(self, io: Io,) -> Framed<Io, Self,> { Framed::new(io, self,) }
}

impl<'t, T,> Client for &'t mut T
  where T: Client {
  #[inline]
  fn open<'a,>(&mut self, message: Message, buffer: &'a mut Vec<u8>,) -> Result<&'a mut [u8], (Message, Error,)> {
    T::open(self, message, buffer,)
  }
  #[inline]
  fn lock(&mut self, message: &mut [u8],) -> Result<Message, Error> {
    T::lock(self, message,)
  }
}

impl<T,> Client for Box<T>
  where T: Client {
  #[inline]
  fn open<'a,>(&mut self, message: Message, buffer: &'a mut Vec<u8>,) -> Result<&'a mut [u8], (Message, Error,)> {
    T::open(self, message, buffer,)
  }
  #[inline]
  fn lock(&mut self, message: &mut [u8],) -> Result<Message, Error> {
    T::lock(self, message,)
  }
}

impl<D, S, A, R, L,> Client for (bool, Box<InnerClient<D, S, A, R, L,>>,)
  where S: ArrayLength<u8>,
    A: aead::Algorithm,
    L: ArrayLength<u8>,
    Ratchet<D, S, R,>: RngCore + CryptoRng, {
  #[inline]
  fn open<'a,>(&mut self, message: Message, buffer: &'a mut Vec<u8>,) -> Result<&'a mut [u8], (Message, Error,)> {
    self.1.open(message, buffer, self.0,)
  }
  #[inline]
  fn lock(&mut self, message: &mut [u8],) -> Result<Message, Error> {
    self.1.lock(message,)
  }
}

/// An error returned from locking a message.
#[derive(PartialEq, Eq, Clone, Copy, Debug,)]
pub enum Error {
  /// The message was too long to lock.
  MessageLength,
  /// The encryption errored.
  Encryption,
  /// There was no key to open a message.
  NoKey,
  /// The decryption errored.
  /// 
  /// # Warning
  /// 
  /// * If an attempt is made to decrypt a message from a previous ratchet step more than
  /// once it is possible for this error to be returned instead of `NoKey` if the client
  /// no longer remembers the public key of the message's header.
  Decryption,
}

#[cfg(test,)]
mod tests {
  use super::*;
  use sha1::Sha1;

  #[test]
  fn test_client() {
    use std::iter::Extend;

    let open_sec = StaticSecret::from([1; 32],);
    let lock_sec = StaticSecret::from([2; 32],);
    let mut lock = LocalClient::<Sha1, consts::U64, aead::Aes256Gcm, consts::U1, consts::U10,>::connect(&(&open_sec).into(), &lock_sec,);
    let mut open = RemoteClient::<Sha1, consts::U64, aead::Aes256Gcm, consts::U1, consts::U10,>::accept(&(&lock_sec).into(), &open_sec,);
    let msg = std::iter::successors(Some(1), |&i,| Some(i + 1),)
      .take(100,)
      .collect::<Box<[u8]>>();
    
    //Test sending.
    let mut buffer = msg.iter().copied().collect::<Vec<_>>();
    let message = lock.lock(&mut buffer,)
      .expect("Error locking first message");
    assert!(buffer.iter().all(|&i,| i == 0,), "Error clearing buffer",);

    //Test receiving.
    buffer.clear();
    open.open(message, &mut buffer,).expect("Error opening first message");
    assert_eq!(buffer, msg.as_ref(), "First received message corrupted",);
    
    //Test sending other way.
    open.lock(&mut [0; 1024],).expect("Error encrypting throwaway message",);
    buffer.clear();
    buffer.extend(msg.iter().copied(),);
    let message = open.lock(&mut buffer,).expect("Error locking second message");
    assert!(buffer.iter().all(|&i,| i == 0,), "Error clearing buffer",);

    //Test receiving other way.
    buffer.clear();
    let buffer = lock.open(message.clone(), &mut buffer,)
      .expect("Error opening second message");
    assert_eq!(buffer, msg.as_ref(), "Second received message corrupted",);

    lock.open(message, &mut Vec::new(),).expect_err("Opened a message twice");
  }
  #[test]
  fn test_client_recovery() {
    let open_sec = StaticSecret::from([1; 32],);
    let lock_sec = StaticSecret::from([2; 32],);
    let mut lock = LocalClient::<Sha1, consts::U64, aead::Aes256Gcm, consts::U1, consts::U10,>::connect(&(&open_sec).into(), &lock_sec,);
    let mut open = RemoteClient::<Sha1, consts::U64, aead::Aes256Gcm, consts::U1, consts::U10,>::accept(&(&lock_sec).into(), &open_sec,);
    let msg = std::iter::successors(Some(1), |&i,| Some(i + 1),)
      .take(100,)
      .collect::<Box<[u8]>>();
    
    //Test sending.
    let mut buffer = msg.iter().copied().collect::<Vec<_>>();
    let message = lock.lock(&mut buffer,)
      .expect("Error locking message");
    assert!(buffer.iter().all(|&i,| i == 0,), "Error clearing buffer",);
    
    //Test corrupted message.
    buffer.clear();
    lock.open(Message { data: Box::new([1; 100]), ..message }, &mut buffer,)
      .expect_err("Opened corrupted message");

    //Test corrupted recovery.
    buffer.clear();
    open.open(message, &mut buffer,).expect("Error opening message");
    assert_eq!(buffer, msg.as_ref(), "Received message corrupted",);
  }
}
