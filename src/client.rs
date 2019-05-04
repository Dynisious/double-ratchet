//! Defines the double ratchet [Client].
//! 
//! Author -- daniel.bechaz@gmail.com  
//! Last Moddified --- 2019-05-04

use crate::{message::Message, ratchet::Ratchet, typenum::{Unsigned, consts,},};
use digest::{BlockInput, generic_array::{ArrayLength, GenericArray,},};
use x25519_dalek::{PublicKey, StaticSecret,};
use rand_core::{RngCore, CryptoRng,};
use std::{ops, iter::{Iterator, FromIterator,},};

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
  /// Whether this initiator of the communication.
  local: bool,
}

impl<D, S, A, R, L,> Client<D, S, A, R, L,>
  where D: BlockInput,
    S: ArrayLength<u8> + ops::Sub<D::BlockSize>,
    A: Algorithm,
    L: ArrayLength<u8>,
    Ratchet<D, S, R,>: Iterator<Item = u8>,
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
  /// key --- The private key to connect with.  
  pub fn connect(remote: PublicKey, key: StaticSecret,) -> Self {
    let (lock, open,) = Self::generate_chains(&remote, &key,);
    let lock = LockClient::new(lock, (&key).into(),);
    let open = OpenClient::new(open, remote,);

    Client { lock, open, local: true, }
  }
  /// Accepts a connection from a remote Client.
  /// 
  /// The function is called after a preceeding `connect` call.
  /// 
  /// # Params
  /// 
  /// remote --- The public key of the remote Client.  
  /// key --- The private key to connect with.  
  pub fn accept(remote: PublicKey, key: StaticSecret,) -> Self {
    let (open, lock,) = Self::generate_chains(&remote, &key,);
    let lock = LockClient::new(lock, (&key).into(),);
    let open = OpenClient::new(open, remote,);

    Client { lock, open, local: false, }
  }
}

impl<D, S, A, R, L,> Client<D, S, A, R, L,>
  where S: ArrayLength<u8>,
    A: Algorithm,
    L: ArrayLength<u8>,
    Ratchet<D, S, R,>: Iterator<Item = u8>,
    A::KeyLength: ops::Add<A::NonceLength>,
    <A::KeyLength as ops::Add<A::NonceLength>>::Output: ops::Add<L>,
    <<A::KeyLength as ops::Add<A::NonceLength>>::Output as ops::Add<L>>::Output: ArrayLength<u8>, {
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
  where S: ArrayLength<u8>,
    A: Algorithm,
    L: ArrayLength<u8>,
    Ratchet<D, S, R,>: Iterator<Item = u8>,
    A::KeyLength: ops::Add<A::NonceLength>,
    <A::KeyLength as ops::Add<A::NonceLength>>::Output: ops::Add<L>,
    <<A::KeyLength as ops::Add<A::NonceLength>>::Output as ops::Add<L>>::Output: ArrayLength<u8>, {
  /// Performs a ratchet step.
  /// 
  /// # Params
  /// 
  /// public_key --- The PublicKey of the remote Client.  
  /// rand --- The source of randomness to generate a Diffie-Hellman keypair.  
  fn ratchet_step<Rand,>(&self, public_key: PublicKey, rand: &mut Rand,) -> Self
    where Rand: RngCore + CryptoRng, {
    let private_key = StaticSecret::new(rand,);

    unimplemented!()
  }
  /// Receives a message from the connected Client.
  /// 
  /// If successful the decrypted message is returned else the Message is returned with
  /// the error.
  /// 
  /// # Params
  /// 
  /// message --- The Message to decrypt.  
  pub fn open(&mut self, message: Message,) -> Result<Box<[u8]>, Message> {
    //Check for Ratchet step.
    if message.header.public_key.as_bytes() != self.open.current_public_key.as_bytes() {
      unimplemented!()
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
    
    let mut buffer = msg.clone();
    let message = lock.lock(&mut buffer,)
      .expect("Error locking message");
    
    assert!(buffer.iter().all(|&i,| i == 0,), "Error clearing buffer",);

    let buffer = open.open(message,)
      .expect("Error opening message");
    
    assert_eq!(buffer, msg, "Received message corrupted",);
    
    open.lock(&mut [0; 1024],).expect("Error encrypting throwaway message",);
    let mut buffer = msg.clone();
    let message = open.lock(&mut buffer,)
      .expect("Error locking message");
    
    assert!(buffer.iter().all(|&i,| i == 0,), "Error clearing buffer",);

    let buffer = lock.open(message,)
      .expect("Error opening message");
    
    assert_eq!(buffer, msg, "Received message corrupted",);
  }
}
