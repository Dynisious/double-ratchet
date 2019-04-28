//! Defines the double ratchet [Client].
//! 
//! Author -- daniel.bechaz@gmail.com  
//! Last Moddified --- 2019-04-28

use crate::{message::Message, ratchet::Ratchet,};
use generic_array::{ArrayLength, typenum::{consts, Unsigned,},};
use x25519_dalek::{PublicKey, StaticSecret,};
use digest::{Input, BlockInput, FixedOutput, Reset,};

pub mod aead;
mod send;
mod receive;

use self::{send::*, receive::*,};

/// A double ratchet Client connected to a partner Client.
/// 
/// Bare in mind that Both Clients must be constructed with the same ADT parameters if
/// they are expected to work correctly.
pub struct Client<Algorithm, Digest, Rounds = consts::U1, AadLength = consts::U0,>
  where Algorithm: aead::Algorithm,
    AadLength: ArrayLength<u8>, {
  /// The sending half of the `Client`.
  sending: SendClient<Algorithm, Digest, Rounds, AadLength,>,
  /// The receiving half of the `Client`.
  receiving: ReceiveClient<Algorithm, Digest, Rounds, AadLength,>,
}

impl<A, D, R, L,> Client<A, D, R, L,>
  where A: aead::Algorithm,
    D: Input + BlockInput + FixedOutput + Reset + Clone + Default,
    <D as BlockInput>::BlockSize: Clone,
    R: Unsigned + Clone,
    L: ArrayLength<u8>, {
  /// Connects to a remote Client.
  /// 
  /// # Params
  /// 
  /// remote --- The public key of the remote Client.  
  /// key_pair --- The private key to connect with.  
  pub fn connect(remote: PublicKey, key: StaticSecret,) -> Self {
    let mut bytes = *key.diffie_hellman(&remote,).as_bytes();
    let mut ratchet = Ratchet::<D, R,>::from_bytes(&mut bytes,);
    //The length of the ratchet state.
    let state = <D as BlockInput>::BlockSize::USIZE
      + A::KeyLength::USIZE
      + A::NonceLength::USIZE
      + A::TagLength::USIZE;
    //The bytes used to initialise the two chains.
    let state = {
      let state = ratchet.advance(state,)
        .expect("Error producing Ratchet state");
      
      state.into_boxed_slice()
    };
    //The Ratchet used to initialise the Client halves.
    let ratchet = Ratchet::new(state,);
    let sending = SendClient::new(ratchet.clone(), (&key).into(),);
    let receiving = ReceiveClient::new(ratchet, remote,);

    Client { sending, receiving, }
  }
  /// Receives a message from the connected Client.
  /// 
  /// If successful the decrypted message is returned else the Message is returned with
  /// the error.
  /// 
  /// # Params
  /// 
  /// message --- The Message to decrypt.  
  pub fn recv(&mut self, message: Message,) -> Result<Box<[u8]>, Message> {
    unimplemented!()
  }
  /// Encrypts the passed message.
  /// 
  /// The buffer will be cleared if the message is encrypted successfully.
  /// 
  /// # Params
  /// 
  /// message --- The Message to encrypt.  
  pub fn send(&mut self, message: &mut [u8],) -> Option<Message> {
    self.sending.send(message,)
  }
}

#[cfg(test,)]
mod tests {
  use super::*;
  use sha1::Sha1;

  #[test]
  fn test_client() {
    let recv = StaticSecret::from([1; 32],);
    let send = StaticSecret::from([2; 32],);
    let pub_send = (&send).into();
    let mut send = Client::<aead::Aes256Gcm, Sha1, consts::U3, consts::U100,>::connect((&recv).into(), send,);
    let mut recv = Client::<aead::Aes256Gcm, Sha1, consts::U3, consts::U100>::connect(pub_send, recv,);
    let msg = std::iter::successors(Some(1), |&i,| Some(i + 1),)
      .take(100,)
      .collect::<Box<_>>();
    
    let mut buffer = msg.clone();
    let message = send.send(&mut buffer,)
      .expect("Error sending message");
    
    assert!(buffer.iter().all(|&i,| i == 0,), "Error clearing buffer",);

    let buffer = recv.recv(message,)
      .expect("Error receiving message");
    
    assert_eq!(buffer, msg, "Received message corrupted",);
    
    recv.send(&mut [0; 1024],).expect("Error encrypting throwaway message",);
    let mut buffer = msg.clone();
    let message = recv.send(&mut buffer,)
      .expect("Error sending message");
    
    assert!(buffer.iter().all(|&i,| i == 0,), "Error clearing buffer",);

    let buffer = send.recv(message,)
      .expect("Error receiving message");
    
    assert_eq!(buffer, msg, "Received message corrupted",);
  }
}
