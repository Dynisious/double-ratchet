//! Defines the [Framed] wrapper.
//! 
//! Author -- daniel.bechaz@gmail.com  
//! Last Moddified --- 2019-05-15

use super::{aead, Client, Message,};
use crate::generic_array::ArrayLength;
use ratchet::Ratchet;
use clear_on_drop::ClearOnDrop;
use rand::{RngCore, CryptoRng,};
use std::{io::{self, Read, Write,}, task::Poll,};

/// Wraps a [Client] and a Stream/Sink of parse messages to/from.
pub struct Framed<Io, Digest, State, Algorithm, Rounds, AadLength,>
  where Io: Read + Write,
    State: ArrayLength<u8>,
    Algorithm: aead::Algorithm,
    AadLength: ArrayLength<u8>, {
  io: Io,
  client: Box<Client<Digest, State, Algorithm, Rounds, AadLength,>>,
  /// The internal buffer of unparsed data.
  buffer: Vec<u8>,
  /// An indicator of if the Client is the initiating side.
  local: bool,
}

impl<Io, D, S, A, R, L,> Framed<Io, D, S, A, R, L,>
  where Io: Read + Write,
    S: ArrayLength<u8>,
    A: aead::Algorithm,
    L: ArrayLength<u8>, {
  /// Construct a new `Framed` from parts.
  /// 
  /// # Params
  /// 
  /// io --- The Stream/Sink to send/receive messages from.  
  /// client --- The [Client] to use to lock/open messages.  
  /// bool --- An indicator of it the Client is the initiating side.  
  #[inline]
  pub(super) fn new(io: Io, client: Box<Client<D, S, A, R, L,>>, local: bool,) -> Self {
    Self { io, client, local, buffer: Vec::new(), }
  }
}

impl<I, D, S, A, R, L,> Framed<I, D, S, A, R, L,>
  where I: Read + Write,
    S: ArrayLength<u8>,
    A: aead::Algorithm,
    L: ArrayLength<u8>,
    Ratchet<D, S, R,>: RngCore + CryptoRng, {
  /// Attempts to send the passed message.
  /// 
  /// # Params
  /// 
  /// message --- The message data to encrypt and send.  
  #[inline]
  pub fn send(&mut self, message: &mut [u8],) -> Result<(), Error> {
    Ok(serde_cbor::ser::to_writer_packed(&mut self.io, &self.client.lock(message,)?,)?)
  }
  /// Attempts to receive the next message.
  /// 
  /// This operation will not block.
  /// 
  /// # Params
  /// 
  /// buffer --- The buffer to append the decrypted message too.  
  pub fn recv<'a,>(&mut self, buffer: &'a mut Vec<u8>,) -> Result<Poll<&'a mut [u8]>, Error> {
    use std::io::ErrorKind;

    //Deserialise a message.
    let message = match serde_cbor::de::from_slice(&self.buffer,) {
      //Consume the used bytes.
      Ok(v) => { self.buffer.clear(); v },
      //Maybe too much data in the buffer, deserialise a subslice.
      Err(e) if e.is_syntax() && e.offset() > 0 => {
        //The range to reattempt on.
        let range = ..(e.offset() as usize - 1);

        match serde_cbor::de::from_slice(&self.buffer[range],) {
          //The subslice was an exact message.
          Ok(v) => { self.buffer.drain(range,); v },
          //Return the original error.
          Err(_) => { return Err(e.into()) },
        }
      },
      //We are waiting on data.
      Err(e) if e.is_eof() => {
        //Remember the current length to 
        let len = self.buffer.len();
        //The buffer to store read data.
        let mut buf = [0; 100];
        while self.buffer.len() <= std::usize::MAX - 100 {
          //Read new data.
          let len = match self.io.read(&mut buf,) {
            Ok(v) => v,
            //If there is no data and we are non blocking stop waiting.
            Err(e) if e.kind() == ErrorKind::WouldBlock => break,
            Err(e) => return Err(e.into()),
          };
          
          //No more data was available.
          if len == 0 { break }
          
          //Add the data to the buffer.
          self.buffer.extend(&buf[..len],);
        }

        //No new data could be read we wont be able to get a new message.
        if len == self.buffer.len() { return Ok(Poll::Pending) }

        //New data was read; recursively receive a message.
        return self.recv(buffer,);
      },
      //Else return the error.
      Err(e) => return Err(e.into()),
    };
    
    Ok(Poll::Ready(self.client.open(message, buffer, self.local,)?))
  }
}

impl<I, D, S, A, R, L,> Drop for Framed<I, D, S, A, R, L,>
  where I: Read + Write,
    S: ArrayLength<u8>,
    A: aead::Algorithm,
    L: ArrayLength<u8>, {
  #[inline]
  fn drop(&mut self,) { ClearOnDrop::new(&mut self.buffer,); }
}

/// An error from a [Framed] instance.
#[derive(Debug,)]
pub enum Error {
  /// There was an error reading/writing to/from the IO.
  Io(io::Error,),
  /// There was an error locking the message.
  Lock(super::Error,),
  /// There was an error opening a received message.
  Open(Message, super::Error,),
  /// There was an error serialising/deserialising a message.
  Serde(serde_cbor::error::Error,),
}

impl From<io::Error> for Error {
  #[inline]
  fn from(from: io::Error,) -> Self { Error::Io(from,) }
}

impl From<io::ErrorKind> for Error {
  #[inline]
  fn from(from: io::ErrorKind,) -> Self { io::Error::from(from,).into() }
}

impl From<super::Error> for Error {
  #[inline]
  fn from(from: super::Error,) -> Self { Error::Lock(from,) }
}

impl From<(Message, super::Error,)> for Error {
  #[inline]
  fn from((message, error,): (Message, super::Error,),) -> Self { Error::Open(message, error,) }
}

impl From<serde_cbor::error::Error> for Error {
  #[inline]
  fn from(from: serde_cbor::error::Error,) -> Self { Error::Serde(from,) }
}

#[cfg(test,)]
mod tests {
  use super::*;
  use crate::{
    typenum::consts,
    client::{LocalClient, RemoteClient, aead::Aes256Gcm,},
  };
  use sha1::Sha1;
  use x25519_dalek::StaticSecret;
  use std::net::{TcpListener, TcpStream,};

  #[test]
  fn test_framed() {
    let addr = "127.0.0.1:4321";
    let listener = TcpListener::bind(addr,)
      .expect("Error binding listener");
    let sock1 = TcpStream::connect(addr,)
      .expect("Error connecting to listener");
    sock1.set_nonblocking(true,)
      .expect("Error setting timeout on sock1");
    let (mut sock2, _,) = listener.accept()
      .expect("Error accepting connection");
    sock2.set_nonblocking(true,)
      .expect("Error setting timeout on sock2");
    let local_sec = StaticSecret::from([1; 32],);
    let remote_sec = StaticSecret::from([2; 32],);
    let local = LocalClient::<Sha1, consts::U64, Aes256Gcm, consts::U1, consts::U10,>::connect(&(&remote_sec).into(), &local_sec,);
    let mut remote = RemoteClient::<Sha1, consts::U64, Aes256Gcm, consts::U1, consts::U10,>::accept(&(&local_sec).into(), &remote_sec,);
    let mut local = local.framed(sock1,);
    
    //First Message.
    let mut msg = [1; 100];
    let other = remote.lock(&mut msg.clone(),).expect("Error locking first message");
    let other = serde_cbor::ser::to_vec_packed(&other,).expect("Error serialising first message");
    sock2.write_all(&other[..50],).expect("Error sending front of first message");
    assert!(local.recv(&mut Vec::new(),).expect("Error receiving partial first message").is_pending(),
      "Received partial first message",
    );
    sock2.write_all(&other[50..],).expect("Error sending back of first message");
    let mut other = Vec::with_capacity(100,);
    assert_eq!(local.recv(&mut other,).expect("Error receiving first message"),
      Poll::Ready(msg.as_mut()),
      "Received first message corrupted",
    );

    //Second and third messages.
    let mut msg2 = [2; 100];
    let mut msg3 = [3; 100];
    let mut remote = remote.framed(sock2,);
    local.send(&mut msg2.clone(),).expect("Error locking second message");
    let mut other2 = Vec::new();
    local.send(&mut msg3.clone(),).expect("Error locking third message");
    let mut other3 = Vec::new();
    assert_eq!(remote.recv(&mut other2,).expect("Error receiving second message"),
      Poll::Ready(msg2.as_mut()),
      "Received second message corrupted",
    );
    assert_eq!(remote.recv(&mut other3,).expect("Error receiving third message"),
      Poll::Ready(msg3.as_mut()),
      "Received third message corrupted",
    );
  }
}
