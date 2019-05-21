//! Defines the `Framed` interface.
//! 
//! Author -- daniel.bechaz@gmail.com  
//! Last Moddified --- 2019-05-21

use crate::{message::Message, client::{self, Client,},};
use clear_on_drop::ClearOnDrop;
use std::{io::{self, Read, Write,}, task::Poll,};

/// Removes `len` bytes from the front of buffer clearing the unused tail bytes.
fn consume_from_front(buffer: &mut Vec<u8>, len: usize,) {
  let tail = buffer.len().saturating_sub(len,);
  let range = 0..tail;

  for (a, b,) in range.zip(len..buffer.len(),) {
    buffer[a] = buffer[b];
  }

  ClearOnDrop::new(&mut buffer[tail..],);

  buffer.truncate(tail,);
}

/// Receives a single message from the start of an input buffer which contains one or
/// more encoded messages.
/// 
/// If a message is received the data encoding the message is removed from the input
/// buffer and the decrypted message data is appended to `buffer`.
/// 
/// # Params
/// 
/// client --- The `Client` to open the message with.  
/// input --- The input buffer to receive a message from.  
/// buffer --- The output buffer to write the received message data out too.  
pub fn receive_one<'a,>(mut client: impl Client, input: &mut Vec<u8>, buffer: &'a mut Vec<u8>,) -> Result<&'a mut [u8], Error> {
  use serde_cbor::de;

  //Deserialise a message.
  let message = match de::from_slice(input,) {
    //Consume the used bytes.
    Ok(v) => {
      ClearOnDrop::new(input.as_mut_slice(),);
      input.clear();
      
      v
    },
    //Maybe too much data in the buffer, deserialise a subslice.
    Err(e) if e.is_syntax() && e.offset() > 0 => {
      //The range to reattempt on.
      let range = ..(e.offset() as usize - 1);

      match de::from_slice(&input[range],) {
        //The subslice was an exact message.
        Ok(v) => { consume_from_front(input, range.end,); v },
        //Return the original error.
        Err(_) => { return Err(Error::Deserialise(e,)) },
      }
    },
    //Else return the error.
    Err(e) => return Err(Error::Deserialise(e,)),
  };
  
  Ok(client.open(message, buffer,)?)
}

/// Wraps a `Client` and a Stream/Sink to parse messages to/from.
/// 
/// It implements `Read`/`Write` by forwarding too the internal `IO` instance however
/// `read` will read out of the internal buffer first.
pub struct Framed<Io, Client,> {
  io: Io,
  client: Client,
  /// The internal buffer of unparsed data.
  buffer: Vec<u8>,
}

impl<Io, Client,> Framed<Io, Client,> {
  /// Construct a new `Framed` from parts.
  /// 
  /// # Params
  /// 
  /// io --- The Stream/Sink to send/receive messages from.  
  /// client --- The [Client] to use to lock/open messages.  
  /// bool --- An indicator of it the Client is the initiating side.  
  #[inline]
  pub(super) const fn new(io: Io, client: Client,) -> Self {
    Self { io, client, buffer: Vec::new(), }
  }
}

impl<I, C,> Framed<I, C,>
  where I: Write,
    C: Client, {
  /// Attempts to send the passed message.
  /// 
  /// # Params
  /// 
  /// message --- The message data to encrypt and send.  
  pub fn send(&mut self, message: &mut [u8],) -> Result<(), Error> {
    use serde_cbor::ser;
    let message = self.client.lock(message,)?;
    
    ser::to_writer_packed(&mut self.io, &message,)
    .map_err(move |e,| Error::Send(message, e,),)
  }
}

impl<I, C,> Framed<I, C,>
  where I: Read, {
  /// Reads as much data as possible into the buffer.
  /// 
  /// Will return on `EOF` or `WouldBlock`.
  /// 
  /// A value of `Ok(true)` indicates `EOF` was reached.
  fn fill_buf(&mut self,) -> io::Result<bool> {
    use std::io::ErrorKind;

    //The buffer to store read data.
    let mut buf = [0; 100];
    let mut buf = ClearOnDrop::new(buf.as_mut(),);

    //Read in data.
    while self.buffer.len() <= std::usize::MAX - 100 {
      //Read new data.
      let len = match self.io.read(buf.as_mut(),) {
        //Reached EOF.
        Ok(0) => return Ok(true),
        Ok(v) => v,
        //If there is no data and we are non blocking stop waiting.
        Err(e) if e.kind() == ErrorKind::WouldBlock => break,
        Err(e) => return Err(e),
      };

      //Add the data to the buffer.
      self.buffer.extend(&buf[..len],);
    }

    Ok(false)
  }
}

impl<I, C,> Framed<I, C,>
  where I: Read,
    C: Client, {
  /// Attempts to receive the next message.
  /// 
  /// If the inner IO object is non blocking this function will not block.
  /// 
  /// `Ready(None)` means EOF was encountered.
  /// 
  /// # Params
  /// 
  /// buffer --- The buffer to append the decrypted message too.  
  pub fn recv<'a,>(&mut self, buffer: &'a mut Vec<u8>,) -> Result<Poll<Option<&'a mut [u8]>>, Error> {
    use std::io::ErrorKind;

    //Deserialise a message.
    match receive_one(&mut self.client, &mut self.buffer, unsafe { &mut *(buffer as *mut _) },) {
      //Consume the used bytes.
      Ok(v) => Ok(Poll::Ready(Some(v))),
      //We are waiting on data.
      Err(Error::Deserialise(e,)) if e.is_eof() => {
        //Remember the current length to 
        let len = self.buffer.len();
        //Read new data.
        let eof = self.fill_buf().map_err(|e,| Error::Recv(e,),)?;

        //No new data could be read we wont be able to get a new message.
        if len == self.buffer.len() {
          return if eof {
              //If we are at EOF return done.
              if self.buffer.is_empty() { Ok(Poll::Ready(None)) }
              //If we are at EOF with unused data return error.
              else { Err(Error::Recv(ErrorKind::UnexpectedEof.into(),)) }
            //If no data was read because we are not blocking return pending.
            } else { Ok(Poll::Pending) }
        }

        //New data was read; recursively receive a message.
        return self.recv(buffer,);
      },
      //Else return the error.
      Err(e) => Err(e),
    }
  }
}

impl<I, C,> Framed<I, C,>
  where I: Read + Write,
    C: Client, {
  /// Run a function on every message received from the `Framed` and optionally send a response.
  /// 
  /// If any error is encounterd it is returned.
  /// 
  /// # Params
  /// 
  /// process --- The function to run on every message received. If a response is
  /// returned it is sent back through the `Framed`.  
  pub fn loop_back(&mut self, mut process: impl FnMut(&mut [u8],) -> Option<&mut [u8]>,) -> Result<(), Error> {
    let mut buffer = Vec::new();
    
    loop {
      //Loop recv until a message is received.
      let msg = loop {
        if let Poll::Ready(v) = self.recv(&mut buffer,)? { break v }
      };

      match msg {
        //If we received a message respond.
        Some(msg) => {
          //If a response is produced send the response.
          if let Some(msg) = process(msg,) { self.send(msg,)?; }

          //Clear the buffer for the next message.
          ClearOnDrop::new(buffer.as_mut_slice(),);
          buffer.clear();
        },
        //If there are no more messages exit.
        None => return Ok(()),
      }
    }
  }
}

impl<I, C,> Write for Framed<I, C,>
  where I: Write, {
  #[inline]
  fn write(&mut self, bytes: &[u8],) -> io::Result<usize> { self.io.write(bytes,) }
  #[inline]
  fn flush(&mut self,) -> io::Result<()> { self.io.flush() }
}

impl<I, C,> Read for Framed<I, C,>
  where I: Read, {
  fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
    let len = usize::min(self.buffer.len(), bytes.len(),);

    //Move bytes out of the internal buffer first.
    for (a, b,) in bytes.iter_mut().zip(self.buffer[..len].iter().copied(),) {
      *a = b;
    }

    //Clear the used bytes.
    consume_from_front(&mut self.buffer, len,);

    //Read any remaining bytes.
    self.io.read(&mut bytes[len..],).map(|read,| read + len,)
  }
}

impl<I, C,> Drop for Framed<I, C,> {
  #[inline]
  fn drop(&mut self,) { ClearOnDrop::new(&mut self.buffer,); }
}

/// An error from a [Framed] instance.
#[derive(Debug,)]
pub enum Error {
  /// There was an error writing a message to the IO.
  Send(Message, serde_cbor::error::Error,),
  /// There was an error reading data from the IO.
  Recv(io::Error,),
  /// There was an error locking the message.
  Lock(client::Error,),
  /// There was an error opening a received message.
  Open(Message, crate::client::Error,),
  /// There was an error deserialising a message.
  Deserialise(serde_cbor::error::Error,),
}

impl From<crate::client::Error> for Error {
  #[inline]
  fn from(from: crate::client::Error,) -> Self { Error::Lock(from,) }
}

impl From<(Message, crate::client::Error,)> for Error {
  #[inline]
  fn from((message, error,): (Message, crate::client::Error,),) -> Self { Error::Open(message, error,) }
}

#[cfg(test,)]
mod tests {
  use super::*;
  use crate::{
    typenum::consts,
    client::{Client, LocalClient, RemoteClient, aead::Aes256Gcm,},
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
      Poll::Ready(Some(msg.as_mut())),
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
      Poll::Ready(Some(msg2.as_mut())),
      "Received second message corrupted",
    );
    assert_eq!(remote.recv(&mut other3,).expect("Error receiving third message"),
      Poll::Ready(Some(msg3.as_mut())),
      "Received third message corrupted",
    );

    //Dropping remote closing the socket.
    std::mem::drop(remote,);
    assert_eq!(local.recv(&mut Vec::new(),).expect("Error on EOF"),
      Poll::Ready(None),
      "Received a message when partner is EOF"
    );
  }
}
