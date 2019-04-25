//! Defines the double ratchet [Client].
//! 
//! Author -- daniel.bechaz@gmail.com  
//! Last Moddified --- 2019-04-25

use generic_array::{ArrayLength, typenum::consts,};

pub mod aead;
mod send;
mod receive;

use self::{send::*, receive::*,};

/// The combined sending and receiving `Client` halves.
pub struct Client<Algorithm, Digest, Rounds = consts::U1, AadLength = consts::U0,>
  where Algorithm: aead::Algorithm,
    AadLength: ArrayLength<u8>, {
  /// The sending half of the `Client`.
  sending: SendClient<Algorithm, Digest, Rounds, AadLength,>,
  /// The receiving half of the `Client`.
  receiving: ReceiveClient<Algorithm, Digest, Rounds, AadLength,>,
}

#[cfg(test,)]
mod tests {
  

  #[test]
  fn test_client() {
    unimplemented!()
  }
}
