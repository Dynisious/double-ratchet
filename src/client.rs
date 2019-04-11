//! Defines the double ratchet [Client].
//! 
//! Author -- daniel.bechaz@gmail.com  
//! Last Moddified --- 2019-04-11

use generic_array::{ArrayLength, typenum::consts,};

mod send;
mod receive;

pub use self::{send::*, receive::*,};

/// The combined sending and receiving `Client` halves.
pub struct Client<D, Rounds = consts::U1, AadLength = consts::U0,>
  where AadLength: ArrayLength<u8>, {
  /// The sending half of the `Client`.
  pub sending: SendClient<D, Rounds, AadLength,>,
  /// The receiving half of the `Client`.
  pub receiving: ReceiveClient<D, Rounds, AadLength,>,
}

#[cfg(test,)]
mod tests {
  use super::*;

  #[test]
  fn test_client() {
    unimplemented!()
  }
  #[test]
  fn test_client_serde() {
    unimplemented!()
  }
}
