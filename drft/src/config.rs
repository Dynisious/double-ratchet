//! Defines the config structs.
//! 
//! Author --- daniel.bechaz@gmail.com  
//! Last Moddified --- 2019-05-21

use std::path::Path;

/// Configuration to file locking operations.
pub struct FileConfig<'config,> {
  /// The path too the output file to create.
  pub out_file: &'config Path,
  /// Whether the output file should be overwritten if it already exists.
  pub overwrite_existing: bool,
  /// Whether the input file should be deleted after encryption.
  pub delete_input: bool,
}
