use crate::Result;
use base64::{engine::general_purpose as b64_engine, Engine as _};
use std::num::ParseIntError;

pub fn decode(hex: &str) -> std::result::Result<Vec<u8>, ParseIntError> {
  (0..hex.len())
    .step_by(2)
    .map(|i| u8::from_str_radix(&hex[i..i + 2], 16))
    .collect()
}

pub fn encode(bytes: &[u8]) -> String {
  bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

pub fn to_base64(hex: &str) -> Result<String> {
  let bytes = decode(hex)?;
  Ok(b64_engine::STANDARD.encode(bytes))
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn hex_to_base64_correct() {
    let result = to_base64("49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d").unwrap();
    assert_eq!(
      result,
      "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"
    );
  }
}
