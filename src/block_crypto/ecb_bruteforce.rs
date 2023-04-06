use super::encrypt_aes_128_ecb;
use crate::Result;
use base64::{engine::general_purpose as base64_engine, Engine as _};

const UNKNOWN_KEY: &str = "YELLOW SUBMARINE";
const APPEND: &str = "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK";

fn oracle_encrypt(data: &[u8]) -> Result<Vec<u8>> {
  let cipherbytes: Vec<u8> = base64_engine::STANDARD.decode(APPEND)?;

  let mut bytes: Vec<u8> = data.to_vec();
  bytes.extend(cipherbytes);

  encrypt_aes_128_ecb(&bytes, UNKNOWN_KEY.as_bytes())
}

fn find_block_size() -> Result<usize> {
  let mut input: Vec<u8> = b"A".to_vec();
  let mut encrypted: Vec<u8> = oracle_encrypt(&input)?;
  let mut prev_len = encrypted.len();

  loop {
    input.push(b'A');
    println!("input: {:?}", input);
    encrypted = oracle_encrypt(&input)?;

    let len = encrypted.len();
    if len != prev_len {
      return Ok(len - prev_len);
    }

    prev_len = len;
  }
}

#[cfg(test)]
mod tests {
  use crate::block_crypto::{detect_mode, util::EncryptionMode};

  use super::*;

  #[test]
  fn finds_block_size() {
    assert_eq!(find_block_size().unwrap(), 16);
  }

  #[test]
  fn detects_ecb() {
    let encrypted: Vec<u8> = oracle_encrypt(&[b'A'; 64]).expect("Failed to encrypt data");
    let mode: EncryptionMode = detect_mode(&encrypted);
    assert_eq!(mode, EncryptionMode::Ecb);
  }
}
