use self::util::{pad_bytes, unpad_bytes, validate_aes_128_inputs, EncryptionMode};
use crate::basics::xor;
use crate::Result;
use aes::{
  cipher::{generic_array::GenericArray, typenum::U16, BlockDecrypt, BlockEncrypt, KeyInit},
  Aes128,
};
use std::collections::HashSet;

pub mod ecb_bruteforce;
pub mod util;

pub fn decrypt_aes_128_ecb(data: &[u8], key: &[u8]) -> Result<Vec<u8>> {
  validate_aes_128_inputs(key, None, None)?;

  let cipher = Aes128::new(&GenericArray::clone_from_slice(key));
  let mut blocks: Vec<GenericArray<u8, U16>> = util::bytes_to_generic_array_blocks(data, 16);
  cipher.decrypt_blocks(&mut blocks);

  Ok(unpad_bytes(&blocks.concat()).to_vec())
}

pub fn encrypt_aes_128_ecb(data: &[u8], key: &[u8]) -> Result<Vec<u8>> {
  validate_aes_128_inputs(key, None, None)?;

  let cipher = Aes128::new(&GenericArray::clone_from_slice(key));
  let padded: Vec<u8> = pad_bytes(data, 16);
  let mut blocks: Vec<GenericArray<u8, U16>> = util::bytes_to_generic_array_blocks(&padded, 16);
  cipher.encrypt_blocks(&mut blocks);

  Ok(blocks.concat())
}

pub fn encrypt_aes_128_cbc(data: &[u8], key: &[u8], iv: &[u8]) -> Result<Vec<u8>> {
  validate_aes_128_inputs(key, Some(iv), None)?;

  let padded: Vec<u8> = pad_bytes(data, 16);
  let cipher = Aes128::new(&GenericArray::clone_from_slice(key));

  let mut encrypted_chunks: Vec<Vec<u8>> = vec![];
  for chunk in padded.chunks_exact(16) {
    let previous: &[u8] = encrypted_chunks.last().map_or(iv.clone(), |c| c.as_slice());

    let xored_chunk: Vec<u8> = xor::xor(previous, chunk);
    let mut encrypted = GenericArray::clone_from_slice(&xored_chunk);
    cipher.encrypt_block(&mut encrypted);

    encrypted_chunks.push(encrypted.to_vec());
  }

  Ok(encrypted_chunks.concat())
}

pub fn decrypt_aes_128_cbc(data: &[u8], key: &[u8], iv: &[u8]) -> Result<Vec<u8>> {
  validate_aes_128_inputs(key, Some(iv), Some(data))?;

  let cipher = Aes128::new(&GenericArray::clone_from_slice(key));

  let mut decrypted_chunks: Vec<Vec<u8>> = vec![vec![]; data.len() / 16];
  for (i, chunk) in data.chunks_exact(16).enumerate() {
    let previous = if i == 0 {
      iv
    } else {
      &data[(i - 1) * 16..i * 16]
    };

    let mut decrypted = GenericArray::clone_from_slice(chunk);
    cipher.decrypt_block(&mut decrypted);
    let xored_chunk: Vec<u8> = xor::xor(previous, &decrypted);

    decrypted_chunks.push(xored_chunk);
  }

  Ok(unpad_bytes(&decrypted_chunks.concat()).to_vec())
}

pub fn detect_mode(data: &[u8]) -> EncryptionMode {
  let chunks = data.chunks(16);
  let unique_chunks: HashSet<&[u8]> = chunks.clone().collect();
  let identical_chunks_count = chunks.len() - unique_chunks.len();

  if identical_chunks_count > 0 {
    EncryptionMode::Ecb
  } else {
    EncryptionMode::Cbc
  }
}

#[cfg(test)]
mod tests {
  use super::{util::encrypt_random, *};
  use crate::basics::hex;
  use std::fs;

  const SAMPLE_TEXT: &[u8] = b"Lorem ipsum dolor sit amet, consectetur adipiscing elit. Sed euismod, nunc vel tincidunt luctus, nisl nisl aliquam nisl, vel aliquet nisl nisl sit am";
  const SAMPLE_KEY: &[u8] = b"YELLOW SUBMARINE";

  #[test]
  fn decrypts_aes_128_ecb() {
    // Original file from cryptopals is Base64 encoded, but Rust refuses to decode it (some whitespace thingy)
    // Therefore manually converted to hex in aes_128_ecb.txt
    let hex: String = fs::read_to_string("src/block_crypto/aes_128_ecb.txt")
      .expect("Failed to read encrypted file");
    let ciphertext: Vec<u8> = hex::decode(&hex.trim()).expect("Failed to decode hex");

    let plaintext: Vec<u8> =
      decrypt_aes_128_ecb(&ciphertext, SAMPLE_KEY).expect("Failed to decrypt");
    let target_text: &[u8] = b"I'm back and I'm ringin' the bell";
    assert_eq!(&plaintext[0..target_text.len()], target_text);
  }

  #[test]
  fn encrypts_aes_128_ecb() {
    let encrypted: Vec<u8> =
      encrypt_aes_128_ecb(SAMPLE_TEXT, SAMPLE_KEY).expect("Failed to encrypt");
    let decrypted: Vec<u8> =
      decrypt_aes_128_ecb(&encrypted, SAMPLE_KEY).expect("Failed to decrypt");

    assert_eq!(decrypted, SAMPLE_TEXT);
  }

  #[test]
  fn encrypts_aes_128_cbc() {
    let iv: &[u8] = &[b'a'; 16];

    let encrypted: Vec<u8> =
      encrypt_aes_128_cbc(SAMPLE_TEXT, SAMPLE_KEY, iv).expect("Failed to encrypt");
    let decrypted: Vec<u8> =
      decrypt_aes_128_cbc(&encrypted, SAMPLE_KEY, iv).expect("Failed to decrypt");

    assert_eq!(decrypted, SAMPLE_TEXT);
  }

  #[test]
  fn decrypts_aes_128_cbc() {
    // Original file from cryptopals is Base64 encoded, but Rust refuses to decode it (some whitespace thingy)
    // Therefore manually converted to hex in cbc.txt
    let hex: String = fs::read_to_string("src/block_crypto/aes_128_cbc.txt")
      .expect("Failed to read encrypted file");
    let ciphertext: Vec<u8> = hex::decode(&hex.trim()).expect("Failed to decode hex");

    let plaintext: Vec<u8> =
      decrypt_aes_128_cbc(&ciphertext, "YELLOW SUBMARINE".as_bytes(), &[0; 16])
        .expect("Failed to decrypt");

    let target_text: &[u8] =
      b"I'm back and I'm ringin' the bell \nA rockin' on the mike while the fly girls yell";
    assert_eq!(&plaintext[0..target_text.len()], target_text);
  }

  #[test]
  fn detects_ecb_cbc() {
    let data = "z".repeat(64);
    let random_encryption: (Vec<u8>, EncryptionMode) =
      encrypt_random(data.as_bytes()).expect("Failed to encrypt");
    let guessed_mode: EncryptionMode = detect_mode(&random_encryption.0);
    assert_eq!(random_encryption.1, guessed_mode,);
  }
}
