use super::{encrypt_aes_128_cbc, encrypt_aes_128_ecb};
use crate::{basics::gen_rand_bytes, Result};
use aes::cipher::{generic_array::GenericArray, ArrayLength};
use rand::Rng;

#[derive(Debug, PartialEq)]
pub enum EncryptionMode {
  Ecb,
  Cbc,
}

pub fn pad_bytes(bytes: &[u8], target_size: usize) -> Vec<u8> {
  let pad_len = target_size - bytes.len() % target_size;
  let padding: Vec<u8> = vec![pad_len as u8; pad_len];

  let mut padded = bytes.to_vec();
  padded.extend(padding);
  padded
}

pub fn unpad_bytes(bytes: &[u8]) -> &[u8] {
  let pad_len = bytes[bytes.len() - 1];
  &bytes[..bytes.len() - pad_len as usize]
}

pub fn validate_aes_128_inputs(
  key: &[u8],
  iv: Option<&[u8]>,
  encrypted_bytes: Option<&[u8]>,
) -> Result<()> {
  if key.len() != 16 {
    return Err("Key must be 16 bytes long".into());
  }

  if let Some(iv) = iv {
    if iv.len() != 16 {
      return Err("IV must be 16 bytes long".into());
    }
  }

  if let Some(encrypted_bytes) = encrypted_bytes {
    if encrypted_bytes.len() % 16 != 0 {
      return Err("Encrypted data must be a multiple of 16 bytes long".into());
    }
  }

  Ok(())
}

pub fn bytes_to_generic_array_blocks<U: ArrayLength<u8>>(
  bytes: &[u8],
  block_size: usize,
) -> Vec<GenericArray<u8, U>> {
  bytes
    .chunks(block_size)
    .map(|b| GenericArray::clone_from_slice(b))
    .collect()
}

pub fn encrypt_random(data: &[u8]) -> Result<(Vec<u8>, EncryptionMode)> {
  let use_ecb: bool = rand::random();
  let key = gen_rand_bytes(16);
  let iv = gen_rand_bytes(16);

  let mut rng = rand::thread_rng();
  let prefix_len = rng.gen_range(5..11);
  let prefix = gen_rand_bytes(prefix_len);
  let suffix_len = rng.gen_range(5..11);
  let suffix = gen_rand_bytes(suffix_len);

  let mut bytes = prefix;
  bytes.extend(data);
  bytes.extend(suffix);

  let mode = match use_ecb {
    true => EncryptionMode::Ecb,
    false => EncryptionMode::Cbc,
  };

  let encrypted = match mode {
    EncryptionMode::Ecb => encrypt_aes_128_ecb(&bytes, &key),
    EncryptionMode::Cbc => encrypt_aes_128_cbc(&bytes, &key, &iv),
  }?;

  Ok((encrypted, mode))
}

#[cfg(test)]
mod tests {
  #[test]
  fn pads_block() {
    let padded: Vec<u8> = super::pad_bytes(&vec![1, 2], 4);
    assert_eq!(padded, vec![1, 2, 2, 2]);
  }
}
