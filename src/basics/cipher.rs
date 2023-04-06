use std::collections::HashSet;

fn relative_unique_chunks(bytes: &[u8]) -> f32 {
  let chunks = bytes.chunks(16);
  let unique_chunks: HashSet<&[u8]> = chunks.clone().collect();
  unique_chunks.len() as f32 / chunks.len() as f32
}

pub fn detect_aes_ecb(ciphertexts: Vec<Vec<u8>>) -> Option<Vec<u8>> {
  let mut least_unique_relative_chunks: f32 = f32::MAX;
  let mut least_unique_chunk: Option<Vec<u8>> = None;

  for ciphertext in ciphertexts {
    let relative_unique_chunks = relative_unique_chunks(ciphertext.as_slice());
    if relative_unique_chunks < least_unique_relative_chunks {
      least_unique_relative_chunks = relative_unique_chunks;
      least_unique_chunk = Some(ciphertext);
    }
  }

  least_unique_chunk
}

#[cfg(test)]
mod tests {
  use super::*;
  use crate::basics::hex;
  use std::{
    fs::File,
    io::{BufRead, BufReader},
  };

  #[test]
  fn detects_aes_ecb() {
    let file: File = File::open("src/basics/detect_aes_ecb.txt").expect("Failed to open file");
    let hex_strings: Vec<String> = BufReader::new(file)
      .lines()
      .map(|l| l.expect("Failed to read line"))
      .collect();

    let ciphertexts: Vec<Vec<u8>> = hex_strings
      .iter()
      .map(|hex| hex::decode(&hex).expect("Failed to decode hex"))
      .collect();

    detect_aes_ecb(ciphertexts).expect("Failed to detect AES ECB");
  }
}
