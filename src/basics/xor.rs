use super::{average_edit_distance, hex, transpose_chunks};
use crate::{basics::linguistics::LanguageAnalyzer, Result};
use std::ops::Range;

/// (score, key, deciphered text)
#[derive(Debug, Clone)]
pub struct XorGuess(pub f32, pub u8, pub String);

pub fn xor(a: &[u8], b: &[u8]) -> Vec<u8> {
  a.iter().zip(b).map(|(a, b)| a ^ b).collect()
}

pub fn hex_xor(hex_a: &str, hex_b: &str) -> Result<String> {
  let bytes_a = hex::decode(hex_a)?;
  let bytes_b = hex::decode(hex_b)?;
  Ok(hex::encode(xor(&bytes_a, &bytes_b).as_slice()))
}

pub fn guess_xor(bytes: &[u8], analyzer: &LanguageAnalyzer) -> XorGuess {
  // (score, key, deciphered text)
  let mut best: XorGuess = XorGuess(0.0, 0, String::new());

  for key in 0..=127 {
    let key_bytes: Vec<u8> = vec![key; bytes.len()];
    let result = xor(bytes, key_bytes.as_slice());
    let text = String::from_utf8_lossy(&result);
    let score = analyzer.eval_text(&text);
    if score > best.0 {
      best.0 = score;
      best.1 = key;
      best.2 = text.to_string();
    }
  }

  XorGuess(best.0, best.1, best.2)
}

pub fn guess_xor_multiple(strings: Vec<String>) -> (String, XorGuess) {
  let analyzer = LanguageAnalyzer::from_sample_file().unwrap();
  let mut results: Vec<(String, XorGuess)> = strings
    .iter()
    .map(|s| {
      (
        s.clone(),
        guess_xor(hex::decode(s).unwrap().as_slice(), &analyzer),
      )
    })
    .collect();
  results.sort_by(|a, b| b.1 .0.partial_cmp(&a.1 .0).unwrap());
  results[0].clone()
}

pub fn xor_with_repeating_key(bytes: &[u8], key: &[u8]) -> Vec<u8> {
  let key_repeating: Vec<u8> = key.iter().cycle().take(bytes.len()).copied().collect();
  xor(bytes, key_repeating.as_slice())
}

fn guess_repeating_key_size(bytes: &[u8], range: Range<usize>) -> usize {
  let mut best_key_size: usize = range.start;
  let mut best_distance: f32 = f32::MAX;

  for key_size in range {
    let chunks: Vec<&[u8]> = bytes.chunks(key_size).collect();
    let normalized = average_edit_distance(chunks) / key_size as f32;

    if normalized < best_distance {
      best_distance = normalized;
      best_key_size = key_size;
    }
  }

  best_key_size
}

pub fn guess_repeating_key(bytes: &[u8], key_size_range: Range<usize>) -> Vec<u8> {
  let key_size = guess_repeating_key_size(bytes, key_size_range);
  let key_size_chunks: Vec<&[u8]> = bytes.chunks(key_size).collect();
  let transposed: Vec<Vec<u8>> = transpose_chunks(key_size_chunks);

  let analyzer = LanguageAnalyzer::from_sample_file().unwrap();
  transposed
    .iter()
    .map(|chunk| guess_xor(chunk.as_slice(), &analyzer).1)
    .collect()
}

#[cfg(test)]
mod tests {
  use super::*;
  use crate::basics::{hex, linguistics};
  use std::{
    fs::{self, File},
    io::{BufRead, BufReader},
  };

  #[test]
  fn hex_xor_correct() {
    let result = hex_xor(
      "1c0111001f010100061a024b53535009181c",
      "686974207468652062756c6c277320657965",
    )
    .unwrap();
    assert_eq!(result, "746865206b696420646f6e277420706c6179");
  }

  #[test]
  fn guesses_xor() {
    let analyzer = linguistics::LanguageAnalyzer::from_sample_file().unwrap();
    let result = guess_xor(
      &hex::decode("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736").unwrap(),
      &analyzer,
    );
    assert_eq!(result.2, "Cooking MC's like a pound of bacon");
  }

  #[test]
  fn guesses_multiple_xor() {
    let file: File = File::open("src/basics/xor_guesses.txt").unwrap();
    let strings: Vec<String> = BufReader::new(file).lines().map(|l| l.unwrap()).collect();
    let (input, guess) = guess_xor_multiple(strings);
    println!("{}: {} {} {}", input, guess.0, guess.1, guess.2);
    assert_eq!(
      input,
      "7b5a4215415d544115415d5015455447414c155c46155f4058455c5b523f"
    );
    assert_eq!(guess.2, "Now that the party is jumping\n");
  }

  #[test]
  fn encrypts_using_repeating_key() {
    let result = xor_with_repeating_key(
      "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal".as_bytes(),
      "ICE".as_bytes(),
    );
    assert_eq!(hex::encode(&result), "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f");
  }

  #[test]
  fn guesses_repeating_key() {
    // Original file from cryptopals is Base64 encoded, but Rust refuses to decode it (some whitespace thingy)
    // Therefore manually converted to hex in repeating_xor.txt
    let hex = fs::read_to_string("src/basics/repeating_xor.txt").unwrap();
    let bytes = hex::decode(&hex.trim()).unwrap();
    let key = guess_repeating_key(&bytes, 2..40);
    assert_eq!(key, b"Terminator X: Bring the noise")
  }
}
