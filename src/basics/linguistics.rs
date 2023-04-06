use crate::Result;
use core::fmt;
use std::{collections::HashMap, fs, path::PathBuf};

pub struct LanguageAnalyzer {
  character_frequencies: HashMap<char, f32>,
}

impl LanguageAnalyzer {
  pub fn into_character_map(text: &str) -> HashMap<char, u32> {
    let mut char_map: HashMap<char, u32> = HashMap::new();
    for c in text.chars() {
      let count: &mut u32 = char_map.entry(c).or_insert(0);
      *count += 1;
    }
    char_map
  }

  pub fn from_text(text: &str) -> LanguageAnalyzer {
    let char_map: HashMap<char, u32> = Self::into_character_map(text);
    let char_total: u32 = char_map.values().sum();

    let char_frequencies: HashMap<char, f32> = char_map
      .iter()
      .map(|(char, count)| (*char, *count as f32 / char_total as f32))
      .collect();

    LanguageAnalyzer {
      character_frequencies: char_frequencies,
    }
  }

  pub fn from_file(path: PathBuf) -> Result<LanguageAnalyzer> {
    let text = fs::read_to_string(path)?;
    Ok(Self::from_text(&text))
  }

  pub fn from_sample_file() -> Result<LanguageAnalyzer> {
    Self::from_file(PathBuf::from("sample_text.txt"))
  }

  pub fn eval_text(&self, text: &str) -> f32 {
    let char_map: HashMap<char, u32> = Self::into_character_map(text);
    let char_total: u32 = char_map.values().sum();

    // Bhattacharyya coefficient
    char_map
      .iter()
      .map(|(char, count)| {
        let freq: &f32 = self.character_frequencies.get(char).unwrap_or(&0.0);
        (freq * *count as f32 / char_total as f32).sqrt()
      })
      .sum()
  }
}

impl fmt::Display for LanguageAnalyzer {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    let mut chars: Vec<char> = self.character_frequencies.keys().cloned().collect();
    chars.sort();
    for char in chars {
      writeln!(
        f,
        "{}: {}%",
        char,
        self.character_frequencies.get(&char).unwrap() * 100.0
      )?;
    }
    Ok(())
  }
}
