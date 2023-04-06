pub mod cipher;
pub mod hex;
pub mod linguistics;
pub mod xor;

pub fn edit_distance(a: &[u8], b: &[u8]) -> u32 {
  a.iter().zip(b).map(|(a, b)| (a ^ b).count_ones()).sum()
}

pub fn average_edit_distance(chunks: Vec<&[u8]>) -> f32 {
  let mut distances: Vec<u32> = vec![];
  let mut i = 0;
  while i + 1 < chunks.len() {
    distances.push(edit_distance(chunks[i], chunks[i + 1]));
    i += 2;
  }

  distances.iter().sum::<u32>() as f32 / distances.len() as f32
}

pub fn transpose_chunks(chunks: Vec<&[u8]>) -> Vec<Vec<u8>> {
  let mut transposed: Vec<Vec<u8>> = vec![vec![]; chunks[0].len()];
  for chunk in chunks {
    for (i, byte) in chunk.iter().enumerate() {
      transposed[i].push(*byte);
    }
  }

  transposed
}

pub fn gen_rand_bytes(count: usize) -> Vec<u8> {
  (0..count).map(|_| rand::random::<u8>()).collect()
}

#[cfg(test)]
mod tests {
  const SAMPLE_BYTES: [u8; 10] = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10];
  const SAMPLE_CHUNK_SIZE: usize = 3;

  #[test]
  fn calculates_edit_distance() {
    let distance = super::edit_distance("this is a test".as_bytes(), "wokka wokka!!!".as_bytes());
    assert_eq!(distance, 37);
  }

  #[test]
  fn transposes_chunks() {
    let chunks: Vec<&[u8]> = SAMPLE_BYTES.chunks(SAMPLE_CHUNK_SIZE).collect();
    let transposed = super::transpose_chunks(chunks);
    assert_eq!(transposed.len(), 3);
    assert_eq!(transposed[0], vec![1, 4, 7, 10]);
    assert_eq!(transposed[2], vec![3, 6, 9]);
  }
}
