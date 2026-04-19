/// Calculate Shannon entropy of a byte slice.
/// Returns a value between 0.0 (all bytes identical) and 8.0 (uniform distribution).
pub fn shannon_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut freq = [0u32; 256];
    for &b in data {
        freq[b as usize] += 1;
    }
    let len = data.len() as f64;
    freq.iter()
        .filter(|&&c| c > 0)
        .fold(0.0f64, |acc, &c| {
            let p = c as f64 / len;
            acc - p * p.log2()
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zero_entropy_uniform_bytes() {
        let data = vec![0xAAu8; 1000];
        assert!(shannon_entropy(&data) < 0.001);
    }

    #[test]
    fn max_entropy_random_like() {
        // All 256 byte values present once → high entropy
        let data: Vec<u8> = (0u8..=255).collect();
        let e = shannon_entropy(&data);
        assert!(e > 7.9, "Expected entropy ~8.0, got {}", e);
    }

    #[test]
    fn empty_slice() {
        assert_eq!(shannon_entropy(&[]), 0.0);
    }
}
