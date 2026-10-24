//! Base45 per draft-faltstrom-base45.
//!
//! Space is a member of the alphabet, so an HC1 payload must never be
//! trimmed -- the Python original documents this trap in its README and
//! `sanitize_base45` preserves spaces deliberately.

use crate::Error;

const ALPHABET: &[u8; 45] = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ $%*+-./:";

/// Reverse lookup: byte -> alphabet index, 0xFF for "not in alphabet".
fn decode_table() -> [u8; 256] {
    let mut t = [0xFFu8; 256];
    for (i, c) in ALPHABET.iter().enumerate() {
        t[*c as usize] = i as u8;
    }
    t
}

pub fn encode(input: &[u8]) -> String {
    let mut out = String::with_capacity(input.len() * 2);
    for chunk in input.chunks(2) {
        if chunk.len() == 2 {
            let v = u16::from_be_bytes([chunk[0], chunk[1]]) as u32;
            out.push(ALPHABET[(v % 45) as usize] as char);
            out.push(ALPHABET[((v / 45) % 45) as usize] as char);
            out.push(ALPHABET[(v / 2025) as usize] as char);
        } else {
            let v = chunk[0] as u32;
            out.push(ALPHABET[(v % 45) as usize] as char);
            out.push(ALPHABET[(v / 45) as usize] as char);
        }
    }
    out
}

pub fn decode(input: &str) -> Result<Vec<u8>, Error> {
    let table = decode_table();
    let bytes = input.as_bytes();

    // Translate first so an invalid character is reported before length,
    // which gives a more useful message on a mangled QR scan.
    let mut vals = Vec::with_capacity(bytes.len());
    for (i, b) in bytes.iter().enumerate() {
        let v = table[*b as usize];
        if v == 0xFF {
            return Err(Error::Base45(format!(
                "invalid character {:?} at offset {}",
                *b as char, i
            )));
        }
        vals.push(v as u32);
    }

    match vals.len() % 3 {
        0 | 2 => {}
        _ => {
            return Err(Error::Base45(format!(
                "invalid length {}: must be a multiple of 3, optionally plus 2",
                vals.len()
            )))
        }
    }

    let mut out = Vec::with_capacity(vals.len() / 3 * 2 + 1);
    for chunk in vals.chunks(3) {
        if chunk.len() == 3 {
            let v = chunk[0] + chunk[1] * 45 + chunk[2] * 2025;
            let v = u16::try_from(v)
                .map_err(|_| Error::Base45(format!("triplet overflows 16 bits: {v}")))?;
            out.extend_from_slice(&v.to_be_bytes());
        } else {
            let v = chunk[0] + chunk[1] * 45;
            let v = u8::try_from(v)
                .map_err(|_| Error::Base45(format!("pair overflows 8 bits: {v}")))?;
            out.push(v);
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Vectors published in draft-faltstrom-base45. Authoritative, and they
    /// need no reference implementation to verify against.
    const VECTORS: &[(&str, &str)] = &[
        ("AB", "BB8"),
        ("Hello!!", "%69 VD92EX0"),
        ("base-45", "UJCLQE7W581"),
        ("ietf!", "QED8WEX0"),
    ];

    #[test]
    fn spec_vectors_encode() {
        for (plain, encoded) in VECTORS {
            assert_eq!(&encode(plain.as_bytes()), encoded, "encoding {plain:?}");
        }
    }

    #[test]
    fn spec_vectors_decode() {
        for (plain, encoded) in VECTORS {
            let got = decode(encoded).expect("decode");
            assert_eq!(got, plain.as_bytes(), "decoding {encoded:?}");
        }
    }

    #[test]
    fn round_trip_all_byte_lengths() {
        for len in 0usize..=64 {
            let data: Vec<u8> = (0..len).map(|i| (i * 7 % 256) as u8).collect();
            assert_eq!(decode(&encode(&data)).unwrap(), data, "len {len}");
        }
    }

    /// The space-preservation trap: a space is data, not padding.
    #[test]
    fn space_is_part_of_the_alphabet() {
        let decoded = decode("%69 VD92EX0").expect("space must decode");
        assert_eq!(decoded, b"Hello!!");
        assert!(decode("%69VD92EX0").is_err(), "trimming the space must not silently succeed");
    }

    #[test]
    fn rejects_invalid_character() {
        let err = decode("QED8WEX!").unwrap_err().to_string();
        assert!(err.contains("invalid character"), "got: {err}");
    }

    #[test]
    fn rejects_bad_length() {
        // length % 3 == 1 is never valid
        let err = decode("QED8").unwrap_err().to_string();
        assert!(err.contains("invalid length"), "got: {err}");
    }

    #[test]
    fn rejects_overflowing_triplet() {
        // 'G','G','G' = 16 + 16*45 + 16*2025 = 33136 -- fits; use max chars instead
        let err = decode(":::").unwrap_err().to_string();
        assert!(err.contains("overflows 16 bits"), "got: {err}");
    }
}
