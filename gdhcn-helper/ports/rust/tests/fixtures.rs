//! Cross-implementation checks against golden fixtures captured from the
//! reference Python service (plan step 0).
//!
//! The fixtures live outside this crate because both ports consume them:
//! `gdhcn-helper/fixtures/`. Point `GDHCN_FIXTURES` at that directory, or rely
//! on the default relative path when running from the crate root.

use std::path::PathBuf;

use gdhcn_helper::base45;

fn fixtures_dir() -> PathBuf {
    match std::env::var_os("GDHCN_FIXTURES") {
        Some(p) => PathBuf::from(p),
        None => PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../fixtures"),
    }
}

/// Reference `base45_decoded_len` for each HC1, straight from the Python
/// service's own `diagnostics`. Extracted without a JSON dependency: the
/// field is a plain integer and this keeps the dev-dependency set empty.
fn reference_decoded_len(json: &str) -> usize {
    let key = "\"base45_decoded_len\":";
    let at = json.find(key).expect("fixture has no base45_decoded_len");
    json[at + key.len()..]
        .trim_start()
        .split(|c: char| !c.is_ascii_digit())
        .find(|s| !s.is_empty())
        .expect("no digits after base45_decoded_len")
        .parse()
        .expect("base45_decoded_len not a number")
}

#[test]
fn base45_matches_reference_on_real_qr_payloads() {
    let dir = fixtures_dir();
    let qr = dir.join("qr");
    assert!(
        qr.is_dir(),
        "fixtures not found at {}; set GDHCN_FIXTURES",
        qr.display()
    );

    let mut checked = 0;
    for entry in std::fs::read_dir(&qr).expect("read fixtures/qr") {
        let path = entry.expect("dir entry").path();
        let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
            continue;
        };
        let Some(stem) = name.strip_suffix(".hc1.txt") else {
            continue;
        };

        let hc1 = std::fs::read_to_string(&path).expect("read hc1");
        let hc1 = hc1.trim_end_matches(['\n', '\r']);
        let payload = hc1
            .strip_prefix("HC1:")
            .unwrap_or_else(|| panic!("{stem}: fixture does not start with HC1:"));

        let decoded = base45::decode(payload)
            .unwrap_or_else(|e| panic!("{stem}: base45 decode failed: {e}"));

        let ref_json = std::fs::read_to_string(dir.join("decode").join(format!("{stem}.json")))
            .unwrap_or_else(|e| panic!("{stem}: missing decode fixture: {e}"));
        let expected = reference_decoded_len(&ref_json);

        assert_eq!(
            decoded.len(),
            expected,
            "{stem}: base45 produced {} bytes, reference says {}",
            decoded.len(),
            expected
        );

        // Every WHO test payload is zlib-wrapped; catches a decode that
        // returns the right length but shifted bytes.
        assert_eq!(
            &decoded[..2],
            &[0x78, 0x9c],
            "{stem}: decoded payload does not start with the zlib header"
        );

        checked += 1;
    }
    assert!(checked >= 3, "expected at least 3 QR fixtures, checked {checked}");
}
