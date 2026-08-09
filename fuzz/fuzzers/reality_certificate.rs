#![no_main]

use libfuzzer_sys::fuzz_target;
use rustls::internal::fuzzing::fuzz_reality_certificate;

fuzz_target!(|data: &[u8]| {
    if let Some(encoded) = data.strip_prefix(b"hex:") {
        if let Some(decoded) = decode_hex(encoded) {
            std::hint::black_box(fuzz_reality_certificate(&decoded));
        }
        return;
    }

    std::hint::black_box(fuzz_reality_certificate(data));
});

fn decode_hex(encoded: &[u8]) -> Option<Vec<u8>> {
    let mut decoded = Vec::with_capacity(encoded.len() / 2);
    let mut high_nibble = None;

    for byte in encoded {
        if byte.is_ascii_whitespace() {
            continue;
        }

        let nibble = match byte {
            b'0'..=b'9' => byte - b'0',
            b'a'..=b'f' => byte - b'a' + 10,
            b'A'..=b'F' => byte - b'A' + 10,
            _ => return None,
        };

        match high_nibble.take() {
            Some(high) => decoded.push((high << 4) | nibble),
            None => high_nibble = Some(nibble),
        }
    }

    high_nibble.is_none().then_some(decoded)
}
