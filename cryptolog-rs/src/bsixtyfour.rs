use base64::{Engine as _, engine::general_purpose};
// Original base64::encode is deprecated. Must reimplement with provided general engine

// General Purpose engine base64
// not constant-time
pub fn b64_general_encode(str: &str) -> String {
    let orig = str.as_bytes();
    let encoded: String = general_purpose::STANDARD_NO_PAD.encode(orig);
    return encoded;
}

// Encode_slice
pub fn b64_vec_encode(data: &[u8]) -> Vec<u8> {
    let mut buf = Vec::new();
    //TODO: explain
    buf.resize(data.len() * 4 / 3 + 4, 0);
    //TODO: handle unwraps with proper error handling
    let bytes_written = general_purpose::STANDARD.encode_slice(data, &mut buf).unwrap();
    buf.truncate(bytes_written);
    return buf;
}