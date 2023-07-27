use base64::{Engine as _, engine::general_purpose};

// General Purpose engine base64
// not constant-time
pub fn b64_general_encode(str: &str) -> String {
    let orig = str.as_bytes();
    let encoded: String = general_purpose::STANDARD_NO_PAD.encode(orig);
    return encoded;
}