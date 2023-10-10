use std::fmt::Write;

pub fn bytes_to_mac(bytes: &[u8]) -> String {
    let mut out = String::new();
    out.reserve("ff:ff:ff:ff:ff:ff".len() + 1);

    for byte in bytes {
        write!(out, "{:02x}:", byte).expect("failed to write!");
    }

    // Trailing ':'
    out.pop();
    out
}
