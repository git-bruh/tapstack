use nix::libc;
use std::fmt::Write;
use std::mem::MaybeUninit;

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

pub fn bytes_to_ip(bytes: &[u8]) -> String {
    let mut out = String::new();
    out.reserve("255.255.255.255".len() + 1);

    for byte in bytes {
        write!(out, "{}.", byte).expect("failed to write!");
    }

    // Trailing '.'
    out.pop();
    out
}

/// BE -> LE
pub fn unpack_u16(bytes: &[u8]) -> u16 {
    assert!(bytes.len() == 2);
    ((bytes[0] as u16) << 8) + (bytes[1] as u16)
}

/// BE -> LE
pub fn unpack_u32(bytes: &[u8]) -> u32 {
    assert!(bytes.len() == 4);
    ((bytes[0] as u32) << 24)
        + ((bytes[1] as u32) << 16)
        + ((bytes[2] as u32) << 8)
        + (bytes[3] as u32)
}

pub fn create_ifreq(devname: &str, ifru_flags: i16) -> libc::ifreq {
    assert!(devname.len() < 16);

    // Note that printing out this structure will yield surpring values in the
    // `ifr_ifru` nested struct as it is a union
    let mut ifreq = unsafe { MaybeUninit::<libc::ifreq>::zeroed().assume_init() };

    // Don't overwrite the NUL char (end at 15)
    for (left, right) in ifreq.ifr_name[..15].iter_mut().zip(devname.chars()) {
        *left = right as _;
    }

    ifreq.ifr_ifru.ifru_flags = ifru_flags;
    ifreq
}
