/// RFC792
use crate::util;
use core::fmt;

#[derive(Debug, Copy, Clone)]
pub struct IcmpHdr {
    pub typ: u8,
    pub code: u8,
    pub cksum: u16,
    pub content: u32,
}

#[derive(Debug, Copy, Clone)]
pub struct IcmpEcho {
    id: u16,
    seq: u16,
}

impl IcmpHdr {
    pub const ICMP_CONTROL_ECHO_REPLY: u8 = 0;
    pub const ICMP_CONTROL_ECHO_REQUEST: u8 = 8;

    pub fn new(bytes: &[u8]) -> Self {
        let hdr = IcmpHdr {
            typ: bytes[0],
            code: bytes[1],
            cksum: util::unpack_u16(&bytes[2..4]),
            content: util::unpack_u32(&bytes[4..8]),
        };

        println!(
            "ID: {}\nSeq: {}",
            hdr.content >> 16,
            hdr.content & ((1 << 16) - 1),
        );

        hdr
    }

    pub fn payload(&self) {}
}
