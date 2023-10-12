/// RFC791
use crate::util;
use core::fmt;

#[derive(Copy, Clone)]
pub struct IpHdr {
    // Pack 4 bit version and ihl into an 8 bit int
    version_ihl: u8,
    pub tos: u8,
    pub tlen: u16,
    pub identification: u16,
    // pack the flags (3 bits) and fragment offset (13 bits)
    // together in a 16 bit int
    flags_frag_offset: u16,
    pub ttl: u8,
    pub proto: u8,
    pub hdr_cksum: u16,
    pub src_addr: u32,
    pub dst_addr: u32,
    /* options */
}

impl IpHdr {
    pub fn new(bytes: &[u8]) -> Self {
        let hdr = IpHdr {
            // Convert to_be() rather than to_le() as to_le() is a no-op
            // on little endian since rust assumes that the original value
            // was in LE
            version_ihl: bytes[0].to_be(),
            tos: bytes[1],
            tlen: util::unpack_u16(&bytes[2..4]),
            identification: util::unpack_u16(&bytes[4..6]),
            flags_frag_offset: util::unpack_u16(&bytes[6..8]),
            ttl: bytes[8],
            proto: bytes[9],
            hdr_cksum: util::unpack_u16(&bytes[10..12]),
            src_addr: util::unpack_u32(&bytes[12..16]),
            dst_addr: util::unpack_u32(&bytes[16..20]),
        };

        assert_eq!(Self::cksum(&bytes[..(hdr.ihl() * 4) as usize]), 0);
        hdr
    }

    /// Compute and verify the checksum
    fn cksum(bytes: &[u8]) -> u16 {
        let mut sum: u32 = 0;

        for (idx, byte) in bytes.iter().enumerate() {
            let byte = *byte as u32;

            // TODO unroll rather than this hack
            // > sum += * (unsigned short) addr++;
            // We must treat individual bytes in such a way that
            // every 2nd byte completes a 16 bit integer value
            if idx % 2 == 0 {
                sum += byte;
            } else {
                sum += byte << 8;
            }
        }

        while (sum >> 16) != 0 {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }

        (!sum as u16)
    }

    /// The first 4 bits contain the number
    pub fn version(&self) -> u8 {
        self.version_ihl >> 4
    }

    /// The last 4 bits contain th header len
    pub fn ihl(&self) -> u8 {
        self.version_ihl & 0b00001111
    }

    /// The first 3 bits contain the flags
    pub fn flags(&self) -> u16 {
        self.flags_frag_offset >> 13
    }

    /// The last 13 bits contain the offset
    pub fn frag_offset(&self) -> u16 {
        self.flags_frag_offset & ((1 << 13) - 1)
    }
}

impl fmt::Debug for IpHdr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("IpHdr")
            .field("version", &self.version())
            .field("ihl", &self.ihl())
            .field("tos", &self.tos)
            .field("tlen", &self.tlen)
            .field("identification", &self.identification)
            .field("flags", &self.flags())
            .field("frag_offset", &self.frag_offset())
            .field("ttl", &self.ttl)
            .field("proto", &self.proto)
            .field("hdr_cksum", &self.hdr_cksum)
            .field("src_addr", &util::bytes_to_ip(&self.src_addr.to_be_bytes()))
            .field("dst_addr", &util::bytes_to_ip(&self.dst_addr.to_be_bytes()))
            .finish()
    }
}
