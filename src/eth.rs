use crate::util;
use core::fmt;

#[derive(Default)]
pub struct EthHdr {
    pub dest_mac: [u8; 6],
    pub source_mac: [u8; 6],
    pub eth_type: u16,
}

impl EthHdr {
    pub fn new(bytes: &[u8]) -> Self {
        if bytes.len() < 14 {
            panic!("read() too few bytes!");
        }

        let mut hdr: EthHdr = Default::default();

        hdr.dest_mac.copy_from_slice(&bytes[0..6]);
        hdr.source_mac.copy_from_slice(&bytes[6..12]);
        hdr.eth_type = util::unpack_u16(&bytes[12..14]);

        hdr
    }

    pub fn to_reply_bytes(&self) -> Vec<u8> {
        let mut out_be_bytes = Vec::<u8>::new();
        out_be_bytes.reserve(14);

        out_be_bytes.extend(self.dest_mac);
        out_be_bytes.extend(self.source_mac);
        out_be_bytes.extend(self.eth_type.to_be_bytes());

        out_be_bytes
    }
}

impl fmt::Debug for EthHdr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EthHdr")
            .field("dest_mac", &util::bytes_to_mac(&self.dest_mac))
            .field("source_mac", &util::bytes_to_mac(&self.source_mac))
            .field("eth_type", &self.eth_type)
            .finish()
    }
}
