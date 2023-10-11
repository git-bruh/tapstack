/// RFC826
use crate::util;
use core::fmt;

#[derive(Default)]
pub struct ArpHdr {
    pub htype: u16,
    pub ptype: u16,
    pub hlen: u8,
    pub plen: u8,
    pub oper: u16,
    pub sha: [u8; 6],
    pub spa: [u8; 4],
    pub tha: [u8; 6],
    pub tpa: [u8; 4],
}

impl ArpHdr {
    pub fn new(bytes: &[u8]) -> Self {
        if bytes.len() < 28 {
            panic!("read() too few bytes!");
        }

        let mut arp: ArpHdr = Default::default();

        arp.htype = util::unpack_u16(&bytes[0..2]);
        arp.ptype = util::unpack_u16(&bytes[2..4]);
        arp.hlen = bytes[4];
        arp.plen = bytes[5];
        arp.oper = util::unpack_u16(&bytes[6..8]);
        arp.sha.copy_from_slice(&bytes[8..14]);
        arp.spa.copy_from_slice(&bytes[14..18]);
        arp.tha.copy_from_slice(&bytes[18..24]);
        arp.tpa.copy_from_slice(&bytes[24..28]);

        arp
    }
}

impl fmt::Debug for ArpHdr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ArpHdr")
            .field("htype", &self.htype)
            .field("ptype", &self.ptype)
            .field("hlen", &self.hlen)
            .field("plen", &self.plen)
            .field("oper", &self.oper)
            .field("sha", &util::bytes_to_mac(&self.sha))
            .field("spa", &util::bytes_to_ip(&self.spa))
            .field("tha", &util::bytes_to_mac(&self.tha))
            .field("tpa", &util::bytes_to_ip(&self.tpa))
            .finish()
    }
}
