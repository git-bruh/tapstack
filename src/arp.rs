/// RFC826
use crate::eth::EthHdr;
use crate::util;
use crate::Tap;
use core::fmt;
use nix::libc;

#[derive(Copy, Clone, Default)]
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

    /// ?Do I have the hardware type in ar$hrd?
    /// Yes: (almost definitely)
    ///   [optionally check the hardware length ar$hln]
    ///   ?Do I speak the protocol in ar$pro?
    ///   Yes:
    ///     [optionally check the protocol length ar$pln]
    ///     Merge_flag := false
    ///     If the pair <protocol type, sender protocol address> is
    ///         already in my translation table, update the sender
    ///         hardware address field of the entry with the new
    ///         information in the packet and set Merge_flag to true.
    ///     ?Am I the target protocol address?
    ///     Yes:
    ///       If Merge_flag is false, add the triplet <protocol type,
    ///           sender protocol address, sender hardware address> to
    ///           the translation table.
    ///       ?Is the opcode ares_op$REQUEST?  (NOW look at the opcode!!)
    ///       Yes:
    ///         Swap hardware and protocol fields, putting the local
    ///             hardware and protocol addresses in the sender fields.
    ///         Set the ar$op field to ares_op$REPLY
    ///         Send the packet to the (new) target hardware address on
    ///             the same hardware on which the request was received.
    pub fn to_reply_bytes<T: Tap>(&self, tap: &T) -> Vec<u8> {
        // XXX This is too tedious, should probably use an external crate
        // or refactor all structs to be packed, with a C representation
        let mut out_be_bytes = EthHdr {
            dest_mac: self.sha,
            source_mac: tap.mac(),
            eth_type: libc::ETH_P_ARP as u16,
        }
        .to_reply_bytes();

        out_be_bytes.extend(self.htype.to_be_bytes());
        out_be_bytes.extend(self.ptype.to_be_bytes());
        out_be_bytes.push(self.hlen);
        out_be_bytes.push(self.plen);
        // oper
        out_be_bytes.extend(libc::ARPOP_REPLY.to_be_bytes());
        // sha
        out_be_bytes.extend(tap.mac());
        // spa
        out_be_bytes.extend(self.tpa);
        // tha
        out_be_bytes.extend(self.sha);
        // tpa
        out_be_bytes.extend(self.spa);

        out_be_bytes
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
