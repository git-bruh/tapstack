#[macro_use]
extern crate nix;

pub mod arp;
pub mod eth;
pub mod icmp;
pub mod ip;
pub mod tap;
pub mod util;

pub trait Tap {
    fn mac(&self) -> [u8; 6];
    fn ip(&self) -> u32;
}
