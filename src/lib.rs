#[macro_use]
extern crate nix;

use nix::fcntl::OFlag;
use nix::libc;
use nix::sys::stat::Mode;
use std::mem::MaybeUninit;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

// ioctl_write_ptr!(tap_fd.as_raw_fd(), TUNSETIFF, &ifreq);

pub struct TapDevice {
    tap_fd: OwnedFd,
}

ioctl_write_int!(tunsetiff, b'T' as u8, 202 as u32);

impl TapDevice {
    pub fn new(devname: &str) -> Result<Self, std::io::Error> {
        let tap_fd = unsafe {
            OwnedFd::from_raw_fd(nix::fcntl::open(
                "/dev/net/tun",
                OFlag::O_RDWR,
                Mode::empty(),
            )?)
        };

        // XXX is there a better way than doing a memcpy by hand like this?
        let mut ifr_name: [i8; 16] = [0; 16];
        assert!(devname.len() < 16);

        // Don't overwrite the NUL char
        for (left, right) in ifr_name[..15].iter_mut().zip(devname.chars()) {
            *left = right as i8;
        }

        // Note that printing out this structure will yield surpring values in the
        // `ifr_ifru` nested struct as it is a union
        let mut ifreq = unsafe { MaybeUninit::<libc::ifreq>::zeroed().assume_init() };

        ifreq.ifr_name = ifr_name;
        // IFF_TAP - TAP Device
        // IFF_NO_PI - Don't provide packet information
        ifreq.ifr_ifru.ifru_flags = (libc::IFF_TAP | libc::IFF_NO_PI) as i16;

        println!("{:#?}", ifreq.ifr_name);

        // TODO investigate why ioctl_write_ptr! causes EBADFD while
        // passing the pointer as a u64 works fine
        unsafe {
            tunsetiff(tap_fd.as_raw_fd(), &ifreq as *const _ as u64)?;
        }

        Ok(Self { tap_fd })
    }
}
