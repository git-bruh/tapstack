use crate::arp::ArpHdr;
use crate::eth::EthHdr;
use crate::ip::IpHdr;
use crate::util;
use crate::Tap;
use nix::fcntl::OFlag;
use nix::libc;
use nix::sys::{
    socket::{AddressFamily, SockFlag, SockType, SockaddrIn, SockaddrLike},
    stat::Mode,
};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
ioctl_write_int!(tunsetiff, b'T' as u8, 202 as u32);
ioctl_write_ptr_bad!(siocsifaddr, libc::SIOCSIFADDR, libc::ifreq);
ioctl_read_bad!(siocgifhwaddr, libc::SIOCGIFHWADDR, libc::ifreq);

pub struct TapDevice {
    devname: String,
    ip: u32,
    mac: [u8; 6],
    tap_fd: OwnedFd,
}

impl TapDevice {
    pub fn new(devname: &str, ip: &SockaddrIn) -> Result<Self, std::io::Error> {
        let tap_fd = unsafe {
            OwnedFd::from_raw_fd(nix::fcntl::open(
                "/dev/net/tun",
                OFlag::O_RDWR,
                Mode::empty(),
            )?)
        };

        let ifreq = util::create_ifreq(devname, (libc::IFF_TAP | libc::IFF_NO_PI) as i16);

        // TODO investigate why ioctl_write_ptr! causes EBADFD while
        // passing the pointer as a u64 works fine
        // Perhaps ioctl_write_ptr_bad! is what we need
        unsafe {
            tunsetiff(tap_fd.as_raw_fd(), &ifreq as *const _ as u64)?;
        }

        Self::set_ip_addr(devname, ip)?;

        Ok(Self {
            devname: String::from(devname),
            ip: ip.ip(),
            mac: Self::get_mac_addr(devname)?,
            tap_fd,
        })
    }

    fn set_ip_addr(devname: &str, sockaddr: &SockaddrIn) -> Result<(), std::io::Error> {
        let sockfd = nix::sys::socket::socket(
            AddressFamily::Inet,
            SockType::Datagram,
            SockFlag::empty(),
            None,
        )?;

        let mut ifreq = util::create_ifreq(devname, 0);

        unsafe {
            ifreq.ifr_ifru.ifru_addr = *sockaddr.as_ptr();
            siocsifaddr(sockfd.as_raw_fd(), &ifreq)?;
        }

        Ok(())
    }

    fn get_mac_addr(devname: &str) -> Result<[u8; 6], std::io::Error> {
        let sockfd = nix::sys::socket::socket(
            AddressFamily::Inet,
            SockType::Datagram,
            SockFlag::empty(),
            None,
        )?;

        let mut ifreq = util::create_ifreq(devname, 0);

        unsafe {
            siocgifhwaddr(sockfd.as_raw_fd(), &mut ifreq)?;
        }

        let mut mac = [0_u8; 6];

        for (left, right) in mac[..]
            .iter_mut()
            .zip(unsafe { ifreq.ifr_ifru.ifru_hwaddr.sa_data })
        {
            *left = right as u8;
        }

        Ok(mac)
    }

    pub fn read_packets(&self) -> Result<(), std::io::Error> {
        loop {
            // TODO re-use this vec rather than re-allocating
            let mut buf = vec![0_u8; 65536];
            let size = nix::unistd::read(self.tap_fd.as_raw_fd(), &mut buf[..])?;

            let eth_hdr = EthHdr::new(&buf[..size]);
            println!("Read ETH {size} {eth_hdr:#?}");

            if eth_hdr.eth_type >= 1536 {
                match eth_hdr.eth_type as i32 {
                    libc::ETH_P_ARP => {
                        let arp_hdr = ArpHdr::new(&buf[14..]);

                        println!("Got ARP request! {:#?}", arp_hdr);

                        let bytes = arp_hdr.to_reply_bytes(self);
                        println!(
                            "Constructed Ethernet Frame {:#?}\nARP Frame {:#?}",
                            EthHdr::new(&bytes[..]),
                            ArpHdr::new(&bytes[14..])
                        );

                        nix::unistd::write(self.tap_fd.as_raw_fd(), &bytes)?;
                    }
                    libc::ETH_P_IP => {
                        let ip_hdr = IpHdr::new(&buf[14..]);

                        println!("Got IP packet! {:#?}", ip_hdr);
                    }
                    libc::ETH_P_IPV6 => {
                        println!("Got IPv6 request!");
                    }
                    unknown => {
                        println!("Unknown type: {unknown}!");
                    }
                }
            } else {
                println!("Got payload with length: {}", eth_hdr.eth_type);
            }
        }
    }
}

impl Tap for TapDevice {
    fn mac(&self) -> [u8; 6] {
        self.mac
    }

    fn ip(&self) -> u32 {
        self.ip
    }
}
