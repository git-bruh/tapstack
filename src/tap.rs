use crate::util;
use nix::{
    fcntl::OFlag,
    libc,
    sys::{
        socket::{AddressFamily, SockFlag, SockType, SockaddrIn, SockaddrLike},
        stat::Mode,
    },
};
use std::{
    sync::{mpsc, mpsc::{Sender, Receiver}},
    os::fd::{AsRawFd, FromRawFd, OwnedFd},
};

ioctl_write_int!(tunsetiff, b'T' as u8, 202 as u32);
ioctl_write_ptr_bad!(siocsifaddr, libc::SIOCSIFADDR, libc::ifreq);
ioctl_read_bad!(siocgifhwaddr, libc::SIOCGIFHWADDR, libc::ifreq);

pub struct TcpPacket {
    pub header: etherparse::TcpHeader,
    pub payload: Vec<u8>,
}

pub struct TapDevice {
    pub devname: String,
    pub ip: [u8; 4],
    pub mac: [u8; 6],
    tx: Sender<TcpPacket>,
    tap_fd: OwnedFd,
}

impl TapDevice {
    pub fn new(devname: &str) -> Result<(Self, Receiver<TcpPacket>), std::io::Error> {
        let tap_fd = unsafe {
            OwnedFd::from_raw_fd(nix::fcntl::open(
                "/dev/net/tun",
                OFlag::O_RDWR,
                Mode::empty(),
            )?)
        };

        let ifreq = util::create_ifreq(devname, (libc::IFF_TUN | libc::IFF_NO_PI) as i16);

        // TODO investigate why ioctl_write_ptr! causes EBADFD while
        // passing the pointer as a u64 works fine
        // Perhaps ioctl_write_ptr_bad! is what we need
        unsafe {
            tunsetiff(tap_fd.as_raw_fd(), &ifreq as *const _ as u64)?;
        }

        std::process::Command::new("ip")
            .arg("link")
            .arg("set")
            .arg(devname)
            .arg("up")
            .spawn()?
            .wait()?;

        std::process::Command::new("ip")
            .arg("route")
            .arg("add")
            .arg("dev")
            .arg(devname)
            .arg("10.0.0.0/24")
            .spawn()?
            .wait()?;

        std::process::Command::new("ip")
            .arg("addr")
            .arg("add")
            .arg("dev")
            .arg(devname)
            .arg("local")
            .arg("10.0.0.2/24")
            .spawn()?
            .wait()?;

        let (tx, rx) = mpsc::channel();

        Ok((Self {
            devname: String::from(devname),
            ip: [10, 0, 0, 1],
            mac: Self::get_mac_addr(devname)?,
            tap_fd,
            tx,
        }, rx))
    }

    fn _set_ip_addr(devname: &str, sockaddr: &SockaddrIn) -> Result<(), std::io::Error> {
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
            let mut buf = vec![0_u8; 65536];
            let size = nix::unistd::read(self.tap_fd.as_raw_fd(), &mut buf[..])?;
            match etherparse::Ipv4HeaderSlice::from_slice(&buf) {
                Ok(ip) => match ip.protocol() {
                    etherparse::IpNumber::TCP => {
                        match etherparse::TcpSlice::from_slice(&buf[ip.slice().len()..size]) {
                            Ok(tcp) => {
                                println!("Got TCP packet: {tcp:?}");
                                self.tx.send(TcpPacket {
                                    header: tcp.to_header(),
                                    payload: tcp.payload().to_vec(),
                                }).unwrap();
                            }
                            Err(e) => eprintln!("Invalid TCP packet received: {e}"),
                        }
                    }
                    etherparse::IpNumber::ICMP => {
                        match etherparse::Icmpv4Slice::from_slice(&buf[ip.slice().len()..size]) {
                            Ok(icmp) => println!("Got ICMP packet: {:?}", icmp.icmp_type()),
                            Err(e) => eprintln!("Invalid ICMP packet received: {e}"),
                        }
                    }
                    protocol => eprintln!("Unknown IP protocol: {protocol:?}"),
                },
                Err(e) => eprintln!("Invalid IP packet received: {e}"),
            }
        }
    }

    pub fn write_packet(&self, data: &[u8]) -> Result<(), std::io::Error> {
        nix::unistd::write(self.tap_fd.as_raw_fd(), data)?;
        Ok(())
    }
}
