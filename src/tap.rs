use crate::{util, tcp};
use nix::{
    fcntl::OFlag,
    libc,
    sys::{
        socket::{AddressFamily, SockFlag, SockType, SockaddrIn, SockaddrLike},
        stat::Mode,
    },
};
use std::{
    sync::{mpsc, Mutex, Arc},
    collections::HashMap,
    os::fd::{AsRawFd, FromRawFd, OwnedFd},
    net::{SocketAddrV4, Ipv4Addr},
};

ioctl_write_int!(tunsetiff, b'T' as u8, 202 as u32);
ioctl_write_ptr_bad!(siocsifaddr, libc::SIOCSIFADDR, libc::ifreq);
ioctl_read_bad!(siocgifhwaddr, libc::SIOCGIFHWADDR, libc::ifreq);

pub struct TapDevice {
    pub devname: String,
    pub ip: [u8; 4],
    pub mac: [u8; 6],
    tap_fd: OwnedFd,
    quad_to_socket: Mutex<HashMap<(SocketAddrV4, SocketAddrV4), Arc<Mutex<tcp::TcpSocket>>>>,
    tx: mpsc::Sender<Vec<u8>>,
    writer_jh: std::thread::JoinHandle<()>,
}

impl TapDevice {
    pub fn new(devname: &str) -> Result<Self, std::io::Error> {
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

        let (tx, rx): (mpsc::Sender<Vec<u8>>, mpsc::Receiver<Vec<u8>>) = mpsc::channel();

        let raw_fd = tap_fd.as_raw_fd();
        let writer_jh = std::thread::spawn(move || loop {
            nix::unistd::write(raw_fd, &rx.recv().unwrap()).unwrap();
        });

        Ok(Self {
            devname: String::from(devname),
            ip: [10, 0, 0, 1],
            mac: Self::get_mac_addr(devname)?,
            quad_to_socket: Mutex::new(HashMap::new()),
            tap_fd,
            tx,
            writer_jh,
        })
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
                                let quad = (SocketAddrV4::new(ip.destination_addr(), tcp.destination_port()), SocketAddrV4::new(ip.source_addr(), tcp.source_port()));
                                if let Some(socket) = self.quad_to_socket.lock().unwrap().get_mut(&quad) {
                                    socket.lock().unwrap().on_packet(tcp);
                                } else {
                                    eprintln!("Received TCP packet for unknown quad: {quad:?}");
                                }
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

    pub fn connect(&self, remote_addr: SocketAddrV4) -> Result<tcp::TcpSocketWrapper, std::io::Error> {
        let [a, b, c, d] = self.ip;
        let mut local_addr = SocketAddrV4::new(
            Ipv4Addr::new(a, b, c, d),
            rand::random_range(10000..=65535),
        );

        let mut quad_to_socket = self.quad_to_socket.lock().unwrap();

        'a: loop {
            for quad in quad_to_socket.keys() {
                if quad.0.port() == local_addr.port() {
                    local_addr.set_port(local_addr.port() + 1);
                    continue 'a;
                }
            }

            break;
        }

        let socket = tcp::TcpSocket::new(local_addr, remote_addr, self.tx.clone());
        let condvar = socket.state_condvar();
        let socket = Arc::new(Mutex::new(socket));
        quad_to_socket.insert((local_addr, remote_addr), socket.clone());
        drop(quad_to_socket);

        let socket = tcp::TcpSocketWrapper::new(socket, condvar);
        socket.connect();

        Ok(socket)
    }
}
