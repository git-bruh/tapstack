use nix::sys::socket::SockaddrIn;
use tapstack::tap::TapDevice;

fn main() {
    let dev = TapDevice::new("tap0", &SockaddrIn::new(10, 0, 2, 100, 0)).unwrap();
    dev.read_packets().unwrap();
}
