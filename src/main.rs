use tapstack::tap::TapDevice;
use std::{net::{SocketAddrV4, Ipv4Addr}, sync::Arc};

fn main() {
    let dev = Arc::new(TapDevice::new("tap0").unwrap());

    std::thread::sleep(std::time::Duration::from_secs(5));

    let reader_handle = {
        let dev = Arc::clone(&dev);
        std::thread::spawn(move || dev.read_packets().unwrap())
    };

    let socket = dev.connect(SocketAddrV4::new(Ipv4Addr::new(45, 79, 112, 203), 4242)).unwrap();
    socket.write(b"hello\n");
    let response = socket.read();
    eprintln!("Response {response:?}");

    reader_handle.join().expect("failed to join thread");
}
