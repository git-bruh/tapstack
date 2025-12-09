use tapstack::tap::TapDevice;
use std::{net::{SocketAddrV4, Ipv4Addr}, io::{Read, Write}, sync::Arc};

fn main() {
    let dev = Arc::new(TapDevice::new("tap0").unwrap());

    std::thread::sleep(std::time::Duration::from_secs(5));

    let reader_handle = {
        let dev = Arc::clone(&dev);
        std::thread::spawn(move || dev.read_packets().unwrap())
    };

    let mut socket = dev.connect(SocketAddrV4::new(Ipv4Addr::new(45, 79, 112, 203), 4242)).unwrap();

    loop {
        socket.write(b"hello\n").unwrap();
        let mut buf = [0; 4096];
        let n = socket.read(&mut buf).unwrap();
        eprintln!("=== Response {}", std::str::from_utf8(&buf[0..n]).unwrap());

        std::thread::sleep(std::time::Duration::from_secs(1));
    }

    reader_handle.join().expect("failed to join thread");
}
