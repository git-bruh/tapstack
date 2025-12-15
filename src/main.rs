use std::{
    io::{Read, Write},
    net::{Ipv4Addr, SocketAddrV4},
    sync::Arc,
};
use tapstack::tun::TunDevice;
use tracing_subscriber::{fmt, layer::SubscriberExt, Registry};

fn main() {
    let subscriber = Registry::default().with(fmt::layer().with_writer(std::io::stderr));
    tracing::subscriber::set_global_default(subscriber).unwrap();

    let dev = Arc::new(TunDevice::new("tun0").unwrap());

    let reader_handle = {
        let dev = Arc::clone(&dev);
        std::thread::spawn(move || dev.read_packets().unwrap())
    };

    let mut socket = dev
        .connect(SocketAddrV4::new(Ipv4Addr::new(45, 79, 112, 203), 4242))
        .unwrap();

    socket.write(b"hello\n").unwrap();
    let mut buf = [0; 4096];
    let n = socket.read(&mut buf).unwrap();
    eprintln!("=== Response {}", std::str::from_utf8(&buf[0..n]).unwrap());
    socket.close();

    reader_handle.join().expect("failed to join thread");
}
