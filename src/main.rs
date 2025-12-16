use std::{
    io::{BufRead, BufReader, BufWriter, Write},
    net::{Ipv4Addr, SocketAddrV4},
    sync::Arc,
};
use tapstack::tun::TunDevice;
use tracing::info;
use tracing_subscriber::{fmt, layer::SubscriberExt, Registry};

fn main() {
    let subscriber = Registry::default().with(fmt::layer().with_writer(std::io::stderr));
    tracing::subscriber::set_global_default(subscriber).unwrap();

    let dev = Arc::new(TunDevice::new("tun0").unwrap());

    let reader_handle = {
        let dev = Arc::clone(&dev);
        std::thread::spawn(move || dev.read_packets().unwrap())
    };

    let socket = dev
        .connect(SocketAddrV4::new(Ipv4Addr::new(78, 46, 170, 2), 80))
        .unwrap();

    let mut writer = BufWriter::new(&socket);
    let mut reader = BufReader::new(&socket);

    let req = format!(
        "{} {} {}\r\nHost: {}\r\nUser-Agent: {}\r\nAccept: {}\r\n\r\n",
        "GET", "/100MB.bin", "HTTP/1.0", "fsn1-speed.hetzner.com", "curl/8.13.0", "*/*"
    );
    writer.write_all(req.as_bytes()).unwrap();
    writer.flush().unwrap();

    let mut buf = String::new();
    let mut content_length = 0;
    while buf != "\r\n" {
        buf.clear();
        reader.read_line(&mut buf).unwrap();
        info!("Got header: {buf:?}");
        if buf.starts_with("Content-Length:") {
            content_length =
                u64::from_str_radix(&buf["Content-Length: ".len()..buf.len() - 2], 10).unwrap();
        }
    }

    socket.reset();

    reader_handle.join().expect("failed to join thread");
}
