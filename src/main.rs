use std::{
    io::{BufRead, BufReader, BufWriter, Write},
    net::{Ipv4Addr, SocketAddrV4, ToSocketAddrs},
    sync::Arc,
};
use tapstack::tun::TunDevice;
use tracing::info;
use tracing_subscriber::{fmt, layer::SubscriberExt, Registry};

fn resolve(url: &str) -> std::net::SocketAddrV4 {
    for addr in url.to_socket_addrs().unwrap() {
        if let std::net::SocketAddr::V4(addr) = addr {
            return addr;
        }
    }

    panic!("no IPv4 address resolved");
}

fn main() {
    let subscriber = Registry::default().with(fmt::layer().with_writer(std::io::stderr));
    tracing::subscriber::set_global_default(subscriber).unwrap();

    let dev = Arc::new(TunDevice::new("tun0").unwrap());

    let reader_handle = {
        let dev = Arc::clone(&dev);
        std::thread::spawn(move || dev.read_packets().unwrap())
    };

    if true {
        let socket = dev.connect(resolve("tcpbin.com:4242")).unwrap();

        let mut writer = BufWriter::new(&socket);
        let mut reader = BufReader::new(&socket);

        writer.write_all(b"hello").unwrap();
        writer.flush().unwrap();

        socket.close();

        let mut buf = String::new();
        reader.read_line(&mut buf).unwrap();

        info!("read after close: {buf}");
    } else {
        let url = "fsn1-speed.hetzner.com:80";
        let path = "/100MB.bin";

        let socket = dev.connect(resolve(url)).unwrap();

        let mut writer = BufWriter::new(&socket);
        let mut reader = BufReader::new(&socket);

        let req = format!(
            "{} {} {}\r\nHost: {}\r\nUser-Agent: {}\r\nAccept: {}\r\n\r\n",
            "GET",
            path,
            "HTTP/1.0",
            url.split(':').nth(0).unwrap(),
            "curl/8.13.0",
            "*/*"
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

        info!("Got content length: {content_length}");
        socket.reset();
    }

    reader_handle.join().expect("failed to join thread");
}
