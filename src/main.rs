use tapstack::tap::TapDevice;
use tapstack::tcp::TcpSocket;
use std::sync::Arc;

fn main() {
    let (dev, rx) = TapDevice::new("tap0").unwrap();
    let dev = Arc::new(dev);

    let handle = {
        let dev = Arc::clone(&dev);
        std::thread::spawn(move || dev.read_packets().unwrap())
    };

    let (mut socket, payload) = TcpSocket::new(dev.ip, [45, 79, 112, 203], 1234, 4242);
    dev.write_packet(&payload).expect("failed to write packet");

    loop {
        match socket.handle_packet(rx.recv().unwrap()) {
            Ok(payload) => dev.write_packet(&payload).expect("failed to write packet"),
            Err(e) => {
                eprintln!("Failed to handle incoming TCP packet: {e:?}");
                break;
            },
        }
    }

    handle.join().expect("failed to join thread");
}
