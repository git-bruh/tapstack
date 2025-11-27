use tapstack::tap::TapDevice;
use tapstack::tcp::TcpSocket;
use std::sync::Arc;

fn main() {
    let (dev, rx) = TapDevice::new("tap0").unwrap();
    let dev = Arc::new(dev);

    std::thread::sleep(std::time::Duration::from_secs(5));

    let handle = {
        let dev = Arc::clone(&dev);
        std::thread::spawn(move || dev.read_packets().unwrap())
    };

    let (mut socket, payload) = TcpSocket::new(dev.ip, [45, 79, 112, 203], 1234, 4242);
    dev.write_packet(&payload).expect("failed to write packet");

    let mut estab = false;
    loop {
        match socket.handle_packet(rx.recv().unwrap()) {
            Ok(payload) => if let Some(payload) = payload { dev.write_packet(&payload).expect("failed to write packet") },
            Err(e) => {
                eprintln!("Failed to handle incoming TCP packet: {e:?}");
                break;
            },
        }

        if !estab {
            estab = true;
            dev.write_packet(&socket.send(b"hello")).expect("failed to write packet");
        }
    }

    handle.join().expect("failed to join thread");
}
