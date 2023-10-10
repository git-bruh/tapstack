use tapstack::tap::TapDevice;

fn main() {
    let dev = TapDevice::new("tap0").unwrap();
    dev.read_packets().unwrap();
}
