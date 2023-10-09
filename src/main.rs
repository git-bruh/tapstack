use tapstack::TunDevice;

fn main() {
    TunDevice::new("tap0").unwrap();
}
