use std::{sync::mpsc, net::SocketAddrV4};

#[derive(Debug)]
pub enum TcpError {
    NoSynAck,
    InvalidAck,
}

enum TcpState {
    Listen,
    SynSent,
    SynReceived,
    Established,
    FinWait1,
    FinWait2,
    CloseWait,
    Closing,
    LastAck,
    TimeWait,
    Closed,
}

pub struct TcpSocket {
    source_ip: [u8; 4],
    destination_ip: [u8; 4],
    header: etherparse::TcpHeader,
    send_unack: u32,
    send_next: u32,
    window: Vec<u8>,
    state: TcpState,
    tx: mpsc::Sender<Vec<u8>>,
}

impl TcpSocket {
    pub fn new(source_addr: SocketAddrV4, destination_addr: SocketAddrV4, tx: mpsc::Sender<Vec<u8>>) -> Self {
        Self {
            source_ip: source_addr.ip().octets(),
            destination_ip: destination_addr.ip().octets(),
            send_unack: 0,
            send_next: 0,
            window: Vec::new(),
            header: etherparse::TcpHeader {
                source_port: source_addr.port(),
                destination_port: destination_addr.port(),
                sequence_number: rand::random(),
                acknowledgment_number: 0,
                ns: false,
                fin: false,
                syn: false,
                rst: false,
                psh: false,
                ack: false,
                urg: false,
                ece: false,
                cwr: false,
                window_size: 0xFFFF,
                checksum: 0,
                urgent_pointer: 0,
                options: etherparse::TcpOptions::default(),
            },
            state: TcpState::Listen,
            tx,
        }
    }

    pub fn connect(&mut self) {
        self.header.syn = true;
        self.state = TcpState::SynSent;

        let tcp = etherparse::PacketBuilder::ipv4(self.source_ip, self.destination_ip, 64)
            .tcp_header(self.header.clone());
        let mut result = Vec::with_capacity(tcp.size(0));
        tcp.write(&mut result, &[]).unwrap();

        self.tx.send(result).unwrap();
    }

    pub fn on_packet(&mut self, pkt: etherparse::TcpSlice) {
        eprintln!("SND.UNA: {}, SND.NXT: {}", self.send_unack, self.send_next);
        eprintln!("{:#?}", pkt);

        match self.state {
            TcpState::SynSent => {
                if !pkt.syn() || !pkt.ack() {
                    eprintln!("received packet without SYN/ACK in SynSent state");
                    return;
                }

                if pkt.acknowledgment_number() != (self.header.sequence_number + 1) {
                    let mut header = self.header.clone();
                    header.syn = false;
                    header.ack = false;
                    header.rst = true;
                    header.sequence_number = pkt.acknowledgment_number();

                    self.state = TcpState::CloseWait;
                    self.tx.send(self.generate_payload(header, &[])).expect("failed to send on channel");
                }

                self.header.syn = false;
                self.header.ack = true;
                self.header.acknowledgment_number = pkt.sequence_number() + 1;
                self.header.sequence_number += 1;
                self.send_next = self.header.sequence_number;
                self.send_unack = self.header.sequence_number;

                self.header.window_size = pkt.window_size().min(self.header.window_size);
                self.window.reserve_exact(self.header.window_size as usize);
                self.window.resize(self.header.window_size as usize, 0);

                self.state = TcpState::Established;
                self.tx.send(self.generate_payload(self.header.clone(), &[])).expect("failed to send on channel");
            },
            TcpState::Established => {
                if pkt.acknowledgment_number() <= self.send_unack || pkt.acknowledgment_number() > self.send_next {
                    eprintln!("invalid acknowledgement number received");
                    return;
                }

                self.send_unack = pkt.acknowledgment_number();
            },
            _ => panic!("unknown state"),
       };
    }

    pub fn send(&mut self, payload: &[u8]) -> Vec<u8> {
        self.header.psh = true;
        self.header.sequence_number = self.send_next;

        // window size = 2
        // SND.UNA = 2
        // SND.NXT = 4
        //  1    2    3    4
        // ----|----|----|----|
        // try to push 2 more bytes
        let len = self.window.len();
        let begin = self.send_unack as usize % len;
        let end = self.send_next as usize % len;

        let available_capacity = if begin <= end {
                (len - (end - begin)).min(payload.len())
            } else {
                begin - end
            };
        for idx in 0..available_capacity {
            self.window[(end + idx) % len] = payload[idx];
        }

        self.send_next += available_capacity as u32;

        let payload = self.generate_payload(self.header.clone(), &payload[0..available_capacity]);
        self.header.psh = false;
        payload
    }

    fn generate_payload(&self, header: etherparse::TcpHeader, payload: &[u8]) -> Vec<u8> {
        let tcp = etherparse::PacketBuilder::ipv4(self.source_ip, self.destination_ip, 64)
           .tcp_header(header);
        let mut result = Vec::with_capacity(tcp.size(0));
        tcp.write(&mut result, payload).unwrap();
        result
    }
}
