use crate::tap::TcpPacket;

#[derive(Debug)]
pub enum TcpError {
    NoSynAck,
}

pub struct TcpSocket {
    source_ip: [u8; 4],
    destination_ip: [u8; 4],
    header: etherparse::TcpHeader,
    send_unack: u32,
    send_next: u32,
    window: Vec<u8>,
}

impl TcpSocket {
    pub fn new(source_ip: [u8; 4], destination_ip: [u8; 4], source_port: u16, destination_port: u16) -> (Self, Vec<u8>) {
        let socket = Self {
            source_ip,
            destination_ip,
            send_unack: 0,
            send_next: 0,
            window: Vec::new(),
            header: etherparse::TcpHeader {
                source_port,
                destination_port,
                sequence_number: 0xDEADBEEF,
                acknowledgment_number: 0,
                ns: false,
                fin: false,
                syn: true,
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
            }
        };

        let tcp = etherparse::PacketBuilder::ipv4(socket.source_ip, socket.destination_ip, 64)
            .tcp_header(socket.header.clone());
        let mut result = Vec::with_capacity(tcp.size(0));
        tcp.write(&mut result, &[]).unwrap();

        (socket, result)
    }

    pub fn handle_packet(&mut self, pkt: TcpPacket) -> Result<Vec<u8>, TcpError> {
        if self.header.syn {
            eprintln!("Handling SYN-ACK");

            if !pkt.header.syn || !pkt.header.ack {
                return Err(TcpError::NoSynAck);
            }

            if pkt.header.acknowledgment_number != (self.header.sequence_number + 1) {
                let mut header = self.header.clone();
                header.syn = false;
                header.ack = false;
                header.rst = true;
                header.sequence_number = pkt.header.acknowledgment_number;

                return Ok(self.generate_payload(header, &[]));
            }

            self.header.syn = false;
            self.header.ack = true;
            self.header.acknowledgment_number = pkt.header.sequence_number + 1;
            self.header.sequence_number += 1;
            self.header.window_size = pkt.header.window_size.min(self.header.window_size);

            self.window.reserve_exact(self.header.window_size as usize);
            self.send_next = self.header.sequence_number + 1;
        }

        Ok(self.generate_payload(self.header.clone(), &[]))
    }

    pub fn send(&mut self, payload: &[u8]) -> Vec<u8> {
        self.header.sequence_number = self.send_next;
        self.header.acknowledgment_number += 1;

        self.send_unack = self.send_next;
        self.send_next += available_capacity;

        self.generate_payload(self.header.clone(), &[])
    }

    fn generate_payload(&self, header: etherparse::TcpHeader, payload: &[u8]) -> Vec<u8> {
        let tcp = etherparse::PacketBuilder::ipv4(self.source_ip, self.destination_ip, 64)
           .tcp_header(header);
        let mut result = Vec::with_capacity(tcp.size(0));
        tcp.write(&mut result, payload).unwrap();
        result
    }
}
