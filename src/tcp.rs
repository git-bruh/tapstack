use std::{
    collections::HashMap,
    net::SocketAddrV4,
    sync::{mpsc, Arc, Condvar, Mutex},
};

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
    recv_next: u32,
    window: Vec<u8>,
    state: TcpState,
    state_condvar: Arc<Condvar>,
    tx: mpsc::Sender<Vec<u8>>,
}

pub struct TcpSocketWrapper {
    socket: Arc<Mutex<TcpSocket>>,
    state_condvar: Arc<Condvar>,
}

impl TcpSocketWrapper {
    pub fn new(socket: Arc<Mutex<TcpSocket>>, state_condvar: Arc<Condvar>) -> Self {
        Self {
            socket,
            state_condvar,
        }
    }

    pub fn connect(&self) {
        let mut socket = self.socket.lock().unwrap();
        socket.connect();

        while !matches!(socket.state, TcpState::Established) {
            socket = self.state_condvar.wait(socket).unwrap();
        }
    }

    pub fn write(&self, data: &[u8]) {
        self.socket.lock().unwrap().write(data)
    }

    pub fn read(&self) -> Vec<u8> {
        let mut socket = self.socket.lock().unwrap();
        Vec::new()
    }
}

impl TcpSocket {
    pub fn new(
        source_addr: SocketAddrV4,
        destination_addr: SocketAddrV4,
        tx: mpsc::Sender<Vec<u8>>,
    ) -> Self {
        let sequence_number = rand::random();

        Self {
            source_ip: source_addr.ip().octets(),
            destination_ip: destination_addr.ip().octets(),
            send_unack: sequence_number,
            send_next: sequence_number + 1,
            recv_next: 0,
            window: Vec::new(),
            header: etherparse::TcpHeader {
                source_port: source_addr.port(),
                destination_port: destination_addr.port(),
                sequence_number,
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
            state_condvar: Arc::new(Condvar::new()),
            tx,
        }
    }

    pub fn state_condvar(&self) -> Arc<Condvar> {
        Arc::clone(&self.state_condvar)
    }

    pub fn connect(&mut self) {
        self.header.syn = true;
        self.state = TcpState::SynSent;

        self.transmit_payload(self.header.clone(), &[]).unwrap();
    }

    fn set_state(&mut self, state: TcpState) {
        self.state = state;
        self.state_condvar.notify_all();
    }

    pub fn on_packet(&mut self, pkt: etherparse::TcpSlice) {
        eprintln!("SND.UNA: {}, SND.NXT: {}", self.send_unack, self.send_next);
        eprintln!("{:#?}", pkt);

        match self.state {
            TcpState::SynSent => {
                if !pkt.ack() {
                    eprintln!("Don't know how to handle packet without ACK bit");
                    return;
                }

                if pkt.rst() {
                    self.set_state(TcpState::Closed);

                    return;
                }

                if pkt.acknowledgment_number() != self.send_next {
                    let mut header = self.header.clone();
                    header.syn = false;
                    header.ack = false;
                    header.rst = true;
                    header.sequence_number = pkt.acknowledgment_number();

                    self.set_state(TcpState::CloseWait);
                    self.transmit_payload(header, &[]).unwrap();

                    return;
                }

                if pkt.syn() {
                    self.recv_next = pkt.sequence_number() + 1;
                    self.send_unack = pkt.acknowledgment_number();

                    self.header.sequence_number = self.send_next;
                    self.header.acknowledgment_number = self.recv_next;
                    self.header.syn = false;
                    self.header.ack = true;

                    self.header.window_size = pkt.window_size();
                    self.window.reserve_exact(self.header.window_size as usize);
                    self.window.resize(self.header.window_size as usize, 0);

                    self.set_state(TcpState::Established);
                    self.transmit_payload(self.header.clone(), &[]).unwrap();
                }
            }
            TcpState::Established => {
                let recv_seq_with_len = self.recv_next + self.header.window_size as u32;
                if pkt.sequence_number() < self.recv_next
                    || pkt.sequence_number() >= recv_seq_with_len
                {
                    if pkt.payload().len() == 0
                        || pkt.sequence_number() + pkt.payload().len() as u32 - 1
                            >= recv_seq_with_len
                    {
                        let mut header = self.header.clone();
                        header.sequence_number = self.send_next;
                        header.acknowledgment_number = self.recv_next;
                        header.ack = true;
                        self.transmit_payload(header, &[]).unwrap();
                        return;
                    }
                }

                if pkt.rst() {
                    self.set_state(TcpState::Closed);
                    return;
                }

                if pkt.syn() || !pkt.ack() {
                    eprintln!("Don't know how to handle packet with SYN bit / no ACK bit");
                    return;
                }

                if pkt.acknowledgment_number() <= self.send_unack
                    || pkt.acknowledgment_number() > self.send_next
                {
                    eprintln!("invalid acknowledgement number received");
                    return;
                }

                self.send_unack = pkt.acknowledgment_number();
            }
            TcpState::Closed => {
                if !pkt.rst() {
                    let mut header = self.header.clone();
                    header.rst = true;
                    if !pkt.ack() {
                        header.sequence_number = 0;
                        header.acknowledgment_number =
                            pkt.sequence_number() + pkt.payload().len() as u32;
                        header.ack = true;
                    } else {
                        header.sequence_number = pkt.acknowledgment_number();
                    }

                    self.transmit_payload(header, &[]).unwrap();
                }
            }
            _ => panic!("unknown state"),
        };
    }

    pub fn write(&mut self, payload: &[u8]) {
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

        self.transmit_payload(self.header.clone(), &payload[0..available_capacity])
            .unwrap();
        self.header.psh = false;
    }

    fn transmit_payload(
        &self,
        header: etherparse::TcpHeader,
        payload: &[u8],
    ) -> Result<(), mpsc::SendError<Vec<u8>>> {
        let tcp = etherparse::PacketBuilder::ipv4(self.source_ip, self.destination_ip, 64)
            .tcp_header(header);
        let mut result = Vec::with_capacity(tcp.size(0));
        tcp.write(&mut result, payload).unwrap();
        self.tx.send(result)
    }
}
