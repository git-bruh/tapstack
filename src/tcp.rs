use std::{
    collections::BTreeMap,
    net::SocketAddrV4,
    sync::{mpsc, Arc, Condvar, Mutex},
    io::{Read, Write},
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
    send_window: Vec<u8>,
    recv_window: Vec<u8>,
    srtt: f64,
    rttvar: f64,
    rto: f64,
    state: TcpState,
    state_condvar: Arc<Condvar>,
    tx: mpsc::Sender<Vec<u8>>,
    timers: BTreeMap<u32, std::time::Instant>,
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
}

impl Write for TcpSocketWrapper {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let mut n = 0;
        let mut socket = self.socket.lock().unwrap();

        loop {
            socket.error_for_state_write()?;
            n += socket.write(&buf[n..]);
            if n == buf.len() {
                return Ok(n);
            }

            socket = self.state_condvar.wait(socket).unwrap();
        }
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl Read for TcpSocketWrapper {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let mut socket = self.socket.lock().unwrap();

        loop {
            socket.error_for_state_read()?;
            let size = socket.read(buf);
            if size > 0 {
                return Ok(size);
            }

            socket = self.state_condvar.wait(socket).unwrap();
        }
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
            srtt: 0.0,
            rttvar: 0.0,
            rto: 0.0,
            send_window: Vec::new(),
            recv_window: Vec::new(),
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
            timers: BTreeMap::new(),
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

    fn error_for_state_read(&self) -> Result<(), std::io::Error> {
        match self.state {
            TcpState::Established => Ok(()),
            _ => Err(std::io::Error::new(std::io::ErrorKind::ConnectionAborted, "can't read")),
        }
    }

    fn error_for_state_write(&self) -> Result<(), std::io::Error> {
        match self.state {
            TcpState::Established => Ok(()),
            _ => Err(std::io::Error::new(std::io::ErrorKind::ConnectionAborted, "can't write")),
        }
    }

    // RFC 6298
    fn on_rtt_measurement(&mut self, r: std::time::Duration) {
        if self.srtt == 0.0 {
            self.srtt = r.as_secs_f64();
            self.rttvar = self.srtt / 2.0;
        } else {
            self.rttvar = (0.75 * self.rttvar) + (0.25 * (self.srtt - r.as_secs_f64()).abs());
            self.srtt = (0.875 * self.srtt) + (0.125 * r.as_secs_f64());
        }

        self.rto = (self.srtt + (4.0 * self.rttvar).max(0.01)).max(1.0);
    }

    pub fn tick(&mut self) {
    }

    pub fn on_packet(&mut self, pkt: etherparse::TcpSlice) {
        eprintln!("SND.UNA: {}, SND.NXT: {} RCV.NXT: {}", self.send_unack, self.send_next, self.recv_next);
        eprintln!("{:?}", pkt);

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
                    self.recv_next = pkt.sequence_number().wrapping_add(1);
                    self.send_unack = pkt.acknowledgment_number();

                    self.header.sequence_number = self.send_next;
                    self.header.acknowledgment_number = self.recv_next;
                    self.header.syn = false;
                    self.header.ack = true;

                    self.header.window_size = pkt.window_size();
                    self.send_window.reserve_exact(self.header.window_size as usize);
                    self.send_window.resize(self.header.window_size as usize, 0);

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

                if pkt.acknowledgment_number() > self.send_unack && pkt.acknowledgment_number() <= self.send_next {
                    self.send_unack = pkt.acknowledgment_number();
                }

                // TODO update SND.WND

                // TODO delayed ACK
                if !pkt.payload().is_empty() {
                    self.recv_window.extend_from_slice(pkt.payload());
                    self.recv_next = self.recv_next.wrapping_add(pkt.payload().len() as u32);
                    let mut header = self.header.clone();
                    header.sequence_number = self.send_next;
                    header.acknowledgment_number = self.recv_next;
                    self.transmit_payload(header, &[]).unwrap();
                }

                self.state_condvar.notify_all();
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

    pub fn read(&mut self, buf: &mut [u8]) -> usize {
        if self.recv_window.is_empty() {
            0
        } else {
            let drained = self.recv_window.drain(0..buf.len().min(self.recv_window.len()));
            buf[0..drained.len()].copy_from_slice(drained.as_slice());
            drained.len()
        }
    }

    pub fn write(&mut self, payload: &[u8]) -> usize {
        // window size = 2
        // SND.UNA = 2
        // SND.NXT = 4
        //  1    2    3    4
        // ----|----|----|----|
        let len = self.send_window.len();
        let begin = self.send_unack as usize % len;
        let end = self.send_next as usize % len;

        let available_capacity = if begin <= end {
            (len - (end - begin)).min(payload.len())
        } else {
            begin - end
        };

        if available_capacity > 0 {
            for idx in 0..available_capacity {
                self.send_window[(end + idx) % len] = payload[idx];
            }

            self.timers.insert(self.send_next, std::time::Instant::now());

            self.header.sequence_number = self.send_next;
            let mut header = self.header.clone();
            header.psh = true;
            self.send_next = self.send_next.wrapping_add(available_capacity as u32);

            self.transmit_payload(header, &payload[0..available_capacity])
                .unwrap();
        }

        available_capacity
    }

    fn transmit_payload(
        &self,
        header: etherparse::TcpHeader,
        payload: &[u8],
    ) -> Result<(), mpsc::SendError<Vec<u8>>> {
        eprintln!("SENT {:?}", header);
        let tcp = etherparse::PacketBuilder::ipv4(self.source_ip, self.destination_ip, 64)
            .tcp_header(header);
        let mut result = Vec::with_capacity(tcp.size(0));
        tcp.write(&mut result, payload).unwrap();
        self.tx.send(result)
    }
}
