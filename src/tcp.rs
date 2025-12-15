use std::{
    collections::BTreeMap,
    io::{Read, Write},
    net::SocketAddrV4,
    sync::{mpsc, Arc, Condvar, Mutex},
};
use tracing::{debug, error, info, warn};

#[derive(Clone, Debug)]
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

impl std::fmt::Display for TcpState {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
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
    syn_seq: u32,
    fin_seq: Option<u32>,
    state: TcpState,
    state_condvar: Arc<Condvar>,
    tx: mpsc::Sender<Vec<u8>>,
    partial_segments: BTreeMap<u32, Vec<u8>>,
    timers: BTreeMap<u32, (bool, std::time::Instant)>,
    time_wait_instant: Option<std::time::Instant>,
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

    pub fn close(&self) {
        self.socket.lock().unwrap().close();
    }
}

impl Write for TcpSocketWrapper {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let mut n = 0;
        let mut socket = self.socket.lock().unwrap();

        loop {
            n += socket.write(&buf[n..])?;
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
            let size = socket.read(buf)?;
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
            rto: 1.0,
            syn_seq: sequence_number,
            fin_seq: None,
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
            partial_segments: BTreeMap::new(),
            timers: BTreeMap::new(),
            time_wait_instant: None,
        }
    }

    pub fn state_condvar(&self) -> Arc<Condvar> {
        Arc::clone(&self.state_condvar)
    }

    pub fn connect(&mut self) {
        self.header.syn = true;
        self.state = TcpState::SynSent;
        self.timers
            .insert(self.syn_seq, (false, std::time::Instant::now()));
        self.transmit_payload(self.header.clone(), &[]).unwrap();
    }

    fn get_span(&self, rseq: Option<u32>) -> tracing::span::Span {
        tracing::span!(
            tracing::Level::TRACE,
            "socket",
            state = self.state.to_string(),
            rto = self.rto,
            seq = self.header.sequence_number,
            rseq,
            snd.una = self.send_unack,
            snd.nxt = self.send_next,
            rcv.nxt = self.recv_next,
            fin_seq = self.fin_seq
        )
    }

    fn set_state(&mut self, state: TcpState) {
        info!("transitioned to {state:?}");

        match state {
            TcpState::TimeWait => self.time_wait_instant = Some(std::time::Instant::now()),
            _ => {}
        };

        self.state = state;
        self.state_condvar.notify_all();
    }

    // RFC 6298
    fn on_rtt_measurement(&mut self, ack: u32) {
        let r = if let Some((retransmitted, instant)) = self.timers.get(&ack) {
            if *retransmitted {
                debug!(ack, "segment was retransmitted, not measuring RTT");
                return;
            }

            std::time::Instant::now().duration_since(*instant)
        } else {
            error!(ack, "segment did not exist in retransmission queue");
            return;
        };

        // reset the measurements if RTO was multiplied for retransmission
        if self.srtt == 0.0 || self.rto > (self.srtt + (4.0 * self.rttvar).max(0.01)).max(1.0) {
            self.srtt = r.as_secs_f64();
            self.rttvar = self.srtt / 2.0;
        } else {
            self.rttvar = (0.75 * self.rttvar) + (0.25 * (self.srtt - r.as_secs_f64()).abs());
            self.srtt = (0.875 * self.srtt) + (0.125 * r.as_secs_f64());
        }

        self.rto = (self.srtt + (4.0 * self.rttvar).max(0.01)).max(1.0);
    }

    /// returns whether the socket can be cleaned up
    pub fn tick(&mut self) -> bool {
        let span = self.get_span(None);
        let _enter = span.enter();

        self.timers.retain(|seq, _| *seq >= self.send_unack);
        if let Some(mut entry) = self.timers.first_entry() {
            let (seq, (retransmitted, instant)) = (entry.key().clone(), entry.get_mut());
            if std::time::Instant::now()
                .duration_since(*instant)
                .as_secs_f64()
                >= self.rto
            {
                debug!(
                    seq,
                    retransmitted = *retransmitted,
                    "retransmitting segment"
                );

                *instant = std::time::Instant::now();
                *retransmitted = true;
                self.rto = (self.rto * 2.0).min(60.0);

                if seq == self.syn_seq {
                    self.transmit_payload(self.header.clone(), &[]).unwrap();
                    return false;
                }

                let mut header = self.header.clone();
                header.sequence_number = seq;

                if let Some(fin_seq) = self.fin_seq {
                    if seq == fin_seq {
                        self.transmit_payload(self.header.clone(), &[]).unwrap();
                        return false;
                    }
                }

                let len = self.send_window.len();
                let begin = seq as usize % len;
                let end = self.send_next as usize % len;

                header.psh = true;

                // TODO respect MSS
                // TODO either re-transmit all segments in the order they were created
                // or remove redundant timers here as we send a larger payload
                if begin <= end {
                    self.transmit_payload(header, &self.send_window[begin..end])
                        .unwrap()
                } else {
                    let mut payload = Vec::with_capacity(self.send_window.len() - (begin - end));
                    payload.extend_from_slice(&self.send_window[begin..self.send_window.len()]);
                    payload.extend_from_slice(&self.send_window[0..end]);
                    self.transmit_payload(header, &payload).unwrap();
                }
            }
        } else if let TcpState::FinWait1 = self.state {
            // all queues are clear, we can close
            if self.fin_seq.is_none() {
                info!("all pending segments retransmitted, sending FIN");

                self.header.fin = true;
                self.header.sequence_number = self.send_next;
                self.fin_seq = Some(self.header.sequence_number);
                self.transmit_payload(self.header.clone(), &[]).unwrap();
            }
        } else if let Some(time_wait_instant) = self.time_wait_instant {
            // we take MSL as 30s
            if std::time::Instant::now()
                .duration_since(time_wait_instant)
                .as_secs()
                > 60
            {
                info!("reached 2MSL, cleaning up");
                return true;
            }
        }

        return false;
    }

    pub fn on_packet(&mut self, pkt: etherparse::TcpSlice) {
        let span = self.get_span(Some(pkt.sequence_number()));
        let _enter = span.enter();

        info!("received packet {:?}", pkt);

        match self.state {
            TcpState::Listen | TcpState::SynReceived => todo!("listen"),
            TcpState::SynSent => {
                if !pkt.ack() {
                    error!("don't know how to handle packet without ACK bit");
                    return;
                }

                if pkt.rst() {
                    info!("received RST, closing");
                    self.set_state(TcpState::Closed);

                    return;
                }

                if pkt.acknowledgment_number() != self.send_next {
                    error!("invalid ACK, sending RST");

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
                    info!("received SYN-ACK");

                    self.recv_next = pkt.sequence_number().wrapping_add(1);
                    self.send_unack = pkt.acknowledgment_number();

                    self.header.sequence_number = self.send_next;
                    self.header.acknowledgment_number = self.recv_next;
                    self.header.syn = false;
                    self.header.ack = true;

                    self.header.window_size = pkt.window_size();
                    self.send_window
                        .reserve_exact(self.header.window_size as usize);
                    self.send_window.resize(self.header.window_size as usize, 0);

                    self.on_rtt_measurement(pkt.acknowledgment_number());

                    self.set_state(TcpState::Established);
                    self.transmit_payload(self.header.clone(), &[]).unwrap();
                }
            }
            TcpState::Established
            | TcpState::FinWait1
            | TcpState::FinWait2
            | TcpState::CloseWait
            | TcpState::Closing
            | TcpState::LastAck
            | TcpState::TimeWait => {
                let recv_seq_with_len = self.recv_next.wrapping_add(self.header.window_size as u32);
                let seq_with_len = pkt
                    .sequence_number()
                    .wrapping_add(pkt.payload().len().max(1) as u32 - 1);
                if !((self.recv_next <= pkt.sequence_number()
                    && pkt.sequence_number() < recv_seq_with_len)
                    || (self.recv_next <= seq_with_len && seq_with_len < recv_seq_with_len))
                {
                    if !pkt.rst() {
                        warn!("received unacceptable segment, sending duplicate ACK");

                        let mut header = self.header.clone();
                        header.sequence_number = self.send_next;
                        header.acknowledgment_number = self.recv_next;
                        header.ack = true;
                        self.transmit_payload(header, &[]).unwrap();
                    } else {
                        warn!("received unacceptable segment with RST, dropping");
                    }

                    return;
                }

                if pkt.rst() {
                    if pkt.sequence_number() == self.recv_next {
                        debug!("received RST, closing");
                        self.set_state(TcpState::Closed);
                    } else {
                        warn!("received RST with wrong seq, sending challenge ACK");
                        // challenge ACK (RFC 5961)
                        let mut header = self.header.clone();
                        header.sequence_number = self.send_next;
                        header.acknowledgment_number = self.recv_next;
                        header.ack = true;
                        self.transmit_payload(header, &[]).unwrap();
                    }

                    return;
                }

                if pkt.syn() {
                    todo!("can't handle SYN packets in state {:?}", self.state);
                }

                if !pkt.ack() {
                    warn!("received segment without ACK, dropping");
                    return;
                }

                if self.send_unack < pkt.acknowledgment_number()
                    && pkt.acknowledgment_number() <= self.send_next
                {
                    self.on_rtt_measurement(pkt.acknowledgment_number());
                    debug!("advancing SND.UNA");
                    self.send_unack = pkt.acknowledgment_number();
                }

                let fin_acked = if let Some(seq) = self.fin_seq {
                    self.send_unack == seq
                } else {
                    false
                };

                if fin_acked {
                    debug!("FIN is acked");

                    match self.state {
                        TcpState::FinWait1 => self.set_state(TcpState::FinWait2),
                        TcpState::FinWait2 => {}
                        TcpState::Closing => self.set_state(TcpState::TimeWait),
                        TcpState::LastAck => {
                            self.set_state(TcpState::Closed);
                            return;
                        }
                        TcpState::TimeWait => {
                            self.set_state(TcpState::TimeWait);
                            let mut header = self.header.clone();
                            header.acknowledgment_number = pkt.sequence_number();
                            header.ack = true;
                            self.transmit_payload(header, &[]).unwrap();
                        }
                        _ => {}
                    }
                }

                // TODO update SND.WND
                if !pkt.payload().is_empty() {
                    if let TcpState::Established | TcpState::FinWait1 | TcpState::FinWait2 =
                        self.state
                    {
                        if pkt.sequence_number() == self.recv_next {
                            debug!("received in-order segment");

                            self.recv_window.extend_from_slice(pkt.payload());
                            self.recv_next =
                                self.recv_next.wrapping_add(pkt.payload().len() as u32);

                            while let Some(pkt) = self.partial_segments.get(&self.recv_next) {
                                self.recv_window.extend_from_slice(&pkt);
                                self.recv_next = self.recv_next.wrapping_add(pkt.len() as u32);
                            }
                            self.partial_segments.retain(|k, _| *k > self.recv_next);
                        } else {
                            debug!("received out-of-order segment");

                            // out-of-order segment, send an ACK for our current state (RFC5581)
                            self.partial_segments
                                .insert(pkt.sequence_number(), pkt.payload().to_vec());
                        }

                        // TODO delayed ACK
                        let mut header = self.header.clone();
                        header.sequence_number = self.send_next;
                        header.acknowledgment_number = self.recv_next;
                        header.ack = true;
                        self.transmit_payload(header, &[]).unwrap();
                    }
                }

                if pkt.fin() && pkt.sequence_number() == self.recv_next {
                    debug!("received FIN, ACKing");

                    // TODO if remote FIN is re-transmitted, this will never run?
                    self.recv_next += 1;
                    let mut header = self.header.clone();
                    header.sequence_number = self.send_next;
                    header.acknowledgment_number = self.recv_next;
                    header.ack = true;
                    self.transmit_payload(header, &[]).unwrap();

                    match self.state {
                        TcpState::Established => self.set_state(TcpState::CloseWait),
                        TcpState::FinWait1 => {
                            if fin_acked {
                                self.set_state(TcpState::TimeWait)
                            }
                        }
                        TcpState::FinWait2 => self.set_state(TcpState::TimeWait),
                        TcpState::TimeWait => self.set_state(TcpState::TimeWait),
                        _ => {}
                    }
                }

                self.state_condvar.notify_all();
            }
            TcpState::Closed => {
                if !pkt.rst() {
                    warn!("received non-RST packet, sending RST");

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
                } else {
                    info!("received RST packet, ignoring");
                }
            }
        };
    }

    pub fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        match &self.state {
            TcpState::Established
            | TcpState::FinWait1
            | TcpState::FinWait2
            | TcpState::CloseWait => {}
            state => {
                if self.recv_window.is_empty() {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::NotConnected,
                        format!("can't read in state {state:?}"),
                    ));
                }
            }
        }

        Ok(if self.recv_window.is_empty() {
            0
        } else {
            let drained = self
                .recv_window
                .drain(0..buf.len().min(self.recv_window.len()));
            buf[0..drained.len()].copy_from_slice(drained.as_slice());
            drained.len()
        })
    }

    pub fn write(&mut self, payload: &[u8]) -> std::io::Result<usize> {
        match &self.state {
            TcpState::Established => {}
            state => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::NotConnected,
                    format!("can't write in state {state:?}"),
                ))
            }
        }

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

            self.timers
                .insert(self.send_next, (false, std::time::Instant::now()));

            self.header.sequence_number = self.send_next;
            let mut header = self.header.clone();
            header.psh = true;
            self.send_next = self.send_next.wrapping_add(available_capacity as u32);

            self.transmit_payload(header, &payload[0..available_capacity])
                .unwrap();
        }

        Ok(available_capacity)
    }

    pub fn close(&mut self) {
        let span = self.get_span(None);
        let _enter = span.enter();

        match self.state {
            TcpState::Closed => {}
            TcpState::SynSent => {
                // TODO delete TCB
            }
            TcpState::Established => {
                // TODO send FIN
                self.set_state(TcpState::FinWait1);
            }
            TcpState::CloseWait => {
                // TODO send FIN
                self.set_state(TcpState::LastAck);
            }
            _ => {}
        }
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
