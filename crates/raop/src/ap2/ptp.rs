//! gPTP wire messages for the AirPlay 2 buffered-audio clock.
//!
//! Apple receivers use majorSdoId 1 and unicast PTPv2 messages on UDP
//! 319/320. These constructors are independent of socket and clock lifetime.

use std::collections::BTreeMap;
use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock, Weak};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tracing::debug;

pub const EVENT_PORT: u16 = 319;
pub const GENERAL_PORT: u16 = 320;
const HEADER_LEN: usize = 34;
const UNICAST: u16 = 0x0400;
const TWO_STEP: u16 = 0x0200;
const PTP_TIMESCALE: u16 = 0x0008;

fn header(
    kind: u8,
    length: usize,
    flags: u16,
    clock_id: u64,
    sequence: u16,
    control: u8,
    interval: i8,
) -> [u8; HEADER_LEN] {
    let mut out = [0u8; HEADER_LEN];
    out[0] = 0x10 | kind; // majorSdoId 1, message type in low nibble
    out[1] = 2; // PTPv2
    out[2..4].copy_from_slice(&(length as u16).to_be_bytes());
    out[6..8].copy_from_slice(&flags.to_be_bytes());
    out[20..28].copy_from_slice(&clock_id.to_be_bytes());
    out[28..30].copy_from_slice(&0x8005u16.to_be_bytes());
    out[30..32].copy_from_slice(&sequence.to_be_bytes());
    out[32] = control;
    out[33] = interval as u8;
    out
}

fn timestamp(out: &mut [u8], unix_ns: u64) {
    let seconds = unix_ns / 1_000_000_000;
    out[..6].copy_from_slice(&seconds.to_be_bytes()[2..]);
    out[6..10].copy_from_slice(&((unix_ns % 1_000_000_000) as u32).to_be_bytes());
}

pub fn announce(clock_id: u64, sequence: u16) -> [u8; 76] {
    let mut out = [0u8; 76];
    out[..HEADER_LEN].copy_from_slice(&header(
        0x0b,
        76,
        UNICAST | PTP_TIMESCALE,
        clock_id,
        sequence,
        0,
        0,
    ));
    let body = &mut out[HEADER_LEN..];
    body[13] = 128; // priority1
    body[14] = 6; // clock class
    body[15] = 0x21; // accuracy
    body[16..18].copy_from_slice(&0x436au16.to_be_bytes());
    body[18] = 128; // priority2
    body[19..27].copy_from_slice(&clock_id.to_be_bytes());
    body[29] = 0x20; // GPS time source
    body[30..34].copy_from_slice(&[0, 8, 0, 8]); // path trace TLV
    body[34..42].copy_from_slice(&clock_id.to_be_bytes());
    out
}

pub fn sync(clock_id: u64, sequence: u16) -> [u8; 44] {
    let mut out = [0u8; 44];
    out[..HEADER_LEN].copy_from_slice(&header(
        0,
        44,
        UNICAST | TWO_STEP | PTP_TIMESCALE,
        clock_id,
        sequence,
        0,
        -3,
    ));
    out
}

pub fn follow_up(clock_id: u64, sequence: u16, sent_at_ns: u64) -> [u8; 96] {
    let mut out = [0u8; 96];
    out[..HEADER_LEN].copy_from_slice(&header(
        8,
        96,
        UNICAST | PTP_TIMESCALE,
        clock_id,
        sequence,
        0,
        -3,
    ));
    timestamp(&mut out[34..44], sent_at_ns);
    out[44..54].copy_from_slice(&[0, 3, 0, 28, 0, 0x80, 0xc2, 0, 0, 1]);
    out[76..86].copy_from_slice(&[0, 3, 0, 16, 0, 0x0d, 0x93, 0, 0, 4]);
    out[86..94].copy_from_slice(&clock_id.to_be_bytes());
    out
}

/// Reply to a receiver's Delay_Req. Returns none for a malformed request.
pub fn delay_response(clock_id: u64, request: &[u8], received_at_ns: u64) -> Option<[u8; 54]> {
    if request.len() < 44 || request[0] != 0x11 || request[1] & 0x0f != 2 {
        return None;
    }
    let sequence = u16::from_be_bytes([request[30], request[31]]);
    let mut out = [0u8; 54];
    out[..HEADER_LEN].copy_from_slice(&header(
        9,
        54,
        UNICAST | TWO_STEP | PTP_TIMESCALE,
        clock_id,
        sequence,
        0,
        -3,
    ));
    timestamp(&mut out[34..44], received_at_ns);
    out[44..54].copy_from_slice(&request[20..30]);
    Some(out)
}

fn pdelay_responses(
    clock_id: u64,
    request: &[u8],
    received_at_ns: u64,
    sent_at_ns: u64,
) -> Option<([u8; 54], [u8; 54])> {
    if request.len() < 44 || request[0] != 0x12 || request[1] & 0x0f != 2 {
        return None;
    }
    let seq = u16::from_be_bytes([request[30], request[31]]);
    let mut response = [0u8; 54];
    response[..34].copy_from_slice(&header(
        3,
        54,
        UNICAST | TWO_STEP | PTP_TIMESCALE,
        clock_id,
        seq,
        0,
        -3,
    ));
    timestamp(&mut response[34..44], received_at_ns);
    response[44..54].copy_from_slice(&request[20..30]);
    let mut follow = [0u8; 54];
    follow[..34].copy_from_slice(&header(
        0x0a,
        54,
        UNICAST | PTP_TIMESCALE,
        clock_id,
        seq,
        0,
        -3,
    ));
    timestamp(&mut follow[34..44], sent_at_ns);
    follow[44..54].copy_from_slice(&request[20..30]);
    Some((response, follow))
}

fn signaling(clock_id: u64, sequence: u16) -> [u8; 106] {
    let mut out = [0u8; 106];
    out[..34].copy_from_slice(&header(
        0x0c,
        106,
        UNICAST | PTP_TIMESCALE,
        clock_id,
        sequence,
        5,
        -128,
    ));
    out[44..58].copy_from_slice(&[0, 3, 0, 22, 0, 0x0d, 0x93, 0, 0, 1, 0, 0, 3, 1]);
    out[70..84].copy_from_slice(&[0, 3, 0, 32, 0, 0x0d, 0x93, 0, 0, 5, 0, 0, 3, 1]);
    out
}

fn signaling_grants(clock_id: u64, request: &[u8]) -> Option<Vec<u8>> {
    if request.len() < 54 || request[0] != 0x1c || request[1] & 0x0f != 2 {
        return None;
    }
    let mut grants = Vec::new();
    let mut offset = 44;
    while offset + 4 <= request.len() && grants.len() < 8 * 12 {
        let kind = u16::from_be_bytes([request[offset], request[offset + 1]]);
        let len = u16::from_be_bytes([request[offset + 2], request[offset + 3]]) as usize;
        if offset + 4 + len > request.len() {
            break;
        }
        if kind == 4 && len >= 6 {
            let value = &request[offset + 4..offset + 10];
            grants.extend_from_slice(&[0, 5, 0, 8, value[0], value[1]]);
            let duration = if value[2..6] == [0; 4] {
                300u32.to_be_bytes()
            } else {
                [value[2], value[3], value[4], value[5]]
            };
            grants.extend_from_slice(&duration);
            grants.extend_from_slice(&[0, 1]); // renewal invited
        }
        offset += 4 + len;
    }
    if grants.is_empty() {
        return None;
    }
    let sequence = u16::from_be_bytes([request[30], request[31]]);
    let reply_len = 44 + grants.len();
    let mut reply = vec![0u8; reply_len];
    reply[..34].copy_from_slice(&header(
        0x0c, reply_len, UNICAST, clock_id, sequence, 5, 0x7f,
    ));
    reply[34..44].copy_from_slice(&request[20..30]);
    reply[44..].copy_from_slice(&grants);
    Some(reply)
}

fn now_ns() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos() as u64
}

struct State {
    peers: Mutex<BTreeMap<Ipv4Addr, usize>>,
    peer_sync: Mutex<BTreeMap<Ipv4Addr, PeerSync>>,
    stop: AtomicBool,
}

#[derive(Clone, Copy, Default)]
struct PeerSync {
    clock_id: u64,
    announced_clock_id: u64,
    sequence: u16,
    received_at_ns: u64,
    offset_ns: i64,
    ready: bool,
}

/// A process-wide PTP grandmaster shared by all buffered speaker sessions.
/// It starts only when an AAC session asks for it and stops with the last lease.
pub struct PtpClock {
    clock_id: u64,
    state: Arc<State>,
    worker: Mutex<Option<JoinHandle<()>>>,
}

pub struct PtpPeerLease {
    clock: Arc<PtpClock>,
    peer: Ipv4Addr,
}

impl PtpClock {
    pub fn shared() -> io::Result<Arc<Self>> {
        static SHARED: OnceLock<Mutex<Weak<PtpClock>>> = OnceLock::new();
        let slot = SHARED.get_or_init(|| Mutex::new(Weak::new()));
        let mut weak = slot.lock().unwrap();
        if let Some(clock) = weak.upgrade() {
            return Ok(clock);
        }
        let clock = Self::start()?;
        *weak = Arc::downgrade(&clock);
        Ok(clock)
    }

    fn start() -> io::Result<Arc<Self>> {
        let event = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, EVENT_PORT))?;
        let general = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, GENERAL_PORT))?;
        event.set_read_timeout(Some(Duration::from_millis(20)))?;
        general.set_nonblocking(true)?;
        let clock_id: u64 = rand::random();
        let state = Arc::new(State {
            peers: Mutex::new(BTreeMap::new()),
            peer_sync: Mutex::new(BTreeMap::new()),
            stop: AtomicBool::new(false),
        });
        let worker_state = state.clone();
        let worker = thread::Builder::new()
            .name("ap2-ptp".into())
            .spawn(move || run_clock(clock_id, worker_state, event, general))?;
        Ok(Arc::new(Self {
            clock_id,
            state,
            worker: Mutex::new(Some(worker)),
        }))
    }

    pub fn clock_id(&self) -> u64 {
        self.clock_id
    }

    pub fn now_ns(&self) -> u64 {
        now_ns()
    }

    /// The receiver may keep its own PTP clock as grandmaster. Once we have
    /// observed a Sync/Follow_Up pair, anchor to that clock instead of ours.
    pub fn timeline_for(&self, peer: Ipv4Addr) -> (u64, u64) {
        let sync = self.state.peer_sync.lock().unwrap().get(&peer).copied();
        match sync.filter(|sync| sync.ready) {
            Some(sync) => (
                sync.clock_id,
                now_ns().saturating_add_signed(sync.offset_ns),
            ),
            None => (self.clock_id, now_ns()),
        }
    }

    pub fn advertised_clock_for(&self, peer: Ipv4Addr) -> u64 {
        self.state
            .peer_sync
            .lock()
            .unwrap()
            .get(&peer)
            .map(|sync| sync.announced_clock_id)
            .filter(|id| *id != 0)
            .unwrap_or(self.clock_id)
    }

    pub fn add_peer(self: &Arc<Self>, peer: Ipv4Addr) -> PtpPeerLease {
        *self.state.peers.lock().unwrap().entry(peer).or_default() += 1;
        PtpPeerLease {
            clock: self.clone(),
            peer,
        }
    }
}

impl Drop for PtpPeerLease {
    fn drop(&mut self) {
        let mut peers = self.clock.state.peers.lock().unwrap();
        if let Some(count) = peers.get_mut(&self.peer) {
            *count -= 1;
            if *count == 0 {
                peers.remove(&self.peer);
                self.clock
                    .state
                    .peer_sync
                    .lock()
                    .unwrap()
                    .remove(&self.peer);
            }
        }
    }
}

impl Drop for PtpClock {
    fn drop(&mut self) {
        self.state.stop.store(true, Ordering::Relaxed);
        if let Some(worker) = self.worker.lock().unwrap().take() {
            let _ = worker.join();
        }
    }
}

fn send_to_peers(socket: &UdpSocket, port: u16, peers: &[Ipv4Addr], packet: &[u8]) {
    for &peer in peers {
        let _ = socket.send_to(packet, SocketAddr::new(IpAddr::V4(peer), port));
    }
}

fn handle_request(
    clock_id: u64,
    state: &State,
    event: &UdpSocket,
    general: &UdpSocket,
    request: &[u8],
    source: SocketAddr,
) {
    let IpAddr::V4(peer) = source.ip() else {
        return;
    };
    if !state.peers.lock().unwrap().contains_key(&peer) || request.len() < 34 {
        return;
    }
    let event_addr = SocketAddr::new(IpAddr::V4(peer), EVENT_PORT);
    let general_addr = SocketAddr::new(IpAddr::V4(peer), GENERAL_PORT);
    match request[0] & 0x0f {
        11 if request.len() >= 64 => {
            let mut syncs = state.peer_sync.lock().unwrap();
            let sync = syncs.entry(peer).or_default();
            sync.announced_clock_id = u64::from_be_bytes(request[53..61].try_into().unwrap());
        }
        0 if request.len() >= 44 => {
            let mut syncs = state.peer_sync.lock().unwrap();
            let sync = syncs.entry(peer).or_default();
            sync.clock_id = u64::from_be_bytes(request[20..28].try_into().unwrap());
            sync.sequence = u16::from_be_bytes([request[30], request[31]]);
            sync.received_at_ns = now_ns();
        }
        8 if request.len() >= 44 => {
            let mut syncs = state.peer_sync.lock().unwrap();
            let sync = syncs.entry(peer).or_default();
            let clock = u64::from_be_bytes(request[20..28].try_into().unwrap());
            let sequence = u16::from_be_bytes([request[30], request[31]]);
            if sync.clock_id == clock && sync.sequence == sequence {
                let seconds = request[34..40]
                    .iter()
                    .fold(0u64, |value, byte| value << 8 | *byte as u64);
                let nanos = u32::from_be_bytes(request[40..44].try_into().unwrap()) as u64;
                let origin = seconds.saturating_mul(1_000_000_000).saturating_add(nanos);
                let offset = origin as i128 - sync.received_at_ns as i128;
                if let Ok(offset) = i64::try_from(offset) {
                    sync.offset_ns = offset;
                    sync.ready = true;
                }
            }
        }
        1 => {
            if let Some(reply) = delay_response(clock_id, request, now_ns()) {
                let _ = general.send_to(&reply, general_addr);
            }
        }
        2 => {
            let received = now_ns();
            if let Some((response, follow)) =
                pdelay_responses(clock_id, request, received, now_ns())
            {
                let _ = event.send_to(&response, event_addr);
                let _ = general.send_to(&follow, general_addr);
            }
        }
        12 => {
            if let Some(reply) = signaling_grants(clock_id, request) {
                let _ = general.send_to(&reply, general_addr);
            }
        }
        _ => {}
    }
}

fn run_clock(clock_id: u64, state: Arc<State>, event: UdpSocket, general: UdpSocket) {
    let mut sync_seq = 0u16;
    let mut announce_seq = 0u16;
    let mut signaling_seq = 0u16;
    let mut next_sync = Instant::now();
    let mut next_announce = next_sync;
    let mut inbound = [0u8; 512];
    while !state.stop.load(Ordering::Relaxed) {
        if let Ok((len, source)) = event.recv_from(&mut inbound) {
            debug!(
                "PTP event RX kind={:x} len={len} from={source}",
                inbound[0] & 15
            );
            handle_request(clock_id, &state, &event, &general, &inbound[..len], source);
        }
        while let Ok((len, source)) = general.recv_from(&mut inbound) {
            debug!(
                "PTP general RX kind={:x} len={len} from={source}",
                inbound[0] & 15
            );
            handle_request(clock_id, &state, &event, &general, &inbound[..len], source);
        }
        let now = Instant::now();
        if now < next_sync && now < next_announce {
            continue;
        }
        let followed = state.peer_sync.lock().unwrap().clone();
        let peers: Vec<_> = state
            .peers
            .lock()
            .unwrap()
            .keys()
            .copied()
            .filter(|peer| {
                !followed
                    .get(peer)
                    .is_some_and(|sync| sync.announced_clock_id != 0)
            })
            .collect();
        if now >= next_announce {
            if !peers.is_empty() {
                send_to_peers(
                    &general,
                    GENERAL_PORT,
                    &peers,
                    &announce(clock_id, announce_seq),
                );
                send_to_peers(
                    &general,
                    GENERAL_PORT,
                    &peers,
                    &signaling(clock_id, signaling_seq),
                );
            }
            announce_seq = announce_seq.wrapping_add(1);
            signaling_seq = signaling_seq.wrapping_add(1);
            next_announce = now + Duration::from_secs(1);
        }
        if now >= next_sync {
            if !peers.is_empty() {
                send_to_peers(&event, EVENT_PORT, &peers, &sync(clock_id, sync_seq));
                send_to_peers(
                    &general,
                    GENERAL_PORT,
                    &peers,
                    &follow_up(clock_id, sync_seq, now_ns()),
                );
            }
            sync_seq = sync_seq.wrapping_add(1);
            next_sync = now + Duration::from_millis(125);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gptp_messages_carry_one_clock_and_valid_lengths() {
        let clock = 0x0123_4567_89ab_cdef;
        let ann = announce(clock, 7);
        let sync = sync(clock, 8);
        let follow = follow_up(clock, 8, 1_798_000_000_123_456_789);
        for (kind, packet) in [
            (0x1b, ann.as_slice()),
            (0x10, sync.as_slice()),
            (0x18, follow.as_slice()),
        ] {
            assert_eq!(packet[0], kind);
            assert_eq!(packet[1], 2);
            assert_eq!(
                u16::from_be_bytes([packet[2], packet[3]]) as usize,
                packet.len()
            );
            assert_eq!(&packet[20..28], &clock.to_be_bytes());
        }
        assert_eq!(&ann[68..76], &clock.to_be_bytes());
        assert_eq!(&follow[86..94], &clock.to_be_bytes());
        assert_eq!(&follow[34..40], &[0, 0, 0x6b, 0x2b, 0x4d, 0x80]);
    }

    #[test]
    fn delay_reply_echoes_request_identity_and_sequence() {
        let mut request = [0u8; 44];
        request[0] = 0x11;
        request[1] = 2;
        request[20..30].copy_from_slice(&[1, 2, 3, 4, 5, 6, 7, 8, 9, 10]);
        request[30..32].copy_from_slice(&0x1234u16.to_be_bytes());
        let reply = delay_response(0xaabb_ccdd, &request, 1_000_000_001).unwrap();
        assert_eq!(reply[0], 0x19);
        assert_eq!(&reply[30..32], &[0x12, 0x34]);
        assert_eq!(&reply[44..54], &request[20..30]);
        assert_eq!(&reply[34..44], &[0, 0, 0, 0, 0, 1, 0, 0, 0, 1]);
        assert!(delay_response(0, &request[..20], 0).is_none());
    }
}
