//! pcap file reader: UDP payloads + relative timing, nothing else.
//!
//! What is kept per packet mirrors SIPp's `prepare_pcap.c`: the UDP
//! destination port (so multi-port captures such as RTP+RTCP replay to
//! `remote_port + offset`), the payload bytes verbatim (RTP headers are
//! never rewritten — every call replaying the same file emits the same SSRC
//! and sequence numbers, exactly like SIPp), and the capture timestamp,
//! turned into a monotone offset from the first kept packet.
//!
//! [`parse`] takes either capture format: the classic one this module reads,
//! and pcapng (which `tcpdump` and Wireshark write by default), handed to
//! [`crate::pcapng`] — a sipr addition, since SIPp's libpcap reader rejects
//! pcapng outright.
//!
//! Supported: microsecond and nanosecond magic in either byte order; link
//! types Ethernet (with one 802.1Q tag), raw IP, Linux cooked v1/v2, and
//! BSD loopback/null; IPv4 (any IHL, unfragmented) and IPv6 (no extension
//! headers). Non-UDP and non-IP packets are skipped and counted rather than
//! aborting the load — SIPp aborts on an unknown EtherType, which makes an
//! incidental ARP frame in a capture fatal; skipping is friendlier and
//! changes nothing about the replayed stream.

use std::time::Duration;

/// One replayable datagram from the capture.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Frame {
    /// Time since the first kept packet; never decreases.
    pub offset: Duration,
    /// UDP destination port in the capture (see [`PcapStream::base_port`]).
    pub dst_port: u16,
    /// UDP payload, verbatim.
    pub payload: Vec<u8>,
}

/// A parsed capture, ready to replay. Shared read-only between calls.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PcapStream {
    /// Kept packets in capture order.
    pub frames: Vec<Frame>,
    /// Lowest destination port seen; a frame's `dst_port - base_port` is the
    /// offset added to the remote (and local) port when replaying, so a
    /// capture with RTP on `P` and RTCP on `P+1` replays to `remote+0` and
    /// `remote+1` — SIPp's `port_diff` model.
    pub base_port: u16,
    /// Packets skipped because they were not UDP over IPv4/IPv6.
    pub skipped: usize,
    /// The file's link-layer type.
    pub link_type: u32,
}

impl PcapStream {
    /// Number of replayable frames.
    #[must_use]
    pub fn len(&self) -> usize {
        self.frames.len()
    }

    /// True when nothing would be sent.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.frames.is_empty()
    }

    /// Offset of the last frame (the replay's nominal duration).
    #[must_use]
    pub fn duration(&self) -> Duration {
        self.frames.last().map_or(Duration::ZERO, |f| f.offset)
    }

    /// Distinct `dst_port - base_port` offsets, ascending. One socket is
    /// bound per offset when replaying.
    #[must_use]
    pub fn port_offsets(&self) -> Vec<u16> {
        let mut offsets: Vec<u16> = self
            .frames
            .iter()
            .map(|f| f.dst_port - self.base_port)
            .collect();
        offsets.sort_unstable();
        offsets.dedup();
        offsets
    }
}

/// Why a capture could not be loaded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PcapError {
    /// Shorter than a pcap global header.
    TooShort,
    /// Neither a classic pcap magic number nor a pcapng section header.
    BadMagic(u32),
    /// A pcapng block that is malformed or references an undeclared
    /// interface. `index` is the 0-based block number.
    BadBlock {
        /// 0-based block index in the file.
        index: usize,
        /// What was wrong with it.
        why: &'static str,
    },
    /// A link-layer type this reader does not decode.
    UnsupportedLinkType(u32),
    /// Record `index` has `caplen < len`: the capture was made with a snap
    /// length and the payload is incomplete. SIPp's own hint applies:
    /// recapture with `-s0`.
    TruncatedPacket {
        /// 0-based record index.
        index: usize,
    },
    /// The file ends in the middle of record `index`.
    TruncatedFile {
        /// 0-based record index.
        index: usize,
    },
}

impl std::fmt::Display for PcapError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TooShort => write!(f, "file is shorter than a pcap header"),
            Self::BadMagic(m) => {
                write!(f, "not a pcap or pcapng capture (leading bytes {m:#010x})")
            }
            Self::BadBlock { index, why } => {
                write!(f, "pcapng block {index}: {why}")
            }
            Self::UnsupportedLinkType(t) => write!(f, "unsupported link-layer type {t}"),
            Self::TruncatedPacket { index } => write!(
                f,
                "packet {index} is truncated (caplen < len) — recapture with -s0"
            ),
            Self::TruncatedFile { index } => {
                write!(f, "file ends inside packet {index}")
            }
        }
    }
}

impl std::error::Error for PcapError {}

const GLOBAL_HEADER_LEN: usize = 24;
const RECORD_HEADER_LEN: usize = 16;

// Link-layer types (LINKTYPE_* values as written in files).
const LINKTYPE_NULL: u32 = 0;
const LINKTYPE_ETHERNET: u32 = 1;
const LINKTYPE_RAW_LEGACY: u32 = 12;
const LINKTYPE_RAW: u32 = 101;
const LINKTYPE_LOOP: u32 = 108;
const LINKTYPE_LINUX_SLL: u32 = 113;
const LINKTYPE_LINUX_SLL2: u32 = 276;

const ETHERTYPE_IPV4: u16 = 0x0800;
const ETHERTYPE_IPV6: u16 = 0x86dd;
const ETHERTYPE_VLAN: u16 = 0x8100;
const IPPROTO_UDP: u8 = 17;

#[derive(Clone, Copy)]
struct Layout {
    big_endian: bool,
    nanos: bool,
}

impl Layout {
    fn from_magic(raw: [u8; 4]) -> Option<Self> {
        match u32::from_le_bytes(raw) {
            0xa1b2_c3d4 => Some(Self {
                big_endian: false,
                nanos: false,
            }),
            0xd4c3_b2a1 => Some(Self {
                big_endian: true,
                nanos: false,
            }),
            0xa1b2_3c4d => Some(Self {
                big_endian: false,
                nanos: true,
            }),
            0x4d3c_b2a1 => Some(Self {
                big_endian: true,
                nanos: true,
            }),
            _ => None,
        }
    }

    fn u32(self, b: &[u8]) -> u32 {
        let arr = [b[0], b[1], b[2], b[3]];
        if self.big_endian {
            u32::from_be_bytes(arr)
        } else {
            u32::from_le_bytes(arr)
        }
    }
}

/// Parse a classic pcap file held in memory.
///
/// # Errors
///
/// [`PcapError`] for a malformed or unsupported file. Packets that are not
/// UDP/IP are skipped (counted in [`PcapStream::skipped`]), never fatal.
pub fn parse(bytes: &[u8]) -> Result<PcapStream, PcapError> {
    if crate::pcapng::is_pcapng(bytes) {
        return crate::pcapng::parse(bytes);
    }
    if bytes.len() < GLOBAL_HEADER_LEN {
        return Err(PcapError::TooShort);
    }
    let magic = [bytes[0], bytes[1], bytes[2], bytes[3]];
    let layout =
        Layout::from_magic(magic).ok_or_else(|| PcapError::BadMagic(u32::from_le_bytes(magic)))?;
    let link_type = layout.u32(&bytes[20..24]);
    if !link_type_supported(link_type) {
        return Err(PcapError::UnsupportedLinkType(link_type));
    }

    let mut stream = PcapStream {
        link_type,
        ..Default::default()
    };
    let mut pos = GLOBAL_HEADER_LEN;
    let mut index = 0usize;
    let mut first_ts: Option<u128> = None;
    let mut last_offset = Duration::ZERO;
    while pos < bytes.len() {
        let Some(hdr) = bytes.get(pos..pos + RECORD_HEADER_LEN) else {
            return Err(PcapError::TruncatedFile { index });
        };
        let ts_sec = u128::from(layout.u32(&hdr[0..4]));
        let ts_frac = u128::from(layout.u32(&hdr[4..8]));
        let caplen = layout.u32(&hdr[8..12]) as usize;
        let origlen = layout.u32(&hdr[12..16]) as usize;
        pos += RECORD_HEADER_LEN;
        let Some(data) = bytes.get(pos..pos + caplen) else {
            return Err(PcapError::TruncatedFile { index });
        };
        pos += caplen;
        if caplen < origlen {
            return Err(PcapError::TruncatedPacket { index });
        }
        index += 1;
        let Some((dst_port, payload)) = udp_payload(link_type, data) else {
            stream.skipped += 1;
            continue;
        };
        let ts_nanos = ts_sec * 1_000_000_000
            + if layout.nanos {
                ts_frac
            } else {
                ts_frac * 1000
            };
        let t0 = *first_ts.get_or_insert(ts_nanos);
        // Non-increasing timestamps get no delay (SIPp: `nap = 0`), and the
        // offset never runs backwards.
        let nanos = ts_nanos.saturating_sub(t0);
        let offset =
            Duration::from_nanos(u64::try_from(nanos).unwrap_or(u64::MAX)).max(last_offset);
        last_offset = offset;
        stream.frames.push(Frame {
            offset,
            dst_port,
            payload: payload.to_vec(),
        });
    }
    stream.base_port = stream.frames.iter().map(|f| f.dst_port).min().unwrap_or(0);
    Ok(stream)
}

/// True for the link-layer types [`udp_payload`] can decode.
pub(crate) fn link_type_supported(link_type: u32) -> bool {
    matches!(
        link_type,
        LINKTYPE_NULL
            | LINKTYPE_ETHERNET
            | LINKTYPE_RAW_LEGACY
            | LINKTYPE_RAW
            | LINKTYPE_LOOP
            | LINKTYPE_LINUX_SLL
            | LINKTYPE_LINUX_SLL2
    )
}

/// Peel the link and IP layers off one captured frame; `None` when it is
/// not an unfragmented UDP/IP packet we can replay.
pub(crate) fn udp_payload(link_type: u32, data: &[u8]) -> Option<(u16, &[u8])> {
    let ip = match link_type {
        LINKTYPE_ETHERNET => {
            let ethertype = be16(data, 12)?;
            let (ethertype, ip_at) = if ethertype == ETHERTYPE_VLAN {
                (be16(data, 16)?, 18)
            } else {
                (ethertype, 14)
            };
            if ethertype != ETHERTYPE_IPV4 && ethertype != ETHERTYPE_IPV6 {
                return None;
            }
            data.get(ip_at..)?
        }
        LINKTYPE_LINUX_SLL => {
            let proto = be16(data, 14)?;
            if proto != ETHERTYPE_IPV4 && proto != ETHERTYPE_IPV6 {
                return None;
            }
            data.get(16..)?
        }
        LINKTYPE_LINUX_SLL2 => {
            let proto = be16(data, 0)?;
            if proto != ETHERTYPE_IPV4 && proto != ETHERTYPE_IPV6 {
                return None;
            }
            data.get(20..)?
        }
        // The 4-byte family word is host-order (NULL) or network-order
        // (LOOP) and its IPv6 value differs per OS; the IP version nibble
        // is the reliable discriminator, so just skip the word.
        LINKTYPE_NULL | LINKTYPE_LOOP => data.get(4..)?,
        // Raw IP: the packet starts at the IP header.
        _ => data,
    };
    let udp = match ip.first()? >> 4 {
        4 => ipv4_udp(ip)?,
        6 => ipv6_udp(ip)?,
        _ => return None,
    };
    // Trust the UDP length field, not the capture length: short Ethernet
    // frames carry trailing padding that must not become payload.
    let udp_len = usize::from(be16(udp, 4)?);
    if udp_len < 8 || udp_len > udp.len() {
        return None;
    }
    let dst_port = be16(udp, 2)?;
    Some((dst_port, &udp[8..udp_len]))
}

fn ipv4_udp(ip: &[u8]) -> Option<&[u8]> {
    let ihl = usize::from(ip.first()? & 0x0f) * 4;
    if ihl < 20 || ip.len() < ihl {
        return None;
    }
    if ip[9] != IPPROTO_UDP {
        return None;
    }
    // Fragmented datagrams cannot be replayed as a unit: MF bit or a
    // non-zero fragment offset.
    let frag = be16(ip, 6)? & 0x3fff;
    if frag != 0 {
        return None;
    }
    // Bound the UDP slice by the IP total length when it is sane, so
    // link-layer padding after the datagram is excluded.
    let total = usize::from(be16(ip, 2)?);
    let end = if total >= ihl && total <= ip.len() {
        total
    } else {
        ip.len()
    };
    ip.get(ihl..end)
}

fn ipv6_udp(ip: &[u8]) -> Option<&[u8]> {
    if ip.len() < 40 || ip[6] != IPPROTO_UDP {
        return None;
    }
    let payload_len = usize::from(be16(ip, 4)?);
    let end = (40 + payload_len).min(ip.len());
    ip.get(40..end)
}

fn be16(b: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_be_bytes([*b.get(at)?, *b.get(at + 1)?]))
}

/// Test-only builders for synthetic captures. Public so integration and
/// end-to-end tests can fabricate fixtures instead of checking binaries in.
pub mod build {
    /// A packet to place in a synthetic capture.
    #[derive(Debug, Clone)]
    pub struct Packet {
        /// Timestamp in microseconds.
        pub ts_micros: u64,
        /// UDP source port.
        pub src_port: u16,
        /// UDP destination port.
        pub dst_port: u16,
        /// UDP payload.
        pub payload: Vec<u8>,
    }

    /// Ethernet + IPv4 + UDP frame bytes for `p` (checksums zero: pcap
    /// readers, ours included, never verify them).
    #[must_use]
    pub fn ethernet_ipv4_udp(p: &Packet) -> Vec<u8> {
        let mut out = vec![0u8; 12];
        out.extend_from_slice(&[0x08, 0x00]);
        out.extend(ipv4_udp(p));
        out
    }

    /// IPv4 + UDP bytes (raw-IP link type).
    #[must_use]
    pub fn ipv4_udp(p: &Packet) -> Vec<u8> {
        let udp = udp(p);
        let total = u16::try_from(20 + udp.len()).unwrap_or(u16::MAX);
        let mut out = vec![0x45, 0x00];
        out.extend_from_slice(&total.to_be_bytes());
        out.extend_from_slice(&[0, 0, 0, 0, 64, 17, 0, 0]);
        out.extend_from_slice(&[10, 0, 0, 1, 10, 0, 0, 2]);
        out.extend(udp);
        out
    }

    /// IPv6 + UDP bytes (raw-IP link type).
    #[must_use]
    pub fn ipv6_udp(p: &Packet) -> Vec<u8> {
        let udp = udp(p);
        let len = u16::try_from(udp.len()).unwrap_or(u16::MAX);
        let mut out = vec![0x60, 0, 0, 0];
        out.extend_from_slice(&len.to_be_bytes());
        out.extend_from_slice(&[17, 64]);
        out.extend_from_slice(&[0; 32]);
        out.extend(udp);
        out
    }

    /// UDP header + payload.
    #[must_use]
    pub fn udp(p: &Packet) -> Vec<u8> {
        let len = u16::try_from(8 + p.payload.len()).unwrap_or(u16::MAX);
        let mut out = Vec::with_capacity(8 + p.payload.len());
        out.extend_from_slice(&p.src_port.to_be_bytes());
        out.extend_from_slice(&p.dst_port.to_be_bytes());
        out.extend_from_slice(&len.to_be_bytes());
        out.extend_from_slice(&[0, 0]);
        out.extend_from_slice(&p.payload);
        out
    }

    /// A little-endian, microsecond-timestamp pcap file containing
    /// `frames` (each `(ts_micros, link-layer frame bytes)`).
    #[must_use]
    pub fn pcap_file(link_type: u32, frames: &[(u64, Vec<u8>)]) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&0xa1b2_c3d4u32.to_le_bytes());
        out.extend_from_slice(&2u16.to_le_bytes());
        out.extend_from_slice(&4u16.to_le_bytes());
        out.extend_from_slice(&0u32.to_le_bytes());
        out.extend_from_slice(&0u32.to_le_bytes());
        out.extend_from_slice(&65_535u32.to_le_bytes());
        out.extend_from_slice(&link_type.to_le_bytes());
        for (ts, frame) in frames {
            let sec = u32::try_from(ts / 1_000_000).unwrap_or(u32::MAX);
            let usec = u32::try_from(ts % 1_000_000).unwrap_or(0);
            let len = u32::try_from(frame.len()).unwrap_or(u32::MAX);
            out.extend_from_slice(&sec.to_le_bytes());
            out.extend_from_slice(&usec.to_le_bytes());
            out.extend_from_slice(&len.to_le_bytes());
            out.extend_from_slice(&len.to_le_bytes());
            out.extend_from_slice(frame);
        }
        out
    }

    /// Convenience: an Ethernet/IPv4/UDP capture of an RTP-looking stream —
    /// `count` packets, `interval_micros` apart, to `dst_port`, payload
    /// `[0x80, 0, seq_hi, seq_lo, ..fill]` so tests can check ordering.
    #[must_use]
    pub fn rtp_capture(count: u16, interval_micros: u64, dst_port: u16) -> Vec<u8> {
        let frames: Vec<(u64, Vec<u8>)> = (0..count)
            .map(|i| {
                let mut payload = vec![0x80, 0x08];
                payload.extend_from_slice(&i.to_be_bytes());
                payload.extend(std::iter::repeat_n(0xd5, 16));
                let p = Packet {
                    ts_micros: u64::from(i) * interval_micros,
                    src_port: 4000,
                    dst_port,
                    payload,
                };
                (p.ts_micros, ethernet_ipv4_udp(&p))
            })
            .collect();
        pcap_file(super::LINKTYPE_ETHERNET, &frames)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::build::{
        Packet, ethernet_ipv4_udp, ipv4_udp, ipv6_udp, pcap_file, rtp_capture, udp,
    };
    use super::*;

    fn pkt(ts: u64, dst: u16, payload: &[u8]) -> Packet {
        Packet {
            ts_micros: ts,
            src_port: 5000,
            dst_port: dst,
            payload: payload.to_vec(),
        }
    }

    #[test]
    fn ethernet_ipv4_stream_parses_with_monotone_offsets() {
        let s = parse(&rtp_capture(3, 20_000, 6000)).unwrap();
        assert_eq!(s.len(), 3);
        assert_eq!(s.base_port, 6000);
        assert_eq!(s.skipped, 0);
        assert_eq!(s.frames[0].offset, Duration::ZERO);
        assert_eq!(s.frames[1].offset, Duration::from_millis(20));
        assert_eq!(s.frames[2].offset, Duration::from_millis(40));
        assert_eq!(s.duration(), Duration::from_millis(40));
        assert_eq!(&s.frames[2].payload[..4], &[0x80, 0x08, 0, 2]);
        assert_eq!(s.port_offsets(), vec![0]);
    }

    #[test]
    fn multi_port_capture_yields_port_offsets() {
        let frames = vec![
            (0, ethernet_ipv4_udp(&pkt(0, 8001, b"rtcp"))),
            (10, ethernet_ipv4_udp(&pkt(10, 8000, b"rtp"))),
            (20, ethernet_ipv4_udp(&pkt(20, 8001, b"rtcp"))),
        ];
        let s = parse(&pcap_file(LINKTYPE_ETHERNET, &frames)).unwrap();
        assert_eq!(s.base_port, 8000);
        assert_eq!(s.port_offsets(), vec![0, 1]);
        assert_eq!(s.frames[0].dst_port, 8001);
    }

    #[test]
    fn timestamps_never_run_backwards() {
        let frames = vec![
            (1_000, ethernet_ipv4_udp(&pkt(0, 6000, b"a"))),
            (500, ethernet_ipv4_udp(&pkt(0, 6000, b"b"))), // earlier than first
            (3_000, ethernet_ipv4_udp(&pkt(0, 6000, b"c"))),
        ];
        let s = parse(&pcap_file(LINKTYPE_ETHERNET, &frames)).unwrap();
        assert_eq!(s.frames[1].offset, Duration::ZERO);
        assert_eq!(s.frames[2].offset, Duration::from_millis(2));
    }

    #[test]
    fn big_endian_and_nanosecond_magics() {
        // Rewrite the LE µs file as BE ns by hand.
        let le = rtp_capture(2, 20_000, 6000);
        let mut be = Vec::new();
        be.extend_from_slice(&0x4d3c_b2a1u32.to_le_bytes()); // BE ns magic
        for chunk in [
            &le[4..6],
            &le[6..8],
            &le[8..12],
            &le[12..16],
            &le[16..20],
            &le[20..24],
        ] {
            let mut c = chunk.to_vec();
            c.reverse();
            be.extend(c);
        }
        let mut pos = 24;
        while pos < le.len() {
            let sec = u32::from_le_bytes(le[pos..pos + 4].try_into().unwrap());
            let usec = u32::from_le_bytes(le[pos + 4..pos + 8].try_into().unwrap());
            let len = u32::from_le_bytes(le[pos + 8..pos + 12].try_into().unwrap());
            be.extend_from_slice(&sec.to_be_bytes());
            be.extend_from_slice(&(usec * 1000).to_be_bytes());
            be.extend_from_slice(&len.to_be_bytes());
            be.extend_from_slice(&len.to_be_bytes());
            pos += 16;
            be.extend_from_slice(&le[pos..pos + len as usize]);
            pos += len as usize;
        }
        let s = parse(&be).unwrap();
        assert_eq!(s.len(), 2);
        assert_eq!(s.frames[1].offset, Duration::from_millis(20));
    }

    #[test]
    fn raw_ip_ipv6_sll_and_null_link_types() {
        let p = pkt(0, 7000, b"payload");
        for (lt, frame) in [
            (LINKTYPE_RAW, ipv4_udp(&p)),
            (LINKTYPE_RAW_LEGACY, ipv6_udp(&p)),
            (LINKTYPE_LINUX_SLL, {
                let mut f = vec![0u8; 14];
                f.extend_from_slice(&[0x08, 0x00]);
                f.extend(ipv4_udp(&p));
                f
            }),
            (LINKTYPE_LINUX_SLL2, {
                let mut f = vec![0x86, 0xdd];
                f.extend(vec![0u8; 18]);
                f.extend(ipv6_udp(&p));
                f
            }),
            (LINKTYPE_NULL, {
                let mut f = vec![2, 0, 0, 0];
                f.extend(ipv4_udp(&p));
                f
            }),
        ] {
            let s = parse(&pcap_file(lt, &[(0, frame)])).unwrap_or_else(|e| panic!("{lt}: {e}"));
            assert_eq!(s.len(), 1, "link type {lt}");
            assert_eq!(s.frames[0].payload, b"payload", "link type {lt}");
            assert_eq!(s.frames[0].dst_port, 7000);
        }
    }

    #[test]
    fn vlan_tag_is_skipped() {
        let mut f = vec![0u8; 12];
        f.extend_from_slice(&[0x81, 0x00, 0x00, 0x05, 0x08, 0x00]);
        f.extend(ipv4_udp(&pkt(0, 6000, b"x")));
        let s = parse(&pcap_file(LINKTYPE_ETHERNET, &[(0, f)])).unwrap();
        assert_eq!(s.frames[0].payload, b"x");
    }

    #[test]
    fn ethernet_padding_is_not_payload() {
        let mut f = ethernet_ipv4_udp(&pkt(0, 6000, b"ab"));
        f.extend(vec![0xee; 18]); // trailer padding to 60 bytes
        let s = parse(&pcap_file(LINKTYPE_ETHERNET, &[(0, f)])).unwrap();
        assert_eq!(s.frames[0].payload, b"ab");
    }

    #[test]
    fn ipv4_options_are_honoured() {
        let mut ip = ipv4_udp(&pkt(0, 6000, b"opt"));
        // Insert 4 bytes of options: IHL 5 → 6, total length +4.
        ip[0] = 0x46;
        let total = u16::from_be_bytes([ip[2], ip[3]]) + 4;
        ip[2..4].copy_from_slice(&total.to_be_bytes());
        ip.splice(20..20, [1, 1, 1, 1]);
        let s = parse(&pcap_file(LINKTYPE_RAW, &[(0, ip)])).unwrap();
        assert_eq!(s.frames[0].payload, b"opt");
    }

    #[test]
    fn non_udp_and_non_ip_packets_are_skipped_not_fatal() {
        let mut tcp = ipv4_udp(&pkt(0, 6000, b"tcp"));
        tcp[9] = 6;
        let mut arp = vec![0u8; 12];
        arp.extend_from_slice(&[0x08, 0x06, 1, 2, 3]);
        let mut frag = ipv4_udp(&pkt(0, 6000, b"frag"));
        frag[6] = 0x20; // MF
        let frames = vec![
            (0, ethernet_ipv4_udp(&pkt(0, 6000, b"keep"))),
            (1, {
                let mut f = vec![0u8; 12];
                f.extend_from_slice(&[0x08, 0x00]);
                f.extend(tcp);
                f
            }),
            (2, arp),
            (3, {
                let mut f = vec![0u8; 12];
                f.extend_from_slice(&[0x08, 0x00]);
                f.extend(frag);
                f
            }),
        ];
        let s = parse(&pcap_file(LINKTYPE_ETHERNET, &frames)).unwrap();
        assert_eq!(s.len(), 1);
        assert_eq!(s.skipped, 3);
    }

    #[test]
    fn errors_are_specific() {
        assert_eq!(parse(&[0u8; 10]), Err(PcapError::TooShort));
        let mut junk = vec![0u8; 24];
        junk[..4].copy_from_slice(&0xdead_beefu32.to_le_bytes());
        assert!(matches!(parse(&junk), Err(PcapError::BadMagic(_))));
        // A pcapng section header with nothing behind it.
        let mut headless = vec![0u8; 24];
        headless[..4].copy_from_slice(&0x0a0d_0d0au32.to_le_bytes());
        assert!(matches!(parse(&headless), Err(PcapError::BadBlock { .. })));
        let wifi = pcap_file(105, &[]);
        assert_eq!(parse(&wifi), Err(PcapError::UnsupportedLinkType(105)));
        let mut trunc = rtp_capture(1, 0, 6000);
        // caplen < origlen on record 0
        let caplen = u32::from_le_bytes(trunc[32..36].try_into().unwrap());
        trunc[36..40].copy_from_slice(&(caplen + 1).to_le_bytes());
        assert_eq!(parse(&trunc), Err(PcapError::TruncatedPacket { index: 0 }));
        let mut short = rtp_capture(2, 0, 6000);
        short.truncate(short.len() - 3);
        assert_eq!(parse(&short), Err(PcapError::TruncatedFile { index: 1 }));
    }

    #[test]
    fn empty_capture_is_ok_and_empty() {
        let s = parse(&pcap_file(LINKTYPE_ETHERNET, &[])).unwrap();
        assert!(s.is_empty());
        assert_eq!(s.duration(), Duration::ZERO);
        assert!(s.port_offsets().is_empty());
    }

    #[test]
    fn never_panics_on_mutations_and_truncations() {
        // Deterministic fuzz-shaped sweep: every truncation and every single
        // byte flipped, over a real-looking file.
        let good = rtp_capture(4, 20_000, 6000);
        for n in 0..good.len() {
            let _ = parse(&good[..n]);
        }
        for i in 0..good.len() {
            let mut m = good.clone();
            m[i] ^= 0xff;
            let _ = parse(&m);
        }
        // And a bare UDP header claiming more than it has.
        let short = udp(&pkt(0, 1, b""));
        let _ = parse(&pcap_file(LINKTYPE_RAW, &[(0, short)]));
    }
}
