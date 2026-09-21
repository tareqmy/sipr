//! pcapng block reader: the same UDP payloads and relative timing the
//! classic [`crate::pcap`] reader extracts, out of the format `tcpdump` and
//! Wireshark write by default today.
//!
//! This is a sipr addition, not SIPp parity — SIPp's `prepare_pcap.c` calls
//! `pcap_open_offline`, which rejects pcapng, and its docs tell you to
//! recapture with `-s0` in the classic format. That advice still stands for
//! the classic reader; it just is no longer the only way in.
//!
//! Supported blocks: Section Header (0x0A0D0D0A, which also sets the
//! section's byte order), Interface Description (link type and the
//! `if_tsresol` option), Enhanced Packet, Simple Packet and the obsolete
//! Packet block. Everything else — name resolution, statistics, custom
//! blocks — is skipped by its length, as the format intends.

use std::time::Duration;

use crate::pcap::{Frame, PcapError, PcapStream, link_type_supported, udp_payload};

/// A pcapng Section Header Block starts a file (and every later section).
/// The value is a palindrome, so it reads the same in either byte order.
pub const SHB_TYPE: u32 = 0x0a0d_0d0a;

const IDB_TYPE: u32 = 0x0000_0001;
const OBSOLETE_PACKET_TYPE: u32 = 0x0000_0002;
const SPB_TYPE: u32 = 0x0000_0003;
const EPB_TYPE: u32 = 0x0000_0006;

/// The byte-order magic in a Section Header Block, as written.
const BYTE_ORDER_MAGIC: u32 = 0x1a2b_3c4d;

/// `if_tsresol`: one byte, the timestamp resolution of an interface.
const OPT_IF_TSRESOL: u16 = 9;
/// `opt_endofopt`.
const OPT_END: u16 = 0;

/// The smallest legal block: type, length, length.
const MIN_BLOCK_LEN: usize = 12;

/// True when `bytes` opens with a Section Header Block.
#[must_use]
pub fn is_pcapng(bytes: &[u8]) -> bool {
    bytes
        .get(..4)
        .and_then(|b| b.try_into().ok())
        .is_some_and(|b: [u8; 4]| u32::from_le_bytes(b) == SHB_TYPE)
}

/// One interface as its Interface Description Block declared it.
#[derive(Clone, Copy)]
struct Interface {
    link_type: u32,
    /// Timestamp units per second (`if_tsresol`; 10^6 by default).
    ticks_per_second: u128,
}

/// Byte order of the section currently being read.
#[derive(Clone, Copy)]
struct Endian(bool);

impl Endian {
    fn u16(self, b: &[u8]) -> u16 {
        let a = [b[0], b[1]];
        if self.0 {
            u16::from_be_bytes(a)
        } else {
            u16::from_le_bytes(a)
        }
    }

    fn u32(self, b: &[u8]) -> u32 {
        let a = [b[0], b[1], b[2], b[3]];
        if self.0 {
            u32::from_be_bytes(a)
        } else {
            u32::from_le_bytes(a)
        }
    }
}

/// Parse a pcapng file held in memory.
///
/// # Errors
///
/// [`PcapError`] for a malformed file or a link-layer type this reader does
/// not decode. Packets that are not UDP over IP are skipped and counted, as
/// in the classic reader.
pub fn parse(bytes: &[u8]) -> Result<PcapStream, PcapError> {
    if bytes.len() < MIN_BLOCK_LEN {
        return Err(PcapError::TooShort);
    }
    if !is_pcapng(bytes) {
        return Err(PcapError::BadMagic(Endian(false).u32(&bytes[0..4])));
    }

    let mut stream = PcapStream::default();
    let mut endian = Endian(false);
    let mut interfaces: Vec<Interface> = Vec::new();
    let mut first_ts: Option<u128> = None;
    let mut last_offset = Duration::ZERO;
    let mut pos = 0usize;
    let mut block = 0usize;
    // Packets are numbered across the whole file, so a truncation reads the
    // same as it does from a classic capture.
    let mut packet = 0usize;

    while pos < bytes.len() {
        let Some(header) = bytes.get(pos..pos + 8) else {
            return Err(PcapError::TruncatedFile { index: packet });
        };
        let raw_type = Endian(false).u32(&header[0..4]);
        if raw_type == SHB_TYPE {
            endian = section_endian(bytes, pos, block)?;
            // A new section restates every interface.
            interfaces.clear();
        }
        let total = endian.u32(&header[4..8]) as usize;
        if total < MIN_BLOCK_LEN || total % 4 != 0 {
            return Err(PcapError::BadBlock {
                index: block,
                why: "block length is not a multiple of 4, or too small",
            });
        }
        // A block ends with its own length repeated, so the file must hold
        // all `total` bytes — a capture cut short fails here, not silently.
        if pos + total > bytes.len() {
            return Err(PcapError::TruncatedFile { index: packet });
        }
        let Some(body) = bytes.get(pos + 8..pos + total - 4) else {
            return Err(PcapError::TruncatedFile { index: packet });
        };
        let block_type = endian.u32(&header[0..4]);
        // Step over the block before handling it: the arms below `continue`.
        let block_index = block;
        pos += total;
        block += 1;
        match block_type {
            SHB_TYPE => {}
            IDB_TYPE => interfaces.push(read_interface(body, endian, block_index)?),
            EPB_TYPE | OBSOLETE_PACKET_TYPE | SPB_TYPE => {
                let record = read_packet(block_type, body, endian, block_index)?;
                let iface = *interfaces
                    .get(record.interface)
                    .ok_or(PcapError::BadBlock {
                        index: block_index,
                        why: "packet names an interface no IDB described",
                    })?;
                if !link_type_supported(iface.link_type) {
                    return Err(PcapError::UnsupportedLinkType(iface.link_type));
                }
                if stream.frames.is_empty() && stream.skipped == 0 {
                    stream.link_type = iface.link_type;
                }
                if record.caplen < record.origlen {
                    return Err(PcapError::TruncatedPacket { index: packet });
                }
                packet += 1;
                let Some((dst_port, payload)) = udp_payload(iface.link_type, record.data) else {
                    stream.skipped += 1;
                    continue;
                };
                let ts_nanos = record.ticks * 1_000_000_000 / iface.ticks_per_second;
                let t0 = *first_ts.get_or_insert(ts_nanos);
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
            // Name resolution, statistics, custom blocks: skipped by length.
            _ => {}
        }
    }
    stream.base_port = stream.frames.iter().map(|f| f.dst_port).min().unwrap_or(0);
    Ok(stream)
}

/// The byte order a Section Header Block declares.
fn section_endian(bytes: &[u8], pos: usize, block: usize) -> Result<Endian, PcapError> {
    let magic = bytes.get(pos + 8..pos + 12).ok_or(PcapError::BadBlock {
        index: block,
        why: "section header block has no byte-order magic",
    })?;
    if Endian(false).u32(magic) == BYTE_ORDER_MAGIC {
        return Ok(Endian(false));
    }
    if Endian(true).u32(magic) == BYTE_ORDER_MAGIC {
        return Ok(Endian(true));
    }
    Err(PcapError::BadBlock {
        index: block,
        why: "section header block has a bad byte-order magic",
    })
}

/// Link type and timestamp resolution from an Interface Description Block.
fn read_interface(body: &[u8], endian: Endian, block: usize) -> Result<Interface, PcapError> {
    if body.len() < 8 {
        return Err(PcapError::BadBlock {
            index: block,
            why: "interface description block is too short",
        });
    }
    let link_type = u32::from(endian.u16(&body[0..2]));
    let mut ticks_per_second = 1_000_000u128; // if_tsresol default: 10^-6
    for (code, value) in options(&body[8..], endian) {
        if code == OPT_IF_TSRESOL
            && let Some(&raw) = value.first()
        {
            let exponent = u32::from(raw & 0x7f);
            let base: u128 = if raw & 0x80 == 0 { 10 } else { 2 };
            ticks_per_second = base.checked_pow(exponent).ok_or(PcapError::BadBlock {
                index: block,
                why: "if_tsresol is out of range",
            })?;
        }
    }
    Ok(Interface {
        link_type,
        ticks_per_second,
    })
}

/// The option list of a block: `(code, value)` until `opt_endofopt` or the
/// end of the body. Malformed tails simply end the iteration.
fn options(mut rest: &[u8], endian: Endian) -> Vec<(u16, &[u8])> {
    let mut out = Vec::new();
    while rest.len() >= 4 {
        let code = endian.u16(&rest[0..2]);
        let len = endian.u16(&rest[2..4]) as usize;
        if code == OPT_END {
            break;
        }
        let padded = len.next_multiple_of(4);
        let Some(value) = rest.get(4..4 + len) else {
            break;
        };
        out.push((code, value));
        let Some(next) = rest.get(4 + padded..) else {
            break;
        };
        rest = next;
    }
    out
}

/// One captured packet, whichever of the three packet blocks carried it.
struct Record<'a> {
    interface: usize,
    /// Timestamp in the interface's own units (0 for a Simple Packet Block,
    /// which carries none).
    ticks: u128,
    caplen: usize,
    origlen: usize,
    data: &'a [u8],
}

fn read_packet<'a>(
    block_type: u32,
    body: &'a [u8],
    endian: Endian,
    block: usize,
) -> Result<Record<'a>, PcapError> {
    let short = || PcapError::BadBlock {
        index: block,
        why: "packet block is shorter than its own header says",
    };
    // (interface, ticks, caplen, origlen, data offset)
    let (interface, ticks, caplen, origlen, at) = match block_type {
        SPB_TYPE => {
            let head = body.get(0..4).ok_or_else(short)?;
            let origlen = endian.u32(head) as usize;
            // A Simple Packet Block stores no captured length: what is there
            // is the whole packet, up to the block's own end.
            (0usize, 0u128, origlen.min(body.len() - 4), origlen, 4usize)
        }
        OBSOLETE_PACKET_TYPE => {
            let head = body.get(0..20).ok_or_else(short)?;
            (
                endian.u16(&head[0..2]) as usize,
                ticks_of(endian, &head[4..12]),
                endian.u32(&head[12..16]) as usize,
                endian.u32(&head[16..20]) as usize,
                20usize,
            )
        }
        // EPB_TYPE
        _ => {
            let head = body.get(0..20).ok_or_else(short)?;
            (
                endian.u32(&head[0..4]) as usize,
                ticks_of(endian, &head[4..12]),
                endian.u32(&head[12..16]) as usize,
                endian.u32(&head[16..20]) as usize,
                20usize,
            )
        }
    };
    let data = body.get(at..at + caplen).ok_or_else(short)?;
    Ok(Record {
        interface,
        ticks,
        caplen,
        origlen,
        data,
    })
}

/// The 64-bit timestamp split across two 32-bit words, high first.
fn ticks_of(endian: Endian, b: &[u8]) -> u128 {
    (u128::from(endian.u32(&b[0..4])) << 32) | u128::from(endian.u32(&b[4..8]))
}

/// Test-only builders for synthetic pcapng captures. Public for the same
/// reason [`crate::pcap::build`] is: fixtures are fabricated, not checked in.
pub mod build {
    use super::{BYTE_ORDER_MAGIC, EPB_TYPE, IDB_TYPE, SHB_TYPE};
    use crate::pcap::build::{Packet, ethernet_ipv4_udp};

    /// One block: type, total length, body, total length again, body padded
    /// to a multiple of 4 as the format requires.
    fn block(block_type: u32, body: &[u8], big_endian: bool) -> Vec<u8> {
        let padded = body.len().next_multiple_of(4);
        let total = u32::try_from(12 + padded).unwrap_or(u32::MAX);
        let word = |v: u32| {
            if big_endian {
                v.to_be_bytes()
            } else {
                v.to_le_bytes()
            }
        };
        let mut out = Vec::with_capacity(12 + padded);
        out.extend_from_slice(&word(block_type));
        out.extend_from_slice(&word(total));
        out.extend_from_slice(body);
        out.resize(8 + padded, 0);
        out.extend_from_slice(&word(total));
        out
    }

    /// A Section Header Block declaring `big_endian` for what follows.
    #[must_use]
    pub fn section_header(big_endian: bool) -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(&if big_endian {
            BYTE_ORDER_MAGIC.to_be_bytes()
        } else {
            BYTE_ORDER_MAGIC.to_le_bytes()
        });
        // Version 1.0, then "section length unknown" (-1).
        body.extend_from_slice(&[1, 0, 0, 0]);
        body.extend_from_slice(&[0xff; 8]);
        block(SHB_TYPE, &body, big_endian)
    }

    /// An Interface Description Block. `tsresol` is the raw `if_tsresol`
    /// byte (`None` leaves the default of 10^-6).
    #[must_use]
    pub fn interface(link_type: u16, tsresol: Option<u8>, big_endian: bool) -> Vec<u8> {
        let half = |v: u16| {
            if big_endian {
                v.to_be_bytes()
            } else {
                v.to_le_bytes()
            }
        };
        let word = |v: u32| {
            if big_endian {
                v.to_be_bytes()
            } else {
                v.to_le_bytes()
            }
        };
        let mut body = Vec::new();
        body.extend_from_slice(&half(link_type));
        body.extend_from_slice(&half(0));
        body.extend_from_slice(&word(65_535));
        if let Some(raw) = tsresol {
            body.extend_from_slice(&half(9)); // if_tsresol
            body.extend_from_slice(&half(1));
            body.extend_from_slice(&[raw, 0, 0, 0]);
            body.extend_from_slice(&half(0)); // opt_endofopt
            body.extend_from_slice(&half(0));
        }
        block(IDB_TYPE, &body, big_endian)
    }

    /// An Enhanced Packet Block carrying `frame` at `ticks` on `interface`.
    #[must_use]
    pub fn packet(interface: u32, ticks: u64, frame: &[u8], big_endian: bool) -> Vec<u8> {
        let word = |v: u32| {
            if big_endian {
                v.to_be_bytes()
            } else {
                v.to_le_bytes()
            }
        };
        let len = u32::try_from(frame.len()).unwrap_or(u32::MAX);
        let mut body = Vec::new();
        body.extend_from_slice(&word(interface));
        #[allow(clippy::cast_possible_truncation)]
        body.extend_from_slice(&word((ticks >> 32) as u32));
        #[allow(clippy::cast_possible_truncation)]
        body.extend_from_slice(&word(ticks as u32));
        body.extend_from_slice(&word(len));
        body.extend_from_slice(&word(len));
        body.extend_from_slice(frame);
        // Packet data is padded inside the block, which `block` handles.
        block(EPB_TYPE, &body, big_endian)
    }

    /// The pcapng twin of [`crate::pcap::build::rtp_capture`]: `count`
    /// Ethernet/IPv4/UDP packets, `interval_micros` apart, to `dst_port`.
    #[must_use]
    pub fn rtp_capture(count: u16, interval_micros: u64, dst_port: u16) -> Vec<u8> {
        let mut out = section_header(false);
        out.extend(interface(1, None, false)); // LINKTYPE_ETHERNET, 10^-6
        for i in 0..count {
            let mut payload = vec![0x80, 0x08];
            payload.extend_from_slice(&i.to_be_bytes());
            payload.extend(std::iter::repeat_n(0xd5, 16));
            let p = Packet {
                ts_micros: u64::from(i) * interval_micros,
                src_port: 4000,
                dst_port,
                payload,
            };
            out.extend(packet(0, p.ts_micros, &ethernet_ipv4_udp(&p), false));
        }
        out
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::build::{interface, packet, rtp_capture, section_header};
    use super::*;
    use crate::pcap::build::{Packet, ethernet_ipv4_udp, ipv4_udp};

    fn pkt(dst: u16, payload: &[u8]) -> Packet {
        Packet {
            ts_micros: 0,
            src_port: 5000,
            dst_port: dst,
            payload: payload.to_vec(),
        }
    }

    #[test]
    fn reads_the_same_stream_as_the_classic_format() {
        let ng = crate::pcap::parse(&rtp_capture(3, 20_000, 6000)).unwrap();
        let classic =
            crate::pcap::parse(&crate::pcap::build::rtp_capture(3, 20_000, 6000)).unwrap();
        assert_eq!(ng, classic, "pcapng and pcap of the same stream must agree");
        assert_eq!(ng.len(), 3);
        assert_eq!(ng.frames[2].offset, Duration::from_millis(40));
        assert_eq!(ng.base_port, 6000);
    }

    #[test]
    fn big_endian_sections_and_nanosecond_resolution() {
        let mut file = section_header(true);
        // if_tsresol = 9: nanoseconds.
        file.extend(interface(1, Some(9), true));
        for (i, ticks) in [0u64, 20_000_000, 40_000_000].into_iter().enumerate() {
            let p = pkt(6000, &[0x80, 0x08, 0, u8::try_from(i).unwrap()]);
            file.extend(packet(0, ticks, &ethernet_ipv4_udp(&p), true));
        }
        let s = crate::pcap::parse(&file).unwrap();
        assert_eq!(s.len(), 3);
        assert_eq!(s.frames[1].offset, Duration::from_millis(20));
        assert_eq!(s.frames[2].offset, Duration::from_millis(40));
    }

    #[test]
    fn binary_tsresol_and_unknown_blocks_are_handled() {
        let mut file = section_header(false);
        // if_tsresol with the high bit set: 2^-10 of a second per tick.
        file.extend(interface(101, Some(0x80 | 10), false)); // LINKTYPE_RAW
        // A name-resolution block (type 4) nobody reads, skipped by length.
        file.extend(super::build::packet(0, 0, &[], false));
        file.truncate(file.len() - 32);
        let p = pkt(7000, b"first");
        file.extend(packet(0, 0, &ipv4_udp(&p), false));
        let q = pkt(7000, b"second");
        file.extend(packet(0, 1024, &ipv4_udp(&q), false));
        let s = crate::pcap::parse(&file).unwrap();
        assert_eq!(s.len(), 2);
        assert_eq!(
            s.frames[1].offset,
            Duration::from_secs(1),
            "1024 ticks of 2^-10 s is one second"
        );
        assert_eq!(s.link_type, 101);
    }

    #[test]
    fn a_second_section_resets_the_interfaces() {
        let mut file = rtp_capture(1, 0, 6000);
        file.extend(rtp_capture(2, 20_000, 6000));
        let s = crate::pcap::parse(&file).unwrap();
        assert_eq!(s.len(), 3, "both sections contribute");
    }

    #[test]
    fn errors_are_specific() {
        // A packet naming an interface no IDB described.
        let mut orphan = section_header(false);
        orphan.extend(packet(0, 0, &ipv4_udp(&pkt(6000, b"x")), false));
        assert!(matches!(
            crate::pcap::parse(&orphan),
            Err(PcapError::BadBlock { .. })
        ));
        // An unsupported link type, reported when a packet uses it.
        let mut wifi = section_header(false);
        wifi.extend(interface(105, None, false));
        wifi.extend(packet(0, 0, &ipv4_udp(&pkt(6000, b"x")), false));
        assert_eq!(
            crate::pcap::parse(&wifi),
            Err(PcapError::UnsupportedLinkType(105))
        );
        // A truncated file ends inside a block.
        let mut short = rtp_capture(2, 20_000, 6000);
        short.truncate(short.len() - 3);
        assert_eq!(
            crate::pcap::parse(&short),
            Err(PcapError::TruncatedFile { index: 1 }),
            "the second packet is the one cut short"
        );
        // A section header with a bad byte-order magic.
        let mut bad = section_header(false);
        bad[8..12].copy_from_slice(&0xdead_beefu32.to_le_bytes());
        assert!(matches!(
            crate::pcap::parse(&bad),
            Err(PcapError::BadBlock { .. })
        ));
    }

    #[test]
    fn never_panics_on_mutations_and_truncations() {
        let good = rtp_capture(4, 20_000, 6000);
        for n in 0..good.len() {
            let _ = crate::pcap::parse(&good[..n]);
        }
        for i in 0..good.len() {
            let mut m = good.clone();
            m[i] ^= 0xff;
            let _ = crate::pcap::parse(&m);
        }
    }
}
