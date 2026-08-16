//! Fuzz-style robustness tests (docs/TESTING.md §3, M2 criterion): the
//! inbound parser must never panic on arbitrary datagrams. proptest is in
//! the sanctioned set but unavailable in this build environment, so this is
//! a deterministic seeded equivalent: random byte soup, random ASCII, and
//! systematic mutations/truncations of a valid message. Reproducible by
//! construction — failures print the seed/iteration.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use sipr_net::message::Inbound;
use sipr_net::rng::Rng;

const VALID: &[u8] = b"INVITE sip:service@10.0.0.2:5060 SIP/2.0\r\n\
    Via: SIP/2.0/UDP 10.0.0.1:5061;branch=z9hG4bK-1-1-7\r\n\
    From: sipr <sip:sipr@10.0.0.1>;tag=1a2b3c\r\n\
    To: service <sip:service@10.0.0.2>\r\n\
    Call-ID: 1-42@10.0.0.1\r\n\
    CSeq: 1 INVITE\r\n\
    Content-Length: 5\r\n\
    \r\n\
    v=0\r\n";

/// Exercise every accessor; none may panic regardless of parse outcome.
fn poke(data: &[u8]) {
    if let Ok(m) = Inbound::parse(data) {
        let _ = m.call_id();
        let _ = m.cseq();
        let _ = m.top_via_branch();
        let _ = m.from_tag();
        let _ = m.to_tag();
        let _ = m.status_code();
        let _ = m.method();
        let _ = m.body();
        let _ = m.header("Via");
        let _ = m.header_values("Record-Route");
        let _ = m.header_lines("Via");
        let _ = m.header("");
        let _ = m.header("no-such-header");
    }
}

#[test]
fn random_byte_soup_never_panics() {
    let mut rng = Rng::new(0xF00D);
    for i in 0..2_000 {
        let len = (rng.next_u64() % 600) as usize;
        let mut buf = vec![0u8; len];
        rng.fill(&mut buf);
        // Half the iterations: make it superficially SIP-shaped.
        if i % 2 == 0 && buf.len() > 8 {
            buf[..8].copy_from_slice(b"SIP/2.0 ");
        }
        poke(&buf);
    }
}

#[test]
fn random_ascii_lines_never_panic() {
    let mut rng = Rng::new(0xCAFE);
    const CHARS: &[u8] =
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789 :;=@.<>[]-_\r\n";
    for _ in 0..2_000 {
        let len = (rng.next_u64() % 400) as usize;
        let buf: Vec<u8> = (0..len)
            .map(|_| CHARS[(rng.next_u64() as usize) % CHARS.len()])
            .collect();
        poke(&buf);
    }
}

#[test]
fn every_truncation_of_a_valid_message_survives() {
    for len in 0..VALID.len() {
        poke(&VALID[..len]);
    }
}

#[test]
fn single_byte_mutations_survive() {
    let mut rng = Rng::new(0xBEEF);
    for _ in 0..2_000 {
        let mut buf = VALID.to_vec();
        let idx = (rng.next_u64() as usize) % buf.len();
        buf[idx] = (rng.next_u64() & 0xFF) as u8;
        poke(&buf);
    }
}

#[test]
fn pathological_shapes_survive() {
    let long_line = [b'A'; 65_000];
    let cases: Vec<Vec<u8>> = vec![
        b"INVITE".to_vec(),
        b"INVITE  SIP/2.0".to_vec(),
        b"SIP/2.0".to_vec(),
        b"SIP/2.0 \r\n\r\n".to_vec(),
        b"SIP/2.0 20a OK\r\n\r\n".to_vec(),
        b"OPTIONS sip:x SIP/2.0\r\n".to_vec(), // no blank line
        b"OPTIONS sip:x SIP/2.0\r\n:\r\n::\r\n:::\r\n\r\n".to_vec(),
        b"OPTIONS sip:x SIP/2.0\r\nVia;branch=\r\nVia: ;branch\r\n\r\n".to_vec(),
        b"OPTIONS sip:x SIP/2.0\r\nCSeq: 99999999999999999999 INVITE\r\n\r\n".to_vec(),
        b"OPTIONS sip:x SIP/2.0\r\nFrom: <sip:a>;tag=\r\nTo: ;tag\r\n\r\n".to_vec(),
        [
            b"OPTIONS sip:x SIP/2.0\r\nX: ".as_slice(),
            &long_line,
            b"\r\n\r\n",
        ]
        .concat(),
        b"\r\n\r\n\r\n".to_vec(),
        vec![0u8; 65_535],
    ];
    for case in &cases {
        poke(case);
    }
}
