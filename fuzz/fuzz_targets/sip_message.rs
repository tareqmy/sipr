//! The inbound SIP parser: every datagram a transport receives goes through
//! `Inbound::parse`, and every accessor the engine uses must hold on
//! whatever it accepted (the seeded version is
//! `crates/sipr-net/tests/no_panic.rs`).

#![no_main]

use libfuzzer_sys::fuzz_target;
use sipr_net::message::Inbound;

fuzz_target!(|data: &[u8]| {
    let Ok(m) = Inbound::parse(data) else {
        return;
    };
    let _ = m.kind();
    let _ = m.start_line();
    let _ = m.status_code();
    let _ = m.method();
    let _ = m.body();
    let _ = m.call_id();
    let _ = m.cseq();
    let _ = m.top_via_branch();
    let _ = m.from_tag();
    let _ = m.to_tag();
    let _ = m.header("Via");
    let _ = m.header("Content-Length");
    let _ = m.header("");
    let _ = m.header_values("Record-Route");
    let _ = m.header_lines("Via");
    let _ = m.reconstruct();
});
