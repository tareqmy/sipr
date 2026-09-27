//! The control surface: a UDP control-socket datagram, a command line, and
//! a JSON document as the HTTP API reads them.

#![no_main]

use libfuzzer_sys::fuzz_target;
use sipr_control::command::{Datagram, parse_command, parse_datagram};

fuzz_target!(|data: &[u8]| {
    if let Some(Datagram::Command(line)) = parse_datagram(data) {
        let _ = parse_command(&line);
    }
    let text = String::from_utf8_lossy(data);
    let _ = parse_command(&text);
    let _ = sipr_control::json::parse(&text);
});
