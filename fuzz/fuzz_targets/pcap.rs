//! The pcap and pcapng readers behind `play_pcap_audio` and friends: one
//! entry point dispatches on the magic, and the replay-side accessors must
//! hold on whatever it kept.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(stream) = sipr_media::pcap::parse(data) else {
        return;
    };
    let _ = stream.len();
    let _ = stream.is_empty();
    let _ = stream.duration();
    let _ = stream.port_offsets();
});
