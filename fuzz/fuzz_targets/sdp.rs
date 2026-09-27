//! The SDP scan that picks the peer's media endpoint and SRTP keys out of a
//! received body.

#![no_main]

use libfuzzer_sys::fuzz_target;
use sipr_media::sdp::{crypto_attributes, remote_endpoint};

fuzz_target!(|data: &[u8]| {
    for kind in ["audio", "video", "image"] {
        let _ = remote_endpoint(data, kind);
        let _ = crypto_attributes(data, kind);
    }
});
