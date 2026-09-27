//! Digest authentication as sipr meets it on the wire: a challenge header
//! from a 401/407 (parse, then answer it, MD5/SHA-256 and IMS AKA alike)
//! and an Authorization header a UAS is asked to `verifyauth`.

#![no_main]

use libfuzzer_sys::fuzz_target;
use sipr_auth::{
    AkaKeys, Credentials, aka_challenge_response, authorization_header, digest_response,
    parse_challenge, verify_authorization,
};

fuzz_target!(|data: &[u8]| {
    let text = String::from_utf8_lossy(data);
    let aka = AkaKeys {
        k: [0x11; 16],
        opc: [0x22; 16],
        amf: Some([0x80, 0x00]),
        sqn_ms: None,
        force_resync: false,
    };
    for proxy in [false, true] {
        let Some(challenge) = parse_challenge(&text, proxy) else {
            continue;
        };
        let credentials = Credentials {
            username: "fuzz",
            password: "secret",
            method: "REGISTER",
            uri: "sip:fuzz.example",
            cnonce: "0a4f113b",
            nc: 1,
            aka: Some(aka.clone()),
        };
        let _ = digest_response(&challenge, &credentials);
        let _ = authorization_header(&challenge, &credentials);
    }
    let _ = aka_challenge_response(&text, &aka);
    let _ = verify_authorization(&text, "fuzz", "secret", "REGISTER", b"", None);
    let _ = verify_authorization(
        &text,
        "fuzz",
        "secret",
        "INVITE",
        data,
        Some("sip:fuzz.example"),
    );
});
