# sipr-auth

SIP digest authentication (RFC 2617 / RFC 7616) and IMS AKA, with every primitive implemented in-tree.

- Digest challenge parsing and `Authorization` / `Proxy-Authorization` header generation, for MD5 and SHA-256 with `qop="auth"`.
- IMS AKA (`AKAv1-MD5`, RFC 3310) with 3GPP Milenage, including AUTS resynchronisation.
- The hashes and encodings those need: MD5, SHA-1, SHA-256, HMAC-SHA1, AES-128 and base64, plus the SRTP key derivation used by `sipr-media`.
- No dependencies.

It backs the `[authentication]` keyword and `<recv auth="true">` in SIPp scenarios.

## About sipr

[sipr](https://github.com/tareqmy/sipr) is a SIPp-compatible SIP testing tool
and traffic generator written in Rust: it plays SIPp XML scenarios as caller
(UAC) or callee (UAS) at a controlled rate, over UDP, TCP, TLS and WebSocket,
with a live terminal dashboard. Documentation: <https://tareqmy.github.io/sipr/>.

## Stability

This crate exists so the `sipr` workspace can be published as separate crates. Its API is internal to sipr and may change in any release; depend on `sipr-engine` if you want to embed sipr in your own Rust code (see its `docs/LIBRARY_API.md`), or install the `sipr` binary.

## License

MIT.
