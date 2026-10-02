# sipr-scenario

Parser and compiler for SIPp XML scenarios: keywords, actions, and the compiled step IR.

- `compile`, `compile_with` and `compile_strict` turn scenario XML into a `Scenario` (a flat step list) plus diagnostics. Unknown elements and actions are errors; unknown attributes and keywords produce a warning with file and line.
- Pre-tokenised message templates, so keyword substitution at send time is slot filling rather than string scanning.
- Injection (`-inf`) file parsing, statistical distributions for pauses, the regex engine behind `<ereg>`, and the `--check` lints.
- SIPp's default scenarios (`uac`, `uas`, the out-of-call responders) embedded in the crate.
- No dependencies.

```rust
use sipr_scenario::{CompileOptions, compile_strict};

let xml = sipr_scenario::embedded("uac").expect("embedded scenario");
let scenario = compile_strict("uac", xml, &CompileOptions::default())
    .expect("the embedded scenario compiles cleanly");
```

## About sipr

[sipr](https://github.com/tareqmy/sipr) is a SIPp-compatible SIP testing tool
and traffic generator written in Rust: it plays SIPp XML scenarios as caller
(UAC) or callee (UAS) at a controlled rate, over UDP, TCP, TLS and WebSocket,
with a live terminal dashboard. Documentation: <https://tareqmy.github.io/sipr/>.

## Stability

This crate exists so the `sipr` workspace can be published as separate crates. Its API is internal to sipr and may change in any release; depend on `sipr-engine` if you want to embed sipr in your own Rust code (see its `docs/LIBRARY_API.md`), or install the `sipr` binary.

## License

MIT.
