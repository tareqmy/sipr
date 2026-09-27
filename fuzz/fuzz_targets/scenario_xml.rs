//! The scenario compiler, from XML text to IR: the loose path the binary
//! takes and the strict `--check` path with the lints on.

#![no_main]

use libfuzzer_sys::fuzz_target;
use sipr_scenario::{CompileOptions, compile, compile_strict};

fuzz_target!(|data: &[u8]| {
    let text = String::from_utf8_lossy(data);
    let _ = compile("fuzz.xml", &text);
    let _ = compile_strict("fuzz.xml", &text, &CompileOptions::default());
});
