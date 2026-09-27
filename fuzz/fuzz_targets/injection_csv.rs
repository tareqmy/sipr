//! The `-inf` injection file reader and the table it builds: parse, then
//! every operation the keywords and `<setvar>`/`[field]` paths perform on it.
//!
//! `-infindex` is only exercised on files up to `MAX_INDEXED_LINES` virtual
//! lines: a `PRINTF=` multiplier is a count the user asked for, indexing it
//! costs one entry per virtual line in sipr and in SIPp alike, and a header
//! saying `PRINTF=344444444` would otherwise read as an out-of-memory finding.

#![no_main]

use libfuzzer_sys::fuzz_target;
use sipr_scenario::inject::InjectionFile;

const MAX_INDEXED_LINES: usize = 4096;

fuzz_target!(|data: &[u8]| {
    let text = String::from_utf8_lossy(data);
    let Ok(mut file) = InjectionFile::parse("fuzz.csv", &text) else {
        return;
    };
    let _ = file.is_printf();
    let _ = file.is_empty();
    for line in 0..file.len().min(16) {
        for field in 0..8 {
            let _ = file.field(line, field);
        }
    }
    let _ = file.field(usize::MAX, 0);
    let _ = file.is_indexed();
    if file.len() <= MAX_INDEXED_LINES {
        file.build_index(0);
    }
    let _ = file.lookup("");
    let _ = file.lookup("fuzz");
    let _ = file.insert("a;b;c");
    let _ = file.replace(0, "d;e");
    let _ = file.replace(usize::MAX, "f");
});
