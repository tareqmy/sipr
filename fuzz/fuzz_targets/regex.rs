//! The in-tree regex engine behind `<ereg>`: a pattern and a haystack,
//! separated by the first NUL byte. Both are capped so that a slow pattern
//! reads as slow, not as a hang.

#![no_main]

use libfuzzer_sys::fuzz_target;
use sipr_scenario::regex::Regex;

const MAX_PATTERN: usize = 64;
const MAX_HAYSTACK: usize = 256;

fuzz_target!(|data: &[u8]| {
    let split = data.iter().position(|&b| b == 0).unwrap_or(data.len());
    let (pattern, haystack) = data.split_at(split);
    if pattern.len() > MAX_PATTERN || haystack.len() > MAX_HAYSTACK + 1 {
        return;
    }
    let pattern = String::from_utf8_lossy(pattern);
    let Ok(re) = Regex::compile(&pattern) else {
        return;
    };
    let haystack = haystack.get(1..).unwrap_or_default();
    let _ = re.group_count();
    let _ = re.find(haystack);
    let _ = re.find_strings(haystack);
});
