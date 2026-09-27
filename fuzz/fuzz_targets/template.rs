//! The message-template tokenizer: CDATA text in, keyword spans out, with a
//! `-key` generic keyword in scope.

#![no_main]

use libfuzzer_sys::fuzz_target;
use sipr_scenario::diag::Diagnostics;
use sipr_scenario::template::{normalize_cdata, tokenize_with};

fuzz_target!(|data: &[u8]| {
    let text = String::from_utf8_lossy(data);
    let _ = normalize_cdata(&text);
    let mut diags = Diagnostics::new("fuzz.xml");
    let generic = ["FUZZKEY".to_owned()];
    let template = tokenize_with(&text, 1, &mut diags, &generic);
    for keyword in template.keywords() {
        let _ = keyword;
    }
});
