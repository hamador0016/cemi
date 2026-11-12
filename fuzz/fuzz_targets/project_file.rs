//! `cemi.toml` (comes with any repository) and CI file headers.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|text: &str| {
    let _ = toml::from_str::<cemi::project::ProjectFile>(text);
    let _ = cemi::ci::read_header(text);
});
