//! Paths and rules of the credential proxy: an AI chooses the path.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|input: (&str, &str)| {
    let (rule, path) = input;
    if let Ok((segments, _)) = cemi::proxy::split_path(path) {
        // An accepted path never climbs out of the API's address.
        for s in &segments {
            let lower = s.to_ascii_lowercase().replace("%2e", ".");
            assert!(lower != "." && lower != "..", "{path:?}");
            assert!(!lower.contains("%2f") && !s.contains('\\'),"{path:?}");
        }
        if let Ok(r) = cemi::proxy::Rule::parse(rule) {
            let _ = r.matches("GET", &segments);
        }
    }
    let _ = cemi::proxy::check_base(path);
});
