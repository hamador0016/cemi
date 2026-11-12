//! References (`global:acme/shop/stripe#key`) and template parts.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|text: &str| {
    if let Ok(r) = cemi::refs::Ref::parse(text) {
        // What parses prints back as something that parses to the same thing.
        let again = cemi::refs::Ref::parse(&r.to_string()).expect("a printed reference parses");
        assert_eq!(again.to_string(), r.to_string());
    }
    for part in cemi::resolve::template_refs(text) {
        let _ = cemi::refs::Ref::parse(&part);
    }
    let _ = cemi::refs::entity_path(text);
});
