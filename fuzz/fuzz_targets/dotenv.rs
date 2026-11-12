//! `.env` files: parsing, and setting a variable while keeping the rest.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|input: (&str, &str)| {
    let (text, value) = input;
    let _ = cemi::dotenv::parse(text);
    let key = "FUZZ_KEY";
    if let Ok(updated) = cemi::dotenv::set(text, key, value) {
        // A value that was set reads back exactly.
        if let Ok(Some(read)) = cemi::dotenv::get(&updated, key) {
            assert_eq!(read, value);
        }
    }
});
