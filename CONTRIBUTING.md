# Contributing

Thanks for helping. Three rules matter more than any other:

1. **Never commit real data.** No real keys, tokens, passwords, project names, hosts or
   account ids — not in code, tests, docs, issues or screenshots. Examples use the fictional
   company `acme` and values like `cemi_test_not_real_…`. Tests create their keys while they run.
   Install the hook before your first commit: `cemi hook install` (and gitleaks if you have it).
2. **No invented cryptography.** Use age and the RustCrypto crates as they are. Changes to
   `crypto.rs`, `vault.rs` or the on-disk format need a clear explanation and tests.
3. **Permissive licenses only.** New dependencies must pass `cargo deny check`
   (MIT, Apache-2.0, BSD, ISC, Zlib…). No GPL, AGPL, LGPL or SSPL.

## Before opening a pull request

```bash
cargo fmt
cargo clippy --all-targets -- -D warnings
cargo test
cargo deny check
```

Tests never touch your real vault or credential store: they set `CEMI_HOME`,
`CEMI_TEST_SESSION_DIR` and `CEMI_INSECURE_FAST_KDF` (the last two only work in debug builds).

## Style

- Messages to the user are short and say what to do next.
- A value is never accepted as a command-line argument and never printed, except by
  `cemi reveal` after asking for the password again.
- Comments explain why, not what.
