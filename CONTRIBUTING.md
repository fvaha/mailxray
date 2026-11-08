# Contributing

Thanks for looking. Two things to know before you open a pull request.

## 1. License of contributions

Contributions are accepted under **AGPL-3.0-only**, the license of the whole
project. By submitting a change you agree to that, and you grant the licensor a
perpetual, worldwide, royalty-free, irrevocable right to relicense your
contribution. Without it, the project cannot offer commercial licenses.

## 2. What fits the design

The project has a deliberate shape: see [README.md](README.md) and
[SPEC.md](SPEC.md). In particular:

- **no rendering, no execution, no network** in the inspection path;
- **memory-safe parsers only** in tier 0; anything in C/C++ belongs behind the
  tier 1 sandbox;
- **bounded work everywhere**: a new parser is expected to have caps for entry
  count, decompression, recursion and time;
- **never report `clean` for a file that was not fully inspected**;
- **the report contract in `SPEC.md` changes first**, code second.

## Local checks

```bash
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
```

Both must pass; CI runs exactly this on Linux and macOS.

## Fixtures

Tests build their fixtures in code (`crates/mailxray-core/tests/inspect.rs`),
no binary samples in the repository. Please keep it that way: a malicious sample
committed "for testing" is a liability, and a generated one is reproducible.
