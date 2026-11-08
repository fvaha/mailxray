# Contributing

Thanks for looking. Two things to know before you open a pull request.

## 1. License of contributions

**`mailxray-core` is MIT:** by submitting a change there you agree it is
licensed under MIT, and you keep your copyright.

**`mailxrayd` is AGPL-3.0-only:** by submitting a change there you agree it is
licensed under the AGPL, **and** that you grant the licensor a perpetual,
worldwide, royalty-free, irrevocable license to use, relicense and distribute
your contribution under other terms, including a commercial license.

Without that second part the project cannot offer a commercial license at all,
because every contributor would hold a veto. If you are not comfortable with it,
an issue with a patch suggestion in prose is welcome instead.

## 2. What fits the design

The project has a deliberate shape — see [README.md](README.md) and
[SPEC.md](SPEC.md). In particular:

- **no rendering, no execution, no network** in the inspection path;
- **memory-safe parsers only** in tier 0; anything in C/C++ belongs behind the
  tier 1 sandbox;
- **bounded work everywhere** — a new parser is expected to have caps for entry
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

Tests build their fixtures in code (`crates/mailxray-core/tests/inspect.rs`) —
no binary samples in the repository. Please keep it that way: a malicious sample
committed "for testing" is a liability, and a generated one is reproducible.
