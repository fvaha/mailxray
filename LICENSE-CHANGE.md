# License history

Three states, in order. Licenses already granted are not revoked by later
changes — if you took a copy under an earlier license, that copy stays yours
under those terms.

| # | State | Applies to |
|---|---|---|
| 1 | **MIT** — `acc3696` … `docs: full English README …` | everything |
| 2 | **PolyForm Noncommercial 1.0.0** — `license: PolyForm Noncommercial 1.0.0` | everything |
| 3 | **Split: `mailxray-core` MIT / `mailxrayd` AGPL-3.0-only** — from this commit on | current |

## Why the current split

The engine is a library and a library is only useful when embedded, so it is
MIT (the Rust ecosystem default). The daemon is a service, so it is AGPL — free
to run anywhere, including inside a company, but anyone offering it to third
parties must publish their deployment's source, or take a
[commercial license](COMMERCIAL.md).

This mirrors Stalwart, Grafana and mupdf: an open core that people actually
adopt, with a paid exception for the case where publication is unacceptable.

Full reasoning: [LICENSING.md](LICENSING.md).

## Consequences

- Code from states 1 and 2 stays available to you under those terms.
- From state 3 on, `crates/mailxray-core` is MIT and `crates/mailxrayd` is
  AGPL-3.0-only. `mailxrayd` links `mailxray-core`, which is fine: MIT code may
  be included in an AGPL work.
- Contributions are accepted under [CONTRIBUTING.md](CONTRIBUTING.md); the daemon
  additionally requires a relicensing grant so that commercial licenses remain
  possible for every line of it.

The changes were made by the sole copyright holder, so no third-party consent
was required.
