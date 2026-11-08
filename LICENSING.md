# Licensing

mailxray is two things with two licenses, split along the crate boundary. This
is deliberate: the library should spread, the service should be paid for.

| Component | Path | License |
|---|---|---|
| **`mailxray-core`** — the inspection engine (library) | `crates/mailxray-core` | **MIT** ([text](crates/mailxray-core/LICENSE)) |
| **`mailxrayd`** — the HTTP daemon / service | `crates/mailxrayd` | **AGPL-3.0-only** ([text](LICENSE)) |
| Everything else in this repository (docs, CI, specs) | — | AGPL-3.0-only |

## Why this split

**The library is MIT** because an inspection engine is only useful when it is
embedded — in a mail server, a webmail, a scanner, a CI pipeline. A restrictive
license on a crate means nobody links it. MIT (the Rust ecosystem default) is
what makes `mailxray-core` a candidate for "the crate you reach for when you
need to look inside an attachment".

**The daemon is AGPL-3.0** because it is a *service*. Anyone may run it, study
it, modify it and self-host it — including inside a company. But if you offer it
to others as a service, or ship it inside a product, you must publish the source
of your whole deployment. Companies that cannot do that buy a
[commercial license](COMMERCIAL.md) instead.

This is the same shape used by Stalwart (the mail server this project was
written for), Grafana, MinIO and mupdf: an open, credible core, with a paid
exception for the case where publication is unacceptable.

## What this means in practice

- You can `cargo add mailxray-core` in **any** project, commercial or not, and
  the only obligation is keeping the MIT notice. No copyleft, no publication.
- You can run `mailxrayd` at home, in a charity, a school, a research lab or
  internally in a company, for free.
- If you run `mailxrayd` as part of a service other people use, AGPL §13 applies:
  those users must be offered the corresponding source — including your
  modifications — or you hold a commercial license.
- The two licenses are compatible in the direction this project uses them:
  MIT code can be included in an AGPL work, which is exactly what `mailxrayd`
  does. `mailxray-core` itself stays MIT for everyone else.

## Commercial licensing

See [COMMERCIAL.md](COMMERCIAL.md). A commercial license exists to remove the
AGPL obligations for deployments that cannot publish their source; it is not
required for the free cases above.

## History

Earlier commits were published under MIT, then briefly under PolyForm
Noncommercial. See [LICENSE-CHANGE.md](LICENSE-CHANGE.md) — licenses already
granted are not revoked by these changes.
