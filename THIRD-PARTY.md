# Third-party components

mailxray links only permissively licensed crates. There is **no copyleft**
(GPL/LGPL/AGPL/MPL/SSPL/BUSL/EPL) anywhere in the dependency graph — verified
with:

```bash
cargo tree -e normal --prefix none --format '{p}|{l}' | grep -iE 'gpl|mpl|sspl|busl|epl|cddl'
# → no matches
```

Direct dependencies:

| Crate | License | Used for |
|---|---|---|
| `serde` | MIT OR Apache-2.0 | report serialisation |
| `sha2` | MIT OR Apache-2.0 | SHA-256 in reports |
| `blake3` | CC0-1.0 OR Apache-2.0 | content-addressed cache key |
| `zip` | MIT | ZIP/tar listing, OOXML containers |
| `flate2` | MIT OR Apache-2.0 | gzip (single-stream archives) |
| `lopdf` | MIT | PDF object graph and streams |
| `cfb` | MIT | OLE2 (legacy Office) containers |
| `thiserror` | MIT OR Apache-2.0 | error types |
| `axum` | MIT | HTTP daemon |
| `tokio` | MIT | async runtime for the daemon |

Transitive dependencies (132 crates at the time of writing) are MIT,
Apache-2.0, BSD-3-Clause, ISC, Zlib, CC0, Unlicense or 0BSD. Regenerate the
current list with:

```bash
cargo tree -e normal --prefix none --format '{p}|{l}' | sort -u
```

Their license texts ship with the crate sources under `~/.cargo/registry/`, and
`cargo deny` (or `cargo about`) can produce a full attribution bundle if you
need one for distribution.

Note that the **PolyForm Noncommercial license applies to mailxray itself**, not
to its dependencies: those remain available to you under their own permissive
terms, independently of any commercial license you may need for mailxray.
