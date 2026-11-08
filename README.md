# mailxray

Structural inspection of untrusted mail attachments — without opening them.

mailxray reads an attachment, says what it really is, what is inside it, and
whether it should reach a user. It never executes, never renders, and never
needs a signature database.

```
$ curl -s -X POST --data-binary @attach.zip 'localhost:8377/inspect?name=attach.zip'
{
  "schema": 1,
  "real_type": "zip",
  "verdict": "blocked",
  "reasons": [
    { "code": "executable-inside", "detail": "invoice.pdf.exe: content is pe", "severity": "blocked" }
  ],
  "details": { "kind": "archive", "format": "zip", "listed": true, "entries": [ … ] }
}
```

## Why

Mail-borne infection is a delivery problem: ~25% of malicious attachments are
ZIP, ~11% HTML, ~8% RAR, ~6% 7z. Handing those to a user — or to a browser — is
the risk. mailxray answers three questions in milliseconds:

1. What is this, really? (magic bytes, not the filename)
2. What is inside it? (archive tree, per-entry verdicts, nesting)
3. Does it carry active content? (PDF `/Launch`/`/JavaScript`, Office macros,
   external relationships)

## What it inspects

| Format | Depth |
|---|---|
| ZIP, tar, gzip | full tree, nested up to `max_depth`, per-entry verdicts |
| RAR, 7z, bzip2, xz, zstd | recognised; listing needs the external handler (tier 1) |
| PDF | pages, `/OpenAction`, `/AA`, `/Launch`, JS + snippets, embedded files, XFA, RichMedia, SubmitForm, links/hosts; deep pass decompresses every stream |
| DOCX/XLSX/PPTX | macros, external relationships (remote template/DDE), embedded objects |
| DOC/XLS/PPT (OLE2) | VBA project, embedded objects |
| PE/ELF/Mach-O/ISO/LNK/scripts | refused on sight |

PDF and Office are never rendered: PDF preview belongs to the browser (served
from an isolated origin), Office is shown as structure + verdict + download.

## Build and run

```bash
cargo build --release
MAILXRAY_ADDR=127.0.0.1:8377 MAILXRAY_STORE=/var/lib/mailxray ./target/release/mailxrayd
```

```
POST /inspect?name=<filename>   body = raw attachment bytes (≤ 50 MB)
GET  /report/{blake3}           cached report
GET  /health
```

Reports are content-addressed by `blake3` of the decoded bytes, so an attachment
delivered to 100 recipients is inspected once.

## Guarantees

- memory-safe parsers (`zip`, `cfb`, `lopdf`), no C, no FFI;
- bounded work: entry caps, decompression budgets, ratio limits, recursion depth;
- a file that was not fully inspected is **never** reported clean — caps produce
  `partial` with a reason;
- no network, no execution, no rendering, no credentials.

The full report contract (fields, verdicts, reason codes, policy defaults) is in
[SPEC.md](SPEC.md).

## Kao biblioteka

```rust
let report = mailxray_core::inspect(Some("invoice.pdf"), &bytes, &Policy::default());
if report.verdict == mailxray_core::Verdict::Blocked {
    // refuse at SMTP
}
```

## Status

0.1.0 — tier 0 only. Planned: tier 1 external handlers for RAR/7z (bwrap +
landlock + cgroup), and a milter integration in RustMailStack.

License: MIT.
