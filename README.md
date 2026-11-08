# mailxray

**Structural inspection of untrusted mail attachments — without opening them.**

mailxray takes one attachment, says what it really is, what is inside it, and
whether it should reach a user's mailbox. It never executes anything, never
renders anything, and needs no signature database.

```
$ curl -s -X POST --data-binary @attach.zip 'localhost:8377/inspect?name=attach.zip'
{
  "schema": 1,
  "real_type": "zip",
  "verdict": "blocked",
  "reasons": [
    { "code": "executable-inside",
      "detail": "invoice.pdf.exe: content is pe",
      "severity": "blocked" }
  ],
  "details": {
    "kind": "archive", "format": "zip", "listed": true, "depth": 0,
    "entries": [
      { "name": "invoice.pdf.exe", "size": 8, "ratio": 1.0,
        "class": "pe", "verdict": "blocked" },
      { "name": "readme.txt", "size": 2, "ratio": 1.0,
        "class": "text", "verdict": "clean" }
    ]
  }
}
```

---

## Why this exists

Mail-borne infection is a *delivery* problem, not a payload problem. Look at what
actually arrives: archives and scripts, almost never a bare executable.

| Attachment type | Share of malicious attachments |
|---|---|
| ZIP | ~25% |
| PDF | ~13% |
| HTML | ~11% |
| RAR | ~8% |
| 7z | ~6% |

<sub>Order of magnitude from public phishing-trend reporting; the exact split
moves month to month.</sub>

An antivirus answers "is this file known-bad?" — and answers it late, expensively
(around 1 GB of RAM for a signature database) and, against a fresh payload, often
wrongly. But the user facing the attachment has a much simpler question:

> What *is* this, what is *inside* it, and is it dangerous to touch?

That question is answerable in **milliseconds** from the bytes alone. That is
what mailxray does.

Three concrete wins:

1. **`invoice.pdf.exe` never gets clicked.** The effective type is decided by
   magic bytes, and the mismatch with the declared extension is reported.
2. **`attachment.zip` is shown as a tree**, not a mystery box: names, real types,
   sizes, compression ratios and a verdict per entry — including one level of
   nesting.
3. **`statement.pdf` with `/OpenAction` + JavaScript** is caught before a browser
   ever parses it, including when the JavaScript is hidden inside a compressed
   stream or behind a name escape (`/Ja#76aScript`).

---

## What it inspects

| Format | What you get |
|---|---|
| **ZIP, tar, gzip** | full entry tree, per-entry verdicts, nesting up to `max_depth`, path-traversal and zip-bomb detection |
| **RAR, 7z, bzip2, xz, zstd** | recognised by magic; entry listing requires the external handler (tier 1, see [Roadmap](#roadmap)) |
| **PDF** | pages, `/OpenAction`, `/AA`, `/Launch`, JavaScript (with a snippet of the code), embedded files, XFA, RichMedia, SubmitForm, link targets and their hosts — plus a **deep pass** that decompresses every stream and searches it for hidden active content |
| **DOCX / XLSX / PPTX** | VBA macro project, external relationships (remote template injection / DDE), embedded OLE objects |
| **DOC / XLS / PPT (OLE2)** | VBA project, embedded objects, stream list |
| **PE / ELF / Mach-O / ISO / LNK / scripts** | refused on sight, whatever the filename says |
| **HTML / SVG** | recognised as executable-class content (they run in a browser, not in yours) |

Every report carries BLAKE3 + SHA-256, the declared extension, the real type and
a `type_mismatch` flag.

---

## What it deliberately does **not** do

This is a design position, not a missing feature.

- **No rendering.** No thumbnails, no page images, no LibreOffice, no PDFium, no
  headless browser. Rendering untrusted documents is where the 0-days live, and
  it costs 100–800 ms and 26–150 MB per file. A PDF preview belongs to the
  browser, served from an isolated origin; an Office document is shown as
  structure + verdict + a deliberate download. Only archives are displayed in
  detail, because a tree is what a user actually needs to decide.
- **No signature database.** No ClamAV, no YARA. Those answer a different
  question; see [Roadmap](#roadmap) for how they compose.
- **No mail access.** mailxrayd never fetches mail and holds no credentials. It
  receives one attachment and returns one report.
- **No network.** Ever.

---

## How it works

```
                      ┌──────────────────────────────┐
  attachment bytes ──▶│ magic-byte type detection    │
                      └──────────────┬───────────────┘
                                     │
        ┌────────────┬───────────────┼──────────────┬─────────────┐
        ▼            ▼               ▼              ▼             ▼
      archive       PDF            OOXML          OLE2       executable
   (zip/tar/gz)  (object        (zip + xml)      (cfb)       → refused
                  graph +
                  streams)
        └────────────┴───────────────┴──────────────┴─────────────┘
                                     │
                             ┌───────▼─────────┐
                             │ policy: verdict  │  clean / suspicious / blocked
                             └───────┬──────────┘
                                     │
                       content-addressed report (BLAKE3)
```

Everything runs in-process with memory-safe parsers (`zip`, `cfb`, `lopdf` — no
C, no FFI). Work is bounded everywhere: entry caps, decompression budgets,
compression-ratio limits, recursion depth, object-walk budget.

### The invariant

> **A file that was not fully inspected is never reported `clean`.**

Any cap that is hit produces `partial` or `suspicious` with the reason attached —
never silence. A 400 MB PDF that could not be fully decompressed is reported as
`pdf-partial-scan`, not as fine.

---

## Sandboxing: what it is for, and what it costs

mailxray is tier 0: it never runs another program, so it needs no sandbox. A
sandbox becomes necessary the moment a *real* parser has to run on the bytes —
`unrar`, `7zz`, `libarchive`, a document converter. Those are C/C++ programs
parsing attacker-controlled input, and that is the part worth isolating.

The design therefore has three tiers, and each format handler picks the cheapest
one that can do its job:

| Tier | Mechanism | Cost (measured) | Used for |
|---|---|---|---|
| **0** | in-process, memory-safe Rust parsers, bounded work | **0.2–2 ms**, 5–14 MB RSS | everything implemented today: ZIP, tar, gzip, PDF, OOXML, OLE2 |
| **1** | `bwrap` (namespaces) + Landlock (filesystem) + seccomp + cgroup `MemoryMax` + wall-clock timeout | **+3 ms** (Landlock), **+8–10 ms** (bwrap), **~0 MB RSS** | external handlers: `unrar`, `7zz`, `libarchive`, poppler |
| **2** | Firecracker microVM | **7.7 MB VMM RSS**, ~2.3 s boot | anything that renders or executes: LibreOffice, unknown binaries |

<sub>Measured on Debian 13, kernel 6.12, Xeon E5-2620. A 20 000-iteration
open/read/close/stat loop ran at 8.0–10.8 µs/op bare versus 7.9–9.9 µs/op inside
bwrap — no measurable syscall cost. `MemoryMax=64M` against a 512 MB allocation
exits 137 with `CONSTRAINT_MEMCG` in the kernel log; a 32 MB allocation passes.
Unpacking 38 MB from a ZIP cost 51 MB RSS bare and 51–52 MB sandboxed.</sub>

The point of those numbers: **isolation is nearly free; what costs memory is the
program you put inside it.** Landlock + seccomp + namespaces + cgroup add
effectively zero RAM and zero syscall overhead. The 51 MB was Python's `zipfile`
unpacking 38 MB — the parser's cost, not the sandbox's.

Two rules for tier 1 when it lands:

- **Limits are enforced from outside** (cgroup, rlimits, wall clock), never by the
  tool's own configuration.
- **Nothing is shared** with the handler: no network namespace, no view of the
  mail store, input as a read-only bind, output collected from a tmpfs, and the
  child dies with its parent.

---

## Policy

Defaults, all configurable:

```
block_executables         true    # PE/ELF/Mach-O/ISO/LNK/scripts
block_macro_office        true    # VBA in OOXML or OLE2
block_active_pdf          true    # /Launch, JavaScript, embedded payloads
block_encrypted_archives  true    # cannot be inspected → refused
max_depth                 2       # nested archives listed
max_entries               2000    # per archive
max_uncompressed_bytes    64 MiB  # total per attachment
max_ratio                 200     # size/compressed, for members over 1 MiB
deep_pdf                  true    # decompress streams looking for hidden content
max_pdf_decompress_bytes  64 MiB
```

Refused extensions, regardless of content:

```
exe dll ocx cpl scr pif sys drv com msi msp msix
js jse mjs vbs vbe wsf wsh hta ps1 psm1 bat cmd reg sct shb lnk url scf
iso img vhd vhdx vmdk dmg one
docm dotm xlsm xltm pptm potm xlam
jar apk chm
```

The full list of reason codes and the JSON contract are in **[SPEC.md](SPEC.md)**.

---

## Run it

```bash
cargo build --release
MAILXRAY_ADDR=127.0.0.1:8377 MAILXRAY_STORE=/var/lib/mailxray \
  ./target/release/mailxrayd
```

```
POST /inspect?name=<filename>   body = raw attachment bytes (≤ 50 MB) → report
GET  /report/{blake3}           cached report
GET  /health
```

Reports are content-addressed by `blake3` of the *decoded* bytes, so an attachment
delivered to 100 recipients is inspected once and the webmail can fetch its card
without re-uploading anything.

Typical cost: **0.2–2 ms** for archives, Office and shallow PDF; **~30–80 ms** for
a multi-megabyte PDF with the deep stream pass — once per content hash.

## Use it as a library

```rust
use mailxray_core::{inspect, Policy, Verdict};

let report = inspect(Some("invoice.pdf"), &bytes, &Policy::default());
if report.verdict == Verdict::Blocked {
    // refuse at SMTP time
}
```

The mail path can call the daemon over HTTP or link the crate directly — the
report is the same struct either way.

---

## Guarantees and limits

**Guarantees**

- parsers are memory-safe Rust; there is no C in the inspection path;
- every loop is bounded: a malicious file cannot make one attachment cost
  unbounded time or memory;
- caps surface as a verdict with a reason, never as a silent "clean";
- no execution, no rendering, no network, no credentials.

**Limits — read these before trusting it**

- mailxray describes *structure and intent*, not identity. It cannot tell you that
  a clean-looking ZIP contains a novel payload; it tells you there is an
  executable inside it, which is usually the same decision.
- RAR/7z/bzip2/xz/zstd are recognised but not listed until tier 1 exists; those
  reports say `container-not-listed` rather than pretending otherwise.
- Encrypted archives and encrypted PDFs cannot be inspected; policy refuses them.
- A determined attacker can build a payload with no distinguishing structure.
  mailxray raises the cost of the cheap attacks that make up almost all mail
  abuse; it is not a substitute for endpoint protection.

---

## Roadmap

- [ ] **Tier 1 handlers** — RAR, 7z, bzip2, xz, zstd entry listing via
      `unrar`/`7zz`/`libarchive` inside a bwrap + Landlock + cgroup sandbox.
- [ ] **Milter integration** — call `/inspect` from the SMTP path, annotate every
      attachment, refuse blocked ones at DATA.
- [ ] **Nesting policy per format**, and extraction of a single safe member
      (image/PDF) for preview.
- [ ] Optional digest lookup (VirusTotal / hash feeds) as a *separate* step that
      never touches the sandbox.

## Status

`0.1.0` — tier 0 complete: type detection, archive listing, PDF active content,
OOXML/OLE2 structure, policy engine, HTTP daemon, 20 tests, clippy clean.

---

## License

**Free for personal and other noncommercial use. Commercial use requires a paid
license.**

mailxray is source-available under the
[PolyForm Noncommercial License 1.0.0](LICENSE): you may read it, run it, modify
it and share it for any noncommercial purpose — home mail servers, study,
research, hobbies, and by charities, schools, public research and government
institutions. Running it as part of a company's mail service, embedding it in a
product, or using it to deliver paid work requires a
[commercial license](COMMERCIAL.md).

There is no copyleft and no forced publication of your changes; the only line is
commercial versus noncommercial. See [COMMERCIAL.md](COMMERCIAL.md) for what
counts as commercial, what a license covers, and how to get one.

Contributions are accepted under the terms in [CONTRIBUTING.md](CONTRIBUTING.md).
Earlier commits were published under MIT — see [LICENSE-CHANGE.md](LICENSE-CHANGE.md).
Third-party components are permissively licensed: [THIRD-PARTY.md](THIRD-PARTY.md).
