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
| **RAR, 7z** | full entry tree via 7-Zip, run inside the tier 1 sandbox (no network, read-only system, wall-clock timeout) |
| **bzip2, xz, zstd** | recognised by magic; single-stream formats, so there is no tree to list |
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
| **1** | `bwrap` (namespaces) + Landlock (filesystem) + seccomp + cgroup `MemoryMax` + wall-clock timeout | **+3 ms** (Landlock), **+8–10 ms** (bwrap), **~0 MB RSS** | **7-Zip: RAR/7z listing and single-member extraction (implemented)**; poppler, libarchive, LibreOffice later |
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

Two rules for tier 1, as implemented in `crates/mailxrayd/src/sandbox.rs`:

- **Limits are enforced from outside** (wall clock, output cap), never by the
  tool's own configuration.
- **Nothing is shared** with the handler: no network namespace, read-only system
  binds, the archive bound read-only, one private writable work dir, and the
  child dies with its parent.

`MAILXRAY_SANDBOX=auto|bwrap|off` selects the mode; `auto` (the default) uses
bwrap when it is installed and falls back to no isolation otherwise, with a
startup line in the log saying which one is active. In production: keep it on
bwrap, and put `MemoryMax=` on the systemd unit so the whole tree is cgroup-capped.

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
POST /entry?path=<member>       body = raw archive bytes → one member (preview)
GET  /report/{blake3}           cached report
GET  /health
```

Reports are content-addressed by `blake3` of the *decoded* bytes, so an attachment
delivered to 100 recipients is inspected once and the webmail can fetch its card
without re-uploading anything.

Typical cost: **0.2–2 ms** for archives, Office and shallow PDF; **~30–80 ms** for
a multi-megabyte PDF with the deep stream pass — once per content hash. RAR/7z
listing goes through 7-Zip in the sandbox: **~10 ms** of sandbox overhead on top
of the tool's own run time.

### `POST /entry` — opening one member

The caller sends the archive bytes it already has (a webmail has the blob from
its mail server), plus the member path. The daemon extracts **that one member**
inside the tier 1 sandbox and returns it only if the bytes are inert — image,
PDF, text, audio or video, decided by magic bytes rather than by the name. An
`invoice.png` that is really a PE is refused with `415`. Members over 8 MB are
refused, and the path is validated (`..`, absolute paths and a leading `-` are
rejected before anything runs).

That is what makes a preview wrapper possible without ever handing the original
file to the client: the wrapper shows a rasterised/served member, not the
attachment.

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

- [x] **Tier 1 handlers** — RAR/7z listing and single-member extraction via
      7-Zip inside a bwrap sandbox (no network, read-only system, timeout, output
      cap).
- [ ] **poppler/libarchive handlers** — PDF text extraction, and formats 7-Zip
      does not cover.
- [ ] **Milter integration** — call `/inspect` from the SMTP path, annotate every
      attachment, refuse blocked ones at DATA.
- [ ] **Nesting policy per format**, and `path` on each entry so nested members
      say which container they came from.
- [ ] Optional digest lookup (VirusTotal / hash feeds) as a *separate* step that
      never touches the sandbox.

## Using it from any webmail

The service speaks JSON only — it never returns HTML, because a webmail that
embedded such HTML would inherit the service's XSS surface. To make that JSON
pleasant without coupling, the repository ships a reference renderer:

```
web/mailxray-card.js    MailxrayCard.render(report, { entryUrl }) -> HTMLElement
web/mailxray-card.css
web/demo.html           open it next to a running daemon to see the output
```

```js
fetch("/mailxray/inspect?name=" + encodeURIComponent(name), { method: "POST", body: blob })
  .then((r) => r.json())
  .then((report) => {
    panel.append(MailxrayCard.render(report, {
      entryUrl: (member) =>
        "https://attach.example.com/entry?path=" + encodeURIComponent(member),
    }));
  });
```

It is built with DOM nodes and `textContent` — no `innerHTML`, no `eval` — so a
member named `<img src=x onerror=alert(1)>.zip` renders as text. Point
`entryUrl` at an **isolated origin** (not the webmail's), without cookies, and
the `open` link becomes a preview the user can click inside your own wrapper.

## Status

`0.2.0` — tier 0 inspection (type detection, archive listing, PDF active
content, OOXML/OLE2 structure, policy engine), tier 1 sandbox with 7-Zip for
RAR/7z listing and member extraction, HTTP daemon with `/inspect`, `/entry`,
`/report`, and a reference UI renderer. 23 tests, clippy clean.

---

## License

**AGPL-3.0-only** — see [LICENSE](LICENSE). Free to run, modify and self-host,
including inside a company. If you offer it to others as a service or ship it in
a closed product, the AGPL requires you to publish your deployment's source; if
that does not work for you, contact the author about a commercial license.
