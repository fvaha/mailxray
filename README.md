# mailxray

**Looks inside untrusted mail attachments without opening them.**

One attachment goes in. This comes back:

- **What the bytes really are**, decided by magic bytes and not by the filename.
  `invoice.pdf.exe` is reported as a PE with a lying extension.
- **What is inside an archive**: every member with its real type, size,
  compression ratio and its own verdict, through two levels of nesting, plus
  zip-bomb and path-traversal checks. RAR and 7z included, listed by 7-Zip
  inside a sandbox.
- **What a document carries**: PDF `/OpenAction`, `/Launch`, JavaScript with a
  snippet of the code, embedded files, XFA, SubmitForm; Office macros and
  external template links.
- **A verdict and its reasons**: `clean`, `suspicious`, `blocked` or `partial`,
  each reason with a stable code you can branch on.

And when the user clicks a file inside an archive, `POST /entry` extracts that
one member inside a bwrap sandbox (no network, no host filesystem, archive bound
read-only, wall-clock timeout, output cap) and hands back only inert content:
image, PDF or text. An executable that sat next to it in the same archive is
refused with `415`. The user sees the file, the browser never receives the
archive.

It does not execute anything, does not render documents, needs no signature
database, and has no access to mail.

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

## What it does, exactly

Two jobs, four endpoints. Nothing else.

| Endpoint | Input | Output | What it is for |
|---|---|---|---|
| `POST /inspect?name=` | attachment bytes | JSON report | what this is, what is inside it, is it dangerous |
| `POST /entry?path=` | archive bytes and member path | that member's bytes | showing one file inside an archive without handing over the archive |
| `GET /report/{blake3}` | nothing | cached JSON report | the webmail drawing a card later, without re-uploading |
| `GET /health` | nothing | status, version, sandbox mode | monitoring |

### Per format

| Format | What the report contains |
|---|---|
| **ZIP, tar, gzip** | every entry: name, real type, size, compression ratio, per-entry verdict; nesting up to `max_depth`; zip-bomb and path-traversal detection |
| **RAR, 7z** | the same tree, produced by 7-Zip running inside the sandbox |
| **bzip2, xz, zstd** | recognised; single-stream, so there is no tree (reported as such, not guessed) |
| **PDF** | page count, `/OpenAction`, `/AA`, `/Launch`, JavaScript actions with a snippet, embedded files, XFA, RichMedia, SubmitForm, link targets and their hosts, plus a deep pass that decompresses every stream and looks for the same markers hidden there |
| **DOCX / XLSX / PPTX** | VBA macro project present, external relationships (remote template or DDE), embedded OLE objects |
| **DOC / XLS / PPT (OLE2)** | VBA project, embedded objects, stream names |
| **PE / ELF / Mach-O / ISO / LNK / scripts** | refused on sight, and reported as such whatever the filename claims |
| **HTML / SVG** | identified as executable-class content, because they run in a browser |

Every report also carries BLAKE3 and SHA-256 of the decoded bytes, the declared
extension, the real type, and a `type_mismatch` flag when they disagree.

### Verdicts

`clean`, `suspicious`, `blocked` or `partial`, with `reasons[]`, each carrying a
machine-readable `code`, a human `detail` and a `severity`. The verdict is the
highest severity present.

**The invariant:** a file that was not fully inspected is never reported `clean`.
Caps and budgets produce `partial` or `suspicious` with a reason attached.

### What it deliberately does **not** do

- **No rendering.** No thumbnails, no page images, no LibreOffice, no PDFium, no
  headless browser. Rendering untrusted documents is where the 0-days live and
  costs 100 to 800 ms and 26 to 150 MB per file. A PDF preview belongs to the
  browser, served from an isolated origin. Office is structure, verdict and a
  deliberate download. Only archives are shown in detail, because a tree is what
  a user needs to decide.
- **No signature database.** Not an antivirus; see [Status and roadmap](#status-and-roadmap).
- **No mail access.** It never fetches mail and holds no credentials.
- **No network** from anything it runs.

---

## How it plugs into a real mail setup

Three shapes. A: webmail only (fastest to adopt). B: mail server at SMTP time
(the strongest). C: library embedded in your own milter, with no HTTP hop.

```
  A. webmail only                  B. mail server + webmail
  ---------------                  ------------------------

  user clicks an attachment        SMTP DATA -> your milter -> POST /inspect
        |                                                    |
        v                                                    +- blocked: reject 5.x
  webmail backend --> POST /inspect                          +- ok: deliver
        |
        +- card (JSON -> web/mailxray-card.js)              user opens it later:
        |                                                   webmail backend -> GET /report/{hash}
        +- user clicks "open"
             +-> POST /entry -> bytes of that one member
```

### A. Webmail: inspect on open, show a card, open a member

Recommended wiring: **the browser talks to your webmail backend, the backend
talks to mailxrayd.** mailxrayd sends no CORS headers and has no authentication,
so it is meant to sit on loopback behind the app that already knows who the user
is.

```js
// in the webmail frontend, when the user expands an attachment panel
const blob = await api.fetchAttachmentBlob(messageId, partId);   // your backend
const report = await api.inspect(blob, name);                    // backend: POST /inspect
panel.append(MailxrayCard.render(report, {
  entryUrl: (member) => api.entryUrl(hash, member),              // isolated origin
}));
```

The reference renderer is in this repository:

```
web/mailxray-card.js     MailxrayCard.render(report, { entryUrl }) -> HTMLElement
web/mailxray-card.css
web/demo.html            open next to a running daemon to see the output
```

It builds DOM nodes with `textContent`, no `innerHTML` and no `eval`, so a member
named `<img src=x onerror=alert(1)>.zip` renders as text.

For "open", the backend proxies `POST /entry` and returns the member from an
**isolated origin** (for example `attach.example.com`, no cookies, `nosniff`), so
a PDF exploit opening in the browser has nothing of the webmail to reach:

```html
<img src="https://attach.example.com/entry?hash=...&path=photo.png" alt="">
<iframe src="https://attach.example.com/entry?hash=...&path=doc.pdf"></iframe>
```

`POST /entry` only returns inert members (image, PDF, text, audio, video, decided
by magic bytes), so the wrapper can never be tricked into serving the executable
that was sitting next to them in the archive.

### B. Mail server: call it at SMTP time

Anything that can make an HTTP request during `DATA` can use it. The filter works
per message part: send each decoded attachment, collect verdicts, decide.

**Stalwart** (the stack this was written for): define an `MtaMilter` and point it
at a small milter of your own, which calls mailxrayd:

```
Settings > MTA > Filters > Milters > new
  host    = 127.0.0.1
  port    = 7357
  stages  = ["data"]
  tempFailOnError = true        # mailxrayd down means 451, never unfiltered delivery
```

**Postfix:** `smtpd_milters = inet:127.0.0.1:7357` plus the same milter.

**Rspamd:** a custom Lua rule that POSTs to `/inspect` and adds a symbol.

The milter itself is about 150 lines and not shipped yet (see
[Status and roadmap](#status-and-roadmap)). The shape is:

```rust
// at end-of-message: walk the MIME parts, send each one, act on the verdict
for part in message.attachments() {
    let report: Report = http.post("/inspect")
        .query(&[("name", part.filename())])
        .body(part.bytes())
        .send().await?.json().await?;

    if report.verdict == Verdict::Blocked {
        return Status::Reject;   // 5.7.1, with the reason codes in the reply
    }
}
```

Two rules that matter at this stage:

- **Fail closed.** If mailxrayd is unreachable, return `451` (a temporary
  failure) rather than delivering uninspected mail.
- **Inspect the decoded part**, not the wire form, so the hash you store is the
  same one the webmail will compute later.

### C. Embed the library

The inspection engine is a plain Rust library, so a milter written in Rust can
skip the HTTP hop entirely:

```rust
use mailxray_core::{inspect, Policy, Verdict};

let report = inspect(Some("invoice.pdf"), &bytes, &Policy::default());
if report.verdict == Verdict::Blocked {
    return Status::Reject;
}
```

Same structs, same reason codes, same JSON. The report serialises identically
whether it came from the daemon or from a linked crate.

### Why the report is content-addressed

`hash` is BLAKE3 of the decoded bytes, and reports are stored as
`<store>/<hash>.json`. So:

- one attachment delivered to 100 recipients is inspected **once**;
- the mail path can inspect at SMTP time and the webmail can later fetch the same
  report with `GET /report/{hash}`, with no second upload and no second parse;
- for mail that predates the deployment, the webmail calls `POST /inspect` once
  and the cache fills itself.

---

## API

### `POST /inspect?name=<filename>`

Body: raw decoded attachment bytes, up to 50 MB. Always answers `200` with a
report. A parse failure is a report with `pdf-unparsed` or `zip-unparsed` and
verdict `suspicious`, never a `500`.

`name` is untrusted; it is used only to compare the declared extension with the
content and to disambiguate text-ish files (`.js` is a script, not text).

### `POST /entry?path=<member>`

Body: the archive bytes the caller already has. Extracts **one** member.

| Condition | Response |
|---|---|
| member is image, PDF, text, audio or video (by magic bytes) | `200`, concrete `Content-Type`, `nosniff`, `inline` |
| member is anything else (`pe`, `zip`, `ole2`, ...) | `415` |
| member larger than 8 MB | `422` |
| `path` empty, longer than 1024 chars, absolute, leading `-`, containing `..`, `\` or NUL | `400` |
| extraction failed | `422` |

ZIP is extracted in-process; RAR and 7z go through 7-Zip inside the sandbox. The
daemon stores no archives, the caller supplies the bytes.

### `GET /report/{blake3}`

64 hex characters. `200` with the cached report, `400` for a malformed hash,
`404` when unknown.

### `GET /health`

```json
{"status":"ok","version":"0.2.0","schema":1,"sandbox":"Bwrap"}
```

`sandbox` is `Bwrap` or `Off`. Worth alerting on if it silently degrades.

Full field-by-field contract: **[SPEC.md](SPEC.md)**.

---

## Deploy

```bash
cargo build --release
MAILXRAY_ADDR=127.0.0.1:8377 \
MAILXRAY_STORE=/var/lib/mailxray \
MAILXRAY_SANDBOX=bwrap \
  ./target/release/mailxrayd
```

| Variable | Default | Meaning |
|---|---|---|
| `MAILXRAY_ADDR` | `127.0.0.1:8377` | listen address; keep it on loopback |
| `MAILXRAY_STORE` | `/var/lib/mailxray` | report cache, one JSON file per content hash |
| `MAILXRAY_SANDBOX` | `auto` | `auto` uses bwrap if installed, `bwrap` requires it, `off` disables isolation |
| `MAILXRAY_7Z` | probe | force a specific 7-Zip binary (`7zz`, `7z`, `7za` are probed) |

Requirements: `bubblewrap` and 7-Zip (`p7zip-full` on Debian) for RAR and 7z
support. Neither is needed for ZIP, tar, gzip, PDF or Office.

`/etc/systemd/system/mailxrayd.service`:

```ini
[Unit]
Description=mailxray attachment inspection
After=network.target

[Service]
ExecStart=/usr/local/bin/mailxrayd
Environment=MAILXRAY_ADDR=127.0.0.1:8377
Environment=MAILXRAY_STORE=/var/lib/mailxray
Environment=MAILXRAY_SANDBOX=bwrap
DynamicUser=yes
StateDirectory=mailxray
MemoryMax=256M
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=strict
ProtectHome=yes
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6
SystemCallFilter=@system-service
Restart=always

[Install]
WantedBy=multi-user.target
```

Notes for a public-ish deployment: it has no auth and no TLS, so put it behind
the reverse proxy that terminates both, or keep it on loopback. `MemoryMax` caps
the whole process tree, which includes the sandboxed 7-Zip children.

---

## Sandboxing

mailxray is tier 0 by default: it runs no other program, so it needs no sandbox.
Isolation starts the moment a real parser has to touch the bytes, which today
means 7-Zip for RAR and 7z, and eventually poppler or LibreOffice. Those are C
and C++ programs parsing attacker-controlled input, and that is the part worth
confining.

| Tier | Mechanism | Cost (measured) | Used for |
|---|---|---|---|
| **0** | in-process memory-safe Rust parsers, bounded work | **0.2 to 2 ms**, 5 to 14 MB RSS | ZIP, tar, gzip, PDF, OOXML, OLE2 |
| **1** | bwrap namespaces (user, mount, pid, net, ipc, uts), wall-clock timeout, output cap, whole tree cgroup-capped by the unit's `MemoryMax` | **+8 to 10 ms**, **about 0 MB RSS** | **7-Zip: RAR and 7z listing, member extraction** |
| **2** | Firecracker microVM | 7.7 MB VMM RSS, about 2.3 s boot | anything that renders or executes (not used yet) |

<sub>Measured on Debian 13, kernel 6.12, Xeon E5-2620. A 20 000-iteration
open/read/close/stat loop ran at 8.0 to 10.8 us/op bare versus 7.9 to 9.9 us/op
inside bwrap, so no measurable syscall cost. `MemoryMax=64M` against a 512 MB
allocation exits 137 with `CONSTRAINT_MEMCG` in the kernel log; 32 MB passes.
Unpacking 38 MB from a ZIP cost 51 MB RSS bare and 51 to 52 MB sandboxed.</sub>

What the sandboxed child gets, verified on a live host: no `/home` (the host
filesystem is not mounted), no writable system paths, no listening sockets, and a
network namespace containing only loopback. The archive is bound read-only, one
private directory is writable, and the child is killed on timeout.

---

## Policy

```
block_executables         true    # PE/ELF/Mach-O/ISO/LNK/scripts
block_macro_office        true    # VBA in OOXML or OLE2
block_active_pdf          true    # /Launch, JavaScript, embedded payloads
block_encrypted_archives  true    # cannot be inspected, so refused
max_depth                 2       # nested archives listed
max_entries               2000    # per archive
max_uncompressed_bytes    64 MiB  # total per attachment
max_ratio                 200     # size/compressed, for members over 1 MiB
deep_pdf                  true    # decompress streams looking for hidden content
max_pdf_decompress_bytes  64 MiB
```

Refused extensions regardless of content:

```
exe dll ocx cpl scr pif sys drv com msi msp msix
js jse mjs vbs vbe wsf wsh hta ps1 psm1 bat cmd reg sct shb lnk url scf
iso img vhd vhdx vmdk dmg one
docm dotm xlsm xltm pptm potm xlam
jar apk chm
```

---

## Guarantees and limits

**Guarantees**

- parsers are memory-safe Rust; there is no C in the inspection path;
- every loop is bounded, so a malicious file cannot make one attachment cost
  unbounded time or memory;
- caps surface as a verdict with a reason, never as a silent "clean";
- no execution, no rendering, no credentials, no network from inspected content.

**Limits, read before trusting it**

- it describes structure and intent, not identity. It cannot tell you that a
  clean-looking ZIP holds a novel payload, only that there is an executable
  inside it, which is usually the same decision;
- bzip2, xz and zstd are recognised but not listed; those reports say so;
- encrypted archives and encrypted PDFs cannot be inspected, and policy refuses
  them;
- a determined attacker can build a payload with no distinguishing structure.
  This raises the cost of the cheap attacks that make up almost all mail abuse.
  It is not endpoint protection.

---

## Status and roadmap

`0.2.0`: tier 0 inspection, tier 1 sandbox with 7-Zip, four endpoints, reference
UI renderer, 23 tests, clippy clean.

- [x] RAR and 7z listing and member extraction in a sandbox
- [ ] **milter** for Stalwart or Postfix that calls `/inspect` at `DATA` and
      returns `5.7.1` on blocked, and `451` when the service is down
- [ ] `path` per entry, so nested members say which container they came from
- [ ] poppler and libarchive handlers (PDF text extraction, formats 7-Zip misses)
- [ ] optional digest lookup (VirusTotal or hash feeds) as a separate step that
      never touches the sandbox

---

## License

**AGPL-3.0-only**, see [LICENSE](LICENSE). Free to run, modify and self-host,
including inside a company. If you offer it to others as a service or ship it in
a closed product, the AGPL requires you to publish your deployment's source. If
that does not work for you, contact the author about a commercial license.
