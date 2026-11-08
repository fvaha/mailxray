# mailxray — the report contract

Version 1. This file is the interface between the mail path (milter) and the
webmail (IRIS). Field names and reason codes are part of the API; changing them
is a schema bump.

## What mailxray is

Structural inspection of untrusted attachments, without opening them:

- reads bytes, never executes or renders anything;
- memory-safe parsers only (ZIP/OLE2/PDF/XML), bounded work, no network;
- one report per attachment, cached by content hash.

## What mailxray is not

- not a renderer (no thumbnails, no page images, no LibreOffice);
- not an antivirus (no signature database, no heuristics beyond structure);
- not a mail client (it never fetches mail and holds no credentials).

PDF preview belongs to the browser (served from an isolated origin); Office is
delivered as structure + verdict + download. Archives are the only thing
mailxray displays in detail, because a tree is what a user needs to decide.

## HTTP API

```
POST /inspect?name=<filename>        body: raw attachment bytes (max 50 MB)
POST /entry?path=<member>            body: raw archive bytes → one member
GET  /report/{blake3-hex}            cached report
GET  /health
```

`POST /entry` returns the bytes of a single archive member, for a preview wrapper:

- **only inert classes** are returned — `image`, `pdf`, `text`, `audio`, `video` —
  decided by magic bytes of the extracted content, not by the member name;
  anything else is `415`;
- members larger than **8 MB** are refused;
- `path` is rejected if it is empty, longer than 1024 chars, absolute, starts
  with `-`, contains `..`, `\` or NUL;
- ZIP is extracted in-process; RAR/7z go through 7-Zip inside the tier 1
  sandbox;
- the caller supplies the archive bytes, so the daemon stores no attachments.

`POST /inspect` always answers `200` with a report — a parse failure is a report
with `pdf-unparsed` / `zip-unparsed` / … and verdict `suspicious`, never a 500.
The report is written to the store as `<store>/{hash}.json` and `GET /report`
reads it back, so the webmail can fetch reports without re-uploading bytes.

`name` is untrusted. It is used only to compare the declared extension with the
real content and to disambiguate text-ish files (`.js` is a script, not text).

## Report

```json
{
  "schema": 1,
  "hash": "<blake3 of the decoded bytes>",
  "sha256": "<sha256 of the decoded bytes>",
  "size": 234,
  "name": "attach.zip",
  "declared_ext": "zip",
  "real_type": "zip",
  "type_mismatch": false,
  "verdict": "blocked",
  "reasons": [
    { "code": "executable-inside", "detail": "invoice.pdf.exe: content is pe", "severity": "blocked" }
  ],
  "details": { "kind": "archive", "...": "see below" }
}
```

- `hash` is the cache key: `blake3(decoded attachment bytes)`. Both sides must
  compute it over the *decoded* part (after base64/QP), not the wire form.
- `real_type` is one of: `pdf zip rar4 rar5 7z gzip bzip2 xz zstd tar ole2 pe
  elf macho iso lnk html svg script text image audio video unknown`.
- `verdict`: `clean` | `suspicious` | `blocked` | `partial`.
- `severity`: `info` | `suspicious` | `blocked`. Verdict is the maximum severity
  present; `partial` means "recognised but not fully inspected".

### details

`kind` discriminates:

```jsonc
// archive
{ "kind": "archive", "format": "zip", "listed": true,
  "entries": [ { "name": "a.txt", "size": 2, "compressed_size": 2,
                 "ratio": 1.0, "class": "text", "verdict": "clean" } ],
  "total_uncompressed": 10, "encrypted": false, "truncated": false, "depth": 0 }

// pdf
{ "kind": "pdf", "pages": 1, "objects": 12, "encrypted": false,
  "javascript": ["this.exportDataObject({cName:'x', nLaunch:2})"],
  "launch": false, "open_action": true, "additional_actions": false,
  "embedded_files": 0, "xfa": false, "rich_media": false, "submit_form": false,
  "links": ["http://evil.example/login"], "hosts": ["evil.example"],
  "decompressed_bytes": 4096, "truncated": false }

// office (ooxml)
{ "kind": "ooxml", "format": "docx", "macros": true,
  "external_rels": ["http://evil.example/t.dotm"], "embedded_objects": 0,
  "entries": 12 }

// office (legacy ole2)
{ "kind": "ole", "has_vba": true, "has_embedded": false,
  "streams": ["/WordDocument", "/Macros/VBA/ThisDocument"] }

// nothing format-specific
{ "kind": "none" }
```

## Reason codes

| code | severity | meaning |
|---|---|---|
| `blocked-type` | blocked | content is PE/ELF/Mach-O/ISO/LNK/script |
| `blocked-extension` | blocked | declared extension is on the refuse list |
| `executable-inside` | blocked | archive member is executable or has a refused extension |
| `archive-bomb` | blocked | member ratio above `max_ratio` at size |
| `path-traversal` | blocked | member name escapes the archive root |
| `macro-present` | blocked*, *suspicious when `block_macro_office=false` | VBA project in OOXML/OLE2 |
| `pdf-launch` | blocked | `/Launch` — can start a program |
| `pdf-javascript` | blocked* | JavaScript action (severity raised when it runs on open) |
| `pdf-embedded-payload` | blocked | embedded file objects (dropper carrier) |
| `pdf-open-action` | blocked | action fires automatically on open |
| `pdf-submit-form` | blocked | data exfiltration |
| `pdf-xfa` | blocked | scriptable XFA form |
| `pdf-rich-media` | blocked | embedded player |
| `pdf-hidden-javascript` | suspicious | JavaScript marker inside a compressed stream |
| `pdf-hidden-launch` | suspicious | `/Launch` inside a compressed stream |
| `pdf-hidden-embedded` | suspicious | embedded-file marker inside a compressed stream |
| `pdf-encrypted` | suspicious | encrypted; active content cannot be ruled out |
| `pdf-partial-scan` | suspicious | decompression budget reached — **never reported clean** |
| `pdf-links` | info | link count and distinct hosts |
| `external-references` | suspicious | OOXML external relationship (remote template/DDE) |
| `embedded-objects` | suspicious | OLE object embedded in a document |
| `type-mismatch` | suspicious | declared extension does not match content |
| `container-not-listed` | suspicious | bzip2/xz/zstd recognised, no tree to list (RAR/7z are listed by the tier 1 handler, which removes this reason) |
| `archive-entry-cap` | suspicious | entry count above `max_entries` |
| `archive-partial-scan` | suspicious | decompression budget reached |
| `*-unparsed` | suspicious | the format handler failed; the file was not inspected |

## Policy defaults

```
block_executables        true
block_macro_office       true
block_encrypted_archives true
block_active_pdf         true
max_depth                2          # nested archives listed
max_entries              2000       # per archive
max_uncompressed_bytes   64 MiB     # total per attachment
max_ratio                200        # size/compressed above 1 MiB member
deep_pdf                 true       # decompress streams looking for hidden content
max_pdf_decompress_bytes 64 MiB
```

Invariant: **a file that was not fully inspected is never reported `clean`.**
Caps produce `partial`/`suspicious` with the reason, never silence.

## Boundary with the mail path

- The milter decides policy (refuse at SMTP) and calls `POST /inspect` with the
  decoded part. It may embed `mailxray-core` directly instead of the HTTP hop.
- The webmail reads `GET /report/{hash}` to render the per-attachment card. If
  the report is missing (mail older than the deployment), it asks `/inspect`
  once with the blob it already has.
- Reports are content-addressed: an attachment seen by 100 recipients is
  inspected once.
