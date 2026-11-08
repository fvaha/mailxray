//! OOXML (.docx/.xlsx/.pptx) inspection. These are ZIP containers, so they must
//! be recognised *before* the generic archive handler, otherwise the user is
//! shown `word/document.xml` instead of a document.

use std::io::{Cursor, Read};

use crate::policy::Policy;
use crate::report::{OoxmlDetails, Reason};

/// Which flavour of OOXML this ZIP is, if any.
pub fn kind_of(bytes: &[u8]) -> Option<&'static str> {
    let mut za = zip::ZipArchive::new(Cursor::new(bytes)).ok()?;
    let mut seen_content_types = false;
    let mut kind = None;
    for i in 0..za.len() {
        let Ok(entry) = za.by_index(i) else { continue };
        let name = entry.name().map(|n| n.to_string()).unwrap_or_default();
        if name == "[Content_Types].xml" {
            seen_content_types = true;
        }
        if name.starts_with("word/") {
            kind = Some("docx");
        } else if name.starts_with("xl/") && kind.is_none() {
            kind = Some("xlsx");
        } else if name.starts_with("ppt/") && kind.is_none() {
            kind = Some("pptx");
        }
    }
    if seen_content_types { kind } else { None }
}

pub fn inspect(
    bytes: &[u8],
    kind: &'static str,
    policy: &Policy,
) -> Result<(Vec<Reason>, OoxmlDetails), String> {
    let mut za = zip::ZipArchive::new(Cursor::new(bytes)).map_err(|e| e.to_string())?;
    let mut macros = false;
    let mut external_rels: Vec<String> = Vec::new();
    let mut embedded_objects = 0usize;
    let mut entries = 0usize;

    for i in 0..za.len() {
        let Ok(mut entry) = za.by_index(i) else { continue };
        entries += 1;
        let name = entry.name().map(|n| n.to_string()).unwrap_or_default();

        if name.to_ascii_lowercase().ends_with("vbaproject.bin") {
            macros = true;
        }
        if name.contains("embeddings/") || name.contains("oleObject") {
            embedded_objects += 1;
        }

        // Relationships are small XML files; substring search is both enough and
        // safe (no entity expansion happens, so no billion-laughs surface).
        if name.ends_with(".rels") && entry.size() <= 4 * 1024 * 1024 {
            let mut buf = Vec::new();
            if entry.by_ref().take(4 * 1024 * 1024).read_to_end(&mut buf).is_ok()
                && let Some(targets) = external_targets(&buf) {
                    external_rels.extend(targets);
                }
        }
    }

    let mut reasons = Vec::new();

    if macros {
        if policy.block_macro_office {
            reasons.push(Reason::blocked(
                "macro-present",
                format!("{kind} contains a VBA macro project"),
            ));
        } else {
            reasons.push(Reason::suspicious(
                "macro-present",
                format!("{kind} contains a VBA macro project"),
            ));
        }
    }
    if !external_rels.is_empty() {
        reasons.push(Reason::suspicious(
            "external-references",
            format!(
                "{} external reference(s): {}",
                external_rels.len(),
                external_rels.join(", ")
            ),
        ));
    }
    if embedded_objects > 0 {
        reasons.push(Reason::suspicious(
            "embedded-objects",
            format!("{embedded_objects} embedded object(s)"),
        ));
    }

    Ok((
        reasons,
        OoxmlDetails {
            format: kind.to_string(),
            macros,
            external_rels,
            embedded_objects,
            entries,
        },
    ))
}

/// Pull `Target="..."` from `<Relationship ... TargetMode="External" ...>`.
fn external_targets(xml: &[u8]) -> Option<Vec<String>> {
    let text = String::from_utf8_lossy(xml);
    if !text.contains("TargetMode=\"External\"") {
        return None;
    }
    let mut out = Vec::new();
    for chunk in text.split("<Relationship").skip(1) {
        if !chunk.contains("TargetMode=\"External\"") {
            continue;
        }
        if let Some(start) = chunk.find("Target=\"") {
            let rest = &chunk[start + 8..];
            if let Some(end) = rest.find('"') {
                out.push(rest[..end].to_string());
                if out.len() >= 10 {
                    break;
                }
            }
        }
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_external_targets() {
        let xml = br#"<Relationships>
            <Relationship Id="r1" Target="http://evil.example/x.dotm" TargetMode="External"/>
            <Relationship Id="r2" Target="word/document.xml" TargetMode="Internal"/>
        </Relationships>"#;
        let t = external_targets(xml).unwrap();
        assert_eq!(t, vec!["http://evil.example/x.dotm".to_string()]);
        assert!(external_targets(b"<Relationships></Relationships>").is_none());
    }
}
