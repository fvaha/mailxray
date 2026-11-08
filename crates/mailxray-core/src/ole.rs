//! Legacy Office (OLE2/CFB) inspection: .doc/.xls/.ppt/.msg.
//!
//! We do not try to read the document text: that needs a format-specific parser
//! and is where the risk lives. What matters for mail is: does it carry a macro
//! project, and does it carry embedded objects.

use std::io::Cursor;

use crate::policy::Policy;
use crate::report::{OleDetails, Reason};

pub fn inspect(bytes: &[u8], policy: &Policy) -> Result<(Vec<Reason>, OleDetails), String> {
    let cf = cfb::CompoundFile::open(Cursor::new(bytes)).map_err(|e| e.to_string())?;

    let mut streams = Vec::new();
    let mut has_vba = false;
    let mut has_embedded = false;

    for entry in cf.walk() {
        if !entry.is_stream() {
            continue;
        }
        let path = entry.path().to_string_lossy().to_string();
        let lower = path.to_ascii_lowercase();
        if lower.contains("vba") || lower.contains("_vba_project") {
            has_vba = true;
        }
        if lower.contains("objectpool") || lower.contains("ole10native") || lower.contains("embeddings")
        {
            has_embedded = true;
        }
        if streams.len() < 64 {
            streams.push(path);
        }
    }

    let mut reasons = Vec::new();
    if has_vba {
        let detail = "OLE2 document contains a VBA project";
        if policy.block_macro_office {
            reasons.push(Reason::blocked("macro-present", detail));
        } else {
            reasons.push(Reason::suspicious("macro-present", detail));
        }
    }
    if has_embedded {
        reasons.push(Reason::suspicious(
            "embedded-objects",
            "OLE2 document contains embedded objects",
        ));
    }

    Ok((reasons, OleDetails { has_vba, has_embedded, streams }))
}
