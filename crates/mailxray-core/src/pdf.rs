//! PDF active-content inspection.
//!
//! Two passes: the object graph (cheap, catches most), and, when `deep_pdf` is
//! on, every stream decompressed and searched for active content, because a
//! `/JavaScript` hidden inside a Flate stream is invisible to pass one.

use crate::policy::Policy;
use crate::report::{PdfDetails, Reason};

const ACTIVE_KEYS: &[&str] = &[
    "OpenAction",
    "AA",
    "Launch",
    "JavaScript",
    "EmbeddedFiles",
    "EmbeddedFile",
    "RichMedia",
    "XFA",
    "SubmitForm",
    "ImportData",
    "Rendition",
    "Collection",
];

pub fn inspect(bytes: &[u8], policy: &Policy) -> Result<(Vec<Reason>, PdfDetails), String> {
    let doc = lopdf::Document::load_mem(bytes).map_err(|e| e.to_string())?;
    let mut reasons = Vec::new();

    let mut d = PdfDetails {
        pages: doc.get_pages().len(),
        objects: doc.objects.len(),
        encrypted: false,
        javascript: Vec::new(),
        launch: false,
        open_action: false,
        additional_actions: false,
        embedded_files: 0,
        xfa: false,
        rich_media: false,
        submit_form: false,
        links: Vec::new(),
        hosts: Vec::new(),
        decompressed_bytes: 0,
        truncated: false,
        error: None,
    };

    d.encrypted = doc.trailer.get(b"Encrypt").is_ok();
    if d.encrypted {
        // An encrypted PDF cannot be inspected; that is a decision, not a bug.
        reasons.push(Reason::suspicious(
            "pdf-encrypted",
            "content is encrypted; active content cannot be ruled out",
        ));
    }

    // Action dictionaries are often nested inline (catalog -> OpenAction -> {S,JS}),
    // so the walk has to recurse, not just look at top-level objects.
    let mut budget = 200_000usize;
    for obj in doc.objects.values() {
        scan_object(obj, &mut d, 0, &mut budget);
    }

    // Deep pass: active content hidden in compressed streams and byte-level
    // evasions such as name escapes (`/Ja#76aScript`).
    if policy.deep_pdf {
        let mut budget = policy.max_pdf_decompress_bytes;
        let mut hidden_js = 0usize;
        let mut hidden_launch = 0usize;
        let mut hidden_embedded = 0usize;

        for obj in doc.objects.values() {
            let lopdf::Object::Stream(stream) = obj else {
                continue;
            };
            let Ok(mut data) = stream.decompressed_content() else {
                continue;
            };
            if data.len() as u64 > budget {
                data.truncate(budget as usize);
                d.truncated = true;
            }
            budget = budget.saturating_sub(data.len() as u64);
            d.decompressed_bytes += data.len() as u64;

            hidden_js += count_any(
                &data,
                &[b"/JavaScript", b"/JS", b"#4a#61#76#61", b"#4A#61#76#61"],
            );
            hidden_launch += count_any(&data, &[b"/Launch"]);
            hidden_embedded += count_any(&data, &[b"/EmbeddedFile", b"/EmbeddedFiles"]);
            if d.truncated && budget == 0 {
                break;
            }
        }

        if hidden_js > 0 && d.javascript.is_empty() {
            reasons.push(Reason::suspicious(
                "pdf-hidden-javascript",
                format!("{hidden_js} JavaScript marker(s) inside compressed streams"),
            ));
            d.javascript.push("<hidden in compressed stream>".to_string());
        }
        if hidden_launch > 0 && !d.launch {
            reasons.push(Reason::suspicious(
                "pdf-hidden-launch",
                format!("{hidden_launch} /Launch marker(s) inside compressed streams"),
            ));
            d.launch = true;
        }
        if hidden_embedded > 0 && d.embedded_files == 0 {
            reasons.push(Reason::suspicious(
                "pdf-hidden-embedded",
                format!("{hidden_embedded} embedded-file marker(s) inside compressed streams"),
            ));
            d.embedded_files = hidden_embedded;
        }
        if d.truncated {
            reasons.push(Reason::suspicious(
                "pdf-partial-scan",
                format!(
                    "decompression budget reached at {} MB; not every stream was inspected",
                    policy.max_pdf_decompress_bytes / 1024 / 1024
                ),
            ));
        }
    }

    // --- verdict shaping
    if d.launch {
        reasons.push(Reason::blocked("pdf-launch", "document can start an external program"));
    }
    if !d.javascript.is_empty() {
        let auto = d.open_action || d.additional_actions;
        if policy.block_active_pdf {
            reasons.push(Reason::blocked(
                "pdf-javascript",
                if auto {
                    "JavaScript that runs on open".to_string()
                } else {
                    format!("{} JavaScript action(s)", d.javascript.len())
                },
            ));
        } else {
            reasons.push(Reason::suspicious("pdf-javascript", "JavaScript present"));
        }
    }
    if d.embedded_files > 0 && (!d.javascript.is_empty() || policy.block_active_pdf) {
        reasons.push(Reason::blocked(
            "pdf-embedded-payload",
            format!("{} embedded file object(s)", d.embedded_files),
        ));
    } else if d.embedded_files > 0 {
        reasons.push(Reason::suspicious(
            "pdf-embedded-files",
            format!("{} embedded file object(s)", d.embedded_files),
        ));
    }
    if d.open_action && (d.launch || !d.javascript.is_empty()) {
        reasons.push(Reason::blocked(
            "pdf-open-action",
            "action fires automatically when the document is opened",
        ));
    }
    if d.submit_form {
        reasons.push(Reason::blocked("pdf-submit-form", "document can post data out"));
    }
    if d.xfa {
        reasons.push(Reason::blocked("pdf-xfa", "XFA form (scriptable legacy format)"));
    }
    if d.rich_media {
        reasons.push(Reason::blocked("pdf-rich-media", "rich media / embedded player"));
    }
    if !d.links.is_empty() {
        reasons.push(Reason::info(
            "pdf-links",
            format!("{} link(s) to {} host(s)", d.links.len(), d.hosts.len()),
        ));
    }

    Ok((reasons, d))
}

fn scan_object(obj: &lopdf::Object, d: &mut PdfDetails, depth: u8, budget: &mut usize) {
    if depth > 8 || *budget == 0 {
        return;
    }
    *budget -= 1;
    match obj {
        lopdf::Object::Dictionary(dict) => {
            scan_dict(dict, d);
            for (_, value) in dict.iter() {
                scan_object(value, d, depth + 1, budget);
            }
        }
        lopdf::Object::Stream(stream) => {
            scan_dict(&stream.dict, d);
            for (_, value) in stream.dict.iter() {
                scan_object(value, d, depth + 1, budget);
            }
        }
        lopdf::Object::Array(items) => {
            for value in items {
                scan_object(value, d, depth + 1, budget);
            }
        }
        _ => {}
    }
}

fn scan_dict(dict: &lopdf::Dictionary, d: &mut PdfDetails) {
    for key in ACTIVE_KEYS {
        if !dict.has(key.as_bytes()) {
            continue;
        }
        match *key {
            "OpenAction" => d.open_action = true,
            "AA" => d.additional_actions = true,
            "Launch" => d.launch = true,
            "EmbeddedFiles" | "EmbeddedFile" => d.embedded_files += 1,
            "XFA" => d.xfa = true,
            "RichMedia" => d.rich_media = true,
            "SubmitForm" => d.submit_form = true,
            "Collection" => d.embedded_files += 1,
            _ => {}
        }
    }

    // Action dictionaries: /S /URI, /S /JavaScript, /S /Launch, ...
    if let Ok(lopdf::Object::Name(s)) = dict.get(b"S") {
        let action = String::from_utf8_lossy(s).to_string();
        match action.as_str() {
            "JavaScript" => {
                let snippet = dict
                    .get(b"JS")
                    .ok()
                    .and_then(object_text)
                    .map(|s| s.chars().take(120).collect::<String>())
                    .unwrap_or_default();
                if d.javascript.len() < 20 {
                    d.javascript.push(snippet);
                }
            }
            "Launch" => d.launch = true,
            "SubmitForm" => d.submit_form = true,
            "URI" => {
                if d.links.len() < 50
                    && let Some(u) = dict.get(b"URI").ok().and_then(object_text) {
                        let host = u
                            .split("://")
                            .nth(1)
                            .unwrap_or(&u)
                            .split('/')
                            .next()
                            .unwrap_or("")
                            .to_ascii_lowercase();
                        if !host.is_empty() && !d.hosts.contains(&host) {
                            d.hosts.push(host);
                        }
                        d.links.push(u.chars().take(300).collect());
                    }
            }
            _ => {}
        }
    }
}

fn object_text(obj: &lopdf::Object) -> Option<String> {
    match obj {
        lopdf::Object::String(bytes, _) => Some(String::from_utf8_lossy(bytes).to_string()),
        lopdf::Object::Name(bytes) => Some(String::from_utf8_lossy(bytes).to_string()),
        _ => None,
    }
}

fn count_any(haystack: &[u8], needles: &[&[u8]]) -> usize {
    needles
        .iter()
        .map(|n| haystack.windows(n.len()).filter(|w| *w == *n).count())
        .sum()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counts_needles() {
        assert_eq!(count_any(b"xx/JSxx/JS", &[b"/JS"]), 2);
        assert_eq!(count_any(b"nothing", &[b"/JS"]), 0);
    }
}
