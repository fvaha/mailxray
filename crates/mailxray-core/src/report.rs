//! The report contract. Field names are part of the public JSON API; see SPEC.md.

use serde::Serialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Verdict {
    Clean,
    Suspicious,
    Blocked,
    /// Recognised but not fully inspected (cap hit, external handler needed).
    Partial,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Info,
    Suspicious,
    Blocked,
}

#[derive(Debug, Clone, Serialize)]
pub struct Reason {
    pub code: String,
    pub detail: String,
    pub severity: Severity,
}

impl Reason {
    pub fn info(code: &str, detail: impl Into<String>) -> Self {
        Self { code: code.into(), detail: detail.into(), severity: Severity::Info }
    }

    pub fn suspicious(code: &str, detail: impl Into<String>) -> Self {
        Self { code: code.into(), detail: detail.into(), severity: Severity::Suspicious }
    }

    pub fn blocked(code: &str, detail: impl Into<String>) -> Self {
        Self { code: code.into(), detail: detail.into(), severity: Severity::Blocked }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct Report {
    pub schema: u32,
    /// BLAKE3 of the decoded attachment bytes: the cache key everywhere.
    pub hash: String,
    pub sha256: String,
    pub size: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Extension taken from the (untrusted) filename.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub declared_ext: Option<String>,
    /// What the bytes actually are.
    pub real_type: String,
    pub type_mismatch: bool,
    pub verdict: Verdict,
    pub reasons: Vec<Reason>,
    pub details: Details,
}

#[derive(Debug, Clone, Serialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum Details {
    None,
    Archive(ArchiveDetails),
    Pdf(PdfDetails),
    Ooxml(OoxmlDetails),
    Ole(OleDetails),
}

#[derive(Debug, Clone, Serialize)]
pub struct ArchiveDetails {
    pub format: String,
    /// false when the container was recognised but not listed (needs tier 1).
    pub listed: bool,
    pub entries: Vec<ArchiveEntry>,
    pub total_uncompressed: u64,
    pub encrypted: bool,
    pub truncated: bool,
    pub depth: u8,
}

impl ArchiveDetails {
    pub fn unlisted(format: &str) -> Self {
        Self {
            format: format.to_string(),
            listed: false,
            entries: Vec::new(),
            total_uncompressed: 0,
            encrypted: false,
            truncated: false,
            depth: 0,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct ArchiveEntry {
    pub name: String,
    pub size: u64,
    pub compressed_size: u64,
    pub ratio: f64,
    pub class: String,
    pub verdict: Verdict,
}

#[derive(Debug, Clone, Serialize)]
pub struct PdfDetails {
    pub pages: usize,
    pub objects: usize,
    pub encrypted: bool,
    /// JavaScript snippets, truncated to 120 chars each.
    pub javascript: Vec<String>,
    pub launch: bool,
    pub open_action: bool,
    pub additional_actions: bool,
    pub embedded_files: usize,
    pub xfa: bool,
    pub rich_media: bool,
    pub submit_form: bool,
    /// Link targets (capped at 50).
    pub links: Vec<String>,
    pub hosts: Vec<String>,
    pub decompressed_bytes: u64,
    pub truncated: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

impl PdfDetails {
    pub fn unparsed(error: String) -> Self {
        Self {
            pages: 0,
            objects: 0,
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
            error: Some(error),
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct OoxmlDetails {
    /// docx | xlsx | pptx
    pub format: String,
    pub macros: bool,
    pub external_rels: Vec<String>,
    pub embedded_objects: usize,
    pub entries: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct OleDetails {
    pub has_vba: bool,
    pub has_embedded: bool,
    pub streams: Vec<String>,
}
