//! Policy: what is refused, what is merely flagged, and the work budgets.

use crate::report::{Reason, Severity, Verdict};

/// Extensions that are refused outright, regardless of content.
pub const BLOCKED_EXTENSIONS: &[&str] = &[
    // executables and loaders
    "exe", "dll", "ocx", "cpl", "scr", "pif", "sys", "drv", "com", "msi", "msp", "msix",
    // scripts
    "js", "jse", "mjs", "vbs", "vbe", "wsf", "wsh", "hta", "ps1", "psm1", "bat", "cmd", "reg",
    "sct", "shb", "lnk", "url", "scf",
    // images that run
    "iso", "img", "vhd", "vhdx", "vmdk", "dmg", "one",
    // macro-enabled office
    "docm", "dotm", "xlsm", "xltm", "pptm", "potm", "xlam",
    // containers of the above
    "jar", "apk", "chm",
];

#[derive(Debug, Clone)]
pub struct Policy {
    /// Refuse PE/ELF/Mach-O/ISO/LNK/script content.
    pub block_executables: bool,
    /// Refuse Office documents carrying macros.
    pub block_macro_office: bool,
    /// Refuse archives we cannot open (password-protected).
    pub block_encrypted_archives: bool,
    /// Refuse PDFs with auto-executing active content.
    pub block_active_pdf: bool,
    /// Nested archive depth that is still listed.
    pub max_depth: u8,
    /// Entries listed per archive.
    pub max_entries: usize,
    /// Total decompressed bytes budget per attachment.
    pub max_uncompressed_bytes: u64,
    /// size/compressed_size above which an entry is treated as a bomb.
    pub max_ratio: f64,
    /// Decompress PDF streams looking for hidden active content.
    pub deep_pdf: bool,
    /// Total bytes decompressed from PDF streams.
    pub max_pdf_decompress_bytes: u64,
    /// Extra extensions to refuse on top of `BLOCKED_EXTENSIONS`.
    pub extra_blocked_extensions: Vec<String>,
}

impl Default for Policy {
    fn default() -> Self {
        Self {
            block_executables: true,
            block_macro_office: true,
            block_encrypted_archives: true,
            block_active_pdf: true,
            max_depth: 2,
            max_entries: 2000,
            max_uncompressed_bytes: 64 * 1024 * 1024,
            max_ratio: 200.0,
            deep_pdf: true,
            max_pdf_decompress_bytes: 64 * 1024 * 1024,
            extra_blocked_extensions: Vec::new(),
        }
    }
}

impl Policy {
    pub fn blocked_extension(&self, ext: &str) -> bool {
        BLOCKED_EXTENSIONS.contains(&ext)
            || self.extra_blocked_extensions.iter().any(|e| e == ext)
    }

    /// Highest severity wins; a clean run stays clean.
    pub fn verdict(&self, reasons: &[Reason]) -> Verdict {
        let mut out = Verdict::Clean;
        for r in reasons {
            match r.severity {
                Severity::Blocked => return Verdict::Blocked,
                Severity::Suspicious => out = Verdict::Suspicious,
                Severity::Info => {}
            }
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verdict_is_max_severity() {
        let p = Policy::default();
        assert_eq!(p.verdict(&[]), Verdict::Clean);
        assert_eq!(
            p.verdict(&[Reason::info("a", "x"), Reason::suspicious("b", "y")]),
            Verdict::Suspicious
        );
        assert_eq!(
            p.verdict(&[Reason::suspicious("b", "y"), Reason::blocked("c", "z")]),
            Verdict::Blocked
        );
    }

    #[test]
    fn blocked_extension_list_covers_the_dangerous_ones() {
        let p = Policy::default();
        for e in ["exe", "lnk", "iso", "hta", "js", "docm", "jar"] {
            assert!(p.blocked_extension(e), "{e} must be blocked");
        }
        for e in ["pdf", "docx", "zip", "png", "txt"] {
            assert!(!p.blocked_extension(e), "{e} must not be blocked");
        }
    }
}
