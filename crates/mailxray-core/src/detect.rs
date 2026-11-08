//! Content type detection by magic bytes. The filename is only a hint: an
//! attacker controls it, the bytes less so (and when they control both, the
//! mismatch is exactly what we report).

use serde::Serialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum FileClass {
    Pdf,
    Zip,
    Rar4,
    Rar5,
    SevenZip,
    Gzip,
    Bzip2,
    Xz,
    Zstd,
    Tar,
    Ole2,
    Pe,
    Elf,
    MachO,
    Iso,
    Lnk,
    Html,
    Svg,
    Script,
    Text,
    Image,
    Audio,
    Video,
    Unknown,
}

impl FileClass {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pdf => "pdf",
            Self::Zip => "zip",
            Self::Rar4 => "rar4",
            Self::Rar5 => "rar5",
            Self::SevenZip => "7z",
            Self::Gzip => "gzip",
            Self::Bzip2 => "bzip2",
            Self::Xz => "xz",
            Self::Zstd => "zstd",
            Self::Tar => "tar",
            Self::Ole2 => "ole2",
            Self::Pe => "pe",
            Self::Elf => "elf",
            Self::MachO => "macho",
            Self::Iso => "iso",
            Self::Lnk => "lnk",
            Self::Html => "html",
            Self::Svg => "svg",
            Self::Script => "script",
            Self::Text => "text",
            Self::Image => "image",
            Self::Audio => "audio",
            Self::Video => "video",
            Self::Unknown => "unknown",
        }
    }

    /// Classes that must never reach a user's machine from mail.
    pub fn is_executable(self) -> bool {
        matches!(
            self,
            Self::Pe | Self::Elf | Self::MachO | Self::Iso | Self::Lnk | Self::Script
        )
    }

    /// Containers we can list in-process.
    pub fn is_listable(self) -> bool {
        matches!(self, Self::Zip | Self::Gzip | Self::Tar)
    }
}

fn starts_with(bytes: &[u8], magic: &[u8]) -> bool {
    bytes.len() >= magic.len() && &bytes[..magic.len()] == magic
}

fn at(bytes: &[u8], offset: usize, magic: &[u8]) -> bool {
    bytes.len() >= offset + magic.len() && &bytes[offset..offset + magic.len()] == magic
}

/// Magic-byte detection, no filename involved.
pub fn detect(bytes: &[u8]) -> FileClass {
    if bytes.is_empty() {
        return FileClass::Unknown;
    }

    // --- containers and documents
    if starts_with(bytes, b"%PDF-") {
        return FileClass::Pdf;
    }
    if starts_with(bytes, b"PK\x03\x04") || starts_with(bytes, b"PK\x05\x06") {
        return FileClass::Zip;
    }
    if starts_with(bytes, b"Rar!\x1a\x07\x01\x00") {
        return FileClass::Rar5;
    }
    if starts_with(bytes, b"Rar!\x1a\x07\x00") {
        return FileClass::Rar4;
    }
    if starts_with(bytes, b"7z\xbc\xaf\x27\x1c") {
        return FileClass::SevenZip;
    }
    if starts_with(bytes, b"\x1f\x8b") {
        return FileClass::Gzip;
    }
    if starts_with(bytes, b"BZh") {
        return FileClass::Bzip2;
    }
    if starts_with(bytes, b"\xfd7zXZ\x00") {
        return FileClass::Xz;
    }
    if starts_with(bytes, b"\x28\xb5\x2f\xfd") {
        return FileClass::Zstd;
    }
    if at(bytes, 257, b"ustar") {
        return FileClass::Tar;
    }
    if starts_with(bytes, b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1") {
        return FileClass::Ole2;
    }

    // --- executables and disk images
    if starts_with(bytes, b"MZ") {
        // e_lfanew at 0x3c points at the PE header
        if bytes.len() > 0x40 {
            let off = u32::from_le_bytes([bytes[0x3c], bytes[0x3d], bytes[0x3e], bytes[0x3f]]) as usize;
            if at(bytes, off, b"PE\x00\x00") {
                return FileClass::Pe;
            }
        }
        return FileClass::Pe;
    }
    if starts_with(bytes, b"\x7fELF") {
        return FileClass::Elf;
    }
    if starts_with(bytes, b"\xfe\xed\xfa\xce")
        || starts_with(bytes, b"\xfe\xed\xfa\xcf")
        || starts_with(bytes, b"\xcf\xfa\xed\xfe")
        || starts_with(bytes, b"\xca\xfe\xba\xbe")
    {
        return FileClass::MachO;
    }
    if at(bytes, 0x8001, b"CD001") || at(bytes, 0x8801, b"CD001") {
        return FileClass::Iso;
    }
    if starts_with(bytes, b"L\x00\x00\x00\x01\x14\x02\x00") {
        return FileClass::Lnk;
    }

    // --- media (checked by magic, cheap and unambiguous)
    if starts_with(bytes, b"\x89PNG\r\n\x1a\n")
        || starts_with(bytes, b"\xff\xd8\xff")
        || starts_with(bytes, b"GIF87a")
        || starts_with(bytes, b"GIF89a")
        || (starts_with(bytes, b"RIFF") && at(bytes, 8, b"WEBP"))
        || starts_with(bytes, b"BM")
        || at(bytes, 4, b"ftyp")
    {
        return FileClass::Image;
    }
    if starts_with(bytes, b"ID3") || starts_with(bytes, b"OggS") || starts_with(bytes, b"fLaC") {
        return FileClass::Audio;
    }
    if at(bytes, 4, b"ftypqt") || (starts_with(bytes, b"RIFF") && at(bytes, 8, b"AVI ")) {
        return FileClass::Video;
    }

    // --- text-ish: look at the first few KB
    let head = &bytes[..bytes.len().min(4096)];
    if head.iter().take(1024).any(|b| *b == 0) {
        return FileClass::Unknown;
    }
    let lower: String = String::from_utf8_lossy(head).to_lowercase();
    if starts_with(bytes, b"#!") {
        return FileClass::Script;
    }
    if lower.contains("<!doctype html") || lower.contains("<html") {
        return FileClass::Html;
    }
    if lower.contains("<svg") {
        return FileClass::Svg;
    }
    FileClass::Text
}

/// Detection with the filename as a tie-breaker for the ambiguous text classes.
pub fn detect_with_name(name: Option<&str>, bytes: &[u8]) -> FileClass {
    let class = detect(bytes);
    let Some(ext) = name.and_then(extension) else {
        return class;
    };
    match class {
        // A .js/.vbs/.hta that is plain text is a script, not a text file.
        FileClass::Text | FileClass::Unknown if SCRIPT_EXTS.contains(&ext.as_str()) => FileClass::Script,
        // A .svg served as text is still executable in a browser.
        FileClass::Text if ext == "svg" => FileClass::Svg,
        _ => class,
    }
}

pub const SCRIPT_EXTS: &[&str] = &[
    "js", "jse", "mjs", "vbs", "vbe", "wsf", "wsh", "hta", "ps1", "psm1", "bat", "cmd", "com",
    "scr", "reg", "sct", "sh", "py", "pl", "rb",
];

/// Last extension, lowercased. `invoice.pdf.exe` -> "exe".
pub fn extension(name: &str) -> Option<String> {
    let base = name
        .rsplit(['/', '\\'])
        .next()
        .unwrap_or(name)
        .trim_end_matches('.');
    let (_, ext) = base.rsplit_once('.')?;
    if ext.is_empty() || ext.len() > 12 {
        return None;
    }
    Some(ext.to_ascii_lowercase())
}

/// All extensions, for double-extension reporting. `a.pdf.exe` -> ["pdf","exe"].
pub fn extensions(name: &str) -> Vec<String> {
    let base = name.rsplit(['/', '\\']).next().unwrap_or(name);
    base.split('.')
        .skip(1)
        .filter(|e| !e.is_empty() && e.len() <= 12)
        .map(|e| e.to_ascii_lowercase())
        .collect()
}

/// Does the declared extension plausibly match the real class?
pub fn extension_matches(ext: &str, class: FileClass) -> bool {
    let ok: &[&str] = match class {
        FileClass::Pdf => &["pdf"],
        FileClass::Zip => &["zip", "docx", "xlsx", "pptx", "odt", "ods", "odp", "jar", "apk", "epub"],
        FileClass::Rar4 | FileClass::Rar5 => &["rar"],
        FileClass::SevenZip => &["7z"],
        FileClass::Gzip => &["gz", "tgz"],
        FileClass::Bzip2 => &["bz2", "tbz2"],
        FileClass::Xz => &["xz", "txz"],
        FileClass::Zstd => &["zst"],
        FileClass::Tar => &["tar"],
        FileClass::Ole2 => &["doc", "xls", "ppt", "msg", "vsd"],
        FileClass::Pe => &["exe", "dll", "scr", "sys", "cpl", "ocx", "pif", "com", "msi"],
        FileClass::Elf => &["so", "elf", "bin"],
        FileClass::MachO => &["dylib", "macho", "bin"],
        FileClass::Iso => &["iso", "img"],
        FileClass::Lnk => &["lnk"],
        FileClass::Html => &["html", "htm", "shtml", "xhtml"],
        FileClass::Svg => &["svg"],
        FileClass::Script => SCRIPT_EXTS,
        FileClass::Image => &["png", "jpg", "jpeg", "gif", "webp", "bmp", "tif", "tiff", "heic", "avif"],
        FileClass::Audio => &["mp3", "ogg", "flac", "wav", "m4a"],
        FileClass::Video => &["mp4", "mov", "avi", "mkv", "webm"],
        FileClass::Text => &["txt", "csv", "log", "md", "json", "xml", "ics", "vcf"],
        FileClass::Unknown => return true,
    };
    ok.contains(&ext)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_pe_even_without_full_header() {
        assert_eq!(detect(b"MZ\x90\x00"), FileClass::Pe);
    }

    #[test]
    fn detects_pdf_and_zip() {
        assert_eq!(detect(b"%PDF-1.7\n"), FileClass::Pdf);
        assert_eq!(detect(b"PK\x03\x04rest"), FileClass::Zip);
    }

    #[test]
    fn double_extension_is_reported() {
        assert_eq!(extensions("invoice.pdf.exe"), vec!["pdf", "exe"]);
        assert_eq!(extension("invoice.pdf.exe").as_deref(), Some("exe"));
        assert_eq!(extension("noext"), None);
    }

    #[test]
    fn js_named_file_is_a_script_not_text() {
        let body = b"var x = 1;\n";
        assert_eq!(detect(body), FileClass::Text);
        assert_eq!(detect_with_name(Some("dropper.js"), body), FileClass::Script);
    }
}
