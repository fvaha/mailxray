//! rendgen-core — inspection of untrusted attachments without opening them.
//!
//! Everything here is tier 0: memory-safe parsers, bounded work, no rendering,
//! no network, no execution. The output is a structural report and a verdict.
//!
//! The contract (field names, verdicts) is documented in `SPEC.md`; the daemon
//! in `crates/rendgend` serves the same structs as JSON.

pub mod archive;
pub mod detect;
pub mod ole;
pub mod ooxml;
pub mod pdf;
pub mod policy;
pub mod report;

pub use detect::{FileClass, detect, detect_with_name, extensions};
pub use policy::Policy;
pub use report::{
    ArchiveDetails, ArchiveEntry, Details, OleDetails, OoxmlDetails, PdfDetails, Reason, Report,
    Verdict,
};

use sha2::Digest;

/// Inspect one attachment and produce its report.
///
/// `name` is the filename as it arrived (untrusted); it is only used to compare
/// the declared extension against the real content and to pick a handler.
pub fn inspect(name: Option<&str>, bytes: &[u8], policy: &Policy) -> Report {
    let mut reasons = Vec::new();
    let hash = blake3::hash(bytes).to_hex().to_string();
    let sha256 = hex(&sha2::Sha256::digest(bytes));
    let real = detect_with_name(name, bytes);
    let declared = name.and_then(detect::extension);
    let type_mismatch = declared
        .as_deref()
        .map(|ext| !detect::extension_matches(ext, real))
        .unwrap_or(false);

    // 1. hard policy: the class itself is refused
    if policy.block_executables && real.is_executable() {
        reasons.push(Reason::blocked(
            "blocked-type",
            format!("content is {} (executable class)", real.as_str()),
        ));
    }
    if let Some(ext) = declared.as_deref()
        && policy.blocked_extension(ext) {
            reasons.push(Reason::blocked(
                "blocked-extension",
                format!("declared extension .{ext}"),
            ));
        }
    if type_mismatch {
        reasons.push(Reason::suspicious(
            "type-mismatch",
            format!(
                "declared .{} but content is {}",
                declared.as_deref().unwrap_or("?"),
                real.as_str()
            ),
        ));
    }

    // 2. format handlers
    let details = match real {
        FileClass::Pdf => match pdf::inspect(bytes, policy) {
            Ok((mut r, d)) => {
                reasons.append(&mut r);
                Details::Pdf(d)
            }
            Err(e) => {
                reasons.push(Reason::suspicious("pdf-unparsed", e.to_string()));
                Details::Pdf(PdfDetails::unparsed(e.to_string()))
            }
        },
        FileClass::Zip => match ooxml::kind_of(bytes) {
            Some(kind) => match ooxml::inspect(bytes, kind, policy) {
                Ok((mut r, d)) => {
                    reasons.append(&mut r);
                    Details::Ooxml(d)
                }
                Err(e) => {
                    reasons.push(Reason::suspicious("ooxml-unparsed", e.to_string()));
                    Details::None
                }
            },
            None => match archive::inspect_zip(bytes, policy) {
                Ok((mut r, d)) => {
                    reasons.append(&mut r);
                    Details::Archive(d)
                }
                Err(e) => {
                    reasons.push(Reason::suspicious("zip-unparsed", e.to_string()));
                    Details::None
                }
            },
        },
        FileClass::Ole2 => match ole::inspect(bytes, policy) {
            Ok((mut r, d)) => {
                // .doc/.xls with macros are handled by the macro policy
                reasons.append(&mut r);
                Details::Ole(d)
            }
            Err(e) => {
                reasons.push(Reason::suspicious("ole-unparsed", e.to_string()));
                Details::None
            }
        },
        FileClass::Gzip => match archive::inspect_gzip(bytes, policy) {
            Ok((mut r, d)) => {
                reasons.append(&mut r);
                Details::Archive(d)
            }
            Err(e) => {
                reasons.push(Reason::suspicious("gzip-unparsed", e.to_string()));
                Details::None
            }
        },
        // rar/7z/bzip2/xz/zstd need an external handler (tier 1): recognised,
        // deliberately not parsed here.
        FileClass::Rar4
        | FileClass::Rar5
        | FileClass::SevenZip
        | FileClass::Bzip2
        | FileClass::Xz
        | FileClass::Zstd
        | FileClass::Tar => {
            reasons.push(Reason::suspicious(
                "container-not-listed",
                format!(
                    "{} recognised; entry listing requires the external handler",
                    real.as_str()
                ),
            ));
            Details::Archive(ArchiveDetails::unlisted(real.as_str()))
        }
        _ => Details::None,
    };

    let verdict = policy.verdict(&reasons);

    Report {
        schema: 1,
        hash,
        sha256,
        size: bytes.len() as u64,
        name: name.map(str::to_string),
        declared_ext: declared,
        real_type: real.as_str().to_string(),
        type_mismatch,
        verdict,
        reasons,
        details,
    }
}

fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}
