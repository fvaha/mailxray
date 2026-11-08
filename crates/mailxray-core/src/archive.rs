//! Archive listing with bounded work: entry caps, decompression budget, ratio
//! limits, and one level of nesting (configurable).

use std::io::{Cursor, Read};

use crate::detect::{self, FileClass};
use crate::policy::Policy;
use crate::report::{ArchiveDetails, ArchiveEntry, Reason, Verdict};

pub fn inspect_zip(bytes: &[u8], policy: &Policy) -> Result<(Vec<Reason>, ArchiveDetails), String> {
    let mut details = ArchiveDetails {
        format: "zip".into(),
        listed: true,
        entries: Vec::new(),
        total_uncompressed: 0,
        encrypted: false,
        truncated: false,
        depth: 0,
    };
    let mut reasons = Vec::new();
    walk_zip(bytes, policy, 0, &mut details, &mut reasons)?;
    Ok((reasons, details))
}

fn walk_zip(
    bytes: &[u8],
    policy: &Policy,
    depth: u8,
    details: &mut ArchiveDetails,
    reasons: &mut Vec<Reason>,
) -> Result<(), String> {
    let mut za = zip::ZipArchive::new(Cursor::new(bytes)).map_err(|e| e.to_string())?;
    let count = za.len();
    if count > policy.max_entries {
        details.truncated = true;
        reasons.push(Reason::suspicious(
            "archive-entry-cap",
            format!("{count} entries, only the first {} were listed", policy.max_entries),
        ));
    }

    for i in 0..count.min(policy.max_entries) {
        if details.total_uncompressed > policy.max_uncompressed_bytes {
            details.truncated = true;
            break;
        }

        let (name, size, csize, class, ratio, prefix_len) = {
            let mut entry = za.by_index(i).map_err(|e| e.to_string())?;
            let name = entry.name().map(|n| n.to_string()).unwrap_or_default();
            let size = entry.size();
            let csize = entry.compressed_size();
            let ratio = if csize == 0 { 0.0 } else { size as f64 / csize as f64 };

            let mut prefix = [0u8; 8192];
            let read = match entry.read(&mut prefix) {
                Ok(n) => n,
                Err(_) => {
                    // Usually "password required": the container is encrypted.
                    details.encrypted = true;
                    0
                }
            };
            let class = detect::detect_with_name(Some(&name), &prefix[..read]);
            (name, size, csize, class, ratio, read)
        };

        let mut verdict = Verdict::Clean;
        let mut entry_prefix = vec![0u8; prefix_len];
        if prefix_len > 0
            && let Ok(mut entry) = za.by_index(i) {
                let _ = entry.read(&mut entry_prefix);
            }

        if let Some(ext) = detect::extension(&name)
            && policy.blocked_extension(&ext) {
                verdict = Verdict::Blocked;
                reasons.push(Reason::blocked(
                    "executable-inside",
                    format!("{name}: blocked extension .{ext} inside the archive"),
                ));
            }
        if class.is_executable() {
            verdict = Verdict::Blocked;
            reasons.push(Reason::blocked(
                "executable-inside",
                format!("{name}: content is {}", class.as_str()),
            ));
        }
        if ratio > policy.max_ratio && size > 1024 * 1024 {
            verdict = Verdict::Blocked;
            reasons.push(Reason::blocked(
                "archive-bomb",
                format!("{name}: ratio {ratio:.0}x over {size} bytes"),
            ));
        }
        if name.contains("..") || name.starts_with('/') {
            verdict = Verdict::Blocked;
            reasons.push(Reason::blocked(
                "path-traversal",
                format!("{name}: entry name escapes the archive root"),
            ));
        }

        details.entries.push(ArchiveEntry {
            name: name.clone(),
            size,
            compressed_size: csize,
            ratio,
            class: class.as_str().to_string(),
            verdict,
        });
        details.total_uncompressed = details.total_uncompressed.saturating_add(size);

        // One more level of nesting, bounded by size.
        if class == FileClass::Zip
            && depth < policy.max_depth
            && size <= policy.max_uncompressed_bytes / 4
        {
            let mut inner = Vec::with_capacity(size as usize);
            if let Ok(entry) = za.by_index(i)
                && entry.take(size).read_to_end(&mut inner).is_ok() && !inner.is_empty() {
                    details.depth = details.depth.max(depth + 1);
                    let mut nested = ArchiveDetails {
                        format: format!("zip (inside {name})"),
                        listed: true,
                        entries: Vec::new(),
                        total_uncompressed: 0,
                        encrypted: false,
                        truncated: false,
                        depth: depth + 1,
                    };
                    walk_zip(&inner, policy, depth + 1, &mut nested, reasons)?;
                    details.entries.extend(nested.entries);
                    details.total_uncompressed = details
                        .total_uncompressed
                        .saturating_add(nested.total_uncompressed);
                    details.encrypted |= nested.encrypted;
                }
        }
    }

    Ok(())
}

/// gzip is a single stream: no entry names. We decompress (bounded) and report
/// what came out, because "a .gz" tells a user nothing.
pub fn inspect_gzip(
    bytes: &[u8],
    policy: &Policy,
) -> Result<(Vec<Reason>, ArchiveDetails), String> {
    let mut out = Vec::new();
    let mut decoder = flate2::read::GzDecoder::new(bytes);
    decoder
        .by_ref()
        .take(policy.max_uncompressed_bytes)
        .read_to_end(&mut out)
        .map_err(|e| e.to_string())?;

    let truncated = out.len() as u64 >= policy.max_uncompressed_bytes;
    let class = detect::detect(&out);
    let mut reasons = Vec::new();
    let mut verdict = Verdict::Clean;

    if class.is_executable() {
        verdict = Verdict::Blocked;
        reasons.push(Reason::blocked(
            "executable-inside",
            format!("decompressed content is {}", class.as_str()),
        ));
    }
    if truncated {
        reasons.push(Reason::suspicious(
            "archive-partial-scan",
            "decompression budget reached; content is larger than inspected",
        ));
    }

    let details = ArchiveDetails {
        format: "gzip".into(),
        listed: true,
        entries: vec![ArchiveEntry {
            name: "<decompressed stream>".into(),
            size: out.len() as u64,
            compressed_size: bytes.len() as u64,
            ratio: if bytes.is_empty() {
                0.0
            } else {
                out.len() as f64 / bytes.len() as f64
            },
            class: class.as_str().to_string(),
            verdict,
        }],
        total_uncompressed: out.len() as u64,
        encrypted: false,
        truncated,
        depth: 0,
    };
    Ok((reasons, details))
}

/// Plain tar: 512-byte headers, no compression, so listing is a scan.
pub fn inspect_tar(bytes: &[u8], policy: &Policy) -> Result<(Vec<Reason>, ArchiveDetails), String> {
    let mut details = ArchiveDetails {
        format: "tar".into(),
        listed: true,
        entries: Vec::new(),
        total_uncompressed: 0,
        encrypted: false,
        truncated: false,
        depth: 0,
    };
    let mut reasons = Vec::new();
    let mut off = 0usize;

    while off + 512 <= bytes.len() && details.entries.len() < policy.max_entries {
        let header = &bytes[off..off + 512];
        if header.iter().all(|b| *b == 0) {
            break;
        }
        let name = cstr(&header[0..100]);
        let size_field = cstr(&header[124..136]).trim().to_string();
        let size = usize::from_str_radix(size_field.trim_start_matches('0'), 8).unwrap_or(0);
        if !name.is_empty() {
            details.entries.push(ArchiveEntry {
                name: name.clone(),
                size: size as u64,
                compressed_size: size as u64,
                ratio: 1.0,
                class: detect::detect_with_name(Some(&name), &[]).as_str().to_string(),
                verdict: Verdict::Clean,
            });
            details.total_uncompressed += size as u64;
            if let Some(ext) = detect::extension(&name)
                && policy.blocked_extension(&ext) {
                    if let Some(last) = details.entries.last_mut() {
                        last.verdict = Verdict::Blocked;
                    }
                    reasons.push(Reason::blocked(
                        "executable-inside",
                        format!("{name}: blocked extension .{ext}"),
                    ));
                }
        }
        off += 512 + size.div_ceil(512) * 512;
    }

    Ok((reasons, details))
}

fn cstr(bytes: &[u8]) -> String {
    let end = bytes.iter().position(|b| *b == 0).unwrap_or(bytes.len());
    String::from_utf8_lossy(&bytes[..end]).to_string()
}
