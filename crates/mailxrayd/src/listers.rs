//! External archive handlers: listing and single-member extraction for the
//! formats the in-process parsers deliberately do not open (RAR, 7z, bzip2, xz,
//! zstd). 7-Zip does the work, inside the tier 1 sandbox.

use std::io::Read;

use mailxray_core::{ArchiveEntry, Policy, Verdict, detect};

use crate::sandbox::{Runner, TempDir};

/// 7-Zip is `7zz` on macOS/Windows and `7z` on Debian's p7zip. Probe once.
fn seven_zip() -> &'static str {
    static PROG: std::sync::OnceLock<&'static str> = std::sync::OnceLock::new();
    PROG.get_or_init(|| {
        if let Ok(explicit) = std::env::var("MAILXRAY_7Z") {
            return Box::leak(explicit.into_boxed_str());
        }
        for candidate in ["7zz", "7z", "7za"] {
            let ok = std::process::Command::new(candidate)
                .arg("i")
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .status()
                .map(|s| s.success())
                .unwrap_or(false);
            if ok {
                return candidate;
            }
        }
        "7zz"
    })
}

/// List a container with `7zz l -slt`. `format` is the class detected by core.
pub async fn list(
    runner: &Runner,
    bytes: &[u8],
    policy: &Policy,
) -> Result<Vec<ArchiveEntry>, String> {
    let dir = TempDir::new("list")?;
    let archive = dir.path().join("archive");
    tokio::fs::write(&archive, bytes)
        .await
        .map_err(|e| format!("write temp: {e}"))?;

    let args = vec![
        "l".to_string(),
        "-slt".to_string(),
        "--".to_string(),
        archive.display().to_string(),
    ];
    let out = runner.run(seven_zip(), &args, dir.path(), dir.path()).await?;
    let text = String::from_utf8_lossy(&out);
    Ok(parse_slt(&text, policy))
}

/// Extract one member. ZIP is handled in-process (no external tool needed for
/// the most common mail container); everything else goes through 7-Zip.
pub async fn extract(
    runner: &Runner,
    bytes: &[u8],
    format: &str,
    path: &str,
    max_bytes: usize,
) -> Result<Vec<u8>, String> {
    if format.starts_with("zip") {
        return extract_zip(bytes, path, max_bytes);
    }

    let dir = TempDir::new("entry")?;
    let archive = dir.path().join("archive");
    tokio::fs::write(&archive, bytes)
        .await
        .map_err(|e| format!("write temp: {e}"))?;

    let args = vec![
        "e".to_string(),
        "-so".to_string(),
        "-y".to_string(),
        "--".to_string(),
        archive.display().to_string(),
        path.to_string(),
    ];
    let out = runner.run(seven_zip(), &args, dir.path(), dir.path()).await?;
    if out.len() > max_bytes {
        return Err(format!("member larger than {max_bytes} bytes"));
    }
    Ok(out)
}

fn extract_zip(bytes: &[u8], path: &str, max_bytes: usize) -> Result<Vec<u8>, String> {
    let mut za = zip::ZipArchive::new(std::io::Cursor::new(bytes)).map_err(|e| e.to_string())?;
    let mut entry = za.by_name(path).map_err(|e| e.to_string())?;
    if entry.size() as usize > max_bytes {
        return Err(format!("member larger than {max_bytes} bytes"));
    }
    let mut out = Vec::with_capacity(entry.size() as usize);
    entry
        .by_ref()
        .take(max_bytes as u64)
        .read_to_end(&mut out)
        .map_err(|e| e.to_string())?;
    Ok(out)
}

/// Parse `7zz l -slt` output: a header block, then one blank-line-separated
/// block per member after the `----------` separator.
pub fn parse_slt(text: &str, policy: &Policy) -> Vec<ArchiveEntry> {
    let body = match text.split_once("----------") {
        Some((_, rest)) => rest,
        None => return Vec::new(),
    };

    let mut entries = Vec::new();
    for block in body.split("\n\n") {
        let mut name = None;
        let mut size = None;
        let mut packed = None;
        let mut folder = false;

        for line in block.lines() {
            let Some((key, value)) = line.split_once(" = ") else {
                continue;
            };
            match key.trim() {
                "Path" => name = Some(value.trim().to_string()),
                "Size" => size = value.trim().parse::<u64>().ok(),
                "Packed Size" => packed = value.trim().parse::<u64>().ok(),
                "Folder" => folder = value.trim() == "+",
                _ => {}
            }
        }

        let (Some(name), Some(size)) = (name, size) else {
            continue;
        };
        if folder || name.is_empty() {
            continue;
        }
        if entries.len() >= policy.max_entries {
            break;
        }

        let class = detect::class_from_name(&name);
        let mut verdict = Verdict::Clean;
        if class.is_executable() {
            verdict = Verdict::Blocked;
        }
        if let Some(ext) = detect::extension(&name)
            && policy.blocked_extension(&ext) {
                verdict = Verdict::Blocked;
            }

        let packed = packed.unwrap_or(0);
        entries.push(ArchiveEntry {
            name,
            size,
            compressed_size: packed,
            ratio: if packed == 0 {
                0.0
            } else {
                size as f64 / packed as f64
            },
            class: class.as_str().to_string(),
            verdict,
        });
    }
    entries
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = r#"
Listing archive: test.7z

--
Path = test.7z
Type = 7z
Physical Size = 552

----------
Path = nested.zip
Size = 517
Packed Size = 422
Folder = -
Encrypted = -

Path = setup.exe
Size = 15
Packed Size = 20
Folder = -

Path = sub/dir
Size = 0
Packed Size = 0
Folder = +

Path = readme.txt
Size = 19
Packed Size = 23
Folder = -
"#;

    #[test]
    fn parses_entries_and_skips_folders() {
        let p = Policy::default();
        let e = parse_slt(SAMPLE, &p);
        assert_eq!(e.len(), 3, "folders must not be listed: {e:?}");
        assert_eq!(e[0].name, "nested.zip");
        assert_eq!(e[0].class, "zip");
        assert_eq!(e[1].name, "setup.exe");
        assert_eq!(e[1].verdict, Verdict::Blocked);
        assert_eq!(e[2].name, "readme.txt");
        assert_eq!(e[2].verdict, Verdict::Clean);
        assert!((e[0].ratio - 517.0 / 422.0).abs() < 0.001);
    }

    #[test]
    fn parses_empty_output() {
        assert!(parse_slt("no separator here", &Policy::default()).is_empty());
    }
}
