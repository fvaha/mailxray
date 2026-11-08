//! Tier 1: run an external tool on untrusted bytes inside a disposable sandbox.
//!
//! Everything here is deliberate about ordering: the sandbox is created first
//! (no network namespace, read-only system, read-only input, a private writable
//! work dir), then the tool runs with a wall-clock timeout and its output is
//! capped. Limits are enforced from outside; the tool's own settings are never
//! trusted.

use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::process::Command;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Mode {
    /// No sandbox: only for development on systems without bwrap.
    Off,
    /// bubblewrap: user/mount/pid/net/ipc/uts namespaces, read-only system.
    Bwrap,
}

impl Mode {
    pub fn detect() -> Self {
        match std::env::var("MAILXRAY_SANDBOX").as_deref() {
            Ok("off") | Ok("none") => return Mode::Off,
            Ok("bwrap") => return Mode::Bwrap,
            _ => {}
        }
        let available = std::process::Command::new("bwrap")
            .arg("--version")
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false);
        if available { Mode::Bwrap } else { Mode::Off }
    }
}

pub struct Runner {
    pub mode: Mode,
    pub timeout: Duration,
    pub max_output: usize,
}

impl Runner {
    pub fn new() -> Self {
        Self {
            mode: Mode::detect(),
            timeout: Duration::from_secs(20),
            max_output: 8 * 1024 * 1024,
        }
    }

    /// Run `program` with `args`, confined to `input` (read-only) and `work`
    /// (writable). Returns stdout, capped at `max_output`.
    pub async fn run(
        &self,
        program: &str,
        args: &[String],
        input: &Path,
        work: &Path,
    ) -> Result<Vec<u8>, String> {
        let mut cmd = match self.mode {
            Mode::Bwrap => {
                let mut c = Command::new("bwrap");
                c.arg("--unshare-all").arg("--die-with-parent");
                for p in ["/usr", "/bin", "/sbin", "/lib", "/lib64", "/etc"] {
                    if Path::new(p).exists() {
                        c.arg("--ro-bind").arg(p).arg(p);
                    }
                }
                // tmpfs first, then the binds we actually need, so they stay visible
                c.arg("--tmpfs").arg("/tmp");
                c.arg("--ro-bind").arg(input).arg(input);
                c.arg("--bind").arg(work).arg(work);
                c.arg("--proc").arg("/proc");
                c.arg("--dev").arg("/dev");
                c.arg("--chdir").arg(work);
                c.arg("--").arg(program);
                c.args(args);
                c
            }
            Mode::Off => {
                let mut c = Command::new(program);
                c.args(args);
                c.current_dir(work);
                c
            }
        };

        cmd.stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());

        let child = cmd.spawn().map_err(|e| format!("cannot start {program}: {e}"))?;
        let output = tokio::time::timeout(self.timeout, child.wait_with_output())
            .await
            .map_err(|_| format!("{program} exceeded {:?}", self.timeout))?
            .map_err(|e| format!("{program}: {e}"))?;

        if !output.status.success() {
            let err = String::from_utf8_lossy(&output.stderr);
            let err: String = err.chars().take(300).collect();
            return Err(format!("{program} exited {}: {err}", output.status));
        }

        let mut stdout = output.stdout;
        if stdout.len() > self.max_output {
            stdout.truncate(self.max_output);
        }
        Ok(stdout)
    }
}

/// A directory that removes itself, used for the input file and the work area.
pub struct TempDir(PathBuf);

impl TempDir {
    pub fn new(tag: &str) -> Result<Self, String> {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let path = std::env::temp_dir().join(format!(
            "mailxray-{tag}-{}-{nanos}",
            std::process::id()
        ));
        std::fs::create_dir_all(&path).map_err(|e| format!("temp dir: {e}"))?;
        Ok(Self(path))
    }

    pub fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
