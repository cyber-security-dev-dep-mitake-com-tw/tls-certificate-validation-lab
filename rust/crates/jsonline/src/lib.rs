//! One JSON object per line, spoken to a long-running Julia process.

use anyhow::{anyhow, Context, Result};
use serde_json::Value;
use std::io::{BufRead, BufReader, Write};
use std::path::Path;
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::thread;

pub struct JsonProcess {
    child: Child,
    stdin: ChildStdin,
    stdout: BufReader<std::process::ChildStdout>,
    stderr: Arc<Mutex<String>>,
}

impl JsonProcess {
    pub fn spawn(script: &Path) -> Result<Self> {
        let project = script
            .parent()
            .ok_or_else(|| anyhow!("julia script has no directory"))?;
        let mut child = Command::new("julia")
            .args([
                "--quiet",
                "--startup-file=no",
                &format!("--project={}", project.display()),
                script.to_str().context("script path is not utf-8")?,
            ])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .with_context(|| format!("failed to start julia {}", script.display()))?;
        let stdin = child.stdin.take().context("julia stdin")?;
        let stdout = child.stdout.take().context("julia stdout")?;
        let stderr = child.stderr.take().context("julia stderr")?;
        let stderr_buf = Arc::new(Mutex::new(String::new()));
        let stored = Arc::clone(&stderr_buf);
        thread::spawn(move || {
            let mut reader = BufReader::new(stderr);
            let mut line = String::new();
            while reader.read_line(&mut line).unwrap_or(0) > 0 {
                if let Ok(mut guard) = stored.lock() {
                    guard.push_str(&line);
                    if guard.len() > 8000 {
                        let drain = guard.len() - 4000;
                        guard.drain(..drain);
                    }
                }
                line.clear();
            }
        });
        Ok(Self {
            child,
            stdin,
            stdout: BufReader::new(stdout),
            stderr: stderr_buf,
        })
    }

    pub fn call(&mut self, request: &Value) -> Result<Value> {
        let mut line = serde_json::to_string(request)?;
        line.push('\n');
        self.stdin
            .write_all(line.as_bytes())
            .context("write julia request")?;
        self.stdin.flush().context("flush julia request")?;
        let mut response = String::new();
        let read = self
            .stdout
            .read_line(&mut response)
            .context("read julia response")?;
        if read == 0 {
            let err = self.stderr.lock().map(|g| g.clone()).unwrap_or_default();
            return Err(anyhow!("julia closed the protocol pipe: {err}"));
        }
        serde_json::from_str(response.trim()).with_context(|| {
            let err = self.stderr.lock().map(|g| g.clone()).unwrap_or_default();
            format!("julia returned non-json `{response}` stderr={err}")
        })
    }
}

impl Drop for JsonProcess {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}
