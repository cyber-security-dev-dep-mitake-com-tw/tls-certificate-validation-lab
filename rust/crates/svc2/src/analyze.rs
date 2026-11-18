//! Public-only Julia analysis. Requests that ask for factors are not sent,
//! and responses that contain factors are discarded.

use anyhow::{anyhow, bail, Result};
use jsonline::JsonProcess;
use serde_json::{json, Value};
use std::path::Path;

const ALLOWED: &[&str] = &[
    "WEAK_KEY",
    "ROCA_FINGERPRINT",
    "STRUCTURAL_WEAKNESS",
    "WEAK_SIGNATURE",
    "SHARED_FACTOR",
];
const SECRET_FIELDS: &[&str] = &[
    "d",
    "p",
    "q",
    "dp",
    "dq",
    "phi",
    "private",
    "private_key",
    "factor",
    "factors",
    "iqmp",
];

pub struct JuliaAnalyzer {
    process: JsonProcess,
}

impl JuliaAnalyzer {
    pub fn start(script: &Path) -> Result<Self> {
        Ok(Self {
            process: JsonProcess::spawn(script)?,
        })
    }

    pub fn inspect(&mut self, n: &str, e: &str, sig_alg: &str) -> Result<Vec<String>> {
        if decimal_too_wide_for_display(n) && n.len() > 2000 {
            bail!("modulus is too large to inspect");
        }
        let response = self.process.call(&json!({
            "op": "inspect",
            "n": n,
            "e": e,
            "sig_alg": sig_alg
        }))?;
        reject_secrets(&response)?;
        if response.get("ok") != Some(&Value::Bool(true)) {
            bail!("analyze refused the public key: {response}");
        }
        let reasons = response["reasons"]
            .as_array()
            .ok_or_else(|| anyhow!("analyze reasons missing"))?;
        Ok(reasons
            .iter()
            .filter_map(|item| item.as_str())
            .filter(|item| ALLOWED.contains(item))
            .map(|item| item.to_string())
            .collect())
    }

    pub fn batch_gcd(&mut self, moduli: &[String]) -> Result<Vec<(usize, usize)>> {
        let response = self.process.call(&json!({
            "op": "batch_gcd",
            "moduli": moduli
        }))?;
        reject_secrets(&response)?;
        if response.get("ok") != Some(&Value::Bool(true)) {
            bail!("batch gcd refused: {response}");
        }
        let mut pairs = Vec::new();
        for pair in response["pairs"]
            .as_array()
            .ok_or_else(|| anyhow!("pairs missing"))?
        {
            let i = pair["i"].as_u64().ok_or_else(|| anyhow!("pair index"))? as usize;
            let j = pair["j"].as_u64().ok_or_else(|| anyhow!("pair index"))? as usize;
            if pair.get("shared") == Some(&Value::Bool(true)) {
                pairs.push((i, j));
            }
        }
        Ok(pairs)
    }
}

fn decimal_too_wide_for_display(n: &str) -> bool {
    n.len() > 4000
}

pub(crate) fn reject_secrets(value: &Value) -> Result<()> {
    fn walk(value: &Value) -> bool {
        match value {
            Value::Object(map) => map
                .iter()
                .any(|(key, child)| SECRET_FIELDS.contains(&key.as_str()) || walk(child)),
            Value::Array(items) => items.iter().any(walk),
            _ => false,
        }
    }
    if walk(value) {
        Err(anyhow!("analyze response included secret material"))
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn factor_field_is_rejected() {
        let value = json!({"ok": true, "reasons": ["SHARED_FACTOR"], "factor": "11"});
        assert!(reject_secrets(&value).is_err());
    }
}
