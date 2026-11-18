//! Client for `oracle.jl`.
//!
//! Only the harness crate depends on this one. The response is rejected if it
//! carries primes, a private exponent, or a factor.

use anyhow::{anyhow, bail, Result};
use jsonline::JsonProcess;
use serde_json::{json, Value};
use std::path::Path;

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
    "dmp1",
    "dmq1",
    "n",
];

pub struct OracleClient {
    process: JsonProcess,
}

impl OracleClient {
    pub fn start(script: &Path) -> Result<Self> {
        Ok(Self {
            process: JsonProcess::spawn(script)?,
        })
    }

    pub fn confirm(&mut self, request: Value) -> Result<Value> {
        let response = self.process.call(&request)?;
        reject_secrets(&response)?;
        Ok(response)
    }

    /// A public modulus labelled as harvested must be refused before any check.
    pub fn refuse_harvested(&mut self) -> Result<()> {
        let response = self.confirm(json!({
            "profile": "weak_rsa",
            "origin": "harvested",
            "n": "65537",
            "e": "65537",
            "d": "1",
            "p": "3",
            "q": "5"
        }))?;
        if response.get("refused") != Some(&Value::Bool(true)) {
            bail!("oracle accepted a harvested origin: {response}");
        }
        Ok(())
    }
}

fn reject_secrets(value: &Value) -> Result<()> {
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
        return Err(anyhow!("oracle response included secret material"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secret_response_is_rejected() {
        let value = json!({"ok": true, "confirmed": true, "p": "3"});
        assert!(reject_secrets(&value).is_err());
    }
}
