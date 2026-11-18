//! Reverse-engineering advice and the LLM provider boundary.
//!
//! An advisor may recommend detectors and name a threat event. It cannot
//! change `certificate_status` or `risk_class`, and the advisory schema has
//! no field for a private key or a factor.

use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PublicObservation {
    pub key_type: Option<String>,
    pub bits: Option<u32>,
    pub exponent_bits: Option<u32>,
    pub signature_algorithm: Option<String>,
    pub duplicate_nonce_r: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VerdictSnapshot {
    pub certificate_status: String,
    pub risk_class: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdvisoryRequest {
    pub observation: PublicObservation,
    pub certificate_status: String,
    pub risk_class: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Advisory {
    pub recommended_detectors: Vec<String>,
    pub threat_event: String,
    pub notes: Vec<String>,
    pub source: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Applied {
    pub verdict: VerdictSnapshot,
    pub advisory: Advisory,
}

pub trait ReaAdvisor {
    fn advise(&self, observation: &PublicObservation, verdict: &VerdictSnapshot) -> Advisory;
}

pub trait LlmProvider {
    fn name(&self) -> &str;
    fn enabled(&self) -> bool;
    fn complete(&self, request: &AdvisoryRequest) -> Result<Advisory, ProviderError>;
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ProviderError {
    #[error("llm provider is disabled")]
    Disabled,
    #[error("llm response was rejected: {0}")]
    Rejected(String),
}

#[derive(Clone, Debug, Default)]
pub struct DeterministicRea;

impl ReaAdvisor for DeterministicRea {
    fn advise(&self, observation: &PublicObservation, verdict: &VerdictSnapshot) -> Advisory {
        let mut recommended = Vec::new();
        if observation.key_type.as_deref() == Some("rsa") {
            if observation.bits.unwrap_or(2048) < 2048 {
                recommended.extend([
                    "weak-key".to_string(),
                    "roca-fingerprint".to_string(),
                    "shared-prime".to_string(),
                ]);
            }
            if let (Some(bits), Some(exponent_bits)) = (observation.bits, observation.exponent_bits)
            {
                if exponent_bits.saturating_mul(2) > bits {
                    recommended.push("structural-weakness".to_string());
                }
            }
        }
        if observation
            .signature_algorithm
            .as_deref()
            .map(is_deprecated_signature)
            .unwrap_or(false)
        {
            recommended.push("deprecated-signature".to_string());
        }
        if observation.duplicate_nonce_r {
            recommended.push("nonce-reuse".to_string());
        }
        Advisory {
            recommended_detectors: recommended,
            threat_event: threat_event(verdict.risk_class.as_deref()).to_string(),
            notes: vec!["Cryptographic breakage is decided by deterministic checks.".into()],
            source: "deterministic".into(),
        }
    }
}

pub struct DisabledLlmProvider;

impl LlmProvider for DisabledLlmProvider {
    fn name(&self) -> &str {
        "disabled"
    }
    fn enabled(&self) -> bool {
        false
    }
    fn complete(&self, _request: &AdvisoryRequest) -> Result<Advisory, ProviderError> {
        Err(ProviderError::Disabled)
    }
}

#[derive(Clone, Debug)]
pub struct ScriptedLlmProvider {
    pub advisory: Advisory,
}

impl ScriptedLlmProvider {
    pub fn conflicting() -> Self {
        Self {
            advisory: Advisory {
                recommended_detectors: vec!["ignore-the-verdict".into()],
                threat_event: "VALID".into(),
                notes: vec!["private key recovered".into()],
                source: "llm".into(),
            },
        }
    }
}

impl LlmProvider for ScriptedLlmProvider {
    fn name(&self) -> &str {
        "scripted"
    }
    fn enabled(&self) -> bool {
        true
    }
    fn complete(&self, _request: &AdvisoryRequest) -> Result<Advisory, ProviderError> {
        Ok(self.advisory.clone())
    }
}

pub fn provider_from_name(name: &str) -> Box<dyn LlmProvider> {
    match name {
        "scripted" => Box::new(ScriptedLlmProvider::conflicting()),
        _ => Box::new(DisabledLlmProvider),
    }
}

/// Attach advice without letting it rewrite the verdict.
pub fn apply_advisory(verdict: &VerdictSnapshot, advisory: Advisory) -> Applied {
    Applied {
        verdict: verdict.clone(),
        advisory,
    }
}

pub fn parse_advisory(bytes: &[u8]) -> Result<Advisory, ProviderError> {
    serde_json::from_slice(bytes).map_err(|err| ProviderError::Rejected(err.to_string()))
}

fn threat_event(risk: Option<&str>) -> &'static str {
    match risk {
        Some("INVALID_CERTIFICATE") => "invalid_certificate",
        Some("WEAK_CRYPTOGRAPHY") => "weak_cryptography",
        Some("VALID_BUT_UNAUTHORIZED") => "valid_but_unauthorized",
        _ => "baseline",
    }
}

fn is_deprecated_signature(algorithm: &str) -> bool {
    let lowered = algorithm.to_ascii_lowercase();
    lowered.contains("sha1") || lowered.contains("md5")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unknown_advisory_fields_are_rejected() {
        let raw = br#"{"recommended_detectors":[],"threat_event":"VALID","notes":["cracked"],"source":"llm","private_key":"abcd","certificate_status":"VALID"}"#;
        assert!(parse_advisory(raw).is_err());
    }

    #[test]
    fn scripted_model_cannot_rewrite_the_verdict() {
        let verdict = VerdictSnapshot {
            certificate_status: "WEAK_KEY".into(),
            risk_class: Some("WEAK_CRYPTOGRAPHY".into()),
        };
        let before = verdict.clone();
        let advisory = ScriptedLlmProvider::conflicting()
            .complete(&AdvisoryRequest {
                observation: PublicObservation {
                    key_type: Some("rsa".into()),
                    bits: Some(512),
                    exponent_bits: Some(17),
                    signature_algorithm: Some("sha256WithRSAEncryption".into()),
                    duplicate_nonce_r: false,
                },
                certificate_status: verdict.certificate_status.clone(),
                risk_class: verdict.risk_class.clone(),
            })
            .unwrap();
        let applied = apply_advisory(&verdict, advisory);
        assert_eq!(applied.verdict, before);
        assert_eq!(applied.verdict.certificate_status, "WEAK_KEY");
        assert_eq!(applied.advisory.threat_event, "VALID");
    }

    #[test]
    fn deterministic_rules_follow_public_features() {
        let advice = DeterministicRea.advise(
            &PublicObservation {
                key_type: Some("rsa".into()),
                bits: Some(512),
                exponent_bits: Some(500),
                signature_algorithm: Some("sha1WithRSAEncryption".into()),
                duplicate_nonce_r: true,
            },
            &VerdictSnapshot {
                certificate_status: "ROCA_FINGERPRINT".into(),
                risk_class: Some("WEAK_CRYPTOGRAPHY".into()),
            },
        );
        assert_eq!(advice.source, "deterministic");
        assert_eq!(advice.threat_event, "weak_cryptography");
        assert!(advice
            .recommended_detectors
            .iter()
            .any(|d| d == "roca-fingerprint"));
        assert!(advice
            .recommended_detectors
            .iter()
            .any(|d| d == "structural-weakness"));
        assert!(advice
            .recommended_detectors
            .iter()
            .any(|d| d == "nonce-reuse"));
        assert!(advice
            .recommended_detectors
            .iter()
            .any(|d| d == "deprecated-signature"));
    }

    #[test]
    fn disabled_provider_does_not_answer() {
        let err = DisabledLlmProvider.complete(&AdvisoryRequest {
            observation: PublicObservation {
                key_type: None,
                bits: None,
                exponent_bits: None,
                signature_algorithm: None,
                duplicate_nonce_r: false,
            },
            certificate_status: "VALID".into(),
            risk_class: None,
        });
        assert_eq!(err.unwrap_err(), ProviderError::Disabled);
    }
}
