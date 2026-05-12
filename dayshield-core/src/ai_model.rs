use std::{fs, io::Write, net::IpAddr, path::{Path, PathBuf}};

use anyhow::{Context, Result};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::{config::models::{AiEngineConfig, AiModelType}, logs::LogEvent};

#[derive(Debug, Serialize, Deserialize)]
struct AiModelState {
    weights: Vec<f64>,
    learning_rate: f64,
}

/// Numeric history features that provide context for current events.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AiContextFeatures {
    pub recent_high_risk_count: f64,
    pub recent_feedback_malicious: f64,
    pub recent_feedback_false_positive: f64,
    pub recent_manual_unblock: f64,
    pub recent_firewall_drops: f64,
    pub recent_firewall_accepts: f64,
    pub recent_scan_events: f64,
    pub crowdsec_decisions: f64,
    pub dns_blocklist_configured: f64,
}

/// Abstraction over AI model runtimes.
#[derive(Debug, Clone)]
pub struct AiModel {
    inner: AiModelRuntime,
    training_enabled: bool,
}

#[derive(Debug, Clone)]
enum AiModelRuntime {
    Local(LocalLogisticModel),
    Remote(RemoteInferenceModel),
}

#[derive(Debug, Clone)]
struct LocalLogisticModel {
    weights: Vec<f64>,
    learning_rate: f64,
    path: PathBuf,
}

#[derive(Debug, Clone)]
struct RemoteInferenceModel {
    client: Client,
    url: String,
    api_key: Option<String>,
}

impl AiModel {
    pub fn new(config_dir: &Path, config: &AiEngineConfig) -> Self {
        let runtime = match config.model_type {
            AiModelType::Remote => match config.remote_inference_url.clone() {
                Some(url) => AiModelRuntime::Remote(RemoteInferenceModel::new(url, config.remote_api_key.clone())),
                None => AiModelRuntime::Local(LocalLogisticModel::new(config_dir, config.model_learning_rate)),
            },
            AiModelType::Local => AiModelRuntime::Local(LocalLogisticModel::new(config_dir, config.model_learning_rate)),
        };

        Self {
            inner: runtime,
            training_enabled: config.training_enabled,
        }
    }

    pub async fn predict_suricata_alert(
        &self,
        signature: &str,
        severity: u8,
        category: Option<&str>,
        protocol: &str,
        src_ip: &str,
        dst_ip: &str,
        src_port: Option<u16>,
        dst_port: Option<u16>,
        history: &AiContextFeatures,
    ) -> Result<(f64, Vec<String>)> {
        match &self.inner {
            AiModelRuntime::Local(local) => Ok(local.predict_suricata_alert(
                signature,
                severity,
                category,
                protocol,
                src_ip,
                dst_ip,
                src_port,
                dst_port,
                history,
            )),
            AiModelRuntime::Remote(remote) => remote
                .predict(
                    "suricata",
                    Some(signature),
                    Some(severity),
                    category,
                    protocol,
                    src_ip,
                    dst_ip,
                    src_port,
                    dst_port,
                    None,
                    None,
                    history,
                )
                .await,
        }
    }

    pub async fn predict_firewall_event(
        &self,
        action: &str,
        protocol: &str,
        src_ip: &str,
        dst_ip: &str,
        src_port: Option<u16>,
        dst_port: Option<u16>,
        iface: &str,
        history: &AiContextFeatures,
    ) -> Result<(f64, Vec<String>)> {
        match &self.inner {
            AiModelRuntime::Local(local) => Ok(local.predict_firewall_event(
                action,
                protocol,
                src_ip,
                dst_ip,
                src_port,
                dst_port,
                iface,
                history,
            )),
            AiModelRuntime::Remote(remote) => remote
                .predict(
                    "firewall",
                    None,
                    None,
                    None,
                    protocol,
                    src_ip,
                    dst_ip,
                    src_port,
                    dst_port,
                    Some(action),
                    Some(iface),
                    history,
                )
                .await,
        }
    }

    pub async fn predict_event(&self, event: &LogEvent, history: &AiContextFeatures) -> Result<(f64, Vec<String>)> {
        match event {
            LogEvent::SuricataAlert {
                signature,
                severity,
                category,
                proto,
                src_ip,
                dest_ip,
                src_port,
                dest_port,
                ..
            } => self
                .predict_suricata_alert(
                    signature,
                    *severity,
                    category.as_deref(),
                    proto,
                    src_ip,
                    dest_ip,
                    *src_port,
                    *dest_port,
                    history,
                )
                .await,
            LogEvent::FirewallEvent {
                action,
                proto,
                src_ip,
                dest_ip,
                sport,
                dport,
                iface,
                ..
            } => self
                .predict_firewall_event(
                    action,
                    proto,
                    src_ip,
                    dest_ip,
                    Some(*sport).filter(|port| *port != 0),
                    Some(*dport).filter(|port| *port != 0),
                    iface,
                    history,
                )
                .await,
            _ => Ok((0.0, vec!["Unsupported event type for AI scoring".to_string()])),
        }
    }

    pub fn train_on_feedback(&mut self, features: &[f64], label: f64) -> Result<()> {
        if !self.training_enabled {
            return Ok(());
        }

        match &mut self.inner {
            AiModelRuntime::Local(local) => local.train_on_feedback(features, label),
            AiModelRuntime::Remote(_) => Ok(()),
        }
    }

    pub fn save(&self) -> Result<()> {
        if let AiModelRuntime::Local(local) = &self.inner {
            local.save()
        } else {
            Ok(())
        }
    }
}

impl LocalLogisticModel {
    pub fn new(config_dir: &Path, learning_rate: f64) -> Self {
        let model_path = config_dir.join("ai_engine").join("model_weights.json");
        let state = fs::read_to_string(&model_path)
            .ok()
            .and_then(|raw| serde_json::from_str::<AiModelState>(&raw).ok());

        let weights = state.as_ref().map(|s| s.weights.clone()).unwrap_or_else(Self::default_weights);
        let lr = state.as_ref().map(|s| s.learning_rate).unwrap_or(learning_rate);

        let model = Self {
            weights,
            learning_rate: lr,
            path: model_path,
        };

        let _ = model.save();
        model
    }

    fn default_weights() -> Vec<f64> {
        vec![
            -2.4, // bias
            1.10, // severity
            0.25, // src_public
            0.15, // dst_public
            0.90, // scan
            1.10, // brute/password
            1.40, // malware/botnet
            0.75, // ssh
            0.80, // rdp
            0.40, // http
            0.22, // tcp
            0.10, // udp
            0.18, // icmp
            0.60, // high_risk_port
            0.85, // action_drop
            -0.25, // action_accept
            0.15, // action_other
            0.12, // external_iface
            0.25, // recent_scan_events
            0.55, // crowdsec_decisions
            0.35, // dns_blocklist_configured
            0.20, // recent_high_risk_count
            1.25, // recent_feedback_malicious
            -1.10, // recent_feedback_false_positive
            -0.75, // recent_manual_unblock
            0.40, // recent_firewall_drops
            0.10, // recent_firewall_accepts
        ]
    }

    fn predict_suricata_alert(
        &self,
        signature: &str,
        severity: u8,
        category: Option<&str>,
        protocol: &str,
        src_ip: &str,
        dst_ip: &str,
        src_port: Option<u16>,
        dst_port: Option<u16>,
        history: &AiContextFeatures,
    ) -> (f64, Vec<String>) {
        let (features, reasons) = AiModel::build_feature_vector(
            Some(signature),
            Some(severity),
            category,
            protocol,
            src_ip,
            dst_ip,
            src_port,
            dst_port,
            None,
            None,
            history,
        );
        let score = self.predict(&features);
        (score, reasons)
    }

    fn predict_firewall_event(
        &self,
        action: &str,
        protocol: &str,
        src_ip: &str,
        dst_ip: &str,
        src_port: Option<u16>,
        dst_port: Option<u16>,
        iface: &str,
        history: &AiContextFeatures,
    ) -> (f64, Vec<String>) {
        let (features, reasons) = AiModel::build_feature_vector(
            None,
            None,
            None,
            protocol,
            src_ip,
            dst_ip,
            src_port,
            dst_port,
            Some(action),
            Some(iface),
            history,
        );
        let score = self.predict(&features);
        (score, reasons)
    }

    fn train_on_feedback(&mut self, features: &[f64], label: f64) -> Result<()> {
        let prediction = self.predict(features);
        let error = label - prediction;
        for (weight, feature) in self.weights.iter_mut().zip(features.iter()) {
            *weight += self.learning_rate * error * feature;
        }
        self.save()
    }

    fn predict(&self, features: &[f64]) -> f64 {
        let raw: f64 = self.weights.iter().zip(features.iter()).map(|(w, f)| w * f).sum();
        1.0 / (1.0 + (-raw).exp())
    }

    fn save(&self) -> Result<()> {
        if let Some(parent) = self.path.parent() {
            fs::create_dir_all(parent)
                .with_context(|| format!("failed to create model directory {}", parent.display()))?;
        }

        let state = AiModelState {
            weights: self.weights.clone(),
            learning_rate: self.learning_rate,
        };
        let raw = serde_json::to_string_pretty(&state)?;
        let mut file = fs::File::create(&self.path)
            .with_context(|| format!("failed to open {} for writing", self.path.display()))?;
        file.write_all(raw.as_bytes())?;
        Ok(())
    }

    pub fn reset_to_default_weights(&mut self) {
        self.weights = Self::default_weights();
    }
}

impl RemoteInferenceModel {
    pub fn new(url: String, api_key: Option<String>) -> Self {
        Self {
            client: Client::new(),
            url,
            api_key,
        }
    }

    async fn predict(
        &self,
        event_type: &str,
        signature: Option<&str>,
        severity: Option<u8>,
        category: Option<&str>,
        protocol: &str,
        src_ip: &str,
        dst_ip: &str,
        src_port: Option<u16>,
        dst_port: Option<u16>,
        action: Option<&str>,
        iface: Option<&str>,
        history: &AiContextFeatures,
    ) -> Result<(f64, Vec<String>)> {
        let payload = json!({
            "event_type": event_type,
            "signature": signature,
            "severity": severity,
            "category": category,
            "protocol": protocol,
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "src_port": src_port,
            "dst_port": dst_port,
            "action": action,
            "iface": iface,
            "history": history,
        });

        let mut request = self.client.post(&self.url).json(&payload);
        if let Some(key) = &self.api_key {
            request = request.header("Authorization", format!("Bearer {}", key));
        }

        let response = request.send().await?.error_for_status()?;
        let inference: RemoteInferenceResponse = response.json().await?;
        Ok((inference.risk_score, inference.reasons))
    }
}

#[derive(Debug, Deserialize)]
struct RemoteInferenceResponse {
    risk_score: f64,
    reasons: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    #[test]
    fn suricata_model_scores_severity_correctly() {
        let model = LocalLogisticModel::new(Path::new("."), 0.25);
        let history = AiContextFeatures::default();
        let (score, reasons) = model.predict_suricata_alert(
            "ET SYNC Scan",
            1,
            Some("Scan"),
            "TCP",
            "203.0.113.1",
            "10.0.0.1",
            Some(443),
            Some(80),
            &history,
        );

        assert!(score >= 0.9, "expected high score for severity 1 scan");
        assert!(reasons.iter().any(|r| r.contains("Signature matched")));
    }

    #[test]
    fn firewall_model_applies_drop_and_port_features() {
        let model = LocalLogisticModel::new(Path::new("."), 0.25);
        let history = AiContextFeatures::default();
        let (score, reasons) = model.predict_firewall_event(
            "DROP",
            "TCP",
            "198.51.100.22",
            "192.0.2.5",
            Some(55555),
            Some(22),
            "eth0",
            &history,
        );

        assert!(score > 0.4, "expected firewall drop on high-risk port to raise risk");
        assert!(reasons.iter().any(|r| r.contains("Firewall drop action observed")));
        assert!(reasons.iter().any(|r| r.contains("High-risk port observed")));
    }
}
