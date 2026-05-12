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

    pub fn reset_to_default_weights(&mut self) {
        if let AiModelRuntime::Local(local) = &mut self.inner {
            local.reset_to_default_weights();
        }
    }

    pub fn build_feature_vector(
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
    ) -> (Vec<f64>, Vec<String>) {
        let mut reasons = Vec::new();
        let normalized_severity = severity.map(Self::normalize_severity).unwrap_or(0.25);

        let signature_lc = signature.unwrap_or_default().to_lowercase();
        let category_lc = category.unwrap_or_default().to_lowercase();

        if let Some(sig) = signature {
            reasons.push(format!("Signature matched: {}", sig));
        }
        if !category_lc.is_empty() {
            reasons.push(format!("Alert category: {}", category_lc));
        }

        let scan = (signature_lc.contains("scan") || category_lc.contains("scan") || category_lc.contains("recon")) as u8 as f64;
        let brute = (signature_lc.contains("brute") || signature_lc.contains("password") || category_lc.contains("brute")) as u8 as f64;
        let malware = (signature_lc.contains("botnet")
            || signature_lc.contains("malware")
            || signature_lc.contains("trojan")
            || signature_lc.contains("ransomware")
            || category_lc.contains("malware")) as u8 as f64;
        let ssh = (signature_lc.contains("ssh") || category_lc.contains("ssh")) as u8 as f64;
        let rdp = (signature_lc.contains("rdp") || category_lc.contains("rdp")) as u8 as f64;
        let http = ((protocol.eq_ignore_ascii_case("tcp") && signature_lc.contains("http")) || category_lc.contains("http")) as u8 as f64;

        let proto_tcp = protocol.eq_ignore_ascii_case("tcp") as u8 as f64;
        let proto_udp = protocol.eq_ignore_ascii_case("udp") as u8 as f64;
        let proto_icmp = protocol.eq_ignore_ascii_case("icmp") as u8 as f64;

        let high_risk_port = Self::is_high_risk_port(src_port) || Self::is_high_risk_port(dst_port);
        let high_risk_port = if high_risk_port { 1.0 } else { 0.0 };

        let action_drop = action.map_or(0.0, |a| a.eq_ignore_ascii_case("drop") as u8 as f64);
        let action_accept = action.map_or(0.0, |a| a.eq_ignore_ascii_case("accept") as u8 as f64);
        let action_other = if action.is_some() && action_drop == 0.0 && action_accept == 0.0 {
            1.0
        } else {
            0.0
        };

        let external_iface = iface
            .map(|value| {
                let lower = value.to_lowercase();
                !lower.is_empty() && lower != "lo" && !lower.starts_with("br") && !lower.starts_with("docker")
            })
            .unwrap_or(false) as u8 as f64;

        let src_public = Self::is_public_ip(src_ip) as u8 as f64;
        let dst_public = Self::is_public_ip(dst_ip) as u8 as f64;

        if src_public > 0.0 {
            reasons.push("Source IP appears public".to_string());
        }
        if dst_public > 0.0 {
            reasons.push("Destination IP appears public".to_string());
        }
        if action_drop > 0.0 {
            reasons.push("Firewall drop action observed".to_string());
        }
        if action_accept > 0.0 {
            reasons.push("Firewall accept action observed".to_string());
        }
        if high_risk_port > 0.0 {
            reasons.push("High-risk port observed".to_string());
        }
        if history.recent_high_risk_count > 0.0 {
            reasons.push(format!("{} recent high-risk events for this source", history.recent_high_risk_count));
        }
        if history.recent_feedback_malicious > 0.0 {
            reasons.push("Source IP has prior confirmed malicious feedback".to_string());
        }
        if history.recent_feedback_false_positive > 0.0 {
            reasons.push("Source IP has prior false positive feedback".to_string());
        }
        if history.recent_manual_unblock > 0.0 {
            reasons.push("Source IP was manually unblocked previously".to_string());
        }
        if history.recent_firewall_drops > 0.0 {
            reasons.push(format!("{} recent firewall drop events", history.recent_firewall_drops));
        }
        if history.recent_scan_events > 0.0 {
            reasons.push(format!("{} recent scan-like events", history.recent_scan_events));
        }
        if history.crowdsec_decisions > 0.0 {
            reasons.push("CrowdSec has decisions for this source IP".to_string());
        }
        if history.dns_blocklist_configured > 0.0 {
            reasons.push("DNS blocklist sources are configured".to_string());
        }

        if reasons.is_empty() {
            reasons.push("AI model applied baseline risk features".to_string());
        }

        let features = vec![
            1.0,
            normalized_severity,
            src_public,
            dst_public,
            scan,
            brute,
            malware,
            ssh,
            rdp,
            http,
            proto_tcp,
            proto_udp,
            proto_icmp,
            high_risk_port,
            action_drop,
            action_accept,
            action_other,
            external_iface,
            history.recent_scan_events,
            history.crowdsec_decisions,
            history.dns_blocklist_configured,
            history.recent_high_risk_count,
            history.recent_feedback_malicious,
            history.recent_feedback_false_positive,
            history.recent_manual_unblock,
            history.recent_firewall_drops,
            history.recent_firewall_accepts,
        ];

        (features, reasons)
    }

    fn normalize_severity(severity: u8) -> f64 {
        match severity {
            1 => 1.0,
            2 => 0.75,
            3 => 0.45,
            _ => 0.25,
        }
    }

    fn is_high_risk_port(port: Option<u16>) -> bool {
        matches!(port, Some(22 | 23 | 25 | 53 | 80 | 123 | 443 | 445 | 3389 | 5900 | 8080))
    }

    fn is_public_ip(value: &str) -> bool {
        value
            .parse::<IpAddr>()
            .map(|ip| match ip {
                IpAddr::V4(addr) => {
                    !(addr.is_private() || addr.is_loopback() || addr.is_link_local() || addr.is_broadcast() || addr.is_documentation())
                }
                IpAddr::V6(addr) => {
                    !(addr.is_loopback() || addr.is_unique_local() || addr.is_unspecified() || addr.is_multicast())
                }
            })
            .unwrap_or(false)
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
