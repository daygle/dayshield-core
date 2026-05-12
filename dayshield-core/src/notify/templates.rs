//! Email template helpers - one formatter per notification category.

/// Format a Suricata IDS/IPS alert email.
///
/// Returns `(subject, body)`.
pub fn suricata_alert(signature: &str, severity: u8) -> (String, String) {
    let subject = format!("[Suricata] {signature} (severity {severity})");
    let body = format!(
        "DayShield Suricata Alert\n\
         ========================\n\
         Signature : {signature}\n\
         Severity  : {severity}\n"
    );
    (subject, body)
}

/// Format a CrowdSec decision email.
///
/// Returns `(subject, body)`.
pub fn crowdsec_decision(action: &str, ip: &str) -> (String, String) {
    let subject = format!("[CrowdSec] {action} {ip}");
    let body = format!(
        "DayShield CrowdSec Decision\n\
         ============================\n\
         Action : {action}\n\
         IP     : {ip}\n"
    );
    (subject, body)
}

/// Format an ACME certificate expiry or renewal-failure email.
///
/// Returns `(subject, body)`.
pub fn acme_expiry(days: i64) -> (String, String) {
    let subject = format!("[ACME] Certificate expires in {days} days");
    let body = format!(
        "DayShield ACME Certificate Alert\n\
         =================================\n\
         Your TLS certificate will expire in {days} day(s).\n\
         Please renew it as soon as possible.\n"
    );
    (subject, body)
}

/// Format an ACME renewal failure email.
///
/// Returns `(subject, body)`.
pub fn acme_renewal_failure(domain: &str, reason: &str) -> (String, String) {
    let subject = format!("[ACME] Certificate renewal failed for {domain}");
    let body = format!(
        "DayShield ACME Renewal Failure\n\
         ================================\n\
         Domain : {domain}\n\
         Reason : {reason}\n"
    );
    (subject, body)
}

/// Format a system-level alert email.
///
/// Returns `(subject, body)`.
pub fn system_alert(unit: &str, message: &str) -> (String, String) {
    let subject = format!("[System] {unit}: {message}");
    let body = format!(
        "DayShield System Alert\n\
         =======================\n\
         Unit    : {unit}\n\
         Message : {message}\n"
    );
    (subject, body)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn suricata_subject_format() {
        let (subj, _) = suricata_alert("ET SCAN Port Scan", 2);
        assert_eq!(subj, "[Suricata] ET SCAN Port Scan (severity 2)");
    }

    #[test]
    fn crowdsec_subject_format() {
        let (subj, _) = crowdsec_decision("ban", "1.2.3.4");
        assert_eq!(subj, "[CrowdSec] ban 1.2.3.4");
    }

    #[test]
    fn acme_expiry_subject_format() {
        let (subj, _) = acme_expiry(7);
        assert_eq!(subj, "[ACME] Certificate expires in 7 days");
    }

    #[test]
    fn acme_renewal_failure_subject_format() {
        let (subj, _) = acme_renewal_failure("example.com", "DNS timeout");
        assert_eq!(subj, "[ACME] Certificate renewal failed for example.com");
    }

    #[test]
    fn system_alert_subject_format() {
        let (subj, _) = system_alert("sshd", "authentication failure");
        assert_eq!(subj, "[System] sshd: authentication failure");
    }
}
