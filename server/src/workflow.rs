//! Delivery jobs retain their request and policy revision across process restarts.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Recipient {
    pub email: String,
    pub holder: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Sequence {
    pub prefix: String,
    pub suffix: String,
    pub first: u32,
    pub last: u32,
    pub padding: usize,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub struct MediaCheck {
    pub video_codec: Option<String>,
    pub width: Option<u32>,
    pub height: Option<u32>,
    pub frame_rate: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Project {
    #[serde(default, skip_serializing_if = "is_zero")]
    pub notification_revision: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub notifications: Option<crate::store::NotificationPolicy>,
    pub id: String,
    #[serde(default)]
    pub revision: u64,
    pub label: String,
    pub directory: String,
    #[serde(default)]
    pub members: BTreeMap<String, String>,
    #[serde(default)]
    pub recipients: Vec<Recipient>,
    #[serde(default)]
    pub allowed_domains: Vec<String>,
    #[serde(default)]
    pub require_approval: bool,
    #[serde(default)]
    pub required_metadata: Vec<String>,
    pub sequence: Option<Sequence>,
    pub media: Option<MediaCheck>,
    #[serde(default)]
    pub scan_required: bool,
    #[serde(default)]
    pub destinations: Vec<String>,
    #[serde(default)]
    pub receive: bool,
    #[serde(default)]
    pub release: Release,
}

#[derive(Clone, Copy, Debug, Default, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum Release {
    #[default]
    AllDestinations,
    Local,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct JobRequest {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub notifications: Option<crate::store::NotificationPolicy>,
    pub operation_id: String,
    pub project_id: String,
    pub label: String,
    #[serde(default)]
    pub metadata: BTreeMap<String, String>,
    #[serde(default)]
    pub recipients: Vec<String>,
    pub not_before: Option<u64>,
    pub deadline: Option<u64>,
    pub expires_days: u64,
    pub import: Option<Import>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Import {
    pub storage_id: String,
    pub prefix: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Job {
    pub id: String,
    pub tenant: String,
    pub token_generation: u64,
    pub actor: String,
    pub credential_version: u64,
    pub automation_token_id: Option<String>,
    pub request: JobRequest,
    pub project: Project,
    pub state: String,
    pub manifest: Option<String>,
    pub approved_by: Option<String>,
    pub attempts: u64,
    pub created_at: u64,
    pub updated_at: u64,
    pub error: Option<String>,
    pub checks: serde_json::Value,
    #[serde(default)]
    pub received: Option<Received>,
}

impl Job {
    pub fn released(&self) -> bool {
        self.state == "ready"
            || (self.checks["released_at"].as_u64().is_some()
                && ["exporting", "retrying", "failed"].contains(&self.state.as_str()))
    }

    pub fn uses_snapshot(&self) -> bool {
        self.received.is_none()
            && (self.project.media.is_some()
                || self.project.scan_required
                || self.request.import.is_some())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Received {
    pub link_id: String,
    pub upload_id: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ReceiveWorkflow {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub notifications: Option<crate::store::NotificationPolicy>,
    pub project_id: String,
    #[serde(default)]
    pub metadata: BTreeMap<String, String>,
    #[serde(default)]
    pub recipients: Vec<String>,
}

impl ReceiveWorkflow {
    pub fn request(&self, operation_id: &str, label: &str) -> JobRequest {
        JobRequest {
            notifications: self.notifications.clone(),
            operation_id: operation_id.into(),
            project_id: self.project_id.clone(),
            label: label.into(),
            metadata: self.metadata.clone(),
            recipients: self.recipients.clone(),
            not_before: None,
            deadline: None,
            expires_days: 30,
            import: None,
        }
    }
}

pub fn within(directory: &str, path: &str) -> bool {
    use unicode_normalization::UnicodeNormalization;
    let directory: String = directory.nfkc().flat_map(char::to_uppercase).collect();
    let path: String = path.nfkc().flat_map(char::to_uppercase).collect();
    path == directory
        || path
            .strip_prefix(&directory)
            .is_some_and(|rest| rest.starts_with('/'))
}

pub fn valid_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 100
        && value
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'-' | b'_'))
}

pub fn valid_path(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 1024
        && !value.contains(['\\', '\0'])
        && value
            .split('/')
            .all(|part| !part.is_empty() && part != "." && part != "..")
}

fn is_zero(value: &u64) -> bool {
    *value == 0
}

impl Project {
    pub fn same_delivery_policy(&self, other: &Self) -> bool {
        let mut policy = self.clone();
        policy.notifications = other.notifications.clone();
        policy.notification_revision = other.notification_revision;
        policy == *other
    }
    pub fn validate(&self) -> Result<(), String> {
        if !valid_id(&self.id)
            || self.label.trim().is_empty()
            || self.label.len() > 200
            || !valid_path(&self.directory)
        {
            return Err("project needs a valid ID, label and relative library directory".into());
        }
        if self.members.len() > 500
            || self.members.iter().any(|(subject, role)| {
                subject.is_empty()
                    || subject.len() > 500
                    || !["sender", "approver", "viewer"].contains(&role.as_str())
            })
        {
            return Err("project members require sender, approver or viewer roles".into());
        }
        if self.allowed_domains.len() > 100
            || self.allowed_domains.iter().any(|domain| {
                domain.is_empty()
                    || domain.len() > 253
                    || domain != &domain.to_ascii_lowercase()
                    || !domain
                        .bytes()
                        .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'.' | b'-'))
            })
        {
            return Err("allowed domains must be lowercase DNS names".into());
        }
        let mut holders = std::collections::BTreeSet::new();
        if self.recipients.len() > 500
            || self.recipients.iter().any(|recipient| {
                let email_valid = recipient.email.len() <= 254
                    && !recipient.email.chars().any(char::is_whitespace)
                    && recipient
                        .email
                        .split_once('@')
                        .is_some_and(|(local, domain)| {
                            !local.is_empty()
                                && !domain.contains('@')
                                && !domain.is_empty()
                                && (self.allowed_domains.is_empty()
                                    || self
                                        .allowed_domains
                                        .iter()
                                        .any(|d| domain.eq_ignore_ascii_case(d)))
                        });
                !email_valid
                    || !valid_holder(&recipient.holder)
                    || !holders.insert(&recipient.holder)
            })
        {
            return Err(
                "recipients need unique lowercase device public keys and permitted email domains"
                    .into(),
            );
        }
        if !self.allowed_domains.is_empty() && self.recipients.is_empty() {
            return Err("domain restrictions require enrolled recipients".into());
        }
        if self.required_metadata.len() > 50
            || self.required_metadata.iter().any(|key| !valid_id(key))
        {
            return Err("required metadata must contain at most 50 field IDs".into());
        }
        if let Some(sequence) = &self.sequence {
            if sequence.first > sequence.last
                || sequence.last - sequence.first > 1_000_000
                || !(1..=10).contains(&sequence.padding)
                || !valid_path(&format!("{}0{}", sequence.prefix, sequence.suffix))
            {
                return Err("invalid sequence range or filename pattern".into());
            }
        }
        if self.destinations.len() > 16
            || self.destinations.iter().any(|id| !valid_id(id))
            || self
                .destinations
                .iter()
                .collect::<std::collections::BTreeSet<_>>()
                .len()
                != self.destinations.len()
        {
            return Err("choose at most 16 unique destinations".into());
        }
        if let Some(media) = &self.media {
            if media.video_codec.as_ref().is_some_and(|v| !valid_id(v))
                || media.width == Some(0)
                || media.height == Some(0)
                || media
                    .frame_rate
                    .as_ref()
                    .is_some_and(|value| frame_rate(value).is_none())
            {
                return Err("invalid media check".into());
            }
        }
        Ok(())
    }

    pub fn allows(&self, actor: &str, role: &str, administrator: bool) -> bool {
        administrator
            || self.members.get(actor).is_some_and(|allowed| {
                allowed == role
                    || (role == "viewer" && ["sender", "approver"].contains(&allowed.as_str()))
            })
    }

    pub fn validate_job(&self, request: &JobRequest, now: u64) -> Result<(), String> {
        if !valid_id(&request.operation_id)
            || request.project_id != self.id
            || request.label.trim().is_empty()
            || request.label.len() > 200
            || !(1..=365).contains(&request.expires_days)
            || request
                .not_before
                .is_some_and(|t| t > now.saturating_add(365 * 86400))
            || request.deadline.is_some_and(|t| {
                t <= request.not_before.unwrap_or(now).max(now)
                    || t > now.saturating_add(366 * 86400)
            })
        {
            return Err("invalid delivery operation, label, schedule or lifetime".into());
        }
        if request.metadata.len() > 50
            || request
                .metadata
                .iter()
                .any(|(k, v)| !valid_id(k) || v.len() > 4096)
            || self.required_metadata.iter().any(|key| {
                request
                    .metadata
                    .get(key)
                    .is_none_or(|v| v.trim().is_empty())
            })
        {
            return Err("required delivery metadata is missing or invalid".into());
        }
        if request.recipients.len() > 500
            || (!self.recipients.is_empty() && request.recipients.is_empty())
            || request
                .recipients
                .iter()
                .any(|holder| !self.recipients.iter().any(|r| &r.holder == holder))
        {
            return Err("choose enrolled project recipients".into());
        }
        if request
            .import
            .as_ref()
            .is_some_and(|import| !valid_id(&import.storage_id) || !valid_path(&import.prefix))
        {
            return Err("invalid storage import".into());
        }
        Ok(())
    }
}

pub fn frame_rate(value: &str) -> Option<(u64, u64)> {
    let (a, b) = value.split_once('/')?;
    let a = a.parse::<u32>().ok()?;
    let b = b.parse::<u32>().ok()?;
    (a > 0 && b > 0).then_some((u64::from(a), u64::from(b)))
}

pub fn same_frame_rate(expected: &str, actual: &str) -> bool {
    frame_rate(expected)
        .zip(frame_rate(actual))
        .is_some_and(|((a, b), (c, d))| a * d == c * b)
}

pub fn valid_holder(holder: &str) -> bool {
    holder.len() == 64
        && holder == holder.to_ascii_lowercase()
        && hex::decode(holder)
            .ok()
            .and_then(|bytes| <[u8; 32]>::try_from(bytes).ok())
            .and_then(|bytes| ed25519_dalek::VerifyingKey::from_bytes(&bytes).ok())
            .is_some()
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    pub fn project() -> Project {
        Project {
            notification_revision: 0,
            notifications: None,
            id: "project".into(),
            revision: 0,
            label: "Delivery project".into(),
            directory: "project".into(),
            members: BTreeMap::from([
                ("sender".into(), "sender".into()),
                ("approver".into(), "approver".into()),
                ("observer".into(), "viewer".into()),
            ]),
            recipients: vec![],
            allowed_domains: vec![],
            require_approval: true,
            required_metadata: vec!["client".into()],
            sequence: None,
            media: None,
            scan_required: false,
            destinations: vec![],
            receive: false,
            release: Release::AllDestinations,
        }
    }

    pub fn request() -> JobRequest {
        JobRequest {
            notifications: None,
            operation_id: "operation_1".into(),
            project_id: "project".into(),
            label: "Final delivery".into(),
            metadata: BTreeMap::from([("client".into(), "Example".into())]),
            recipients: vec![],
            not_before: None,
            deadline: None,
            expires_days: 1,
            import: None,
        }
    }

    #[test]
    fn media_rates_compare_exact_ratios_and_reject_invalid_values() {
        for (expected, actual, equal) in [
            ("30000/1001", "60000/2002", true),
            ("24/1", "24000/1000", true),
            ("24/1", "24000/1001", false),
            ("4294967295/1", "4294967295/1", true),
            ("0/1", "0/1", false),
            ("1/0", "1/0", false),
            ("1/1/1", "1/1", false),
            ("4294967296/1", "1/1", false),
            ("24", "24/1", false),
        ] {
            assert_eq!(
                same_frame_rate(expected, actual),
                equal,
                "{expected}: {actual}"
            );
        }
    }

    #[test]
    fn policy_paths_and_roles_have_component_boundaries() {
        for path in [
            "project",
            "project/sub/file",
            "PROJECT/file",
            "ｐｒｏｊｅｃｔ/file",
        ] {
            assert!(within("project", path));
        }
        for path in [
            "project-old/file",
            "projects/file",
            "other/project",
            "projectish",
        ] {
            assert!(!within("project", path));
        }
        assert!(within("Café", "Cafe\u{301}/file"));
        for path in [
            "",
            "/project",
            "project/",
            "../project",
            "project/../file",
            "a\\b",
            "a\0b",
            "a//b",
        ] {
            assert!(!valid_path(path));
        }
        for id in ["", "a/b", "x.y", "x y", &"a".repeat(101)] {
            assert!(!valid_id(id));
        }
        assert!(valid_id(&"a".repeat(100)));
        let project = project();
        assert!(project.validate().is_ok());
        for (actor, role, allowed) in [
            ("sender", "sender", true),
            ("sender", "viewer", true),
            ("sender", "approver", false),
            ("approver", "approver", true),
            ("approver", "viewer", true),
            ("observer", "viewer", true),
            ("observer", "sender", false),
            ("stranger", "viewer", false),
        ] {
            assert_eq!(project.allows(actor, role, false), allowed);
        }
        assert!(project.allows("admin", "approver", true));
    }

    #[test]
    fn templates_require_metadata_valid_schedules_and_enrolled_recipients() {
        let mut project = project();
        let mut request = request();
        assert!(project.validate_job(&request, 100).is_ok());
        request.metadata.clear();
        assert!(project.validate_job(&request, 100).is_err());
        request.metadata.insert("client".into(), "  ".into());
        assert!(project.validate_job(&request, 100).is_err());
        request.metadata.insert("client".into(), "Example".into());
        for days in [0, 366, u64::MAX] {
            request.expires_days = days;
            assert!(project.validate_job(&request, 100).is_err());
        }
        request.expires_days = 365;
        for deadline in [99, 100, 100 + 366 * 86400 + 1] {
            request.deadline = Some(deadline);
            assert!(project.validate_job(&request, 100).is_err());
        }
        request.deadline = Some(101);
        assert!(project.validate_job(&request, 100).is_ok());
        request.not_before = Some(101);
        assert!(project.validate_job(&request, 100).is_err());
        request.deadline = None;
        request.not_before = Some(100 + 365 * 86400);
        assert!(project.validate_job(&request, 100).is_ok());
        request.not_before = Some(100 + 365 * 86400 + 1);
        assert!(project.validate_job(&request, 100).is_err());
        request.not_before = None;
        let holder = hex::encode(
            ed25519_dalek::SigningKey::from_bytes(&[2; 32])
                .verifying_key()
                .to_bytes(),
        );
        project.allowed_domains = vec!["example.com".into()];
        assert!(project.validate().is_err());
        project.recipients = vec![Recipient {
            email: "person@elsewhere.com".into(),
            holder: holder.clone(),
        }];
        assert!(project.validate().is_err());
        project.recipients[0].email = "person@Example.com".into();
        assert!(project.validate().is_ok());
        assert!(project.validate_job(&request, 100).is_err());
        request.recipients = vec![holder.clone()];
        assert!(project.validate_job(&request, 100).is_ok());
        request.recipients = vec!["other".into()];
        assert!(project.validate_job(&request, 100).is_err());
        assert!(valid_holder(&holder));
        assert!(!valid_holder(&holder.to_ascii_uppercase()));
        assert!(!valid_holder(&"gg".repeat(32)));
        assert!(!valid_holder("ab"));
        project.recipients.push(project.recipients[0].clone());
        assert!(project.validate().is_err());
    }
}
