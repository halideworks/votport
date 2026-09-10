use crate::{port, Error};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::HashMap;

#[derive(Clone, Debug, Deserialize, uniffi::Record)]
pub struct WorkflowRecipient {
    pub email: String,
    pub holder: String,
}

#[derive(Clone, Debug, Deserialize, uniffi::Record)]
pub struct WorkflowProject {
    pub id: String,
    pub revision: u64,
    pub label: String,
    pub directory: String,
    pub required_metadata: Vec<String>,
    pub recipients: Vec<WorkflowRecipient>,
    pub require_approval: bool,
    pub scan_required: bool,
    pub receive: bool,
    pub destinations: Vec<String>,
    pub release: String,
}

#[derive(Clone, Debug, Serialize, uniffi::Record)]
pub struct WorkflowJobSpec {
    pub operation_id: String,
    pub project_id: String,
    pub label: String,
    pub metadata: HashMap<String, String>,
    pub recipients: Vec<String>,
    pub expires_days: u64,
    pub not_before: Option<u64>,
    pub deadline: Option<u64>,
}

#[derive(Clone, Debug, uniffi::Record)]
pub struct WorkflowJob {
    pub destinations: Vec<String>,
    pub received: bool,
    pub id: String,
    pub label: String,
    pub project: String,
    pub state: String,
    pub manifest: Option<String>,
    pub url: Option<String>,
    pub error: Option<String>,
    pub approved_by: Option<String>,
    pub created_at: u64,
}

#[derive(Clone, Debug, uniffi::Record)]
pub struct WorkflowJobPage {
    pub jobs: Vec<WorkflowJob>,
    pub next: Option<String>,
}

fn job(value: Value) -> crate::Result<WorkflowJob> {
    #[derive(Deserialize)]
    struct Envelope {
        job: Job,
        url: Option<String>,
    }
    #[derive(Deserialize)]
    struct Job {
        id: String,
        request: Request,
        project: Project,
        state: String,
        manifest: Option<String>,
        error: Option<String>,
        approved_by: Option<String>,
        created_at: u64,
        checks: Value,
        received: Option<Value>,
    }
    #[derive(Deserialize)]
    struct Request {
        label: String,
    }
    #[derive(Deserialize)]
    struct Project {
        label: String,
        destinations: Vec<String>,
    }
    let value: Envelope =
        serde_json::from_value(value).map_err(|error| Error::Other(error.to_string()))?;
    let destinations = value
        .job
        .project
        .destinations
        .iter()
        .map(|id| {
            let leg = &value.job.checks["destinations"][id];
            let revocation = &value.job.checks["route_revocations"][id];
            let status = match revocation["state"].as_str() {
                Some("acknowledged") => "Revocation acknowledged",
                Some("pending") => "Revocation awaiting destination",
                _ => match leg["state"].as_str() {
                    Some("complete") => "Verified copy complete",
                    Some("sending") => "Transferring files",
                    _ => leg["error"].as_str().unwrap_or("Copy pending"),
                },
            };
            format!("{id}: {status}")
        })
        .collect();
    Ok(WorkflowJob {
        destinations,
        received: value.job.received.is_some(),
        id: value.job.id,
        label: value.job.request.label,
        project: value.job.project.label,
        state: value.job.state,
        manifest: value.job.manifest,
        url: value.url,
        error: value.job.error,
        approved_by: value.job.approved_by,
        created_at: value.job.created_at,
    })
}

#[uniffi::export]
pub fn workflow_projects() -> Result<Vec<WorkflowProject>, port::PortError> {
    #[derive(Deserialize)]
    struct Projects {
        projects: Vec<WorkflowProject>,
    }
    port::run(|client, cookie| {
        client
            .admin_get::<Projects>("/api/workflows/projects", cookie)
            .map(|value| value.projects)
    })
    .map_err(Into::into)
}

#[uniffi::export]
pub fn workflow_jobs(after: Option<String>) -> Result<WorkflowJobPage, port::PortError> {
    #[derive(Deserialize)]
    struct Page {
        jobs: Vec<Value>,
        next: Option<String>,
    }
    let cursor = after.as_deref().unwrap_or_default();
    if !cursor
        .bytes()
        .all(|c| c.is_ascii_alphanumeric() || b"-_".contains(&c))
        || cursor.len() > 100
    {
        return Err(Error::Other("invalid job cursor".into()).into());
    }
    port::run(|client, cookie| {
        let value: Page = client.admin_get(
            &format!("/api/workflows/jobs?limit=50&after={cursor}"),
            cookie,
        )?;
        Ok(WorkflowJobPage {
            jobs: value
                .jobs
                .into_iter()
                .map(job)
                .collect::<crate::Result<_>>()?,
            next: value.next,
        })
    })
    .map_err(Into::into)
}

#[uniffi::export]
pub fn create_workflow_job(spec: WorkflowJobSpec) -> Result<WorkflowJob, port::PortError> {
    port::run(|client, cookie| {
        let request =
            serde_json::to_value(spec).map_err(|error| Error::Other(error.to_string()))?;
        job(client.admin_send(
            reqwest::Method::POST,
            "/api/workflows/jobs",
            cookie,
            Some(&request),
        )?)
    })
    .map_err(Into::into)
}

#[uniffi::export]
pub fn change_workflow_job(
    id: String,
    action: String,
    manifest: Option<String>,
) -> Result<WorkflowJob, port::PortError> {
    if id.is_empty()
        || id.len() > 100
        || !id
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || b"-_".contains(&c))
        || !["approve", "cancel", "retry"].contains(&action.as_str())
    {
        return Err(Error::Other("invalid job action".into()).into());
    }
    port::run(|client, cookie| {
        job(client.admin_send(
            reqwest::Method::POST,
            &format!("/api/workflows/jobs/{id}"),
            cookie,
            Some(&json!({"action":action,"manifest":manifest})),
        )?)
    })
    .map_err(Into::into)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn jobs_expose_reception_and_each_destinations_control_status() {
        let result = job(json!({"url":"https://port.example/s/link","job":{"id":"job","request":{"label":"Received masters"},"project":{"label":"Studio","destinations":["nyc","s3","shared"]},"state":"retrying","manifest":"root","error":null,"approved_by":null,"created_at":1,"received":{"upload_id":"upload"},"checks":{"destinations":{"nyc":{"state":"complete"},"s3":{"state":"failed","error":"Bucket unavailable"}},"route_revocations":{"nyc":{"state":"pending"}}}}})).unwrap();
        assert!(result.received);
        assert!(result.url.is_some());
        assert_eq!(
            result.destinations,
            vec![
                "nyc: Revocation awaiting destination",
                "s3: Bucket unavailable",
                "shared: Copy pending"
            ]
        );
    }
}
