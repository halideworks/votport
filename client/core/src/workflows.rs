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
    }
    #[derive(Deserialize)]
    struct Request {
        label: String,
    }
    #[derive(Deserialize)]
    struct Project {
        label: String,
    }
    let value: Envelope =
        serde_json::from_value(value).map_err(|error| Error::Other(error.to_string()))?;
    Ok(WorkflowJob {
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
