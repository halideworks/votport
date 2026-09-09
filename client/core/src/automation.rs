//! Automation credentials are supplied explicitly and never replace the desktop session.

use crate::{api::Client, Error, Result};
use reqwest::{Method, Url};
use serde_json::{json, Value};

pub struct Automation {
    client: Client,
    token: String,
}

impl Automation {
    pub fn new(base: &str, token: &str) -> Result<Self> {
        let url = Url::parse(base)
            .map_err(|_| Error::Other("VOTPORT_URL must be an HTTPS origin".to_owned()))?;
        let loopback = url.host_str().is_some_and(|h| {
            h.eq_ignore_ascii_case("localhost")
                || h.trim_matches(['[', ']'])
                    .parse::<std::net::IpAddr>()
                    .is_ok_and(|ip| ip.is_loopback())
        });
        if url.host_str().is_none()
            || !(url.scheme() == "https" || (url.scheme() == "http" && loopback))
            || !url.username().is_empty()
            || url.password().is_some()
            || url.path() != "/"
            || url.query().is_some()
            || url.fragment().is_some()
        {
            return Err(Error::Other(
                "VOTPORT_URL must be an HTTPS origin; HTTP is allowed for loopback".to_owned(),
            ));
        }
        if token.len() != 32 || !token.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(Error::Other(
                "VOTPORT_AUTOMATION_TOKEN must be a 32-character token".to_owned(),
            ));
        }
        Ok(Self {
            client: Client::new(url.as_str())?,
            token: token.to_owned(),
        })
    }

    pub fn from_env() -> Result<Self> {
        let base = std::env::var("VOTPORT_URL")
            .map_err(|_| Error::Other("VOTPORT_URL is required".to_owned()))?;
        let token = std::env::var("VOTPORT_AUTOMATION_TOKEN")
            .map_err(|_| Error::Other("VOTPORT_AUTOMATION_TOKEN is required".to_owned()))?;
        Self::new(&base, &token)
    }

    pub fn session(&self) -> Result<Value> {
        self.call(Method::GET, "/session", &[], None)
    }

    pub fn files(&self, directory: Option<&str>, after: Option<&str>, limit: u64) -> Result<Value> {
        let mut query = vec![("limit", limit.to_string())];
        if let Some(directory) = directory {
            query.push(("directory", directory.to_owned()));
        }
        if let Some(after) = after {
            query.push(("after", after.to_owned()));
        }
        self.call(Method::GET, "/files", &query, None)
    }

    pub fn create_delivery(&self, request: &Value) -> Result<Value> {
        let id = request["operation_id"].as_str().ok_or_else(|| {
            Error::Other("operation_id is required so creation can be retried safely".to_owned())
        })?;
        validate_id(id)?;
        self.call(Method::POST, "/share", &[], Some(request))
    }

    pub fn recover(&self, operation_id: &str) -> Result<Value> {
        validate_id(operation_id)?;
        self.call(
            Method::GET,
            &format!("/operations/{operation_id}"),
            &[],
            None,
        )
    }

    pub fn deliveries(&self, after: u64, limit: u64) -> Result<Value> {
        self.call(
            Method::GET,
            "/deliveries",
            &[("after", after.to_string()), ("limit", limit.to_string())],
            None,
        )
    }

    pub fn delivery(&self, id: &str, offset: u64, limit: u64) -> Result<Value> {
        validate_id(id)?;
        self.call(
            Method::GET,
            &format!("/deliveries/{id}"),
            &[("offset", offset.to_string()), ("limit", limit.to_string())],
            None,
        )
    }

    pub fn revoke(&self, id: &str) -> Result<Value> {
        validate_id(id)?;
        self.call(Method::DELETE, &format!("/deliveries/{id}"), &[], None)
    }

    pub fn projects(&self) -> Result<Value> {
        self.workflow_call(Method::GET, "/projects", &[], None)
    }

    pub fn jobs(&self, after: Option<&str>, limit: u64) -> Result<Value> {
        self.workflow_call(
            Method::GET,
            "/jobs",
            &[
                ("after", after.unwrap_or_default().into()),
                ("limit", limit.to_string()),
            ],
            None,
        )
    }

    pub fn job(&self, id: &str) -> Result<Value> {
        validate_id(id)?;
        self.workflow_call(Method::GET, &format!("/jobs/{id}"), &[], None)
    }

    pub fn create_job(&self, request: &Value) -> Result<Value> {
        validate_id(request["operation_id"].as_str().ok_or_else(|| {
            Error::Other("operation_id is required; reuse it after a timeout".into())
        })?)?;
        self.workflow_call(Method::POST, "/jobs", &[], Some(request))
    }

    pub fn job_action(&self, id: &str, action: &str) -> Result<Value> {
        validate_id(id)?;
        if !["retry", "cancel"].contains(&action) {
            return Err(Error::Other("agents may retry or cancel jobs".into()));
        }
        self.workflow_call(
            Method::POST,
            &format!("/jobs/{id}"),
            &[],
            Some(&json!({"action": action})),
        )
    }

    pub fn events(&self, after: u64, limit: u64) -> Result<Value> {
        self.workflow_call(
            Method::GET,
            "/events",
            &[("after", after.to_string()), ("limit", limit.to_string())],
            None,
        )
    }

    pub fn job_evidence(&self, id: &str, after: u64, limit: u64) -> Result<Value> {
        validate_id(id)?;
        self.workflow_call(
            Method::GET,
            &format!("/jobs/{id}/evidence"),
            &[("after", after.to_string()), ("limit", limit.to_string())],
            None,
        )
    }

    fn workflow_call(
        &self,
        method: Method,
        path: &str,
        query: &[(&str, String)],
        body: Option<&Value>,
    ) -> Result<Value> {
        self.call_path(method, &format!("/api/workflows{path}"), query, body)
    }

    fn call(
        &self,
        method: Method,
        path: &str,
        query: &[(&str, String)],
        body: Option<&Value>,
    ) -> Result<Value> {
        self.call_path(method, &format!("/api/automation{path}"), query, body)
    }

    fn call_path(
        &self,
        method: Method,
        path: &str,
        query: &[(&str, String)],
        body: Option<&Value>,
    ) -> Result<Value> {
        let mut url = Url::parse("https://automation.invalid/").unwrap();
        url.set_path(path);
        if !query.is_empty() {
            url.query_pairs_mut()
                .extend_pairs(query.iter().map(|(key, value)| (*key, value)));
        }
        let path = match url.query() {
            Some(query) => format!("{}?{query}", url.path()),
            None => url.path().to_owned(),
        };
        self.client.automation(method, &path, &self.token, body)
    }
}

fn validate_id(id: &str) -> Result<()> {
    if id.is_empty()
        || id.len() > 128
        || !id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b))
        || matches!(id, "." | "..")
    {
        return Err(Error::Other(
            "ID must contain 1..=128 letters, digits, dots, hyphens or underscores".to_owned(),
        ));
    }
    Ok(())
}

pub fn error_json(error: &Error) -> Value {
    if let Error::Server { status, body, .. } = error {
        let body: Value = serde_json::from_str(body).unwrap_or_default();
        return json!({"error": body["error"].as_str().unwrap_or("server refused the request"), "code": body["code"].as_str().unwrap_or("request_failed"), "status": status, "retryable": body["retryable"].as_bool().unwrap_or(*status == 429 || (500..600).contains(status)), "retry_after_seconds": body["retry_after_seconds"]});
    }
    if matches!(error, Error::Http { .. }) {
        return json!({"error": "network request failed; recover or retry with the same operation_id", "code": "network_error", "retryable": true});
    }
    json!({"error": error.to_string(), "code": "invalid_request", "retryable": false})
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn credentials_and_ids_cannot_redirect_requests() {
        let token = "a".repeat(32);
        for base in [
            "http://example.com",
            "https://u:p@example.com",
            "https://example.com/path",
            "https://example.com/?q=1",
            "https://example.com/#fragment",
            "file:///tmp",
        ] {
            assert!(Automation::new(base, &token).is_err(), "{base}");
        }
        for base in [
            "https://example.com",
            "http://localhost:8080",
            "http://127.0.0.1:8080",
            "http://[::1]:8080",
        ] {
            assert!(Automation::new(base, &token).is_ok(), "{base}");
        }
        for id in [
            "",
            ".",
            "..",
            "../../admin",
            "x?path=other",
            "x#other",
            "a/b",
            "a\\b",
        ] {
            assert!(validate_id(id).is_err());
        }
        assert!(validate_id("render-2026.09_01").is_ok());
    }
    #[test]
    fn gateway_errors_remain_retryable_without_a_json_body() {
        for (status, retryable) in [
            (400, false),
            (403, false),
            (429, true),
            (502, true),
            (503, true),
            (504, true),
        ] {
            let error = Error::Server {
                status,
                what: "share".into(),
                body: "<html>gateway failed</html>".into(),
            };
            assert_eq!(error_json(&error)["retryable"], retryable);
        }
    }
}
