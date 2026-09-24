use serde_json::{json, Value};
use votport_client_core::automation::{error_json, Automation};

pub fn run(args: &[String]) -> Result<Value, Value> {
    let Some((command, args)) = args.split_first() else {
        return Err(invalid(
            "agent needs session, notifications, files, share, recover, deliveries, delivery, revoke, projects, jobs, create-job, job, retry-job, cancel-job, events or job-evidence",
        ));
    };
    let valued: &[&str] = match command.as_str() {
        "files" => &["--after", "--limit"],
        "share" => &[
            "--operation-id",
            "--expires-days",
            "--label",
            "--max-downloads",
            "--notifications",
        ],
        "deliveries" | "jobs" | "events" | "job-evidence" => &["--after", "--limit"],
        "delivery" => &["--offset", "--limit"],
        "notifications" | "session" | "recover" | "revoke" | "projects" | "job" | "create-job"
        | "retry-job" | "cancel-job" => &[],
        _ => return Err(invalid("unknown agent command")),
    };
    let (options, positional, _) = super::parse(args, valued).map_err(|e| invalid(&e))?;
    let count = match command.as_str() {
        "notifications" | "session" | "deliveries" | "projects" | "jobs" | "events" => 0..=0,
        "files" => 0..=1,
        _ => 1..=1,
    };
    if !count.contains(&positional.len()) {
        return Err(invalid("unexpected number of arguments"));
    }
    let number = |flag: &str, default: u64| -> Result<u64, Value> {
        super::number::<u64>(&options, flag)
            .map(|n| n.unwrap_or(default))
            .map_err(|e| invalid(&e))
    };
    let client = Automation::from_env().map_err(|e| error_json(&e))?;
    let result = match command.as_str() {
        "session" => client.session(),
        "notifications" => client.notification_destinations(),
        "projects" => client.projects(),
        "jobs" => client.jobs(
            options.get("--after").map(String::as_str),
            number("--limit", 50)?,
        ),
        "job" => client.job(&positional[0]),
        "retry-job" => client.job_action(&positional[0], "retry"),
        "cancel-job" => client.job_action(&positional[0], "cancel"),
        "events" => client.events(number("--after", 0)?, number("--limit", 50)?),
        "job-evidence" => client.job_evidence(
            &positional[0],
            number("--after", 0)?,
            number("--limit", 50)?,
        ),
        "create-job" => {
            use std::io::Read;
            let input: Box<dyn Read> = if positional[0] == "-" {
                Box::new(std::io::stdin())
            } else {
                Box::new(std::fs::File::open(&positional[0]).map_err(|e| invalid(&e.to_string()))?)
            };
            let mut bytes = Vec::new();
            input
                .take(256 * 1024 + 1)
                .read_to_end(&mut bytes)
                .map_err(|e| invalid(&e.to_string()))?;
            if bytes.len() > 256 * 1024 {
                return Err(invalid("job request exceeds 256 KiB"));
            }
            let request: Value =
                serde_json::from_slice(&bytes).map_err(|e| invalid(&e.to_string()))?;
            client.create_job(&request)
        }
        "files" => client.files(
            positional.first().map(String::as_str),
            options.get("--after").map(String::as_str),
            number("--limit", 50)?,
        ),
        "deliveries" => client.deliveries(number("--after", 0)?, number("--limit", 50)?),
        "delivery" => client.delivery(
            &positional[0],
            number("--offset", 0)?,
            number("--limit", 50)?,
        ),
        "recover" => client.recover(&positional[0]),
        "revoke" => client.revoke(&positional[0]),
        "share" => {
            let operation_id = options
                .get("--operation-id")
                .ok_or_else(|| invalid("--operation-id is required; reuse it after a timeout"))?;
            let mut request = json!({"directory": positional[0], "operation_id": operation_id, "expires_days": number("--expires-days", 7)?, "label": options.get("--label")});
            if let Some(password) = std::env::var("VOTPORT_SHARE_PASSWORD")
                .ok()
                .filter(|p| !p.is_empty())
            {
                request["password"] = json!(password);
            }
            if options.contains_key("--max-downloads") {
                request["max_downloads"] = json!(number("--max-downloads", 1)?);
            }
            if let Some(policy) = options.get("--notifications") {
                if policy.len() > 65536 {
                    return Err(invalid("notification policy exceeds 64 KiB"));
                }
                request["notifications"] = serde_json::from_str(policy)
                    .map_err(|_| invalid("--notifications requires a JSON notification policy"))?;
            }
            client.create_delivery(&request)
        }
        _ => unreachable!(),
    };
    result.map_err(|e| error_json(&e))
}

pub fn invalid(message: &str) -> Value {
    json!({"error": message, "code": "invalid_request", "retryable": false})
}

/// Exit codes mirror the server's share subcommand: a transport failure or a
/// 5xx-class server answer may succeed on a retry (exit 2); a usage error or
/// a 4xx-class refusal will not succeed as given (exit 1).
pub fn exit_code(value: &Value) -> u8 {
    if value["code"] == json!("network_error") {
        return 2;
    }
    if value["status"]
        .as_u64()
        .is_some_and(|status| (500..600).contains(&status))
    {
        return 2;
    }
    1
}

#[cfg(test)]
mod tests {
    use super::{exit_code, invalid};

    #[test]
    fn agent_exit_codes_mirror_the_share_subcommand_split() {
        assert_eq!(exit_code(&invalid("bad arguments")), 1);
        assert_eq!(
            exit_code(&serde_json::json!({"code": "network_error", "retryable": true})),
            2
        );
        assert_eq!(
            exit_code(&serde_json::json!({"code": "request_failed", "status": 502})),
            2
        );
        assert_eq!(
            exit_code(&serde_json::json!({"code": "not_found", "status": 404})),
            1
        );
        assert_eq!(exit_code(&serde_json::json!({"code": "request_failed"})), 1);
    }
}
