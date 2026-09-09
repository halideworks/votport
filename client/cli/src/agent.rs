use serde_json::{json, Value};
use votport_client_core::automation::{error_json, Automation};

pub fn run(args: &[String]) -> Result<Value, Value> {
    let Some((command, args)) = args.split_first() else {
        return Err(invalid(
            "agent needs session, files, share, recover, deliveries, delivery or revoke",
        ));
    };
    let valued: &[&str] = match command.as_str() {
        "files" => &["--after", "--limit"],
        "share" => &[
            "--operation-id",
            "--expires-days",
            "--label",
            "--max-downloads",
        ],
        "deliveries" => &["--after", "--limit"],
        "delivery" => &["--offset", "--limit"],
        "session" | "recover" | "revoke" => &[],
        _ => return Err(invalid("unknown agent command")),
    };
    let (options, positional, _) = super::parse(args, valued).map_err(|e| invalid(&e))?;
    let count = match command.as_str() {
        "session" | "deliveries" => 0..=0,
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
            client.create_delivery(&request)
        }
        _ => unreachable!(),
    };
    result.map_err(|e| error_json(&e))
}

pub fn invalid(message: &str) -> Value {
    json!({"error": message, "code": "invalid_request", "retryable": false})
}
