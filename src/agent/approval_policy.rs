//! Scoped auto-approval policy for trusted operators.
//!
//! This keeps approval friction low for high-frequency, low-risk operations
//! while preserving approval gates for sensitive actions.

use serde_json::Value;

/// Trusted operator IDs (Discord user IDs in this deployment).
const TRUSTED_OPERATOR_IDS: &[&str] = &[
    "989554992786579536",  // tarrence
    "975815588930781308",  // clicksave
    "1001181816490827817", // gabe
];

/// Check whether a tool call should be auto-approved for this user.
pub fn is_tool_auto_approved_for_user(user_id: &str, tool_name: &str, params: &Value) -> bool {
    if !TRUSTED_OPERATOR_IDS.contains(&user_id) {
        return false;
    }

    match tool_name {
        // Installing skills is an intended workflow for trusted operators.
        "skill_install" => true,
        // Read-only web research.
        "http" => is_readonly_http_request(params),
        // Prefix-allowlisted shell workflows (runtime-configurable).
        "shell" if is_auto_approved_shell_prefix(params) => true,
        // Read-only local CLI help discovery (e.g. codex --help).
        "shell" => is_readonly_help_shell_command(params),
        _ => false,
    }
}

/// Return a rejection reason for disallowed tool calls.
///
/// Used to block known-bad execution paths before approval prompts are emitted.
pub fn reject_tool_call_for_user(_user_id: &str, tool_name: &str, params: &Value) -> Option<String> {
    // Generic runtime deny patterns for extension/tool installation.
    if tool_name == "tool_install" {
        let kind = params
            .get("kind")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_ascii_lowercase();
        let name = params
            .get("name")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_ascii_lowercase();
        let url = params
            .get("url")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_ascii_lowercase();
        let haystack = format!("{kind} {name} {url}");
        for pat in deny_tool_install_patterns() {
            if haystack.contains(&pat) {
                return Some(format!(
                    "Installation request denied by policy pattern '{}'.",
                    pat
                ));
            }
        }
    }
    None
}

fn is_readonly_http_request(params: &Value) -> bool {
    let method = params
        .get("method")
        .and_then(|v| v.as_str())
        .unwrap_or("GET")
        .trim()
        .to_ascii_uppercase();
    if method != "GET" && method != "HEAD" {
        return false;
    }

    // Read-only requests must not include request body payloads.
    let has_body = params.get("body").is_some_and(|v| match v {
        Value::Null => false,
        Value::String(s) => !s.trim().is_empty(),
        _ => true,
    });
    if has_body {
        return false;
    }

    // Keep auth-bearing requests under explicit approval.
    if let Some(headers) = params.get("headers") {
        let header_pairs: Vec<(String, String)> = match headers {
            Value::Object(map) => map
                .iter()
                .filter_map(|(k, v)| v.as_str().map(|sv| (k.clone(), sv.to_string())))
                .collect(),
            Value::Array(arr) => arr
                .iter()
                .filter_map(|item| {
                    let obj = item.as_object()?;
                    let name = obj.get("name")?.as_str()?.to_string();
                    let value = obj.get("value")?.as_str()?.to_string();
                    Some((name, value))
                })
                .collect(),
            _ => return false,
        };

        let has_sensitive_header = header_pairs.iter().any(|(name, value)| {
            let n = name.to_ascii_lowercase();
            let v = value.trim();
            n == "authorization"
                || n == "proxy-authorization"
                || n == "cookie"
                || n == "x-api-key"
                || n.starts_with("x-auth-")
                || (!v.is_empty() && v.to_ascii_lowercase().starts_with("bearer "))
        });
        if has_sensitive_header {
            return false;
        }
    }

    true
}

fn is_readonly_help_shell_command(params: &Value) -> bool {
    let cmd = params
        .get("command")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .trim();
    if cmd.is_empty() {
        return false;
    }

    // Accept only explicit help/introspection forms for codex.
    matches!(
        cmd,
        "codex --help"
            | "codex help"
            | "codex -h"
            | "codex --version"
            | "codex version"
    ) || (cmd.starts_with("codex ")
        && (cmd.ends_with(" --help") || cmd.ends_with(" -h") || cmd.contains(" help")))
}

fn is_auto_approved_shell_prefix(params: &Value) -> bool {
    let cmd = params
        .get("command")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .trim_start()
        .to_ascii_lowercase();
    if cmd.is_empty() {
        return false;
    }
    auto_approved_shell_prefixes()
        .iter()
        .any(|prefix| command_starts_with_prefix(&cmd, prefix))
}

fn auto_approved_shell_prefixes() -> Vec<String> {
    std::env::var("TRUSTED_SHELL_AUTO_APPROVE_PREFIXES")
        .ok()
        .map(|v| {
            v.split(',')
                .map(|s| s.trim().to_ascii_lowercase())
                .filter(|s| !s.is_empty())
                .collect::<Vec<_>>()
        })
        .unwrap_or_default()
}

fn deny_tool_install_patterns() -> Vec<String> {
    std::env::var("TOOL_INSTALL_DENY_PATTERNS")
        .ok()
        .map(|v| {
            v.split(',')
                .map(|s| s.trim().to_ascii_lowercase())
                .filter(|s| !s.is_empty())
                .collect::<Vec<_>>()
        })
        .unwrap_or_default()
}

fn command_starts_with_prefix(cmd: &str, prefix: &str) -> bool {
    if cmd == prefix {
        return true;
    }
    cmd.strip_prefix(prefix)
        .is_some_and(|rest| rest.starts_with(char::is_whitespace))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn trusted_user_get_http_is_allowed() {
        let params = serde_json::json!({
            "method": "GET",
            "url": "https://example.com/docs"
        });
        assert!(is_tool_auto_approved_for_user(
            "989554992786579536",
            "http",
            &params
        ));
    }

    #[test]
    fn trusted_user_post_http_is_not_allowed() {
        let params = serde_json::json!({
            "method": "POST",
            "url": "https://example.com/api"
        });
        assert!(!is_tool_auto_approved_for_user(
            "989554992786579536",
            "http",
            &params
        ));
    }

    #[test]
    fn trusted_user_auth_header_http_is_not_allowed() {
        let params = serde_json::json!({
            "method": "GET",
            "url": "https://example.com/api",
            "headers": {
                "Authorization": "Bearer token"
            }
        });
        assert!(!is_tool_auto_approved_for_user(
            "989554992786579536",
            "http",
            &params
        ));
    }

    #[test]
    fn untrusted_user_never_auto_approved() {
        let params = serde_json::json!({});
        assert!(!is_tool_auto_approved_for_user("not-trusted", "skill_install", &params));
    }

    #[test]
    fn trusted_user_codex_help_shell_is_allowed() {
        let params = serde_json::json!({ "command": "codex mcp --help" });
        assert!(is_tool_auto_approved_for_user(
            "989554992786579536",
            "shell",
            &params
        ));
    }

    #[test]
    fn trusted_user_mercury_shell_is_allowed() {
        // SAFETY: test-only env mutation.
        unsafe { std::env::set_var("TRUSTED_SHELL_AUTO_APPROVE_PREFIXES", "mercury") };
        let params = serde_json::json!({ "command": "mercury accounts get-accounts --limit 100" });
        assert!(is_tool_auto_approved_for_user(
            "989554992786579536",
            "shell",
            &params
        ));
        // SAFETY: test-only env mutation.
        unsafe { std::env::remove_var("TRUSTED_SHELL_AUTO_APPROVE_PREFIXES") };
    }

    #[test]
    fn reject_mercury_mcp_install() {
        // SAFETY: test-only env mutation.
        unsafe { std::env::set_var("TOOL_INSTALL_DENY_PATTERNS", "mcp_server mercury") };
        let params = serde_json::json!({
            "kind": "mcp_server",
            "name": "mercury-bank-accounts"
        });
        assert!(reject_tool_call_for_user("989554992786579536", "tool_install", &params).is_some());
        // SAFETY: test-only env mutation.
        unsafe { std::env::remove_var("TOOL_INSTALL_DENY_PATTERNS") };
    }

    #[test]
    fn allow_non_mercury_mcp_install_policy_layer() {
        // SAFETY: test-only env mutation.
        unsafe { std::env::set_var("TOOL_INSTALL_DENY_PATTERNS", "mcp_server mercury") };
        let params = serde_json::json!({
            "kind": "mcp_server",
            "name": "notion"
        });
        assert!(reject_tool_call_for_user("989554992786579536", "tool_install", &params).is_none());
        // SAFETY: test-only env mutation.
        unsafe { std::env::remove_var("TOOL_INSTALL_DENY_PATTERNS") };
    }
}
