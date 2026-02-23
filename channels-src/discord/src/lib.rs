//! Discord Gateway/Webhook channel for IronClaw.
//!
//! This WASM component implements the channel interface for handling Discord
//! interactions via webhooks and sending messages back to Discord.
//!
//! # Features
//!
//! - URL verification for Discord interactions
//! - Slash command handling
//! - Message event parsing (@mentions, DMs)
//! - Thread support for conversations
//! - Response posting via Discord Web API
//! - Automatic message truncation (> 2000 chars)
//!
//! # Security
//!
//! - Signature validation is handled by the host (webhook secrets)
//! - Bot token is injected by host during HTTP requests
//! - WASM never sees raw credentials

wit_bindgen::generate!({
    world: "sandboxed-channel",
    path: "../../wit/channel.wit",
});

use serde::{Deserialize, Serialize};

use exports::near::agent::channel::{
    AgentResponse, ChannelConfig, Guest, HttpEndpointConfig, IncomingHttpRequest,
    OutgoingHttpResponse, PollConfig, StatusUpdate,
};
use near::agent::channel_host::{self, EmittedMessage};

/// Discord interaction wrapper.
#[derive(Debug, Deserialize)]
struct DiscordInteraction {
    /// Interaction type (1=Ping, 2=ApplicationCommand, 3=MessageComponent)
    #[serde(rename = "type")]
    interaction_type: u8,

    /// Interaction ID
    id: String,

    /// Application ID
    application_id: String,

    /// Guild ID (if in server)
    #[allow(dead_code)] // Part of API payload, currently unused
    guild_id: Option<String>,

    /// Channel ID
    channel_id: Option<String>,

    /// Member info (if in server)
    member: Option<DiscordMember>,

    /// User info (if DM)
    user: Option<DiscordUser>,

    /// Command data (for slash commands)
    data: Option<DiscordCommandData>,

    /// Message (for component interactions)
    message: Option<DiscordMessage>,

    /// Token for responding
    token: String,
}

#[derive(Debug, Deserialize, Clone)]
struct DiscordMember {
    user: DiscordUser,
    #[allow(dead_code)] // Part of API payload, currently unused
    nick: Option<String>,
}

#[derive(Debug, Deserialize, Clone)]
struct DiscordUser {
    id: String,
    username: String,
    global_name: Option<String>,
}

#[derive(Debug, Deserialize, Clone)]
struct DiscordCommandData {
    #[allow(dead_code)] // Part of API payload, currently unused
    id: String,
    name: String,
    options: Option<Vec<DiscordCommandOption>>,
}

#[derive(Debug, Deserialize, Clone)]
struct DiscordCommandOption {
    name: String,
    value: serde_json::Value,
}

#[derive(Debug, Deserialize, Clone)]
struct DiscordMessage {
    #[allow(dead_code)] // Part of API payload, currently unused
    id: String,
    content: String,
    channel_id: String,
    #[allow(dead_code)] // Part of API payload, currently unused
    author: DiscordUser,
}

#[derive(Debug, Deserialize)]
struct DiscordChannelMessage {
    id: String,
    content: String,
    channel_id: String,
    author: DiscordChannelAuthor,
    #[serde(default)]
    mentions: Vec<DiscordUser>,
    #[serde(default)]
    webhook_id: Option<String>,
}

#[derive(Debug, Deserialize)]
struct DiscordChannelAuthor {
    id: String,
    username: String,
    global_name: Option<String>,
    #[serde(default)]
    bot: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct DiscordRuntimeConfig {
    #[serde(default)]
    polling_enabled: bool,
    #[serde(default = "default_poll_interval_ms")]
    poll_interval_ms: u32,
    #[serde(default)]
    mention_channel_ids: Vec<String>,
}

fn default_poll_interval_ms() -> u32 {
    30_000
}

/// Metadata stored with emitted messages for response routing.
#[derive(Debug, Serialize, Deserialize)]
struct DiscordMessageMetadata {
    /// Discord channel ID
    channel_id: String,

    /// Interaction ID for followups
    #[serde(default)]
    interaction_id: Option<String>,

    /// Interaction token for responding
    #[serde(default)]
    token: Option<String>,

    /// Application ID
    #[serde(default)]
    application_id: Option<String>,

    /// Source message ID when handling mention-poll events.
    #[serde(default)]
    source_message_id: Option<String>,

    /// Thread ID (for forum threads)
    thread_id: Option<String>,
}

struct DiscordChannel;

impl Guest for DiscordChannel {
    fn on_start(config_json: String) -> Result<ChannelConfig, String> {
        channel_host::log(channel_host::LogLevel::Info, "Discord channel starting");

        let config = serde_json::from_str::<DiscordRuntimeConfig>(&config_json).unwrap_or_else(|e| {
            channel_host::log(
                channel_host::LogLevel::Warn,
                &format!("Invalid config JSON, using defaults: {}", e),
            );
            DiscordRuntimeConfig {
                polling_enabled: false,
                poll_interval_ms: default_poll_interval_ms(),
                mention_channel_ids: Vec::new(),
            }
        });

        if let Ok(serialized) = serde_json::to_string(&config) {
            let _ = channel_host::workspace_write("config.json", &serialized);
        }

        Ok(ChannelConfig {
            display_name: "Discord".to_string(),
            http_endpoints: vec![HttpEndpointConfig {
                path: "/webhook/discord".to_string(),
                methods: vec!["POST".to_string()],
                require_secret: true,
            }],
            poll: if config.polling_enabled {
                Some(PollConfig {
                    interval_ms: config.poll_interval_ms.max(30_000),
                    enabled: true,
                })
            } else {
                None
            },
        })
    }

    fn on_http_request(req: IncomingHttpRequest) -> OutgoingHttpResponse {
        let body_str = match std::str::from_utf8(&req.body) {
            Ok(s) => s,
            Err(_) => {
                return json_response(400, serde_json::json!({"error": "Invalid UTF-8 body"}));
            }
        };

        let interaction: DiscordInteraction = match serde_json::from_str(body_str) {
            Ok(i) => i,
            Err(e) => {
                channel_host::log(
                    channel_host::LogLevel::Error,
                    &format!("Failed to parse Discord interaction: {}", e),
                );
                return json_response(400, serde_json::json!({"error": "Invalid interaction"}));
            }
        };

        match interaction.interaction_type {
            // Ping - Discord verification
            1 => {
                channel_host::log(channel_host::LogLevel::Info, "Responding to Discord ping");
                json_response(200, serde_json::json!({"type": 1}))
            }

            // Application Command (slash command)
            2 => {
                handle_slash_command(&interaction);
                json_response(
                    200,
                    serde_json::json!({
                        "type": 5,
                        "data": {
                            "content": "🤔 Thinking..."
                        }
                    }),
                )
            }

            // Message Component (buttons, selects)
            3 => {
                if let Some(ref message) = interaction.message {
                    handle_message_component(&interaction, message);
                }
                json_response(200, serde_json::json!({"type": 6}))
            }

            _ => {
                channel_host::log(
                    channel_host::LogLevel::Warn,
                    &format!(
                        "Unknown Discord interaction type: {}",
                        interaction.interaction_type
                    ),
                );
                json_response(200, serde_json::json!({"type": 6}))
            }
        }
    }

    fn on_poll() {
        poll_for_mentions();
    }

    fn on_respond(response: AgentResponse) -> Result<(), String> {
        let metadata: DiscordMessageMetadata = serde_json::from_str(&response.metadata_json)
            .map_err(|e| format!("Failed to parse metadata: {}", e))?;

        // Truncate content to 2000 characters to comply with Discord limits
        let content = truncate_message(&response.content);

        let mut payload = serde_json::json!({ "content": content });

        // Check for embeds in metadata
        if let Ok(meta_json) = serde_json::from_str::<serde_json::Value>(&response.metadata_json) {
            if let Some(embeds) = meta_json.get("embeds") {
                payload["embeds"] = embeds.clone();
            }
        }

        let payload_bytes =
            serde_json::to_vec(&payload).map_err(|e| format!("Failed to serialize: {}", e))?;

        let headers = serde_json::json!({
            "Content-Type": "application/json"
        });

        let (method, url) = if let (Some(application_id), Some(token)) =
            (metadata.application_id.as_ref(), metadata.token.as_ref())
        {
            (
                "PATCH",
                format!(
                    "https://discord.com/api/v10/webhooks/{}/{}/messages/@original",
                    application_id, token
                ),
            )
        } else if let Some(source_message_id) = metadata.source_message_id.as_ref() {
            payload["message_reference"] = serde_json::json!({
                "message_id": source_message_id
            });
            payload["allowed_mentions"] = serde_json::json!({
                "replied_user": true
            });
            let mention_payload = serde_json::to_vec(&payload)
                .map_err(|e| format!("Failed to serialize mention payload: {}", e))?;
            let mention_url = format!(
                "https://discord.com/api/v10/channels/{}/messages",
                metadata.channel_id
            );
            let result = channel_host::http_request(
                "POST",
                &mention_url,
                &discord_auth_headers_json(true),
                Some(&mention_payload),
                None,
            );
            return map_discord_response(result);
        } else {
            return Err("Unsupported Discord response metadata".to_string());
        };

        let result =
            channel_host::http_request(method, &url, &headers.to_string(), Some(&payload_bytes), None);

        map_discord_response(result)
    }

    fn on_status(_update: StatusUpdate) {}

    fn on_shutdown() {
        channel_host::log(
            channel_host::LogLevel::Info,
            "Discord channel shutting down",
        );
    }
}

fn map_discord_response(
    result: Result<near::agent::channel_host::HttpResponse, String>,
) -> Result<(), String> {
    match result {
        Ok(http_response) => {
            if http_response.status >= 200 && http_response.status < 300 {
                channel_host::log(channel_host::LogLevel::Debug, "Posted response to Discord");
                Ok(())
            } else {
                let body_str = String::from_utf8_lossy(&http_response.body);
                Err(format!(
                    "Discord API error: {} - {}",
                    http_response.status, body_str
                ))
            }
        }
        Err(e) => Err(format!("HTTP request failed: {}", e)),
    }
}

fn load_runtime_config() -> DiscordRuntimeConfig {
    channel_host::workspace_read("config.json")
        .and_then(|raw| serde_json::from_str::<DiscordRuntimeConfig>(&raw).ok())
        .unwrap_or(DiscordRuntimeConfig {
            polling_enabled: false,
            poll_interval_ms: default_poll_interval_ms(),
            mention_channel_ids: Vec::new(),
        })
}

fn poll_for_mentions() {
    let config = load_runtime_config();
    if !config.polling_enabled || config.mention_channel_ids.is_empty() {
        return;
    }

    let bot_id = match get_or_fetch_bot_id() {
        Some(id) => id,
        None => {
            channel_host::log(
                channel_host::LogLevel::Warn,
                "Skipping mention polling: failed to resolve bot user id",
            );
            return;
        }
    };

    for channel_id in &config.mention_channel_ids {
        poll_channel_mentions(channel_id, &bot_id);
    }
}

fn get_or_fetch_bot_id() -> Option<String> {
    if let Some(id) = channel_host::workspace_read("bot_user_id.txt") {
        let trimmed = id.trim();
        if !trimmed.is_empty() {
            return Some(trimmed.to_string());
        }
    }

    let response = channel_host::http_request(
        "GET",
        "https://discord.com/api/v10/users/@me",
        &discord_auth_headers_json(false),
        None,
        Some(10_000),
    )
    .ok()?;

    if !(200..300).contains(&response.status) {
        return None;
    }

    let value: serde_json::Value = serde_json::from_slice(&response.body).ok()?;
    let id = value.get("id")?.as_str()?.to_string();
    let _ = channel_host::workspace_write("bot_user_id.txt", &id);
    Some(id)
}

fn poll_channel_mentions(channel_id: &str, bot_id: &str) {
    let cursor_path = format!("cursor_{}.txt", channel_id);
    let last_seen = channel_host::workspace_read(&cursor_path).map(|s| s.trim().to_string());

    let url = format!(
        "https://discord.com/api/v10/channels/{}/messages?limit=25",
        channel_id
    );

    let response = match channel_host::http_request(
        "GET",
        &url,
        &discord_auth_headers_json(false),
        None,
        Some(10_000),
    ) {
        Ok(r) => r,
        Err(e) => {
            channel_host::log(
                channel_host::LogLevel::Warn,
                &format!("Discord poll request failed for channel {}: {}", channel_id, e),
            );
            return;
        }
    };

    if !(200..300).contains(&response.status) {
        let body = String::from_utf8_lossy(&response.body);
        channel_host::log(
            channel_host::LogLevel::Warn,
            &format!(
                "Discord poll failed for channel {}: status={} body={}",
                channel_id, response.status, body
            ),
        );
        return;
    }

    let mut messages: Vec<DiscordChannelMessage> = match serde_json::from_slice(&response.body) {
        Ok(v) => v,
        Err(e) => {
            channel_host::log(
                channel_host::LogLevel::Warn,
                &format!("Failed to parse polled Discord messages: {}", e),
            );
            return;
        }
    };

    // On first run for a channel, initialize the cursor to "latest seen" and
    // skip back-processing historical messages.
    if last_seen.is_none() {
        if let Some(latest) = messages.first() {
            let _ = channel_host::workspace_write(&cursor_path, &latest.id);
        }
        return;
    }

    messages.reverse();
    let mut max_seen = last_seen.clone();

    for msg in messages {
        if !is_new_message(last_seen.as_deref(), &msg.id) {
            continue;
        }

        if is_new_message(max_seen.as_deref(), &msg.id) {
            max_seen = Some(msg.id.clone());
        }

        if msg.webhook_id.is_some() || msg.author.bot || msg.author.id == bot_id {
            continue;
        }

        if !message_mentions_bot(&msg, bot_id) {
            continue;
        }

        let content = strip_bot_mention(&msg.content, bot_id);
        let metadata = DiscordMessageMetadata {
            channel_id: msg.channel_id.clone(),
            interaction_id: None,
            token: None,
            application_id: None,
            source_message_id: Some(msg.id.clone()),
            thread_id: None,
        };

        let metadata_json = match serde_json::to_string(&metadata) {
            Ok(v) => v,
            Err(e) => {
                channel_host::log(
                    channel_host::LogLevel::Warn,
                    &format!("Failed to serialize mention metadata: {}", e),
                );
                continue;
            }
        };

        let user_name = msg
            .author
            .global_name
            .as_ref()
            .filter(|s| !s.is_empty())
            .unwrap_or(&msg.author.username)
            .clone();

        channel_host::emit_message(&EmittedMessage {
            user_id: msg.author.id.clone(),
            user_name: Some(user_name),
            content: if content.is_empty() {
                "mention".to_string()
            } else {
                content
            },
            thread_id: None,
            metadata_json,
        });
    }

    if let Some(cursor) = max_seen {
        let _ = channel_host::workspace_write(&cursor_path, &cursor);
    }
}

fn is_new_message(last_seen: Option<&str>, current: &str) -> bool {
    match last_seen {
        None => true,
        Some(prev) => {
            let prev_num = prev.parse::<u64>().ok();
            let cur_num = current.parse::<u64>().ok();
            match (prev_num, cur_num) {
                (Some(p), Some(c)) => c > p,
                _ => current > prev,
            }
        }
    }
}

fn message_mentions_bot(msg: &DiscordChannelMessage, bot_id: &str) -> bool {
    msg.mentions.iter().any(|u| u.id == bot_id)
        || msg.content.contains(&format!("<@{}>", bot_id))
        || msg.content.contains(&format!("<@!{}>", bot_id))
}

fn strip_bot_mention(content: &str, bot_id: &str) -> String {
    content
        .replace(&format!("<@{}>", bot_id), "")
        .replace(&format!("<@!{}>", bot_id), "")
        .trim()
        .to_string()
}

fn discord_auth_headers_json(include_content_type: bool) -> String {
    if include_content_type {
        serde_json::json!({
            "Content-Type": "application/json",
            "Authorization": "Bot {DISCORD_BOT_TOKEN}"
        })
        .to_string()
    } else {
        serde_json::json!({
            "Authorization": "Bot {DISCORD_BOT_TOKEN}"
        })
        .to_string()
    }
}

fn handle_slash_command(interaction: &DiscordInteraction) {
    let user = interaction
        .member
        .as_ref()
        .map(|m| &m.user)
        .or(interaction.user.as_ref());
    let user_id = user.map(|u| u.id.clone()).unwrap_or_default();
    let user_name = user
        .map(|u| {
            u.global_name
                .as_ref()
                .filter(|s| !s.is_empty())
                .unwrap_or(&u.username)
                .clone()
        })
        .unwrap_or_default();

    let channel_id = interaction.channel_id.clone().unwrap_or_default();

    let command_name = interaction
        .data
        .as_ref()
        .map(|d| d.name.clone())
        .unwrap_or_default();
    let options = interaction.data.as_ref().and_then(|d| d.options.clone());

    let content = if let Some(opts) = options {
        let opt_str = opts
            .iter()
            .map(|o| format!("{}: {}", o.name, o.value))
            .collect::<Vec<_>>()
            .join(", ");
        format!("/{} {}", command_name, opt_str)
    } else {
        format!("/{}", command_name)
    };

    let metadata = DiscordMessageMetadata {
        channel_id: channel_id.clone(),
        interaction_id: Some(interaction.id.clone()),
        token: Some(interaction.token.clone()),
        application_id: Some(interaction.application_id.clone()),
        source_message_id: None,
        thread_id: None,
    };

    let metadata_json = match serde_json::to_string(&metadata) {
        Ok(json) => json,
        Err(e) => {
            channel_host::log(
                channel_host::LogLevel::Error,
                &format!("Failed to serialize metadata: {}", e),
            );
            // Attempt to notify user of internal error
            let url = format!(
                "https://discord.com/api/v10/webhooks/{}/{}",
                interaction.application_id, interaction.token
            );
            let payload = serde_json::json!({
                "content": "❌ Internal Error: Failed to process command metadata.",
                "flags": 64 // Ephemeral
            });
            let _ = channel_host::http_request(
                "POST",
                &url,
                &serde_json::json!({"Content-Type": "application/json"}).to_string(),
                Some(&serde_json::to_vec(&payload).unwrap_or_default()),
                None,
            );
            return;
        }
    };

    channel_host::emit_message(&EmittedMessage {
        user_id,
        user_name: Some(user_name),
        content,
        thread_id: None,
        metadata_json,
    });
}

fn handle_message_component(interaction: &DiscordInteraction, message: &DiscordMessage) {
    // Check member first (for server contexts), then user (for DMs)
    let user = interaction
        .member
        .as_ref()
        .map(|m| &m.user)
        .or(interaction.user.as_ref());
    let user_id = user.map(|u| u.id.clone()).unwrap_or_default();
    let user_name = user
        .map(|u| {
            u.global_name
                .as_ref()
                .filter(|s| !s.is_empty())
                .unwrap_or(&u.username)
                .clone()
        })
        .unwrap_or_default();

    let channel_id = message.channel_id.clone();

    let metadata = DiscordMessageMetadata {
        channel_id: channel_id.clone(),
        interaction_id: Some(interaction.id.clone()),
        token: Some(interaction.token.clone()),
        application_id: Some(interaction.application_id.clone()),
        source_message_id: None,
        thread_id: None,
    };

    let metadata_json = match serde_json::to_string(&metadata) {
        Ok(json) => json,
        Err(e) => {
            channel_host::log(
                channel_host::LogLevel::Error,
                &format!("Failed to serialize metadata: {}", e),
            );
            return; // Don't emit message if metadata can't be serialized
        }
    };

    channel_host::emit_message(&EmittedMessage {
        user_id,
        user_name: Some(user_name),
        content: format!("[Button clicked] {}", message.content),
        thread_id: None,
        metadata_json,
    });
}

fn json_response(status: u16, value: serde_json::Value) -> OutgoingHttpResponse {
    let body = serde_json::to_vec(&value).unwrap_or_default();
    let headers = serde_json::json!({"Content-Type": "application/json"});

    OutgoingHttpResponse {
        status,
        headers_json: headers.to_string(),
        body,
    }
}

export!(DiscordChannel);

fn truncate_message(content: &str) -> String {
    if content.len() <= 2000 {
        content.to_string()
    } else {
        let max_bytes = 1990;
        let cutoff = content
            .char_indices()
            .map(|(i, c)| i + c.len_utf8())
            .take_while(|&end| end <= max_bytes)
            .last()
            .unwrap_or(0);
        let mut truncated = content[..cutoff].to_string();
        truncated.push_str("\n... (truncated)");
        truncated
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_truncate_message() {
        let short = "Hello world";
        assert_eq!(truncate_message(short), short);

        let long = "a".repeat(2005);
        let truncated = truncate_message(&long);
        assert_eq!(truncated.len(), 2006); // 1990 + 16 chars suffix
        assert!(truncated.ends_with("\n... (truncated)"));

        // Test with multibyte characters (Euro sign is 3 bytes)
        // 1000 chars * 3 bytes = 3000 bytes
        let multi = "€".repeat(1000);
        let truncated_multi = truncate_message(&multi);

        // 1990 bytes limit. 1990 / 3 = 663 with remainder 1.
        // Should truncate at 663 chars (1989 bytes).
        // Suffix is 16 bytes. Total: 1989 + 16 = 2005 bytes.
        assert!(truncated_multi.len() <= 2006);
        assert!(truncated_multi.len() >= 2006 - 4); // Allow for max utf8 char width variance
        assert!(truncated_multi.ends_with("\n... (truncated)"));

        let content_part = &truncated_multi[..truncated_multi.len() - 16];
        assert!(content_part.chars().all(|c| c == '€'));
    }

    #[test]
    fn test_metadata_serialization() {
        let metadata = DiscordMessageMetadata {
            channel_id: "123".into(),
            interaction_id: Some("456".into()),
            token: Some("abc".into()),
            application_id: Some("789".into()),
            source_message_id: None,
            thread_id: None,
        };
        let json = serde_json::to_string(&metadata).unwrap();
        let parsed: DiscordMessageMetadata = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.channel_id, "123");
        assert_eq!(parsed.interaction_id.as_deref(), Some("456"));
    }
}
