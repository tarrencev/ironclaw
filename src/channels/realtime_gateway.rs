//! Discord Gateway channel for instant @mention handling.
//!
//! This channel connects to Discord Gateway via WebSocket, listens for
//! MESSAGE_CREATE events, and emits incoming messages when the bot is
//! mentioned. Responses are sent via Discord REST API.

use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use futures::{SinkExt, StreamExt};
use reqwest::header::{AUTHORIZATION, CONTENT_TYPE, HeaderMap, HeaderValue};
use serde::Deserialize;
use tokio::sync::{Mutex, RwLock, mpsc};
use tokio::task::JoinHandle;
use tokio_stream::wrappers::ReceiverStream;
use tokio_tungstenite::{connect_async, tungstenite::protocol::Message};

use crate::channels::{Channel, IncomingMessage, MessageStream, OutgoingResponse};
use crate::error::ChannelError;

const CHANNEL_NAME: &str = "discord-gateway";
const DISCORD_GATEWAY_URL: &str = "wss://gateway.discord.gg/?v=10&encoding=json";
const INTENT_GUILD_MESSAGES: u64 = 1 << 9;
const INTENT_DIRECT_MESSAGES: u64 = 1 << 12;
const INTENT_MESSAGE_CONTENT: u64 = 1 << 15;

#[derive(Debug, Clone)]
pub struct RealtimeGatewayConfig {
    pub token: String,
    pub mention_channel_ids: Vec<String>,
}

pub struct RealtimeGatewayChannel {
    config: RealtimeGatewayConfig,
    tx: Arc<RwLock<Option<mpsc::Sender<IncomingMessage>>>>,
    task: Arc<RwLock<Option<JoinHandle<()>>>>,
    http: reqwest::Client,
}

impl RealtimeGatewayChannel {
    pub fn new(config: RealtimeGatewayConfig) -> Result<Self, ChannelError> {
        let mut headers = HeaderMap::new();
        let auth = format!("Bot {}", config.token);
        let auth_value = HeaderValue::from_str(&auth).map_err(|e| ChannelError::StartupFailed {
            name: CHANNEL_NAME.to_string(),
            reason: format!("invalid bot token header: {e}"),
        })?;
        headers.insert(AUTHORIZATION, auth_value);
        headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));

        let http = reqwest::Client::builder()
            .default_headers(headers)
            .timeout(Duration::from_secs(15))
            .build()
            .map_err(|e| ChannelError::StartupFailed {
                name: CHANNEL_NAME.to_string(),
                reason: format!("failed to create HTTP client: {e}"),
            })?;

        Ok(Self {
            config,
            tx: Arc::new(RwLock::new(None)),
            task: Arc::new(RwLock::new(None)),
            http,
        })
    }
}

#[derive(Debug, Deserialize)]
struct GatewayEnvelope {
    op: i64,
    #[serde(default)]
    s: Option<i64>,
    #[serde(default)]
    t: Option<String>,
    #[serde(default)]
    d: serde_json::Value,
}

#[derive(Debug, Deserialize)]
struct HelloPayload {
    heartbeat_interval: u64,
}

#[derive(Debug, Deserialize)]
struct ReadyPayload {
    user: DiscordAuthor,
}

#[derive(Debug, Deserialize)]
struct DiscordMessageEvent {
    id: String,
    channel_id: String,
    #[allow(dead_code)]
    guild_id: Option<String>,
    content: String,
    author: DiscordAuthor,
    #[serde(default)]
    mentions: Vec<DiscordMention>,
}

#[derive(Debug, Deserialize)]
struct DiscordAuthor {
    id: String,
    username: String,
    #[serde(default)]
    global_name: Option<String>,
    #[serde(default)]
    bot: bool,
}

#[derive(Debug, Deserialize)]
struct DiscordMention {
    id: String,
}

async fn run_gateway_loop(
    token: String,
    allow_channels: HashSet<String>,
    tx: Arc<RwLock<Option<mpsc::Sender<IncomingMessage>>>>,
) {
    let mut backoff_secs = 1u64;
    loop {
        match run_gateway_session(&token, &allow_channels, &tx).await {
            Ok(()) => {
                backoff_secs = 1;
            }
            Err(e) => {
                tracing::warn!("Discord gateway session ended: {}", e);
                tokio::time::sleep(Duration::from_secs(backoff_secs)).await;
                backoff_secs = (backoff_secs * 2).min(30);
            }
        }
    }
}

async fn run_gateway_session(
    token: &str,
    allow_channels: &HashSet<String>,
    tx: &Arc<RwLock<Option<mpsc::Sender<IncomingMessage>>>>,
) -> Result<(), String> {
    let (stream, _) = connect_async(DISCORD_GATEWAY_URL)
        .await
        .map_err(|e| format!("connect failed: {e}"))?;
    let (writer, mut reader) = stream.split();
    let writer = Arc::new(Mutex::new(writer));

    let hello = match reader.next().await {
        Some(Ok(Message::Text(t))) => {
            serde_json::from_str::<GatewayEnvelope>(&t).map_err(|e| format!("hello parse: {e}"))?
        }
        Some(Ok(_)) => return Err("expected text hello frame".to_string()),
        Some(Err(e)) => return Err(format!("hello read error: {e}")),
        None => return Err("gateway closed before hello".to_string()),
    };
    if hello.op != 10 {
        return Err(format!("expected HELLO (op=10), got op={}", hello.op));
    }
    let hello_payload: HelloPayload =
        serde_json::from_value(hello.d).map_err(|e| format!("hello payload: {e}"))?;

    let identify = serde_json::json!({
        "op": 2,
        "d": {
            "token": token,
            "intents": INTENT_GUILD_MESSAGES | INTENT_DIRECT_MESSAGES | INTENT_MESSAGE_CONTENT,
            "properties": {
                "$os": "linux",
                "$browser": "ironclaw",
                "$device": "ironclaw"
            }
        }
    });
    {
        let mut w = writer.lock().await;
        w.send(Message::Text(identify.to_string().into()))
            .await
            .map_err(|e| format!("identify send failed: {e}"))?;
    }

    let seq = Arc::new(Mutex::new(None::<i64>));
    let seq_for_heartbeat = Arc::clone(&seq);
    let writer_for_heartbeat = Arc::clone(&writer);
    let heartbeat_interval = Duration::from_millis(hello_payload.heartbeat_interval.max(1_000));

    let heartbeat_task = tokio::spawn(async move {
        loop {
            tokio::time::sleep(heartbeat_interval).await;
            let d = *seq_for_heartbeat.lock().await;
            let heartbeat = serde_json::json!({ "op": 1, "d": d });
            let mut w = writer_for_heartbeat.lock().await;
            if w.send(Message::Text(heartbeat.to_string().into()))
                .await
                .is_err()
            {
                break;
            }
        }
    });

    let mut bot_user_id: Option<String> = None;

    while let Some(frame) = reader.next().await {
        let frame = frame.map_err(|e| format!("gateway read error: {e}"))?;
        let text = match frame {
            Message::Text(t) => t,
            Message::Close(_) => break,
            _ => continue,
        };
        let envelope: GatewayEnvelope = serde_json::from_str(&text)
            .map_err(|e| format!("gateway payload parse failed: {e}"))?;
        if let Some(s) = envelope.s {
            *seq.lock().await = Some(s);
        }

        match envelope.op {
            0 => {
                if let Some(event) = envelope.t.as_deref() {
                    match event {
                        "READY" => {
                            let ready: ReadyPayload = serde_json::from_value(envelope.d)
                                .map_err(|e| format!("READY parse failed: {e}"))?;
                            bot_user_id = Some(ready.user.id);
                        }
                        "MESSAGE_CREATE" => {
                            let Some(bot_id) = bot_user_id.as_deref() else {
                                continue;
                            };
                            let msg: DiscordMessageEvent = serde_json::from_value(envelope.d)
                                .map_err(|e| format!("MESSAGE_CREATE parse failed: {e}"))?;
                            if msg.author.bot || msg.author.id == bot_id {
                                continue;
                            }
                            if !allow_channels.is_empty() && !allow_channels.contains(&msg.channel_id)
                            {
                                continue;
                            }
                            let mentioned = msg.mentions.iter().any(|m| m.id == bot_id)
                                || msg.content.contains(&format!("<@{}>", bot_id))
                                || msg.content.contains(&format!("<@!{}>", bot_id));
                            if !mentioned {
                                continue;
                            }

                            let content = msg
                                .content
                                .replace(&format!("<@{}>", bot_id), "")
                                .replace(&format!("<@!{}>", bot_id), "")
                                .trim()
                                .to_string();

                            let user_name = msg
                                .author
                                .global_name
                                .clone()
                                .filter(|s| !s.is_empty())
                                .unwrap_or(msg.author.username.clone());

                            let incoming = IncomingMessage::new(
                                CHANNEL_NAME,
                                msg.author.id.clone(),
                                if content.is_empty() { "mention" } else { &content },
                            )
                            .with_user_name(user_name)
                            .with_metadata(serde_json::json!({
                                "channel_id": msg.channel_id,
                                "source_message_id": msg.id
                            }));

                            let tx_guard = tx.read().await;
                            if let Some(sender) = tx_guard.as_ref()
                                && sender.send(incoming).await.is_err()
                            {
                                break;
                            }
                        }
                        _ => {}
                    }
                }
            }
            1 => {
                let d = *seq.lock().await;
                let heartbeat = serde_json::json!({ "op": 1, "d": d });
                let mut w = writer.lock().await;
                w.send(Message::Text(heartbeat.to_string().into()))
                    .await
                    .map_err(|e| format!("heartbeat send failed: {e}"))?;
            }
            7 | 9 => {
                return Err(format!("gateway requested reconnect op={}", envelope.op));
            }
            _ => {}
        }
    }

    heartbeat_task.abort();
    Ok(())
}

#[async_trait]
impl Channel for RealtimeGatewayChannel {
    fn name(&self) -> &str {
        CHANNEL_NAME
    }

    async fn start(&self) -> Result<MessageStream, ChannelError> {
        let (tx, rx) = mpsc::channel(256);
        *self.tx.write().await = Some(tx);

        let token = self.config.token.clone();
        let allow_channels: HashSet<String> = self.config.mention_channel_ids.iter().cloned().collect();
        let tx_ref = Arc::clone(&self.tx);
        let handle = tokio::spawn(async move {
            run_gateway_loop(token, allow_channels, tx_ref).await;
        });
        *self.task.write().await = Some(handle);

        tracing::info!(
            channel = CHANNEL_NAME,
            monitored_channels = ?self.config.mention_channel_ids,
            "Discord gateway channel started"
        );
        Ok(Box::pin(ReceiverStream::new(rx)))
    }

    async fn respond(
        &self,
        msg: &IncomingMessage,
        response: OutgoingResponse,
    ) -> Result<(), ChannelError> {
        let channel_id = msg
            .metadata
            .get("channel_id")
            .and_then(|v| v.as_str())
            .ok_or_else(|| ChannelError::SendFailed {
                name: CHANNEL_NAME.to_string(),
                reason: "missing metadata.channel_id".to_string(),
            })?;
        let source_message_id = msg
            .metadata
            .get("source_message_id")
            .and_then(|v| v.as_str());

        let mut payload = serde_json::json!({
            "content": response.content,
        });
        if let Some(message_id) = source_message_id {
            payload["message_reference"] = serde_json::json!({ "message_id": message_id });
            payload["allowed_mentions"] = serde_json::json!({ "replied_user": true });
        }

        let url = format!("https://discord.com/api/v10/channels/{}/messages", channel_id);
        let resp = self
            .http
            .post(&url)
            .json(&payload)
            .send()
            .await
            .map_err(|e| ChannelError::Http(e.to_string()))?;
        if resp.status().is_success() {
            Ok(())
        } else {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            Err(ChannelError::SendFailed {
                name: CHANNEL_NAME.to_string(),
                reason: format!("discord API error {}: {}", status, body),
            })
        }
    }

    async fn health_check(&self) -> Result<(), ChannelError> {
        let guard = self.task.read().await;
        if let Some(handle) = guard.as_ref()
            && !handle.is_finished()
        {
            return Ok(());
        }
        Err(ChannelError::HealthCheckFailed {
            name: CHANNEL_NAME.to_string(),
        })
    }

    async fn shutdown(&self) -> Result<(), ChannelError> {
        if let Some(handle) = self.task.write().await.take() {
            handle.abort();
        }
        *self.tx.write().await = None;
        Ok(())
    }
}
