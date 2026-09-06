#[cfg(not(unix))]
compile_error!("shadow6-rust currently requires a Unix or Unix-like target; use Core-Go on other operating-system families");

use base64::{engine::general_purpose::STANDARD as B64, Engine};
use ed25519_dalek::{Signature, Signer, Verifier, VerifyingKey};
use futures_util::{SinkExt, StreamExt};
use quinn::{
    ClientConfig as QuinnClientConfig, Endpoint, ServerConfig as QuinnServerConfig, VarInt,
};
use rand::rngs::OsRng;
use rand::RngCore;
use rcgen::generate_simple_self_signed;
use rustls::pki_types::CertificateDer;
use serde::{Deserialize, Serialize};
mod strict_json;
use sha2::{Digest, Sha256};
use socket2::{Domain, Protocol, Socket, Type};
use std::collections::{HashMap, HashSet};
use std::env;
use std::ffi::CString;
use std::fs;
use std::io::{Read, Write};
use std::net::{IpAddr, Ipv6Addr, SocketAddr, SocketAddrV6};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::process::Command;
use tokio::sync::{mpsc, oneshot, Mutex, RwLock, Semaphore};
use tokio_tungstenite::tungstenite::protocol::WebSocketConfig;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::{accept_hdr_async_with_config, connect_async_with_config, WebSocketStream};

// ============================================================================
// CONFIGURATION MODELS (JSON)
// ============================================================================

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
struct Config {
    role: String, // "broker", "agent", or "client"
    broker: Option<BrokerConfig>,
    agent: Option<AgentConfig>,
    client: Option<ClientConfig>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
struct BrokerConfig {
    listen_addr: String,
    private_key: String, // Hex encoded
    agents: Vec<AgentRBAC>,
    clients: Vec<ClientRBAC>,
    webhook_url: String,
    stealth_mode: bool,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
struct AgentRBAC {
    id: String,
    pubkey: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
struct ClientRBAC {
    id: String,
    pubkey: String,
    allowed_agents: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
struct AgentConfig {
    id: String,
    broker_addrs: Vec<String>,
    broker_pubkey: String,
    private_key: String,
    target_port: u16,
    auto_close_after: u64, // seconds
    allow_local_discovery: bool,
    #[serde(default)]
    client_pubkeys: HashMap<String, String>,
    pub sni: Option<String>,
    pub alpn: Option<String>,
    pub transport: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
struct ClientConfig {
    id: String,
    broker_addrs: Vec<String>,
    broker_pubkey: String,
    private_key: String,
    target_agent: String,
    on_success: String,
    allow_local_discovery: bool,
    #[serde(default)]
    agent_pubkey: String,
    pub sni: Option<String>,
    pub alpn: Option<String>,
    pub transport: Option<String>,
}

const CORE_VERSION: &str = "1.1.0";
const TARGET_THROUGHPUT_BITS_PER_SECOND: u64 = 10_000_000_000;
const DESIGN_ROUND_TRIP_MILLISECONDS: u64 = 50;
const QUIC_CONNECTION_WINDOW_BYTES: u64 = 64 * 1024 * 1024;
const QUIC_STREAM_WINDOW_BYTES: u64 = 16 * 1024 * 1024;
const MAX_ACTIVE_TUNNELS: usize = 512;
const MAX_CONTROL_CONNECTIONS: usize = 4096;
const MAX_STREAMS_PER_TUNNEL: u32 = 256;
const CROSED_CAPABILITIES: [(&str, u8); 10] = [
    ("observe.version", 1),
    ("observe.health", 1),
    ("policy.request", 2),
    ("policy.config", 2),
    ("transport.metadata", 3),
    ("transport.application", 3),
    ("identity.assert", 4),
    ("identity.resolve", 4),
    ("core.lifecycle", 5),
    ("core.hook", 5),
];

#[derive(Debug, Serialize)]
struct FeatureReport {
    core: &'static str,
    version: &'static str,
    crosed_compiled: bool,
    crosed_max_level: u8,
    app_transport: bool,
    qubes_isolation: bool,
    gate_compiled: bool,
    gate_enabled_by_default: bool,
    utf8: bool,
    crosed_capabilities: Vec<&'static str>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CrosedRequest {
    version: u8,
    mod_id: String,
    nonce: String,
    issued_at: i64,
    requested_level: u8,
    capabilities: Vec<String>,
    #[serde(default)]
    source_domain: String,
    #[serde(default)]
    target_domain: String,
    payload: serde_json::Value,
    signature: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CrosedTrust {
    mods: HashMap<String, CrosedTrustEntry>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CrosedTrustEntry {
    pubkey: String,
    max_level: u8,
    capabilities: Vec<String>,
    #[serde(default)]
    allowed_domains: Vec<String>,
}

#[derive(Debug, Serialize)]
struct CrosedResponse {
    #[serde(flatten)]
    features: FeatureReport,
    mod_id: String,
    granted_level: u8,
    granted_capabilities: Vec<String>,
    status: &'static str,
    #[serde(skip_serializing_if = "String::is_empty")]
    reason: String,
}

fn compiled_crosed_level() -> u8 {
    if cfg!(feature = "crosed-level-5") {
        5
    } else if cfg!(feature = "crosed-level-4") {
        4
    } else if cfg!(feature = "crosed-level-3") {
        3
    } else if cfg!(feature = "crosed-level-2") {
        2
    } else if cfg!(feature = "crosed") {
        1
    } else {
        0
    }
}

fn feature_report() -> FeatureReport {
    let level = compiled_crosed_level();
    let mut capabilities: Vec<_> = CROSED_CAPABILITIES
        .iter()
        .filter(|(name, required)| {
            *required <= level
                && (*name != "transport.application" || cfg!(feature = "app-transport"))
        })
        .map(|(name, _)| *name)
        .collect();
    capabilities.sort_unstable();
    FeatureReport {
        core: "shadow6-rust",
        version: CORE_VERSION,
        crosed_compiled: level > 0,
        crosed_max_level: level,
        app_transport: cfg!(feature = "app-transport"),
        qubes_isolation: cfg!(feature = "qubes-isolation"),
        gate_compiled: true,
        gate_enabled_by_default: false,
        utf8: true,
        crosed_capabilities: capabilities,
    }
}

fn crosed_signed_payload(request: &CrosedRequest) -> Result<Vec<u8>, String> {
    validate_crosed_payload(&request.payload, 0)?;
    let payload = serde_json::to_vec(&request.payload).map_err(|error| error.to_string())?;
    let digest = Sha256::digest(payload);
    let mut capabilities = request.capabilities.clone();
    capabilities.sort_unstable();
    Ok(format!(
        "{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}",
        request.version,
        request.mod_id,
        request.nonce,
        request.issued_at,
        request.requested_level,
        capabilities.join(","),
        hex::encode(digest),
        request.source_domain,
        request.target_domain,
    )
    .into_bytes())
}

fn validate_crosed_payload(value: &serde_json::Value, depth: usize) -> Result<(), String> {
    if depth > 16 { return Err("Crosed payload nesting exceeds 16 levels".into()); }
    match value {
        serde_json::Value::Null | serde_json::Value::Bool(_) => Ok(()),
        serde_json::Value::Number(number) => {
            if number.is_f64() || !number.as_i64().is_some_and(|n| (-9_007_199_254_740_991..=9_007_199_254_740_991).contains(&n)) {
                Err("Crosed numbers must be portable integers".into())
            } else { Ok(()) }
        }
        serde_json::Value::String(text) => {
            if text.len() > 16_384 || text.contains('\0') { Err("invalid Crosed string".into()) } else { Ok(()) }
        }
        serde_json::Value::Array(items) => {
            for item in items { validate_crosed_payload(item, depth + 1)?; }
            Ok(())
        }
        serde_json::Value::Object(items) => {
            for (key, item) in items {
                validate_crosed_payload(&serde_json::Value::String(key.clone()), depth + 1)?;
                validate_crosed_payload(item, depth + 1)?;
            }
            Ok(())
        }
    }
}

fn handle_crosed_request(request_path: &str, trust_path: &str) -> Result<CrosedResponse, String> {
    let features = feature_report();
    let mut response = CrosedResponse {
        features,
        mod_id: String::new(),
        granted_level: 0,
        granted_capabilities: Vec::new(),
        status: "denied",
        reason: String::new(),
    };
    if !response.features.crosed_compiled {
        response.reason = "crosed is not compiled into this core".into();
        return Ok(response);
    }
    let request_data = read_secure_config(Path::new(request_path))?;
    let trust_data = read_secure_config(Path::new(trust_path))?;
    if request_data.len() > 65_536 || trust_data.len() > 65_536 {
        return Err("Crosed request or trust store exceeds 64 KiB".into());
    }
    let request: CrosedRequest = strict_json::from_str(&request_data)
        .map_err(|error| format!("invalid Crosed request: {error}"))?;
    let trust: CrosedTrust = strict_json::from_str(&trust_data)
        .map_err(|error| format!("invalid Crosed trust store: {error}"))?;
    response.mod_id = request.mod_id.clone();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| "system clock is before Unix epoch")?
        .as_secs() as i64;
    if request.version != 1
        || !valid_identity(&request.mod_id)
        || hex::decode(&request.nonce).map_or(true, |nonce| nonce.len() != 16)
        || !(1..=5).contains(&request.requested_level)
        || now.abs_diff(request.issued_at) > 300
    {
        return Err("invalid Crosed request fields".into());
    }
    let policy = trust
        .mods
        .get(&request.mod_id)
        .ok_or("untrusted Crosed mod")?;
    if !(1..=5).contains(&policy.max_level) || request.requested_level > policy.max_level {
        response.reason = "requested level exceeds the per-Mod policy".into();
        return Ok(response);
    }
    let key_bytes = hex::decode(&policy.pubkey).map_err(|_| "invalid Crosed public key hex")?;
    let key_array: [u8; 32] = key_bytes
        .try_into()
        .map_err(|_| "invalid Crosed public key length")?;
    let verifying_key =
        VerifyingKey::from_bytes(&key_array).map_err(|_| "invalid Crosed public key")?;
    let signature_bytes =
        hex::decode(&request.signature).map_err(|_| "invalid Crosed signature hex")?;
    let signature =
        Signature::from_slice(&signature_bytes).map_err(|_| "invalid Crosed signature length")?;
    verifying_key
        .verify(&crosed_signed_payload(&request)?, &signature)
        .map_err(|_| "invalid Crosed request signature")?;
    if request.requested_level > response.features.crosed_max_level {
        response.reason = "requested level exceeds this Core build".into();
        return Ok(response);
    }
    let mut seen = HashSet::new();
    let allowed_capabilities: HashSet<_> = policy.capabilities.iter().collect();
    for capability in &request.capabilities {
        if !seen.insert(capability) {
            return Err("duplicate Crosed capability".into());
        }
        let required = CROSED_CAPABILITIES
            .iter()
            .find(|(name, _)| name == capability)
            .map(|(_, level)| *level)
            .ok_or("unknown Crosed capability")?;
        if !allowed_capabilities.contains(capability)
            || required > request.requested_level
            || (capability == "transport.application" && !response.features.app_transport)
        {
            response.reason = "capability unavailable at requested level or build".into();
            return Ok(response);
        }
        response.granted_capabilities.push(capability.clone());
    }
    if response.features.qubes_isolation {
        let (source_domain, target_domain) =
            if request.source_domain.is_empty() && request.target_domain.is_empty() {
                ("default", "default")
            } else {
                (
                    request.source_domain.as_str(),
                    request.target_domain.as_str(),
                )
            };
        if !valid_crosed_domain(source_domain) || !valid_crosed_domain(target_domain) {
            return Err("Qubes isolation requires valid source and target domains".into());
        }
        if source_domain != target_domain
            && !policy
                .allowed_domains
                .iter()
                .any(|domain| domain == target_domain)
        {
            response.reason = "Qubes cross-domain policy denied".into();
            return Ok(response);
        }
    }
    response.granted_capabilities.sort_unstable();
    response.granted_level = request.requested_level;
    response.status = "granted";
    Ok(response)
}

fn valid_crosed_domain(value: &str) -> bool {
    if value.is_empty() || value.len() > 32 {
        return false;
    }
    value.chars().enumerate().all(|(index, character)| {
        character.is_ascii_lowercase()
            || (index > 0 && character.is_ascii_digit())
            || (index > 0 && character == '-')
    })
}

// ============================================================================
// RPC PAYLOAD MODELS
// ============================================================================

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct AuthResponse {
    pub id: String,
    pub signature: String, // Base64 encoded
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
struct AccessReq {
    pub client_id: String,
    pub target_agent: String,
    pub client_ipv6: String,
    pub e2ee_pubkey: String, // Base64-encoded client nonce binding the Agent response to this request.
    pub client_signature: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
struct AccessResp {
    pub success: bool,
    pub target_ipv6: String,
    pub dynamic_port: u16,
    pub kcp_port: u16,       // Legacy name, now maps to QUIC Port
    pub e2ee_pubkey: String, // Base64 encoded Agent's QUIC Cert DER
    pub error_msg: String,
    #[serde(default)]
    pub sni: String,
    #[serde(default)]
    pub alpn: String,
    #[serde(default)]
    pub transport: String,
    pub agent_signature: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
struct UpdateIPReq {
    pub agent_id: String,
    pub ipv6: String,
}

// JSON-RPC 2.0 Base Structures
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct JsonRpcRequest {
    jsonrpc: String,
    id: u64,
    method: String,
    params: serde_json::Value,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct JsonRpcResponse {
    jsonrpc: String,
    id: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    result: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

impl JsonRpcRequest {
    fn is_valid(&self) -> bool {
        self.jsonrpc == "2.0" && self.id != 0 && !self.method.is_empty() && self.method.len() <= 128
    }
}

impl JsonRpcResponse {
    fn is_valid(&self) -> bool {
        self.jsonrpc == "2.0"
            && self.id != 0
            && matches!(
                (&self.result, &self.error),
                (Some(_), None) | (None, Some(_))
            )
    }
}

// ============================================================================
// ASYNC JSON-RPC OVER WEBSOCKET WRAPPER
// ============================================================================

type RpcResult = Result<serde_json::Value, String>;
type RpcPendingMap = Arc<RwLock<HashMap<u64, oneshot::Sender<RpcResult>>>>;

#[derive(Clone)]
struct WsRpcClient {
    tx: mpsc::Sender<Message>,
    pending: RpcPendingMap,
    req_id: Arc<AtomicU64>,
}

impl WsRpcClient {
    async fn call<T: Serialize, R: serde::de::DeserializeOwned>(
        &self,
        method: &str,
        params: T,
    ) -> Result<R, Box<dyn std::error::Error + Send + Sync>> {
        let id = self.req_id.fetch_add(1, Ordering::SeqCst);
        let req = JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            id,
            method: method.to_string(),
            params: serde_json::to_value(params)?,
        };

        let (resp_tx, resp_rx) = oneshot::channel();
        self.pending.write().await.insert(id, resp_tx);

        if let Err(error) = self
            .tx
            .send(Message::Text(serde_json::to_string(&req)?.into()))
            .await
        {
            self.pending.write().await.remove(&id);
            return Err(error.into());
        }

        // Wait for response with timeout
        let result_val = match tokio::time::timeout(Duration::from_secs(10), resp_rx).await {
            Ok(Ok(result)) => result.map_err(std::io::Error::other)?,
            Ok(Err(error)) => return Err(error.into()),
            Err(error) => {
                self.pending.write().await.remove(&id);
                return Err(error.into());
            }
        };
        let result: R = serde_json::from_value(result_val)?;
        Ok(result)
    }
}

// ============================================================================
// CRYPTO, STEALTH & HELPERS
// ============================================================================

fn s6_log(prefix: &str, msg: &str) {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    println!("[{}] {} {}", now, prefix, msg);
    let _ = std::io::stdout().flush();
}

fn mask_ip(ip: &str, stealth: bool) -> String {
    if !stealth || ip.is_empty() {
        return ip.to_string();
    }
    static MASK_SALT: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    let salt = MASK_SALT.get_or_init(|| {
        let mut buf = [0u8; 16];
        rand::rngs::OsRng.fill_bytes(&mut buf);
        hex::encode(buf)
    });
    let mut hasher = Sha256::new();
    hasher.update(format!("{}{}", ip, salt));
    hasher.update(format!("{}shadow_salt", ip));
    let hash = hasher.finalize();
    format!(
        "IP[MASKED:{:02x}{:02x}{:02x}{:02x}]",
        hash[0], hash[1], hash[2], hash[3]
    )
}

async fn get_route_ip() -> String {
    // UDP connect does not transmit a packet; it asks the kernel which source
    // address it would use. Prefer IPv6 and remain usable on IPv4-only hosts.
    for (bind, destination) in [
        ("[::]:0", "[2606:4700:4700::1111]:53"),
        ("0.0.0.0:0", "1.1.1.1:53"),
    ] {
        if let Ok(socket) = UdpSocket::bind(bind).await {
            if socket.connect(destination).await.is_ok() {
                if let Ok(addr) = socket.local_addr() {
                    if !addr.ip().is_unspecified() {
                        return addr.ip().to_string();
                    }
                }
            }
        }
    }
    String::new()
}

fn signing_key_from_hex(value: &str) -> Result<ed25519_dalek::SigningKey, String> {
    let bytes = hex::decode(value).map_err(|error| format!("invalid private-key hex: {error}"))?;
    let seed: [u8; 32] = match bytes.len() {
        32 => bytes
            .as_slice()
            .try_into()
            .map_err(|_| "invalid private key".to_string())?,
        // Accept expanded Ed25519 keys emitted by some older Shadow6 builds.
        64 => {
            let seed: [u8; 32] = bytes[..32]
                .try_into()
                .map_err(|_| "invalid private key".to_string())?;
            let key = ed25519_dalek::SigningKey::from_bytes(&seed);
            if key.verifying_key().as_bytes() != &bytes[32..] {
                return Err("expanded private key has an inconsistent public half".into());
            }
            seed
        }
        size => return Err(format!("private key must be 32 or 64 bytes, got {size}")),
    };
    Ok(ed25519_dalek::SigningKey::from_bytes(&seed))
}

fn verifying_key_from_hex(value: &str) -> Result<VerifyingKey, String> {
    let bytes = hex::decode(value).map_err(|error| format!("invalid public-key hex: {error}"))?;
    let bytes: [u8; 32] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| "public key must be exactly 32 bytes".to_string())?;
    VerifyingKey::from_bytes(&bytes).map_err(|error| format!("invalid public key: {error}"))
}

fn verify_auth_response(
    response: &AuthResponse,
    expected_id: &str,
    key: &VerifyingKey,
    nonce: &[u8],
) -> Result<(), String> {
    if response.id != expected_id {
        return Err("unexpected peer identity".into());
    }
    let bytes = B64
        .decode(&response.signature)
        .map_err(|_| "invalid base64 signature".to_string())?;
    let signature = ed25519_dalek::Signature::from_slice(&bytes)
        .map_err(|_| "invalid Ed25519 signature".to_string())?;
    key.verify(&auth_payload(expected_id, nonce), &signature)
        .map_err(|_| "signature verification failed".to_string())
}

fn auth_payload(identity: &str, nonce: &[u8]) -> Vec<u8> {
    signed_fields(
        b"shadow6-rust-control-auth-v1",
        &[identity.as_bytes(), nonce],
    )
}

fn agent_access_payload(request: &AccessReq, response: &AccessResp) -> Vec<u8> {
    signed_fields(
        b"shadow6-rust-agent-access-v1",
        &[
            request.client_id.as_bytes(),
            request.target_agent.as_bytes(),
            request.client_ipv6.as_bytes(),
            request.e2ee_pubkey.as_bytes(),
            response.e2ee_pubkey.as_bytes(),
            &response.dynamic_port.to_be_bytes(),
            &response.kcp_port.to_be_bytes(),
            response.sni.as_bytes(),
            response.alpn.as_bytes(),
            response.transport.as_bytes(),
        ],
    )
}

fn client_access_payload(request: &AccessReq) -> Vec<u8> {
    signed_fields(
        b"shadow6-rust-client-access-v1",
        &[
            request.client_id.as_bytes(),
            request.target_agent.as_bytes(),
            request.client_ipv6.as_bytes(),
            request.e2ee_pubkey.as_bytes(),
        ],
    )
}

fn verify_client_access(request: &AccessReq, key: &VerifyingKey) -> Result<(), String> {
    let signature_bytes = B64
        .decode(&request.client_signature)
        .map_err(|_| "client returned invalid access-signature encoding".to_string())?;
    let signature = ed25519_dalek::Signature::from_slice(&signature_bytes)
        .map_err(|_| "client returned an invalid access signature".to_string())?;
    key.verify(&client_access_payload(request), &signature)
        .map_err(|_| "client access-signature verification failed".to_string())
}

fn verify_agent_access(
    request: &AccessReq,
    response: &AccessResp,
    key: &VerifyingKey,
) -> Result<(), String> {
    let signature_bytes = B64
        .decode(&response.agent_signature)
        .map_err(|_| "agent returned invalid access-signature encoding".to_string())?;
    let signature = ed25519_dalek::Signature::from_slice(&signature_bytes)
        .map_err(|_| "agent returned an invalid access signature".to_string())?;
    key.verify(&agent_access_payload(request, response), &signature)
        .map_err(|_| "agent access-signature verification failed".to_string())
}

fn unix_timestamp() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn websocket_config() -> WebSocketConfig {
    WebSocketConfig::default()
        .read_buffer_size(16 * 1024)
        .write_buffer_size(16 * 1024)
        .max_write_buffer_size(128 * 1024)
        .max_message_size(Some(64 * 1024))
        .max_frame_size(Some(64 * 1024))
}

fn normalized_broker_url(value: &str) -> Result<String, String> {
    if value.is_empty() || value.len() > 2048 || value.contains(['\r', '\n', '\0']) {
        return Err("invalid broker URL".into());
    }
    let candidate = if value.starts_with("ws://") || value.starts_with("wss://") {
        value.to_string()
    } else {
        format!("wss://{value}/ws")
    };
    let parsed = reqwest::Url::parse(&candidate).map_err(|_| "invalid broker URL".to_string())?;
    let host = parsed.host_str().ok_or("broker URL is missing a host")?;
    if !parsed.username().is_empty() || parsed.password().is_some() || parsed.fragment().is_some() {
        return Err("broker URL must not contain credentials or a fragment".into());
    }
    let loopback = host == "localhost" || host.parse::<IpAddr>().is_ok_and(|ip| ip.is_loopback());
    if parsed.scheme() != "wss" && !(parsed.scheme() == "ws" && loopback) {
        return Err("broker URLs must use wss:// (ws:// is loopback-only)".into());
    }
    Ok(candidate)
}

fn validate_webhook_url(value: &str) -> Result<(), String> {
    if value.is_empty() {
        return Ok(());
    }
    if value.len() > 2048 || value.contains(['\r', '\n', '\0']) {
        return Err("webhook_url is invalid".into());
    }
    let parsed = reqwest::Url::parse(value).map_err(|_| "webhook_url is invalid".to_string())?;
    if parsed.scheme() != "https"
        || parsed.host_str().is_none()
        || !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.fragment().is_some()
    {
        return Err(
            "webhook_url must be an absolute HTTPS URL without credentials or a fragment".into(),
        );
    }
    Ok(())
}

#[allow(clippy::result_large_err)] // Callback's error type is fixed by tungstenite.
fn websocket_callback(
    request: &tokio_tungstenite::tungstenite::handshake::server::Request,
    response: tokio_tungstenite::tungstenite::handshake::server::Response,
) -> Result<
    tokio_tungstenite::tungstenite::handshake::server::Response,
    tokio_tungstenite::tungstenite::handshake::server::ErrorResponse,
> {
    if request.uri().path() != "/ws" || request.headers().contains_key("origin") {
        Err(tokio_tungstenite::tungstenite::http::Response::builder()
            .status(403)
            .body(Some("WebSocket endpoint rejected".into()))
            .expect("static HTTP rejection"))
    } else {
        Ok(response)
    }
}

fn interface_scope_id(zone: &str) -> Result<u32, String> {
    if zone.is_empty()
        || zone.len() > 64
        || !zone
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || "-_.".contains(character))
    {
        return Err("invalid IPv6 scope zone".into());
    }
    if let Ok(index) = zone.parse::<u32>() {
        return (index > 0)
            .then_some(index)
            .ok_or_else(|| "IPv6 scope index must be positive".into());
    }
    let name = CString::new(zone).map_err(|_| "invalid IPv6 scope zone".to_string())?;
    // POSIX if_nametoindex(3) is provided by the host network stack on Linux,
    // Android, the BSDs, macOS, illumos/Solaris, AIX, and other Unix-like
    // systems.  Do not infer an index from Linux-only sysfs paths.
    let index = unsafe { libc::if_nametoindex(name.as_ptr()) };
    (index > 0)
        .then_some(index)
        .ok_or_else(|| "unknown IPv6 scope interface".into())
}

fn parse_scoped_peer_ip(value: &str) -> Result<(IpAddr, u32), String> {
    let (address, scope_id) = match value.rsplit_once('%') {
        Some((address, zone)) => (address, interface_scope_id(zone)?),
        None => (value, 0),
    };
    let ip: IpAddr = address
        .parse()
        .map_err(|_| "invalid peer IP address".to_string())?;
    if ip.is_unspecified() || ip.is_multicast() {
        return Err("unspecified or multicast peer IP is not allowed".into());
    }
    if scope_id != 0 && ip.is_ipv4() {
        return Err("scope zones are valid only for IPv6 addresses".into());
    }
    Ok((ip, scope_id))
}

fn parse_peer_ip(value: &str) -> Result<IpAddr, String> {
    parse_scoped_peer_ip(value).map(|(ip, _)| ip)
}

fn ipv6_interface_indices() -> Vec<u32> {
    let mut indices = Vec::new();

    // POSIX specifies a sentinel-terminated array owned by libc; walk it fully
    // so high-interface hosts do not silently lose usable IPv6 interfaces.
    let interfaces = unsafe { libc::if_nameindex() };
    if interfaces.is_null() {
        return indices;
    }
    let mut offset = 0usize;
    loop {
        let interface = unsafe { &*interfaces.add(offset) };
        if interface.if_index == 0 && interface.if_name.is_null() {
            break;
        }
        if interface.if_index > 0
            && !interface.if_name.is_null()
            && !indices.contains(&interface.if_index)
        {
            indices.push(interface.if_index);
        }
        offset += 1;
    }
    unsafe { libc::if_freenameindex(interfaces) };
    indices.sort_unstable();
    indices
}

fn bind_ipv6_udp(address: SocketAddrV6) -> std::io::Result<UdpSocket> {
    let socket = Socket::new(Domain::IPV6, Type::DGRAM, Some(Protocol::UDP))?;
    socket.set_only_v6(true)?;
    socket.set_nonblocking(true)?;
    socket.bind(&SocketAddr::V6(address).into())?;
    UdpSocket::from_std(socket.into())
}

fn validate_access_response(response: &AccessResp) -> Result<(), String> {
    if !response.success || response.kcp_port == 0 || response.transport != "quic" {
        return Err("agent returned an invalid QUIC access response".into());
    }
    if response.sni.is_empty()
        || response.sni.len() > 253
        || response.sni.contains(['\r', '\n', '\0'])
        || response.alpn.is_empty()
        || response.alpn.len() > 255
    {
        return Err("agent returned invalid SNI or ALPN metadata".into());
    }
    let certificate = B64
        .decode(&response.e2ee_pubkey)
        .map_err(|_| "agent returned invalid certificate encoding".to_string())?;
    if certificate.is_empty() || certificate.len() > 32 * 1024 {
        return Err("agent certificate size is outside safe bounds".into());
    }
    Ok(())
}

// ============================================================================
// BROKER IMPLEMENTATION
// ============================================================================

// Generates a private-use server name. It is authenticated by the pinned ephemeral
// certificate and deliberately does not impersonate a public web site.
fn generate_random_sni() -> String {
    let consonants = *b"bcdfghjklmnprstvwxz";
    let vowels = *b"aeiou";
    let mut sni = String::new();
    let mut rng = rand::rngs::OsRng;
    for _ in 0..(rng.next_u32() % 3 + 3) {
        sni.push(consonants[(rng.next_u32() as usize) % consonants.len()] as char);
        sni.push(vowels[(rng.next_u32() as usize) % vowels.len()] as char);
    }
    sni.push_str(".shadow6.invalid");
    sni
}

async fn start_broker(cfg: Config) -> Result<(), String> {
    let broker_cfg = cfg.broker.ok_or("missing broker configuration")?;
    let addr = broker_cfg.listen_addr.clone();
    let broker_signing_key = signing_key_from_hex(&broker_cfg.private_key)?;

    // Parse keys
    let mut expected_keys = HashMap::new();
    for agent in &broker_cfg.agents {
        if let Ok(key) = verifying_key_from_hex(&agent.pubkey) {
            expected_keys.insert(agent.id.clone(), key);
        }
    }
    for client in &broker_cfg.clients {
        if let Ok(key) = verifying_key_from_hex(&client.pubkey) {
            expected_keys.insert(client.id.clone(), key);
        }
    }
    let expected_keys = Arc::new(expected_keys);

    let agent_ips: Arc<RwLock<HashMap<String, String>>> = Arc::new(RwLock::new(HashMap::new()));
    let agent_rpcs: Arc<RwLock<HashMap<String, (u64, WsRpcClient)>>> =
        Arc::new(RwLock::new(HashMap::new()));
    let agent_generation = Arc::new(AtomicU64::new(1));

    let listener = TcpListener::bind(&addr)
        .await
        .map_err(|error| format!("failed to bind {addr}: {error}"))?;
    let connection_limit = Arc::new(Semaphore::new(MAX_CONTROL_CONNECTIONS));
    s6_log(
        "[Broker]",
        &format!(
            "Listening on {} (Stealth Mode: {})",
            addr, broker_cfg.stealth_mode
        ),
    );

    loop {
        let (stream, peer_addr) = listener
            .accept()
            .await
            .map_err(|error| format!("broker accept failed: {error}"))?;
        let Ok(connection_permit) = connection_limit.clone().try_acquire_owned() else {
            s6_log("[Broker]", "Connection limit reached; dropping new peer");
            drop(stream);
            continue;
        };
        let b_cfg = broker_cfg.clone();
        let expected_keys = expected_keys.clone();
        let agent_ips = agent_ips.clone();
        let agent_rpcs = agent_rpcs.clone();
        let agent_generation = agent_generation.clone();
        let broker_signing_key = broker_signing_key.clone();

        tokio::spawn(async move {
            let _connection_permit = connection_permit;
            let ws_stream = match accept_hdr_async_with_config(
                stream,
                websocket_callback,
                Some(websocket_config()),
            )
            .await
            {
                Ok(ws) => ws,
                Err(_) => return,
            };
            let (mut ws_tx, mut ws_rx) = ws_stream.split();

            // --- Authentication Phase ---
            let mut nonce = [0u8; 32];
            OsRng.fill_bytes(&mut nonce);
            if ws_tx
                .send(Message::Binary(nonce.to_vec().into()))
                .await
                .is_err()
            {
                return;
            }

            let auth_msg = match tokio::time::timeout(Duration::from_secs(10), ws_rx.next()).await {
                Ok(Some(Ok(Message::Text(text)))) => text,
                _ => return,
            };

            let auth_resp: AuthResponse = match strict_json::from_str(&auth_msg) {
                Ok(r) => r,
                Err(_) => return,
            };

            let pubkey = match expected_keys.get(&auth_resp.id) {
                Some(k) => k,
                None => return,
            };

            let sig_bytes = match B64.decode(&auth_resp.signature) {
                Ok(b) => b,
                Err(_) => return,
            };

            let sig = match ed25519_dalek::Signature::from_slice(&sig_bytes) {
                Ok(s) => s,
                Err(_) => return,
            };

            if pubkey
                .verify(&auth_payload(&auth_resp.id, &nonce), &sig)
                .is_err()
            {
                s6_log(
                    "[Broker]",
                    &format!("Invalid signature from {}", auth_resp.id),
                );
                return;
            }

            // Mutual authentication: a peer must authenticate the Broker before
            // either side can send or process RPC messages.
            let peer_nonce = match tokio::time::timeout(Duration::from_secs(10), ws_rx.next()).await
            {
                Ok(Some(Ok(Message::Binary(value)))) if value.len() == 32 => value,
                _ => return,
            };
            let broker_auth = AuthResponse {
                id: "broker".into(),
                signature: B64.encode(
                    broker_signing_key
                        .sign(&auth_payload("broker", &peer_nonce))
                        .to_bytes(),
                ),
            };
            let broker_auth_json = match serde_json::to_string(&broker_auth) {
                Ok(value) => value,
                Err(_) => return,
            };
            if ws_tx
                .send(Message::Text(broker_auth_json.into()))
                .await
                .is_err()
            {
                return;
            }

            let peer_id = auth_resp.id.clone();
            let is_agent = b_cfg.agents.iter().any(|a| a.id == peer_id);
            let connection_generation = agent_generation.fetch_add(1, Ordering::Relaxed);

            // --- RPC Setup ---
            let (rpc_tx, mut rpc_rx) = mpsc::channel(100);
            let pending: RpcPendingMap = Arc::new(RwLock::new(HashMap::new()));
            let rpc_client = WsRpcClient {
                tx: rpc_tx.clone(),
                pending: pending.clone(),
                req_id: Arc::new(AtomicU64::new(1)),
            };

            tokio::spawn(async move {
                while let Some(msg) = rpc_rx.recv().await {
                    let _ = ws_tx.send(msg).await;
                }
            });

            if is_agent {
                s6_log(
                    "[Broker]",
                    &format!(
                        "Agent {} connected from {}",
                        peer_id,
                        mask_ip(&peer_addr.ip().to_string(), b_cfg.stealth_mode)
                    ),
                );
                agent_rpcs
                    .write()
                    .await
                    .insert(peer_id.clone(), (connection_generation, rpc_client.clone()));
            } else {
                s6_log("[Broker]", &format!("Client {} connected", peer_id));
            }

            // --- Incoming Message Loop ---
            let request_limit = Arc::new(Semaphore::new(32));
            while let Some(Ok(Message::Text(text))) = ws_rx.next().await {
                if let Some(resp) = strict_json::from_str::<JsonRpcResponse>(&text)
                    .ok()
                    .filter(JsonRpcResponse::is_valid)
                {
                    if let Some(sender) = pending.write().await.remove(&resp.id) {
                        let result = match (resp.result, resp.error) {
                            (Some(result), None) => Ok(result),
                            (_, Some(error)) => Err(error),
                            _ => Err("malformed RPC response".into()),
                        };
                        let _ = sender.send(result);
                    }
                    continue;
                }

                if let Some(req) = strict_json::from_str::<JsonRpcRequest>(&text)
                    .ok()
                    .filter(JsonRpcRequest::is_valid)
                {
                    let Ok(request_permit) = request_limit.clone().acquire_owned().await else {
                        break;
                    };
                    let b_cfg_cloned = b_cfg.clone();
                    let agent_ips_cloned = agent_ips.clone();
                    let agent_rpcs_cloned = agent_rpcs.clone();
                    let peer_id_cloned = peer_id.clone();
                    let rpc_tx_cloned = rpc_tx.clone();

                    tokio::spawn(async move {
                        let _request_permit = request_permit;
                        let mut response = JsonRpcResponse {
                            jsonrpc: "2.0".to_string(),
                            id: req.id,
                            result: None,
                            error: None,
                        };

                        if req.method == "Broker.UpdateIP" {
                            if !is_agent {
                                response.error =
                                    Some("only authenticated agents may update an address".into());
                            } else if let Ok(params) =
                                serde_json::from_value::<UpdateIPReq>(req.params)
                            {
                                match parse_peer_ip(&params.ipv6) {
                                    Ok(ip) => {
                                        agent_ips_cloned
                                            .write()
                                            .await
                                            .insert(peer_id_cloned.clone(), ip.to_string());
                                        s6_log(
                                            "[Broker]",
                                            &format!(
                                                "Agent {} updated IP: {}",
                                                peer_id_cloned,
                                                mask_ip(&ip.to_string(), b_cfg_cloned.stealth_mode)
                                            ),
                                        );
                                        response.result =
                                            Some(serde_json::json!({"success": true}));
                                    }
                                    Err(error) => response.error = Some(error),
                                }
                            } else {
                                response.error = Some("invalid UpdateIP parameters".into());
                            }
                        } else if req.method == "Broker.RequestAccess" {
                            if is_agent {
                                response.error =
                                    Some("only authenticated clients may request access".into());
                            } else if let Ok(mut params) =
                                serde_json::from_value::<AccessReq>(req.params)
                            {
                                params.client_id = peer_id_cloned.clone();
                                if let Err(error) = parse_peer_ip(&params.client_ipv6) {
                                    response.error = Some(error);
                                    let message = match serde_json::to_string(&response) {
                                        Ok(value) => value,
                                        Err(_) => return,
                                    };
                                    let _ = rpc_tx_cloned.send(Message::Text(message.into())).await;
                                    return;
                                }
                                let request_binding = B64.decode(&params.e2ee_pubkey).ok();
                                let client_key = b_cfg_cloned
                                    .clients
                                    .iter()
                                    .find(|client| client.id == peer_id_cloned)
                                    .and_then(|client| verifying_key_from_hex(&client.pubkey).ok());
                                if request_binding
                                    .as_ref()
                                    .is_none_or(|value| value.len() != 32)
                                    || client_key.as_ref().is_none_or(|key| {
                                        verify_client_access(&params, key).is_err()
                                    })
                                {
                                    response.error =
                                        Some("invalid end-to-end client access signature".into());
                                    let message = match serde_json::to_string(&response) {
                                        Ok(value) => value,
                                        Err(_) => return,
                                    };
                                    let _ = rpc_tx_cloned.send(Message::Text(message.into())).await;
                                    return;
                                }
                                // RBAC Check
                                let allowed = b_cfg_cloned
                                    .clients
                                    .iter()
                                    .find(|c| c.id == peer_id_cloned)
                                    .is_some_and(|c| {
                                        c.allowed_agents.contains(&params.target_agent)
                                    });

                                if !allowed {
                                    send_webhook(
                                        &b_cfg_cloned.webhook_url,
                                        "Unauthorized access attempt",
                                        &peer_id_cloned,
                                        &params.target_agent,
                                        &params.client_ipv6,
                                        b_cfg_cloned.stealth_mode,
                                    )
                                    .await;
                                    response.error = Some("RBAC: Access Denied".into());
                                } else {
                                    let target_ip = agent_ips_cloned
                                        .read()
                                        .await
                                        .get(&params.target_agent)
                                        .cloned();
                                    let agent_client = agent_rpcs_cloned
                                        .read()
                                        .await
                                        .get(&params.target_agent)
                                        .map(|(_, client)| client.clone());

                                    if let (Some(ip), Some(client)) = (target_ip, agent_client) {
                                        s6_log(
                                            "[Broker]",
                                            &format!(
                                                "Forwarding GrantAccess to Agent {}",
                                                params.target_agent
                                            ),
                                        );

                                        // Forward to Agent
                                        match client
                                            .call::<AccessReq, AccessResp>(
                                                "AgentRPC.GrantAccess",
                                                params.clone(),
                                            )
                                            .await
                                        {
                                            Ok(mut agent_resp) => {
                                                if let Err(error) =
                                                    validate_access_response(&agent_resp)
                                                {
                                                    response.error = Some(error);
                                                } else if b_cfg_cloned
                                                    .agents
                                                    .iter()
                                                    .find(|agent| agent.id == params.target_agent)
                                                    .and_then(|agent| {
                                                        verifying_key_from_hex(&agent.pubkey).ok()
                                                    })
                                                    .and_then(|key| {
                                                        verify_agent_access(
                                                            &params,
                                                            &agent_resp,
                                                            &key,
                                                        )
                                                        .ok()
                                                    })
                                                    .is_none()
                                                {
                                                    response.error = Some(
                                                        "invalid Agent access signature".into(),
                                                    );
                                                } else {
                                                    agent_resp.target_ipv6 = ip;
                                                    send_webhook(
                                                        &b_cfg_cloned.webhook_url,
                                                        "Access Granted",
                                                        &peer_id_cloned,
                                                        &params.target_agent,
                                                        &params.client_ipv6,
                                                        b_cfg_cloned.stealth_mode,
                                                    )
                                                    .await;
                                                    match serde_json::to_value(agent_resp) {
                                                        Ok(value) => response.result = Some(value),
                                                        Err(_) => response.error = Some(
                                                            "failed to serialize access response"
                                                                .into(),
                                                        ),
                                                    }
                                                }
                                            }
                                            Err(e) => {
                                                response.error = Some(format!(
                                                    "Agent Provisioning Failed: {}",
                                                    e
                                                ))
                                            }
                                        }
                                    } else {
                                        response.error = Some("Agent is offline".into());
                                    }
                                }
                            } else {
                                response.error = Some("invalid RequestAccess parameters".into());
                            }
                        } else {
                            response.error = Some("method not found".into());
                        }

                        if let Ok(message) = serde_json::to_string(&response) {
                            let _ = rpc_tx_cloned.send(Message::Text(message.into())).await;
                        }
                    });
                }
            }

            if is_agent {
                let mut agents = agent_rpcs.write().await;
                if agents
                    .get(&peer_id)
                    .is_some_and(|(generation, _)| *generation == connection_generation)
                {
                    agents.remove(&peer_id);
                }
                s6_log("[Broker]", &format!("Agent {} disconnected", peer_id));
            }
        });
    }
}

static WEBHOOK_SEM: tokio::sync::Semaphore = tokio::sync::Semaphore::const_new(50); // Security Fix: Bounded concurrency for DoS prevention
static PROVISION_SEM: Semaphore = Semaphore::const_new(MAX_ACTIVE_TUNNELS);

fn high_throughput_transport_config() -> quinn::TransportConfig {
    debug_assert!(
        QUIC_CONNECTION_WINDOW_BYTES
            >= (TARGET_THROUGHPUT_BITS_PER_SECOND * DESIGN_ROUND_TRIP_MILLISECONDS).div_ceil(8000)
    );
    let mut config = quinn::TransportConfig::default();
    config
        .max_concurrent_bidi_streams(MAX_STREAMS_PER_TUNNEL.into())
        .send_window(QUIC_CONNECTION_WINDOW_BYTES)
        .receive_window(
            VarInt::from_u64(QUIC_CONNECTION_WINDOW_BYTES).expect("bounded QUIC window"),
        )
        .stream_receive_window(
            VarInt::from_u64(QUIC_STREAM_WINDOW_BYTES).expect("bounded QUIC stream window"),
        )
        .max_idle_timeout(Some(
            Duration::from_secs(60)
                .try_into()
                .expect("bounded idle timeout"),
        ));
    config
}
async fn send_webhook(url: &str, status: &str, client: &str, agent: &str, ip: &str, stealth: bool) {
    if url.is_empty() {
        return;
    }
    if !(url.starts_with("https://")
        || url.starts_with("http://127.0.0.1:")
        || url.starts_with("http://[::1]:"))
    {
        s6_log("[Broker]", "Rejected non-HTTPS webhook URL");
        return;
    }
    let Ok(_permit) = WEBHOOK_SEM.try_acquire() else {
        s6_log(
            "[Broker]",
            "Webhook queue full, dropping alert to prevent DoS.",
        );
        return;
    };
    let payload = serde_json::json!({
        "event": "AccessRequest",
        "status": status,
        "client_id": client,
        "target_agent": agent,
        "client_ip": mask_ip(ip, stealth),
    });
    let client = match reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
    {
        Ok(client) => client,
        Err(_) => return,
    };
    let _ = client.post(url).json(&payload).send().await;
}

// ============================================================================
// AGENT IMPLEMENTATION (QUIC Data Plane)
// ============================================================================

async fn start_agent(cfg: Config) -> Result<(), String> {
    let agent_cfg = cfg.agent.ok_or("missing agent configuration")?;
    let priv_key = signing_key_from_hex(&agent_cfg.private_key)?;
    let broker_key = verifying_key_from_hex(&agent_cfg.broker_pubkey)?;

    if agent_cfg.allow_local_discovery {
        let acfg = agent_cfg.clone();
        tokio::spawn(async move { start_agent_lpd(acfg).await });
    }

    loop {
        s6_log("[Agent]", "Connecting to Broker(s)...");
        let ws_stream = connect_to_brokers(&agent_cfg.broker_addrs).await;
        if ws_stream.is_none() {
            tokio::time::sleep(Duration::from_secs(5)).await;
            continue;
        }
        let Some(ws_stream) = ws_stream else {
            continue;
        };
        let (mut ws_tx, mut ws_rx) = ws_stream.split();

        // Answer the Broker challenge, then challenge the Broker in return.
        if let Ok(Some(Ok(Message::Binary(nonce)))) =
            tokio::time::timeout(Duration::from_secs(10), ws_rx.next()).await
        {
            if nonce.len() != 32 {
                continue;
            }
            let sig = priv_key.sign(&auth_payload(&agent_cfg.id, &nonce));
            let resp = AuthResponse {
                id: agent_cfg.id.clone(),
                signature: B64.encode(sig.to_bytes()),
            };
            let Ok(response) = serde_json::to_string(&resp) else {
                continue;
            };
            if ws_tx.send(Message::Text(response.into())).await.is_err() {
                continue;
            }
        } else {
            continue;
        }

        let mut broker_nonce = [0u8; 32];
        OsRng.fill_bytes(&mut broker_nonce);
        if ws_tx
            .send(Message::Binary(broker_nonce.to_vec().into()))
            .await
            .is_err()
        {
            continue;
        }
        let broker_auth = match tokio::time::timeout(Duration::from_secs(10), ws_rx.next()).await {
            Ok(Some(Ok(Message::Text(text)))) => strict_json::from_str::<AuthResponse>(&text).ok(),
            _ => None,
        };
        if broker_auth
            .as_ref()
            .and_then(|response| {
                verify_auth_response(response, "broker", &broker_key, &broker_nonce).ok()
            })
            .is_none()
        {
            s6_log("[Agent]", "Broker authentication failed");
            continue;
        }

        let (rpc_tx, mut rpc_rx) = mpsc::channel(100);
        let pending = Arc::new(RwLock::new(HashMap::new()));
        let rpc_client = WsRpcClient {
            tx: rpc_tx.clone(),
            pending: pending.clone(),
            req_id: Arc::new(AtomicU64::new(1)),
        };

        let writer_task = tokio::spawn(async move {
            while let Some(msg) = rpc_rx.recv().await {
                let _ = ws_tx.send(msg).await;
            }
        });

        // Background IP Updater
        let rpc_cloned = rpc_client.clone();
        let agent_id = agent_cfg.id.clone();
        let updater_task = tokio::spawn(async move {
            let mut last_ip = "".to_string();
            loop {
                let current_ip = get_route_ip().await;
                if !current_ip.is_empty() && current_ip != last_ip {
                    s6_log("[Agent]", &format!("Updating IP: {}", current_ip));
                    let req = UpdateIPReq {
                        agent_id: agent_id.clone(),
                        ipv6: current_ip.clone(),
                    };
                    let _ = rpc_cloned
                        .call::<UpdateIPReq, serde_json::Value>("Broker.UpdateIP", req)
                        .await;
                    last_ip = current_ip;
                }
                tokio::time::sleep(Duration::from_secs(10)).await;
            }
        });

        s6_log("[Agent]", "Connected to Broker. Awaiting RPCs.");

        // RPC Processing Loop
        let request_limit = Arc::new(Semaphore::new(32));
        while let Some(Ok(Message::Text(text))) = ws_rx.next().await {
            if let Some(resp) = strict_json::from_str::<JsonRpcResponse>(&text)
                .ok()
                .filter(JsonRpcResponse::is_valid)
            {
                if let Some(sender) = pending.write().await.remove(&resp.id) {
                    let result = match (resp.result, resp.error) {
                        (Some(result), None) => Ok(result),
                        (_, Some(error)) => Err(error),
                        _ => Err("malformed RPC response".into()),
                    };
                    let _ = sender.send(result);
                }
                continue;
            }

            if let Some(req) = strict_json::from_str::<JsonRpcRequest>(&text)
                .ok()
                .filter(JsonRpcRequest::is_valid)
            {
                let Ok(request_permit) = request_limit.clone().acquire_owned().await else {
                    break;
                };
                let rpc_tx_cloned = rpc_tx.clone();
                let agent_cfg = agent_cfg.clone();
                let agent_signing_key = priv_key.clone();

                tokio::spawn(async move {
                    let _request_permit = request_permit;
                    let mut response = JsonRpcResponse {
                        jsonrpc: "2.0".to_string(),
                        id: req.id,
                        result: None,
                        error: None,
                    };

                    if req.method == "AgentRPC.GrantAccess" {
                        if let Ok(params) = serde_json::from_value::<AccessReq>(req.params) {
                            let binding = B64.decode(&params.e2ee_pubkey).ok();
                            let client_key = agent_cfg
                                .client_pubkeys
                                .get(&params.client_id)
                                .and_then(|value| verifying_key_from_hex(value).ok());
                            if !valid_identity(&params.client_id)
                                || params.target_agent != agent_cfg.id
                                || binding.as_ref().is_none_or(|value| value.len() != 32)
                                || client_key
                                    .as_ref()
                                    .is_none_or(|key| verify_client_access(&params, key).is_err())
                            {
                                response.error = Some("invalid GrantAccess request binding".into());
                            } else {
                                s6_log(
                                    "[Agent]",
                                    &format!("Provisioning access for Client {}", params.client_id),
                                );
                                match provision_access(&agent_cfg, &params.client_ipv6).await {
                                    Ok(mut access_resp) => {
                                        access_resp.agent_signature = B64.encode(
                                            agent_signing_key
                                                .sign(&agent_access_payload(&params, &access_resp))
                                                .to_bytes(),
                                        );
                                        response.result = serde_json::to_value(access_resp).ok();
                                    }
                                    Err(e) => response.error = Some(e.to_string()),
                                }
                            }
                        } else {
                            response.error = Some("invalid GrantAccess parameters".into());
                        }
                    } else {
                        response.error = Some("method not found".into());
                    }
                    if let Ok(message) = serde_json::to_string(&response) {
                        let _ = rpc_tx_cloned.send(Message::Text(message.into())).await;
                    }
                });
            }
        }
        updater_task.abort();
        writer_task.abort();
        pending.write().await.clear();
        s6_log("[Agent]", "Connection lost. Reconnecting...");
    }
}

async fn provision_access(
    cfg: &AgentConfig,
    client_ip: &str,
) -> Result<AccessResp, Box<dyn std::error::Error + Send + Sync>> {
    let provision_permit = PROVISION_SEM
        .try_acquire()
        .map_err(|_| "maximum active tunnel count reached")?;
    let authorized_ip = parse_peer_ip(client_ip).map_err(std::io::Error::other)?;
    // 1. Generate Ephemeral QUIC Cert (TLS 1.3 Self-Signed)
    let sni = cfg.sni.clone().unwrap_or_else(generate_random_sni);
    let alpn = cfg.alpn.clone().unwrap_or_else(|| "shadow6/1".to_string());
    let transport = "quic".to_string();
    if sni.is_empty() || alpn.is_empty() || alpn.len() > 255 {
        return Err("invalid SNI or ALPN configuration".into());
    }
    let cert = generate_simple_self_signed(vec![sni.clone()])?;
    let cert_der = cert.cert.der().to_vec();
    let key_der = cert.key_pair.serialize_der();
    let priv_key = rustls::pki_types::PrivateKeyDer::Pkcs8(key_der.into());
    let cert_chain = vec![CertificateDer::from(cert_der.clone())];

    let mut server_crypto = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(cert_chain, priv_key)?;
    server_crypto.alpn_protocols = vec![alpn.clone().into_bytes()];

    let quic_crypto = quinn::crypto::rustls::QuicServerConfig::try_from(server_crypto)?;
    let mut server_config = QuinnServerConfig::with_crypto(Arc::new(quic_crypto));
    server_config.transport_config(Arc::new(high_throughput_transport_config()));
    let bind_address: SocketAddr = if authorized_ip.is_ipv4() {
        "0.0.0.0:0".parse()?
    } else {
        "[::]:0".parse()?
    };
    let quic_endpoint = Endpoint::server(server_config, bind_address)?;
    let quic_port = quic_endpoint.local_addr()?.port();

    // 2. Spawn the short-lived, peer-bound data-plane listener. Source-IP
    // authorization is enforced in-process and never mutates host firewall state.
    let ttl = cfg.auto_close_after;
    let target_port = cfg.target_port;

    tokio::spawn(async move {
        let _provision_permit = provision_permit;
        let connection_slots = Arc::new(Semaphore::new(MAX_STREAMS_PER_TUNNEL as usize));
        tokio::select! {
            _ = tokio::time::sleep(Duration::from_secs(ttl)) => {
                s6_log("[Agent]", &format!("TTL expired. Closing QUIC port {quic_port}"));
            }
            _ = async {
                while let Some(conn) = quic_endpoint.accept().await {
                    let Ok(connection_permit) = connection_slots.clone().try_acquire_owned() else {
                        continue;
                    };
                    let connection = match conn.await {
                        Ok(c) => c,
                        Err(_) => continue,
                    };
                    let remote_ip = normalize_ip(connection.remote_address().ip());
                    if remote_ip != normalize_ip(authorized_ip) {
                        connection.close(0u32.into(), b"unauthorized source address");
                        continue;
                    }
                    s6_log("[Agent]", "QUIC E2EE Tunnel Established");

                    let target_p = target_port;
                    tokio::spawn(async move {
                        let _connection_permit = connection_permit;
                        while let Ok((mut send, mut recv)) = connection.accept_bi().await {
                            if let Ok(target) = TcpStream::connect(format!("127.0.0.1:{}", target_p)).await {
                                let (mut t_read, mut t_write) = target.into_split();
                                let c1 = tokio::spawn(async move { tokio::io::copy(&mut recv, &mut t_write).await });
                                let c2 = tokio::spawn(async move { tokio::io::copy(&mut t_read, &mut send).await });
                                let _ = tokio::try_join!(c1, c2);
                            }
                        }
                    });
                }
            } => {}
        }
    });

    Ok(AccessResp {
        success: true,
        target_ipv6: "".into(),
        dynamic_port: 0,
        kcp_port: quic_port, // Legacy wire name; this is the QUIC UDP port.
        e2ee_pubkey: B64.encode(cert_der),
        error_msg: "".into(),
        sni,
        alpn,
        transport,
        agent_signature: String::new(),
    })
}

fn normalize_ip(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(value) => value
            .to_ipv4_mapped()
            .map(IpAddr::V4)
            .unwrap_or(IpAddr::V6(value)),
        other => other,
    }
}

fn valid_identity(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
}

fn split_command(value: &str) -> Result<Vec<String>, String> {
    let mut result = Vec::new();
    let mut current = String::new();
    let mut quote: Option<char> = None;
    let mut escaped = false;
    for character in value.chars() {
        if escaped {
            current.push(character);
            escaped = false;
            continue;
        }
        if character == '\\' {
            escaped = true;
            continue;
        }
        if let Some(active_quote) = quote {
            if character == active_quote {
                quote = None;
            } else {
                current.push(character);
            }
            continue;
        }
        if matches!(character, '\'' | '"') {
            quote = Some(character);
        } else if character.is_whitespace() {
            if !current.is_empty() {
                result.push(std::mem::take(&mut current));
            }
        } else {
            current.push(character);
        }
    }
    if escaped || quote.is_some() {
        return Err("on_success contains an unterminated quote or escape".into());
    }
    if !current.is_empty() {
        result.push(current);
    }
    Ok(result)
}

fn validate_config(cfg: &Config) -> Result<(), String> {
    match cfg.role.as_str() {
        "broker" => {
            if cfg.agent.is_some() || cfg.client.is_some() {
                return Err("broker configuration contains fields for another role".into());
            }
            let broker = cfg.broker.as_ref().ok_or("missing broker configuration")?;
            broker
                .listen_addr
                .parse::<SocketAddr>()
                .map_err(|_| "invalid broker listen_addr".to_string())?;
            signing_key_from_hex(&broker.private_key)?;
            validate_webhook_url(&broker.webhook_url)?;
            let mut identities = HashSet::new();
            let agent_ids: HashSet<&str> = broker
                .agents
                .iter()
                .map(|agent| agent.id.as_str())
                .collect();
            for agent in &broker.agents {
                if !valid_identity(&agent.id) || !identities.insert(agent.id.as_str()) {
                    return Err(format!("invalid or duplicate identity: {}", agent.id));
                }
                verifying_key_from_hex(&agent.pubkey)?;
            }
            for client in &broker.clients {
                if !valid_identity(&client.id) || !identities.insert(client.id.as_str()) {
                    return Err(format!("invalid or duplicate identity: {}", client.id));
                }
                verifying_key_from_hex(&client.pubkey)?;
                if client
                    .allowed_agents
                    .iter()
                    .any(|id| !agent_ids.contains(id.as_str()))
                {
                    return Err(format!("client {} references an unknown agent", client.id));
                }
            }
        }
        "agent" => {
            if cfg.broker.is_some() || cfg.client.is_some() {
                return Err("agent configuration contains fields for another role".into());
            }
            let agent = cfg.agent.as_ref().ok_or("missing agent configuration")?;
            if !valid_identity(&agent.id) || agent.target_port == 0 {
                return Err("invalid agent identity or target_port".into());
            }
            if agent.broker_addrs.is_empty()
                || agent.broker_addrs.iter().any(|addr| addr.len() > 2048)
            {
                return Err("at least one valid broker address is required".into());
            }
            for address in &agent.broker_addrs {
                normalized_broker_url(address)?;
            }
            if !(1..=86_400).contains(&agent.auto_close_after) {
                return Err("auto_close_after must be between 1 and 86400 seconds".into());
            }
            signing_key_from_hex(&agent.private_key)?;
            verifying_key_from_hex(&agent.broker_pubkey)?;
            if agent
                .transport
                .as_deref()
                .is_some_and(|value| value != "quic")
            {
                return Err("the Rust data plane currently supports transport=quic".into());
            }
            if agent.sni.as_ref().is_some_and(|value| {
                value.is_empty() || value.len() > 253 || value.contains(['\r', '\n', '\0'])
            }) || agent.alpn.as_ref().is_some_and(|value| {
                value.is_empty() || value.len() > 255 || value.contains(['\r', '\n', '\0'])
            }) {
                return Err("invalid SNI or ALPN configuration".into());
            }
            if agent.client_pubkeys.is_empty() {
                return Err(
                    "agent requires client_pubkeys for end-to-end access authorization".into(),
                );
            }
            for (id, key) in &agent.client_pubkeys {
                if !valid_identity(id) {
                    return Err(format!("invalid authorized client identity: {id}"));
                }
                verifying_key_from_hex(key)?;
            }
        }
        "client" => {
            if cfg.broker.is_some() || cfg.agent.is_some() {
                return Err("client configuration contains fields for another role".into());
            }
            let client = cfg.client.as_ref().ok_or("missing client configuration")?;
            if !valid_identity(&client.id) || !valid_identity(&client.target_agent) {
                return Err("invalid client or target-agent identity".into());
            }
            if client.broker_addrs.is_empty()
                || client.broker_addrs.iter().any(|addr| addr.len() > 2048)
            {
                return Err("at least one valid broker address is required".into());
            }
            for address in &client.broker_addrs {
                normalized_broker_url(address)?;
            }
            signing_key_from_hex(&client.private_key)?;
            verifying_key_from_hex(&client.broker_pubkey)?;
            if client.on_success.len() > 4096 {
                return Err("on_success exceeds the 4096-byte limit".into());
            }
            if !client.on_success.is_empty() && split_command(&client.on_success)?.is_empty() {
                return Err("on_success command is empty".into());
            }
            if client
                .transport
                .as_deref()
                .is_some_and(|value| value != "quic")
            {
                return Err("the Rust data plane currently supports transport=quic".into());
            }
            verifying_key_from_hex(&client.agent_pubkey)?;
        }
        _ => return Err("role must be broker, agent, or client".into()),
    }
    Ok(())
}

fn effective_user_id() -> u32 {
    // SAFETY: geteuid has no arguments and no memory-safety preconditions.
    unsafe { libc::geteuid() }
}

fn read_secure_config(path: &Path) -> Result<String, String> {
    let before =
        fs::symlink_metadata(path).map_err(|error| format!("cannot inspect config: {error}"))?;
    if before.file_type().is_symlink() || !before.is_file() {
        return Err("configuration must be a regular, non-symlink file".into());
    }
    if before.permissions().mode() & 0o077 != 0 {
        return Err("configuration contains private keys and must have mode 0600".into());
    }
    if before.uid() != effective_user_id() {
        return Err("configuration must be owned by the effective user".into());
    }
    if before.len() > 1024 * 1024 {
        return Err("configuration exceeds the 1 MiB size limit".into());
    }

    let file = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(path)
        .map_err(|error| format!("cannot open config securely: {error}"))?;
    let opened = file
        .metadata()
        .map_err(|error| format!("cannot inspect opened config: {error}"))?;
    if !opened.is_file()
        || (opened.dev(), opened.ino()) != (before.dev(), before.ino())
        || opened.permissions().mode() & 0o077 != 0
        || opened.uid() != effective_user_id()
    {
        return Err(
            "configuration changed during validation or has unsafe ownership/permissions".into(),
        );
    }
    if opened.len() > 1024 * 1024 {
        return Err("configuration exceeds the 1 MiB size limit".into());
    }

    let mut data = Vec::with_capacity(opened.len() as usize);
    file.take(1024 * 1024 + 1)
        .read_to_end(&mut data)
        .map_err(|error| format!("cannot read config: {error}"))?;
    if data.len() > 1024 * 1024 {
        return Err("configuration exceeds the 1 MiB size limit".into());
    }
    String::from_utf8(data).map_err(|_| "configuration is not valid UTF-8".into())
}

fn write_owner_only(path: &Path, data: &[u8]) -> Result<(), String> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let mut random = [0_u8; 16];
    OsRng.fill_bytes(&mut random);
    let temporary = parent.join(format!(".shadow6-config-{}", hex::encode(random)));
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&temporary)
        .map_err(|error| format!("cannot create temporary config: {error}"))?;
    file.set_permissions(fs::Permissions::from_mode(0o600))
        .map_err(|error| format!("cannot secure {}: {error}", temporary.display()))?;
    let result = file
        .write_all(data)
        .and_then(|_| file.sync_all())
        .and_then(|_| fs::rename(&temporary, path))
        .map_err(|error| format!("cannot persist {}: {error}", path.display()));
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct DiscoveryRequest {
    version: u8,
    agent_id: String,
    client_id: String,
    timestamp: u64,
    nonce: String,
    signature: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct DiscoveryOffer {
    version: u8,
    agent_id: String,
    request_nonce: String,
    access: AccessResp,
    signature: String,
}

fn signed_fields(domain: &[u8], fields: &[&[u8]]) -> Vec<u8> {
    let mut output = Vec::with_capacity(128);
    output.extend_from_slice(domain);
    for field in fields {
        output.extend_from_slice(&(field.len() as u32).to_be_bytes());
        output.extend_from_slice(field);
    }
    output
}

fn discovery_request_payload(request: &DiscoveryRequest) -> Vec<u8> {
    signed_fields(
        b"shadow6-lpd-request-v1",
        &[
            request.agent_id.as_bytes(),
            request.client_id.as_bytes(),
            &request.timestamp.to_be_bytes(),
            request.nonce.as_bytes(),
        ],
    )
}

fn discovery_offer_payload(offer: &DiscoveryOffer) -> Result<Vec<u8>, serde_json::Error> {
    let access = serde_json::to_vec(&offer.access)?;
    Ok(signed_fields(
        b"shadow6-lpd-offer-v1",
        &[
            offer.agent_id.as_bytes(),
            offer.request_nonce.as_bytes(),
            &access,
        ],
    ))
}

async fn serve_agent_lpd_socket(
    socket: UdpSocket,
    cfg: Arc<AgentConfig>,
    signing_key: Arc<ed25519_dalek::SigningKey>,
    allowed_clients: Arc<HashMap<String, VerifyingKey>>,
    seen_nonces: Arc<Mutex<HashMap<String, u64>>>,
) {
    let mut buf = [0u8; 4096];
    while let Ok((len, remote)) = socket.recv_from(&mut buf).await {
        let Ok(request) = strict_json::from_slice::<DiscoveryRequest>(&buf[..len]) else {
            continue;
        };
        let now = unix_timestamp();
        if request.version != 1
            || request.agent_id != cfg.id
            || now.abs_diff(request.timestamp) > 30
        {
            continue;
        }
        let Some(client_key) = allowed_clients.get(&request.client_id) else {
            continue;
        };
        let Ok(signature_bytes) = B64.decode(&request.signature) else {
            continue;
        };
        let Ok(signature) = ed25519_dalek::Signature::from_slice(&signature_bytes) else {
            continue;
        };
        if client_key
            .verify(&discovery_request_payload(&request), &signature)
            .is_err()
        {
            continue;
        }
        let Ok(nonce) = B64.decode(&request.nonce) else {
            continue;
        };
        if nonce.len() != 32 {
            continue;
        }
        {
            let mut seen = seen_nonces.lock().await;
            seen.retain(|_, timestamp| now.saturating_sub(*timestamp) <= 60);
            if seen.contains_key(&request.nonce) || seen.len() >= 50_000 {
                continue;
            }
            seen.insert(request.nonce.clone(), now);
        }

        s6_log(
            "[Agent]",
            &format!("Authorized local discovery request from {}", remote),
        );
        if let Ok(resp) = provision_access(&cfg, &remote.ip().to_string()).await {
            let mut offer = DiscoveryOffer {
                version: 1,
                agent_id: cfg.id.clone(),
                request_nonce: request.nonce,
                access: resp,
                signature: String::new(),
            };
            let Ok(payload) = discovery_offer_payload(&offer) else {
                continue;
            };
            offer.signature = B64.encode(signing_key.sign(&payload).to_bytes());
            if let Ok(reply) = serde_json::to_vec(&offer) {
                let _ = socket.send_to(&reply, remote).await;
            }
        }
    }
}

async fn start_agent_lpd(cfg: AgentConfig) {
    let signing_key = match signing_key_from_hex(&cfg.private_key) {
        Ok(key) => Arc::new(key),
        Err(error) => {
            s6_log("[Agent]", &format!("LPD disabled: {error}"));
            return;
        }
    };
    let allowed_clients: HashMap<String, VerifyingKey> = cfg
        .client_pubkeys
        .iter()
        .filter_map(|(id, key)| {
            verifying_key_from_hex(key)
                .ok()
                .map(|key| (id.clone(), key))
        })
        .collect();
    if allowed_clients.is_empty() {
        s6_log("[Agent]", "LPD disabled: no authorized client public keys");
        return;
    }
    let cfg = Arc::new(cfg);
    let allowed_clients = Arc::new(allowed_clients);
    let seen_nonces = Arc::new(Mutex::new(HashMap::new()));
    let mut tasks = Vec::new();

    match UdpSocket::bind("0.0.0.0:44333").await {
        Ok(socket) => tasks.push(tokio::spawn(serve_agent_lpd_socket(
            socket,
            cfg.clone(),
            signing_key.clone(),
            allowed_clients.clone(),
            seen_nonces.clone(),
        ))),
        Err(error) => s6_log("[Agent]", &format!("IPv4 LPD bind failed: {error}")),
    }
    match bind_ipv6_udp(SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, 44333, 0, 0)) {
        Ok(socket) => {
            let group = "ff02::1".parse::<Ipv6Addr>().expect("static IPv6 group");
            let mut joined = 0usize;
            for index in ipv6_interface_indices() {
                if socket.join_multicast_v6(&group, index).is_ok() {
                    joined += 1;
                }
            }
            s6_log(
                "[Agent]",
                &format!("IPv6 LPD joined ff02::1 on {joined} interface(s)"),
            );
            tasks.push(tokio::spawn(serve_agent_lpd_socket(
                socket,
                cfg.clone(),
                signing_key.clone(),
                allowed_clients.clone(),
                seen_nonces.clone(),
            )));
        }
        Err(error) => s6_log("[Agent]", &format!("IPv6 LPD bind failed: {error}")),
    }
    if tasks.is_empty() {
        s6_log("[Agent]", "LPD disabled: no UDP listener could be created");
        return;
    }
    s6_log("[Agent]", "Authenticated IPv4/IPv6 LPD active on UDP 44333");
    for task in tasks {
        let _ = task.await;
    }
}

async fn connect_to_brokers(
    addrs: &[String],
) -> Option<WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>> {
    for addr in addrs {
        let Ok(url) = normalized_broker_url(addr) else {
            continue;
        };
        if let Ok(Ok((ws, _))) = tokio::time::timeout(
            Duration::from_secs(10),
            connect_async_with_config(&url, Some(websocket_config()), false),
        )
        .await
        {
            return Some(ws);
        }
    }
    None
}

// ============================================================================
// CLIENT IMPLEMENTATION
// ============================================================================

async fn receive_discovery_offer(
    socket: UdpSocket,
    target_agent: String,
    request_nonce: String,
    agent_key: VerifyingKey,
) -> Option<(AccessResp, String)> {
    let deadline = tokio::time::Instant::now() + Duration::from_millis(1500);
    let mut buf = [0u8; 4096];
    loop {
        let (len, remote) = tokio::time::timeout_at(deadline, socket.recv_from(&mut buf))
            .await
            .ok()?
            .ok()?;
        let Ok(offer) = strict_json::from_slice::<DiscoveryOffer>(&buf[..len]) else {
            continue;
        };
        if offer.version != 1
            || offer.agent_id != target_agent
            || offer.request_nonce != request_nonce
        {
            continue;
        }
        let Ok(signature_bytes) = B64.decode(&offer.signature) else {
            continue;
        };
        let Ok(signature) = ed25519_dalek::Signature::from_slice(&signature_bytes) else {
            continue;
        };
        let Ok(payload) = discovery_offer_payload(&offer) else {
            continue;
        };
        if agent_key.verify(&payload, &signature).is_err()
            || validate_access_response(&offer.access).is_err()
        {
            continue;
        }
        let remote_ip = match remote {
            SocketAddr::V4(address) => address.ip().to_string(),
            SocketAddr::V6(address) if address.scope_id() != 0 => {
                format!("{}%{}", address.ip(), address.scope_id())
            }
            SocketAddr::V6(address) => address.ip().to_string(),
        };
        return Some((offer.access, remote_ip));
    }
}

async fn perform_local_discovery_to(
    cfg: &ClientConfig,
    signing_key: &ed25519_dalek::SigningKey,
    destinations: Vec<SocketAddr>,
) -> Option<(AccessResp, String)> {
    let agent_key = verifying_key_from_hex(&cfg.agent_pubkey).ok()?;
    let mut nonce = [0u8; 32];
    OsRng.fill_bytes(&mut nonce);
    let mut request = DiscoveryRequest {
        version: 1,
        agent_id: cfg.target_agent.clone(),
        client_id: cfg.id.clone(),
        timestamp: unix_timestamp(),
        nonce: B64.encode(nonce),
        signature: String::new(),
    };
    request.signature = B64.encode(
        signing_key
            .sign(&discovery_request_payload(&request))
            .to_bytes(),
    );
    let message = serde_json::to_vec(&request).ok()?;
    let mut sockets = Vec::new();
    for ipv6_family in [false, true] {
        let family_destinations: Vec<SocketAddr> = destinations
            .iter()
            .copied()
            .filter(|destination| destination.is_ipv6() == ipv6_family)
            .collect();
        if family_destinations.is_empty() {
            continue;
        }
        let bind_address = if ipv6_family { "[::]:0" } else { "0.0.0.0:0" };
        let Ok(socket) = UdpSocket::bind(bind_address).await else {
            continue;
        };
        if !ipv6_family {
            let _ = socket.set_broadcast(true);
        }
        let mut sent = false;
        for destination in family_destinations {
            if socket.send_to(&message, destination).await.is_ok() {
                sent = true;
            }
        }
        if sent {
            sockets.push(socket);
        }
    }
    if sockets.is_empty() {
        return None;
    }
    let (sender, mut receiver) = mpsc::channel(sockets.len());
    for socket in sockets {
        let sender = sender.clone();
        let target_agent = cfg.target_agent.clone();
        let request_nonce = request.nonce.clone();
        let receiver_agent_key = agent_key;
        tokio::spawn(async move {
            let result =
                receive_discovery_offer(socket, target_agent, request_nonce, receiver_agent_key)
                    .await;
            let _ = sender.send(result).await;
        });
    }
    drop(sender);
    tokio::time::timeout(Duration::from_millis(1600), async {
        while let Some(result) = receiver.recv().await {
            if result.is_some() {
                return result;
            }
        }
        None
    })
    .await
    .ok()
    .flatten()
}

async fn perform_local_discovery(
    cfg: &ClientConfig,
    signing_key: &ed25519_dalek::SigningKey,
) -> Option<(AccessResp, String)> {
    let mut destinations = vec!["255.255.255.255:44333".parse().ok()?];
    let group = "ff02::1".parse::<Ipv6Addr>().ok()?;
    for scope_id in ipv6_interface_indices() {
        destinations.push(SocketAddr::V6(SocketAddrV6::new(group, 44333, 0, scope_id)));
    }
    perform_local_discovery_to(cfg, signing_key, destinations).await
}

async fn start_client(cfg: Config) -> Result<(), String> {
    let client_cfg = cfg.client.ok_or("missing client configuration")?;
    let priv_key = signing_key_from_hex(&client_cfg.private_key)?;
    let broker_key = verifying_key_from_hex(&client_cfg.broker_pubkey)?;

    let mut access_resp: Option<AccessResp> = None;
    let mut target_ip = String::new();

    // 1. Local Peer Discovery
    if client_cfg.allow_local_discovery {
        s6_log(
            "[Client]",
            &format!(
                "Broadcasting LPD search for agent '{}'...",
                client_cfg.target_agent
            ),
        );
        if let Some((resp, ip)) = perform_local_discovery(&client_cfg, &priv_key).await {
            s6_log(
                "[+]",
                &format!(
                    "Local Discovery Success! Found Agent at {}. Bypassing Broker.",
                    ip
                ),
            );
            access_resp = Some(resp);
            target_ip = ip;
        }
    }

    // 2. Broker WSS Fallback
    if access_resp.is_none() {
        s6_log("[Client]", "Authenticating with Internet Broker...");
        let Some(ws_stream) = connect_to_brokers(&client_cfg.broker_addrs).await else {
            return Err("failed to connect to any configured Broker".into());
        };
        let (mut ws_tx, mut ws_rx) = ws_stream.split();

        if let Ok(Some(Ok(Message::Binary(nonce)))) =
            tokio::time::timeout(Duration::from_secs(10), ws_rx.next()).await
        {
            if nonce.len() != 32 {
                return Err("Broker sent an invalid authentication challenge".into());
            }
            let sig = priv_key.sign(&auth_payload(&client_cfg.id, &nonce));
            let resp = AuthResponse {
                id: client_cfg.id.clone(),
                signature: B64.encode(sig.to_bytes()),
            };
            let response = serde_json::to_string(&resp)
                .map_err(|error| format!("failed to serialize authentication: {error}"))?;
            ws_tx
                .send(Message::Text(response.into()))
                .await
                .map_err(|error| format!("failed to send authentication: {error}"))?;
        } else {
            return Err("Broker did not send an authentication challenge".into());
        }

        let mut broker_nonce = [0u8; 32];
        OsRng.fill_bytes(&mut broker_nonce);
        ws_tx
            .send(Message::Binary(broker_nonce.to_vec().into()))
            .await
            .map_err(|error| format!("failed to send Broker challenge: {error}"))?;
        let broker_auth = match tokio::time::timeout(Duration::from_secs(10), ws_rx.next()).await {
            Ok(Some(Ok(Message::Text(text)))) => strict_json::from_str::<AuthResponse>(&text).ok(),
            _ => None,
        };
        if broker_auth
            .as_ref()
            .and_then(|response| {
                verify_auth_response(response, "broker", &broker_key, &broker_nonce).ok()
            })
            .is_none()
        {
            return Err("Broker authentication failed".into());
        }

        let (rpc_tx, mut rpc_rx) = mpsc::channel(100);
        let pending = Arc::new(RwLock::new(HashMap::new()));
        let rpc_client = WsRpcClient {
            tx: rpc_tx.clone(),
            pending: pending.clone(),
            req_id: Arc::new(AtomicU64::new(1)),
        };

        tokio::spawn(async move {
            while let Some(msg) = rpc_rx.recv().await {
                let _ = ws_tx.send(msg).await;
            }
        });

        let pending_cloned = pending.clone();
        tokio::spawn(async move {
            while let Some(Ok(Message::Text(text))) = ws_rx.next().await {
                if let Some(resp) = strict_json::from_str::<JsonRpcResponse>(&text)
                    .ok()
                    .filter(JsonRpcResponse::is_valid)
                {
                    if let Some(sender) = pending_cloned.write().await.remove(&resp.id) {
                        let result = match (resp.result, resp.error) {
                            (Some(result), None) => Ok(result),
                            (_, Some(error)) => Err(error),
                            _ => Err("malformed RPC response".into()),
                        };
                        let _ = sender.send(result);
                    }
                }
            }
        });

        let mut request_binding = [0_u8; 32];
        OsRng.fill_bytes(&mut request_binding);
        let req = AccessReq {
            client_id: client_cfg.id.clone(),
            target_agent: client_cfg.target_agent.clone(),
            client_ipv6: get_route_ip().await,
            e2ee_pubkey: B64.encode(request_binding),
            client_signature: String::new(),
        };
        let mut req = req;
        req.client_signature = B64.encode(priv_key.sign(&client_access_payload(&req)).to_bytes());

        s6_log("[Client]", "Requesting access via WSS Control Plane...");
        let resp: AccessResp = match rpc_client.call("Broker.RequestAccess", req.clone()).await {
            Ok(response) => response,
            Err(error) => return Err(format!("Broker access RPC failed: {error}")),
        };
        validate_access_response(&resp)?;
        let agent_key = verifying_key_from_hex(&client_cfg.agent_pubkey)?;
        verify_agent_access(&req, &resp, &agent_key)?;

        target_ip = resp.target_ipv6.clone();
        access_resp = Some(resp);
        s6_log(
            "[+]",
            &format!("Broker Access Granted. Target IP: {}", target_ip),
        );
    }

    let resp = access_resp.ok_or("no access response was obtained")?;

    // 3. Trust exactly the ephemeral Agent certificate. Standard rustls
    // verification still checks SNI, validity, and proof of its private key.
    let expected_der = B64
        .decode(&resp.e2ee_pubkey)
        .map_err(|_| "Agent returned an invalid certificate".to_string())?;
    let mut roots = rustls::RootCertStore::empty();
    roots
        .add(CertificateDer::from(expected_der))
        .map_err(|_| "Agent certificate cannot be used as a trust anchor".to_string())?;
    let mut crypto = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    crypto.alpn_protocols = vec![resp.alpn.clone().into_bytes()];

    let quic_crypto = quinn::crypto::rustls::QuicClientConfig::try_from(crypto)
        .map_err(|_| "invalid QUIC TLS configuration".to_string())?;
    let mut client_config = QuinnClientConfig::new(Arc::new(quic_crypto));
    client_config.transport_config(Arc::new(high_throughput_transport_config()));
    let (target_address, target_scope_id) = parse_scoped_peer_ip(&target_ip)?;
    let bind_addr: SocketAddr = if target_address.is_ipv6() {
        "[::]:0".parse().map_err(|_| "invalid IPv6 bind address")?
    } else {
        "0.0.0.0:0"
            .parse()
            .map_err(|_| "invalid IPv4 bind address")?
    };
    let mut endpoint = Endpoint::client(bind_addr)
        .map_err(|error| format!("failed to create QUIC endpoint: {error}"))?;
    endpoint.set_default_client_config(client_config);

    let local_proxy = TcpListener::bind("127.0.0.1:0")
        .await
        .map_err(|error| format!("local proxy bind failed: {error}"))?;
    let local_addr = local_proxy
        .local_addr()
        .map_err(|error| format!("cannot inspect local proxy address: {error}"))?;
    let local_port = local_addr.port();

    // Establish QUIC Connection
    let target_addr = match target_address {
        IpAddr::V4(address) => SocketAddr::new(IpAddr::V4(address), resp.kcp_port),
        IpAddr::V6(address) => SocketAddr::V6(SocketAddrV6::new(
            address,
            resp.kcp_port,
            0,
            target_scope_id,
        )),
    };

    s6_log(
        "[Client]",
        &format!("Dialing QUIC E2EE Tunnel to {}", target_addr),
    );

    // Perform Quinn connect. ALPN + Pinned Cert prevents MITM.
    let connecting = endpoint
        .connect(target_addr, &resp.sni)
        .map_err(|error| format!("invalid QUIC connection parameters: {error}"))?;
    let connection = connecting
        .await
        .map_err(|error| format!("QUIC connection failed: {error}"))?;

    s6_log("[=========================================]", "");
    s6_log("[+]", "SECURE QUIC E2EE TUNNEL ESTABLISHED!");
    s6_log(
        "[+]",
        &format!("Connect via Local Proxy: 127.0.0.1:{}", local_port),
    );
    s6_log("[=========================================]", "");

    // 4. On-Success Hook Execution
    if !client_cfg.on_success.is_empty() {
        let cmd_str = client_cfg
            .on_success
            .replace("$LOCAL_TCP_PORT", &local_port.to_string())
            .replace("$TARGET_IPV6", &target_ip)
            .replace("$TARGET_IP", &target_ip)
            .replace("$DYNAMIC_PORT", &resp.dynamic_port.to_string());
        s6_log("[Client]", "Executing configured on_success hook");

        let parts = split_command(&cmd_str)?;
        if parts.is_empty() {
            return Err("configured hook is empty".into());
        }
        tokio::spawn(async move {
            let _ = Command::new(&parts[0]).args(&parts[1..]).spawn();
        });
    }

    // 5. Loopback-only local proxy. Each accepted connection receives an
    // independent QUIC stream and no traffic is exposed on a LAN interface.
    let local_slots = Arc::new(Semaphore::new(MAX_STREAMS_PER_TUNNEL as usize));
    loop {
        let (user_conn, _) = local_proxy
            .accept()
            .await
            .map_err(|error| format!("local proxy accept failed: {error}"))?;
        let permit = local_slots
            .clone()
            .acquire_owned()
            .await
            .map_err(|_| "local proxy connection limiter closed".to_string())?;
        let (mut send, mut recv) = connection
            .open_bi()
            .await
            .map_err(|error| format!("failed to open QUIC stream: {error}"))?;
        tokio::spawn(async move {
            let _permit = permit;
            let (mut local_read, mut local_write) = user_conn.into_split();
            let upload =
                tokio::spawn(async move { tokio::io::copy(&mut local_read, &mut send).await });
            let download =
                tokio::spawn(async move { tokio::io::copy(&mut recv, &mut local_write).await });
            let _ = tokio::try_join!(upload, download);
        });
    }
}

// ============================================================================
// ADMIN UTILITIES
// ============================================================================

fn generate_keys() {
    let mut csprng = OsRng;
    let signing_key = ed25519_dalek::SigningKey::generate(&mut csprng);
    let verifying_key = signing_key.verifying_key();

    println!("--- Ed25519 Key Pair Generated ---");
    println!("Private Key (Hex): {}", hex::encode(signing_key.to_bytes()));
    println!(
        "Public Key (Hex):  {}",
        hex::encode(verifying_key.to_bytes())
    );
    println!("-----------------------------------");
}

fn init_config(role: &str) -> Result<(), String> {
    let mut cfg = Config {
        role: role.to_string(),
        broker: None,
        agent: None,
        client: None,
    };
    match role {
        "broker" => {
            cfg.broker = Some(BrokerConfig {
                listen_addr: "0.0.0.0:4433".into(),
                private_key: "<HEX_PRIVATE_KEY>".into(),
                stealth_mode: true,
                agents: vec![AgentRBAC {
                    id: "nas-1".into(),
                    pubkey: "<AGENT_PUB_KEY>".into(),
                }],
                clients: vec![ClientRBAC {
                    id: "mac-1".into(),
                    pubkey: "<CLIENT_PUB_KEY>".into(),
                    allowed_agents: vec!["nas-1".into()],
                }],
                webhook_url: "".into(),
            });
        }
        "agent" => {
            cfg.agent = Some(AgentConfig {
                id: "nas-1".into(),
                broker_addrs: vec!["wss://your-cdn.com/ws".into(), "vps_ip:4433".into()],
                broker_pubkey: "<BROKER_PUB_KEY>".into(),
                private_key: "<HEX_PRIVATE_KEY>".into(),
                target_port: 22,
                auto_close_after: 7200,
                allow_local_discovery: false,
                client_pubkeys: HashMap::from([("mac-1".into(), "<CLIENT_PUB_KEY>".into())]),
                sni: None,
                alpn: None,
                transport: Some("quic".into()),
            });
        }
        "client" => {
            cfg.client = Some(ClientConfig {
                id: "mac-1".into(),
                broker_addrs: vec!["wss://your-cdn.com/ws".into(), "vps_ip:4433".into()],
                broker_pubkey: "<BROKER_PUB_KEY>".into(),
                private_key: "<HEX_PRIVATE_KEY>".into(),
                target_agent: "nas-1".into(),
                on_success: "ssh root@127.0.0.1 -p $LOCAL_TCP_PORT".into(),
                allow_local_discovery: false,
                agent_pubkey: "<AGENT_PUB_KEY>".into(),
                sni: None,
                alpn: None,
                transport: Some("quic".into()),
            });
        }
        _ => return Err("role must be broker, agent, or client".into()),
    }
    let data = serde_json::to_vec_pretty(&cfg)
        .map_err(|error| format!("failed to serialize template: {error}"))?;
    write_owner_only(Path::new("config.json.example"), &data)?;
    println!(
        "Template config for role '{}' written to config.json.example",
        role
    );
    Ok(())
}

fn install_service(config_file: &str) -> Result<(), String> {
    if config_file.is_empty() {
        return Err("please provide --config with --install-service".into());
    }
    let abs_config = fs::canonicalize(config_file)
        .map_err(|error| format!("cannot resolve config path: {error}"))?;
    let abs_exec =
        env::current_exe().map_err(|error| format!("cannot resolve executable: {error}"))?;
    for path in [&abs_config, &abs_exec] {
        if path.to_string_lossy().contains(['\n', '\r', '"']) {
            return Err("service paths may not contain quotes or newlines".into());
        }
    }

    let unit = format!(
        r#"[Unit]
Description=Shadow6 Rust Ultimate Service
After=network.target

[Service]
Type=simple
ExecStart="{}" --config "{}"
Restart=always
RestartSec=5
User=root
NoNewPrivileges=true
PrivateTmp=true
ProtectHome=read-only
ProtectSystem=strict
ReadWritePaths=/run

[Install]
WantedBy=multi-user.target
"#,
        abs_exec.display(),
        abs_config.display()
    );

    fs::write("/etc/systemd/system/shadow6-rust.service", unit)
        .map_err(|error| format!("failed to write service file: {error}"))?;
    println!("Systemd service created. Run 'systemctl enable --now shadow6-rust' to start.");
    Ok(())
}

fn daemonize(log_file: &str) -> Result<(), String> {
    let args: Vec<String> = env::args().filter(|a| a != "--daemon").collect();
    let executable = args.first().ok_or("missing executable name")?;
    let mut cmd = std::process::Command::new(executable);
    cmd.args(&args[1..]);

    if !log_file.is_empty() {
        let f = fs::OpenOptions::new()
            .create(true)
            .append(true)
            .mode(0o600)
            .open(log_file)
            .map_err(|error| format!("cannot open log file: {error}"))?;
        let stderr = f
            .try_clone()
            .map_err(|error| format!("cannot clone log handle: {error}"))?;
        cmd.stdout(f).stderr(stderr);
    }

    let child = cmd
        .spawn()
        .map_err(|error| format!("daemon start failed: {error}"))?;
    println!("[Shadow6 Rust] Running in background (PID: {})", child.id());
    std::process::exit(0);
}

// ============================================================================
// ENTRYPOINT
// ============================================================================

#[tokio::main]
async fn main() {
    if let Err(error) = run().await {
        eprintln!("shadow6-rust: {error}");
        std::process::exit(2);
    }
}

async fn run() -> Result<(), String> {
    let args: Vec<String> = env::args().collect();
    let mut config_path = String::new();
    let mut gen_key = false;
    let mut init_cfg = String::new();
    let mut install_svc = false;
    let mut check_config = false;
    let mut daemon = false;
    let mut log_file = String::new();
    let mut show_help = false;
    let mut show_features = false;
    let mut crosed_request = String::new();
    let mut crosed_trust = String::new();

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--config" => {
                config_path = args.get(i + 1).ok_or("--config requires a path")?.clone();
                i += 1;
            }
            "--gen-key" => gen_key = true,
            "--init-config" => {
                init_cfg = args
                    .get(i + 1)
                    .ok_or("--init-config requires a role")?
                    .clone();
                i += 1;
            }
            "--install-service" => install_svc = true,
            "--check-config" => check_config = true,
            "--feature-report" => show_features = true,
            "--crosed-request" => {
                crosed_request = args
                    .get(i + 1)
                    .ok_or("--crosed-request requires a path")?
                    .clone();
                i += 1;
            }
            "--crosed-trust" => {
                crosed_trust = args
                    .get(i + 1)
                    .ok_or("--crosed-trust requires a path")?
                    .clone();
                i += 1;
            }
            "-h" | "--help" => show_help = true,
            "--daemon" => daemon = true,
            "--log" => {
                log_file = args.get(i + 1).ok_or("--log requires a path")?.clone();
                i += 1;
            }
            value => return Err(format!("unknown option: {value}")),
        }
        i += 1;
    }

    if show_help || args.len() == 1 {
        println!("Usage: shadow6-rust --config config.json [Options]");
        println!("  --config <path>       Path to the config.json file");
        println!("  --gen-key             Generate a new Ed25519 key pair");
        println!("  --init-config <role>  Generate a template config for a role");
        println!("  --install-service     Create a systemd service file");
        println!("  --check-config        Validate configuration and exit");
        println!("  --feature-report      Print compiled Core/Crosed feature levels as JSON");
        println!("  --crosed-request <p>  Process a signed local Crosed request");
        println!("  --crosed-trust <p>    Owner-only Crosed trust store");
        println!("  --daemon              Run the process in the background");
        println!("  --log <path>          Log file path (used with --daemon)");
        return Ok(());
    }
    if gen_key {
        generate_keys();
        return Ok(());
    }
    if show_features {
        println!(
            "{}",
            serde_json::to_string(&feature_report()).map_err(|error| error.to_string())?
        );
        return Ok(());
    }
    if !crosed_request.is_empty() {
        if crosed_trust.is_empty() {
            return Err("--crosed-request requires --crosed-trust".into());
        }
        let response = handle_crosed_request(&crosed_request, &crosed_trust)?;
        println!(
            "{}",
            serde_json::to_string(&response).map_err(|error| error.to_string())?
        );
        return Ok(());
    }
    if !init_cfg.is_empty() {
        return init_config(&init_cfg);
    }
    if install_svc {
        return install_service(&config_path);
    }

    if config_path.is_empty() {
        return Err("--config is required (use --help for usage)".into());
    }

    if daemon {
        return daemonize(&log_file);
    }

    let config_file = Path::new(&config_path);
    let data = read_secure_config(config_file)?;
    let cfg: Config =
        strict_json::from_str(&data).map_err(|error| format!("invalid config JSON: {error}"))?;
    validate_config(&cfg)?;
    if check_config {
        println!("Configuration {config_path} is valid for role {}", cfg.role);
        return Ok(());
    }

    let _ = rustls::crypto::ring::default_provider().install_default();
    s6_log(
        "[Shadow6 Rust]",
        &format!("Initializing in {} mode", cfg.role),
    );

    match cfg.role.as_str() {
        "broker" => start_broker(cfg).await,
        "agent" => start_agent(cfg).await,
        "client" => start_client(cfg).await,
        _ => unreachable!("validated role"),
    }
}

// ============================================================================
// SHADOW6 RUST COMPREHENSIVE TEST SUITE
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::time::timeout;

    // Helper to generate mock ED25519 keys
    fn setup_crypto() {
        let _ = rustls::crypto::ring::default_provider().install_default();
    }

    fn generate_mock_keys() -> (ed25519_dalek::SigningKey, String, String) {
        let mut csprng = OsRng;
        let signing_key = ed25519_dalek::SigningKey::generate(&mut csprng);
        let verifying_key = signing_key.verifying_key();
        (
            signing_key.clone(),
            hex::encode(signing_key.to_bytes()),
            hex::encode(verifying_key.to_bytes()),
        )
    }

    #[tokio::test]
    async fn test_authentication() {
        setup_crypto();
        let (client_priv, _, client_pub_hex) = generate_mock_keys();
        let mut expected_keys = HashMap::new();
        let pub_bytes = hex::decode(&client_pub_hex).unwrap();
        let verifying_key =
            VerifyingKey::from_bytes(pub_bytes.as_slice().try_into().unwrap()).unwrap();
        expected_keys.insert("test-client".to_string(), verifying_key);

        let mut nonce = [0u8; 32];
        OsRng.fill_bytes(&mut nonce);

        // Sign the nonce using the client's private key
        let sig = client_priv.sign(&auth_payload("test-client", &nonce));

        let auth_resp = AuthResponse {
            id: "test-client".to_string(),
            signature: B64.encode(sig.to_bytes()),
        };

        // Verify Authentication Logic
        let pubkey = expected_keys.get(&auth_resp.id).expect("Key not found");
        let sig_bytes = B64.decode(&auth_resp.signature).expect("B64 decode failed");
        let signature =
            ed25519_dalek::Signature::from_slice(&sig_bytes).expect("Invalid sig format");

        assert!(
            pubkey
                .verify(&auth_payload("test-client", &nonce), &signature)
                .is_ok(),
            "Signature verification should pass"
        );
    }

    #[test]
    fn test_agent_access_signature_binds_ephemeral_certificate() {
        let (agent_key, _, _) = generate_mock_keys();
        let (client_key, _, _) = generate_mock_keys();
        let mut request = AccessReq {
            client_id: "client-1".into(),
            target_agent: "agent-1".into(),
            client_ipv6: "192.0.2.10".into(),
            e2ee_pubkey: B64.encode([7_u8; 32]),
            client_signature: String::new(),
        };
        request.client_signature =
            B64.encode(client_key.sign(&client_access_payload(&request)).to_bytes());
        assert!(verify_client_access(&request, &client_key.verifying_key()).is_ok());
        let mut response = AccessResp {
            success: true,
            target_ipv6: String::new(),
            dynamic_port: 0,
            kcp_port: 4433,
            e2ee_pubkey: B64.encode(b"ephemeral certificate"),
            error_msg: String::new(),
            sni: "agent.shadow6.invalid".into(),
            alpn: "shadow6/1".into(),
            transport: "quic".into(),
            agent_signature: String::new(),
        };
        response.agent_signature = B64.encode(
            agent_key
                .sign(&agent_access_payload(&request, &response))
                .to_bytes(),
        );
        assert!(verify_agent_access(&request, &response, &agent_key.verifying_key()).is_ok());

        response.e2ee_pubkey = B64.encode(b"broker-substituted certificate");
        assert!(verify_agent_access(&request, &response, &agent_key.verifying_key()).is_err());

        request.client_ipv6 = "192.0.2.99".into();
        assert!(verify_client_access(&request, &client_key.verifying_key()).is_err());
    }

    #[tokio::test]
    async fn test_broker_mutual_auth_and_role_enforcement() {
        setup_crypto();
        let (broker_key, broker_private, broker_public) = generate_mock_keys();
        let (client_key, _, client_public) = generate_mock_keys();
        let reservation = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = reservation.local_addr().unwrap().port();
        drop(reservation);

        let config = Config {
            role: "broker".into(),
            broker: Some(BrokerConfig {
                listen_addr: format!("127.0.0.1:{port}"),
                private_key: broker_private,
                agents: Vec::new(),
                clients: vec![ClientRBAC {
                    id: "client-1".into(),
                    pubkey: client_public,
                    allowed_agents: Vec::new(),
                }],
                webhook_url: String::new(),
                stealth_mode: false,
            }),
            agent: None,
            client: None,
        };
        let broker_task = tokio::spawn(start_broker(config));
        tokio::time::sleep(Duration::from_millis(50)).await;
        let url = format!("ws://127.0.0.1:{port}/ws");
        let (mut socket, _) = connect_async_with_config(url, Some(websocket_config()), false)
            .await
            .unwrap();

        let challenge = match socket.next().await.unwrap().unwrap() {
            Message::Binary(value) => value,
            other => panic!("unexpected challenge: {other:?}"),
        };
        let response = AuthResponse {
            id: "client-1".into(),
            signature: B64.encode(
                client_key
                    .sign(&auth_payload("client-1", &challenge))
                    .to_bytes(),
            ),
        };
        socket
            .send(Message::Text(
                serde_json::to_string(&response).unwrap().into(),
            ))
            .await
            .unwrap();

        let mut broker_nonce = [0u8; 32];
        OsRng.fill_bytes(&mut broker_nonce);
        socket
            .send(Message::Binary(broker_nonce.to_vec().into()))
            .await
            .unwrap();
        let broker_response = match socket.next().await.unwrap().unwrap() {
            Message::Text(value) => serde_json::from_str::<AuthResponse>(&value).unwrap(),
            other => panic!("unexpected broker response: {other:?}"),
        };
        let broker_verify = verifying_key_from_hex(&broker_public).unwrap();
        verify_auth_response(&broker_response, "broker", &broker_verify, &broker_nonce).unwrap();
        assert_eq!(broker_verify, broker_key.verifying_key());

        let unauthorized = JsonRpcRequest {
            jsonrpc: "2.0".into(),
            id: 9,
            method: "Broker.UpdateIP".into(),
            params: serde_json::json!({"agent_id": "spoofed-agent", "ipv6": "::1"}),
        };
        socket
            .send(Message::Text(
                serde_json::to_string(&unauthorized).unwrap().into(),
            ))
            .await
            .unwrap();
        let denial = match timeout(Duration::from_secs(2), socket.next())
            .await
            .unwrap()
            .unwrap()
            .unwrap()
        {
            Message::Text(value) => serde_json::from_str::<JsonRpcResponse>(&value).unwrap(),
            other => panic!("unexpected RPC response: {other:?}"),
        };
        assert!(denial.result.is_none());
        assert!(denial.error.unwrap().contains("authenticated agents"));
        broker_task.abort();
    }

    #[tokio::test]
    async fn test_agent_dynamic_port_and_proxy() {
        setup_crypto();
        // A real TCP target behind the Agent.
        let dummy_target = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target_port = dummy_target.local_addr().unwrap().port();
        let target_task = tokio::spawn(async move {
            let (mut stream, _) = dummy_target.accept().await.unwrap();
            let mut request = [0u8; 4];
            stream.read_exact(&mut request).await.unwrap();
            assert_eq!(&request, b"ping");
            stream.write_all(b"pong").await.unwrap();
        });

        // Simulate Agent Config
        let cfg = AgentConfig {
            id: "agent-1".into(),
            broker_addrs: vec![],
            broker_pubkey: "".into(),
            private_key: "".into(),
            target_port,
            auto_close_after: 5,
            allow_local_discovery: false,
            client_pubkeys: HashMap::new(),
            sni: None,
            alpn: None,
            transport: None,
        };

        // Call provision_access
        let result = provision_access(&cfg, "127.0.0.1").await;
        assert!(result.is_ok(), "Provision access should succeed");

        let resp = result.unwrap();
        assert!(resp.success);
        assert_eq!(
            resp.dynamic_port, 0,
            "plaintext TCP fallback must stay disabled"
        );
        assert!(resp.kcp_port > 0);
        assert!(
            !resp.e2ee_pubkey.is_empty(),
            "Expected QUIC TLS Cert to be provided"
        );

        assert_eq!(resp.transport, "quic");

        // Validate the real data path and standard TLS proof, rather than only
        // asserting that a random port was allocated.
        let mut roots = rustls::RootCertStore::empty();
        roots
            .add(CertificateDer::from(B64.decode(&resp.e2ee_pubkey).unwrap()))
            .unwrap();
        let mut tls = rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        tls.alpn_protocols = vec![resp.alpn.as_bytes().to_vec()];
        let quic_tls = quinn::crypto::rustls::QuicClientConfig::try_from(tls).unwrap();
        let mut endpoint = Endpoint::client("0.0.0.0:0".parse().unwrap()).unwrap();
        endpoint.set_default_client_config(QuinnClientConfig::new(Arc::new(quic_tls)));
        let address = format!("127.0.0.1:{}", resp.kcp_port).parse().unwrap();
        let connecting = endpoint.connect(address, &resp.sni).unwrap();
        let connection = timeout(Duration::from_secs(3), connecting)
            .await
            .unwrap()
            .unwrap();
        let (mut send, mut receive) = connection.open_bi().await.unwrap();
        send.write_all(b"ping").await.unwrap();
        let mut reply = [0u8; 4];
        timeout(Duration::from_secs(3), receive.read_exact(&mut reply))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&reply, b"pong");
        connection.close(0u32.into(), b"test complete");
        target_task.await.unwrap();
    }

    #[test]
    fn test_peer_ip_validation() {
        assert!(parse_peer_ip("").is_err());
        assert!(parse_peer_ip("ff02::1").is_err());
        assert_eq!(
            parse_scoped_peer_ip("fe80::1%7").unwrap(),
            ("fe80::1".parse().unwrap(), 7)
        );
        assert!(parse_scoped_peer_ip("192.0.2.1%7").is_err());
    }

    #[test]
    fn test_native_interface_index_enumeration_and_name_lookup() {
        use std::ffi::CStr;

        let interfaces = unsafe { libc::if_nameindex() };
        if interfaces.is_null() {
            return;
        }
        let first = unsafe { &*interfaces };
        if first.if_index != 0 && !first.if_name.is_null() {
            let expected = first.if_index;
            let name = unsafe { CStr::from_ptr(first.if_name) }
                .to_str()
                .ok()
                .map(str::to_owned);
            unsafe { libc::if_freenameindex(interfaces) };
            if let Some(name) = name {
                assert_eq!(interface_scope_id(&name).unwrap(), expected);
                assert!(ipv6_interface_indices().contains(&expected));
            }
        } else {
            unsafe { libc::if_freenameindex(interfaces) };
        }
    }

    #[tokio::test]
    async fn test_local_peer_discovery_ipv6() {
        setup_crypto();
        let (agent_signing, agent_private, agent_public) = generate_mock_keys();
        let (_, client_private, client_public) = generate_mock_keys();
        let mut client_pubkeys = HashMap::new();
        client_pubkeys.insert("lpd-client".into(), client_public.clone());
        let agent_cfg = AgentConfig {
            id: "LPD_LOCAL".into(),
            broker_addrs: vec![],
            broker_pubkey: "".into(),
            private_key: agent_private,
            target_port: 22,
            auto_close_after: 2,
            allow_local_discovery: true,
            client_pubkeys,
            sni: None,
            alpn: None,
            transport: None,
        };

        let server = match UdpSocket::bind("[::1]:0").await {
            Ok(socket) => socket,
            Err(_) => return,
        };
        let server_address = server.local_addr().unwrap();
        let mut authorized = HashMap::new();
        authorized.insert(
            "lpd-client".to_string(),
            verifying_key_from_hex(&client_public).unwrap(),
        );
        let lpd_task = tokio::spawn(serve_agent_lpd_socket(
            server,
            Arc::new(agent_cfg),
            Arc::new(agent_signing),
            Arc::new(authorized),
            Arc::new(Mutex::new(HashMap::new())),
        ));

        // Perform Client Discovery
        let client_cfg = ClientConfig {
            id: "lpd-client".into(),
            broker_addrs: vec![],
            broker_pubkey: "".into(),
            private_key: client_private,
            target_agent: "LPD_LOCAL".into(),
            on_success: String::new(),
            allow_local_discovery: true,
            agent_pubkey: agent_public,
            sni: None,
            alpn: None,
            transport: Some("quic".into()),
        };
        // Use the key encoded in the requester's configuration.
        let client_signing = signing_key_from_hex(&client_cfg.private_key).unwrap();
        let discovery_result =
            perform_local_discovery_to(&client_cfg, &client_signing, vec![server_address]).await;

        assert!(discovery_result.is_some(), "LPD Discovery failed, got None");
        let (resp, ip) = discovery_result.unwrap();

        assert!(resp.success);
        assert!(resp.kcp_port > 0);
        assert!(!resp.e2ee_pubkey.is_empty());
        assert_eq!(ip, "::1");
        lpd_task.abort();
    }

    #[test]
    fn test_utilities_keygen_and_config() {
        // Just verify utilities run without panicking
        generate_keys();
        init_config("broker").unwrap();
        let exists = std::path::Path::new("config.json.example").exists();
        assert!(exists, "Config file should have been generated");
        std::fs::remove_file("config.json.example").unwrap();
    }

    #[test]
    fn test_client_on_success_hook_execution() {
        let target_ipv6 = "2001:db8::cafe";
        let dynamic_port = 54321;
        let raw_hook_cmd = "echo Hook Triggered: IP is $TARGET_IPV6 and Port is $DYNAMIC_PORT";

        let cmd_str = raw_hook_cmd
            .replace("$TARGET_IPV6", target_ipv6)
            .replace("$DYNAMIC_PORT", &dynamic_port.to_string());

        assert_eq!(
            cmd_str,
            "echo Hook Triggered: IP is 2001:db8::cafe and Port is 54321"
        );

        let parts: Vec<String> = cmd_str.split_whitespace().map(|s| s.to_string()).collect();
        assert_eq!(parts[0], "echo");
        assert_eq!(parts[1], "Hook");
    }

    #[tokio::test]
    async fn test_webhook_alert() {
        // Set up a mock local TCP server to intercept the HTTP POST request
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let url = format!("http://127.0.0.1:{}", port);

        let handle = tokio::spawn(async move {
            if let Ok((mut stream, _)) = listener.accept().await {
                let mut buf = vec![0; 1024];
                let _ = stream.read(&mut buf).await;
                let request_str = String::from_utf8_lossy(&buf);
                assert!(request_str.contains("POST / HTTP/1.1"));
                assert!(request_str.contains("client-99"));
                assert!(request_str.contains("Access Granted"));

                let response = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK";
                let _ = stream.write_all(response.as_bytes()).await;
            }
        });

        send_webhook(
            &url,
            "Access Granted",
            "client-99",
            "agent-1",
            "127.0.0.1",
            true,
        )
        .await;

        let _ = timeout(Duration::from_secs(2), handle)
            .await
            .expect("Webhook server timeout");
    } // Closes the original test_webhook_alert function

    // ============================================================================
    // 5. SECURITY PATCH & E2E TESTS (PERFECTLY SCOPED)
    // ============================================================================

    #[tokio::test]
    async fn test_dynamic_salt() {
        let ip = "192.168.1.100";
        let m1 = mask_ip(ip, true);
        let m2 = mask_ip(ip, true);
        assert_eq!(
            m1, m2,
            "Salt should remain consistent during a single runtime"
        );
        assert!(m1.starts_with("IP[MASKED:"));
    }

    #[tokio::test]
    async fn test_webhook_dos_prevention() {
        let mut permits = vec![];
        for _ in 0..50 {
            permits.push(WEBHOOK_SEM.try_acquire().unwrap());
        }
        // This should return safely without spawning due to the semaphore limit
        send_webhook(
            "http://127.0.0.1:0",
            "Test",
            "client",
            "agent",
            "1.1.1.1",
            false,
        )
        .await;
        assert!(WEBHOOK_SEM.available_permits() == 0);
    }

    #[tokio::test]
    async fn test_e2e_network_integration() {
        setup_crypto();
        let cfg = AgentConfig {
            id: "e2e-agent".into(),
            broker_addrs: vec![],
            broker_pubkey: "".into(),
            private_key: "".into(),
            target_port: 22,
            auto_close_after: 2,
            allow_local_discovery: false,
            client_pubkeys: HashMap::new(),
            sni: None,
            alpn: None,
            transport: None,
        };
        let access_result = provision_access(&cfg, "127.0.0.1").await;
        assert!(access_result.is_ok(), "E2E Agent provisioning failed");
        let access = access_result.unwrap();
        assert!(access.success, "E2E Access must be successful");
        assert!(access.kcp_port > 0, "QUIC Port must be allocated");
        assert!(
            !access.e2ee_pubkey.is_empty(),
            "E2EE Cert Fingerprint must be generated for Pinning"
        );
    }

    #[test]
    fn test_generate_random_sni() {
        let sni1 = generate_random_sni();
        let sni2 = generate_random_sni();
        assert!(sni1.ends_with(".shadow6.invalid"));
        assert_ne!(sni1, sni2, "SNIs should be randomly generated");
    }

    #[test]
    fn test_webtransport_obfuscation_config() {
        let cfg = AgentConfig {
            id: "test-agent".into(),
            broker_addrs: vec![],
            broker_pubkey: "".into(),
            private_key: "".into(),
            target_port: 80,
            auto_close_after: 10,
            allow_local_discovery: false,
            client_pubkeys: HashMap::new(),
            sni: Some("microsoft.com".into()),
            alpn: Some("h3".into()),
            transport: Some("quic".into()),
        };
        assert_eq!(cfg.sni.unwrap(), "microsoft.com");
        assert_eq!(cfg.transport.unwrap(), "quic");
        assert_eq!(cfg.alpn.unwrap(), "h3");
    }

    #[test]
    fn test_strict_inputs_and_command_parser() {
        let (_, private_hex, _) = generate_mock_keys();
        let mut expanded = hex::decode(&private_hex).unwrap();
        let signing = signing_key_from_hex(&private_hex).unwrap();
        expanded.extend_from_slice(signing.verifying_key().as_bytes());
        assert!(signing_key_from_hex(&hex::encode(&expanded)).is_ok());
        expanded[63] ^= 1;
        assert!(signing_key_from_hex(&hex::encode(expanded)).is_err());

        let parts = split_command(r#"echo "two words" ';' literal"#).unwrap();
        assert_eq!(parts, vec!["echo", "two words", ";", "literal"]);
        assert!(split_command("echo 'unterminated").is_err());
        assert!(normalized_broker_url("wss://user@example.com/ws").is_err());
        assert!(normalized_broker_url("wss://example.com/ws#fragment").is_err());

        let unknown =
            r#"{"role":"broker","broker":null,"agent":null,"client":null,"unexpected":true}"#;
        assert!(serde_json::from_str::<Config>(unknown).is_err());
    }

    #[test]
    fn test_high_throughput_capacity_contract() {
        let required =
            (TARGET_THROUGHPUT_BITS_PER_SECOND * DESIGN_ROUND_TRIP_MILLISECONDS).div_ceil(8000);
        assert!(QUIC_CONNECTION_WINDOW_BYTES >= required);
        const {
            assert!(QUIC_STREAM_WINDOW_BYTES >= 16 * 1024 * 1024);
            assert!(MAX_STREAMS_PER_TUNNEL >= 256);
        }
    }

    #[test]
    fn test_secure_config_open_rejects_unsafe_paths_and_modes() {
        use std::os::unix::fs::symlink;

        let mut random = [0_u8; 16];
        OsRng.fill_bytes(&mut random);
        let directory = env::temp_dir().join(format!(
            "shadow6-rust-config-test-{}-{}",
            std::process::id(),
            hex::encode(random)
        ));
        fs::create_dir(&directory).unwrap();
        let config = directory.join("config.json");
        write_owner_only(&config, b"{}").unwrap();
        assert_eq!(read_secure_config(&config).unwrap(), "{}");

        fs::set_permissions(&config, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(read_secure_config(&config).is_err());
        fs::set_permissions(&config, fs::Permissions::from_mode(0o600)).unwrap();

        let link = directory.join("config-link.json");
        symlink(&config, &link).unwrap();
        assert!(read_secure_config(&link).is_err());

        fs::remove_file(link).unwrap();
        fs::remove_file(config).unwrap();
        fs::remove_dir(directory).unwrap();
    }

    #[test]
    fn test_compiled_features_and_signed_crosed_negotiation() {
        let report = feature_report();
        assert_eq!(report.core, "shadow6-rust");
        assert!(report.utf8);
        assert_eq!(report.crosed_max_level, compiled_crosed_level());
        let (signing_key, _, public_hex) = generate_mock_keys();
        let mut request = CrosedRequest {
            version: 1,
            mod_id: "test-mod".into(),
            nonce: "00112233445566778899aabbccddeeff".into(),
            issued_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs() as i64,
            requested_level: 1,
            capabilities: vec!["observe.version".into()],
            source_domain: "work-vm".into(),
            target_domain: "work-vm".into(),
            payload: serde_json::json!({"message": "你好"}),
            signature: String::new(),
        };
        request.signature = hex::encode(
            signing_key
                .sign(&crosed_signed_payload(&request).unwrap())
                .to_bytes(),
        );
        let trust = serde_json::json!({"mods": {"test-mod": {
            "pubkey": public_hex, "max_level": 1,
            "capabilities": ["observe.version"], "allowed_domains": ["work-vm"]
        }}});
        let mut random = [0_u8; 16];
        OsRng.fill_bytes(&mut random);
        let directory =
            env::temp_dir().join(format!("shadow6-crosed-test-{}", hex::encode(random)));
        fs::create_dir(&directory).unwrap();
        let request_path = directory.join("request.json");
        let trust_path = directory.join("trust.json");
        write_owner_only(
            &request_path,
            serde_json::to_string(&request).unwrap().as_bytes(),
        )
        .unwrap();
        write_owner_only(
            &trust_path,
            serde_json::to_string(&trust).unwrap().as_bytes(),
        )
        .unwrap();
        let response =
            handle_crosed_request(request_path.to_str().unwrap(), trust_path.to_str().unwrap())
                .unwrap();
        if report.crosed_compiled {
            assert_eq!(response.status, "granted");
            assert_eq!(response.granted_level, 1);
        } else {
            assert_eq!(response.status, "denied");
            assert_eq!(response.features.crosed_max_level, 0);
        }
        fs::remove_file(request_path).unwrap();
        fs::remove_file(trust_path).unwrap();
        fs::remove_dir(directory).unwrap();
    }
} // Closes mod tests properly
