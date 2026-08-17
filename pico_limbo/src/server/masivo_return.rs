use crate::configuration::config::MasivoReturnConfig;
use hmac::KeyInit;
use hmac::{Hmac, Mac};
use serde::Deserialize;
use sha2::Sha256;
use std::collections::{HashMap, HashSet};
use std::io;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Mutex, mpsc};
use tokio::time::Instant;
use tracing::{error, info, warn};
use uuid::Uuid;

type HmacSha256 = Hmac<Sha256>;
const MAX_REQUEST_BYTES: usize = 8 * 1024;
const MAX_BODY_BYTES: usize = 4 * 1024;
const SIGNATURE_TOLERANCE_SECONDS: u64 = 30;

#[derive(Clone)]
pub(super) struct TransferTarget {
    pub host: String,
    pub port: u16,
}

#[derive(Clone)]
pub struct ReturnController {
    config: Arc<MasivoReturnConfig>,
    state: Arc<Mutex<ControllerState>>,
    next_client_id: Arc<AtomicU64>,
}

struct ControllerState {
    clients: HashMap<u64, mpsc::UnboundedSender<TransferTarget>>,
    released_operations: HashSet<Uuid>,
    active: Option<ActiveRelease>,
}

struct ActiveRelease {
    operation_id: Uuid,
    expires_at: Instant,
}

struct ReleaseOutcome {
    queued: usize,
    duplicate: bool,
}

impl ReturnController {
    pub(super) fn new(config: MasivoReturnConfig) -> Option<Self> {
        config.enabled.then(|| Self {
            config: Arc::new(config),
            state: Arc::new(Mutex::new(ControllerState {
                clients: HashMap::new(),
                released_operations: HashSet::new(),
                active: None,
            })),
            next_client_id: Arc::new(AtomicU64::new(1)),
        })
    }

    pub(super) async fn bind(&self) -> io::Result<TcpListener> {
        TcpListener::bind(&self.config.control_address).await
    }

    pub(super) async fn serve(self, listener: TcpListener) {
        info!(
            "Masivo return control listening on {}",
            self.config.control_address
        );
        loop {
            match listener.accept().await {
                Ok((stream, address)) => {
                    let controller = self.clone();
                    tokio::spawn(async move {
                        if let Err(reason) = handle_request(stream, &controller).await {
                            warn!("Rejected Masivo return request from {address}: {reason}");
                        }
                    });
                }
                Err(reason) => error!("Masivo return control accept failed: {reason}"),
            }
        }
    }

    pub(super) async fn register(&self, sender: mpsc::UnboundedSender<TransferTarget>) -> u64 {
        let id = self.next_client_id.fetch_add(1, Ordering::Relaxed);
        let mut state = self.state.lock().await;
        state.clients.insert(id, sender.clone());
        let release_active = active_operation(&mut state).is_some();
        drop(state);
        if release_active {
            let _ = sender.send(self.target());
        }
        id
    }

    pub(super) async fn unregister(&self, id: u64) {
        self.state.lock().await.clients.remove(&id);
    }

    async fn release(&self, operation_id: Uuid) -> ReleaseOutcome {
        let senders = {
            let mut state = self.state.lock().await;
            if !state.released_operations.insert(operation_id) {
                return ReleaseOutcome {
                    queued: 0,
                    duplicate: true,
                };
            }
            state.active = Some(ActiveRelease {
                operation_id,
                expires_at: Instant::now()
                    + Duration::from_secs(self.config.release_window_seconds),
            });
            state.clients.values().cloned().collect::<Vec<_>>()
        };
        let queued = senders.len();
        let target = self.target();
        let players_per_tick = self.config.players_per_tick;
        tokio::spawn(async move {
            let mut batches = senders.chunks(players_per_tick).peekable();
            while let Some(batch) = batches.next() {
                for sender in batch {
                    let _ = sender.send(target.clone());
                }
                if batches.peek().is_some() {
                    tokio::time::sleep(Duration::from_millis(50)).await;
                }
            }
        });
        ReleaseOutcome {
            queued,
            duplicate: false,
        }
    }

    async fn status(&self) -> (usize, Option<Uuid>) {
        let mut state = self.state.lock().await;
        let active = active_operation(&mut state);
        (state.clients.len(), active)
    }

    fn target(&self) -> TransferTarget {
        TransferTarget {
            host: self.config.return_host.clone(),
            port: self.config.return_port,
        }
    }
}

fn active_operation(state: &mut ControllerState) -> Option<Uuid> {
    if state
        .active
        .as_ref()
        .is_some_and(|active| active.expires_at <= Instant::now())
    {
        state.active = None;
    }
    state.active.as_ref().map(|active| active.operation_id)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ReleaseRequest {
    operation_id: String,
}

struct HttpRequest {
    method: String,
    path: String,
    headers: HashMap<String, String>,
    body: Vec<u8>,
}

async fn handle_request(mut stream: TcpStream, controller: &ReturnController) -> io::Result<()> {
    let request =
        match tokio::time::timeout(Duration::from_secs(5), read_request(&mut stream)).await {
            Ok(Ok(request)) => request,
            Ok(Err(reason)) => {
                write_response(&mut stream, 400, &format!(r#"{{"error":"{reason}"}}"#)).await?;
                return Err(io::Error::new(io::ErrorKind::InvalidData, reason));
            }
            Err(_) => {
                write_response(&mut stream, 408, r#"{"error":"request timeout"}"#).await?;
                return Err(io::Error::new(io::ErrorKind::TimedOut, "request timeout"));
            }
        };

    if let Err(reason) = verify_request(&request, &controller.config.shared_secret, epoch_seconds())
    {
        write_response(&mut stream, 401, r#"{"error":"unauthorized"}"#).await?;
        return Err(io::Error::new(io::ErrorKind::PermissionDenied, reason));
    }

    match (request.method.as_str(), request.path.as_str()) {
        ("POST", "/v1/release") => {
            let payload: ReleaseRequest = match serde_json::from_slice(&request.body) {
                Ok(payload) => payload,
                Err(reason) => {
                    write_response(&mut stream, 400, r#"{"error":"invalid JSON"}"#).await?;
                    return Err(io::Error::new(io::ErrorKind::InvalidData, reason));
                }
            };
            let operation_id = match Uuid::parse_str(&payload.operation_id) {
                Ok(operation_id) => operation_id,
                Err(reason) => {
                    write_response(&mut stream, 400, r#"{"error":"invalid operation UUID"}"#)
                        .await?;
                    return Err(io::Error::new(io::ErrorKind::InvalidData, reason));
                }
            };
            let outcome = controller.release(operation_id).await;
            info!(
                "Masivo return operation {operation_id} accepted; {} player(s) queued",
                outcome.queued
            );
            write_response(
                &mut stream,
                200,
                &format!(
                    r#"{{"operation_id":"{operation_id}","queued":{},"duplicate":{}}}"#,
                    outcome.queued, outcome.duplicate
                ),
            )
            .await?;
        }
        ("GET", "/v1/status") => {
            let (connected, operation_id) = controller.status().await;
            let operation = operation_id.map_or_else(|| "null".into(), |id| format!(r#""{id}""#));
            write_response(
                &mut stream,
                200,
                &format!(r#"{{"connected":{connected},"active_operation":{operation}}}"#),
            )
            .await?;
        }
        _ => write_response(&mut stream, 404, r#"{"error":"not found"}"#).await?,
    }
    Ok(())
}

async fn read_request(stream: &mut TcpStream) -> Result<HttpRequest, String> {
    let mut bytes = Vec::new();
    let header_end = loop {
        if bytes.len() >= MAX_REQUEST_BYTES {
            return Err("request too large".into());
        }
        let mut chunk = [0_u8; 1024];
        let read = stream
            .read(&mut chunk)
            .await
            .map_err(|reason| reason.to_string())?;
        if read == 0 {
            return Err("unexpected end of request".into());
        }
        bytes.extend_from_slice(&chunk[..read]);
        if let Some(index) = bytes.windows(4).position(|window| window == b"\r\n\r\n") {
            break index + 4;
        }
    };

    let header_text =
        std::str::from_utf8(&bytes[..header_end - 4]).map_err(|_| "headers must be UTF-8")?;
    let mut lines = header_text.split("\r\n");
    let mut request_line = lines
        .next()
        .ok_or_else(|| "missing request line".to_string())?
        .split_ascii_whitespace();
    let method = request_line
        .next()
        .ok_or_else(|| "missing method".to_string())?
        .to_string();
    let path = request_line
        .next()
        .ok_or_else(|| "missing path".to_string())?
        .to_string();
    if request_line.next() != Some("HTTP/1.1") || request_line.next().is_some() {
        return Err("only HTTP/1.1 is supported".into());
    }

    let mut headers = HashMap::new();
    for line in lines {
        let (name, value) = line
            .split_once(':')
            .ok_or_else(|| "malformed header".to_string())?;
        let name = name.trim().to_ascii_lowercase();
        if headers.insert(name, value.trim().to_string()).is_some() {
            return Err("duplicate header".into());
        }
    }
    if headers.contains_key("transfer-encoding") {
        return Err("transfer encoding is not supported".into());
    }
    let content_length = headers
        .get("content-length")
        .map_or(Ok(0), |value| value.parse::<usize>())
        .map_err(|_| "invalid content length")?;
    if content_length > MAX_BODY_BYTES || header_end + content_length > MAX_REQUEST_BYTES {
        return Err("request body too large".into());
    }
    while bytes.len() < header_end + content_length {
        let mut chunk = [0_u8; 1024];
        let read = stream
            .read(&mut chunk)
            .await
            .map_err(|reason| reason.to_string())?;
        if read == 0 {
            return Err("unexpected end of body".into());
        }
        bytes.extend_from_slice(&chunk[..read]);
    }
    Ok(HttpRequest {
        method,
        path,
        headers,
        body: bytes[header_end..header_end + content_length].to_vec(),
    })
}

fn verify_request(request: &HttpRequest, secret: &str, now: u64) -> Result<(), &'static str> {
    let timestamp = request
        .headers
        .get("x-masivo-timestamp")
        .ok_or("missing timestamp")?
        .parse::<u64>()
        .map_err(|_| "invalid timestamp")?;
    if timestamp.abs_diff(now) > SIGNATURE_TOLERANCE_SECONDS {
        return Err("expired timestamp");
    }
    let signature = decode_hex(
        request
            .headers
            .get("x-masivo-signature")
            .ok_or("missing signature")?,
    )?;
    let mut signed = format!("{timestamp}\n{}\n{}\n", request.method, request.path).into_bytes();
    signed.extend_from_slice(&request.body);
    let mut mac = HmacSha256::new_from_slice(secret.as_bytes()).map_err(|_| "invalid secret")?;
    mac.update(&signed);
    mac.verify_slice(&signature)
        .map_err(|_| "invalid signature")
}

fn decode_hex(value: &str) -> Result<Vec<u8>, &'static str> {
    if value.len() != 64 {
        return Err("invalid signature");
    }
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let text = std::str::from_utf8(pair).map_err(|_| "invalid signature")?;
            u8::from_str_radix(text, 16).map_err(|_| "invalid signature")
        })
        .collect()
}

fn epoch_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

async fn write_response(stream: &mut TcpStream, status: u16, body: &str) -> io::Result<()> {
    let reason = match status {
        200 => "OK",
        400 => "Bad Request",
        401 => "Unauthorized",
        404 => "Not Found",
        408 => "Request Timeout",
        _ => "Error",
    };
    let response = format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    stream.write_all(response.as_bytes()).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fmt::Write;

    fn signed_request(body: &[u8], timestamp: u64, secret: &str) -> HttpRequest {
        let method = "POST".to_string();
        let path = "/v1/release".to_string();
        let mut signed = format!("{timestamp}\n{method}\n{path}\n").into_bytes();
        signed.extend_from_slice(body);
        let mut mac = HmacSha256::new_from_slice(secret.as_bytes()).unwrap();
        mac.update(&signed);
        let signature = mac.finalize().into_bytes();
        let signature = signature.iter().fold(String::new(), |mut result, byte| {
            write!(result, "{byte:02x}").unwrap();
            result
        });
        HttpRequest {
            method,
            path,
            headers: HashMap::from([
                ("x-masivo-timestamp".into(), timestamp.to_string()),
                ("x-masivo-signature".into(), signature),
            ]),
            body: body.to_vec(),
        }
    }

    #[test]
    fn rejects_tampered_release_requests() {
        let secret = "0123456789abcdef0123456789abcdef";
        let mut request = signed_request(
            br#"{"operation_id":"00000000-0000-0000-0000-000000000001"}"#,
            100,
            secret,
        );
        assert_eq!(
            request.headers["x-masivo-signature"],
            "db35b0dd7fa7f6799302a47423bb61ac71f030db3e2fdd112f7e8b1b4cf46c8d"
        );
        assert!(verify_request(&request, secret, 100).is_ok());
        request.body = b"tampered".to_vec();
        assert!(verify_request(&request, secret, 100).is_err());
    }

    #[tokio::test(start_paused = true)]
    async fn releases_existing_clients_in_tick_batches() {
        let controller = ReturnController::new(MasivoReturnConfig {
            enabled: true,
            shared_secret: "0123456789abcdef0123456789abcdef".into(),
            return_host: "play.example.com".into(),
            players_per_tick: 3,
            ..MasivoReturnConfig::default()
        })
        .unwrap();
        let mut receivers = Vec::new();
        for _ in 0..7 {
            let (sender, receiver) = mpsc::unbounded_channel();
            controller.register(sender).await;
            receivers.push(receiver);
        }

        let outcome = controller.release(Uuid::new_v4()).await;
        assert_eq!(outcome.queued, 7);
        tokio::task::yield_now().await;
        assert_eq!(
            receivers
                .iter_mut()
                .map(|rx| rx.try_recv().is_ok())
                .filter(|received| *received)
                .count(),
            3
        );
        tokio::time::advance(Duration::from_millis(50)).await;
        tokio::task::yield_now().await;
        assert_eq!(
            receivers
                .iter_mut()
                .map(|rx| rx.try_recv().is_ok())
                .filter(|received| *received)
                .count(),
            3
        );
        tokio::time::advance(Duration::from_millis(50)).await;
        tokio::task::yield_now().await;
        assert_eq!(
            receivers
                .iter_mut()
                .map(|rx| rx.try_recv().is_ok())
                .filter(|received| *received)
                .count(),
            1
        );
    }
}
