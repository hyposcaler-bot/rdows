pub mod handler;
pub mod memory_store;
pub mod session;

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use tokio::net::TcpListener;
use tokio::sync::Mutex;
use tokio_rustls::TlsAcceptor;
use tokio_tungstenite::tungstenite::handshake::server::{ErrorResponse, Request, Response};
use tokio_tungstenite::tungstenite::http;
use tracing::{debug, error, info, warn};

use rdows_core::SUBPROTOCOL;

pub struct ServerConfig {
    pub recv_queue_depth: u32,
    pub max_regions_per_session: usize,
    pub max_total_bytes_per_session: u64,
    pub max_outstanding_reads: u32,
    pub max_sessions_per_ip: u32,
    pub mr_reg_rate_limit: u32,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            recv_queue_depth: 128,
            max_regions_per_session: 4096,
            max_total_bytes_per_session: 32 * 1024 * 1024 * 1024,
            max_outstanding_reads: 128,
            max_sessions_per_ip: 256,
            mr_reg_rate_limit: 1000,
        }
    }
}

type SessionTracker = Arc<Mutex<HashMap<IpAddr, u32>>>;

pub async fn run_server(listener: TcpListener, tls_acceptor: TlsAcceptor, config: ServerConfig) {
    info!(
        addr = %listener.local_addr().unwrap(),
        "RDoWS server listening"
    );

    let session_tracker: SessionTracker = Arc::new(Mutex::new(HashMap::new()));
    let config = Arc::new(config);

    loop {
        let (stream, peer) = match listener.accept().await {
            Ok(s) => s,
            Err(e) => {
                error!("accept error: {e}");
                continue;
            }
        };

        let acceptor = tls_acceptor.clone();
        let tracker = Arc::clone(&session_tracker);
        let config = Arc::clone(&config);
        tokio::spawn(async move {
            if let Err(e) = handle_connection(stream, acceptor, peer, &config, &tracker).await {
                debug!(peer = %peer, "connection error: {e}");
            }
        });
    }
}

async fn handle_connection(
    stream: tokio::net::TcpStream,
    acceptor: TlsAcceptor,
    peer: SocketAddr,
    config: &ServerConfig,
    session_tracker: &SessionTracker,
) -> Result<(), Box<dyn std::error::Error>> {
    debug!(peer = %peer, "new TCP connection");

    let ip = peer.ip();

    // Per-IP session limit check
    {
        let mut tracker = session_tracker.lock().await;
        let count = tracker.entry(ip).or_insert(0);
        if *count >= config.max_sessions_per_ip {
            warn!(peer = %peer, "per-IP session limit reached ({} sessions)", config.max_sessions_per_ip);
            return Err("per-IP session limit exceeded".into());
        }
        *count += 1;
    }

    let tls_stream = match acceptor.accept(stream).await {
        Ok(s) => s,
        Err(e) => {
            let mut tracker = session_tracker.lock().await;
            if let Some(count) = tracker.get_mut(&ip) {
                *count -= 1;
                if *count == 0 {
                    tracker.remove(&ip);
                }
            }
            return Err(e.into());
        }
    };
    debug!(peer = %peer, "TLS handshake complete");

    let ws_stream = match tokio_tungstenite::accept_hdr_async(tls_stream, check_subprotocol).await
    {
        Ok(s) => s,
        Err(e) => {
            let mut tracker = session_tracker.lock().await;
            if let Some(count) = tracker.get_mut(&ip) {
                *count -= 1;
                if *count == 0 {
                    tracker.remove(&ip);
                }
            }
            return Err(e.into());
        }
    };

    info!(peer = %peer, "WebSocket upgrade complete");
    session::run_session(ws_stream, config).await;

    // Decrement session count for this IP
    {
        let mut tracker = session_tracker.lock().await;
        if let Some(count) = tracker.get_mut(&ip) {
            *count -= 1;
            if *count == 0 {
                tracker.remove(&ip);
            }
        }
    }

    Ok(())
}

#[allow(clippy::result_large_err)]
fn check_subprotocol(req: &Request, mut resp: Response) -> Result<Response, ErrorResponse> {
    let has_rdows = req
        .headers()
        .get_all("Sec-WebSocket-Protocol")
        .iter()
        .any(|v| {
            v.to_str()
                .map(|s| s.split(',').any(|p| p.trim() == SUBPROTOCOL))
                .unwrap_or(false)
        });

    if !has_rdows {
        let mut err_resp = ErrorResponse::new(Some("missing rdows.v1 subprotocol".into()));
        *err_resp.status_mut() = http::StatusCode::BAD_REQUEST;
        return Err(err_resp);
    }

    resp.headers_mut().insert(
        "Sec-WebSocket-Protocol",
        http::HeaderValue::from_static(SUBPROTOCOL),
    );
    Ok(resp)
}

pub fn build_server_tls_config(
    cert_pem: &[u8],
    key_pem: &[u8],
) -> Result<Arc<rustls::ServerConfig>, Box<dyn std::error::Error>> {
    let certs: Vec<_> = rustls_pemfile::certs(&mut &*cert_pem).collect::<Result<Vec<_>, _>>()?;
    let key = rustls_pemfile::private_key(&mut &*key_pem)?
        .ok_or("no private key found")?;

    let mut config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)?;

    config.key_log = Arc::new(rustls::KeyLogFile::new());

    Ok(Arc::new(config))
}
