mod api;
mod kv;

use std::sync::Arc;

use tokio::net::TcpListener;
use tokio::sync::Mutex;
use tokio_rustls::TlsAcceptor;

use rdows_client::rdows_core::memory::AccessFlags;
use rdows_client::RdowsConnection;

use crate::kv::{KvStore, MR_SIZE, SLOT_SIZE};

struct Args {
    http_port: u16,
    rdows_port: u16,
    remote: Option<String>,
    cert: Option<String>,
    insecure: bool,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt::init();

    let args = parse_args();

    let (mut conn, rdows_url) = if let Some(ref remote_url) = args.remote {
        // Remote mode: connect to an existing RDoWS server
        let client_config = build_remote_tls_config(args.cert.as_deref(), args.insecure)?;
        println!("Connecting to remote RDoWS server: {remote_url}");
        let conn = RdowsConnection::connect(remote_url, client_config).await?;
        (conn, remote_url.clone())
    } else {
        // Embedded mode: start a local RDoWS server with ephemeral TLS
        let (conn, url) = start_embedded(args.rdows_port).await?;
        (conn, url)
    };

    let session_id = conn.session_id();

    // Register remote MR (hash table backing store)
    let remote_mr = conn
        .reg_mr(AccessFlags::REMOTE_WRITE | AccessFlags::REMOTE_READ, MR_SIZE)
        .await?;

    // Register local MR (staging buffer for one slot)
    let local_mr = conn
        .reg_mr(AccessFlags::LOCAL_WRITE, SLOT_SIZE as u64)
        .await?;

    let store = Arc::new(Mutex::new(KvStore::new(
        conn,
        session_id,
        remote_mr.rkey,
        local_mr.lkey,
    )));

    let app = api::router(store);

    println!("RDoWS KV server starting...");
    println!("  RDoWS server: {rdows_url}");
    println!("  Session: 0x{session_id:08X}");
    println!(
        "  Remote MR: R_Key=0x{:08X}, {} bytes ({} slots \u{00d7} {} bytes)",
        remote_mr.rkey.0, MR_SIZE, kv::SLOT_COUNT, SLOT_SIZE
    );
    println!("  HTTP UI: http://localhost:{}", args.http_port);
    println!();
    println!("Open http://localhost:{} in your browser.", args.http_port);

    let http_listener = TcpListener::bind(format!("0.0.0.0:{}", args.http_port)).await?;
    axum::serve(http_listener, app).await?;

    Ok(())
}

async fn start_embedded(
    rdows_port: u16,
) -> Result<(RdowsConnection, String), Box<dyn std::error::Error>> {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()])?;
    let cert_der = cert.cert.der().clone();
    let key_der = cert.key_pair.serialize_der();

    let mut server_config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(
            vec![cert_der.clone()],
            rustls::pki_types::PrivateKeyDer::Pkcs8(key_der.into()),
        )?;
    server_config.key_log = Arc::new(rustls::KeyLogFile::new());

    let mut root_store = rustls::RootCertStore::empty();
    root_store.add(cert_der)?;
    let mut client_config = rustls::ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();
    client_config.key_log = Arc::new(rustls::KeyLogFile::new());

    let rdows_listener = TcpListener::bind(format!("127.0.0.1:{rdows_port}")).await?;
    let rdows_addr = rdows_listener.local_addr()?;
    let acceptor = TlsAcceptor::from(Arc::new(server_config));

    tokio::spawn(async move {
        rdows_server::run_server(
            rdows_listener,
            acceptor,
            rdows_server::ServerConfig::default(),
        )
        .await;
    });

    let url = format!("wss://localhost:{}/rdows", rdows_addr.port());
    let conn = RdowsConnection::connect(&url, client_config).await?;
    Ok((conn, url))
}

fn build_remote_tls_config(
    cert_path: Option<&str>,
    insecure: bool,
) -> Result<rustls::ClientConfig, Box<dyn std::error::Error>> {
    if insecure {
        let config = rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(InsecureVerifier))
            .with_no_client_auth();
        return Ok(config);
    }

    let mut root_store = rustls::RootCertStore::empty();

    if let Some(path) = cert_path {
        let pem = std::fs::read(path)?;
        let certs: Vec<_> =
            rustls_pemfile::certs(&mut &*pem).collect::<Result<Vec<_>, _>>()?;
        for cert in certs {
            root_store.add(cert)?;
        }
    } else {
        let native = rustls_native_certs::load_native_certs();
        for cert in native.certs {
            let _ = root_store.add(cert);
        }
    }

    let mut config = rustls::ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();
    config.key_log = Arc::new(rustls::KeyLogFile::new());
    Ok(config)
}

#[derive(Debug)]
struct InsecureVerifier;

impl rustls::client::danger::ServerCertVerifier for InsecureVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        rustls::crypto::CryptoProvider::get_default()
            .map(|p| p.signature_verification_algorithms.supported_schemes())
            .unwrap_or_default()
    }
}

fn parse_args() -> Args {
    let args: Vec<String> = std::env::args().collect();
    let mut http_port: u16 = 8080;
    let mut rdows_port: u16 = 9443;
    let mut remote: Option<String> = None;
    let mut cert: Option<String> = None;
    let mut insecure = false;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--http-port" => {
                i += 1;
                http_port = args[i].parse().expect("invalid --http-port");
            }
            "--rdows-port" => {
                i += 1;
                rdows_port = args[i].parse().expect("invalid --rdows-port");
            }
            "--remote" => {
                i += 1;
                remote = Some(args[i].clone());
            }
            "--cert" => {
                i += 1;
                cert = Some(args[i].clone());
            }
            "--insecure" => {
                insecure = true;
            }
            _ => {
                eprintln!(
                    "Usage: rdows-kv [--http-port PORT] [--rdows-port PORT]\n\
                     \n\
                     Remote mode:\n  \
                       rdows-kv --remote wss://host:port/rdows [--cert ca.pem] [--insecure]"
                );
                std::process::exit(1);
            }
        }
        i += 1;
    }

    Args {
        http_port,
        rdows_port,
        remote,
        cert,
        insecure,
    }
}
