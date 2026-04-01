use std::env;
use std::sync::Arc;

use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;
use tracing::info;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt::init();

    let args: Vec<String> = env::args().collect();
    let bind = get_arg(&args, "--bind").unwrap_or_else(|| "0.0.0.0:9443".to_string());
    let cert_path = get_arg(&args, "--cert").expect("--cert <path> required");
    let key_path = get_arg(&args, "--key").expect("--key <path> required");

    let cert_pem = std::fs::read(&cert_path)?;
    let key_pem = std::fs::read(&key_path)?;

    let tls_config = rdows_server::build_server_tls_config(&cert_pem, &key_pem)?;
    let acceptor = TlsAcceptor::from(Arc::clone(&tls_config));

    let listener = TcpListener::bind(&bind).await?;
    info!(bind = %bind, "starting RDoWS server");

    rdows_server::run_server(listener, acceptor).await;
    Ok(())
}

fn get_arg(args: &[String], flag: &str) -> Option<String> {
    args.iter()
        .position(|a| a == flag)
        .and_then(|i| args.get(i + 1).cloned())
}
