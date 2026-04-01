use std::env;

use rdows_client::rdows_core::memory::AccessFlags;
use rdows_client::rdows_core::queue::ScatterGatherEntry;
use rdows_client::RdowsConnection;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt::init();

    let args: Vec<String> = env::args().collect();
    let url = get_arg(&args, "--url")
        .unwrap_or_else(|| "wss://localhost:9443/rdows".to_string());
    let cert_path = get_arg(&args, "--cert");

    let tls_config = build_tls_config(cert_path.as_deref())?;

    println!("Connecting to {url}...");
    let mut conn = RdowsConnection::connect(&url, tls_config).await?;
    println!("Session established (id: 0x{:08X})", conn.session_id());

    // Register remote MR with write + read access
    let remote_mr = conn
        .reg_mr(AccessFlags::REMOTE_WRITE | AccessFlags::REMOTE_READ, 4096)
        .await?;
    println!(
        "Remote MR registered: R_Key=0x{:08X}, size=4096",
        remote_mr.rkey.0
    );

    // Register local MR for source/sink
    let local_mr = conn.reg_mr(AccessFlags::LOCAL_WRITE, 4096).await?;

    // RDMA Write
    let payload = b"RDMA over WebSockets: because InfiniBand was too easy.";
    conn.write_local_mr(local_mr.lkey, 0, payload)?;

    println!("RDMA Write: {} bytes -> remote VA 0x0000", payload.len());
    conn.rdma_write(
        1,
        remote_mr.rkey,
        0,
        &[ScatterGatherEntry {
            lkey: local_mr.lkey,
            offset: 0,
            length: payload.len() as u32,
        }],
    )
    .await?;

    let cqes = conn.poll_cq(10);
    println!(
        "Write complete: status=0x{:04X}",
        cqes.first().map(|c| c.status).unwrap_or(0xFFFF)
    );

    // RDMA Read
    let read_mr = conn.reg_mr(AccessFlags::LOCAL_WRITE, 4096).await?;

    println!("RDMA Read: {} bytes <- remote VA 0x0000", payload.len());
    conn.rdma_read(2, remote_mr.rkey, 0, payload.len() as u64, read_mr.lkey, 0).await?;

    let cqes = conn.poll_cq(10);
    println!(
        "Read complete: status=0x{:04X}",
        cqes.first().map(|c| c.status).unwrap_or(0xFFFF)
    );

    let read_back = conn.read_local_mr(read_mr.lkey, 0, payload.len())?;
    println!("Data: {:?}", std::str::from_utf8(&read_back)?);
    assert_eq!(&read_back, payload);
    println!("Verification passed.");

    conn.disconnect().await?;
    println!("Disconnected.");
    Ok(())
}

fn build_tls_config(cert_path: Option<&str>) -> Result<rustls::ClientConfig, Box<dyn std::error::Error>> {
    let mut root_store = rustls::RootCertStore::empty();

    if let Some(path) = cert_path {
        // Load a PEM cert file (self-signed or custom CA)
        let pem = std::fs::read(path)?;
        let certs: Vec<_> = rustls_pemfile::certs(&mut &*pem).collect::<Result<Vec<_>, _>>()?;
        for cert in certs {
            root_store.add(cert)?;
        }
        println!("Loaded trust anchor from {path}");
    } else {
        // Use system roots
        let native = rustls_native_certs::load_native_certs();
        for cert in native.certs {
            let _ = root_store.add(cert);
        }
        println!("Using system trust store ({} roots)", root_store.len());
    }

    Ok(rustls::ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth())
}

fn get_arg(args: &[String], flag: &str) -> Option<String> {
    args.iter()
        .position(|a| a == flag)
        .and_then(|i| args.get(i + 1).cloned())
}
