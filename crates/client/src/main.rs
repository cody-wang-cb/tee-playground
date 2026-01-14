use anyhow::Result;
use clap::Parser;
use common::AttestationResponse;
use rustls::pki_types::ServerName;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use tracing::{info, Level};
use tracing_subscriber::FmtSubscriber;

mod verifier;

#[derive(Parser, Debug)]
#[command(name = "client")]
#[command(about = "Client that verifies TEE attestation via TLS")]
struct Args {
    /// Indexer URL
    #[arg(long, default_value = "http://localhost:8080")]
    indexer_url: String,

    /// TEE address to connect to
    #[arg(long)]
    tee_address: String,

    /// TEE host
    #[arg(long, default_value = "localhost")]
    tee_host: String,

    /// TEE port
    #[arg(long, default_value = "8443")]
    tee_port: u16,
}

#[tokio::main]
async fn main() -> Result<()> {
    // Install rustls crypto provider
    rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .expect("Failed to install rustls crypto provider");

    // Setup logging
    let subscriber = FmtSubscriber::builder()
        .with_max_level(Level::INFO)
        .finish();
    tracing::subscriber::set_global_default(subscriber)?;

    let args = Args::parse();

    info!("Fetching attestation for TEE: {}", args.tee_address);

    // Fetch attestation from indexer
    let client = reqwest::Client::new();
    let attestation_url = format!("{}/attestation/{}", args.indexer_url, args.tee_address);

    let response: AttestationResponse = client
        .get(&attestation_url)
        .send()
        .await?
        .json()
        .await?;

    if !response.found {
        anyhow::bail!("TEE not found in registry: {}", args.tee_address);
    }

    let registration = response.registration.unwrap();

    if !registration.is_valid {
        anyhow::bail!("TEE attestation is not valid");
    }

    info!("Attestation found:");
    info!("  TEE Address: {:?}", registration.tee_address);
    info!("  Workload ID: {:?}", registration.workload_id);
    info!("  TLS Pubkey: {} bytes", registration.tls_pubkey.len());

    // Create custom TLS verifier that checks against attested pubkey
    let verifier = verifier::AttestationVerifier::new(registration.tls_pubkey.clone());

    let config = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(verifier))
        .with_no_client_auth();

    let connector = TlsConnector::from(Arc::new(config));

    // Connect to TEE
    let addr = format!("{}:{}", args.tee_host, args.tee_port);
    info!("Connecting to TEE at {}", addr);

    let stream = TcpStream::connect(&addr).await?;
    let server_name = ServerName::try_from(args.tee_host.clone())?;

    let mut tls_stream = connector.connect(server_name, stream).await?;

    info!("TLS connection established and attestation verified!");

    // Send HTTP request
    let request = format!(
        "GET /status HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n",
        args.tee_host
    );

    tls_stream.write_all(request.as_bytes()).await?;

    // Read response
    let mut response = Vec::new();
    tls_stream.read_to_end(&mut response).await?;

    let response_str = String::from_utf8_lossy(&response);
    info!("Response from TEE:\n{}", response_str);

    Ok(())
}
