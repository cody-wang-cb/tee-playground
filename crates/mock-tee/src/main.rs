use alloy::{
    network::EthereumWallet,
    primitives::{keccak256, Address, Bytes, B256},
    providers::ProviderBuilder,
    signers::local::PrivateKeySigner,
    sol,
};
use anyhow::Result;
use axum::{routing::get, Json, Router};
use clap::Parser;
use common::{ExtendedRegistrationData, MockQuote};
use rcgen::KeyPair;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use serde::Serialize;
use std::{net::SocketAddr, sync::Arc};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;
use tracing::{info, Level};
use tracing_subscriber::FmtSubscriber;

mod tls;

// Generate contract bindings
sol! {
    #[sol(rpc)]
    interface IFlashtestationRegistry {
        function registerTEEService(bytes calldata rawQuote, bytes calldata extendedRegistrationData) external payable;
        function getRegistration(address teeAddress) external view returns (bool isValid, RegisteredTEE memory registration);

        struct RegisteredTEE {
            bool isValid;
            bytes rawQuote;
            TD10ReportBody parsedReportBody;
            bytes extendedRegistrationData;
            bytes32 quoteHash;
        }

        struct TD10ReportBody {
            bytes16 teeTcbSvn;
            bytes mrSeam;
            bytes mrsignerSeam;
            bytes8 seamAttributes;
            bytes8 tdAttributes;
            bytes8 xFAM;
            bytes mrTd;
            bytes mrConfigId;
            bytes mrOwner;
            bytes mrOwnerConfig;
            bytes rtMr0;
            bytes rtMr1;
            bytes rtMr2;
            bytes rtMr3;
            bytes reportData;
        }
    }

    #[sol(rpc)]
    interface IBlockBuilderPolicy {
        function addWorkloadToPolicy(bytes32 workloadId, string calldata commitHash, string[] calldata sourceLocators) external;
        function isAllowedPolicy(address teeAddress) external view returns (bool allowed, bytes32 workloadId);
    }
}

#[derive(Parser, Debug)]
#[command(name = "mock-tee")]
#[command(about = "Mock TEE that registers with Flashtestation Registry")]
struct Args {
    /// RPC URL for the Ethereum node
    #[arg(long, default_value = "http://localhost:8545")]
    rpc_url: String,

    /// Registry contract address
    #[arg(long)]
    registry: Address,

    /// Policy contract address
    #[arg(long)]
    policy: Address,

    /// Private key for the TEE (will derive TEE address from this)
    /// Default is Anvil's first account
    #[arg(long, default_value = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80")]
    private_key: String,

    /// Port for the HTTPS server
    #[arg(long, default_value = "8443")]
    port: u16,

    /// Skip registration (useful if already registered)
    #[arg(long, default_value = "false")]
    skip_register: bool,

    /// Setup policy (add workload to policy)
    #[arg(long, default_value = "false")]
    setup_policy: bool,
}

#[derive(Clone)]
struct AppState {
    tee_address: Address,
    tls_pubkey: Vec<u8>,
    workload_id: B256,
}

#[derive(Serialize)]
struct StatusResponse {
    tee_address: String,
    tls_pubkey_hex: String,
    workload_id: String,
    status: String,
}

async fn status_handler(
    axum::extract::State(state): axum::extract::State<Arc<AppState>>,
) -> Json<StatusResponse> {
    Json(StatusResponse {
        tee_address: format!("{:?}", state.tee_address),
        tls_pubkey_hex: hex::encode(&state.tls_pubkey),
        workload_id: format!("{:?}", state.workload_id),
        status: "running".to_string(),
    })
}

async fn health_handler() -> &'static str {
    "OK"
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

    // Parse private key and create signer
    let private_key_bytes = hex::decode(args.private_key.trim_start_matches("0x"))?;
    let signer = PrivateKeySigner::from_bytes(&B256::from_slice(&private_key_bytes))?;
    let tee_address = signer.address();
    info!("TEE Address: {:?}", tee_address);

    // Generate TLS keypair (P-256 for standard TLS)
    let tls_key_pair = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)?;
    let tls_pubkey = tls_key_pair.public_key_raw().to_vec();
    info!("TLS Public Key: {}", hex::encode(&tls_pubkey));

    // Create extended registration data
    let ext_data = ExtendedRegistrationData::new(tls_pubkey.clone());
    let ext_data_encoded = ext_data.encode();
    let ext_data_hash = keccak256(&ext_data_encoded);
    info!("Extended Data Hash: {:?}", ext_data_hash);

    // Create mock quote
    let quote = MockQuote::new(tee_address, ext_data_hash);
    let workload_id = quote.workload_id();
    info!("Workload ID: {:?}", workload_id);

    // Setup provider with wallet
    let wallet = EthereumWallet::from(signer);
    let provider = ProviderBuilder::new()
        .wallet(wallet)
        .connect(&args.rpc_url)
        .await?;

    // Create contract instances
    let registry = IFlashtestationRegistry::new(args.registry, provider.clone());
    let policy = IBlockBuilderPolicy::new(args.policy, provider.clone());

    // Setup policy if requested (must be done by owner)
    if args.setup_policy {
        info!("Adding workload to policy...");
        let source_locators = vec!["https://github.com/example/mock-tee".to_string()];

        let tx = policy
            .addWorkloadToPolicy(workload_id, "mock-v1".to_string(), source_locators)
            .send()
            .await?
            .get_receipt()
            .await?;

        info!("Workload added to policy. Tx: {:?}", tx.transaction_hash);
    }

    // Register TEE
    if !args.skip_register {
        info!("Registering TEE with attestation...");

        let quote_bytes = Bytes::from(quote.to_bytes());
        let ext_data_bytes = Bytes::from(ext_data_encoded);

        let tx = registry
            .registerTEEService(quote_bytes, ext_data_bytes)
            .send()
            .await?
            .get_receipt()
            .await?;

        info!("TEE registered. Tx: {:?}", tx.transaction_hash);

        // Verify registration
        let result = registry.getRegistration(tee_address).call().await?;
        info!("Registration valid: {}", result.isValid);

        // Check policy
        let result = policy.isAllowedPolicy(tee_address).call().await?;
        info!("Policy allowed: {}", result.allowed);
    }

    // Generate self-signed certificate
    let cert = tls::generate_self_signed_cert(&tls_key_pair, tee_address)?;
    info!("Generated self-signed TLS certificate");

    // Setup TLS
    let cert_der = CertificateDer::from(cert.der().to_vec());
    let key_der = PrivateKeyDer::try_from(tls_key_pair.serialize_der()).unwrap();

    let tls_config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert_der], key_der)?;

    let acceptor = TlsAcceptor::from(Arc::new(tls_config));

    // Setup HTTP server with state
    let state = Arc::new(AppState {
        tee_address,
        tls_pubkey,
        workload_id,
    });

    let app = Router::new()
        .route("/status", get(status_handler))
        .route("/health", get(health_handler))
        .with_state(state);

    // Start HTTPS server
    let addr = SocketAddr::from(([0, 0, 0, 0], args.port));
    info!("Starting HTTPS server on {}", addr);

    let listener = TcpListener::bind(addr).await?;

    loop {
        let (stream, peer_addr) = listener.accept().await?;
        let acceptor = acceptor.clone();
        let app = app.clone();

        tokio::spawn(async move {
            match acceptor.accept(stream).await {
                Ok(tls_stream) => {
                    info!("TLS connection from {:?}", peer_addr);

                    let io = hyper_util::rt::TokioIo::new(tls_stream);

                    if let Err(e) = hyper_util::server::conn::auto::Builder::new(
                        hyper_util::rt::TokioExecutor::new(),
                    )
                    .serve_connection(io, hyper::service::service_fn(move |req| {
                        let app = app.clone();
                        async move {
                            use tower::ServiceExt;
                            app.oneshot(req).await
                        }
                    }))
                    .await
                    {
                        tracing::error!("Error serving connection: {:?}", e);
                    }
                }
                Err(e) => {
                    tracing::error!("TLS accept error: {:?}", e);
                }
            }
        });
    }
}
