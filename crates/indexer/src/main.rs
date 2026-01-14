use alloy::{
    primitives::{Address, B256},
    providers::{Provider, ProviderBuilder},
    rpc::types::Filter,
    sol,
    sol_types::SolEvent,
};
use anyhow::Result;
use axum::{
    extract::{Path, State},
    routing::get,
    Json, Router,
};
use clap::Parser;
use common::{AttestationResponse, RegistrationInfo, ExtendedRegistrationData};
use serde::Serialize;
use std::{
    collections::HashMap,
    sync::Arc,
};
use tokio::sync::RwLock;
use tracing::{info, Level};
use tracing_subscriber::FmtSubscriber;

// Contract event bindings
sol! {
    event TEEServiceRegistered(
        address indexed teeAddress,
        bytes32 indexed workloadId,
        bytes32 quoteHash
    );

    event TEEServiceInvalidated(
        address indexed teeAddress,
        bytes32 quoteHash
    );

    #[sol(rpc)]
    interface IFlashtestationRegistry {
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
}

#[derive(Parser, Debug)]
#[command(name = "indexer")]
#[command(about = "Indexes TEE registrations from Flashtestation Registry")]
struct Args {
    /// RPC URL for the Ethereum node
    #[arg(long, default_value = "http://localhost:8545")]
    rpc_url: String,

    /// Registry contract address
    #[arg(long)]
    registry: Address,

    /// Port for the HTTP API
    #[arg(long, default_value = "8080")]
    port: u16,

    /// Block to start indexing from
    #[arg(long, default_value = "0")]
    from_block: u64,
}

/// In-memory store for registrations
#[derive(Default)]
struct RegistrationStore {
    registrations: HashMap<Address, StoredRegistration>,
}

#[derive(Clone)]
struct StoredRegistration {
    tee_address: Address,
    workload_id: B256,
    quote_hash: B256,
    tls_pubkey: Vec<u8>,
    is_valid: bool,
}

type SharedStore = Arc<RwLock<RegistrationStore>>;

#[derive(Clone)]
struct AppState {
    store: SharedStore,
    registry: Address,
    rpc_url: String,
}

#[derive(Serialize)]
struct IndexerStatus {
    registry: String,
    registration_count: usize,
}

async fn status_handler(State(state): State<AppState>) -> Json<IndexerStatus> {
    let store = state.store.read().await;
    Json(IndexerStatus {
        registry: format!("{:?}", state.registry),
        registration_count: store.registrations.len(),
    })
}

async fn get_attestation(
    State(state): State<AppState>,
    Path(address): Path<String>,
) -> Json<AttestationResponse> {
    // Parse address
    let address = match address.parse::<Address>() {
        Ok(addr) => addr,
        Err(_) => {
            return Json(AttestationResponse {
                found: false,
                registration: None,
            });
        }
    };

    let store = state.store.read().await;

    match store.registrations.get(&address) {
        Some(reg) => Json(AttestationResponse {
            found: true,
            registration: Some(RegistrationInfo {
                tee_address: reg.tee_address,
                is_valid: reg.is_valid,
                workload_id: reg.workload_id,
                quote_hash: reg.quote_hash,
                tls_pubkey: reg.tls_pubkey.clone(),
                extended_data: ExtendedRegistrationData::new(reg.tls_pubkey.clone()),
            }),
        }),
        None => Json(AttestationResponse {
            found: false,
            registration: None,
        }),
    }
}

async fn list_registrations(State(state): State<AppState>) -> Json<Vec<RegistrationInfo>> {
    let store = state.store.read().await;

    let registrations: Vec<RegistrationInfo> = store
        .registrations
        .values()
        .map(|reg| RegistrationInfo {
            tee_address: reg.tee_address,
            is_valid: reg.is_valid,
            workload_id: reg.workload_id,
            quote_hash: reg.quote_hash,
            tls_pubkey: reg.tls_pubkey.clone(),
            extended_data: ExtendedRegistrationData::new(reg.tls_pubkey.clone()),
        })
        .collect();

    Json(registrations)
}

/// Index historical events
async fn index_historical_events(
    state: &AppState,
    from_block: u64,
) -> Result<()> {
    let provider = ProviderBuilder::new().connect(&state.rpc_url).await?;

    // Get current block
    let current_block = provider.get_block_number().await?;
    info!("Indexing from block {} to {}", from_block, current_block);

    // Build filter for TEEServiceRegistered events
    let filter = Filter::new()
        .address(state.registry)
        .event_signature(TEEServiceRegistered::SIGNATURE_HASH)
        .from_block(from_block)
        .to_block(current_block);

    let logs = provider.get_logs(&filter).await?;
    info!("Found {} registration events", logs.len());

    // Create registry contract instance
    let registry = IFlashtestationRegistry::new(state.registry, provider.clone());

    for log in logs {
        if let Ok(event) = TEEServiceRegistered::decode_log_data(log.data()) {
            let tee_address = event.teeAddress;
            let workload_id = event.workloadId;
            let quote_hash = event.quoteHash;

            // Fetch extended registration data from contract
            let tls_pubkey = match registry.getRegistration(tee_address).call().await {
                Ok(result) => {
                    // extendedRegistrationData contains the TLS pubkey
                    result.registration.extendedRegistrationData.to_vec()
                }
                Err(e) => {
                    tracing::warn!("Failed to fetch registration for {:?}: {:?}", tee_address, e);
                    vec![]
                }
            };

            let registration = StoredRegistration {
                tee_address,
                workload_id,
                quote_hash,
                tls_pubkey,
                is_valid: true,
            };

            let mut store = state.store.write().await;
            store.registrations.insert(tee_address, registration);

            info!("Indexed registration: {:?}", tee_address);
        }
    }

    // Also check for invalidations
    let filter = Filter::new()
        .address(state.registry)
        .event_signature(TEEServiceInvalidated::SIGNATURE_HASH)
        .from_block(from_block)
        .to_block(current_block);

    let logs = provider.get_logs(&filter).await?;

    for log in logs {
        if let Ok(event) = TEEServiceInvalidated::decode_log_data(log.data()) {
            let mut store = state.store.write().await;
            if let Some(reg) = store.registrations.get_mut(&event.teeAddress) {
                reg.is_valid = false;
                info!("Marked as invalid: {:?}", event.teeAddress);
            }
        }
    }

    Ok(())
}

/// Watch for new events
async fn watch_events(state: AppState) -> Result<()> {
    let provider = ProviderBuilder::new().connect(&state.rpc_url).await?;

    let mut last_block = provider.get_block_number().await?;

    loop {
        tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;

        let current_block = provider.get_block_number().await?;

        if current_block > last_block {
            // Check for new registration events
            let filter = Filter::new()
                .address(state.registry)
                .event_signature(TEEServiceRegistered::SIGNATURE_HASH)
                .from_block(last_block + 1)
                .to_block(current_block);

            let registry = IFlashtestationRegistry::new(state.registry, provider.clone());

            if let Ok(logs) = provider.get_logs(&filter).await {
                for log in logs {
                    if let Ok(event) = TEEServiceRegistered::decode_log_data(log.data()) {
                        // Fetch TLS pubkey from contract
                        let tls_pubkey = match registry.getRegistration(event.teeAddress).call().await {
                            Ok(result) => result.registration.extendedRegistrationData.to_vec(),
                            Err(_) => vec![],
                        };

                        let registration = StoredRegistration {
                            tee_address: event.teeAddress,
                            workload_id: event.workloadId,
                            quote_hash: event.quoteHash,
                            tls_pubkey,
                            is_valid: true,
                        };

                        let mut store = state.store.write().await;
                        store.registrations.insert(event.teeAddress, registration);

                        info!("New registration: {:?}", event.teeAddress);
                    }
                }
            }

            // Check for invalidations
            let filter = Filter::new()
                .address(state.registry)
                .event_signature(TEEServiceInvalidated::SIGNATURE_HASH)
                .from_block(last_block + 1)
                .to_block(current_block);

            if let Ok(logs) = provider.get_logs(&filter).await {
                for log in logs {
                    if let Ok(event) = TEEServiceInvalidated::decode_log_data(log.data()) {
                        let mut store = state.store.write().await;
                        if let Some(reg) = store.registrations.get_mut(&event.teeAddress) {
                            reg.is_valid = false;
                            info!("Invalidated: {:?}", event.teeAddress);
                        }
                    }
                }
            }

            last_block = current_block;
        }
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    // Setup logging
    let subscriber = FmtSubscriber::builder()
        .with_max_level(Level::INFO)
        .finish();
    tracing::subscriber::set_global_default(subscriber)?;

    let args = Args::parse();

    info!("Starting indexer for registry: {:?}", args.registry);

    let store = Arc::new(RwLock::new(RegistrationStore::default()));

    let state = AppState {
        store: store.clone(),
        registry: args.registry,
        rpc_url: args.rpc_url.clone(),
    };

    // Index historical events
    index_historical_events(&state, args.from_block).await?;

    // Start event watcher in background
    let watcher_state = state.clone();
    tokio::spawn(async move {
        if let Err(e) = watch_events(watcher_state).await {
            tracing::error!("Event watcher error: {:?}", e);
        }
    });

    // Setup HTTP API
    let app = Router::new()
        .route("/status", get(status_handler))
        .route("/attestation/{address}", get(get_attestation))
        .route("/registrations", get(list_registrations))
        .with_state(state);

    let addr = std::net::SocketAddr::from(([0, 0, 0, 0], args.port));
    info!("Starting HTTP API on {}", addr);

    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}
