use alloy::primitives::{Address, B256};
use serde::{Deserialize, Serialize};

/// Extended registration data that gets bound to the attestation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExtendedRegistrationData {
    /// P-256 TLS public key (uncompressed, 65 bytes)
    pub tls_pubkey: Vec<u8>,
    /// Optional operator identifier
    pub operator_id: Option<String>,
    /// Optional configuration hash
    pub config_hash: Option<B256>,
}

impl ExtendedRegistrationData {
    pub fn new(tls_pubkey: Vec<u8>) -> Self {
        Self {
            tls_pubkey,
            operator_id: None,
            config_hash: None,
        }
    }

    /// Encode for on-chain registration
    pub fn encode(&self) -> Vec<u8> {
        // Simple encoding: just the TLS pubkey for MVP
        // In production, use ABI encoding
        self.tls_pubkey.clone()
    }
}

/// Registration info returned by indexer
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegistrationInfo {
    pub tee_address: Address,
    pub is_valid: bool,
    pub workload_id: B256,
    pub quote_hash: B256,
    pub tls_pubkey: Vec<u8>,
    pub extended_data: ExtendedRegistrationData,
}

/// API response for attestation query
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttestationResponse {
    pub found: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub registration: Option<RegistrationInfo>,
}
