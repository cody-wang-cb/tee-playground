use alloy::primitives::{keccak256, Address, B256};
use serde::{Deserialize, Serialize};
use serde_with::{serde_as, Bytes};

/// Quote header size (simplified)
pub const HEADER_LENGTH: usize = 48;
/// TD10 Report Body size
pub const TD_REPORT10_LENGTH: usize = 584;
/// Total quote size (header + report + mock signature)
pub const MOCK_QUOTE_LENGTH: usize = HEADER_LENGTH + TD_REPORT10_LENGTH + 64;

/// TD10 Report Body structure matching the Solidity contract
#[serde_as]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TD10ReportBody {
    #[serde_as(as = "Bytes")]
    pub tee_tcb_svn: [u8; 16],
    #[serde_as(as = "Bytes")]
    pub mr_seam: [u8; 48],
    #[serde_as(as = "Bytes")]
    pub mrsigner_seam: [u8; 48],
    #[serde_as(as = "Bytes")]
    pub seam_attributes: [u8; 8],
    #[serde_as(as = "Bytes")]
    pub td_attributes: [u8; 8],
    #[serde_as(as = "Bytes")]
    pub x_fam: [u8; 8],
    #[serde_as(as = "Bytes")]
    pub mr_td: [u8; 48],
    #[serde_as(as = "Bytes")]
    pub mr_config_id: [u8; 48],
    #[serde_as(as = "Bytes")]
    pub mr_owner: [u8; 48],
    #[serde_as(as = "Bytes")]
    pub mr_owner_config: [u8; 48],
    #[serde_as(as = "Bytes")]
    pub rt_mr0: [u8; 48],
    #[serde_as(as = "Bytes")]
    pub rt_mr1: [u8; 48],
    #[serde_as(as = "Bytes")]
    pub rt_mr2: [u8; 48],
    #[serde_as(as = "Bytes")]
    pub rt_mr3: [u8; 48],
    #[serde_as(as = "Bytes")]
    pub report_data: [u8; 64],
}

impl Default for TD10ReportBody {
    fn default() -> Self {
        Self {
            tee_tcb_svn: [0u8; 16],
            mr_seam: [0u8; 48],
            mrsigner_seam: [0u8; 48],
            seam_attributes: [0u8; 8],
            td_attributes: [0u8; 8],
            x_fam: [0u8; 8],
            mr_td: [0u8; 48],
            mr_config_id: [0u8; 48],
            mr_owner: [0u8; 48],
            mr_owner_config: [0u8; 48],
            rt_mr0: [0u8; 48],
            rt_mr1: [0u8; 48],
            rt_mr2: [0u8; 48],
            rt_mr3: [0u8; 48],
            report_data: [0u8; 64],
        }
    }
}

impl TD10ReportBody {
    /// Create report body with TEE address and extended data hash in report_data
    pub fn with_report_data(mut self, tee_address: Address, ext_data_hash: B256) -> Self {
        // report_data[0:20] = tee_address
        self.report_data[..20].copy_from_slice(tee_address.as_slice());
        // report_data[20:52] = ext_data_hash
        self.report_data[20..52].copy_from_slice(ext_data_hash.as_slice());
        self
    }

    /// Compute workload ID matching the Solidity contract
    pub fn workload_id(&self) -> B256 {
        let mut data = Vec::with_capacity(48 * 6 + 8 + 8);
        data.extend_from_slice(&self.mr_td);
        data.extend_from_slice(&self.rt_mr0);
        data.extend_from_slice(&self.rt_mr1);
        data.extend_from_slice(&self.rt_mr2);
        data.extend_from_slice(&self.rt_mr3);
        data.extend_from_slice(&self.mr_config_id);
        data.extend_from_slice(&self.x_fam);
        data.extend_from_slice(&self.td_attributes);
        keccak256(&data)
    }

    /// Serialize to bytes (584 bytes)
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(TD_REPORT10_LENGTH);
        bytes.extend_from_slice(&self.tee_tcb_svn);
        bytes.extend_from_slice(&self.mr_seam);
        bytes.extend_from_slice(&self.mrsigner_seam);
        bytes.extend_from_slice(&self.seam_attributes);
        bytes.extend_from_slice(&self.td_attributes);
        bytes.extend_from_slice(&self.x_fam);
        bytes.extend_from_slice(&self.mr_td);
        bytes.extend_from_slice(&self.mr_config_id);
        bytes.extend_from_slice(&self.mr_owner);
        bytes.extend_from_slice(&self.mr_owner_config);
        bytes.extend_from_slice(&self.rt_mr0);
        bytes.extend_from_slice(&self.rt_mr1);
        bytes.extend_from_slice(&self.rt_mr2);
        bytes.extend_from_slice(&self.rt_mr3);
        bytes.extend_from_slice(&self.report_data);
        bytes
    }

    /// Parse from bytes
    pub fn from_bytes(data: &[u8]) -> anyhow::Result<Self> {
        if data.len() < TD_REPORT10_LENGTH {
            anyhow::bail!("Data too short for TD10ReportBody");
        }

        let mut body = Self::default();
        let mut offset = 0;

        body.tee_tcb_svn.copy_from_slice(&data[offset..offset + 16]);
        offset += 16;
        body.mr_seam.copy_from_slice(&data[offset..offset + 48]);
        offset += 48;
        body.mrsigner_seam.copy_from_slice(&data[offset..offset + 48]);
        offset += 48;
        body.seam_attributes.copy_from_slice(&data[offset..offset + 8]);
        offset += 8;
        body.td_attributes.copy_from_slice(&data[offset..offset + 8]);
        offset += 8;
        body.x_fam.copy_from_slice(&data[offset..offset + 8]);
        offset += 8;
        body.mr_td.copy_from_slice(&data[offset..offset + 48]);
        offset += 48;
        body.mr_config_id.copy_from_slice(&data[offset..offset + 48]);
        offset += 48;
        body.mr_owner.copy_from_slice(&data[offset..offset + 48]);
        offset += 48;
        body.mr_owner_config.copy_from_slice(&data[offset..offset + 48]);
        offset += 48;
        body.rt_mr0.copy_from_slice(&data[offset..offset + 48]);
        offset += 48;
        body.rt_mr1.copy_from_slice(&data[offset..offset + 48]);
        offset += 48;
        body.rt_mr2.copy_from_slice(&data[offset..offset + 48]);
        offset += 48;
        body.rt_mr3.copy_from_slice(&data[offset..offset + 48]);
        offset += 48;
        body.report_data.copy_from_slice(&data[offset..offset + 64]);

        Ok(body)
    }

    /// Extract TEE address from report_data[0:20]
    pub fn tee_address(&self) -> Address {
        Address::from_slice(&self.report_data[..20])
    }

    /// Extract extended data hash from report_data[20:52]
    pub fn ext_data_hash(&self) -> B256 {
        B256::from_slice(&self.report_data[20..52])
    }
}

/// Mock TDX Quote structure
#[derive(Debug, Clone)]
pub struct MockQuote {
    pub header: [u8; HEADER_LENGTH],
    pub report_body: TD10ReportBody,
    pub signature: [u8; 64], // Mock signature
}

impl MockQuote {
    /// Create a new mock quote with default measurements
    pub fn new(tee_address: Address, ext_data_hash: B256) -> Self {
        // Create deterministic mock measurements
        let report_body = Self::default_measurements().with_report_data(tee_address, ext_data_hash);

        Self {
            header: Self::mock_header(),
            report_body,
            signature: [0u8; 64],
        }
    }

    /// Create a mock quote with custom measurements
    pub fn with_measurements(measurements: TD10ReportBody) -> Self {
        Self {
            header: Self::mock_header(),
            report_body: measurements,
            signature: [0u8; 64],
        }
    }

    /// Default mock measurements (deterministic for testing)
    pub fn default_measurements() -> TD10ReportBody {
        let mut body = TD10ReportBody::default();

        // Use deterministic values derived from "mock-tee-v1"
        let seed = keccak256(b"mock-tee-v1");
        body.mr_td[..32].copy_from_slice(seed.as_slice());
        body.mr_td[32..48].copy_from_slice(&seed.as_slice()[..16]);

        let seed = keccak256(b"mock-rtmr0");
        body.rt_mr0[..32].copy_from_slice(seed.as_slice());
        body.rt_mr0[32..48].copy_from_slice(&seed.as_slice()[..16]);

        let seed = keccak256(b"mock-rtmr1");
        body.rt_mr1[..32].copy_from_slice(seed.as_slice());
        body.rt_mr1[32..48].copy_from_slice(&seed.as_slice()[..16]);

        let seed = keccak256(b"mock-rtmr2");
        body.rt_mr2[..32].copy_from_slice(seed.as_slice());
        body.rt_mr2[32..48].copy_from_slice(&seed.as_slice()[..16]);

        let seed = keccak256(b"mock-rtmr3");
        body.rt_mr3[..32].copy_from_slice(seed.as_slice());
        body.rt_mr3[32..48].copy_from_slice(&seed.as_slice()[..16]);

        let seed = keccak256(b"mock-config-id");
        body.mr_config_id[..32].copy_from_slice(seed.as_slice());
        body.mr_config_id[32..48].copy_from_slice(&seed.as_slice()[..16]);

        // Set some realistic attributes
        body.td_attributes = [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01];
        body.x_fam = [0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];

        body
    }

    fn mock_header() -> [u8; HEADER_LENGTH] {
        let mut header = [0u8; HEADER_LENGTH];
        // TDX quote version (4)
        header[0..2].copy_from_slice(&4u16.to_le_bytes());
        // Attestation key type (ECDSA-256)
        header[2..4].copy_from_slice(&2u16.to_le_bytes());
        // TEE type (TDX = 0x81)
        header[4..8].copy_from_slice(&0x81u32.to_le_bytes());
        header
    }

    /// Serialize to bytes for on-chain submission
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(MOCK_QUOTE_LENGTH);
        bytes.extend_from_slice(&self.header);
        bytes.extend_from_slice(&self.report_body.to_bytes());
        bytes.extend_from_slice(&self.signature);
        bytes
    }

    /// Get the workload ID for this quote
    pub fn workload_id(&self) -> B256 {
        self.report_body.workload_id()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_report_body_serialization() {
        let body = MockQuote::default_measurements();
        let bytes = body.to_bytes();
        assert_eq!(bytes.len(), TD_REPORT10_LENGTH);

        let parsed = TD10ReportBody::from_bytes(&bytes).unwrap();
        assert_eq!(parsed.mr_td, body.mr_td);
        assert_eq!(parsed.workload_id(), body.workload_id());
    }

    #[test]
    fn test_mock_quote() {
        let tee_addr = Address::repeat_byte(0x42);
        let ext_hash = B256::repeat_byte(0x11);

        let quote = MockQuote::new(tee_addr, ext_hash);
        let bytes = quote.to_bytes();

        assert_eq!(bytes.len(), MOCK_QUOTE_LENGTH);
        assert_eq!(quote.report_body.tee_address(), tee_addr);
        assert_eq!(quote.report_body.ext_data_hash(), ext_hash);
    }
}
