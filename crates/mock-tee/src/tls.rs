use alloy::primitives::Address;
use anyhow::Result;
use rcgen::{Certificate, CertificateParams, DnType, KeyPair};

/// Generate a self-signed certificate for the TEE
pub fn generate_self_signed_cert(key_pair: &KeyPair, tee_address: Address) -> Result<Certificate> {
    let mut params = CertificateParams::default();

    // Set subject with TEE address for identification
    params.distinguished_name.push(
        DnType::CommonName,
        format!("TEE-{}", hex::encode(tee_address.as_slice())),
    );
    params
        .distinguished_name
        .push(DnType::OrganizationName, "Mock TEE");

    // Add Subject Alternative Names
    params.subject_alt_names = vec![
        rcgen::SanType::DnsName("localhost".try_into()?),
        rcgen::SanType::IpAddress(std::net::IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1))),
    ];

    // Generate certificate
    let cert = params.self_signed(key_pair)?;

    Ok(cert)
}
