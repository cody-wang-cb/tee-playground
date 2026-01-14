use rustls::{
    client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    pki_types::{CertificateDer, ServerName, UnixTime},
    DigitallySignedStruct, Error, SignatureScheme,
};
use std::fmt::Debug;

/// Custom TLS certificate verifier that checks the server's public key
/// matches the attested TLS public key from the Flashtestation Registry.
#[derive(Debug)]
pub struct AttestationVerifier {
    /// The expected TLS public key from the attestation (P-256 uncompressed)
    expected_pubkey: Vec<u8>,
}

impl AttestationVerifier {
    pub fn new(expected_pubkey: Vec<u8>) -> Self {
        Self { expected_pubkey }
    }

    /// Extract the public key from a DER-encoded certificate
    fn extract_pubkey_from_cert(&self, cert_der: &[u8]) -> Result<Vec<u8>, Error> {
        // Parse the certificate using x509-cert or manual parsing
        // For simplicity, we'll use a basic approach that works for P-256 certs

        // Look for the SubjectPublicKeyInfo OID for EC keys
        // OID 1.2.840.10045.2.1 (ecPublicKey) = 06 07 2A 86 48 CE 3D 02 01
        let ec_oid = [0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01];

        // Find the OID in the certificate
        if let Some(pos) = cert_der
            .windows(ec_oid.len())
            .position(|w| w == ec_oid)
        {
            // The public key should follow after the OID and curve OID
            // P-256 curve OID: 06 08 2A 86 48 CE 3D 03 01 07
            // Then BIT STRING with the actual key

            // Search for BIT STRING tag (03) followed by length and public key
            // P-256 uncompressed public key is 65 bytes (04 || x || y)
            for i in (pos + ec_oid.len())..cert_der.len().saturating_sub(66) {
                if cert_der[i] == 0x03 && cert_der[i + 1] == 0x42 && cert_der[i + 2] == 0x00 {
                    // Found BIT STRING with 65 bytes + 1 unused bits byte
                    let pubkey_start = i + 3;
                    let pubkey = cert_der[pubkey_start..pubkey_start + 65].to_vec();
                    return Ok(pubkey);
                }
            }
        }

        Err(Error::General("Could not extract public key from certificate".into()))
    }
}

impl ServerCertVerifier for AttestationVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, Error> {
        tracing::info!("Verifying server certificate against attestation...");

        // Extract public key from the certificate
        let cert_pubkey = self.extract_pubkey_from_cert(end_entity.as_ref())?;

        tracing::info!("Extracted pubkey: {} bytes", cert_pubkey.len());
        tracing::info!("Expected pubkey: {} bytes", self.expected_pubkey.len());

        // Compare with the attested public key
        if cert_pubkey == self.expected_pubkey {
            tracing::info!("Certificate public key matches attestation!");
            Ok(ServerCertVerified::assertion())
        } else {
            tracing::error!("Certificate public key does NOT match attestation!");
            tracing::error!("  Cert:     {}", hex::encode(&cert_pubkey));
            tracing::error!("  Expected: {}", hex::encode(&self.expected_pubkey));
            Err(Error::General(
                "Certificate public key does not match attested key".into(),
            ))
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &rustls::crypto::aws_lc_rs::default_provider().signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &rustls::crypto::aws_lc_rs::default_provider().signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        rustls::crypto::aws_lc_rs::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}
