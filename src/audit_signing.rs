use anyhow::{anyhow, Result};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand_core::OsRng;
use serde::{Deserialize, Serialize};
use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AuditSignatureAlgorithm {
    Ed25519LocalV1,
    DevEd25519V1,
    ReservedExternalKmsV1,
    ReservedHsmV1,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct AuditSigningKeyId(pub String);

impl fmt::Display for AuditSigningKeyId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditPublicKeyRecord {
    pub key_id: AuditSigningKeyId,
    pub algorithm: AuditSignatureAlgorithm,
    pub public_key: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditSignatureRecord {
    pub key_id: AuditSigningKeyId,
    pub algorithm: AuditSignatureAlgorithm,
    pub signature: Vec<u8>,
}

pub trait AuditSigner {
    fn key_id(&self) -> AuditSigningKeyId;
    fn algorithm(&self) -> AuditSignatureAlgorithm;
    fn public_key_record(&self) -> AuditPublicKeyRecord;
    fn sign(&self, payload: &[u8]) -> Result<AuditSignatureRecord>;
}

pub struct DevAuditSigner {
    key_id: AuditSigningKeyId,
    signing_key: SigningKey,
}

impl DevAuditSigner {
    pub fn new(key_id: String) -> Result<Self> {
        if std::env::var("TUFF_CSE_WINFS_ALLOW_DEV_AUDIT_SIGNER").is_err() {
            return Err(anyhow!("Dev audit signer not allowed"));
        }
        let mut csprng = OsRng;
        let signing_key = SigningKey::generate(&mut csprng);
        Ok(Self {
            key_id: AuditSigningKeyId(key_id),
            signing_key,
        })
    }
}

impl AuditSigner for DevAuditSigner {
    fn key_id(&self) -> AuditSigningKeyId {
        self.key_id.clone()
    }
    fn algorithm(&self) -> AuditSignatureAlgorithm {
        AuditSignatureAlgorithm::DevEd25519V1
    }
    fn public_key_record(&self) -> AuditPublicKeyRecord {
        AuditPublicKeyRecord {
            key_id: self.key_id.clone(),
            algorithm: self.algorithm(),
            public_key: self.signing_key.verifying_key().to_bytes().to_vec(),
        }
    }
    fn sign(&self, payload: &[u8]) -> Result<AuditSignatureRecord> {
        let signature = self.signing_key.sign(payload);
        Ok(AuditSignatureRecord {
            key_id: self.key_id.clone(),
            algorithm: self.algorithm(),
            signature: signature.to_vec(),
        })
    }
}

pub fn verify_signature(
    record: &AuditSignatureRecord,
    public_key_bytes: &[u8],
    payload: &[u8],
) -> Result<bool> {
    match record.algorithm {
        AuditSignatureAlgorithm::Ed25519LocalV1 | AuditSignatureAlgorithm::DevEd25519V1 => {
            let verifying_key = VerifyingKey::from_bytes(
                public_key_bytes
                    .try_into()
                    .map_err(|_| anyhow!("Invalid public key size"))?,
            )?;
            let signature = Signature::from_bytes(
                record
                    .signature
                    .as_slice()
                    .try_into()
                    .map_err(|_| anyhow!("Invalid signature size"))?,
            );
            Ok(verifying_key.verify(payload, &signature).is_ok())
        }
        _ => Err(anyhow!("Unsupported signature algorithm")),
    }
}
