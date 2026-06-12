use std::fmt;
use zeroize::{Zeroize, ZeroizeOnDrop};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RuntimeSecretKind {
    PlaceholderUnlockMaterial,
    ReservedMasterKey,
    ReservedTokenKey,
    ReservedPairingKey,
}

#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SecureRuntimeBuffer {
    buffer: Vec<u8>,
}

impl SecureRuntimeBuffer {
    /// Creates a new buffer for test/dev placeholder bytes only.
    /// Real MK/TK/PK creation is prohibited in P2C.
    pub fn new_placeholder(kind: RuntimeSecretKind, bytes: Vec<u8>) -> Result<Self, &'static str> {
        match kind {
            RuntimeSecretKind::PlaceholderUnlockMaterial => Ok(Self { buffer: bytes }),
            _ => Err("Creation of real or reserved secret keys is prohibited in P2C."),
        }
    }

    pub fn test_only_len(&self) -> usize {
        self.buffer.len()
    }

    pub fn test_only_is_zeroized(&self) -> bool {
        self.buffer.iter().all(|&b| b == 0)
    }
}

impl fmt::Debug for SecureRuntimeBuffer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SecureRuntimeBuffer(<SECRET_REDACTED>)")
    }
}
