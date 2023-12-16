use solana_program::{program_error::ProgramError, secp256k1_recover::Secp256k1RecoverError};
use thiserror::Error;

use crate::signed_message::WalletType;

#[derive(Error, Debug, PartialEq, Eq)]
pub enum SSIError {
    /// an error return when the message hash input does not match
    /// the expected hash. expected hash is usually the hash
    /// returned by the program manually encoding the instruction during
    /// verification
    #[error("invalid hash. input {input:?}, expected {expected:?}")]
    InvalidMessageHash { input: [u8; 32], expected: [u8; 32] },
    #[error("signature  recovery failed {0}")]
    SignatureRecoveryFailure(#[from] Secp256k1RecoverError),
    #[error("libsecp256k1 encountered error {0}")]
    Secp256k1Error(#[from] libsecp256k1::Error),
    #[error("signature is malleable, see secp256k1_recover docs")]
    SignatureMalleabilityError,
    #[error("when constructing a key, a mismatch took place {0}")]
    CompareAndConstructMismatchedKey(String),
    #[error("wallet type expected to be eth not {0}")]
    NonEthWallet(WalletType),
    #[error("the specified wallet type is unsupported")]
    UnsupportedWalletType,
}

impl From<SSIError> for ProgramError {
    fn from(value: SSIError) -> Self {
        let err_msg = value.to_string();
        solana_program::log::sol_log(&err_msg);
        Self::BorshIoError(err_msg)
    }
}
