use sha3::Digest;
use solana_program::secp256k1_recover::Secp256k1Pubkey;

use crate::error::SSIError;
/// an uncompressed secp256k1 public key is 65 bytes, with a "raw" format
/// representing the last 64 bytes of the public key.
pub fn serialize_raw(pub_key: libsecp256k1::PublicKey) -> [u8; 64] {
    let mut raw: [u8; 64] = [0_u8; 64];
    raw.copy_from_slice(&pub_key.serialize()[1..]);
    raw
}

/// attempts to recover a public key in the raw format, returning Some(..) if a valid key was contained
pub fn recover_raw_pubkey(key: [u8; 64]) -> Result<libsecp256k1::PublicKey, SSIError> {
    Ok(libsecp256k1::PublicKey::parse_slice(
        &key,
        Some(libsecp256k1::PublicKeyFormat::Raw),
    )?)
}

/// returns Some(eth_pubkey) if the signed message was of type WalletType::Ethereum
pub fn construct_eth_pubkey(pub_key: &libsecp256k1::PublicKey) -> [u8; 20] {
    let mut addr = [0u8; 20];
    addr.copy_from_slice(&sha3::Keccak256::digest(&serialize_raw(*pub_key)[12..]));
    addr
}

pub fn convert_recovered_public_key(
    key: Secp256k1Pubkey,
) -> Result<libsecp256k1::PublicKey, SSIError> {
    let parsed_key =
        libsecp256k1::PublicKey::parse_slice(&key.0, Some(libsecp256k1::PublicKeyFormat::Raw))?;
    Ok(parsed_key)
}
