use sha3::Digest;
use solana_program::secp256k1_recover::Secp256k1Pubkey;

use crate::{error::SSIError, signed_message::{WalletType, ETH_KEY_GARBAGE}};
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
    addr.copy_from_slice(&sha3::Keccak256::digest(&pub_key.serialize()[1..])[12..]);
    addr
}

pub fn convert_recovered_public_key(
    key: Secp256k1Pubkey,
) -> Result<libsecp256k1::PublicKey, SSIError> {
    let parsed_key =
        libsecp256k1::PublicKey::parse_slice(&key.0, Some(libsecp256k1::PublicKeyFormat::Raw))?;
    Ok(parsed_key)
}

/// pad the right hand 12 bytes with the "ETH GARBAGE" value, for added security precautions
pub fn pad_eth_pubkey(pub_key_bytes: [u8; 20]) -> [u8; 32] {{
    // initialize with all 0's accomplishing the left padding of
    // the public key bytes by 12 bytes
    let mut output: [u8; 32] = [0_u8; 32];
    output[0..20].copy_from_slice(&pub_key_bytes);
    output[20..].copy_from_slice(&ETH_KEY_GARBAGE);
    output
}}

#[cfg(test)]
mod test {

    use super::*;
    fn test_key() -> Secp256k1Pubkey {
        let decoded = hex::decode("d8c858c1b940d1b057ed41a8b95c66c5e62eed8cf7c9b10427962acde766a454f996be64d75112b8da400c90bf3040c4598cea1a05e9adbe8a1789b2e39bf964").unwrap();
        let decoded = <[u8; 64]>::try_from(decoded).unwrap();
        Secp256k1Pubkey::new(&decoded)
    }

    fn convert_recovered() -> libsecp256k1::PublicKey {
        convert_recovered_public_key(test_key()).unwrap()
    }

    #[test]
    fn test_serialize_and_recover_raw() {
        let pk = convert_recovered();
        let raw_pk = serialize_raw(pk);
        let rec_raw_pk = recover_raw_pubkey(raw_pk).unwrap();
        assert_eq!(pk, rec_raw_pk);
    }
    #[test]
    fn test_construct_eth_pubkey() {
        const EXPECTED: &str = "bdff84f40d14d993a221859c2c5dcdc90305ab26";
        let pk = convert_recovered();
        let eth_pubkey = construct_eth_pubkey(&pk);
        assert_eq!(EXPECTED, hex::encode(eth_pubkey));
    }
    #[test]
    fn test_convert_recovered_public_key() {
        const EXPECTED: &str = "04d8c858c1b940d1b057ed41a8b95c66c5e62eed8cf7c9b10427962acde766a454f996be64d75112b8da400c90bf3040c4598cea1a05e9adbe8a1789b2e39bf964";
        let pk = convert_recovered();
        assert_eq!(EXPECTED, hex::encode(pk.serialize()));
    }
}
