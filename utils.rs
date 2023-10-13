/// an uncompressed secp256k1 public key is 65 bytes, with a "raw" format
/// representing the last 64 bytes of the public key.
pub fn serialize_raw(pub_key: libsecp256k1::PublicKey) -> [u8; 64] {
    let mut raw: [u8; 64] = [0_u8; 64];
    raw.copy_from_slice(&pub_key.serialize()[1..]);
    raw
}

/// attempts to recover a public key in the raw format, returning Some(..) if a valid key was contained
pub fn recover_raw_pubkey(key: [u8; 64]) -> Option<libsecp256k1::PublicKey> {
    libsecp256k1::PublicKey::parse_slice(&key, Some(libsecp256k1::PublicKeyFormat::Raw)).ok()
}