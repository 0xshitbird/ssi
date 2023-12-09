use libsecp256k1::{RecoveryId, Signature};
use solana_program::{pubkey::Pubkey, secp256k1_recover::Secp256k1Pubkey};

use crate::{
    error::SSIError,
    utils::{construct_eth_pubkey, serialize_raw},
};

use {
    borsh::{BorshDeserialize, BorshSerialize},
    sha3::Digest,
};

/// special garbage data added to eth keys to occupy 32 bytes
pub const ETH_KEY_GARBAGE: [u8; 12] = [6, 9, 4, 2, 0, 1, 3, 3, 7, 6, 6, 6];

/// a trait which must be implemented by instructions that wish to provide support for gasless transaction relaying
pub trait SignedInstruction: SignedInstructionSerializoor {
    /// encodes the signed instruction, which involves serializing the instruction and then hashing the serialized bytes
    fn encode(&self) -> [u8; 32];
    /// signs the instruction to be relayed, and executed by a compatible program
    /// 1) encode (serialize -> hash)
    /// 2) sign hashed message
    /// 3) return signature
    /// 
    /// to convert the signature into the format accepted by the SSI standard, call: `signature.serialize()`
    /// to convert the recoveryId into the format accepted by the SSI stadanrd, call `recovery_id.serialize()`
    fn sign(&self, key: libsecp256k1::SecretKey) -> Result<(Signature, RecoveryId), SSIError>;
    /// signs the instruction, generating the signed message bundle that must be submitted
    /// to the the gasless relayer. This allows for concise representation of the instruction
    /// which was signed, allowing a program to reconstruct the signature based on instruction data.
    ///
    /// returns None if conversion failed, usually due to public key encoding issues
    fn into_signed_message(&self, opts: SignedMessageOpts) -> Option<SignedMessage>;
    /// recovers the public key which was used to sign the given message, performing
    /// message verification in the process.
    ///
    /// it is EXTREMELY important you validate the signed message matches up as expected
    /// as it is assumed that if the message is invalid, this returns an error
    fn recover_signer(&self, signed_message: SignedMessage) -> Result<Secp256k1Pubkey, SSIError>;
    /// helper function which is used to convert the public key recovered during
    /// signature verification
    fn convert_recovered_public_key(
        key: Secp256k1Pubkey,
    ) -> Result<libsecp256k1::PublicKey, SSIError>;
}

/// a trait which serializes an instruction into bytes, usually through borsh serialization
pub trait SignedInstructionSerializoor {
    /// perform serialization against the implementing type converting it into raw bytes
    fn serialize(&self) -> Vec<u8>;
}

/// options type struct for use by the SignedInstruction trait
#[derive(Clone, Copy)]
pub struct SignedMessageOpts {
    pub signature: [u8; 64],
    pub recovery_id: u8,
    pub signing_wallet_type: WalletType,
    pub pub_key: libsecp256k1::PublicKey,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, BorshSerialize, BorshDeserialize,)]
pub struct SignedMessage {
    /// this is the signature which was returned from signing the message_hash
    pub signature: [u8; 64],
    /// this is the hash of the serialized instruction which is being signed
    pub message_hash: [u8; 32],
    /// the public key which was responsible for generating the signature
    pub wallet_pubkey: [u8; 32],
    /// recovery id from the secp256k1_recover operation
    pub recovery_id: u8,
}

/// to prevent issues with wallet types requiring different amount of space
/// just allocate a fixed 32 bytes per wallet
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WalletType {
    Ethereum = 0,
    Solana = 1,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct WalletInfo {
    pub wallet_type: WalletType,
    pub raw_public_key: [u8; 64],
}

impl SignedMessage {
    /// constructs an eth public key from the input_key, validating
    /// that it is the same one referenced by the signed message.
    ///
    /// the input_key must be in RAW form
    ///
    /// this compares the constructed public key derived from the input_key against
    /// the first 20 bytes of Self::wallet_pubkey, so it may also pass for
    /// non ethereum keys.
    ///
    /// as such callers must be sure this is used only where appropriate
    ///
    /// this does some additional verification by converting input_key -> pubkey -> raw serialize -> construct
    pub fn compare_and_construct_eth_pubkey(
        &self,
        wallet: WalletInfo,
    ) -> Result<[u8; 20], SSIError> {
        wallet.construct_eth_pubkey(self.wallet_pubkey)
    }
}

impl WalletInfo {
    pub fn construct_eth_pubkey(&self, wallet_pubkey: [u8; 32]) -> Result<[u8; 20], SSIError> {
        match self.wallet_type {
            WalletType::Ethereum => (),
            _ => return Err(SSIError::NonEthWallet(self.wallet_type)),
        };
        // recover the libsecp256k1 key from the wallet's raw public key
        let recovered_key = crate::utils::recover_raw_pubkey(self.raw_public_key)?;
        // encode the recovered key into an ethereum key, with an additional 12 bytes of garbage data
        let constructed_key = self.wallet_type.encode_key(recovered_key);
        // validate the garbage
        if constructed_key[20..32].ne(&ETH_KEY_GARBAGE) {
            return Err(SSIError::CompareAndConstructMismatchedKey(
                "garbage mismatch".to_string(),
            ));
        }
        // this is an ethereum wallet, so only compare the first 20 bytes of actual data
        if wallet_pubkey[0..20].ne(&constructed_key[0..20]) {
            // invalid key
            return Err(SSIError::CompareAndConstructMismatchedKey(
                "reconstruction failed".to_string(),
            ));
        }
        // copy the first 20 bytes
        let mut parsed_key: [u8; 20] = [0_u8; 20];
        parsed_key.copy_from_slice(&constructed_key[0..20]);
        Ok(parsed_key)
    }
}

impl WalletType {
    pub const fn pubkey_length(self) -> usize {
        match self {
            Self::Ethereum => 20,
            Self::Solana => 32,
        }
    }
    /// based on the wallet type, encode the public key. returns NOne
    /// if encoding failed
    pub fn encode_key(&self, key: libsecp256k1::PublicKey) -> [u8; 32] {
        match self {
            Self::Ethereum => {
                let k = construct_eth_pubkey(&key);
                let mut kk: [u8; 32] = [0_u8; 32];
                // eth keys only use the first 20 bytes when encoded
                kk[0..20].copy_from_slice(&k[..]);
                // write garbage data to the final bytes
                kk[20..32].copy_from_slice(&[6, 9, 4, 2, 0, 1, 3, 3, 7, 6, 6, 6][..]);
                kk
            }
            Self::Solana => unimplemented!("functionality not available for solana keys"),
        }
    }
}

/// NOTE: this sets the `message_hash` field of SignedMessage
/// to `[9_u8; 32]`, please make sure to update the field after this function returns
///
/// only currently works for ethereum keys
impl From<SignedMessageOpts> for SignedMessage {
    fn from(value: SignedMessageOpts) -> Self {
        let wallet_pubkey = value.signing_wallet_type.encode_key(value.pub_key);
        SignedMessage {
            signature: value.signature,
            message_hash: [9_u8; 32],
            wallet_pubkey,
            recovery_id: value.recovery_id,
        }
    }
}

impl From<u8> for WalletType {
    fn from(value: u8) -> Self {
        match value {
            0 => Self::Ethereum,
            1 => Self::Solana,
            _ => unimplemented!("not supported"),
        }
    }
}

impl std::fmt::Display for WalletType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("WalletType(")?;
        match self {
            Self::Ethereum => f.write_str("ethereum"),
            Self::Solana => f.write_str("solana"),
        }?;
        f.write_str(")")
    }
}

impl Default for SignedMessage {
    fn default() -> Self {
        Self {
            signature: [0_u8; 64],
            message_hash: [0_u8; 32],
            wallet_pubkey: [0_u8; 32],
            recovery_id: 0
        }
    }
}

#[cfg(test)]
mod test {
    use crate::utils::convert_recovered_public_key;

    use super::*;

    struct SignedInstructionSerializoorTest {}

    impl SignedInstructionSerializoor for SignedInstructionSerializoorTest {
        fn serialize(&self) -> Vec<u8> {
            ETH_KEY_GARBAGE.to_vec()
        }
    }
    fn test_key() -> Secp256k1Pubkey {
        let decoded = hex::decode("d8c858c1b940d1b057ed41a8b95c66c5e62eed8cf7c9b10427962acde766a454f996be64d75112b8da400c90bf3040c4598cea1a05e9adbe8a1789b2e39bf964").unwrap();
        let decoded = <[u8; 64]>::try_from(decoded).unwrap();
        Secp256k1Pubkey::new(&decoded)
    }
    #[test]
    fn test_eth_garbage() {
        assert_eq!(ETH_KEY_GARBAGE, [6, 9, 4, 2, 0, 1, 3, 3, 7, 6, 6, 6]);
    }

    #[test]
    fn test_signed_instruction_serializoor() {
        assert_eq!(
            SignedInstructionSerializoorTest {}.serialize(),
            ETH_KEY_GARBAGE.to_vec()
        );
    }

    #[test]
    fn test_signed_message_compare_and_construct_eth_pubkey() {
        let key = test_key();
        let pub_key = convert_recovered_public_key(key).unwrap();
        let pub_key_part = construct_eth_pubkey(&pub_key);
        let mut pub_key_data: [u8; 32] = [0_u8; 32];
        pub_key_data[0..20].copy_from_slice(&pub_key_part);

        let s_msg = SignedMessage {
            signature: [9_u8; 64],
            message_hash: [6_u8; 32],
            wallet_pubkey: pub_key_data,
            recovery_id: 1,
        };

        let constructed_key = s_msg
            .compare_and_construct_eth_pubkey(WalletInfo {
                wallet_type: WalletType::Ethereum,
                raw_public_key: serialize_raw(pub_key),
            })
            .unwrap();

        assert_eq!(constructed_key, pub_key_part);

        // solana wallet shouldnt be usable in this code
        assert!(s_msg
            .compare_and_construct_eth_pubkey(WalletInfo {
                wallet_type: WalletType::Solana,
                raw_public_key: serialize_raw(pub_key)
            })
            .is_err());
    }

    #[test]
    fn test_wallet_type_pubkey_length() {
        assert_eq!(WalletType::Ethereum.pubkey_length(), 20);
        assert_eq!(WalletType::Solana.pubkey_length(), 32);
    }

    #[test]
    fn test_wallet_type_encode_key() {
        const EXPECTED: &str = "bdff84f40d14d993a221859c2c5dcdc90305ab26";
        let key = test_key();
        let pk = convert_recovered_public_key(key).unwrap();
        let enc_key = WalletType::Ethereum.encode_key(pk);
        assert_eq!(EXPECTED, hex::encode(&enc_key[0..20]));
        assert_eq!(enc_key[20..32], ETH_KEY_GARBAGE);
    }
    #[test]
    fn test_from_signed_message_to_message_opts() {
        let key = test_key();
        let pub_key = convert_recovered_public_key(key).unwrap();
        let enc_key = WalletType::Ethereum.encode_key(pub_key);

        // the signed message we are expecting
        let s_msg = SignedMessage {
            signature: [69_u8; 64],
            message_hash: [9_u8; 32],
            wallet_pubkey: enc_key,
            recovery_id: 1,
        };
        let s_opts = SignedMessageOpts {
            signature: s_msg.signature,
            signing_wallet_type: WalletType::Ethereum,
            recovery_id: s_msg.recovery_id,
            pub_key: pub_key,
        };
        let s_msg2: SignedMessage = s_opts.into();
        assert_eq!(s_msg, s_msg2);
    }
    #[test]
    fn test_display_wallet_type() {
        let disp_eth = format!("{}", WalletType::Ethereum);
        let disp_sol = format!("{}", WalletType::Solana);
        assert_eq!(disp_eth, "WalletType(ethereum)");
        assert_eq!(disp_sol, "WalletType(solana)");
    }
}
