use libsecp256k1::{Signature, RecoveryId};

use crate::utils::serialize_raw;

use {
    borsh::{BorshDeserialize, BorshSerialize},
    sha3::Digest,
};

/// a trait which must be implemented by instructions that wish to provide support for gasless transaction relaying
pub trait SignedInstruction {
    /// serialize the instruction, normally done as message preparation before signing the instruction
    fn serialize(&self) -> Vec<u8>;
    /// encodes the signed instruction, which involves serializing the instruction and then hashing the serialized bytes
    fn encode(&self) -> [u8; 32];
    /// signs the instruction to be relayed, and executed by a compatible program
    /// 1) encode (serialize -> hash)
    /// 2) sign hashed message
    /// 3) return signature
    fn sign(&self, key: libsecp256k1::SecretKey) -> (Signature, RecoveryId);
    /// signs the instruction, generating the signed message bundle that must be submitted
    /// to the the gasless relayer. This allows for concise representation of the instruction
    /// which was signed, allowing a program to reconstruct the signature based on instruction data.
    fn into_signed_message(&self) -> SignedMessage;
}


#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, BorshSerialize, BorshDeserialize)]
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
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, BorshSerialize, BorshDeserialize)]
pub enum WalletType {
    Ethereum,
    Solana,
}


impl WalletType {
    pub const fn pubkey_length(self) -> usize {
        match self {
            Self::Ethereum => 20,
            Self::Solana => 32,
        }
    }
}

impl SignedMessage {
    /// returns Some(eth_pubkey) if the signed message was of type WalletType::Ethereum
    pub fn construct_eth_pubkey(self, pub_key: &libsecp256k1::PublicKey) -> Option<[u8; 20]> {
        let mut addr = [0u8; 20];
        addr.copy_from_slice(&sha3::Keccak256::digest(&serialize_raw(*pub_key)[12..]));
        Some(addr)
    }
}