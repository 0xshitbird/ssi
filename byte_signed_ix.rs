use libsecp256k1::{Message, RecoveryId, Signature};
use sha3::{Digest, Keccak256};
use solana_program::secp256k1_recover::{secp256k1_recover, Secp256k1Pubkey};

use crate::{
    error::SSIError,
    signed_message::{
        SignedInstruction, SignedInstructionSerializoor, SignedMessage, SignedMessageOpts,
    },
};

pub struct ByteSignedIx {
    pub instruction: dyn SignedInstructionSerializoor,
}

impl SignedInstructionSerializoor for ByteSignedIx {
    fn serialize(&self) -> Vec<u8> {
        self.instruction.serialize()
    }
}

impl SignedInstruction for ByteSignedIx {
    fn encode(&self) -> [u8; 32] {
        let serialized_instruction = self.serialize();
        let mut hasher = Keccak256::new();
        hasher.update(serialized_instruction);
        hasher.finalize().into()
    }
    fn sign(&self, key: libsecp256k1::SecretKey) -> Result<(Signature, RecoveryId), SSIError> {
        let signed_message = libsecp256k1::sign(&Message::parse_slice(&self.encode())?, &key);
        Ok(signed_message)
    }
    fn into_signed_message(&self, opts: SignedMessageOpts) -> Option<SignedMessage> {
        let hashed_message = self.encode();
        let mut s_msg: SignedMessage = opts.into();
        s_msg.message_hash = hashed_message;
        Some(s_msg)
    }
    fn recover_signer(&self, signed_message: SignedMessage) -> Result<Secp256k1Pubkey, SSIError> {
        // first generate the message hash references by the current ByteSignedIx instance
        let expected_hash = self.encode();
        if expected_hash.ne(&signed_message.message_hash) {
            return Err(SSIError::InvalidMessageHash {
                input: signed_message.message_hash,
                expected: expected_hash,
            });
        }
        // only accept low order signatures https://docs.rs/solana-sdk/latest/solana_sdk/secp256k1_recover/fn.secp256k1_recover.html
        if libsecp256k1::Signature::parse_standard_slice(&signed_message.signature)?
            .s
            .is_high()
        {
            return Err(SSIError::SignatureMalleabilityError);
        }
        let recovered_key = secp256k1_recover(
            &expected_hash[..],
            signed_message.recovery_id,
            &signed_message.signature,
        )?;

        Ok(recovered_key)
    }
    fn convert_recovered_public_key(
        key: Secp256k1Pubkey,
    ) -> Result<libsecp256k1::PublicKey, SSIError> {
        crate::utils::convert_recovered_public_key(key)
    }
}
