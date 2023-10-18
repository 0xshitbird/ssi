use libsecp256k1::{Message, RecoveryId, Signature};
use sha3::{Digest, Keccak256};
use solana_program::secp256k1_recover::{secp256k1_recover, Secp256k1Pubkey};

use crate::{
    error::SSIError,
    signed_message::{
        SignedInstruction, SignedInstructionSerializoor, SignedMessage, SignedMessageOpts,
    },
};

/// ByteSignedIx is a reasonable default for usage of the SSI specification. To use this
/// simply implement the `SignedInstructinSerializoor` trait for the instruction enum defined
/// in your solana program, and wrap any instance of the enum in `ByteSignedIx`.
///
/// This will conveniently wrap your instruction with all required functionality needed to perform
/// on-chain verification of the instruction, and the entity signing the instruction while permitted the
/// actual instruction to be relayed by anyone willing to pay a fee.
pub struct ByteSignedIx {
    pub instruction: Box<dyn SignedInstructionSerializoor>,
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

#[cfg(test)]
mod test {
    use borsh::{BorshDeserialize, BorshSerialize};
    use rand::thread_rng;

    use crate::signed_message::WalletType;

    use super::*;
    #[repr(C)]
    #[derive(Clone, Copy, Debug, PartialEq, BorshSerialize, BorshDeserialize)]
    enum SomeInstruction {
        Initialize { nonce: u8 },
    }

    impl SignedInstructionSerializoor for SomeInstruction {
        fn serialize(&self) -> Vec<u8> {
            self.try_to_vec().unwrap()
        }
    }

    fn test_sk() -> libsecp256k1::SecretKey {
        let dec_sk =
            hex::decode("6305ebd1c45068587419680294b2cc67e8116710bec85c4ca1fa7e6722e8be6a")
                .unwrap();
        let dec_sk = <[u8; 32]>::try_from(dec_sk).unwrap();
        libsecp256k1::SecretKey::parse(&dec_sk).unwrap()
    }

    #[test]
    fn test_signed_instruction_serializoor() {
        let ix = SomeInstruction::Initialize { nonce: 69 };
        let serialized_ix = ix.try_to_vec().unwrap();
        assert_eq!(
            crate::signed_message::SignedInstructionSerializoor::serialize(&ix),
            serialized_ix
        );
    }

    #[test]
    fn test_bytesigned_ix_serializooor() {
        let ix = SomeInstruction::Initialize { nonce: 69 };

        let b_ix = ByteSignedIx {
            instruction: Box::new(ix),
        };

        let serialized_ix = ix.try_to_vec().unwrap();

        assert_eq!(
            crate::signed_message::SignedInstructionSerializoor::serialize(&b_ix),
            serialized_ix
        );
    }

    #[test]
    fn test_bytesigned_ix_signed_instruction() {
        let sk = test_sk();

        const EXPECTED_SERIALIZED_RECOVERED_SIGNER: &str = "0494842fd8e1f384dececf37b342a9e2cab26c7a3d1fdfd0619858fc6aa3c1011552c818ab2e19c3779e63e2291f032db04bec1508f4747f1713d69a864bd85d57";
        const EXPECTED_RECOVERED_SIGNER: &str  = "94842fd8e1f384dececf37b342a9e2cab26c7a3d1fdfd0619858fc6aa3c1011552c818ab2e19c3779e63e2291f032db04bec1508f4747f1713d69a864bd85d57";
        const EXPECTED_ENC_B_IX: &str =
            "41896cdf1cfa7c6a44b5ee18d57b32712ad86c69a76a3ae57957a0238b20a205";
        const EXPECTED_SIG_B_IX: &str = "ccd6775ff206ac97924053627fddb4abf2bb9904a6de018986f6236f6c50160e3dc22ac57f88506e3dac60d0e7a6d1ac1d5a175f34e4b0685fa44cc4c93353f0";
        const EXPECTED_RECID_B_IX: u8 = 1;
        let ix = SomeInstruction::Initialize { nonce: 69 };

        let b_ix = ByteSignedIx {
            instruction: Box::new(ix),
        };

        let enc_b_ix = b_ix.encode();

        assert_eq!(EXPECTED_ENC_B_IX, hex::encode(&enc_b_ix));

        let (sig, rec_id) = b_ix.sign(sk).unwrap();
        assert_eq!(EXPECTED_SIG_B_IX, hex::encode(sig.serialize()));
        assert_eq!(EXPECTED_RECID_B_IX, rec_id.serialize());
        let expected_s_msg = SignedMessage {
            signature: sig.serialize(),
            message_hash: b_ix.encode(),
            wallet_pubkey: WalletType::Ethereum
                .encode_key(libsecp256k1::PublicKey::from_secret_key(&sk)),
            recovery_id: rec_id.serialize(),
        };
        let s_msg = b_ix
            .into_signed_message(SignedMessageOpts {
                signature: sig.serialize(),
                recovery_id: rec_id.serialize(),
                signing_wallet_type: WalletType::Ethereum,
                pub_key: libsecp256k1::PublicKey::from_secret_key(&sk),
            })
            .unwrap();

        assert_eq!(s_msg, expected_s_msg);

        let recovered_signer = b_ix.recover_signer(s_msg).unwrap();

        assert_eq!(EXPECTED_RECOVERED_SIGNER, hex::encode(&recovered_signer.0));

        let recovered = ByteSignedIx::convert_recovered_public_key(recovered_signer).unwrap();

        assert_eq!(
            EXPECTED_SERIALIZED_RECOVERED_SIGNER,
            hex::encode(recovered.serialize())
        );
    }
}
