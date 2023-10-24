use {
    solana_program::{
        instruction::{AccountMeta, Instruction},
        pubkey::Pubkey,
    },
    solana_program_test::*,
    solana_sdk::{signature::Signer, transaction::Transaction},
    std::str::FromStr,
};
use borsh::BorshSerialize;
use libsecp256k1::{sign, SecretKey, Message, PublicKey};
use rand::{rngs::OsRng, thread_rng};
use sha3::{Keccak256, Digest};
use solana_program::{system_instruction, system_program, sysvar};
use crate::{proxy_auth, signed_message::{WalletType, SignedInstruction, SignedMessageOpts}, byte_signed_ix::ByteSignedIx};
use proxy_auth::{
    processor::process_instruction
};
// this will panic because wormhole isn't properly forked into the localnet environment
#[tokio::test]
async fn test_register_auth_user() {
    let mut rng = thread_rng();


    let mut pt = ProgramTest::new(
        "proxy_auth",
        proxy_auth::id(),
        processor!(process_instruction), 
    );

    let (mut banks_client, payer, recent_blockhash) = pt
    .start()
    .await;
    // Generate a random secret key
    let secret_key = SecretKey::random(&mut rng);
    let pub_key = PublicKey::from_secret_key(&secret_key);
    let eth_pub_key =crate::utils::construct_eth_pubkey(&pub_key);
    let eth_pub_key_padded = crate::utils::pad_eth_pubkey(eth_pub_key);

    let pub_key_serialized = pub_key.serialize();
    let mut public_key: [u8; 64] = [0_u8; 64];
    public_key.copy_from_slice(&pub_key_serialized[1..]);

    let (pda, nonce) = proxy_auth::state::auth_user::AuthUser::derive(eth_pub_key_padded);
    
    let mut proxy_auth_ix = proxy_auth::instructions::ProxyAuthIx::RegisterAuthUser {
        ix_data: proxy_auth::instructions::RegisterAuthUserIx {
            nonce,
            wallet_type: WalletType::Ethereum,
        },
        // because we are just signing  the `ix_data`, we can leave this default for nwo
        signed_message: Default::default()
    };
    let byte_signed_ix: ByteSignedIx = (&proxy_auth_ix).into();
    let ix_accounts = proxy_auth::instructions::register_auth_user::RegisterAuthUserAccountMeta {
        fee_payer: payer.pubkey(),
        auth_user: pda,
        system_program: system_program::id()
    };
    let (signature, recovery_id) = byte_signed_ix.sign(secret_key).unwrap();
    let s_msg = byte_signed_ix.into_signed_message(SignedMessageOpts {
        signature: signature.serialize(),
        recovery_id: recovery_id.serialize(),
        signing_wallet_type: WalletType::Ethereum,
        pub_key,
    }).unwrap();
    if let proxy_auth::instructions::ProxyAuthIx::RegisterAuthUser {
        ix_data,
        signed_message
    } = &mut proxy_auth_ix {
        *signed_message = s_msg;
    } else {
        panic!("Invalid type");
    };
    let mut transaction = Transaction::new_with_payer(
        &[
            Instruction::new_with_bytes(
                proxy_auth::id(),
                &proxy_auth_ix.pack(),
                ix_accounts.to_account_metas(),
            )
        ],
        Some(&payer.pubkey())
    );
    let recent_blockhash = banks_client.get_latest_blockhash().await.unwrap();
    transaction.sign(&[&payer], recent_blockhash);
    banks_client.process_transaction(transaction).await.unwrap();
}