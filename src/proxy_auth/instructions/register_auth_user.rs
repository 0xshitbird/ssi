use crate::{
    byte_signed_ix::ByteSignedIx,
    error::SSIError,
    proxy_auth::state::auth_user::AuthUser,
    signed_message::{SignedInstruction, WalletInfo},
    utils::serialize_raw,
};
use solana_program::{
    account_info::AccountInfo,
    entrypoint::ProgramResult,
    log::sol_log as log,
    program::invoke_signed,
    program_error::ProgramError,
    program_pack::{IsInitialized, Pack},
    rent::Rent,
    secp256k1_recover::Secp256k1RecoverError,
    system_instruction,
    sysvar::Sysvar, instruction::AccountMeta, pubkey::Pubkey,
};

use super::ProxyAuthIx;
use crate::signed_message::WalletType;

pub struct RegisterAuthUserAccountMeta {
    pub fee_payer: Pubkey,
    pub auth_user: Pubkey,
    pub system_program: Pubkey
}

impl RegisterAuthUserAccountMeta {
    pub fn to_account_metas(&self) -> Vec<AccountMeta> {
        vec![
            AccountMeta::new(self.fee_payer, true),
            AccountMeta::new(self.auth_user, false),
            AccountMeta::new_readonly(self.system_program, false),
        ]
    }
}

/// handlers register the authenticated user
///
/// accounts
///     0 [writeable] - fee payer
///     1 [writeable] - auth_user
///     2 []          - system_program
pub fn handle_register_auth_user(
    accounts: &[AccountInfo],
    ix: ProxyAuthIx,
) -> Result<(), ProgramError> {
    let ProxyAuthIx::RegisterAuthUser {
        ix_data,
        signed_message,
    } = ix
    else {
        return Err(ProgramError::InvalidArgument);
    };
    let pda = AuthUser::create_pda(signed_message.wallet_pubkey, ix_data.nonce);

    let fee_payer = accounts.get(0).unwrap();
    let auth_user = accounts.get(1).unwrap();

    if pda.ne(auth_user.key) {
        log("invalid pda");
        return Err(ProgramError::InvalidSeeds);
    }

    // verify the instruction
    let byte_signed_ix = ByteSignedIx {
        instruction: Box::new(ix),
    };

    // extract the signer key
    let recovered_signer = byte_signed_ix.recover_signer(signed_message)?;
    // convert the signer key into a public key
    let recovered_signer = crate::utils::convert_recovered_public_key(recovered_signer)?;

    // based on the specified wallet type, ensure the signatures match up
    match ix_data.wallet_type {
        WalletType::Ethereum => {
            let constructed_key = signed_message.compare_and_construct_eth_pubkey(WalletInfo {
                wallet_type: WalletType::Ethereum,
                raw_public_key: serialize_raw(recovered_signer),
            })?;
            // we only care about verifying the first 20 bytes of the public key for eth wallets
            if constructed_key.ne(&signed_message.wallet_pubkey[0..20]) {
                return Err(SSIError::CompareAndConstructMismatchedKey(format!(
                    "constructed_key {:?} != wallet_pubkey {:?}",
                    constructed_key,
                    &signed_message.wallet_pubkey[0..20]
                ))
                .into());
            }
        }
        WalletType::Solana => {
            // TODO: add support
            return Err(SSIError::UnsupportedWalletType.into());
        }
    }

    let rent = Rent::get()?;
    let lamports = rent.minimum_balance(AuthUser::size());
    invoke_signed(
        &system_instruction::create_account(
            fee_payer.key,
            auth_user.key,
            lamports,
            AuthUser::size() as u64,
            &crate::proxy_auth::id(),
        ),
        &[fee_payer.clone(), auth_user.clone()],
        &[&[
            AuthUser::seed(),
            &signed_message.wallet_pubkey[..],
            &[ix_data.nonce],
        ]],
    )?;

    let mut auth_user_info = AuthUser::unpack_unchecked(&auth_user.data.borrow())?;
    if auth_user_info.is_initialized() {
        log("already initialized");
        return Err(ProgramError::AccountAlreadyInitialized);
    }

    auth_user_info.signing_key = signed_message.wallet_pubkey;
    auth_user_info.nonce = ix_data.nonce;

    AuthUser::pack(auth_user_info, &mut auth_user.data.borrow_mut())?;

    Ok(())
}
