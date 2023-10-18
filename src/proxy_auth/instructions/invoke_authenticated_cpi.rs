use crate::{
    byte_signed_ix::ByteSignedIx,
    error::SSIError,
    proxy_auth::state::auth_user::AuthUser,
    signed_message::{SignedInstruction, SignedInstructionSerializoor, WalletInfo},
    utils::serialize_raw,
};
use solana_program::{
    account_info::AccountInfo,
    entrypoint::ProgramResult,
    instruction::{AccountMeta, Instruction},
    log::sol_log as log,
    program::invoke_signed,
    program_error::ProgramError,
    program_pack::{IsInitialized, Pack},
    rent::Rent,
    secp256k1_recover::Secp256k1RecoverError,
    system_instruction,
    sysvar::Sysvar,
};

use super::ProxyAuthIx;
use crate::signed_message::WalletType;

/// handlers register the authenticated user
///
/// accounts
///     0 [writeable] - fee payer
///     1 [writeable] - auth_user
///     2 []          - cpi_program
///     ....          - cpi_program_accounts
pub fn handle_invoke_authenticated_cpi(
    accounts: &[AccountInfo],
    ix: ProxyAuthIx,
) -> Result<(), ProgramError> {
    let ProxyAuthIx::InvokeAuthenticatedCPI {
        ix_data: _,
        signed_message,
    } = ix
    else {
        return Err(ProgramError::InvalidArgument);
    };

    let auth_user = accounts.get(1).unwrap();
    // ensure we own this user account
    if auth_user.owner.ne(&crate::proxy_auth::id()) {
        return Err(ProgramError::IllegalOwner);
    }

    let auth_user_info = AuthUser::unpack(&auth_user.data.borrow())?;
    let derived_auth_user = auth_user_info.parse_pda();
    // ensure that the derived account contents match the account key
    // this is one stage of the authentication process
    //
    // afterwards we validate that the recovered signature is equal to the accounts wallet
    if auth_user.key.ne(&derived_auth_user) {
        log("invalid pda");
        return Err(ProgramError::InvalidSeeds);
    }
    let ix_data = {
        // verify the instruction
        let byte_signed_ix = ByteSignedIx {
            instruction: Box::new(ix),
        };
        // extract the signer key
        let recovered_signer = byte_signed_ix.recover_signer(signed_message)?;
        // convert the signer key into a public key
        let recovered_signer = crate::utils::convert_recovered_public_key(recovered_signer)?;

        // based on the specified wallet type, ensure the signatures match up
        match auth_user_info.wallet_type {
            WalletType::Ethereum => {
                let constructed_key =
                    signed_message.compare_and_construct_eth_pubkey(WalletInfo {
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
        // return the instruction data to avoid borrow errors
        byte_signed_ix.serialize()
    };
    let cpi_program_id = *accounts.get(2).unwrap().key;
    let account_infos = accounts.get(3..).unwrap();
    invoke_signed(
        &Instruction {
            program_id: cpi_program_id,
            // we need to convert all account infos into AccountMeta
            accounts: account_infos
                .iter()
                .map(|acct| {
                    if !acct.is_writable {
                        AccountMeta::new_readonly(*acct.key, acct.is_signer)
                    } else {
                        AccountMeta::new(*acct.key, acct.is_signer)
                    }
                })
                .collect(),
            data: ix_data,
        },
        account_infos,
        &[&[
            AuthUser::seed(),
            &auth_user_info.signing_key[..],
            &[auth_user_info.nonce],
        ]],
    )?;
    Ok(())
}
