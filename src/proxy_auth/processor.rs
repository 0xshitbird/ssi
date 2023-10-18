use solana_program::{
    account_info::AccountInfo, entrypoint::ProgramResult, log::sol_log as log,
    program_error::ProgramError, pubkey::Pubkey,
};

use super::instructions::{
    invoke_authenticated_cpi::handle_invoke_authenticated_cpi,
    register_auth_user::handle_register_auth_user, ProxyAuthIx,
};

pub fn process_instruction(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    instruction_data: &[u8],
) -> ProgramResult {
    if program_id.ne(&super::id()) {
        log(&format!("invalid program_id {:?}", program_id));
        return Err(ProgramError::IncorrectProgramId);
    }
    let proxy_auth_ix = ProxyAuthIx::unpack(instruction_data)?;
    match proxy_auth_ix {
        ProxyAuthIx::RegisterAuthUser { .. } => {
            handle_register_auth_user(accounts, proxy_auth_ix)?;
        }
        ProxyAuthIx::InvokeAuthenticatedCPI { .. } => {
            handle_invoke_authenticated_cpi(accounts, proxy_auth_ix)?;
        }
    }
    Ok(())
}
