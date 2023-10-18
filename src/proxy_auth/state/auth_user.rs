use arrayref::{array_mut_ref, array_ref, array_refs, mut_array_refs};
use borsh::{BorshDeserialize, BorshSerialize};
use solana_program::{
    program_error::ProgramError,
    program_pack::{IsInitialized, Pack, Sealed},
    pubkey::Pubkey,
};

use crate::signed_message::WalletType;

#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct AuthUser {
    /// 32 byte public key of the wallet which is expected to sign messages
    pub signing_key: [u8; 32],
    /// the nonce that was used to generate the pda
    pub nonce: u8,
    pub wallet_type: WalletType,
    /// padding for extra storage space
    pub padding: [u8; 128],
}

impl AuthUser {
    pub const fn size() -> usize {
        32 + 128 + 2
    }
    pub const fn seed() -> &'static [u8] {
        b"auth_user"
    }
    pub fn derive(signing_key: [u8; 32]) -> (Pubkey, u8) {
        Pubkey::find_program_address(&[Self::seed(), &signing_key[..]], &crate::proxy_auth::id())
    }
    /// creates a pda address given the signign key and nonce
    pub fn create_pda(signing_key: [u8; 32], nonce: u8) -> Pubkey {
        Pubkey::create_program_address(
            &[Self::seed(), &signing_key[..], &[nonce]],
            &crate::proxy_auth::id(),
        )
        .unwrap()
    }
    /// similar to create_pda except it uses data stored in the account
    pub fn parse_pda(&self) -> Pubkey {
        Self::create_pda(self.signing_key, self.nonce)
    }
}

impl Sealed for AuthUser {}
impl IsInitialized for AuthUser {
    fn is_initialized(&self) -> bool {
        // TODO: should we remove the nonce == 0 check?
        self.signing_key.ne(&[0_u8; 32]) && self.nonce > 0
    }
}
impl Pack for AuthUser {
    const LEN: usize = AuthUser::size();
    fn unpack_from_slice(src: &[u8]) -> Result<Self, ProgramError> {
        let src = array_ref![src, 0, AuthUser::size()];
        let (signing_key, nonce, wallet_type, padding) = array_refs![src, 32, 1, 1, 128];
        Ok(Self {
            signing_key: *signing_key,
            nonce: nonce[0],
            wallet_type: From::from(wallet_type[0]),
            padding: *padding,
        })
    }
    fn pack_into_slice(&self, dst: &mut [u8]) {
        let dst = array_mut_ref![dst, 0, AuthUser::size()];
        let (_signing_key, _nonce, _wallet_type, _padding) = mut_array_refs![dst, 32, 1, 1, 128];

        let AuthUser {
            ref signing_key,
            ref nonce,
            ref wallet_type,
            ref padding,
        } = self;
        _signing_key.copy_from_slice(&signing_key[..]);
        _nonce[0] = *nonce;
        _wallet_type[0] = *wallet_type as u8;
        _padding.copy_from_slice(&padding[..]);
    }
}

#[cfg(test)]
mod test {
    use super::*;
    #[test]
    fn test_pack_unpack() {
        let auth_user = AuthUser {
            signing_key: [69_u8; 32],
            nonce: 42,
            wallet_type: WalletType::Ethereum,
            padding: [22_u8; 128],
        };
        let mut buf: [u8; AuthUser::size()] = [0_u8; AuthUser::size()];
        AuthUser::pack(auth_user, &mut buf).unwrap();
        let unpacked_auth_user = AuthUser::unpack(&buf[..]).unwrap();
        assert_eq!(auth_user, unpacked_auth_user);
    }
    #[test]
    fn test_derive() {
        let default_key = Pubkey::default();
        let (pda, nonce) = AuthUser::derive(default_key.to_bytes());
        assert_eq!(
            pda.to_string(),
            "3KBAZTvyWkvTHQVhMLmpbGWsQUbtBhC4STsMk7tqjXLY"
        );
        assert_eq!(nonce, 253);
        assert_eq!(pda, AuthUser::create_pda(default_key.to_bytes(), nonce));
    }
}
