# SSI (Solana Signed Instruction)

SSI is a specification for gasless solana instructions, allowing any compatible wallet to securely execute instructions on Solana without paying gas, and without actually needing to use a solana wallet (:pogchamp: :wot:).

# Gasless Instruction

The gasless instruction functionality is obtained by using a secp256k1 private key to sign the instruction data you would normally provide to a solana program. 

With some minor modification, any solana program that has 129 bytes of free space in the transaction itself can utilize gasless instructions. 

# Solana Transaction Without A Solana Wallet

Any compatible blockchain (currently solana + ethereum) which utilizes a secp256k1 public/private key can execute instructions on Solana without actually needing to have a solana wallet.

All you need is a way to construct a signed message in the SSI format, and relaying it to a program on Solana.

# Usage

For simplicity a general purpose implementation of SSI is provided as [ByteSignedIx](./src/byte_signed_ix.rs), which acts as a wrapper around any existing instruction. 

You can read the tests in `byte_signed_ix.rs` for an example PoC implementing the byte_signed_ix.
