//! proxy_auth implements a thin program that integrates the SSI specification, allowing for
//! invocation of arbitrary solana programs using the SSI authenticated user as the owner of all CPI program accounts.

/// entrypoint for the solana program
pub mod entrypoint;
/// instruction definitions and helper functions
pub mod instructions;
/// unpacks instruction data and routes to instruction handler
pub mod processor;
/// account state objects
pub mod state;

/// program testing
#[cfg(test)]
pub mod test;

solana_program::declare_id!("9AXGZxRCXdVeghrfHTFAKVumngPuksG43StaGudXoqgm");
