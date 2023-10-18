/// a default implementation of the ssi for arbitrary serialized bytes of instruction data.
/// suitable for use, however due to the unstructured nature of the data it may be difficult to work with
pub mod byte_signed_ix;
/// error types
pub mod error;
/// provides the core signed message object utilized for gasless tx relaying
pub mod signed_message;
/// utilities for working with ssi format
pub mod utils;

/// module providing authenticated proxy program
#[cfg(feature = "proxy-auth")]
pub mod proxy_auth;
