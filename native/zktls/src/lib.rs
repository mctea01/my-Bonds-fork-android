//! TLSNotary alpha.15 adapter. Protocol failures never carry transcript data.
pub mod noise;

pub const TLSN_REVISION: &str = "47aee45b53e06648c1b2ad3689b367b8c923fdec";

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("Invalid TLS proof input")]
    Input,
    #[error("TLS proof protocol failed")]
    Protocol,
    #[error("TLS proof transport failed")]
    Channel,
    #[error("TLS proof resource limit reached")]
    Limit,
    #[error("TLS proof worker failed")]
    Worker,
    #[error("TLS proof cancelled")]
    Cancelled,
}
pub type Result<T> = std::result::Result<T, Error>;

pub mod channel;
pub mod protocol;
