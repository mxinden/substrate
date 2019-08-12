/// ValidatorDiscovery Result.
pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, derive_more::Display, derive_more::From)]
pub enum Error {
    RetrievingPublicKey,
    CallingRuntime,
}
