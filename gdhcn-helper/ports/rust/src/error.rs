use thiserror::Error as ThisError;

#[derive(Debug, ThisError)]
pub enum Error {
    #[error("base45: {0}")]
    Base45(String),
    #[error("zlib: {0}")]
    Zlib(String),
    #[error("cbor: {0}")]
    Cbor(String),
    #[error("cose: {0}")]
    Cose(String),
    #[error("json: {0}")]
    Json(String),
}
