use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("invalid rule: {0}")]
    InvalidRule(String),

    #[error("yaml parse error: {0}")]
    Yaml(#[from] serde_yaml::Error),

    #[error("json parse error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("regex compile error: {0}")]
    Regex(#[from] regex::Error),

    #[error("protocol error: {0}")]
    Protocol(String),
}

pub type Result<T> = std::result::Result<T, Error>;
