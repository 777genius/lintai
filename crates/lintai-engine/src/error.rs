use std::io;

use crate::ConfigError;

#[derive(Debug)]
pub enum EngineError {
    Io(io::Error),
    Config(ConfigError),
    ProviderContract(String),
}

impl std::fmt::Display for EngineError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(error) => write!(f, "{error}"),
            Self::Config(error) => write!(f, "{error}"),
            Self::ProviderContract(message) => write!(f, "{message}"),
        }
    }
}

impl std::error::Error for EngineError {}

impl From<io::Error> for EngineError {
    fn from(value: io::Error) -> Self {
        Self::Io(value)
    }
}

impl From<ConfigError> for EngineError {
    fn from(value: ConfigError) -> Self {
        Self::Config(value)
    }
}
