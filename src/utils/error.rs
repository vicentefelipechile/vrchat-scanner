use thiserror::Error;

#[derive(Debug, Error)]
pub enum ScannerError {
    #[error("File not found: {0}")]
    FileNotFound(String),

    #[error("Extraction error: {0}")]
    ExtractionError(String),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("HTTP error: {0}")]
    Http(#[from] reqwest::Error),

    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("YAML error: {0}")]
    Yaml(#[from] serde_yaml::Error),

    #[error("Export error: {0}")]
    ExportError(String),

    #[error("ZIP error: {0}")]
    ZipError(String),
}

impl From<zip::result::ZipError> for ScannerError {
    fn from(e: zip::result::ZipError) -> Self {
        ScannerError::ZipError(e.to_string())
    }
}

pub type Result<T> = std::result::Result<T, ScannerError>;
