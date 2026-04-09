use thiserror::Error;

#[derive(Debug, Error)]
pub enum DecompError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("unsupported binary format")]
    UnsupportedFormat,

    #[error("unsupported architecture: {0}")]
    UnsupportedArch(String),

    #[error("binary parse error: {0}")]
    ParseError(String),

    #[error("no executable sections found")]
    NoExecutableSections,

    #[error("function not found at address 0x{0:x}")]
    FunctionNotFound(u64),

    #[error("disassembly error: {0}")]
    DisassemblyError(String),

    #[error("lift error: {0}")]
    LiftError(String),

    #[error("analysis error: {0}")]
    AnalysisError(String),
}

pub type Result<T> = std::result::Result<T, DecompError>;
