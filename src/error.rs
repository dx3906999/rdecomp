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

    #[error("unsupported instruction at 0x{addr:x}: {mnemonic}")]
    UnsupportedInstruction { addr: u64, mnemonic: String },

    #[error("lift error at 0x{addr:x}: {detail}")]
    LiftError { addr: u64, detail: String },

    #[error("invalid CFG: {0}")]
    InvalidCfg(String),

    #[error("type conflict: {0}")]
    TypeConflict(String),

    #[error("project error: {0}")]
    ProjectError(String),

    #[error("analysis error: {0}")]
    AnalysisError(String),

    #[error("{0}")]
    Other(String),
}

pub type Result<T> = std::result::Result<T, DecompError>;
