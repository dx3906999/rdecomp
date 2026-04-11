use crate::ir::Function;
use crate::loader::{Arch, BinaryFormat, FunctionSymbol};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::io::{BufReader, BufWriter};
use std::path::Path;

/// Magic bytes at the start of every `.rdb` file.
const MAGIC: &[u8; 4] = b"RDB\x00";
/// Format version — bump when the on-disk layout changes.
const VERSION: u32 = 1;

/// A cached analysis result for a single function.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalyzedFunction {
    /// Optimized IR.
    pub ir: Function,
    /// Generated pseudo-C code.
    pub c_code: String,
    /// Hash of the raw bytes that were disassembled, used for invalidation.
    pub bytes_hash: u64,
}

/// Metadata about the binary that was loaded — does NOT include section data.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BinaryMeta {
    pub arch: Arch,
    pub format: BinaryFormat,
    pub entry_point: u64,
    pub base_address: u64,
    pub functions: Vec<FunctionSymbol>,
    pub plt_map: HashMap<u64, String>,
    pub globals_map: HashMap<u64, String>,
}

/// On-disk project file payload.
#[derive(Debug, Serialize, Deserialize)]
struct ProjectPayload {
    version: u32,
    /// Path to the original binary (for re-loading section data).
    binary_path: String,
    meta: BinaryMeta,
    /// Cached function analyses keyed by function start address.
    cache: HashMap<u64, AnalyzedFunction>,
}

/// Project database: wraps metadata + per-function cache with lazy I/O.
pub struct ProjectDb {
    /// Where this project file lives on disk.
    path: std::path::PathBuf,
    /// Original binary path (needed to re-open for section bytes).
    binary_path: String,
    pub meta: BinaryMeta,
    cache: HashMap<u64, AnalyzedFunction>,
    dirty: bool,
}

impl ProjectDb {
    // ------------------------------------------------------------------
    // Construction
    // ------------------------------------------------------------------

    /// Create a new project from a loaded `Binary`.
    pub fn create(
        project_path: &Path,
        binary_path: &str,
        binary: &crate::loader::Binary,
    ) -> Self {
        let meta = BinaryMeta {
            arch: binary.arch,
            format: binary.format,
            entry_point: binary.entry_point,
            base_address: binary.base_address,
            functions: binary.functions.clone(),
            plt_map: binary.plt_map.clone(),
            globals_map: binary.globals_map.clone(),
        };
        Self {
            path: project_path.to_path_buf(),
            binary_path: binary_path.to_string(),
            meta,
            cache: HashMap::new(),
            dirty: true,
        }
    }

    /// Open an existing `.rdb` project file.
    pub fn open(path: &Path) -> crate::Result<Self> {
        let file = std::fs::File::open(path)?;
        let mut reader = BufReader::new(file);

        // Read and verify magic
        let mut magic = [0u8; 4];
        std::io::Read::read_exact(&mut reader, &mut magic)?;
        if &magic != MAGIC {
            return Err(crate::DecompError::Other("not a valid .rdb project file".into()));
        }

        let payload: ProjectPayload = bincode::deserialize_from(&mut reader)
            .map_err(|e| crate::DecompError::Other(format!("deserialize error: {e}")))?;

        if payload.version != VERSION {
            return Err(crate::DecompError::Other(format!(
                "unsupported project version {} (expected {VERSION})",
                payload.version
            )));
        }

        Ok(Self {
            path: path.to_path_buf(),
            binary_path: payload.binary_path,
            meta: payload.meta,
            cache: payload.cache,
            dirty: false,
        })
    }

    // ------------------------------------------------------------------
    // Persistence
    // ------------------------------------------------------------------

    /// Write the project to disk atomically (temp file + rename).
    /// Call after analyses are cached.
    pub fn save(&mut self) -> crate::Result<()> {
        let tmp_path = self.path.with_extension("rdb.tmp");
        let file = std::fs::File::create(&tmp_path)?;
        let mut writer = BufWriter::new(file);

        std::io::Write::write_all(&mut writer, MAGIC)?;

        let payload = ProjectPayload {
            version: VERSION,
            binary_path: self.binary_path.clone(),
            meta: self.meta.clone(),
            cache: self.cache.clone(),
        };
        bincode::serialize_into(&mut writer, &payload)
            .map_err(|e| crate::DecompError::Other(format!("serialize error: {e}")))?;

        std::io::Write::flush(&mut writer)?;
        // Ensure data is written to disk before rename
        writer.get_ref().sync_all()?;
        drop(writer);

        // Atomic rename: replaces the old file only after the new one is fully written
        std::fs::rename(&tmp_path, &self.path)?;
        self.dirty = false;
        Ok(())
    }

    // ------------------------------------------------------------------
    // Cache operations
    // ------------------------------------------------------------------

    /// Look up a cached analysis by function address.
    /// Returns `Some` only if the cache entry's `bytes_hash` matches.
    pub fn get(&self, addr: u64, current_hash: u64) -> Option<&AnalyzedFunction> {
        self.cache.get(&addr).filter(|af| af.bytes_hash == current_hash)
    }

    /// Insert or update a cached analysis.
    pub fn insert(&mut self, addr: u64, entry: AnalyzedFunction) {
        self.cache.insert(addr, entry);
        self.dirty = true;
    }

    /// Number of cached functions.
    pub fn cached_count(&self) -> usize {
        self.cache.len()
    }

    pub fn is_dirty(&self) -> bool {
        self.dirty
    }

    /// Path to the original binary.
    pub fn binary_path(&self) -> &str {
        &self.binary_path
    }

    /// Project file path.
    pub fn project_path(&self) -> &Path {
        &self.path
    }
}

// ------------------------------------------------------------------
// Hashing helper
// ------------------------------------------------------------------

/// Fast non-cryptographic hash of a byte slice (FNV-1a 64-bit).
pub fn hash_bytes(data: &[u8]) -> u64 {
    let mut h: u64 = 0xcbf29ce484222325;
    for &b in data {
        h ^= u64::from(b);
        h = h.wrapping_mul(0x100000001b3);
    }
    h
}
