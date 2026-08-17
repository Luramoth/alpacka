#[cfg(not(target_pointer_width = "64"))]
compile_error!(
    "alpacka requires a 64-bit target. archive offsets and sizes are stored as u64 on disk, \
and casting them to a 32-bit usize can silently truncate entries larger than ~4.29GB, \
producing corrupted reads without any error. Building for 32-bit targets is unsupported."
);
pub mod format;
pub mod meta_file;
pub mod reader;
#[cfg(feature = "writer")]
pub mod writer;
