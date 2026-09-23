#[cfg(not(target_pointer_width = "64"))]
compile_error!(
    "alpacka requires a 64-bit target. archive offsets and sizes are stored as u64 on disk, \
and casting them to a 32-bit usize can silently truncate entries larger than ~4.29GB, \
producing corrupted reads without any error. Building for 32-bit targets is unsupported."
);
#[cfg(any(feature = "reader", feature = "writer"))]
pub mod format;
#[cfg(any(feature = "reader", feature = "writer"))]
pub mod meta_file;
#[cfg(feature = "packager_api")]
pub mod packager;
#[cfg(feature = "preprocessor_api")]
pub mod preprocessor;
#[cfg(feature = "reader")]
pub mod reader;
#[cfg(feature = "writer")]
pub mod writer;
