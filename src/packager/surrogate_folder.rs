//! Temporary folders mirroring in a chain starting from root asset folder to the final preprocessor
//! step.
//!
//! Surrogate folders are a part of the Packager API with the intent that they would allow for
//! non-destructive automatic asset editing through the preprocessor API. the APi was designed to
//! allow the use of multiple preprocessors in a stack (ex: lightmapper -> mipmapper -> occlusion_baker)
//!
//! The idea is first a packer will clear the previous surrogate root ".alpacka_surrogates/"
//! [`SurrogateFolder::clean_stale_surrogates`].\
//! Then it will create a new fresh one [`SurrogateFolder::create_surrogate_root`].
//!
//! Then for every step, using previous example:\
//! * First step, create the first surrogate for the lightmapper [`SurrogateFolder::new`].\
//! * Second step, create a new surrogate for the mipmapper [`SurrogateFolder::derive_surrogate_from_self`].\
//! * Let's say the second step failed, but it was marked as not required, so we decide to skip it
//! using [`SurrogateFolder::derive_surrogate_from_root`] which will derive a surrogate folder
//! from the first step's surrogate, meaning any mistakes from the second step aren't carried over to step 3
//!
//!
//! from there the packager will use the very last step's surrogate folder and use that as an input
//! for the alpack writer

use std::fs;
use std::fs::remove_dir_all;
use std::path::{Path, PathBuf};
use tempfile::Builder;

pub struct SurrogateFolder {
    /// Path to the surrogate folder itself
    pub path: PathBuf,
    /// path to the folder this surrogate is derived from
    pub source_path: PathBuf,
    surrogates_root_path: PathBuf,
}

impl SurrogateFolder {
    /// creates a new surrogate folder using provided asset source directory and a place to put the
    /// actual directory. from here it's recommended to made derivative folders through
    /// [`SurrogateFolder::derive_surrogate_from_self`] and [`SurrogateFolder::derive_surrogate_from_root`]
    ///
    /// # Errors:
    /// will return an error if for any reason the surrogate folder fails to be created, or if
    /// mirroring the source directory ever fails
    pub fn new(
        source_path: PathBuf,
        surrogates_root_path: PathBuf,
    ) -> std::io::Result<SurrogateFolder> {
        let path = Builder::new()
            .prefix("surrogate.")
            .tempdir_in(&surrogates_root_path)?
            .keep();

        Self::mirror_dir(source_path.as_path(), path.as_path())?;

        let surrogate = SurrogateFolder {
            source_path,
            path,
            surrogates_root_path,
        };

        Ok(surrogate)
    }

    /// given the same path ypu presumably gave to [`SurrogateFolder::create_surrogate_root`] it will
    /// delete the surrogate root and its contents, leaving the actual source content untouched
    ///
    /// ## source_path: &PathBuf
    /// path to the original source folder of your assets (ex: `{PROJECT_ROOT}/Assets/`)
    ///
    /// # Errors:
    /// will return an error if for any reason the folder deletion process fails
    pub fn clean_stale_surrogates(source_path: &PathBuf) -> std::io::Result<()> {
        let staging_dir = source_path
            .parent()
            .ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "source_root has no parent directory",
                )
            })?
            .join(".alpacka_surrogates");

        match remove_dir_all(&staging_dir) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e),
        }
    }

    /// creates a surrogate root directory to contain the surrogates.
    ///
    /// ```text
    /// Project root folder/
    /// ├ .alpacka_surrogates/ (created)
    /// └ source_path/ (parameter)
    /// ```
    pub fn create_surrogate_root(source_path: &PathBuf) -> std::io::Result<PathBuf> {
        let staging_dir = source_path
            .parent()
            .ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "source_root has no parent directory",
                )
            })?
            .join(".alpacka_surrogates");

        fs::create_dir_all(&staging_dir)?;

        Ok(staging_dir)
    }

    /// creates a new surrogate folder derived from `this`.
    ///
    /// this is to allow packagers the ability to create a new surrogate using this one as a base
    /// with the intent that it will be used in a non-destructive way to edit `this` step's work.
    pub fn derive_surrogate_from_self(&self) -> std::io::Result<SurrogateFolder> {
        SurrogateFolder::new(self.path.clone(), self.surrogates_root_path.clone())
    }

    /// creates a new surrogate based on `this` surrogat's source folder.
    ///
    /// this is to allow packagers to skip `this` step in case the preprocessor fails to do its work
    /// and will prevent `this` step from inserting corrupted or incomplete fails into the final package.
    pub fn derive_surrogate_from_root(&self) -> std::io::Result<SurrogateFolder> {
        SurrogateFolder::new(self.source_path.clone(), self.surrogates_root_path.clone())
    }

    fn mirror_dir(src_root: &Path, dst_root: &Path) -> std::io::Result<()> {
        let mut stack = vec![PathBuf::new()];

        while let Some(rel) = stack.pop() {
            let src_dir = src_root.join(&rel);
            let dst_dir = dst_root.join(&rel);
            fs::create_dir_all(dst_dir)?;

            for entry in fs::read_dir(&src_dir)? {
                let entry = entry?;
                let rel_child = rel.join(entry.file_name());
                let file_type = entry.file_type()?;

                if file_type.is_dir() {
                    stack.push(rel_child);
                } else {
                    fs::hard_link(entry.path(), dst_root.join(&rel_child))?;
                }
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::format::CompressionType;
    use crate::reader::AlpackReader;
    use crate::writer::AlpackWriter;
    use pretty_assertions::{assert_eq, assert_ne};
    use std::fs;
    use tempfile::env::temp_dir;

    fn scratch_dir(name: &str) -> PathBuf {
        let dir = temp_dir().join(name);
        let _ = remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn mirror_dir_recreates_nested_structure() {
        let src = scratch_dir("mirror_src_structure");
        fs::create_dir_all(src.join("sub/deep")).unwrap();
        fs::write(src.join("a.txt"), b"top level").unwrap();
        fs::write(src.join("sub/b.txt"), b"one level down").unwrap();
        fs::write(src.join("sub/deep/c.txt"), b"two levels down").unwrap();

        let dst = scratch_dir("mirror_dst_structure");
        SurrogateFolder::mirror_dir(&src, &dst).unwrap();

        assert!(dst.join("a.txt").exists());
        assert!(dst.join("sub/b.txt").exists());
        assert!(dst.join("sub/deep/c.txt").exists());

        assert_eq!(fs::read(dst.join("a.txt")).unwrap(), b"top level");
        assert_eq!(fs::read(dst.join("sub/b.txt")).unwrap(), b"one level down");
        assert_eq!(
            fs::read(dst.join("sub/deep/c.txt")).unwrap(),
            b"two levels down"
        );
    }

    #[test]
    fn mirror_dir_create_true_hardlinks_not_copies() {
        let src = scratch_dir("mirror_src_hardlink_proof");
        fs::write(src.join("shared.txt"), b"original").unwrap();

        let dst = scratch_dir("mirror_dst_hardlink_proof");
        SurrogateFolder::mirror_dir(&src, &dst).unwrap();

        fs::write(src.join("shared.txt"), b"mutated").unwrap();

        assert_eq!(fs::read(dst.join("shared.txt")).unwrap(), b"mutated");
    }

    #[cfg(unix)]
    #[test]
    fn mirror_dir_shares_inode_on_unix() {
        use std::os::unix::fs::MetadataExt;

        let src = scratch_dir("mirror_src_inode");
        fs::write(src.join("f.txt"), b"x").unwrap();

        let dst = scratch_dir("mirror_dst_inode");
        SurrogateFolder::mirror_dir(&src, &dst).unwrap();

        let src_ino = fs::metadata(src.join("f.txt")).unwrap().ino();
        let dst_ino = fs::metadata(dst.join("f.txt")).unwrap().ino();
        assert_eq!(src_ino, dst_ino);
    }

    #[test]
    fn mirror_dir_handles_empty_source() {
        let src = scratch_dir("mirror_src_empty");
        let dst = scratch_dir("mirror_dst_empty");

        SurrogateFolder::mirror_dir(&src, &dst).unwrap();

        assert!(dst.exists());
        assert_eq!(fs::read_dir(&dst).unwrap().count(), 0);
    }

    #[test]
    fn mirror_dir_fails_on_missing_source() {
        let dst = scratch_dir("mirror_dst_missing_source");
        let fake_src = temp_dir().join("this_does_not_exist_at_all");

        assert!(SurrogateFolder::mirror_dir(&fake_src, &dst).is_err());
    }

    #[test]
    fn new_populates_surrogate_from_source() {
        let source = scratch_dir("surrogate_new_source");
        fs::write(source.join("asset.bin"), b"payload").unwrap();

        let staging = scratch_dir("surrogate_new_staging");
        let surrogate = SurrogateFolder::new(source.clone(), staging.clone()).unwrap();

        assert_eq!(surrogate.source_path, source);
        assert_eq!(surrogate.surrogates_root_path, staging);
        assert!(surrogate.path.starts_with(&staging));
        assert!(surrogate.path.join("asset.bin").exists());
    }

    #[test]
    fn two_surrogates_from_the_same_root_get_distinct_paths() {
        let source = scratch_dir("surrogate_distinct_source");
        let staging = scratch_dir("surrogate_distinct_staging");

        let first = SurrogateFolder::new(source.clone(), staging.clone()).unwrap();
        let second = SurrogateFolder::new(source.clone(), staging.clone()).unwrap();

        assert_ne!(first.path, second.path);
    }

    #[test]
    fn create_surrogate_root_functions() {
        let project = scratch_dir("surrogate_root_test");
        let source = project.join("source");
        fs::create_dir_all(&source).unwrap();

        SurrogateFolder::create_surrogate_root(&source).unwrap();

        assert!(project.join(".alpacka_surrogates").exists());
    }

    #[test]
    fn clean_stale_surrogate_removes_existing_surrogate_root() {
        let project = scratch_dir("surrogate_clean_test");
        let source = project.join("source");
        fs::create_dir_all(&source).unwrap();

        SurrogateFolder::create_surrogate_root(&source).unwrap();

        SurrogateFolder::clean_stale_surrogates(&source).unwrap();

        assert!(!project.join(".alpacka_surrogates").exists());
    }

    #[test]
    fn clean_stale_surrogates_fails_with_nothing_to_clean() {
        let project = scratch_dir("surrogate_clean_fail_test");
        let source = project.join("source");
        fs::create_dir_all(&source).unwrap();

        assert!(SurrogateFolder::clean_stale_surrogates(&source).is_ok())
    }

    #[test]
    fn clean_stale_surrogates_leaves_source_files_untouched() {
        let project = scratch_dir("surrogate_clean_fail_test");
        let source = project.join("source");
        fs::create_dir_all(&source).unwrap();
        let staging = SurrogateFolder::create_surrogate_root(&source).unwrap();
        fs::write(&source.join("exists.txt"), b"exists").unwrap();

        SurrogateFolder::mirror_dir(&source, &staging).unwrap();

        assert!(&staging.join("exists.txt").exists());

        SurrogateFolder::clean_stale_surrogates(&source).unwrap();

        assert!(&source.join("exists.txt").exists());
        assert_eq!(fs::read(&source.join("exists.txt")).unwrap(), b"exists");
    }

    #[test]
    fn derive_from_root_rebuilds_from_original_source() {
        let source = scratch_dir("derive_root_source");
        fs::write(source.join("a.txt"), b"a").unwrap();

        let staging = scratch_dir("derive_root_staging");
        let first = SurrogateFolder::new(source.clone(), staging.clone()).unwrap();

        fs::write(&first.path.join("b.txt"), b"b").unwrap();

        let second = first.derive_surrogate_from_root().unwrap();

        assert_eq!(second.source_path, source);
        assert!(second.path.join("a.txt").exists());
        assert!(!source.join("b.txt").exists());
    }

    #[test]
    fn derive_from_self_mirrors_the_surrogate_folder() {
        let source = scratch_dir("derive_root_source");
        fs::write(source.join("a.txt"), b"a").unwrap();

        let staging = scratch_dir("derive_root_staging");
        let first = SurrogateFolder::new(source.clone(), staging.clone()).unwrap();

        fs::write(&first.path.join("b.txt"), b"b").unwrap();

        let second = first.derive_surrogate_from_self().unwrap();

        fs::write(&second.path.join("c.txt"), b"c").unwrap();

        assert_eq!(second.source_path, first.path);
        assert!(second.path.join("a.txt").exists());
        assert!(second.path.join("b.txt").exists());
        assert!(second.path.join("c.txt").exists());
    }

    #[test]
    fn failed_step_is_skipped_and_next_step_rebuilds_from_prior_surrogate() {
        let project = scratch_dir("pipeline_staging");
        let source = project.join("source");
        fs::create_dir_all(&source).unwrap();
        fs::write(source.join("base.txt"), b"base content").unwrap();
        let staging = SurrogateFolder::create_surrogate_root(&source).unwrap();

        let step1 = SurrogateFolder::new(source.clone(), staging.clone()).unwrap();
        fs::write(step1.path.join("step1_output.txt"), b"good processing").unwrap();

        let step2 = step1.derive_surrogate_from_self().unwrap();
        fs::write(
            step2.path.join("step2_corrupted_output.txt"),
            b"corrupted partial",
        )
        .unwrap();

        // step 2 messed up and failed, so instead of including its garbage data we use its source
        // (this assumes that the previous step is not a required part of the build)
        let step3 = step2.derive_surrogate_from_root().unwrap();

        assert!(!step3.path.join("step2_corrupted_output.txt").exists());
        assert!(step3.path.join("step1_output.txt").exists());
        assert!(step3.path.join("base.txt").exists());
        assert_eq!(step3.source_path, step1.path);
    }

    #[test]
    fn round_trip_simulation() {
        const TEST_KEY: [u8; 32] = *b"testtesttesttesttesttesttesttest";

        let project = scratch_dir("round-trip_simulation");
        let source = project.join("source");
        fs::create_dir_all(&source).unwrap();
        fs::write(source.join("base.txt"), b"base content").unwrap();
        let staging = SurrogateFolder::create_surrogate_root(&source).unwrap();

        let step1 = SurrogateFolder::new(source.clone(), staging.clone()).unwrap();
        fs::create_dir_all(&step1.path.join("step1")).unwrap();
        fs::write(
            step1.path.join("step1/step1_output.txt"),
            b"good processing",
        )
        .unwrap();

        let step2 = step1.derive_surrogate_from_self().unwrap();
        fs::write(
            step2.path.join("step2_corrupted_output.txt"),
            b"corrupted partial",
        )
        .unwrap();

        // step 2 messed up and failed, so instead of including its garbage data we use its source
        // (this assumes that the previous step is not a required part of the build)
        let step3 = step2.derive_surrogate_from_root().unwrap();

        let mut writer = AlpackWriter::new(&project.join("archive.alpack"), &step3.path, TEST_KEY);

        // walk through ad add all files in the final step directory
        let mut stack = vec![PathBuf::new()];

        while let Some(rel) = stack.pop() {
            for entry in fs::read_dir(&step3.path.join(&rel)).unwrap() {
                let entry = entry.unwrap();
                let rel_child = rel.join(entry.file_name());
                let file_type = entry.file_type().unwrap();

                if file_type.is_dir() {
                    stack.push(rel_child);
                } else {
                    writer
                        .add(entry.path().as_path(), CompressionType::Lz4, true, 0, 0)
                        .unwrap()
                }
            }
        }

        writer.finalise().unwrap();

        let reader = AlpackReader::open(&project.join("archive.alpack"), TEST_KEY).unwrap();
        let base_data = reader.extract("base.txt").unwrap();
        let step1_data = reader.extract("step1/step1_output.txt").unwrap();
        let step2_data = reader.extract("step2_corrupted_output.txt");

        assert_eq!(base_data, b"base content");
        assert_eq!(step1_data, b"good processing");
        assert!(step2_data.is_err());
    }
}
