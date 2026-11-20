//! The digest-named image records freshdock made, and must remove again.
//!
//! Before a pull moves a tag that a sibling still runs, freshdock names the
//! old image by its digest (`Nerdctl::keep_current`). Those names have to be
//! removed once no container runs the image, possibly days later (siblings on
//! different schedules) and possibly by another freshdock process (a one-off
//! `recreate` keeps, the daemon releases). So the list lives in a root-owned
//! state file, not only in memory: a restart in between would otherwise leave
//! the old image held on disk for good, indistinguishable from a record a user
//! made.
//!
//! Every change takes a lock, rereads the file and replaces it whole (see
//! [`update_file`]), so concurrent freshdock processes can share it and a
//! failed write leaves it as it was. Where the file can't be used (freshdock
//! not running as root, say) the list falls back to memory, with a warning.

use std::collections::BTreeSet;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use tracing::warn;

/// Where the daemon and one-off runs keep the list.
pub const DEFAULT_STATE_FILE: &str = "/var/lib/freshdock/nerdctl-kept-images";

/// The kept names for one containerd namespace.
#[derive(Debug)]
pub struct KeptStore {
    namespace: String,
    /// `None` once the file proved unusable, or for an in-memory store.
    file: Mutex<Option<PathBuf>>,
    memory: Mutex<BTreeSet<String>>,
}

impl KeptStore {
    /// A store that lives only as long as this process (tests).
    pub fn in_memory(namespace: &str) -> Self {
        Self {
            namespace: namespace.to_owned(),
            file: Mutex::new(None),
            memory: Mutex::new(BTreeSet::new()),
        }
    }

    /// A store backed by `path`, shared with other freshdock processes.
    pub fn persistent(namespace: &str, path: impl Into<PathBuf>) -> Self {
        Self {
            namespace: namespace.to_owned(),
            file: Mutex::new(Some(path.into())),
            memory: Mutex::new(BTreeSet::new()),
        }
    }

    pub fn insert(&self, name: &str) {
        self.change(|names| {
            names.insert(name.to_owned());
        });
    }

    pub fn remove(&self, name: &str) {
        self.change(|names| {
            names.remove(name);
        });
    }

    /// The names for this namespace, as stored now (including those another
    /// freshdock process added).
    pub fn names(&self) -> BTreeSet<String> {
        let mut out = BTreeSet::new();
        self.change(|names| out = names.clone());
        out
    }

    /// Apply `f` to this namespace's names, persisting the result.
    fn change(&self, mut f: impl FnMut(&mut BTreeSet<String>)) {
        let path = self.file.lock().unwrap().clone();
        if let Some(path) = path {
            match update_file(&path, &self.namespace, &mut f) {
                Ok(()) => return,
                Err(e) => {
                    warn!(
                        path = %path.display(),
                        error = %e,
                        "cannot use the state file for kept images; keeping the list in \
                         memory, so a restart may leave an old image named by its digest"
                    );
                    *self.file.lock().unwrap() = None;
                }
            }
        }
        f(&mut self.memory.lock().unwrap());
    }
}

/// Lock `path`, read every namespace's entries, apply `f` to `namespace`'s, and
/// write it back. Each line is the namespace, a tab, and the entry; an entry
/// may hold further tabs. Created owner-only, in an owner-only directory. On an error
/// `f` may or may not have run; the caller then applies it in memory, which is
/// safe because every change made through it (insert, remove, read) is
/// idempotent. Shared with [`SeenStore`](super::seen::SeenStore).
///
/// The lock is held on a separate `<path>.lock`, which is never replaced, and
/// a change is written to a temporary file that is then renamed over `path`.
/// So a write that fails part-way (a full disk, an I/O error) leaves the
/// previous contents, every namespace's, as they were: rewriting `path` in
/// place would already have truncated them.
pub(super) fn update_file(
    path: &Path,
    namespace: &str,
    f: &mut dyn FnMut(&mut BTreeSet<String>),
) -> std::io::Result<()> {
    let dir = path.parent().filter(|d| !d.as_os_str().is_empty());
    if let Some(dir) = dir {
        create_private_dir_all(dir)?;
    }
    let lock = open_private(&sibling(path, ".lock"))?;
    lock.lock()?;
    let mut body = String::new();
    match std::fs::File::open(path) {
        Ok(mut file) => {
            file.read_to_string(&mut body)?;
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(e),
    }
    let mut others = Vec::new();
    let mut mine = BTreeSet::new();
    for line in body.lines() {
        match line.split_once('\t') {
            Some((ns, name)) if ns == namespace => {
                mine.insert(name.to_owned());
            }
            Some(_) => others.push(line.to_owned()),
            None => {}
        }
    }
    let before = mine.clone();
    f(&mut mine);
    if mine != before {
        let mut out = others.join("\n");
        for name in &mine {
            if !out.is_empty() {
                out.push('\n');
            }
            out.push_str(namespace);
            out.push('\t');
            out.push_str(name);
        }
        if !out.is_empty() {
            out.push('\n');
        }
        replace(path, dir, out.as_bytes())?;
    }
    Ok(())
}

/// `path` with `suffix` added to its file name.
fn sibling(path: &Path, suffix: &str) -> PathBuf {
    let mut name = path.as_os_str().to_owned();
    name.push(suffix);
    PathBuf::from(name)
}

/// Write `body` to a private temporary file next to `path`, sync it, and
/// rename it over `path`; then sync the directory, so the rename itself
/// survives a crash. The caller holds the lock, so the temporary name can't
/// clash with another freshdock process's.
///
/// Only a failure up to the rename is an error: the old contents are then
/// still in place. Once renamed, the new contents are what every process
/// reads, so a directory sync that fails after it is logged, not returned:
/// the write stands, and only whether it would survive a crash is in doubt.
/// Returning it would switch the store to memory while the file holds
/// entries the memory doesn't.
fn replace(path: &Path, dir: Option<&Path>, body: &[u8]) -> std::io::Result<()> {
    let tmp = sibling(path, &format!(".tmp-{}", std::process::id()));
    let written = (|| {
        let mut file = create_private(&tmp)?;
        file.write_all(body)?;
        file.sync_all()?;
        std::fs::rename(&tmp, path)
    })();
    if written.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    written?;
    #[cfg(unix)]
    if let Err(e) = std::fs::File::open(dir.unwrap_or(Path::new("."))).and_then(|d| d.sync_all()) {
        warn!(
            path = %path.display(),
            error = %e,
            "the state file was written, but its directory could not be synced, so the \
             change may not survive a crash"
        );
    }
    #[cfg(not(unix))]
    let _ = dir;
    Ok(())
}

#[cfg(unix)]
fn create_private_dir_all(dir: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::DirBuilderExt;
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(dir)
}

#[cfg(not(unix))]
fn create_private_dir_all(dir: &Path) -> std::io::Result<()> {
    std::fs::create_dir_all(dir)
}

#[cfg(unix)]
fn open_private(path: &Path) -> std::io::Result<std::fs::File> {
    use std::os::unix::fs::OpenOptionsExt;
    std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .open(path)
}

#[cfg(not(unix))]
fn open_private(path: &Path) -> std::io::Result<std::fs::File> {
    std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(path)
}

/// An empty owner-only file at `path`, replacing whatever was left there.
#[cfg(unix)]
fn create_private(path: &Path) -> std::io::Result<std::fs::File> {
    use std::os::unix::fs::OpenOptionsExt;
    std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)
}

#[cfg(not(unix))]
fn create_private(path: &Path) -> std::io::Result<std::fs::File> {
    std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::nerdctl::private::PrivateDir;

    #[test]
    fn names_survive_a_new_store_on_the_same_file() {
        let dir = PrivateDir::new("keptstore").unwrap();
        let path = dir.path().join("state/kept");
        let first = KeptStore::persistent("ns", &path);
        first.insert("repo@sha256:aaa");
        first.insert("repo@sha256:bbb");
        first.remove("repo@sha256:aaa");
        // A restart: a new process reads what the old one kept.
        let second = KeptStore::persistent("ns", &path);
        assert_eq!(second.names(), ["repo@sha256:bbb".to_owned()].into());
    }

    #[test]
    fn namespaces_are_kept_apart_in_one_file() {
        let dir = PrivateDir::new("keptstore").unwrap();
        let path = dir.path().join("kept");
        let a = KeptStore::persistent("a", &path);
        let b = KeptStore::persistent("b", &path);
        a.insert("x@sha256:1");
        b.insert("y@sha256:2");
        a.remove("x@sha256:1");
        assert!(a.names().is_empty());
        assert_eq!(b.names(), ["y@sha256:2".to_owned()].into());
    }

    #[test]
    fn another_process_additions_are_seen() {
        let dir = PrivateDir::new("keptstore").unwrap();
        let path = dir.path().join("kept");
        let daemon = KeptStore::persistent("ns", &path);
        let one_off = KeptStore::persistent("ns", &path);
        one_off.insert("repo@sha256:ccc");
        assert!(daemon.names().contains("repo@sha256:ccc"));
    }

    #[cfg(unix)]
    #[test]
    fn the_state_file_is_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let dir = PrivateDir::new("keptstore").unwrap();
        let path = dir.path().join("state/kept");
        KeptStore::persistent("ns", &path).insert("repo@sha256:ddd");
        let mode = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(&path), 0o600);
        assert_eq!(mode(&sibling(&path, ".lock")), 0o600);
        assert_eq!(mode(path.parent().unwrap()), 0o700);
    }

    #[test]
    fn a_failed_write_leaves_the_file_as_it_was() {
        let dir = PrivateDir::new("keptstore").unwrap();
        let path = dir.path().join("kept");
        KeptStore::persistent("a", &path).insert("x@sha256:1");
        KeptStore::persistent("b", &path).insert("y@sha256:2");
        let before = std::fs::read_to_string(&path).unwrap();
        // Something in the way of the temporary file: the write fails after
        // the old contents were read, which a rewrite in place would already
        // have truncated.
        let tmp = sibling(&path, &format!(".tmp-{}", std::process::id()));
        std::fs::create_dir(&tmp).unwrap();
        let failed = update_file(&path, "a", &mut |names| {
            names.insert("x@sha256:3".to_owned());
        });
        assert!(failed.is_err());
        assert_eq!(
            std::fs::read_to_string(&path).unwrap(),
            before,
            "every namespace's entries survive"
        );
        std::fs::remove_dir(&tmp).unwrap();
        KeptStore::persistent("a", &path).insert("x@sha256:3");
        assert_eq!(
            KeptStore::persistent("b", &path).names(),
            ["y@sha256:2".to_owned()].into()
        );
    }

    #[test]
    fn a_write_leaves_no_temporary_file() {
        let dir = PrivateDir::new("keptstore").unwrap();
        let path = dir.path().join("kept");
        let store = KeptStore::persistent("ns", &path);
        store.insert("repo@sha256:1");
        store.remove("repo@sha256:1");
        let mut left: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .map(|e| e.unwrap().file_name().into_string().unwrap())
            .collect();
        left.sort();
        assert_eq!(left, ["kept", "kept.lock"]);
    }

    #[test]
    fn concurrent_changes_are_not_lost() {
        let dir = PrivateDir::new("keptstore").unwrap();
        let path = dir.path().join("kept");
        std::thread::scope(|s| {
            for t in 0..4 {
                let path = &path;
                s.spawn(move || {
                    // A store each, as separate processes would have.
                    let store = KeptStore::persistent("ns", path);
                    for n in 0..10 {
                        store.insert(&format!("repo@sha256:{t}-{n}"));
                    }
                });
            }
        });
        assert_eq!(KeptStore::persistent("ns", &path).names().len(), 40);
    }

    #[test]
    fn an_unusable_file_falls_back_to_memory() {
        let store = KeptStore::persistent("ns", "/proc/definitely/not/writable/kept");
        store.insert("repo@sha256:eee");
        store.insert("repo@sha256:fff");
        assert_eq!(
            store.names(),
            ["repo@sha256:eee".to_owned(), "repo@sha256:fff".to_owned()].into(),
            "nothing is lost when the file can't be used"
        );
    }

    #[test]
    fn an_in_memory_store_works_without_a_file() {
        let store = KeptStore::in_memory("ns");
        store.insert("repo@sha256:ggg");
        assert!(store.names().contains("repo@sha256:ggg"));
        store.remove("repo@sha256:ggg");
        assert!(store.names().is_empty());
    }
}
