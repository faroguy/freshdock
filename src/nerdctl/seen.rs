//! The image each container runs, as freshdock first saw it.
//!
//! containerd records a container's image by name only. Once a pull moves
//! the tag, nothing nerdctl reports says which image a container created
//! from it still runs: a sibling on the same tag, or the container itself
//! when its update was called off after the pull (a pre-update hook's "not
//! now", a refused preflight, a rollback). freshdock notes each container's
//! image the first time it lists it, before anything pulls.
//!
//! Those notes have to outlive the process. Otherwise, after a restart, the
//! tag's new image would be taken for the one the container runs: the update
//! check would call it up to date, and its rebuild would leave out the wrong
//! image's settings (see [`ImageConfig`](super::spec::ImageConfig)). So they
//! live in a root-owned state file, shared with other freshdock processes the
//! way [`KeptStore`](super::kept::KeptStore) is, with an in-memory copy for the
//! lookups of every pass.

use std::collections::{BTreeSet, HashMap, HashSet};
use std::path::PathBuf;
use std::sync::Mutex;

use tracing::warn;

use super::kept::update_file;

/// Where the daemon and one-off runs keep the notes.
pub const DEFAULT_SEEN_FILE: &str = "/var/lib/freshdock/nerdctl-seen-images";

/// One image, as nerdctl can be asked for it.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Seen {
    /// The config digest `image inspect` reports as `Id`: what the update
    /// check compares against the tag's (see `probe::behind_tag`).
    pub id: Option<String>,
    /// A digest-pinned reference (`docker.io/library/nginx@sha256:...`), the
    /// handle `nerdctl create` and `rmi` accept for one specific image.
    pub pinned: Option<String>,
}

impl Seen {
    /// `<container id>\t<config digest>\t<pinned reference>`, an absent one
    /// empty.
    fn entry(&self, container: &str) -> String {
        format!(
            "{container}\t{}\t{}",
            self.id.as_deref().unwrap_or(""),
            self.pinned.as_deref().unwrap_or("")
        )
    }

    fn parse(entry: &str) -> Option<(String, Seen)> {
        let mut fields = entry.split('\t');
        let container = fields.next().filter(|c| !c.is_empty())?;
        let some = |f: Option<&str>| f.filter(|v| !v.is_empty()).map(str::to_owned);
        let seen = Seen {
            id: some(fields.next()),
            pinned: some(fields.next()),
        };
        Some((container.to_owned(), seen))
    }
}

/// The notes for one containerd namespace, by container id.
#[derive(Debug)]
pub struct SeenStore {
    namespace: String,
    /// `None` once the file proved unusable, or for an in-memory store.
    file: Mutex<Option<PathBuf>>,
    memory: Mutex<HashMap<String, Seen>>,
}

impl SeenStore {
    /// Notes that live only as long as this process (tests).
    pub fn in_memory(namespace: &str) -> Self {
        Self {
            namespace: namespace.to_owned(),
            file: Mutex::new(None),
            memory: Mutex::new(HashMap::new()),
        }
    }

    /// Notes backed by `path`, shared with other freshdock processes.
    pub fn persistent(namespace: &str, path: impl Into<PathBuf>) -> Self {
        Self {
            namespace: namespace.to_owned(),
            file: Mutex::new(Some(path.into())),
            memory: Mutex::new(HashMap::new()),
        }
    }

    /// The note for `container`: this process's, or one in the file (made
    /// before a restart, or by another freshdock process).
    pub fn get(&self, container: &str) -> Option<Seen> {
        if let Some(seen) = self.memory.lock().unwrap().get(container) {
            return Some(seen.clone());
        }
        let mut found = None;
        self.change_file(|entries| {
            found = entries
                .iter()
                .filter_map(|e| Seen::parse(e))
                .find(|(c, _)| c == container)
                .map(|(_, seen)| seen);
        });
        if let Some(seen) = &found {
            self.memory
                .lock()
                .unwrap()
                .insert(container.to_owned(), seen.clone());
        }
        found
    }

    /// Note `container`'s image. Only an image freshdock could name goes to
    /// the file: "nothing" (a tag with no local image) is an answer for this
    /// run, and looked at again after a restart.
    pub fn insert(&self, container: &str, seen: Seen) {
        if seen != Seen::default() {
            let entry = seen.entry(container);
            self.change_file(|entries| {
                entries.retain(|e| Seen::parse(e).is_none_or(|(c, _)| c != container));
                entries.insert(entry.clone());
            });
        }
        self.memory
            .lock()
            .unwrap()
            .insert(container.to_owned(), seen);
    }

    /// Every container with a note: this process's, and those in the file
    /// (another freshdock's, or from before a restart).
    pub fn noted(&self) -> HashSet<String> {
        let mut out: HashSet<String> = self.memory.lock().unwrap().keys().cloned().collect();
        self.change_file(|entries| {
            out.extend(
                entries
                    .iter()
                    .filter_map(|e| Seen::parse(e))
                    .map(|(c, _)| c),
            );
        });
        out
    }

    /// Forget the containers in `gone`, and only those: a note another
    /// freshdock process writes meanwhile is left alone.
    pub fn forget(&self, gone: &HashSet<String>) {
        if gone.is_empty() {
            return;
        }
        self.memory.lock().unwrap().retain(|c, _| !gone.contains(c));
        self.change_file(|entries| {
            entries.retain(|e| Seen::parse(e).is_some_and(|(c, _)| !gone.contains(&c)));
        });
    }

    /// The images of the containers this process has looked at.
    pub fn values(&self) -> Vec<Seen> {
        self.memory.lock().unwrap().values().cloned().collect()
    }

    /// The same, with each container's id.
    pub fn entries(&self) -> Vec<(String, Seen)> {
        self.memory
            .lock()
            .unwrap()
            .iter()
            .map(|(c, s)| (c.clone(), s.clone()))
            .collect()
    }

    pub fn len(&self) -> usize {
        self.memory.lock().unwrap().len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Apply `f` to this namespace's entries in the file. Once the file
    /// proves unusable the notes are kept in memory only, with a warning.
    fn change_file(&self, mut f: impl FnMut(&mut BTreeSet<String>)) {
        let path = self.file.lock().unwrap().clone();
        let Some(path) = path else {
            return;
        };
        if let Err(e) = update_file(&path, &self.namespace, &mut f) {
            warn!(
                path = %path.display(),
                error = %e,
                "cannot use the state file for the images containers run; keeping them in \
                 memory, so after a restart a container whose tag has moved may be taken \
                 for one on the tag's new image"
            );
            *self.file.lock().unwrap() = None;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::nerdctl::private::PrivateDir;

    fn image(n: u8) -> Seen {
        Seen {
            id: Some(format!("sha256:{n}")),
            pinned: Some(format!("repo@sha256:{n}{n}")),
        }
    }

    #[test]
    fn a_note_survives_a_restart() {
        let dir = PrivateDir::new("seenstore").unwrap();
        let path = dir.path().join("state/seen");
        let first = SeenStore::persistent("ns", &path);
        first.insert("c1", image(1));
        first.insert("c2", image(2));
        first.insert("c1", image(3));
        // A restart: the new process knows what the old one noted.
        let second = SeenStore::persistent("ns", &path);
        assert_eq!(second.get("c1"), Some(image(3)), "the latest note");
        assert_eq!(second.get("c2"), Some(image(2)));
        assert_eq!(second.get("c3"), None);
    }

    #[test]
    fn another_process_notes_are_found() {
        let dir = PrivateDir::new("seenstore").unwrap();
        let path = dir.path().join("seen");
        let daemon = SeenStore::persistent("ns", &path);
        assert_eq!(daemon.get("c1"), None);
        // A one-off `recreate` notes a container the daemon has not listed.
        SeenStore::persistent("ns", &path).insert("c1", image(1));
        assert_eq!(daemon.get("c1"), Some(image(1)));
    }

    #[test]
    fn namespaces_are_kept_apart_and_gone_containers_forgotten() {
        let dir = PrivateDir::new("seenstore").unwrap();
        let path = dir.path().join("seen");
        let a = SeenStore::persistent("a", &path);
        let b = SeenStore::persistent("b", &path);
        a.insert("c1", image(1));
        a.insert("c2", image(2));
        b.insert("c1", image(9));
        assert_eq!(a.noted(), ["c1".to_owned(), "c2".to_owned()].into());
        a.forget(&["c1".to_owned()].into());
        let a = SeenStore::persistent("a", &path);
        assert_eq!(a.get("c1"), None);
        assert_eq!(a.get("c2"), Some(image(2)));
        assert_eq!(
            SeenStore::persistent("b", &path).get("c1"),
            Some(image(9)),
            "another namespace's note is untouched"
        );
    }

    #[test]
    fn nothing_found_is_not_written_down() {
        let dir = PrivateDir::new("seenstore").unwrap();
        let path = dir.path().join("seen");
        let store = SeenStore::persistent("ns", &path);
        store.insert("c1", Seen::default());
        assert_eq!(
            store.get("c1"),
            Some(Seen::default()),
            "remembered this run"
        );
        assert_eq!(
            SeenStore::persistent("ns", &path).get("c1"),
            None,
            "and looked at again after a restart"
        );
        let half = Seen {
            id: Some("sha256:1".to_owned()),
            pinned: None,
        };
        store.insert("c2", half.clone());
        assert_eq!(SeenStore::persistent("ns", &path).get("c2"), Some(half));
    }

    #[cfg(unix)]
    #[test]
    fn the_state_file_is_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let dir = PrivateDir::new("seenstore").unwrap();
        let path = dir.path().join("state/seen");
        SeenStore::persistent("ns", &path).insert("c1", image(1));
        let mode = |p: &std::path::Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(&path), 0o600);
        assert_eq!(mode(path.parent().unwrap()), 0o700);
    }

    #[test]
    fn an_unusable_file_falls_back_to_memory() {
        let store = SeenStore::persistent("ns", "/proc/definitely/not/writable/seen");
        store.insert("c1", image(1));
        assert_eq!(store.get("c1"), Some(image(1)));
        store.forget(&["c1".to_owned()].into());
        assert!(store.is_empty());
    }

    #[test]
    fn a_note_written_after_the_others_were_read_is_not_forgotten() {
        let dir = PrivateDir::new("seenstore").unwrap();
        let path = dir.path().join("seen");
        let daemon = SeenStore::persistent("ns", &path);
        daemon.insert("gone", image(1));
        let gone = daemon.noted();
        // A one-off run notes a new container before the daemon prunes.
        SeenStore::persistent("ns", &path).insert("new", image(2));
        daemon.forget(&gone);
        assert_eq!(daemon.get("gone"), None);
        assert_eq!(daemon.get("new"), Some(image(2)));
    }
}
