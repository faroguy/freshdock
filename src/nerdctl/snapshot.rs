//! Which image a container runs, told from its filesystem.
//!
//! containerd records a container's image by name only, so once its tag has
//! moved, the name says nothing about the image the container was created
//! from. Its filesystem does: it is a snapshot whose parent is the snapshot
//! of its image's top layer, and containerd labels each image config it
//! unpacks with that snapshot (`containerd.io/gc.ref.snapshot.<snapshotter>`).
//! So `ctr` can name the configs of the images a container's filesystem sits
//! on, with nothing freshdock had to note beforehand (seen with containerd
//! 2.3).
//!
//! Two limits. Images with identical layers (a rebuild that only changed
//! `ENV` or a label) sit on the same snapshot, so they can't be told apart.
//! And once an image has no name left, containerd removes its config, so a
//! container whose old image lost its last name can only be found running
//! *something else*.

use serde::Deserialize;
use serde_json::Value;

/// Where a container's filesystem is: from `ctr containers info`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContainerSnapshot {
    pub snapshotter: String,
    pub key: String,
}

/// The snapshot `ctr containers info <id>` names; `None` when it names none.
pub fn container_snapshot(info: &str) -> Option<ContainerSnapshot> {
    #[derive(Deserialize)]
    #[serde(rename_all = "PascalCase")]
    struct Info {
        snapshotter: Option<String>,
        snapshot_key: Option<String>,
    }
    let info: Info = serde_json::from_str(info).ok()?;
    let snapshotter = info.snapshotter.filter(|s| !s.is_empty())?;
    let key = info.snapshot_key.filter(|k| !k.is_empty())?;
    Some(ContainerSnapshot { snapshotter, key })
}

/// The parent `ctr snapshots info <key>` names: the image's top layer.
pub fn snapshot_parent(info: &str) -> Option<String> {
    let info: Value = serde_json::from_str(info).ok()?;
    info.get("Parent")?
        .as_str()
        .filter(|p| !p.is_empty())
        .map(str::to_owned)
}

/// The `ctr content ls` filter for the image configs unpacked onto `parent`.
pub fn configs_on(snapshotter: &str, parent: &str) -> String {
    format!("labels.\"containerd.io/gc.ref.snapshot.{snapshotter}\"=={parent}")
}

/// The digests `ctr content ls -q` printed, one per line.
pub fn digests(listing: &str) -> Vec<String> {
    let mut out: Vec<String> = listing
        .lines()
        .map(str::trim)
        .filter(|l| l.starts_with("sha256:"))
        .map(str::to_owned)
        .collect();
    out.sort();
    out.dedup();
    out
}

/// What an image record's target blob points at.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Target {
    /// A manifest, with its config's digest.
    Config(String),
    /// An index: the manifests for the record's platform.
    Manifests(Vec<String>),
}

/// Read a manifest or an index (`ctr content get <digest>`). For an index,
/// only the manifests for `platform` (`os/architecture[/variant]`, as
/// `nerdctl images` prints it) count; without one, all do.
pub fn target(blob: &str, platform: Option<&str>) -> Option<Target> {
    let blob: Value = serde_json::from_str(blob).ok()?;
    if let Some(config) = blob.pointer("/config/digest").and_then(Value::as_str) {
        return Some(Target::Config(config.to_owned()));
    }
    let manifests = blob.get("manifests")?.as_array()?;
    let mut wanted = platform.map(|p| p.split('/'));
    let (os, arch) = match wanted.as_mut() {
        Some(parts) => (parts.next(), parts.next()),
        None => (None, None),
    };
    let picked = manifests
        .iter()
        .filter(|m| {
            let field = |k: &str| m.pointer(&format!("/platform/{k}")).and_then(Value::as_str);
            os.is_none_or(|os| field("os") == Some(os))
                && arch.is_none_or(|arch| field("architecture") == Some(arch))
        })
        .filter_map(|m| m.get("digest")?.as_str().map(str::to_owned))
        .collect();
    Some(Target::Manifests(picked))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_containers_snapshot_and_its_parent_are_read() {
        // As `ctr` 2.3 prints them for fd-canary-a on testbed.
        let info = r#"{"ID":"cb8b94c3569b","Image":"lscr.io/linuxserver/nginx:latest",
            "Snapshotter":"overlayfs","SnapshotKey":"cb8b94c3569b0e94","Labels":{}}"#;
        assert_eq!(
            container_snapshot(info),
            Some(ContainerSnapshot {
                snapshotter: "overlayfs".to_owned(),
                key: "cb8b94c3569b0e94".to_owned()
            })
        );
        assert_eq!(container_snapshot(r#"{"ID":"x"}"#), None);
        assert_eq!(container_snapshot("not json"), None);
        let snapshot = r#"{"Kind":"Active","Name":"9301","Parent":"sha256:f6df","Created":"x"}"#;
        assert_eq!(snapshot_parent(snapshot).as_deref(), Some("sha256:f6df"));
        assert_eq!(snapshot_parent(r#"{"Kind":"Committed"}"#), None);
    }

    #[test]
    fn the_configs_on_a_snapshot_are_listed() {
        assert_eq!(
            configs_on("overlayfs", "sha256:f6df"),
            r#"labels."containerd.io/gc.ref.snapshot.overlayfs"==sha256:f6df"#
        );
        assert_eq!(
            digests("sha256:b\nsha256:a\n\nsha256:b\n"),
            ["sha256:a", "sha256:b"]
        );
        assert!(digests("").is_empty());
    }

    #[test]
    fn an_image_records_target_leads_to_its_config() {
        let manifest = r#"{"mediaType":"application/vnd.oci.image.manifest.v1+json",
            "config":{"digest":"sha256:cfg"},"layers":[]}"#;
        assert_eq!(
            target(manifest, Some("linux/amd64")),
            Some(Target::Config("sha256:cfg".to_owned()))
        );
        // As immich-server's index: one manifest per platform, and
        // attestations for "unknown/unknown".
        let index = r#"{"mediaType":"application/vnd.oci.image.index.v1+json","manifests":[
            {"digest":"sha256:amd","platform":{"architecture":"amd64","os":"linux"}},
            {"digest":"sha256:att","platform":{"architecture":"unknown","os":"unknown"}},
            {"digest":"sha256:arm","platform":{"architecture":"arm64","os":"linux"}}]}"#;
        assert_eq!(
            target(index, Some("linux/amd64")),
            Some(Target::Manifests(vec!["sha256:amd".to_owned()]))
        );
        assert_eq!(
            target(index, Some("linux/arm64/v8")),
            Some(Target::Manifests(vec!["sha256:arm".to_owned()]))
        );
        assert_eq!(
            target(index, None),
            Some(Target::Manifests(vec![
                "sha256:amd".to_owned(),
                "sha256:att".to_owned(),
                "sha256:arm".to_owned()
            ]))
        );
        assert_eq!(target("{}", None), None);
    }
}
