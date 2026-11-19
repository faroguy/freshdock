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

/// The `history` entries of an image config blob, in order; none when it
/// has no history (or isn't a config).
pub fn history(blob: &str) -> Vec<Value> {
    serde_json::from_str::<Value>(blob)
        .ok()
        .and_then(|b| b.get("history")?.as_array().cloned())
        .unwrap_or_default()
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
    let wanted = platform.map(|p| {
        let mut parts = p.split('/');
        let os = parts.next().unwrap_or("");
        let arch = parts.next().unwrap_or("");
        normalise(os, arch, parts.next().unwrap_or(""))
    });
    let picked = manifests
        .iter()
        .filter(|m| {
            let field = |k: &str| {
                m.pointer(&format!("/platform/{k}"))
                    .and_then(Value::as_str)
                    .unwrap_or("")
            };
            wanted.as_ref().is_none_or(|w| {
                *w == normalise(field("os"), field("architecture"), field("variant"))
            })
        })
        .filter_map(|m| m.get("digest")?.as_str().map(str::to_owned))
        .collect();
    Some(Target::Manifests(picked))
}

/// A platform in one spelling, as containerd's `platforms.Normalize` gives
/// it, so that equal platforms compare equal: architecture aliases are
/// folded (`aarch64` is `arm64`, `x86_64` is `amd64`) and default variants
/// made one (`arm64` and `arm64/v8`, `amd64` and `amd64/v1`, `arm` and
/// `arm/v7`). A different variant is a different platform: nerdctl wouldn't
/// pick an `arm/v7` manifest for `arm/v6`.
fn normalise(os: &str, arch: &str, variant: &str) -> (String, String, String) {
    let os = os.to_ascii_lowercase();
    let (arch, variant) = match (arch.to_ascii_lowercase().as_str(), variant) {
        ("x86_64" | "x86-64" | "amd64", "v1") => ("amd64", String::new()),
        ("x86_64" | "x86-64" | "amd64", v) => ("amd64", v.to_owned()),
        ("aarch64" | "arm64", "8" | "v8" | "v8.0") => ("arm64", String::new()),
        ("aarch64" | "arm64", v) => ("arm64", v.to_owned()),
        ("armhf", _) => ("arm", "v7".to_owned()),
        ("armel", _) => ("arm", "v6".to_owned()),
        ("arm", "" | "7") => ("arm", "v7".to_owned()),
        ("arm", v @ ("5" | "6" | "8")) => ("arm", format!("v{v}")),
        ("arm", v) => ("arm", v.to_owned()),
        (other, v) => return (os, other.to_owned(), v.to_owned()),
    };
    (os, arch.to_owned(), variant)
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

    #[test]
    fn an_index_manifest_is_picked_by_its_cpu_variant_too() {
        // #115 review: two arm manifests that differ only in variant.
        let index = r#"{"manifests":[
            {"digest":"sha256:v6","platform":{"architecture":"arm","os":"linux","variant":"v6"}},
            {"digest":"sha256:v7","platform":{"architecture":"arm","os":"linux","variant":"v7"}},
            {"digest":"sha256:a64","platform":{"architecture":"arm64","os":"linux","variant":"v8"}},
            {"digest":"sha256:amd","platform":{"architecture":"amd64","os":"linux"}}]}"#;
        let picked = |platform| match target(index, Some(platform)) {
            Some(Target::Manifests(m)) => m,
            other => panic!("{other:?}"),
        };
        assert_eq!(picked("linux/arm/v6"), ["sha256:v6"]);
        assert_eq!(picked("linux/arm/v7"), ["sha256:v7"]);
        assert_eq!(picked("linux/arm"), ["sha256:v7"], "arm means arm/v7");
        assert_eq!(
            picked("linux/arm64"),
            ["sha256:a64"],
            "arm64 means arm64/v8"
        );
        assert_eq!(picked("linux/arm64/v8"), ["sha256:a64"]);
        assert_eq!(picked("linux/amd64/v1"), ["sha256:amd"]);
        assert!(picked("linux/arm/v5").is_empty());
    }
}
