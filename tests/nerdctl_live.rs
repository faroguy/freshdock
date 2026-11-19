//! Live nerdctl gate: the update cycle against a **real** containerd, driven
//! through the nerdctl CLI exactly as `FRESHDOCK_RUNTIME=nerdctl` does.
//!
//! Opt-in twice over. The tests are `#[ignore]`d, and they only run when
//! `FRESHDOCK_NERDCTL_LIVE=1`; otherwise they skip, even under
//! `FRESHDOCK_LIVE_REQUIRED`, so the Docker live gate (`just live`) is not
//! turned red by a host without nerdctl. With the variable set, an unreachable
//! nerdctl is a failure, not a skip.
//!
//! Needs rootful nerdctl (2.3+), and BuildKit for the tests that build
//! images, so run the test binary as root:
//!
//! ```bash
//! bin=$(cargo test --locked --test nerdctl_live --no-run --message-format=json \
//!   | jq -r 'select(.executable != null and .profile.test) | .executable')
//! sudo FRESHDOCK_NERDCTL_LIVE=1 "$bin" --ignored --test-threads=1
//! ```
//!
//! Everything happens in the `freshdock-live` containerd namespace, under
//! per-test name prefixes, and is removed afterwards, even on a failed
//! assertion.

use std::process::Command;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use freshdock::config::{CredentialStore, Runtime, RuntimeSettings};
use freshdock::docker::check::DockerCheck;
use freshdock::docker::recreate::{Cleanup, DockerOps, recreate_with_health};
use freshdock::health::{HealthConfig, TokioClock};
use freshdock::labels::LifecycleHooks;
use freshdock::nerdctl::inspect::classify_error;
use freshdock::nerdctl::private::unique_suffix;
use freshdock::nerdctl::{Nerdctl, compare};
use freshdock::updater::RecreateOutcome;
use serde_json::Value;

const NS: &str = "freshdock-live";
const ALPINE: &str = "docker.io/library/alpine:3.20";
const NGINX: &str = "docker.io/library/nginx:1.27-alpine";

fn enabled() -> bool {
    std::env::var("FRESHDOCK_NERDCTL_LIVE")
        .map(|v| matches!(v.trim().to_ascii_lowercase().as_str(), "1" | "true" | "yes"))
        .unwrap_or(false)
}

fn nerdctl_bin() -> String {
    std::env::var("FRESHDOCK_NERDCTL_PATH").unwrap_or_else(|_| "nerdctl".to_owned())
}

/// Run nerdctl in the test namespace; `Err` carries its stderr.
fn nerdctl(args: &[&str]) -> Result<String, String> {
    let out = Command::new(nerdctl_bin())
        .args(["--namespace", NS])
        .args(args)
        .output()
        .map_err(|e| format!("could not run nerdctl: {e}"))?;
    if out.status.success() {
        Ok(String::from_utf8_lossy(&out.stdout).trim().to_owned())
    } else {
        Err(String::from_utf8_lossy(&out.stderr).trim().to_owned())
    }
}

fn must(args: &[&str]) -> String {
    nerdctl(args).unwrap_or_else(|e| panic!("nerdctl {}: {e}", args.join(" ")))
}

/// Run containerd's `ctr` (next to nerdctl, else on `PATH`) in the test
/// namespace; a failure panics.
fn ctr(args: &[&str]) -> String {
    let bin = std::path::Path::new(&nerdctl_bin())
        .parent()
        .map(|dir| dir.join("ctr"))
        .filter(|p| p.exists())
        .map_or_else(|| "ctr".to_owned(), |p| p.display().to_string());
    let out = Command::new(&bin)
        .args(["--namespace", NS])
        .args(args)
        .output()
        .unwrap_or_else(|e| panic!("could not run {bin}: {e}"));
    assert!(
        out.status.success(),
        "ctr {}: {}",
        args.join(" "),
        String::from_utf8_lossy(&out.stderr).trim()
    );
    String::from_utf8_lossy(&out.stdout).trim().to_owned()
}

/// The image configs the container's filesystem sits on, as `ctr` lists
/// them: what freshdock tells a container's image by.
fn configs_under(name: &str) -> String {
    let id = id_of(name).expect("the container exists");
    let info: Value = serde_json::from_str(&ctr(&["containers", "info", &id])).unwrap();
    let snapshotter = info["Snapshotter"].as_str().unwrap();
    let key = info["SnapshotKey"].as_str().unwrap();
    let snapshot: Value = serde_json::from_str(&ctr(&[
        "snapshots",
        "--snapshotter",
        snapshotter,
        "info",
        key,
    ]))
    .unwrap();
    let parent = snapshot["Parent"].as_str().unwrap();
    ctr(&[
        "content",
        "ls",
        "-q",
        &format!(r#"labels."containerd.io/gc.ref.snapshot.{snapshotter}"=={parent}"#),
    ])
}

/// The container's inspect, or `None` when nerdctl says there is no such
/// container. Any other failure panics, so an inspect that broke never
/// passes for a container that is gone.
fn inspect(name: &str) -> Option<Value> {
    match nerdctl(&["inspect", name]) {
        Ok(out) => {
            let listed = serde_json::from_str::<Vec<Value>>(&out)
                .unwrap_or_else(|e| panic!("nerdctl inspect {name}: {e}: {out}"));
            match listed.into_iter().next() {
                Some(c) => Some(c),
                None => panic!("nerdctl inspect {name} listed nothing"),
            }
        }
        Err(e) if classify_error(e.clone()).is_not_found() => None,
        Err(e) => panic!("nerdctl inspect {name}: {e}"),
    }
}

fn native(name: &str) -> Value {
    let out = must(&["inspect", "--mode=native", name]);
    serde_json::from_str::<Vec<Value>>(&out).unwrap().remove(0)
}

fn id_of(name: &str) -> Option<String> {
    inspect(name)?["Id"].as_str().map(str::to_owned)
}

fn running(name: &str) -> bool {
    inspect(name).is_some_and(|c| c["State"]["Running"] == Value::Bool(true))
}

/// `portMappings` from the container's `network-config.json`. Panics when it
/// can't be read, so two unreadable files never compare equal.
fn port_mappings(name: &str) -> Value {
    let c = inspect(name).expect("container exists");
    let dir = c["Config"]["Labels"]["nerdctl/state-dir"]
        .as_str()
        .expect("state dir");
    let path = format!("{dir}/network-config.json");
    let body = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{path}: {e}"));
    let config: Value = serde_json::from_str(&body).unwrap_or_else(|e| panic!("{path}: {e}"));
    match &config["portMappings"] {
        Value::Array(_) => config["portMappings"].clone(),
        other => panic!("{path}: portMappings is {other}"),
    }
}

fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs() as i64)
}

fn prefix(test: &str) -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.subsec_nanos());
    format!("fdl-{test}-{nanos}")
}

/// Stops and removes every container whose name starts with the prefix, then
/// the listed networks and every volume whose name starts with the prefix
/// (after the containers that mount them). Stopping first matters: `rm -f` on
/// a container with a restart policy can race containerd's restart monitor
/// and orphan a task that keeps its ports.
struct Teardown {
    prefix: String,
    networks: Vec<String>,
}

impl Drop for Teardown {
    fn drop(&mut self) {
        let names = nerdctl(&["ps", "-a", "--format", "{{.Names}}"]).unwrap_or_default();
        // `--volumes`: and their anonymous volumes, such as the one each
        // test registry's image declares.
        for name in names.lines().filter(|n| n.starts_with(&self.prefix)) {
            let _ = nerdctl(&["stop", "--time", "1", name]);
            if nerdctl(&["rm", "--volumes", name]).is_err() {
                let _ = nerdctl(&["rm", "--force", "--volumes", name]);
            }
        }
        for net in &self.networks {
            let _ = nerdctl(&["network", "rm", net]);
        }
        let volumes = nerdctl(&["volume", "ls", "--format", "{{.Name}}"]).unwrap_or_default();
        for volume in volumes.lines().filter(|v| v.starts_with(&self.prefix)) {
            let _ = nerdctl(&["volume", "rm", volume]);
        }
    }
}

/// The backend under test, or `None` to skip.
async fn backend() -> Option<Nerdctl> {
    if !enabled() {
        eprintln!("skipping: set FRESHDOCK_NERDCTL_LIVE=1 to run the nerdctl live gate");
        return None;
    }
    let settings = RuntimeSettings {
        runtime: Runtime::Nerdctl,
        nerdctl_path: nerdctl_bin(),
        containerd_namespace: NS.to_owned(),
    };
    let n = Nerdctl::connect(&settings, Arc::new(CredentialStore::default()))
        .await
        .unwrap_or_else(|e| panic!("FRESHDOCK_NERDCTL_LIVE is set but nerdctl is unusable: {e}"));
    must(&["pull", "--quiet", ALPINE]);
    must(&["pull", "--quiet", NGINX]);
    Some(n)
}

fn health() -> HealthConfig {
    HealthConfig {
        health_timeout: Duration::from_secs(60),
        grace_period: Duration::from_secs(5),
        poll_interval: Duration::from_millis(500),
    }
}

const NO_CLEANUP: Cleanup = Cleanup {
    remove_replaced: false,
    prune_dangling: false,
};

async fn recreate(
    n: &Nerdctl,
    name: &str,
) -> Result<RecreateOutcome, freshdock::docker::DockerError> {
    recreate_with_health(
        n,
        name,
        &health(),
        &TokioClock,
        NO_CLEANUP,
        &LifecycleHooks::default(),
        now_unix,
    )
    .await
}

#[tokio::test]
#[ignore = "needs rootful nerdctl; set FRESHDOCK_NERDCTL_LIVE=1"]
async fn a_richly_configured_container_round_trips() {
    let Some(n) = backend().await else { return };
    let p = prefix("rt");
    let net = format!("{p}-net");
    let vol = format!("{p}-vol");
    let _teardown = Teardown {
        prefix: p.clone(),
        networks: vec![net.clone()],
    };
    must(&["network", "create", &net]);
    let name = format!("{p}-web");
    let volume = format!("{vol}:/data");
    #[rustfmt::skip]
    let args = [
        "run", "-d", "--name", &name,
        "--label", "freshdock.enable=true", "--label", "app=demo",
        "--network", &net,
        "-p", "127.0.0.1:18190:80", "-p", "[::1]:18191:81",
        "-v", &volume, "-v", "/etc/hostname:/host-hostname:ro", "--tmpfs", "/scratch",
        "-e", "FOO=bar", "-e", "SPACED=a b c", "--workdir", "/usr/share/nginx",
        "--restart", "unless-stopped",
        "--health-cmd", "wget -qO- http://127.0.0.1/ >/dev/null || exit 1",
        "--health-interval", "2s",
        "--hostname", "rt-host", "--add-host", "example.test:10.0.0.9", "--dns", "9.9.9.9",
        "--cap-add", "NET_ADMIN", "--memory", "256m", "--cpus", "0.5", "--pids-limit", "300",
        // Zero and -1 are settings here, not "unset" (#115 review).
        "--memory-swappiness", "0", "--memory-swap", "-1", "--oom-score-adj", "-1",
        // Recorded only in the OCI cgroups path.
        "--cgroup-parent", "freshdock-live.slice",
        "--stop-signal", "SIGQUIT", "--stop-timeout", "20", "--log-opt", "max-size=5m",
        "--security-opt", "no-new-privileges", "--init", "--shm-size", "96m",
        NGINX,
    ];
    must(&args);
    let before_id = id_of(&name).unwrap();
    let before = native(&name);
    let before_ports = port_mappings(&name);
    let host_ports: Vec<_> = before_ports
        .as_array()
        .unwrap()
        .iter()
        .map(|m| m["HostPort"].as_u64())
        .collect();
    assert_eq!(
        host_ports,
        [Some(18190), Some(18191)],
        "both published ports, before anything is compared: {before_ports}"
    );
    let cgroups_path = |c: &Value| {
        c["Spec"]["linux"]["cgroupsPath"]
            .as_str()
            .map(str::to_owned)
    };
    assert!(
        cgroups_path(&before).is_some_and(|p| p.starts_with("freshdock-live.slice:")),
        "{:?}",
        cgroups_path(&before)
    );
    let records_before = digest_records();

    let outcome = recreate(&n, &name).await.expect("recreate");
    assert_eq!(
        digest_records(),
        records_before,
        "updating a lone container leaves no digest-named image record behind"
    );
    assert!(
        matches!(outcome, RecreateOutcome::Recreated { .. }),
        "{outcome:?}"
    );

    let after_id = id_of(&name).expect("the container exists under its name");
    assert_ne!(after_id, before_id, "a new container replaced the old one");
    assert!(running(&name));
    let after = native(&name);
    let differences = compare::differences(&before, &before_id, &after, &after_id);
    assert!(differences.is_empty(), "settings changed: {differences:?}");
    assert!(
        cgroups_path(&after).is_some_and(|p| p.starts_with("freshdock-live.slice:")),
        "still under its cgroup parent: {:?}",
        cgroups_path(&after)
    );
    assert_eq!(
        after["Spec"]["linux"]["resources"]["memory"]["swap"], -1,
        "unlimited swap carried over"
    );
    assert_eq!(
        after["Spec"]["linux"]["resources"]["memory"]["swappiness"], 0,
        "zero swappiness carried over"
    );
    assert_eq!(
        after["Spec"]["process"]["oomScoreAdj"], -1,
        "an OOM score of -1 carried over"
    );
    assert_eq!(
        port_mappings(&name),
        before_ports,
        "published ports carried over"
    );
    let names = must(&["ps", "-a", "--format", "{{.Names}}"]);
    assert!(
        !names
            .lines()
            .any(|l| l.starts_with(&format!("{name}-old-")) || l.contains("-freshdock-")),
        "no archive or throwaway container left: {names}"
    );
}

#[tokio::test]
#[ignore = "needs rootful nerdctl; set FRESHDOCK_NERDCTL_LIVE=1"]
async fn a_compose_service_round_trips() {
    // As `nerdctl compose` makes containers: a temporary `--cidfile`, and the
    // namespace from the environment rather than a flag. The image's own
    // entrypoint ends in `--` (`tini --` style), so the container's command
    // starts with one, which a create from the command line would lose.
    let Some(n) = backend().await else { return };
    let p = prefix("compose");
    // The update pulls the image, so it is served from a local registry.
    let image = "127.0.0.1:15001/freshdock-live/entry:1".to_owned();
    // Declared first so it drops last, after the containers using it.
    let _image = RemoveImage(image.clone());
    let _teardown = Teardown {
        prefix: p.clone(),
        networks: vec![format!("{p}_default")],
    };
    must(&[
        "run",
        "-d",
        "--name",
        &format!("{p}-registry"),
        "-p",
        "127.0.0.1:15001:5000",
        "docker.io/library/registry:2",
    ]);
    let base = format!("{p}-base");
    must(&["run", "-d", "--name", &base, ALPINE, "sleep", "100000"]);
    must(&[
        "commit",
        "--change",
        r#"ENTRYPOINT ["/usr/bin/env", "--"]"#,
        &base,
        &image,
    ]);
    must(&["stop", "--time", "1", &base]);
    must(&["rm", &base]);
    let mut pushed = Err(String::new());
    for _ in 0..20 {
        pushed = nerdctl(&["push", &image]);
        if pushed.is_ok() {
            break;
        }
        std::thread::sleep(Duration::from_millis(500));
    }
    pushed.unwrap_or_else(|e| panic!("push {image}: {e}"));

    let dir = std::env::temp_dir().join(&p);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(
        dir.join("compose.yaml"),
        format!(
            "services:\n  app:\n    image: {image}\n    command: [\"sleep\", \"100000\"]\n    \
             restart: unless-stopped\n    labels:\n      - freshdock.enable=true\n"
        ),
    )
    .unwrap();
    let up = Command::new(nerdctl_bin())
        .args(["compose", "-p", &p, "up", "-d"])
        .current_dir(&dir)
        .env("CONTAINERD_NAMESPACE", NS)
        .output()
        .expect("nerdctl compose");
    std::fs::remove_dir_all(&dir).ok();
    assert!(
        up.status.success(),
        "{}",
        String::from_utf8_lossy(&up.stderr)
    );
    let name = format!("{p}-app-1");
    let before = native(&name);
    assert_eq!(
        before["Spec"]["process"]["args"],
        serde_json::json!(["/usr/bin/env", "--", "sleep", "100000"])
    );

    let outcome = recreate(&n, &name).await.expect("not refused");
    assert!(
        matches!(outcome, RecreateOutcome::Recreated { .. }),
        "{outcome:?}"
    );
    assert_eq!(
        native(&name)["Spec"]["process"]["args"],
        before["Spec"]["process"]["args"],
        "the command, `--` included, carried over"
    );
    assert!(running(&name));
}

#[tokio::test]
#[ignore = "needs rootful nerdctl; set FRESHDOCK_NERDCTL_LIVE=1"]
async fn a_crashing_replacement_is_rolled_back() {
    let Some(n) = backend().await else { return };
    let p = prefix("rb");
    let _teardown = Teardown {
        prefix: p.clone(),
        networks: vec![],
    };
    let name = format!("{p}-app");
    // Stays up only while /tmp/ok exists in its own writable layer, which a
    // replacement never has. The marker is copied in before the first start,
    // so the original never looks for it too early.
    must(&[
        "create",
        "--name",
        &name,
        "--label",
        "freshdock.enable=true",
        ALPINE,
        "sh",
        "-c",
        "while [ -f /tmp/ok ]; do sleep 1; done; exit 3",
    ]);
    let marker = std::env::temp_dir().join(format!("{p}-ok"));
    std::fs::write(&marker, "").unwrap();
    let copied = nerdctl(&[
        "cp",
        &marker.display().to_string(),
        &format!("{name}:/tmp/ok"),
    ]);
    std::fs::remove_file(&marker).ok();
    copied.unwrap_or_else(|e| panic!("nerdctl cp: {e}"));
    must(&["start", &name]);
    assert!(running(&name), "the original runs on its marker");
    let before_id = id_of(&name).unwrap();

    let outcome = recreate(&n, &name).await.expect("recreate");
    assert!(
        matches!(outcome, RecreateOutcome::RolledBack(_)),
        "{outcome:?}"
    );
    assert_eq!(
        id_of(&name).as_deref(),
        Some(before_id.as_str()),
        "the original is back"
    );
    assert!(running(&name));
}

#[tokio::test]
#[ignore = "needs rootful nerdctl; set FRESHDOCK_NERDCTL_LIVE=1"]
async fn a_network_namespace_dependent_follows_its_owner() {
    let Some(n) = backend().await else { return };
    let p = prefix("ns");
    let _teardown = Teardown {
        prefix: p.clone(),
        networks: vec![],
    };
    let owner = format!("{p}-vpn");
    let dependent = format!("{p}-app");
    must(&[
        "run",
        "-d",
        "--name",
        &owner,
        "--label",
        "freshdock.enable=true",
        ALPINE,
        "sleep",
        "100000",
    ]);
    must(&[
        "run",
        "-d",
        "--name",
        &dependent,
        "--network",
        &format!("container:{owner}"),
        ALPINE,
        "sleep",
        "100000",
    ]);
    let dependent_before = id_of(&dependent).unwrap();

    let outcome = recreate(&n, &owner).await.expect("recreate");
    assert!(
        matches!(outcome, RecreateOutcome::Recreated { .. }),
        "{outcome:?}"
    );
    let owner_after = id_of(&owner).unwrap();
    let dep = inspect(&dependent).expect("dependent exists");
    assert_ne!(
        id_of(&dependent).unwrap(),
        dependent_before,
        "the dependent was re-created"
    );
    assert_eq!(
        dep["HostConfig"]["NetworkMode"],
        format!("container:{owner_after}")
    );
    assert_eq!(
        dep["Config"]["Image"], ALPINE,
        "still on its tag, so it keeps being checked (#102)"
    );
    assert!(running(&dependent));
}

#[tokio::test]
#[ignore = "needs rootful nerdctl; set FRESHDOCK_NERDCTL_LIVE=1"]
async fn an_owner_whose_dependent_cannot_be_recreated_is_left_alone() {
    // The dependent would have to be re-created after the owner's update,
    // and an env file can't carry its multi-line value: refused up front,
    // rather than stopping the dependent and failing to bring it back.
    let Some(n) = backend().await else { return };
    let p = prefix("nsref");
    let _teardown = Teardown {
        prefix: p.clone(),
        networks: vec![],
    };
    let owner = format!("{p}-vpn");
    let dependent = format!("{p}-app");
    #[rustfmt::skip]
    must(&[
        "run", "-d", "--name", &owner, "--label", "freshdock.enable=true",
        ALPINE, "sleep", "100000",
    ]);
    #[rustfmt::skip]
    must(&[
        "run", "-d", "--name", &dependent, "--network", &format!("container:{owner}"),
        "-e", "CERT=line one\nline two", ALPINE, "sleep", "100000",
    ]);
    let owner_before = id_of(&owner).unwrap();
    let dependent_before = id_of(&dependent).unwrap();

    let err = recreate(&n, &owner)
        .await
        .expect_err("refused at preflight");
    let msg = err.to_string();
    assert!(msg.contains(&dependent), "{msg}");
    assert!(msg.contains("CERT has a multi-line value"), "{msg}");
    assert!(!msg.contains("line one"), "no value is printed: {msg}");
    assert_eq!(id_of(&owner).as_deref(), Some(owner_before.as_str()));
    assert_eq!(
        id_of(&dependent).as_deref(),
        Some(dependent_before.as_str())
    );
    assert!(
        running(&owner) && running(&dependent),
        "nothing was stopped"
    );
}

#[tokio::test]
#[ignore = "needs rootful nerdctl; set FRESHDOCK_NERDCTL_LIVE=1"]
async fn an_owner_whose_dependents_image_is_gone_is_left_alone() {
    // The dependent's tag moved before freshdock saw it, and the image it
    // runs has no name left. Its repair after the owner's update could only
    // fall back to the tag, moving it to the new image with no health gate,
    // so the owner is refused up front (#115 review).
    let Some(n) = backend().await else { return };
    let p = prefix("nsgone");
    let tag = "127.0.0.1:15005/freshdock-live/depgone:v";
    let _images = ImageTeardown(tag);
    let _teardown = Teardown {
        prefix: p.clone(),
        networks: vec![],
    };
    #[rustfmt::skip]
    must(&[
        "run", "-d", "--name", &format!("{p}-registry"), "-p", "127.0.0.1:15005:5000",
        "docker.io/library/registry:2",
    ]);
    let version = |v: &str| {
        format!("FROM {ALPINE}\nRUN echo depgone {v} > /version\nCMD [\"sleep\", \"100000\"]\n")
    };
    build_and_publish(&version("v1"), tag);
    must(&["pull", "--quiet", tag]);
    let owner = format!("{p}-vpn");
    let dependent = format!("{p}-app");
    #[rustfmt::skip]
    must(&[
        "run", "-d", "--name", &owner, "--label", "freshdock.enable=true",
        ALPINE, "sleep", "100000",
    ]);
    #[rustfmt::skip]
    must(&[
        "run", "-d", "--name", &dependent, "--network", &format!("container:{owner}"), tag,
    ]);
    build_and_publish(&version("v2"), tag);
    must(&["pull", "--quiet", tag]);
    let owner_before = id_of(&owner).unwrap();
    let dependent_before = id_of(&dependent).unwrap();

    let err = recreate(&n, &owner)
        .await
        .expect_err("refused at preflight");
    let msg = err.to_string();
    assert!(msg.contains(&dependent), "{msg}");
    assert!(msg.contains("was not updated"), "{msg}");
    assert_eq!(id_of(&owner).as_deref(), Some(owner_before.as_str()));
    assert_eq!(
        id_of(&dependent).as_deref(),
        Some(dependent_before.as_str()),
        "not moved to v2"
    );
    assert!(
        running(&owner) && running(&dependent),
        "nothing was stopped"
    );
}

#[tokio::test]
#[ignore = "needs rootful nerdctl; set FRESHDOCK_NERDCTL_LIVE=1"]
async fn a_setting_that_cannot_be_reproduced_is_refused_before_the_stop() {
    let Some(n) = backend().await else { return };
    let p = prefix("ip");
    let net = format!("{p}-net");
    let _teardown = Teardown {
        prefix: p.clone(),
        networks: vec![net.clone()],
    };
    must(&["network", "create", "--subnet", "10.199.77.0/24", &net]);
    let name = format!("{p}-app");
    must(&[
        "run",
        "-d",
        "--name",
        &name,
        "--label",
        "freshdock.enable=true",
        "--network",
        &net,
        "--ip",
        "10.199.77.9",
        ALPINE,
        "sleep",
        "100000",
    ]);
    let before_id = id_of(&name).unwrap();

    let spec = n.inspect(&name).await.expect("inspect");
    let err = n
        .preflight_recreate(&spec)
        .await
        .expect_err("a static IP is refused");
    assert!(err.to_string().contains("nerdctl/ip"), "{err}");
    let err = recreate(&n, &name)
        .await
        .expect_err("the cycle stops at preflight");
    assert!(err.to_string().contains("not updated"), "{err}");
    assert_eq!(
        id_of(&name).as_deref(),
        Some(before_id.as_str()),
        "untouched"
    );
    assert!(running(&name));
}

#[tokio::test]
#[ignore = "needs rootful nerdctl; set FRESHDOCK_NERDCTL_LIVE=1"]
async fn the_sweep_repairs_a_dead_freshdocks_leftovers_but_not_a_running_ones() {
    let Some(_) = backend().await else { return };
    let p = prefix("sw");
    let _teardown = Teardown {
        prefix: p.clone(),
        networks: vec![],
    };
    // Left by a freshdock that died (pid 999999999 can't exist): a service
    // stepped aside between the renames, and a never-started trial container.
    let service = format!("{p}-svc");
    let aside = format!("{service}-freshdock-aside-999999999-2-0-0");
    must(&["run", "-d", "--name", &aside, ALPINE, "sleep", "100000"]);
    let service_id = id_of(&aside).unwrap();
    let trial = format!("{p}-db-freshdock-check-999999999-2-0-1");
    must(&["create", "--name", &trial, ALPINE, "true"]);
    // The same, but made by a process that is still running (this test): a
    // daemon in the middle of an update.
    // Named as this process names things: a name records its maker's pid
    // and start, and another start under the same pid is another process.
    let busy_aside = format!("{p}-busy-freshdock-aside-{}", unique_suffix());
    // And a dead freshdock's pid, reused since by this running process.
    let mine: Vec<String> = unique_suffix().split('-').map(str::to_owned).collect();
    let reused_trial = format!("{p}-reused-freshdock-check-{}-2-{}-1", mine[0], mine[2]);
    // And one from the boot before, under this very pid and start: what a
    // freshdock started early by systemd can get again after a reboot.
    let other_boot = if mine[2] == "1" { "2" } else { "1" };
    let old_boot_trial = format!(
        "{p}-oldboot-freshdock-check-{}-{}-{other_boot}-1",
        mine[0], mine[1]
    );
    must(&["create", "--name", &old_boot_trial, ALPINE, "true"]);
    must(&["create", "--name", &reused_trial, ALPINE, "true"]);
    must(&[
        "run",
        "-d",
        "--name",
        &busy_aside,
        ALPINE,
        "sleep",
        "100000",
    ]);
    let busy_trial = format!("{p}-busy-freshdock-check-{}", unique_suffix());
    must(&["create", "--name", &busy_trial, ALPINE, "true"]);

    // Connecting alone (what `check` does) changes nothing.
    let n = backend().await.unwrap();
    assert!(
        inspect(&aside).is_some() && inspect(&trial).is_some(),
        "connect must not sweep"
    );

    n.sweep().await.expect("sweep");

    assert_eq!(
        id_of(&service).as_deref(),
        Some(service_id.as_str()),
        "the service has its name back"
    );
    assert!(running(&service));
    assert!(inspect(&aside).is_none());
    assert!(
        inspect(&trial).is_none(),
        "the dead process's trial is gone"
    );
    assert!(
        inspect(&busy_aside).is_some(),
        "a running freshdock's step-aside is left alone"
    );
    assert!(
        inspect(&busy_trial).is_some(),
        "a running freshdock's trial is left alone"
    );
    assert!(
        inspect(&reused_trial).is_none(),
        "a pid now used by a later process doesn't keep a dead one's trial"
    );
    assert!(
        inspect(&old_boot_trial).is_none(),
        "a trial from the boot before is gone, whatever its pid and start"
    );
}

/// Removes one image record when dropped.
struct RemoveImage(String);

impl Drop for RemoveImage {
    fn drop(&mut self) {
        let _ = nerdctl(&["rmi", "--force", &self.0]);
    }
}

#[tokio::test]
#[ignore = "needs rootful nerdctl; set FRESHDOCK_NERDCTL_LIVE=1"]
async fn a_local_build_is_not_taken_for_its_registry_namesake() {
    let Some(n) = backend().await else { return };
    let p = prefix("local");
    let _teardown = Teardown {
        prefix: p.clone(),
        networks: vec![],
    };
    // A local image under a name the registry also serves: Docker Hub's
    // alpine repository. nerdctl still lists a digest for it.
    let local = format!("docker.io/library/alpine:{p}");
    let _image = RemoveImage(local.clone());
    let source = format!("{p}-src");
    must(&["run", "-d", "--name", &source, ALPINE, "sleep", "100000"]);
    must(&["commit", &source, &local]);
    let listed: Value = serde_json::from_str(&must(&["image", "inspect", &local])).unwrap();
    assert!(
        listed[0]["RepoDigests"]
            .as_array()
            .is_some_and(|d| !d.is_empty()),
        "nerdctl lists a digest for the local image: {listed}"
    );

    let img = n
        .inspect_image(&local)
        .await
        .expect("inspect the local image");
    assert!(
        img.repo_digests.is_empty(),
        "never compared with the registry: {:?}",
        img.repo_digests
    );
    let pulled = n.inspect_image(ALPINE).await.expect("inspect alpine");
    assert!(
        !pulled.repo_digests.is_empty(),
        "a pulled image keeps its digest"
    );
}

/// A second namespace to publish from. Namespaces have separate image stores,
/// so the registry's tag can move while the test namespace's stays put, as
/// when upstream publishes a new image.
const STAGING_NS: &str = "freshdock-live-staging";

fn staging(args: &[&str]) -> Result<String, String> {
    let out = Command::new(nerdctl_bin())
        .args(["--namespace", STAGING_NS])
        .args(args)
        .output()
        .map_err(|e| format!("could not run nerdctl: {e}"))?;
    if out.status.success() {
        Ok(String::from_utf8_lossy(&out.stdout).trim().to_owned())
    } else {
        Err(String::from_utf8_lossy(&out.stderr).trim().to_owned())
    }
}

/// Publish `source` as `tag` from the staging namespace, retrying while a
/// freshly started registry comes up.
fn publish(source: &str, tag: &str) {
    for args in [vec!["pull", "--quiet", source], vec!["tag", source, tag]] {
        staging(&args).unwrap_or_else(|e| panic!("staging nerdctl {}: {e}", args.join(" ")));
    }
    let mut last = String::new();
    for _ in 0..20 {
        match staging(&["push", tag]) {
            Ok(_) => return,
            Err(e) => last = e,
        }
        std::thread::sleep(Duration::from_millis(500));
    }
    panic!("push {tag}: {last}");
}

fn image_id(reference: &str) -> String {
    let out = must(&["image", "inspect", reference]);
    serde_json::from_str::<Vec<Value>>(&out).unwrap()[0]["Id"]
        .as_str()
        .unwrap()
        .to_owned()
}

#[tokio::test]
#[ignore = "needs rootful nerdctl; set FRESHDOCK_NERDCTL_LIVE=1"]
async fn siblings_on_a_tag_that_moves_are_both_updated() {
    let Some(n) = backend().await else { return };
    let p = prefix("tag");
    let tag = "127.0.0.1:15000/freshdock-live/shared:v";
    // Declared first so it drops last: the images can only go once the
    // containers using them have.
    let _images = ImageTeardown(tag);
    let _teardown = Teardown {
        prefix: p.clone(),
        networks: vec![],
    };
    must(&[
        "run",
        "-d",
        "--name",
        &format!("{p}-registry"),
        "-p",
        "127.0.0.1:15000:5000",
        // So the old manifest can be deleted, as registries do with old digests.
        "-e",
        "REGISTRY_STORAGE_DELETE_ENABLED=true",
        "docker.io/library/registry:2",
    ]);
    publish(ALPINE, tag);
    must(&["pull", "--quiet", tag]);
    let old = image_id(tag);
    let old_digest = image_digest(tag);

    let (a, b) = (format!("{p}-a"), format!("{p}-b"));
    for c in [&a, &b] {
        must(&[
            "run",
            "-d",
            "--name",
            c,
            "--label",
            "freshdock.enable=true",
            tag,
            "sleep",
            "100000",
        ]);
    }
    // As `freshdock run` and `recreate` do, this process tidies up after
    // itself; `check` never would.
    n.sweep_or_warn().await;
    // freshdock lists them before anything is pulled, as a scheduler pass does.
    let image_of = |listed: &[freshdock::docker::container::ContainerInfo], name: &str| {
        listed
            .iter()
            .find(|c| {
                c.names
                    .as_ref()
                    .is_some_and(|n| n.iter().any(|x| x == name))
            })
            .and_then(|c| c.image_id.clone())
    };
    let first = n.list_running().await.unwrap();
    assert_eq!(image_of(&first, &b).as_deref(), Some(old.as_str()));

    // Upstream publishes a new image under the same tag; updating A pulls it.
    publish("docker.io/library/busybox:1.36", tag);
    // The registry forgets the old image, as registries that clean up
    // untagged digests do. From here on B's old image exists only locally, so
    // nothing below may fetch it: a create that quietly pulled would fail.
    let manifest =
        format!("http://127.0.0.1:15000/v2/freshdock-live/shared/manifests/{old_digest}");
    let deleted = Command::new("curl")
        .args(["-fsS", "-X", "DELETE", &manifest])
        .status()
        .expect("curl");
    assert!(deleted.success(), "the registry deletes the old manifest");
    let gone = Command::new("curl")
        .args([
            "-s",
            "-o",
            "/dev/null",
            "-w",
            "%{http_code}",
            "-I",
            &manifest,
        ])
        .output()
        .expect("curl");
    assert_eq!(
        String::from_utf8_lossy(&gone.stdout),
        "404",
        "the old image is no longer served"
    );

    let outcome = recreate(&n, &a).await.expect("recreate a");
    assert!(
        matches!(outcome, RecreateOutcome::Recreated { .. }),
        "{outcome:?}"
    );
    let new = image_id(tag);
    assert_ne!(new, old, "A's pull moved the tag");

    // B still runs the old image, so it is behind its tag...
    let listed = n.list_running().await.unwrap();
    assert_eq!(
        image_of(&listed, &b).as_deref(),
        Some(old.as_str()),
        "B is seen behind its tag"
    );
    assert_eq!(image_of(&listed, &a).as_deref(), Some(new.as_str()));
    // ...and its update goes through: the trial is built from the image B
    // runs, not the new one, so nothing looks like a lost setting.
    let outcome = recreate(&n, &b).await.expect("recreate b is not refused");
    assert!(
        matches!(outcome, RecreateOutcome::Recreated { .. }),
        "{outcome:?}"
    );
    let listed = n.list_running().await.unwrap();
    assert_eq!(
        image_of(&listed, &b).as_deref(),
        Some(new.as_str()),
        "B is on the new image"
    );

    // With both siblings moved on, the record kept for the old image goes.
    n.release_unneeded_images().await;
    let records = must(&["images", "--format", "{{.Repository}}:{{.Tag}} {{.Digest}}"]);
    assert!(
        !records.lines().any(|l| l.contains(&old_digest)),
        "no record of the old image is left: {records}"
    );
}

/// Build `dockerfile` as `tag` in the staging namespace and push it,
/// retrying while a freshly started registry comes up. Needs BuildKit.
fn build_and_publish(dockerfile: &str, tag: &str) {
    let dir = std::env::temp_dir().join(format!(
        "fdl-build-{}",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos())
    ));
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("Dockerfile"), dockerfile).unwrap();
    let built = staging(&["build", "--quiet", "-t", tag, &dir.display().to_string()]);
    std::fs::remove_dir_all(&dir).ok();
    built.unwrap_or_else(|e| panic!("build {tag} (is BuildKit running?): {e}"));
    let mut last = String::new();
    for _ in 0..20 {
        match staging(&["push", tag]) {
            Ok(_) => return,
            Err(e) => last = e,
        }
        std::thread::sleep(Duration::from_millis(500));
    }
    panic!("push {tag}: {last}");
}

#[tokio::test]
#[ignore = "needs rootful nerdctl; set FRESHDOCK_NERDCTL_LIVE=1"]
async fn an_updated_container_gets_its_new_images_own_settings() {
    // Inspect shows an image's settings merged into the container's. An
    // update must leave them to the new image, and keep only what the
    // container set itself (#115 review).
    let Some(n) = backend().await else { return };
    let p = prefix("img");
    let tag = "127.0.0.1:15002/freshdock-live/defaults:v";
    // Declared first so it drops last, after the containers using it.
    let _images = ImageTeardown(tag);
    let _teardown = Teardown {
        prefix: p.clone(),
        networks: vec![],
    };
    must(&[
        "run",
        "-d",
        "--name",
        &format!("{p}-registry"),
        "-p",
        "127.0.0.1:15002:5000",
        "docker.io/library/registry:2",
    ]);
    let version = |v: &str, only: &str, entrypoint: &str| {
        format!(
            "FROM {ALPINE}\n\
             ENV SHARED={v} {only}=1\n\
             LABEL org.example.version={v} org.example.shared={v}\n\
             USER {uid}\n\
             WORKDIR /{v}\n\
             STOPSIGNAL {signal}\n\
             {healthcheck}\n\
             ENTRYPOINT {entrypoint}\n\
             CMD [\"sleep 100000 # {v}\"]\n",
            uid = if v == "v1" { 4321 } else { 1234 },
            signal = if v == "v1" { "SIGUSR1" } else { "SIGUSR2" },
            // v1 has its healthcheck as nerdctl's label alone, which nerdctl
            // applies as well (#115 review).
            healthcheck = if v == "v1" {
                r#"LABEL nerdctl/healthcheck="{\"Test\":[\"CMD-SHELL\",\"test -d /v1\"],\"Interval\":2000000000}""#
            } else {
                "HEALTHCHECK --interval=2s CMD test -d /v2"
            },
        )
    };
    build_and_publish(&version("v1", "OLD_ONLY", r#"["/bin/sh", "-c"]"#), tag);
    must(&["pull", "--quiet", tag]);
    let name = format!("{p}-app");
    #[rustfmt::skip]
    must(&[
        "run", "-d", "--name", &name, "--label", "freshdock.enable=true",
        // The container's own settings, one of them over the image's.
        "-e", "MINE=1", "-e", "SHARED=mine", "--label", "org.example.shared=mine",
        tag,
    ]);
    let v1_health = inspect(&name).unwrap()["Config"]["Labels"]["nerdctl/healthcheck"].clone();
    assert!(
        v1_health
            .as_str()
            .is_some_and(|h| h.contains("test -d /v1")),
        "nerdctl applied v1's healthcheck label: {v1_health}"
    );
    // Upstream publishes v2 under the same tag; the update pulls it.
    build_and_publish(&version("v2", "NEW_ONLY", r#"["/bin/sh", "-ec"]"#), tag);

    let outcome = recreate(&n, &name).await.expect("recreate");
    assert!(
        matches!(outcome, RecreateOutcome::Recreated { .. }),
        "{outcome:?}"
    );
    let c = inspect(&name).expect("the container exists under its name");
    assert_eq!(c["Path"], "/bin/sh");
    assert_eq!(
        c["Args"],
        serde_json::json!(["-ec", "sleep 100000 # v2"]),
        "v2's entrypoint and command"
    );
    let env: Vec<&str> = c["Config"]["Env"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(Value::as_str)
        .collect();
    for want in ["MINE=1", "SHARED=mine", "NEW_ONLY=1"] {
        assert!(env.contains(&want), "missing {want}: {env:?}");
    }
    assert!(
        !env.iter().any(|v| v.starts_with("OLD_ONLY=")),
        "a variable only v1 set is gone: {env:?}"
    );
    let labels = &c["Config"]["Labels"];
    assert_eq!(labels["org.example.version"], "v2");
    assert_eq!(labels["org.example.shared"], "mine");
    assert_eq!(labels["io.containerd.image.config.stop-signal"], "SIGUSR2");
    let health: Value =
        serde_json::from_str(labels["nerdctl/healthcheck"].as_str().unwrap()).unwrap();
    assert_eq!(
        health["Test"],
        serde_json::json!(["CMD-SHELL", "test -d /v2"])
    );
    assert_eq!(c["Config"]["User"], "1234");
    let after = native(&name);
    assert_eq!(after["Spec"]["process"]["cwd"], "/v2");
    assert!(running(&name));
}

#[tokio::test]
#[ignore = "needs rootful nerdctl; set FRESHDOCK_NERDCTL_LIVE=1"]
async fn a_restarted_freshdock_still_knows_the_image_a_container_runs() {
    // freshdock pulls v2 but doesn't replace the container (its pre-update
    // hook says "not now"), then restarts. The container still runs v1, and
    // its update must leave v1's settings to v2, not v2's (#115 review).
    let Some(before) = backend().await else {
        return;
    };
    let p = prefix("restart");
    let tag = "127.0.0.1:15003/freshdock-live/restart:v";
    // Declared first so it drops last, after the containers using it.
    let _images = ImageTeardown(tag);
    let _teardown = Teardown {
        prefix: p.clone(),
        networks: vec![],
    };
    must(&[
        "run",
        "-d",
        "--name",
        &format!("{p}-registry"),
        "-p",
        "127.0.0.1:15003:5000",
        "docker.io/library/registry:2",
    ]);
    let v1 = format!("FROM {ALPINE}\nENV ONLY_V1=1\nCMD [\"sleep\", \"100001\"]\n");
    let v2 = format!("FROM {ALPINE}\nCMD [\"sleep\", \"100002\"]\n");
    build_and_publish(&v1, tag);
    must(&["pull", "--quiet", tag]);
    let name = format!("{p}-app");
    must(&[
        "run",
        "-d",
        "--name",
        &name,
        "--label",
        "freshdock.enable=true",
        tag,
    ]);
    before.list_running().await.unwrap();
    build_and_publish(&v2, tag);
    before
        .pull(&freshdock::registry::ImageRef::parse(tag))
        .await
        .expect("pull v2");
    drop(before);

    // The restarted daemon: the tag names v2, the container runs v1.
    let after = backend().await.unwrap();
    let outcome = recreate(&after, &name).await.expect("recreate");
    assert!(
        matches!(outcome, RecreateOutcome::Recreated { .. }),
        "{outcome:?}"
    );
    let c = inspect(&name).expect("the container exists under its name");
    assert_eq!(
        c["Args"],
        serde_json::json!(["100002"]),
        "v2's command, not v1's pinned on: {c}"
    );
    let env: Vec<&str> = c["Config"]["Env"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(Value::as_str)
        .collect();
    assert!(
        !env.contains(&"ONLY_V1=1"),
        "a variable only v1 set is gone: {env:?}"
    );
    assert!(running(&name));
}

#[tokio::test]
#[ignore = "needs rootful nerdctl; set FRESHDOCK_NERDCTL_LIVE=1"]
async fn a_stopped_container_keeps_its_image_note() {
    // freshdock pulls v2, the container is stopped and listed while stopped,
    // then started again. It still runs v1, and only its note says so: v1 and
    // v2 share their layers, so its filesystem can't (#115 review).
    let Some(n) = backend().await else { return };
    let p = prefix("stopped");
    let tag = "127.0.0.1:15006/freshdock-live/stopped:v";
    let _images = ImageTeardown(tag);
    let _teardown = Teardown {
        prefix: p.clone(),
        networks: vec![],
    };
    #[rustfmt::skip]
    must(&[
        "run", "-d", "--name", &format!("{p}-registry"), "-p", "127.0.0.1:15006:5000",
        "docker.io/library/registry:2",
    ]);
    let v1 = format!("FROM {ALPINE}\nENV ONLY_V1=1\nCMD [\"sleep\", \"100001\"]\n");
    let v2 = format!("FROM {ALPINE}\nCMD [\"sleep\", \"100002\"]\n");
    build_and_publish(&v1, tag);
    must(&["pull", "--quiet", tag]);
    let name = format!("{p}-app");
    #[rustfmt::skip]
    must(&["run", "-d", "--name", &name, "--label", "freshdock.enable=true", tag]);
    n.list_running().await.unwrap();
    build_and_publish(&v2, tag);
    n.pull(&freshdock::registry::ImageRef::parse(tag))
        .await
        .expect("pull v2");
    must(&["stop", &name]);
    n.list_running().await.unwrap();
    drop(n);
    // freshdock restarts while the container is stopped, and its first pass
    // must not release the name v1 was kept under: the stopped container
    // still needs it, and only the note on disk says so.
    let n = backend().await.unwrap();
    n.sweep_or_warn().await;
    n.list_running().await.unwrap();
    assert!(
        digest_records()
            .iter()
            .any(|r| r.starts_with("127.0.0.1:15006/freshdock-live/stopped@")),
        "v1 is still kept: {:?}",
        digest_records()
    );
    must(&["start", &name]);

    let outcome = recreate(&n, &name).await.expect("recreate");
    assert!(
        matches!(outcome, RecreateOutcome::Recreated { .. }),
        "{outcome:?}"
    );
    let c = inspect(&name).expect("the container exists under its name");
    assert_eq!(
        c["Args"],
        serde_json::json!(["100002"]),
        "v2's command: {c}"
    );
    assert!(
        !c["Config"]["Env"].to_string().contains("ONLY_V1"),
        "v1's variable was left to v1: {c}"
    );
}

#[tokio::test]
#[ignore = "needs rootful nerdctl; set FRESHDOCK_NERDCTL_LIVE=1"]
async fn a_tag_moved_before_freshdock_saw_the_container_is_noticed() {
    // `nerdctl pull` by hand moves two tags before any freshdock has listed
    // the containers on them. Their filesystems still tell their image: one
    // that kept another name is found and updated from properly; one with no
    // name left can't be told, and is left alone (#115 review).
    let Some(n) = backend().await else { return };
    let p = prefix("moved");
    let told = "127.0.0.1:15004/freshdock-live/told:v";
    let lost = "127.0.0.1:15004/freshdock-live/lost:v";
    // Declared first so they drop last, after the containers using them.
    let _told_images = ImageTeardown(told);
    let _lost_images = ImageTeardown(lost);
    let _teardown = Teardown {
        prefix: p.clone(),
        networks: vec![],
    };
    must(&[
        "run",
        "-d",
        "--name",
        &format!("{p}-registry"),
        "-p",
        "127.0.0.1:15004:5000",
        "docker.io/library/registry:2",
    ]);
    // A layer of each version's own, as a real release has: images with the
    // same layers sit on the same filesystem and can't be told apart. Each
    // repository's are its own too, or BuildKit's cache would make them one
    // image, kept alive by the other's name.
    let v1 = |tag: &str| {
        format!(
            "FROM {ALPINE}\nRUN echo {tag} v1 > /version\nENV ONLY_V1=1\n\
             CMD [\"sleep\", \"100001\"]\n"
        )
    };
    let v2 = |tag: &str| {
        format!("FROM {ALPINE}\nRUN echo {tag} v2 > /version\nCMD [\"sleep\", \"100002\"]\n")
    };
    let mut names = Vec::new();
    for tag in [told, lost] {
        build_and_publish(&v1(tag), tag);
        must(&["pull", "--quiet", tag]);
        let name = format!("{p}-{}", if tag == told { "told" } else { "lost" });
        must(&[
            "run",
            "-d",
            "--name",
            &name,
            "--label",
            "freshdock.enable=true",
            tag,
        ]);
        names.push(name);
    }
    let (told_name, lost_name) = (&names[0], &names[1]);
    // The told one's v1 keeps a name of its own; the lost one's has none.
    must(&["tag", told, "127.0.0.1:15004/freshdock-live/told:keep"]);
    for tag in [told, lost] {
        build_and_publish(&v2(tag), tag);
        must(&["pull", "--quiet", tag]);
    }
    // The lost one's v1 now has no name, but containerd removes its config
    // only when it next collects garbage, which is scheduled, not tied to
    // the pull. Collect now, and make sure, so what follows tests the
    // refusal and not containerd's timing.
    let throwaway = "127.0.0.1:15004/freshdock-live/gc:now";
    must(&["tag", ALPINE, throwaway]);
    ctr(&["images", "rm", "--sync", throwaway]);
    assert_eq!(
        configs_under(lost_name),
        "",
        "v1's config of the lost image is collected"
    );

    let outcome = recreate(&n, told_name).await.expect("recreate told");
    assert!(
        matches!(outcome, RecreateOutcome::Recreated { .. }),
        "{outcome:?}"
    );
    let c = inspect(told_name).expect("the container exists under its name");
    assert_eq!(
        c["Args"],
        serde_json::json!(["100002"]),
        "v2's command, v1's not pinned on: {c}"
    );
    let env = c["Config"]["Env"].to_string();
    assert!(
        !env.contains("ONLY_V1"),
        "a variable only v1 set is gone: {env}"
    );
    assert_eq!(
        c["Config"]["Image"].as_str(),
        Some(told),
        "still on its own tag, never on the name its old image was found by: {c}"
    );
    // The trial was created from a digest name freshdock made for v1, not
    // from the user's tag, which is left as it was.
    let keep = "127.0.0.1:15004/freshdock-live/told:keep";
    assert!(
        must(&["images", "--format", "{{.Repository}}:{{.Tag}}"])
            .lines()
            .any(|l| l == keep),
        "the user's name is untouched"
    );

    let lost_before = id_of(lost_name).unwrap();
    let err = recreate(&n, lost_name)
        .await
        .expect_err("refused: its image can't be told");
    assert!(
        err.to_string().contains("could not tell which image"),
        "{err}"
    );
    assert_eq!(id_of(lost_name).as_deref(), Some(lost_before.as_str()));
    assert!(running(lost_name), "left alone");
}

/// The manifest digest a tag points at, as the registry serves it.
fn image_digest(reference: &str) -> String {
    let out = must(&["image", "inspect", reference]);
    let repo_digest = serde_json::from_str::<Vec<Value>>(&out).unwrap()[0]["RepoDigests"][0]
        .as_str()
        .unwrap()
        .to_owned();
    repo_digest.rsplit_once('@').unwrap().1.to_owned()
}

/// Removes the test registry's images from both namespaces.
struct ImageTeardown(&'static str);

impl Drop for ImageTeardown {
    fn drop(&mut self) {
        let repo = self.0.rsplit_once(':').map_or(self.0, |(r, _)| r);
        for run in [nerdctl as fn(&[&str]) -> Result<String, String>, staging] {
            let out = run(&["images", "--format", "{{.Repository}}:{{.Tag}}@{{.Digest}}"])
                .unwrap_or_default();
            for line in out.lines().filter(|l| l.starts_with(repo)) {
                let (name, digest) = line.split_once('@').unwrap_or((line, ""));
                let target = if name.ends_with(":<none>") {
                    format!("{repo}@{digest}")
                } else {
                    name.to_owned()
                };
                let _ = run(&["rmi", "--force", &target]);
            }
        }
    }
}

/// The digest-named image records (`repo@sha256:...`) in the test namespace.
fn digest_records() -> std::collections::BTreeSet<String> {
    must(&["images", "--format", "{{.Name}}"])
        .lines()
        .filter(|l| l.contains("@sha256:"))
        .map(str::to_owned)
        .collect()
}
