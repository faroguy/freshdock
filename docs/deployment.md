# Deployment

freshdock is a single static binary that talks to the Docker socket. Run it however
suits you: as a container alongside the ones it manages, or directly on the host
(under systemd, for example). For configuration, see the
[configuration reference](configuration.md).

## As a container (recommended)

Mount the Docker socket and run the `run` subcommand:

```bash
docker run -d \
  --name freshdock \
  --restart unless-stopped \
  -v /var/run/docker.sock:/var/run/docker.sock \
  ghcr.io/turbootzz/freshdock:latest run
```

Or with compose. The runnable stacks live in
[`examples/compose/`](https://github.com/Turbootzz/freshdock/tree/main/examples/compose):

- [`minimal-watch.yml`](https://github.com/Turbootzz/freshdock/blob/main/examples/compose/minimal-watch.yml): watch-only, read-only socket.
- [`mixed-modes.yml`](https://github.com/Turbootzz/freshdock/blob/main/examples/compose/mixed-modes.yml): live + nightly + watch on one daemon.
- [`notifications-enabled.yml`](https://github.com/Turbootzz/freshdock/blob/main/examples/compose/notifications-enabled.yml): mounts a `freshdock.toml`.
- [`registry-authenticated.yml`](https://github.com/Turbootzz/freshdock/blob/main/examples/compose/registry-authenticated.yml): private registry via env.
- [`watch-all.yml`](https://github.com/Turbootzz/freshdock/blob/main/examples/compose/watch-all.yml): opt-out mode, every container included unless it opts out.
- [`compose-project.yml`](https://github.com/Turbootzz/freshdock/blob/main/examples/compose/compose-project.yml): a stack with a one-shot migration, rolled out as one unit. See [Compose projects](compose.md).

### Socket: read-only vs writable

| Workload | Socket mount |
|---|---|
| `watch` / `check` only (never recreates) | `:ro` is enough: `-v /var/run/docker.sock:/var/run/docker.sock:ro` |
| Any updating mode (`live`/`nightly`/`weekly`/`monthly`, or `recreate`) | writable: `-v /var/run/docker.sock:/var/run/docker.sock` |

### Configuration: environment first

Most deployments need no config file. Fleet-wide settings, registry credentials,
notification targets, and the `run` flags are all environment variables. Pass them under `environment:` in
compose, or `Environment=` in a systemd unit:

```yaml
services:
  freshdock:
    image: ghcr.io/turbootzz/freshdock:latest
    command: ["run"]
    environment:
      FRESHDOCK_DEFAULT_MODE: "nightly"
      FRESHDOCK_REGISTRY_GHCR_USERNAME: "${GHCR_USER:-}"
      FRESHDOCK_REGISTRY_GHCR_TOKEN: "${GHCR_TOKEN:-}"
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock
    restart: unless-stopped
```

Add `FRESHDOCK_WATCH_ALL: "true"` to that block if you would rather not label each
container: every running container is then included unless it opts out, on the mode
set by `FRESHDOCK_DEFAULT_MODE`. See
[watching every container](configuration.md#watching-every-container).

The full list is the [env-var table](configuration.md#environment-variables).

### Notifications

A notification target can be declared from the environment with a
[shoutrrr-style URL](notifications.md#declaring-targets-from-the-environment), with
no file to mount:

```yaml
services:
  freshdock:
    image: ghcr.io/turbootzz/freshdock:latest
    command: ["run"]
    environment:
      FRESHDOCK_NOTIFY_OPS_URL: "discord://${DISCORD_TOKEN}@${DISCORD_ID}"
      FRESHDOCK_NOTIFY_OPS_TRIGGERS: "succeeded,failed"
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock
    restart: unless-stopped
```

To use a file instead, declare the target in a `[notifications.<name>]` table, mount
it read-only, and keep its secret in the environment:

```yaml
services:
  freshdock:
    image: ghcr.io/turbootzz/freshdock:latest
    command: ["run", "--config", "/config/freshdock.toml"]
    environment:
      FRESHDOCK_NOTIFY_EMAIL_PASSWORD: "${SMTP_PASSWORD:-}"
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock
      - ./freshdock.toml:/config/freshdock.toml:ro
    restart: unless-stopped
```

## As a host binary (systemd)

Install the binary (`cargo install freshdock`, a release binary, or `just build`),
then create a unit. The host needs a CA bundle (the `ca-certificates` package) or
`SSL_CERT_FILE` pointing at one, or freshdock refuses to start; see
[Troubleshooting](troubleshooting.md#no-ca-certificates-were-found).

```ini
# /etc/systemd/system/freshdock.service
[Unit]
Description=freshdock container auto-updater
After=docker.service
Requires=docker.service

[Service]
ExecStart=/usr/local/bin/freshdock run
Restart=on-failure
Environment=RUST_LOG=info
# If freshdock.toml is not in the working directory:
# Environment=FRESHDOCK_CONFIG=/etc/freshdock/freshdock.toml
# Run as a user in the docker group rather than root where possible.
# SupplementaryGroups=docker

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now freshdock
journalctl -u freshdock -f
```

## Docker socket permissions

freshdock talks to `/var/run/docker.sock`. `permission denied` on the socket means
the process isn't allowed to use it:

- On the host: run as a user in the `docker` group.
- In a container: the socket's group GID inside the container must match the host
  socket's owner. On some hosts you must pass `--group-add <gid>` (find it with
  `stat -c '%g' /var/run/docker.sock`).

Access to the Docker socket is effectively root on the host, so grant it with care.

## With nerdctl (containerd)

freshdock can manage containers you run with [nerdctl](https://github.com/containerd/nerdctl)
on containerd. It does every operation by running the `nerdctl` command, so nerdctl
keeps doing the networking, naming and port setup it does for `nerdctl run`.

Requirements:

- nerdctl 2.3 or newer, **rootful** (one containerd running as root). Rootless
  nerdctl is not supported yet.
- freshdock runs **as root on the same host**, as a host binary or systemd service.
  It needs the containerd socket, nerdctl's state under `/var/lib/nerdctl`, and the
  CNI setup, so running it in a container is not supported.
- `runtime = "nerdctl"` in `[settings]`, or `FRESHDOCK_RUNTIME=nerdctl`.
- containerd's `ctr`, next to the nerdctl binary or on `PATH` (containerd and the
  nerdctl-full bundle both install it). freshdock only reads with it. Without it,
  freshdock warns at startup and reports containers but updates none (see below).

```ini
# /etc/systemd/system/freshdock.service
[Unit]
Description=freshdock container auto-updater (nerdctl)
After=containerd.service
Requires=containerd.service

[Service]
ExecStart=/usr/local/bin/freshdock run
Restart=on-failure
Environment=RUST_LOG=info
Environment=FRESHDOCK_RUNTIME=nerdctl
# Only if nerdctl is not on the service's PATH:
# Environment=FRESHDOCK_NERDCTL_PATH=/usr/local/bin/nerdctl
# Only if your containers are not in nerdctl's default namespace:
# Environment=FRESHDOCK_CONTAINERD_NAMESPACE=default
# Do not add PrivatePIDs=: the cleanup of an interrupted update tells a live
# freshdock from a dead one by process id, so `run` and `recreate` must share
# the host's pid namespace.

[Install]
WantedBy=multi-user.target
```

Labels, modes, schedules, hooks and notifications work as on Docker. At startup
freshdock checks the nerdctl version and that nerdctl can reach containerd, and
logs both.

### What is different on nerdctl

- **Locally built images are never updated, as on Docker.** nerdctl lists a
  registry-style digest for every image, including ones you built, committed or
  loaded, so freshdock asks containerd instead: it only compares an image with a
  registry if containerd recorded pulling it from that registry and repository
  (read with `ctr content ls`). A local build named like a registry image
  (`myapp:latest`, `ghcr.io/you/app`) is therefore never replaced by the
  registry's. An image you `nerdctl load`ed counts as local until you pull it
  once.
- **Compose projects are updated one container at a time.** nerdctl compose does
  not record the `depends_on` graph on its containers, so `compose_aware` is
  turned off. Keep services you don't want updated on their own (a database, a
  migration) in `watch` mode.
- **Settings are rebuilt, then checked, before anything stops.** nerdctl cannot
  recreate a container from its inspect output, so freshdock rebuilds the
  `nerdctl create` flags from what nerdctl reports. Before stopping the container,
  it creates a throwaway copy from those flags (never started), compares its
  runtime settings with the original's, and removes it. If they differ, the update
  is refused and the log names the differing fields. The container keeps running
  untouched.
- **The new image's own settings apply.** nerdctl reports a container's settings
  with its image's merged in: `ENV`, `LABEL`, `ENTRYPOINT`, `CMD`, `WORKDIR`,
  `USER`, `STOPSIGNAL` and `HEALTHCHECK`. freshdock reads the config of the image
  the container runs (with `ctr content get`) and leaves out every value that is
  that image's own, so the updated container gets the new image's values, and
  a variable or label only the old image set goes with it. What you set yourself
  (`-e`, `--label`, a compose `command:`, an `--entrypoint`) is kept, even where it
  overrides the image. A value you set equal to the image's own counts as the
  image's, and follows the new image. If the image's config can't be read, the
  update is refused and tried again on the next pass.
- **Some settings are always refused**: a static IP (`--ip`), an explicit
  `--group-add` (nerdctl reports it together with the groups it derives from the
  image), `--userns-remap`, an environment variable of the container's own whose
  value spans several lines or ends in whitespace, an exec-form healthcheck of
  the container's own (`CMD`, not `CMD-SHELL`), and anything nerdctl does not
  report. A container
  created with different nerdctl global flags (for example another
  `--snapshotter`) is refused too. Recreate such a container by hand, or keep it in
  `watch` mode.
- **Secrets stay off the command line.** Anything in nerdctl's arguments is
  readable by every local user, so a container's environment variables are passed
  through an owner-only `--env-file` that exists only for the `nerdctl create`.
  nerdctl is also started with only the environment it needs (`PATH`, `HOME`,
  containerd, nerdctl and CNI variables), because it copies its caller's
  environment into every container it creates; freshdock's own
  `FRESHDOCK_REGISTRY_*` and `FRESHDOCK_NOTIFY_*` secrets never reach it. Proxy
  settings (`HTTP_PROXY` and the like, which can carry a password) go to
  `nerdctl pull` alone, the one call that needs the network.
- **An interrupted update is cleaned up by the next `run` or `recreate`.** To
  remove a renamed archive, freshdock briefly renames the updated container to
  `<name>-freshdock-aside-...` (a nerdctl limitation), and preflight creates a
  `<name>-freshdock-check-...` trial container. If freshdock is killed in between,
  the next `run` or `recreate` gives the container its name back, removes the
  trial and any leftover private temp directory, and logs it. Only what an exited
  freshdock left is touched, never what a still-running one (another daemon, a
  `recreate` in progress) is using, and `check` never cleans up at all.
- **A misspelled `runtime`** (say `nerdcl`) stops freshdock at startup rather than
  falling back to Docker.
- **The running image is remembered from first sight.** containerd records a
  container's image by name only, so freshdock notes which image each container
  runs when it first lists it, before pulling anything, in
  `/var/lib/freshdock/nerdctl-seen-images` (root-only), and keeps each note until
  the container is removed, stopped or not. When containers share a
  tag, updating one moves the tag, and the others are still recognised as behind
  it and updated in turn, even after freshdock restarts. The same goes for a
  container whose update was called off after the pull (a pre-update hook's
  "not now", a refused or rolled-back update): its next update leaves the
  settings of the image it really runs to the new one. A tag that moved before
  freshdock first saw the container (a `nerdctl pull` by hand before freshdock
  was installed, say) is caught from the container's filesystem, which sits on
  its image's layers (read with `ctr`): if that image still has a name, freshdock
  updates the container from it as usual. If it has none left (containerd then
  removes it), freshdock can't tell which image the container runs. It warns
  once and leaves the container alone until you re-create it from its tag.
  Images with exactly the same layers (a rebuild that changed nothing but `ENV`
  or labels, or an image that adds no layers to its base) are told apart: the
  base of another candidate (its build history is where the other's begins,
  and no name of the container's repository has it), or an image that sets a
  variable or label the container lacks, can't be its image. The history test
  is no proof on its own: an old release that only another repository names,
  whose successor only appended steps, looks like a base too. So whatever it
  leaves must still fit the container's settings, and one release that differs
  from the next only in something the container can override (its command,
  say) can still be ruled out by it. If the ones left
  give their containers the same settings, it makes no difference which it
  runs; if they differ, freshdock warns and leaves the container alone as
  above. A container freshdock itself creates from its tag is noted at once, when
  the tag names the same image before and after the create and the new
  container's filesystem sits on it, so this doesn't apply to it. (Only a tag
  moved away and back by something else during that one create, to an image
  with the same layers, could make that note wrong.)

  `freshdock check` reads the same notes, and tells a container it has no note
  for from its filesystem in the same way, so it reports each container by the
  image it runs, as the daemon does: a sibling left behind a shared tag shows
  as behind it. It also keeps the state file current, as the daemon does: it
  writes the notes it makes on first sight, and removes those of containers
  that nerdctl confirms are gone. It removes no container or image.

  If containerd can't be asked about a container's image (it is restarting,
  say), freshdock asks again on the next pass, and until it has an answer it
  pulls nothing on that tag and removes no image of that repository, so the
  image the container runs can't move out of sight first.
- **Containers are only ever created from local images** (`--pull=never`), so
  only `nerdctl pull` reaches the network, with freshdock's credentials and
  proxy settings. Before a pull, freshdock names the image the tag points at by
  its digest (`<repository>@sha256:...`) while any container runs it, so
  containers still on it stay usable after the pull moves the tag: siblings not
  updated yet, and a container whose pre-update hook calls its update off after
  the pull. It removes the name again once no container runs that image (at
  once if the pull found nothing new). freshdock records the names it made in
  `/var/lib/freshdock/nerdctl-kept-images` (root-only), so a restart, or a
  one-off `freshdock recreate`, doesn't lose track of them: the daemon removes
  them on a later pass. Names you made yourself are never touched. Both state
  files are replaced whole on every change, under a lock on a `.lock` file next
  to them, so a write that fails (a full disk, say) leaves them as they were. A
  failure only after the new file is in place (syncing its directory) is logged:
  the change stands, but may not survive a crash. After a write that did fail,
  freshdock warns and keeps that list in memory for the rest of the run, even
  once the disk has room again: restart freshdock (`systemctl restart
  freshdock`) to write to the file again, or changes made in the meantime are
  lost at the next restart. While the image notes can't be read, freshdock
  releases and removes no image a container might still run.
- **Registry credentials** from freshdock's configuration are passed to
  `nerdctl pull` through a temporary, owner-only `DOCKER_CONFIG`. Without them,
  nerdctl's own login (`nerdctl login`) is used. See
  [Registry authentication](registry-auth.md).
- **A rate-limited pull is retried.** When the registry answers a pull with
  429 Too Many Requests or a 5xx error, or the connection drops, freshdock
  logs `pull hit a temporary registry error; retrying` and tries again after
  1, 4 and 10 minutes before giving up until the next scheduled run. ghcr.io
  (which also serves `lscr.io`) limits anonymous pulls, most often on the
  hour, when many scheduled pulls fire at once. Registry credentials raise
  that limit, and a schedule off the hour (`freshdock.schedule=17 4 * * *`)
  avoids the rush. A 401, 403, "not found" or Docker Hub's pull quota
  (which resets in hours) is not retried. The waits are longer than the
  Docker backend's 2, 5 and 10 seconds: in testing, ghcr.io's limit on
  nerdctl pulls outlasted seconds but cleared within the first minute.

## Compatibility

| Platform | Status |
|---|---|
| Plain Docker | Primary target. The API version is negotiated with your daemon at connect time; CI exercises the Docker engine shipped on GitHub's `ubuntu-latest` runners. |
| Docker Desktop (Linux, macOS, Windows) | Supported. |
| Portainer (CE and Business) | Supported via the same Docker socket. |
| Podman 4+ | Supported via the Docker-compatible socket (discovery below). |
| containerd with nerdctl 2.3+ (rootful) | Supported with `runtime = "nerdctl"`, as a host binary running as root. Compose projects are updated one container at a time. See [below](#with-nerdctl-containerd). Rootless nerdctl is not supported yet. |
| Docker Compose | A multi-service project is updated as one unit, in `depends_on` order. See [Compose projects](compose.md). |
| Compose-based UIs (Dockge, Komodo, and similar) | Supported; compose files are never read or edited. |
| Kubernetes / Swarm | Out of scope; use platform-native mechanisms. |

One daemon-version floor applies: re-creating a container attached to more than one
network requires Docker API 1.44 (Docker 25.0), because older daemons cannot attach
several networks in a single create call. freshdock checks the negotiated API
version before it stops anything, so on an older daemon such a container is refused
with an explanatory error rather than being taken down and left unable to come back.
Detach the extra networks (re-attaching them after the update) or upgrade the daemon.

### Which socket freshdock uses

freshdock connects in this order at startup and logs which family answered:

1. `DOCKER_HOST`, if set. `unix://`, `tcp://`, `http://`, `https://` and `ssh://`
   are all honoured. Only the scheme is logged; the value may carry credentials.
2. The local Docker socket: `/var/run/docker.sock` (named pipe on Windows).
3. Podman's sockets: `$XDG_RUNTIME_DIR/podman/podman.sock`,
   `/run/user/$UID/podman/podman.sock`, then `/run/podman/podman.sock`.

So a rootless or rootful Podman host in the standard location works with no
configuration. For anything else, set `DOCKER_HOST=unix:///path/to/podman.sock`.

A recreate replaces the container with a new ID, so a UI that pinned the old ID may
briefly show it "out of sync" until its next refresh. freshdock never edits your
compose/stack files, only the running container.
