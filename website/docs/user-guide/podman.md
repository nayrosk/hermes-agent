---
sidebar_position: 8
title: "Rootless Podman Backend"
description: "Run agent commands in a rootless Podman sandbox: setup, every podman_* key, posture warnings, strict mode, and egress"
---

# Rootless Podman Backend

The `podman` terminal backend runs every agent command inside a persistent sandbox container managed by your own **rootless Podman**. It has no daemon and no `docker` group, and the container's root is your unprivileged host user rather than the host's real root.

It behaves like the [Docker backend](./configuration.md#docker-backend): one long-lived container shared across tool calls, `/new`, and subagents, reused across Hermes processes, hardened with dropped capabilities, and covered by the same [egress proxy](./egress/index.md). The differences are in how it talks to Podman and how it treats user namespaces.

## Why rootless

With the Docker backend, a container escape lands in a root daemon. With rootless Podman, an escape lands as your unprivileged user, which is far less to lose. Hermes checks the host posture at startup and tells you what is weakening that guarantee (see [Posture warnings](#posture-warnings-and-fixes)).

## Setup

Requirements:

- Podman, installed and runnable as your regular user (no `sudo`). Tested with Podman 4.9 and newer; the version is not checked at startup. Hermes finds `podman` on `PATH`; there is no binary-override environment variable.
- Optional: `pasta` (package `passt`) if you use the [egress proxy](#egress-proxy).

Select the backend:

```yaml
terminal:
  backend: podman
  podman_image: "nousresearch/hermes-sandbox:desktop"
```

Or set `TERMINAL_ENV=podman`. Run `hermes doctor` to see the posture warnings described below before your first session.

:::note Already using `HERMES_DOCKER_BINARY=podman`?
Pointing the `docker` backend at Podman via `HERMES_DOCKER_BINARY=podman` keeps working. The `podman` backend is the supported path for Podman going forward: it understands rootless user namespaces, cgroup delegation, SELinux relabeling, and pasta networking, which the docker backend does not.
:::

## Configuration

All keys live under `terminal:` in `~/.hermes/config.yaml`. Each maps to a `TERMINAL_PODMAN_*` environment variable (see the [environment variable reference](../reference/environment-variables.md#terminal-backend)).

```yaml
terminal:
  backend: podman
  podman_image: "nousresearch/hermes-sandbox:desktop"
  podman_volumes:                 # Host directory mounts
    - "/home/user/projects:/workspace/projects"
    - "/home/user/data:/data:ro"
  podman_env:                     # Literal env vars to inject (KEY=value)
    DEBUG: "1"
  podman_forward_env:             # Host env vars to forward into the container
    - "GITHUB_TOKEN"
  podman_extra_args: []           # Extra flags appended verbatim to `podman run`
  podman_shm_size: "1g"
  podman_network: true            # false = --network=none
  podman_persist_across_processes: true
  podman_shared_container_key: ""
  podman_orphan_reaper: true
  podman_mount_cwd_to_workspace: false
  podman_userns: ""               # "", "keep-id", or "auto"
  podman_strict: false

  container_cpu: 1                # CPU cores (0 = unlimited)
  container_memory: 5120          # MB (0 = unlimited)
```

| Key | Default | Meaning |
|---|---|---|
| `podman_image` | the default sandbox image | Image for the sandbox. See [Images](#images). |
| `podman_volumes` | `[]` | Extra bind mounts, `host:container[:opts]`. |
| `podman_env` | `{}` | Literal environment variables injected into the sandbox. |
| `podman_forward_env` | `[]` | Names of host variables forwarded into the sandbox. Values stay out of the config file. |
| `podman_extra_args` | `[]` | Extra `podman run` flags, appended last. Flags that conflict with the sandbox hardening weaken isolation. |
| `podman_shm_size` | `"1g"` | Size of `/dev/shm`. |
| `podman_network` | `true` | `false` runs with `--network=none` (no network at all). |
| `podman_persist_across_processes` | `true` | Reuse the container across Hermes restarts. |
| `podman_shared_container_key` | `""` | Opt trusted profiles into one shared container identity. Empty keeps the per-profile boundary. |
| `podman_orphan_reaper` | `true` | Sweep abandoned exited Podman containers at startup. |
| `podman_mount_cwd_to_workspace` | `false` | Mount the launch directory at `/workspace`. |
| `podman_userns` | `""` | User-namespace mode. See [User namespaces](#user-namespaces). |
| `podman_strict` | `false` | Refuse to start on posture warnings. See [Strict mode](#strict-mode). |

`container_cpu` and `container_memory` are shared with the other container backends. **`container_disk` is ignored by Podman**; it has no effect on this backend. `container_persistent` and `TERMINAL_SANDBOX_DIR` apply as for Docker.

Lifecycle, reuse, and the `podman_env`/`podman_forward_env` split work as described for the [Docker backend](./configuration.md#container-lifecycle). The labels differ: Podman sandboxes carry `hermes-podman=1`, never `hermes-agent=1`, so the Docker backend never touches them (and the reverse).

## Images

Podman refuses unqualified (short) image names when there is no terminal to ask which registry to use, which is always the case for Hermes. Hermes therefore qualifies unqualified names with `docker.io/` (for example `ubuntu` becomes `docker.io/library/ubuntu`, `nousresearch/hermes-sandbox:desktop` becomes `docker.io/nousresearch/hermes-sandbox:desktop`). Use a fully qualified name to pull from any other registry.

## User namespaces

`podman_userns` controls how container users map to host users.

| Value | Rootless behavior | Use when |
|---|---|---|
| `""` (default) | `--userns=host`: container root is your unprivileged host user. Files created in mounts are owned by you. Overrides a `userns` set in `containers.conf`. | Almost always. Simple ownership, no surprises. |
| `keep-id` | The container process runs as a non-root user with your uid. | Images built for a non-root user. |
| `auto` | A distinct UID range per sandbox, so sandboxes are isolated from each other as well as from the host. | You run several sandboxes and want them isolated from one another. |

On a **rootful** Podman the default passes no `--userns` flag at all, so `containers.conf` decides.

With `auto`, container root is a subuid, not you. Hermes chowns its own per-sandbox directories with Podman's `:U` mount option so the sandbox can write to them. Files the sandbox leaves under the sandbox directory then belong to a subuid and your normal user cannot delete them. Remove them with:

```sh
podman unshare rm -rf ~/.hermes/sandboxes/podman/<task_id>
```

`auto` needs a healthy subuid setup; see the split-range problem below.

## Posture warnings and fixes

At startup Hermes inspects Podman and **warns and continues** when something weakens the rootless guarantees. `hermes doctor` reports the same checks.

| Warning | Consequence | Fix |
|---|---|---|
| **Rootful Podman** | Container root is the host's real root; an escape gives full host control. | Run Podman as a regular user, without `sudo`. |
| **cgroups v1, or controllers not delegated** | CPU, memory, and PID limits are not applied; a runaway sandbox can exhaust the host. | Boot with cgroups v2 and delegate controllers: run `sudo systemctl edit user@.service` and add `[Service]` / `Delegate=cpu memory pids`, then log in again. |
| **Subuid range too small** | Images that use many UIDs fail to unpack. | `sudo usermod --add-subuids 100000-165535 --add-subgids 100000-165535 $USER`, then `podman system migrate`. |
| **Subuid range split across adjacent lines** | Podman maps it as split extents. `userns=auto` fails with `gid_map: Operation not permitted`, and layers with high UIDs fail with `not enough unused IDs`. | Merge the lines in `/etc/subuid` (and `/etc/subgid`) into one, for example `user:100000:1065536`, then run `podman system migrate`. |

:::warning `podman system migrate` stops running containers
It restarts Podman's storage state and stops every running container, including a persistent Hermes sandbox. Background processes inside it are lost. Run it when no work is in flight.
:::

### Strict mode

Set `podman_strict: true` to turn every posture warning into a refusal: Hermes will not start the sandbox until the posture is fixed. Use it for unattended gateways where a silently degraded sandbox is worse than no sandbox.

```yaml
terminal:
  backend: podman
  podman_strict: true
```

## Egress proxy

The [egress proxy](./egress/iron-proxy.md) (`proxy.enabled: true`) works with the Podman backend, with one requirement: **`pasta`** (package `passt`) must be installed. Hermes never uses slirp4netns `allow_host_loopback` and never exposes the proxy on a public interface.

- **Proxy on loopback.** The sandbox is attached through pasta with port forwarding (`-T`) for exactly the two proxy ports, so those are the only host-local ports it can reach. This also means those two ports on `127.0.0.1` inside the sandbox are reserved for the proxy.
- **Proxy on a private IP** (such as `docker0`). Reached directly through plain pasta networking.
- **Public or wildcard listen address.** Not used. The sandbox is never pointed at it.

:::caution Do not bind the proxy to all interfaces
An `http_listen` with an empty host (for example `":8443"`) makes iron-proxy bind every interface. Always give an explicit loopback or private address.
:::

If egress is on but cannot be reached, Hermes refuses to start the sandbox when `proxy.enforce_on_podman: true` (the default). The cases are: `pasta` is missing, the proxy listens on a non-private address, or `podman_extra_args` sets its own `--network` while egress is on. With `proxy.enforce_on_podman: false` Hermes logs a warning and starts the sandbox **without** the proxy, so real credentials may be reachable from inside it. See [Egress proxy](./egress/iron-proxy.md).

`podman_network: false` disables all networking and makes egress irrelevant.

## SELinux

On SELinux hosts Hermes relabels bind mounts automatically: `z` (shared label) for mounts in general, and `Z` (private label) only for the per-sandbox directories Hermes creates itself. Your own `podman_volumes` are never given the private label.

## Troubleshooting

- **`short-name resolution` errors**: qualify the image (`registry.example.com/org/image:tag`).
- **Permission denied on mounted files**: with `userns: auto`, files belong to a subuid; use the default or `keep-id`, or clean up with `podman unshare`.
- **`gid_map: Operation not permitted`**: split `/etc/subuid`; merge the ranges and run `podman system migrate`.
- **Limits not applied**: cgroup controllers are not delegated; see the posture table above.
