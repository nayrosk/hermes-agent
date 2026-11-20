"""Pure ``podman run`` argument builders for the rootless Podman backend."""

from __future__ import annotations

from tools.environments.docker import (
    _DEFAULT_PIDS_LIMIT,
    _build_security_args,
    _extra_args_network_mode,
    _extra_args_set_shm_size,
)
from tools.environments.podman_posture import PodmanPosture, cgroup_limits_supported


def qualify_image(image: str) -> str:
    """Fully qualify *image* (Podman may have no unqualified-search registries)."""
    first, sep, _ = image.partition("/")
    if not sep:
        return f"docker.io/library/{image}"
    if "." in first or ":" in first or first == "localhost":
        return image
    return f"docker.io/{image}"


def security_args(userns: str, *, s6_init: bool, rootless: bool) -> list[str]:
    """Capability/tmpfs/userns args.

    On rootless Podman the default (``""``) pins ``--userns=host``: that is Podman's own
    rootless namespace, so container root is the host user, even when containers.conf sets a
    ``userns`` default (e.g. ``auto``). On rootful Podman ``host`` is the real host namespace
    (container root = host root), so the default emits no flag and an admin's containers.conf
    ``userns`` still applies.
    """
    args = _build_security_args(run_as_host_user=(userns == "keep-id"), run_exec=s6_init)
    # Explicit exec on /tmp (Podman's default tmpfs mount options are not guaranteed exec).
    args = [
        a.replace("/tmp:rw,", "/tmp:rw,exec,", 1)  # no-tmp: ok — container tmpfs mount spec
        if a.startswith("/tmp:") and ",exec," not in a else a  # no-tmp: ok — container tmpfs mount spec
        for a in args
    ]
    if userns or rootless:
        args.append(f"--userns={userns or 'host'}")
    return args


def resource_args(
    p: PodmanPosture, *, cpu: float, memory: int, shm_size: str, network: bool,
    extra_args: list[str],
) -> list[str]:
    """cgroup-gated CPU/memory/pids limits, shm size and the user's network intent.

    Disk quota is never emitted. ``network=True`` adds no flag (egress networking is
    added separately).
    """
    args: list[str] = []
    if cgroup_limits_supported(p):
        if cpu > 0:
            args.extend(["--cpus", str(cpu)])
        if memory > 0:
            args.extend(["--memory", f"{memory}m"])
        args.extend(["--pids-limit", _DEFAULT_PIDS_LIMIT])
    shm = str(shm_size or "").strip()
    if shm and shm != "0" and not _extra_args_set_shm_size(extra_args):
        args.extend(["--shm-size", shm])
    if not network:
        extra_network = _extra_args_network_mode(extra_args)
        if extra_network is None:
            args.append("--network=none")
        elif extra_network != "none":
            raise RuntimeError(
                f"terminal.podman_network is false (air-gapped) but terminal.podman_extra_args "
                f"requests --network={extra_network!r}. Remove the --network entry from "
                f"podman_extra_args, or set podman_network: true to opt into that network.")
    return args


def label_volume(spec: str, selinux: bool, *, private: bool = False) -> str:
    """Add an SELinux relabel option to a host-path bind mount when SELinux is active.

    ``z`` (shared) is for user/shared host paths; ``Z`` (private) only for
    Hermes-created per-sandbox dirs, since it relabels the files for one container.
    Named volumes, relative paths and specs already carrying ``z``/``Z`` are unchanged.
    """
    if not selinux:
        return spec
    parts = spec.split(":")
    if len(parts) not in (2, 3) or not parts[0].startswith(("/", ".", "~")):
        return spec
    label = "Z" if private else "z"
    if len(parts) == 2:
        return f"{spec}:{label}"
    opts = [o for o in parts[2].split(",") if o]
    if "z" in opts or "Z" in opts:
        return spec
    return f"{parts[0]}:{parts[1]}:{','.join(opts + [label])}"
