"""Rootless security-posture probe for the native Podman backend.

Reads ``podman info --format json`` once per process and reports what protections
the host's Podman is missing, so the backend can warn (or refuse in strict mode).
"""

from __future__ import annotations

import json
import logging
import shutil
import subprocess
from dataclasses import dataclass
from functools import lru_cache
from typing import Any

from tools.environments.base import EnvironmentConnectionError

_MIN_SUBID_RANGE = 65536
_REQUIRED_CONTROLLERS = frozenset({"cpu", "memory", "pids"})
_PROBE_TIMEOUT = 30


@dataclass(frozen=True)
class PodmanPosture:
    version: str
    rootless: bool
    cgroup_v2: bool
    controllers: frozenset[str]
    selinux: bool
    network_cmd: str
    pasta_available: bool
    # (container_id, host_id, size) extents of host.idMappings.uidmap
    uid_extents: tuple[tuple[int, int, int], ...]


class PodmanPostureError(RuntimeError):
    """Raised in strict mode when the Podman posture has warnings."""


@lru_cache(maxsize=1)
def find_podman() -> str | None:
    """``podman`` from PATH (cached; call ``find_podman.cache_clear()`` in tests)."""
    return shutil.which("podman")


def _detect_pasta() -> bool:
    return shutil.which("pasta") is not None


def parse_posture(info: dict[str, Any], *, pasta_available: bool | None = None) -> PodmanPosture:
    """Build a posture from a decoded ``podman info --format json`` document."""
    host = info.get("host") or {}
    security = host.get("security") or {}
    uidmap = (host.get("idMappings") or {}).get("uidmap") or []
    extents = tuple(
        (int(e.get("container_id", 0)), int(e.get("host_id", 0)), int(e.get("size", 0)))
        for e in uidmap
    )
    return PodmanPosture(
        version=str((info.get("version") or {}).get("Version", "")),
        rootless=bool(security.get("rootless", False)),
        cgroup_v2=host.get("cgroupVersion") == "v2",
        controllers=frozenset(host.get("cgroupControllers") or ()),
        selinux=bool(security.get("selinuxEnabled", False)),
        network_cmd=str(host.get("rootlessNetworkCmd") or "slirp4netns"),
        pasta_available=_detect_pasta() if pasta_available is None else pasta_available,
        uid_extents=extents,
    )


_posture_cache: dict[str, PodmanPosture] = {}


def probe_posture(exe: str) -> PodmanPosture:
    """Run ``podman info --format json`` (cached per process per binary)."""
    cached = _posture_cache.get(exe)
    if cached is not None:
        return cached
    hint = " (on macOS, run `podman machine start` first)"
    try:
        proc = subprocess.run(
            [exe, "info", "--format", "json"],
            stdin=subprocess.DEVNULL, capture_output=True, text=True,
            timeout=_PROBE_TIMEOUT, check=False,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise EnvironmentConnectionError(f"`{exe} info` failed: {exc}.{hint}") from exc
    if proc.returncode != 0:
        detail = (proc.stderr or proc.stdout or "").strip()[:300]
        raise EnvironmentConnectionError(f"`{exe} info` exited {proc.returncode}: {detail}.{hint}")
    try:
        info = json.loads(proc.stdout)
    except ValueError as exc:
        raise EnvironmentConnectionError(f"`{exe} info` returned invalid JSON.{hint}") from exc
    posture = parse_posture(info)
    _posture_cache[exe] = posture
    return posture


def cgroup_limits_supported(p: PodmanPosture) -> bool:
    return p.cgroup_v2 and _REQUIRED_CONTROLLERS <= p.controllers


def posture_warnings(p: PodmanPosture) -> list[str]:
    """Human-readable warnings: what is missing, what protection is lost, how to fix."""
    warnings: list[str] = []
    if not p.rootless:
        warnings.append(
            "Podman is rootful: the container's root is the host's real root, so a "
            "container escape grants full host control. Use rootless Podman "
            "(run it as a regular user, without sudo)."
        )
    if not cgroup_limits_supported(p):
        missing = sorted(_REQUIRED_CONTROLLERS - p.controllers) if p.cgroup_v2 else []
        why = (
            "cgroups v1 is in use"
            if not p.cgroup_v2
            else f"cgroup controllers not delegated to this user: {', '.join(missing)}"
        )
        warnings.append(
            f"{why}, so CPU/memory/PID limits are not applied and a runaway sandbox can "
            "exhaust the host. Boot with cgroups v2 and delegate controllers: "
            "`sudo systemctl edit user@.service` with `[Service]\\nDelegate=cpu memory pids`, "
            "then log in again."
        )
    if p.rootless:
        extents = [e for e in p.uid_extents if e[0] != 0 and e[2] > 0]
        for i, a in enumerate(extents):
            if any(
                i != j and a[1] + a[2] == b[1] and a[0] + a[2] == b[0]
                for j, b in enumerate(extents)
            ):
                warnings.append(
                    "/etc/subuid has adjacent ranges on separate lines for this user, which "
                    "Podman maps as split extents; image layers with high UIDs fail with "
                    "'not enough unused IDs'. Merge them into a single line in /etc/subuid "
                    "(and /etc/subgid), then run `podman system migrate`."
                )
                break
        if sum(e[2] for e in extents) < _MIN_SUBID_RANGE:
            warnings.append(
                f"The subuid range is smaller than {_MIN_SUBID_RANGE}, so images that use "
                "many UIDs fail to unpack. Run `sudo usermod --add-subuids 100000-165535 "
                "--add-subgids 100000-165535 $USER`, then `podman system migrate`."
            )
    return warnings


def enforce_posture(p: PodmanPosture, *, strict: bool, log: logging.Logger) -> list[str]:
    """Log each warning; in strict mode refuse when any exist. Returns the warnings."""
    warnings = posture_warnings(p)
    for w in warnings:
        log.warning("Podman posture: %s", w)
    if strict and warnings:
        raise PodmanPostureError(
            "terminal.podman_strict is enabled and the Podman posture is degraded:\n- "
            + "\n- ".join(warnings)
        )
    return warnings
