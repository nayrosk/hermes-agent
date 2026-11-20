"""Host directories that stand in for a Docker container's ``/workspace`` and ``/root``.

``base.py`` and ``run.py`` are over the file-size ratchet, so the candidate list and the
gateway's missing-output-mount warning live here.
The workspace digest is passed in: delivery runs after the turn's context is
gone, and scanning every ``*_ws_*`` directory would serve another session's file.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import re
from collections.abc import Callable
from pathlib import Path

from tools.terminal_tool_config import container_runtime_env_var, is_docker_like_backend

logger = logging.getLogger(__name__)

_WORKSPACE_KEY_RE = re.compile(r"^[0-9a-f]{16}$")
_VOLUME_SPEC_RE = re.compile(r"^(?P<host>.+):(?P<container>/[^:]+?)(?::(?P<options>[^:]+))?$")
_MEDIA_OUTPUT_CONTAINER_PATHS = {"/output", "/outputs"}


def _scope():
    from gateway.platforms.base import _docker_persistent_active, _tenv

    return _tenv, _docker_persistent_active


def _backend() -> str:
    tenv, _persistent = _scope()
    return tenv("TERMINAL_ENV", "").strip().lower()


def _cwd_mount_enabled() -> bool:
    """The terminal's own predicate, so the file panel agrees with what the container mounted."""
    from tools.terminal_tool_config import _tenv_bool, container_runtime_env_var

    return _tenv_bool(container_runtime_env_var(_backend(), "MOUNT_CWD_TO_WORKSPACE"), "false")


def _shared_container_key(tenv) -> str:
    """The active backend's shared-container opt-in (``TERMINAL_PODMAN_*`` under podman)."""
    from tools.terminal_tool_config import container_runtime_env_var

    return tenv(container_runtime_env_var(_backend(), "SHARED_CONTAINER_KEY"), "").strip()


def sandbox_backend_root() -> Path:
    """``<sandbox>/docker`` or ``<sandbox>/podman``: where the active backend keeps persistent sandboxes."""
    from tools.environments.base import get_sandbox_dir
    from tools.terminal_tool_config import container_sandbox_subdir

    return get_sandbox_dir() / container_sandbox_subdir(_backend())


def sandbox_media_base(session_key: str = "", workspace_key: str = "") -> Path:
    """The session's own sandbox dir (first candidate) under :func:`sandbox_backend_root`."""
    return sandbox_backend_root() / _docker_sandbox_dir_candidates(session_key, workspace_key)[0]


def _docker_sandbox_dir_candidates(session_key: str = "", workspace_key: str = "") -> list[str]:
    """Candidate host sandbox dir names, best first.

    Mirrors ``_resolve_container_task_id``: profile scope (``default``, else
    ``profile:<name>``), then the legacy ``session:<key>`` layout. A session
    that bound a host workspace also has ``<base>:ws:<digest>`` — a different
    directory from the shared profile sandbox — but only with the cwd mount on:
    without it every session keeps the profile sandbox, and a ``*_ws_*`` dir
    left by an older build is not this session's. The digest is explicit because
    an ambient lookup after the turn would collapse onto ``default``.
    """
    tenv, _persistent = _scope()
    try:
        from tools.environments.path_utils import sanitize_task_id_for_path
        from tools.terminal_tool_config import container_runtime_env_var, home_profile_name, profile_container_key
        base = profile_container_key(home_profile_name())
    except Exception:  # health: allow BLE001 -- path translation fails closed; a miss is a 404, not a 500
        return ["default"]
    candidates: list[str] = []
    # Explicit trusted-profiles opt-in: one shared container identity. That
    # key is not a per-workspace container, so a :ws: digest does not apply.
    if shared := _shared_container_key(tenv):
        candidates.append(sanitize_task_id_for_path(f"shared:{shared}"))
    elif _WORKSPACE_KEY_RE.fullmatch(workspace_key or "") and _cwd_mount_enabled():
        candidates.append(sanitize_task_id_for_path(f"{base}:ws:{workspace_key}"))
    if base != "default":
        candidates.append(sanitize_task_id_for_path(base))
    candidates.append("default")
    if session_key:  # bug-window legacy layout: per-session sandboxes
        candidates.append(sanitize_task_id_for_path(f"session:{session_key}"))
    return candidates


def _docker_persistent_sandbox_roots(
    session_key: str, leaf: str, workspace_key: str = "",
) -> list[Path]:
    """Existing ``<sandbox>/<docker|podman>/<candidate>/<leaf>`` dirs, candidate order.

    Empty unless Docker/Podman + persistent. The translator tries each until the file
    resolves.
    """
    _tenv, persistent = _scope()
    if not persistent():
        return []
    try:
        base = sandbox_backend_root()
        return [cand for name in _docker_sandbox_dir_candidates(session_key, workspace_key)
                if (cand := (base / name / leaf).resolve(strict=False)).is_dir()]
    except Exception:  # health: allow BLE001 -- path translation fails closed; a miss is a 404, not a 500
        return []


def _mounted_workspace_cwd(workspace_cwd: str = "") -> list[Path]:
    tenv, _persistent = _scope()
    cwd = workspace_cwd or tenv("TERMINAL_CWD") or os.getcwd()
    try:
        host = Path(os.path.expanduser(cwd)).resolve(strict=False)
    except (OSError, RuntimeError, ValueError):
        return []
    return [host] if host.is_dir() else []


def _session_mounted_workspace(workspace_key: str, workspace_cwd: str) -> list[Path]:
    """The host dir a session bound to a workspace mounts at ``/workspace``, or nothing.

    A gateway turn runs with the session's own cwd as ``TERMINAL_CWD``
    (``gateway.session_policy.build_policy``), and that cwd is also what
    ``bind_turn_workspace`` registers and hashes into ``workspace_key``. So the
    mount is that cwd, never the profile's ``terminal.cwd``. A cwd whose digest
    is not ``workspace_key`` names some other container's mount: no root.
    """
    from tools.terminal_tool import workspace_key_for

    cwd = (workspace_cwd or "").strip()
    if not cwd or "\0" in cwd or not os.path.isabs(os.path.expanduser(cwd)):
        return []
    if workspace_key_for(cwd) != workspace_key:
        return []
    return _mounted_workspace_cwd(cwd)


def _shared_cwd_mount_guess(workspace_key: str) -> list[Path]:
    """The profile cwd that stands in for a shared container's ``/workspace``, or nothing.

    With ``TERMINAL_DOCKER_SHARED_CONTAINER_KEY`` (podman: ``TERMINAL_PODMAN_*``) every session reuses one
    ``shared:<key>`` container, which mounts whatever cwd the session that
    created it brought, so a session's own cwd is not its mount. Nothing records
    that first cwd: shared containers carry no mount fingerprint label, and a
    cross-process attach never inspects the container's mounts. Reads keep the
    profile cwd, as before; a session Save there is a guess the caller refuses.
    """
    tenv, persistent = _scope()
    if not persistent() or not _WORKSPACE_KEY_RE.fullmatch(workspace_key or ""):
        return []
    if not _cwd_mount_enabled():
        return []
    if not _shared_container_key(tenv):
        return []
    return _mounted_workspace_cwd()


def _default_docker_workspace_host_roots(
    session_key: str = "", workspace_key: str = "", workspace_cwd: str = "",
) -> list[Path]:
    """Host dirs that stand in for ``/workspace``.

    A cwd mount is tried first. With no workspace digest that mount is the
    profile's cwd and the only candidate, so MEDIA delivery (which has no
    session) stays cwd-only. A download that names a digest mounts that
    session's own cwd (``workspace_cwd``) instead, unless its container is a
    shared one (``_shared_cwd_mount_guess``), then tries that session's
    sandbox: the container key can be ``default:ws:<digest>`` while
    ``/workspace`` is still the sandbox directory, because the host cwd was
    not bind-mounted when the container was created.
    """
    tenv, persistent = _scope()
    if not persistent():
        return []
    roots: list[Path] = []
    if _cwd_mount_enabled():
        if not _WORKSPACE_KEY_RE.fullmatch(workspace_key or ""):
            return _mounted_workspace_cwd()
        if _shared_container_key(tenv):
            roots.extend(_shared_cwd_mount_guess(workspace_key))
        else:
            roots.extend(_session_mounted_workspace(workspace_key, workspace_cwd))
    for root in _docker_persistent_sandbox_roots(session_key, "workspace", workspace_key):
        if root not in roots:
            roots.append(root)
    return roots


async def hand_back_unreadable_media(paths: list[str]) -> None:
    """Validated MEDIA files a root Docker sandbox restricted (``chmod 600``) are unreadable to the
    gateway while the container lives (teardown hands files back only on removal): give each one
    to the host user through the container itself; the sandbox keeps ``no-new-privileges``. Docker
    CLI calls block, so they run off the event loop (``to_thread`` carries the profile scope)."""
    # Docker only: the hand-back drives the ``docker`` binary. Rootless podman's container root is the
    # host user (no hand-back needed), and a remapped userns is not something ``docker`` can fix.
    if not (unreadable := [p for p in paths if not os.access(p, os.R_OK)]) or _backend() != "docker":
        return
    await asyncio.to_thread(_hand_back_files, unreadable)


def _hand_back_files(paths: list[str]) -> None:
    from tools.environments.docker import find_docker
    from tools.environments.docker_ownership import hand_back_media_file
    docker_exe = find_docker()
    for path in paths if docker_exe else []:
        if hand_back_media_file(docker_exe, path):
            logger.info("Handed Docker sandbox MEDIA file %s back to the gateway user", Path(path).name)


def warn_if_media_delivery_is_risky(messaging_platforms: Callable[[], list]) -> None:
    """Warn when a Docker/Podman-backed gateway lacks an explicit export mount: MEDIA delivery runs in the
    gateway process, so model-emitted paths like `/output/report.txt` must be host-readable."""
    backend = os.getenv("TERMINAL_ENV", "").strip().lower()
    if not is_docker_like_backend(backend) or not messaging_platforms():
        return

    volumes_var = container_runtime_env_var(backend, "VOLUMES")
    raw_volumes = os.getenv(volumes_var, "").strip()
    volumes: list[str] = []
    if raw_volumes:
        try:
            parsed = json.loads(raw_volumes)
            if isinstance(parsed, list):
                volumes = [str(v) for v in parsed if isinstance(v, str)]
        except Exception:
            logger.debug("Could not parse %s for gateway media warning", volumes_var, exc_info=True)

    for spec in volumes:
        match = _VOLUME_SPEC_RE.match(spec)
        if match and match.group("container") in _MEDIA_OUTPUT_CONTAINER_PATHS:
            return
    logger.warning(
        "%s backend is enabled for the messaging gateway but no explicit host-visible "
        "output mount (for example '/home/user/.hermes/cache/documents:/output') is configured. "
        "This is fine if the model already emits host-visible paths, but MEDIA file delivery can fail "
        "for container-local paths like '/workspace/...' or '/output/...'.",
        "Podman" if backend == "podman" else "Docker")
