"""Native rootless Podman execution environment.

The Podman counterpart of ``DockerEnvironment``: same lifecycle (snapshot init, name-only
``-e`` env with values in the client env, cross-process reuse by labels, idle stop,
drained teardown, orphan reaper), but it inherits only ``BaseEnvironment`` and reuses
Docker's runtime-agnostic helpers by import. Containers carry ``hermes-podman=1`` (never
``hermes-agent=1``), so the Docker path and this one never see each other's containers.
State is read from ``--format json`` output and exit codes only, never human-readable text.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import subprocess
import threading
import time
import uuid
from typing import Optional

from agent.memory_provider import spawn_context_thread
from hermes_constants import SCRATCH_TMP_ENV_VARS, get_hermes_home
from tools.environments.base import BaseEnvironment, EnvironmentConnectionError, get_sandbox_dir
from tools.environments.base_output import _popen_bash
from tools.environments.docker import (
    _ENVIRONMENT_LABEL_KEY, _WORKSPACE_LABEL_KEY, _WORKSPACE_TASK_RE, _container_identity,
    _extra_args_network_mode, _image_uses_init_entrypoint, _name_only_env_args,
    _normalize_env_dict, _normalize_forward_env_names, _readonly_skill_mount_args,
    _reuse_environment_fingerprint, _sanitize_label_value, plan_mounts,
)
from tools.environments.docker_egress import (
    _EGRESS_LABEL_KEY, _critical_egress_env_names, _egress_reuse_fingerprint,
    check_docker_env_collisions, check_extra_args_collisions, check_forward_env_collisions,
    merge_egress_env,
)
from tools.environments.podman_args import label_volume, qualify_image, resource_args, security_args
from tools.environments.podman_egress import egress_args_for_podman, egress_enforce_on_podman
from tools.environments.podman_posture import (
    PodmanPosture, cgroup_limits_supported, enforce_posture, find_podman, probe_posture,
)
from tools.environments.remote_common import (
    bash_argv, client_env_with, load_hermes_env_vars, prepend_unset, resolve_passthrough_env, run_capture,
)
from tools.terminal_tool_config import cwd_follows_host_mount

logger = logging.getLogger(__name__)

_PODMAN_LABEL = "hermes-podman"
_POSTURE_LABEL_KEY = "hermes-podman-posture"
_DEFAULT_SHM_SIZE = "1g"

# Posture warnings are logged once per process per binary, not per sandbox.
_WARNED_POSTURES: set[str] = set()


class _NullLog:
    """Swallows ``enforce_posture``'s warnings once they have been logged in this process."""

    def warning(self, *args, **kwargs) -> None:
        pass


def _notify_posture_warnings(warnings: list[str]) -> None:
    """Hand each posture warning to the startup-notice channel the CLI and gateway show the user
    (spec §5: no silent degradation). Already logged by ``enforce_posture``; best-effort."""
    if not warnings:
        return
    try:
        from hermes_cli.left_core_migration import defer_startup_notice
    except ImportError:
        return
    for warning in warnings:
        try:
            defer_startup_notice(f"Podman posture: {warning}", log=False)
        except Exception:  # a notice must never stop the sandbox from starting
            logger.debug("podman posture notice not kept", exc_info=True)


# This backend's own teardown registry (Docker's drain never joins Podman workers).
_TEARDOWN_THREADS: set[threading.Thread] = set()
_TEARDOWN_LOCK = threading.Lock()


def _podman_client_env(values: dict[str, str] | None = None) -> dict[str, str]:
    """Env for a podman CLI call: this process's env without TMPDIR/TMP/TEMP, plus *values*.

    Hermes points TMPDIR at its private scratch dir (mode 0700). Rootless crun creates its
    intermediate mountpoint under TMPDIR from inside the user namespace, so every
    ``podman run``/``podman start`` would fail with "OCI permission denied" (exit 126).
    Without TMPDIR Podman falls back to its own runtime/temp defaults."""
    env = {k: v for k, v in os.environ.items() if k not in SCRATCH_TMP_ENV_VARS}
    env.update(values or {})
    return env


def _query(argv: list[str], *, timeout: float) -> Optional[subprocess.CompletedProcess]:
    """Best-effort ``run_capture``: ``None`` (logged at debug) when the CLI cannot run."""
    try:
        return run_capture(argv, timeout=timeout, env=_podman_client_env())
    except (subprocess.SubprocessError, OSError) as e:
        logger.debug("podman %s failed: %s", " ".join(argv[1:3]), e)
        return None


def _query_json(argv: list[str], *, timeout: float) -> Optional[list]:
    """Decoded JSON list from a ``--format json`` podman command, ``None`` on any failure."""
    result = _query(argv, timeout=timeout)
    if result is None or result.returncode != 0:
        return None
    try:
        data = json.loads(result.stdout or "[]")
    except ValueError:
        logger.debug("podman %s returned invalid JSON", argv[1])
        return None
    return data if isinstance(data, list) else None


def _row_id(row: dict) -> str:
    """Container id from a ``podman ps --format json`` row (``Id``; ``ID`` casing fallback)."""
    return str(row.get("Id") or row.get("ID") or "")


def _image_ref_key(ref: str) -> str:
    """*ref* as Podman records it on a container: ``name:tag@digest`` becomes ``name@digest``."""
    name, at, digest = ref.partition("@")
    if not at:
        return ref
    head, slash, last = name.rpartition("/")
    return f"{head}{slash}{last.partition(':')[0]}@{digest}"


def _label_v_args(args: list[str], selinux: bool, *, private: bool) -> list[str]:
    """Apply :func:`label_volume` to every spec following ``-v`` (tmpfs specs untouched)."""
    out = list(args)
    for i in range(len(out) - 1):
        if out[i] == "-v":
            out[i + 1] = label_volume(out[i + 1], selinux, private=private)
    return out


def _chown_v_args(args: list[str]) -> list[str]:
    """Add Podman's ``U`` option to every ``-v`` spec: chown the source to the container's
    root. Only for Hermes-created sandbox dirs under ``userns=auto``, whose container root is
    a subuid that cannot otherwise write (or even create mountpoints) in host-user-owned dirs."""
    out = list(args)
    for i in range(len(out) - 1):
        if out[i] == "-v":
            out[i + 1] = f"{out[i + 1]}{',' if out[i + 1].count(':') >= 2 else ':'}U"
    return out


def _posture_fingerprint(userns: str, sec_args: list[str], limits: bool, network: bool) -> str:
    """Reuse key of the container's security posture. *network* is part of it so an air-gapped
    sandbox never adopts a networked container (or the reverse) on reuse or recovery."""
    payload = json.dumps({"userns": userns, "security_args": sec_args, "limits": limits,
                          "network": network}, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()[:16]


def reap_podman_orphans(
    *, max_age_seconds: int, profile_filter: str | None, podman_exe: str | None = None,
) -> int:
    """Remove stale exited ``hermes-podman=1`` containers left by prior processes.

    Only exited containers of the caller's profile whose ``ExitedAt`` is older than
    *max_age_seconds*; idle-stopped per-workspace containers are spared. ``podman rm``
    without ``-f`` refuses a container a sibling restarted meanwhile. Best-effort: returns
    the count removed."""
    podman = podman_exe or find_podman() or "podman"
    filters = ["--filter", f"label={_PODMAN_LABEL}=1", "--filter", "status=exited"]
    if profile_filter:
        filters += ["--filter", f"label=hermes-profile={_sanitize_label_value(profile_filter)}"]
    rows = _query_json([podman, "ps", "-a", *filters, "--format", "json"], timeout=15)
    if rows is None:
        return 0
    now = time.time()
    removed = 0
    for row in rows:
        if not isinstance(row, dict) or not (cid := _row_id(row)):
            continue
        if str(row.get("State", "")).lower() != "exited":
            continue
        try:
            exited_at = int(row.get("ExitedAt") or 0)
        except (TypeError, ValueError):
            continue
        if exited_at <= 0 or now - exited_at < max_age_seconds:
            continue  # unknown or recent exit: a sibling may be about to reuse it
        if (row.get("Labels") or {}).get(_WORKSPACE_LABEL_KEY):
            continue  # stopped on purpose by stop_idle; restarted on next use
        result = _query([podman, "rm", cid], timeout=30)
        if result is not None and result.returncode == 0:
            removed += 1
            logger.info("Reaped orphan podman container %s (exited %d seconds ago)",
                        cid[:12], int(now - exited_at))
    return removed


class PodmanEnvironment(BaseEnvironment):
    """Rootless Podman sandbox (caps dropped, no-new-privileges, cgroup limits when
    delegated). Persistence bind-mounts /workspace and /root from the sandbox dir."""

    _passwordless_sudo_probe_supported = True
    _profile_scoped_passthrough = True

    def _additional_profile_scoped_passthrough_names(self) -> tuple[str, ...]:
        return tuple(self._forward_env)

    def __init__(
        self, image: str, cwd: str = "/root", timeout: int = 60, cpu: float = 0, memory: int = 0,
        disk: int = 0, persistent_filesystem: bool = False, task_id: str = "default",
        volumes: list | None = None, forward_env: list[str] | None = None, env: dict | None = None,
        network: bool = True, host_cwd: Optional[str] = None, auto_mount_cwd: bool = False,
        extra_args: list | None = None, persist_across_processes: bool = True,
        shm_size: str = _DEFAULT_SHM_SIZE, shared_container_key: str = "", image_pinned: bool = False,
        userns: str = "", strict: bool = False):
        if cwd == "~":
            cwd = "/root"
        super().__init__(cwd=cwd, timeout=timeout)
        self._persistent = persistent_filesystem
        self._persist_across_processes = persist_across_processes
        self._session_scoped = False
        self._task_id = task_id
        self._forward_env = _normalize_forward_env_names(forward_env)
        self._env = _normalize_env_dict(env)
        self._init_unset_passthrough_names: tuple[str, ...] = ()
        self._init_env_values: dict[str, str] = {}
        self._container_id: Optional[str] = None
        self._workspace_dir: Optional[str] = None
        self._home_dir: Optional[str] = None
        if volumes is not None and not isinstance(volumes, list):
            logger.warning("podman_volumes config is not a list: %r", volumes)
            volumes = []
        if disk:
            logger.debug("Podman: container_disk=%s ignored (no per-container disk quota)", disk)

        exe = find_podman()
        if not exe:
            raise EnvironmentConnectionError(
                "Podman executable not found in PATH. Install Podman and ensure the 'podman' "
                "command is available.",
                retry_hint="Install Podman (or fix PATH) and retry, or run `hermes setup terminal` "
                           "to switch backend.")
        self._docker_exe = exe  # kept under Docker's name for consumers that read it
        self.posture: PodmanPosture = probe_posture(exe)
        first_report = exe not in _WARNED_POSTURES
        _WARNED_POSTURES.add(exe)
        self.posture_warnings: list[str] = enforce_posture(
            self.posture, strict=strict, log=logger if first_report else _NullLog())
        if first_report:
            _notify_posture_warnings(self.posture_warnings)

        validated_extra = [a for a in (extra_args or []) if isinstance(a, str)]
        if len(validated_extra) != len(extra_args or []):
            logger.warning("Ignoring non-string podman_extra_args entries")
        res_args = resource_args(self.posture, cpu=cpu, memory=memory, shm_size=shm_size,
                                 network=network, extra_args=validated_extra)

        selinux = self.posture.selinux
        plan = plan_mounts(volumes, host_cwd, auto_mount_cwd, task_id, persistent=persistent_filesystem,
                           sandbox_root=get_sandbox_dir() / "podman" if persistent_filesystem else None)
        self.host_cwd, self.host_cwd_mount = plan.host_cwd, plan.host_cwd_mount
        self._home_dir, self._workspace_dir = plan.home_dir, plan.workspace_dir
        writable_args = plan.writable_args
        if userns == "auto":
            writable_args = _chown_v_args(writable_args)
        writable_args = _label_v_args(writable_args, selinux, private=True)
        volume_args = _label_v_args(
            plan.volume_args + _readonly_skill_mount_args(), selinux, private=False)
        if self.host_cwd_mount and cwd_follows_host_mount(cwd, self.host_cwd_mount):
            logger.info("Container cwd follows configured host workspace at %s (requested %s)",
                        self.host_cwd_mount, cwd)
            cwd = self.cwd = self.host_cwd_mount

        egress_label, egress_volume_args, egress_net_args, env_args = self._egress_and_env_args(
            network, validated_extra)
        volume_args += egress_volume_args

        image = qualify_image(image)
        image_uses_s6_init = _image_uses_init_entrypoint(exe, image)
        sec_args = security_args(userns, s6_init=image_uses_s6_init, rootless=self.posture.rootless)
        self._all_run_args = (sec_args + writable_args + res_args + egress_net_args
                              + volume_args + env_args + validated_extra)
        logger.info("Podman run_args: %s", self._all_run_args)

        profile_name = _container_identity(shared_container_key)
        task_label = _sanitize_label_value(task_id)
        self._labels = {
            _PODMAN_LABEL: "1",
            "hermes-task-id": task_label,
            "hermes-profile": profile_name,
            _EGRESS_LABEL_KEY: egress_label,
            _POSTURE_LABEL_KEY: _posture_fingerprint(
                userns, sec_args, cgroup_limits_supported(self.posture), network),
        }
        if workspace := _WORKSPACE_TASK_RE.search(task_id or ""):
            self._labels[_WORKSPACE_LABEL_KEY] = workspace.group(1)
        if not shared_container_key:
            self._labels[_ENVIRONMENT_LABEL_KEY] = _reuse_environment_fingerprint(
                image=image, mount_args=[*writable_args, *volume_args], hermes_home=str(get_hermes_home()))
        self._image = image
        self._image_pinned = image_pinned
        self._image_uses_s6_init = image_uses_s6_init

        if not (persist_across_processes and self._attach_existing_container(network)):
            self._container_id = self._podman_run(cwd)

        self._init_env_args = self._build_init_env_args()
        self.init_session()

    # --- __init__ helpers ---
    def _egress_and_env_args(
        self, network: bool, extra_args: list[str],
    ) -> tuple[str, list[str], list[str], list[str]]:
        """Egress plumbing reconciled with the user's network flag, merged with podman_env into
        name-only ``-e`` args. Returns ``(egress_label, volume_args, network_args, env_args)``
        and sets ``self._run_env_values`` (carried in the client env, never argv)."""
        volume_args, env_overrides, net_args = egress_args_for_podman(self.posture, network=network)
        if net_args and (user_net := _extra_args_network_mode(extra_args)) is not None:
            msg = (f"terminal.podman_extra_args sets --network={user_net!r}, which would bypass the "
                   "egress proxy's pasta network")
            if egress_enforce_on_podman():
                raise RuntimeError(
                    f"{msg}. Remove the --network entry from podman_extra_args, or set "
                    "proxy.enforce_on_podman: false to start the sandbox without the proxy.")
            logger.warning("%s — starting without the egress proxy (proxy.enforce_on_podman=false).", msg)
            volume_args, env_overrides, net_args = [], {}, []
        egress_label = _egress_reuse_fingerprint(volume_args, env_overrides, net_args)
        enforce = egress_enforce_on_podman() if env_overrides else True
        if env_overrides:
            critical = _critical_egress_env_names(env_overrides)
            check_forward_env_collisions(self._forward_env, critical, enforce)
            check_docker_env_collisions(self._env, env_overrides, enforce)
            check_extra_args_collisions(extra_args, critical, enforce)
        merged = merge_egress_env(self._env, env_overrides, enforce)
        self._run_env_values = dict(merged)
        return egress_label, volume_args, net_args, _name_only_env_args(merged)

    # --- container lifecycle ---
    def _run_command(self, name: str, workdir: str) -> list[str]:
        label_args = [arg for k, v in self._labels.items() for arg in ("--label", f"{k}={v}")]
        return [
            self._docker_exe, "run", "-d",
            *([] if self._image_uses_s6_init else ["--init"]),
            "--name", name, *label_args, "-w", workdir, *self._all_run_args,
            self._image, "sleep", "infinity"]

    def _podman_run(self, cwd: str) -> str:
        """Start a fresh container; a failed run's leftover "Created" container is removed by name."""
        name = f"hermes-podman-{uuid.uuid4().hex[:8]}"
        try:
            result = run_capture(self._run_command(name, cwd), timeout=300, check=True,
                                 env=_podman_client_env(self._run_env_values))
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as e:
            logger.warning("podman run failed for %s, removing leftover container: %s", name, e)
            _query([self._docker_exe, "rm", "-f", name], timeout=10)
            raise
        container_id = result.stdout.strip()
        logger.info("Started podman container %s (%s)", name, container_id[:12])
        return container_id

    def _find_reusable_container(self) -> Optional[tuple[str, str]]:
        """``(id, state)`` of a container carrying every reuse label, preferring a running one."""
        filters = [arg for k in ("hermes-task-id", "hermes-profile", _EGRESS_LABEL_KEY,
                                 _POSTURE_LABEL_KEY, _ENVIRONMENT_LABEL_KEY)
                   if k in self._labels for arg in ("--filter", f"label={k}={self._labels[k]}")]
        rows = _query_json([self._docker_exe, "ps", "-a", "--filter", f"label={_PODMAN_LABEL}=1",
                            *filters, "--format", "json"], timeout=10)
        first = None
        for row in rows or []:
            if not isinstance(row, dict) or not (cid := _row_id(row)):
                continue
            state = str(row.get("State", "")).lower()
            if state == "running":
                return cid, state
            first = first or (cid, state)
        return first

    def _inspect(self, container_id: str) -> dict:
        rows = _query_json([self._docker_exe, "inspect", "--format", "json", container_id], timeout=10)
        return rows[0] if rows and isinstance(rows[0], dict) else {}

    def _remove(self, container_id: str) -> None:
        _query([self._docker_exe, "rm", "-f", container_id], timeout=30)

    def _start(self, container_id: str) -> bool:
        result = _query([self._docker_exe, "start", container_id], timeout=30)
        return result is not None and result.returncode == 0

    def _image_available_locally(self) -> bool:
        probe = _query([self._docker_exe, "image", "exists", self._image], timeout=30)
        if probe is not None and probe.returncode == 0:
            return True
        pull = _query([self._docker_exe, "pull", self._image], timeout=900)
        return pull is not None and pull.returncode == 0

    def _attach_existing_container(self, network: bool) -> bool:
        """Reuse a prior process's labeled container (Docker's rules: a default-image change
        keeps the sandbox, a pinned one replaces it once the image is available; an
        air-gap request never reuses a networked container)."""
        existing = self._find_reusable_container()
        if existing is None:
            return False
        cid, state = existing
        info = self._inspect(cid)
        actual_image = info.get("ImageName") or (info.get("Config") or {}).get("Image")
        if actual_image and _image_ref_key(actual_image) != _image_ref_key(self._image):
            if not self._image_pinned:
                logger.warning(
                    "Existing container %s runs image %s; the default podman_image is now %s. Keeping "
                    "the existing sandbox — approve the switch with `hermes config set "
                    "terminal.podman_image %s` or pin the current image to stop this notice.",
                    cid[:12], actual_image, self._image, self._image)
            elif not self._image_available_locally():
                logger.warning("Existing container %s runs image %s; %s could not be pulled — keeping "
                               "the current sandbox until it can.", cid[:12], actual_image, self._image)
            else:
                logger.warning("Existing container %s runs image %s but podman_image is %s — "
                               "replacing it.", cid[:12], actual_image, self._image)
                self._remove(cid)
                return False
        if not network and (info.get("HostConfig") or {}).get("NetworkMode") != "none":
            logger.warning("Existing container %s is networked but podman_network=false requests an "
                           "air-gapped sandbox — replacing it.", cid[:12])
            self._remove(cid)
            return False
        if state != "running" and not self._start(cid):
            logger.warning("Failed to start existing container %s (state=%s); starting fresh.", cid[:12], state)
            return False
        self._container_id = cid
        logger.info("Reusing podman container %s (prior state=%s)", cid[:12], state)
        return True

    # --- env forwarding / exec ---
    def _resolve_passthrough_env(self) -> tuple[dict[str, str], set[str]]:
        return resolve_passthrough_env(self._forward_env, hermes_env_loader=load_hermes_env_vars)

    def _build_init_env_args(self) -> list[str]:
        """Name-only ``-e`` args seeding the snapshot; values travel in the client env (#96268)."""
        passthrough, unset_names = self._resolve_passthrough_env()
        exec_env = {**self._env, **passthrough}
        for name in unset_names:
            exec_env.pop(name, None)
        self._init_unset_passthrough_names = tuple(sorted(unset_names))
        self._init_env_values = dict(exec_env)
        return _name_only_env_args(exec_env)

    def _run_bash(self, cmd_string: str, *, login: bool = False, timeout: int = 120,
                  stdin_data: str | None = None) -> subprocess.Popen:
        assert self._container_id, "Container not started"
        cmd = [self._docker_exe, "exec", "-w", "/"]
        if stdin_data is not None:
            cmd.append("-i")
        if login:
            cmd.extend(self._init_env_args)
            env_values = dict(self._init_env_values)
            unset_names = self._init_unset_passthrough_names
        else:
            passthrough, unset = self._resolve_passthrough_env()
            cmd.extend(_name_only_env_args(passthrough))
            env_values, unset_names = dict(passthrough), tuple(sorted(unset))
        cmd += [self._container_id, *bash_argv(prepend_unset(cmd_string, unset_names), login)]
        client_env = client_env_with(env_values)
        return _popen_bash(cmd, stdin_data, env=client_env) if client_env is not None else _popen_bash(cmd, stdin_data)

    # --- gone-container recovery ---
    def _recover(self) -> bool:
        """After a non-zero exec: recreate a gone container, restart a stopped one. True when the
        command should be retried. State comes from exit codes and ``inspect`` JSON only:
        ``container exists`` exit 1 means gone; ``State.Running`` false means stopped (sibling
        ``stop_idle``, manual stop, OOM). A running or unknown container is a genuine failure."""
        cid = self._container_id
        if not cid:
            return False
        exists = _query([self._docker_exe, "container", "exists", cid], timeout=10)
        if exists is None or exists.returncode not in (0, 1):
            return False
        if exists.returncode == 1:
            return self._recreate_container()
        if (self._inspect(cid).get("State") or {}).get("Running") is not False:
            return False
        if self._start(cid):
            logger.warning("Podman container %s was stopped — restarted it", cid[:12])
            return self._reinit_session()
        logger.warning("Podman container %s is stopped and failed to start — replacing it", cid[:12])
        self._remove(cid)
        return self._recreate_container()

    def _recreate_container(self) -> bool:
        logger.warning("Podman container %s is gone — attempting recovery", (self._container_id or "")[:12])
        self._container_id = None
        existing = self._find_reusable_container()
        if existing is not None and (existing[1] == "running" or self._start(existing[0])):
            self._container_id = existing[0]
        else:
            try:
                self._container_id = self._podman_run(self.cwd)
            except (subprocess.SubprocessError, OSError) as e:
                logger.error("Recovery: failed to create a new podman container: %s", e)
                return False
        return self._reinit_session()

    def _reinit_session(self) -> bool:
        """Re-snapshot the shell in a restarted/replaced container and flag the recreation."""
        try:
            self._snapshot_ready = False
            self.init_session()
        except (RuntimeError, OSError, subprocess.SubprocessError) as e:
            logger.error("Recovery: init_session failed: %s", e)
            return False
        self._mark_recreated()
        return True

    def execute(self, command: str, cwd: str = "", **kwargs) -> dict:
        """Execute; after a non-zero exit, recover a gone or stopped container and retry once."""
        result = super().execute(command, cwd, **kwargs)
        if (result.get("returncode", 0) != 0 and self._persist_across_processes
                and self._recover()):
            result = super().execute(command, cwd, **kwargs)
        return result

    # --- teardown ---
    def cleanup(self, *, force_remove: bool = False):
        """Persist mode leaves the container running (the reaper reclaims it later); otherwise
        ``podman stop`` + ``rm -f`` on a drained daemon thread."""
        self.stop_all_processes()
        container_id, self._container_id = self._container_id, None
        if container_id and not force_remove and self._persist_across_processes:
            return  # left running for the next process; bind dirs are its state
        if container_id:
            exe = self._docker_exe

            def _do_cleanup() -> None:
                for argv in (["stop", "-t", "10"], ["rm", "-f"]):
                    try:
                        subprocess.run([exe, *argv, container_id], capture_output=True, timeout=30,
                                       stdin=subprocess.DEVNULL, check=False)
                    except (subprocess.TimeoutExpired, OSError) as e:
                        logger.warning("podman %s %s failed: %s", argv[0], container_id[:12], e)

            self._start_teardown(_do_cleanup, container_id[:12])

    def stop_idle(self) -> None:
        """Idle reclaim: ``podman stop`` (never rm); the next use re-attaches and starts it."""
        container_id = self._container_id
        if not container_id:
            return
        exe = self._docker_exe

        def _do_stop() -> None:
            try:
                subprocess.run([exe, "stop", "-t", "10", container_id], capture_output=True,
                               timeout=30, stdin=subprocess.DEVNULL, check=False)
            except (subprocess.TimeoutExpired, OSError) as e:
                logger.warning("podman stop %s (idle) failed: %s", container_id[:12], e)

        self._start_teardown(_do_stop, container_id[:12])
        self._container_id = None

    def _start_teardown(self, work, log_id: str) -> None:
        t = spawn_context_thread(work, name=f"hermes-podman-cleanup-{log_id}")
        with _TEARDOWN_LOCK:
            _TEARDOWN_THREADS.add(t)
        t.start()
        self._cleanup_thread = t

    @staticmethod
    def wait_for_all_teardowns(timeout: float = 15.0) -> bool:
        """Join every in-flight Podman teardown worker (re-snapshotting each pass)."""
        deadline = time.monotonic() + timeout
        while True:
            with _TEARDOWN_LOCK:
                _TEARDOWN_THREADS.difference_update({t for t in _TEARDOWN_THREADS if not t.is_alive()})
                pending = list(_TEARDOWN_THREADS)
            if not pending:
                return True
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return False
            pending[0].join(timeout=remaining)

    def wait_for_cleanup(self, timeout: float = 30.0) -> bool:
        thread = getattr(self, "_cleanup_thread", None)
        if thread is None or not thread.is_alive():
            return True
        thread.join(timeout=timeout)
        return not thread.is_alive()
