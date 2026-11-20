"""Podman behaves like Docker wherever the code means "the Docker container backend".

One test per call site (spec §5.7bis). Sites that mean the Docker *product* (the docker binary's
ownership hand-back, install method, ``docker compose``) are pinned as Docker-only where they sit
next to a converted site.
"""
from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from tools import terminal_tool
from tools.approval import _should_skip_container_guards
from tools.terminal_tool import _docker_has_host_access


@pytest.fixture(autouse=True)
def _clean_overrides(monkeypatch):
    before = dict(terminal_tool._task_env_overrides)
    terminal_tool._task_env_overrides.clear()
    for var in ("TERMINAL_ENV", "HERMES_SESSION_KEY", "TERMINAL_DOCKER_SHARED_CONTAINER_KEY",
                "TERMINAL_PODMAN_SHARED_CONTAINER_KEY", "TERMINAL_DOCKER_MOUNT_CWD_TO_WORKSPACE",
                "TERMINAL_PODMAN_MOUNT_CWD_TO_WORKSPACE", "TERMINAL_DOCKER_VOLUMES", "TERMINAL_PODMAN_VOLUMES"):
        monkeypatch.delenv(var, raising=False)
    yield
    terminal_tool._task_env_overrides.clear()
    terminal_tool._task_env_overrides.update(before)


def _podman(monkeypatch, persistent: bool = True):
    monkeypatch.setenv("TERMINAL_ENV", "podman")
    monkeypatch.setenv("TERMINAL_CONTAINER_PERSISTENT", "true" if persistent else "false")


def _named(cls_name: str, **attrs):
    return type(cls_name, (), attrs)()


# ── tools/approval.py + tools/terminal_tool.py: dangerous-command guard ──────────────────────────

@pytest.mark.parametrize("has_host", [False, True])
def test_approval_guard_skip_matches_docker(has_host):
    assert _should_skip_container_guards("podman", has_host) == _should_skip_container_guards("docker", has_host)


def test_host_access_detection_podman():
    assert _docker_has_host_access({"env_type": "podman", "docker_volumes": ["/home/u:/w"]}) is True
    assert _docker_has_host_access({"env_type": "podman", "docker_volumes": []}) is False
    assert _docker_has_host_access({"env_type": "podman", "docker_volumes": [],
                                    "docker_mount_cwd_to_workspace": True}) is True


# ── tools/terminal_tool.py: container keying / cwd mount ──────────────────────────────────────────

@pytest.mark.parametrize("persistent", [True, False])
def test_session_scope_treats_podman_like_docker(persistent):
    pod, dock = terminal_tool._SessionScope("podman", persistent), terminal_tool._SessionScope("docker", persistent)
    assert (pod.session_isolated, pod.docker_session_isolated, pod.docker_profile_scoped) == \
        (dock.session_isolated, dock.docker_session_isolated, dock.docker_profile_scoped)


def test_shared_container_key_reads_the_podman_slot(monkeypatch):
    _podman(monkeypatch)
    monkeypatch.setenv("TERMINAL_PODMAN_SHARED_CONTAINER_KEY", "team/ws")
    monkeypatch.setenv("TERMINAL_DOCKER_SHARED_CONTAINER_KEY", "docker-only")
    assert terminal_tool._resolve_container_task_id(None) == "shared:team/ws"


def test_shared_container_key_ignores_the_docker_slot_under_podman(monkeypatch):
    _podman(monkeypatch)
    monkeypatch.setenv("TERMINAL_DOCKER_SHARED_CONTAINER_KEY", "docker-only")
    assert not terminal_tool._resolve_container_task_id(None).startswith("shared:")


def test_workspace_container_key_reads_the_podman_mount_flag(monkeypatch, tmp_path):
    _podman(monkeypatch)
    monkeypatch.setenv("TERMINAL_PODMAN_MOUNT_CWD_TO_WORKSPACE", "true")
    terminal_tool.register_task_env_overrides("t1", {"cwd": str(tmp_path), "cwd_source": "session"})
    key = terminal_tool._workspace_container_key("profile:p", "t1")
    assert key == f"profile:p:ws:{terminal_tool.workspace_key_for(str(tmp_path))}"


def test_task_host_cwd_mounts_for_podman(monkeypatch):
    _podman(monkeypatch)
    cfg = {"docker_mount_cwd_to_workspace": True, "host_cwd": "/srv/proj"}
    pod = terminal_tool._resolve_task_host_cwd({**cfg, "env_type": "podman"}, None)
    dock = terminal_tool._resolve_task_host_cwd({**cfg, "env_type": "docker"}, None)
    assert pod == dock == "/srv/proj"


# ── tools/credential_files.py: cache paths ───────────────────────────────────────────────────────

def test_cache_paths_translate_like_docker(monkeypatch):
    import tools.credential_files as cf

    monkeypatch.setattr(cf, "map_cache_path_to_container", lambda p, container_base: f"{container_base}/cache/x")
    monkeypatch.setattr(cf, "_remap_cache_path", lambda *a, **k: "/host/cache/x")
    out = {}
    for backend in ("docker", "podman"):
        monkeypatch.setenv("TERMINAL_ENV", backend)
        out[backend] = (cf.to_agent_visible_cache_path("/host/cache/x"),
                        cf.from_agent_visible_cache_path("/root/.hermes/cache/x"))
    assert out["podman"] == out["docker"] == ("/root/.hermes/cache/x", "/host/cache/x")


# ── tools/file_tools_write_guards.py ─────────────────────────────────────────────────────────────

def test_container_mirror_prefix_for_persistent_podman(monkeypatch):
    from tools import file_tools_write_guards as wg

    monkeypatch.setattr(terminal_tool, "_get_env_config",
                        lambda: {"env_type": "podman", "container_persistent": True})
    assert wg._get_container_mirror_prefix_for_task("nobody-here") == "/root/.hermes"


def test_container_mirror_prefix_for_live_podman_env(monkeypatch):
    from tools import file_tools_write_guards as wg

    env = _named("PodmanEnvironment", _persistent=True)
    monkeypatch.setitem(terminal_tool._active_environments, "mirror-task", env)
    monkeypatch.setattr(terminal_tool, "_resolve_container_task_id", lambda t: "mirror-task")
    assert wg._get_container_mirror_prefix_for_task("mirror-task") == "/root/.hermes"


# ── backend sets: skills / tool results / image cache / connectors / path hints ───────────────────

def test_skills_treat_podman_as_remote():
    from tools.skills_tool_setup import _is_remote_env_backend
    assert _is_remote_env_backend("podman") is True


def test_pruned_archive_published_on_podman(monkeypatch):
    from tools.tool_result_storage import _archive_backend
    monkeypatch.setenv("TERMINAL_ENV", "podman")
    assert _archive_backend() == "podman"


def test_image_cache_base_on_podman(monkeypatch):
    from tools.image_generation_tool import _agent_cache_base_for_env
    monkeypatch.setenv("TERMINAL_ENV", "podman")
    assert _agent_cache_base_for_env(None) == "/root/.hermes"
    assert _agent_cache_base_for_env(_named("PodmanEnvironment")) == "/root/.hermes"


def test_connector_file_input_allowed_on_podman(monkeypatch):
    from tools.connectors.gateway import files
    import tools.file_tools_paths as fp

    monkeypatch.setattr(fp, "_terminal_env_type_for_task", lambda task: "podman")
    monkeypatch.setattr(fp, "_resolve_path_for_task", lambda raw, task: Path("/srv/out.txt"))
    assert files._backend_path("/workspace/out.txt", None) == str(Path("/srv/out.txt"))


def test_path_backend_hint_names_podman(monkeypatch):
    import tools.file_tools_paths as fp

    monkeypatch.setenv("TERMINAL_ENV", "local")
    monkeypatch.setitem(terminal_tool._active_environments, "hint-task", _named("PodmanEnvironment"))
    monkeypatch.setattr(terminal_tool, "_resolve_container_task_id", lambda t: "hint-task")
    assert fp._terminal_env_type_for_task("hint-task") == "podman"


# ── tools/bot_desktop: the screen follows a podman sandbox ────────────────────────────────────────

def test_bot_desktop_places_on_podman_terminal(monkeypatch):
    from tools.bot_desktop import placement

    monkeypatch.setattr(placement, "_terminal_backend", lambda: "podman")
    monkeypatch.setattr(placement, "_setting", lambda: "auto")
    assert placement.resolve().where == placement.TERMINAL


def test_stream_exec_prefix_for_podman():
    from tools.environments import streams
    from tools.environments.podman import PodmanEnvironment

    env = object.__new__(PodmanEnvironment)
    env._container_id, env._docker_exe = "cid1", "/usr/bin/podman"
    assert streams.exec_prefix(env, user="bot", interactive=True) == \
        ["/usr/bin/podman", "exec", "-w", "/", "-i", "-u", "bot", "cid1"]


def test_sandbox_marker_liveness_uses_podman_json(monkeypatch):
    from tools.bot_desktop import sandbox_host

    seen = []

    def fake_run(argv, **kw):
        seen.append(argv)
        return SimpleNamespace(returncode=0, stdout=json.dumps([{"State": {"Running": True}}]))

    monkeypatch.setattr(sandbox_host.subprocess, "run", fake_run)
    sandbox_host._ALIVE_CACHE.pop("pod-c1", None)
    marker = {"backend": "PodmanEnvironment", "container": "pod-c1", "docker": "/usr/bin/podman"}
    assert sandbox_host.marker_sandbox_alive(marker) is True
    assert seen[0][:2] == ["/usr/bin/podman", "inspect"] and "json" in seen[0]


# ── agent/prompt_builder.py ──────────────────────────────────────────────────────────────────────

def test_prompt_describes_podman(monkeypatch):
    from agent import prompt_builder

    monkeypatch.setattr(prompt_builder, "_probe_remote_backend", lambda backend: None)
    assert "rootless Podman container" in prompt_builder._remote_backend_hint("podman")
    assert prompt_builder._BACKEND_IMAGE_KEYS["podman"] == "podman_image"


# ── gateway ──────────────────────────────────────────────────────────────────────────────────────

def test_cwd_placeholder_maps_messaging_cwd_for_podman():
    from gateway.cwd_placeholder import resolve_placeholder_terminal_cwd

    assert resolve_placeholder_terminal_cwd(
        configured_cwd="", terminal_backend="podman", messaging_cwd="/srv/chat",
        docker_mount_cwd_to_workspace=True, home_fallback="/home/u") == "/srv/chat"


def test_gateway_startup_reads_the_podman_mount_flag(monkeypatch):
    from gateway.run_bootstrap import _start_gateway_resolve_terminal_cwd
    import os

    monkeypatch.setenv("TERMINAL_ENV", "podman")
    monkeypatch.setenv("TERMINAL_CWD", "")
    monkeypatch.setenv("MESSAGING_CWD", "/srv/chat")
    monkeypatch.setenv("TERMINAL_PODMAN_MOUNT_CWD_TO_WORKSPACE", "true")
    _start_gateway_resolve_terminal_cwd()
    assert os.environ.get("TERMINAL_CWD") == "/srv/chat"


def test_gateway_media_warning_on_podman(monkeypatch, caplog):
    from gateway.run import GatewayRunner

    monkeypatch.setenv("TERMINAL_ENV", "podman")
    fake = SimpleNamespace(config=SimpleNamespace(get_connected_platforms=lambda: ["telegram"]))
    with caplog.at_level("WARNING"):
        GatewayRunner._warn_if_docker_media_delivery_is_risky(fake)
    assert "output mount" in caplog.text

    caplog.clear()
    monkeypatch.setenv("TERMINAL_PODMAN_VOLUMES", json.dumps(["/home/u/out:/output"]))
    with caplog.at_level("WARNING"):
        GatewayRunner._warn_if_docker_media_delivery_is_risky(fake)
    assert "output mount" not in caplog.text


def test_gateway_media_translation_active_on_podman(monkeypatch, tmp_path):
    from gateway.platforms import base

    monkeypatch.setenv("TERMINAL_ENV", "podman")
    monkeypatch.setenv("TERMINAL_PODMAN_VOLUMES", json.dumps([f"{tmp_path}:/data"]))
    monkeypatch.setenv("TERMINAL_DOCKER_VOLUMES", json.dumps(["/elsewhere:/other"]))
    assert base._docker_env_active() is True
    assert base._parse_docker_volume_mounts() == [(tmp_path.resolve(), Path("/data"))]


def test_media_sandbox_dir_follows_backend(monkeypatch, tmp_path):
    from gateway.platforms.docker_media_paths import sandbox_media_base

    monkeypatch.setenv("TERMINAL_ENV", "podman")
    assert sandbox_media_base().parent.name == "podman"
    monkeypatch.setenv("TERMINAL_ENV", "docker")
    assert sandbox_media_base().parent.name == "docker"


def test_media_sandbox_candidates_read_podman_slots(monkeypatch):
    from gateway.platforms import docker_media_paths as dmp

    _podman(monkeypatch)
    monkeypatch.setenv("TERMINAL_PODMAN_MOUNT_CWD_TO_WORKSPACE", "true")
    monkeypatch.setenv("TERMINAL_PODMAN_SHARED_CONTAINER_KEY", "team")
    assert dmp._cwd_mount_enabled() is True
    assert dmp._docker_sandbox_dir_candidates()[0].startswith("shared")


def test_media_hand_back_stays_docker_only(monkeypatch, tmp_path):
    """The ownership hand-back drives the ``docker`` binary (the Docker product): never under podman."""
    import asyncio
    from gateway.platforms import docker_media_paths as dmp

    monkeypatch.setenv("TERMINAL_ENV", "podman")
    called = []
    monkeypatch.setattr(dmp, "_hand_back_files", lambda paths: called.append(paths))
    monkeypatch.setattr(dmp.os, "access", lambda p, mode: False)
    asyncio.run(dmp.hand_back_unreadable_media([str(tmp_path / "f")]))
    assert called == []


def test_web_fallback_sandbox_under_the_podman_dir(monkeypatch, tmp_path):
    from gateway.platforms import docker_media_paths as dmp
    from hermes_cli import web_server_files as wsf
    import tools.environments.base as envbase

    monkeypatch.setenv("TERMINAL_ENV", "podman")
    monkeypatch.setattr(envbase, "get_sandbox_dir", lambda: tmp_path)
    monkeypatch.setattr(dmp, "_docker_sandbox_dir_candidates", lambda s, w: ["own", "fallback"])
    assert wsf._in_fallback_sandbox(tmp_path / "podman" / "fallback" / "f.txt", "") is True
    assert wsf._in_fallback_sandbox(tmp_path / "docker" / "fallback" / "f.txt", "") is False


# ── hermes_cli/sandbox_image_switch.py ───────────────────────────────────────────────────────────

def test_image_switch_pending_for_podman(tmp_path, monkeypatch):
    import hermes_yaml as yaml
    from hermes_cli import sandbox_image_switch as sw
    from hermes_cli.config_defaults import DEFAULT_SANDBOX_IMAGE, LEGACY_SANDBOX_IMAGE
    from tools.environments import podman_posture
    from tools.environments.podman_args import qualify_image

    home = tmp_path / ".hermes"
    home.mkdir()
    monkeypatch.setenv("HERMES_HOME", str(home))
    for var in ("TERMINAL_PODMAN_IMAGE", "TERMINAL_DOCKER_IMAGE", "TERMINAL_DOCKER_IMAGE_PINNED"):
        monkeypatch.delenv(var, raising=False)
    (home / "config.yaml").write_text(yaml.safe_dump({"terminal": {"backend": "podman"}}), encoding="utf-8")
    rows = [{"Names": ["hermes-abc"], "Image": qualify_image(LEGACY_SANDBOX_IMAGE)},
            {"Names": ["hermes-def"], "Image": qualify_image(DEFAULT_SANDBOX_IMAGE)}]
    seen = []

    def fake_query_json(argv, **kw):
        seen.append(argv)
        return rows

    from tools.environments import podman as podman_env
    monkeypatch.setattr(podman_posture, "find_podman", lambda: "/usr/bin/podman")
    monkeypatch.setattr(podman_env, "_query_json", fake_query_json)
    p = sw.pending()
    assert p is not None
    assert (p.current_image, p.containers, p.config_key) == (
        qualify_image(LEGACY_SANDBOX_IMAGE), ["hermes-abc"], "podman_image")
    assert "label=hermes-podman=1" in seen[0] and "json" in seen[0]


# ── fix round 1 ──────────────────────────────────────────────────────────────────────────────────

def _shared_guess_env(monkeypatch, tmp_path):
    _podman(monkeypatch)
    monkeypatch.setenv("TERMINAL_CWD", str(tmp_path))
    monkeypatch.setenv("TERMINAL_PODMAN_MOUNT_CWD_TO_WORKSPACE", "true")


def test_shared_cwd_mount_guess_reads_the_podman_key(monkeypatch, tmp_path):
    from gateway.platforms import docker_media_paths as dmp

    _shared_guess_env(monkeypatch, tmp_path)
    monkeypatch.setenv("TERMINAL_PODMAN_SHARED_CONTAINER_KEY", "team")
    assert dmp._shared_cwd_mount_guess("0123456789abcdef") == [tmp_path.resolve()]
    assert dmp._default_docker_workspace_host_roots("", "0123456789abcdef")[0] == tmp_path.resolve()


def test_shared_cwd_mount_guess_ignores_the_docker_key_under_podman(monkeypatch, tmp_path):
    from gateway.platforms import docker_media_paths as dmp

    _shared_guess_env(monkeypatch, tmp_path)
    monkeypatch.setenv("TERMINAL_DOCKER_SHARED_CONTAINER_KEY", "team")
    assert dmp._shared_cwd_mount_guess("0123456789abcdef") == []


def test_gateway_bridges_podman_yaml_keys(monkeypatch):
    import os
    from gateway.run import _bridge_terminal_config_to_env
    from hermes_cli.config import TERMINAL_CONFIG_ENV_MAP

    podman_keys = {k: v for k, v in TERMINAL_CONFIG_ENV_MAP.items() if k.startswith("podman_")}
    assert len(podman_keys) == 13
    for var in ("TERMINAL_ENV", *podman_keys.values()):
        monkeypatch.setenv(var, "stale")  # registers restoration of whatever the bridge writes
    _bridge_terminal_config_to_env({"backend": "podman", "podman_volumes": ["/a:/b"], "podman_userns": "keep-id",
                                    "podman_strict": True, "podman_image": "ghcr.io/me/img:1"})
    assert os.environ["TERMINAL_ENV"] == "podman"
    assert json.loads(os.environ["TERMINAL_PODMAN_VOLUMES"]) == ["/a:/b"]
    assert os.environ["TERMINAL_PODMAN_USERNS"] == "keep-id"
    assert os.environ["TERMINAL_PODMAN_STRICT"] == "True"
    assert os.environ["TERMINAL_PODMAN_IMAGE"] == "ghcr.io/me/img:1"


@pytest.fixture
def _home(tmp_path, monkeypatch):
    import hermes_yaml as yaml

    h = tmp_path / ".hermes"
    h.mkdir()
    monkeypatch.setenv("HERMES_HOME", str(h))
    for var in ("TERMINAL_PODMAN_IMAGE", "TERMINAL_PODMAN_IMAGE_PINNED",
                "TERMINAL_DOCKER_IMAGE", "TERMINAL_DOCKER_IMAGE_PINNED"):
        monkeypatch.delenv(var, raising=False)

    def write(terminal: dict, home=h):
        (home / "config.yaml").write_text(yaml.safe_dump({"terminal": terminal}), encoding="utf-8")
    return h, write


def test_bridge_derives_the_podman_pin_like_docker(_home):
    from hermes_cli.config import apply_terminal_config_to_env

    _h, write = _home
    write({"backend": "podman"})
    env = apply_terminal_config_to_env(env={})
    assert env["TERMINAL_PODMAN_IMAGE_PINNED"] == "0"
    write({"backend": "podman", "podman_image": "ghcr.io/me/img:1"})
    env = apply_terminal_config_to_env(env={}, override=True)
    assert env["TERMINAL_PODMAN_IMAGE_PINNED"] == "1"
    assert env["TERMINAL_DOCKER_IMAGE_PINNED"] == "0", "a podman pin is not a docker pin"
    env = apply_terminal_config_to_env(env={"TERMINAL_PODMAN_IMAGE": "ghcr.io/op/x:2"})
    assert env["TERMINAL_PODMAN_IMAGE_PINNED"] == "1", "an operator's env var is their choice"


def test_profile_scope_derives_the_podman_pin(_home, tmp_path):
    from tools.terminal_scope import build_profile_terminal_scope

    home, write = _home
    write({"backend": "podman"})
    scope = build_profile_terminal_scope(home, env_overlay={"TERMINAL_PODMAN_IMAGE_PINNED": "1"})
    assert scope["TERMINAL_PODMAN_IMAGE_PINNED"] == "0", "the launch overlay's verdict is never inherited"
    write({"backend": "podman", "podman_image": "ghcr.io/me/img:1"})
    scope = build_profile_terminal_scope(home)
    assert (scope["TERMINAL_PODMAN_IMAGE_PINNED"], scope["TERMINAL_DOCKER_IMAGE_PINNED"]) == ("1", "0")


def test_env_config_reads_the_podman_pin_for_podman(monkeypatch):
    _podman(monkeypatch)
    monkeypatch.setenv("TERMINAL_PODMAN_IMAGE_PINNED", "1")
    monkeypatch.setenv("TERMINAL_DOCKER_IMAGE_PINNED", "0")
    assert terminal_tool._get_env_config()["docker_image_pinned"] is True
    monkeypatch.setenv("TERMINAL_PODMAN_IMAGE_PINNED", "0")
    monkeypatch.setenv("TERMINAL_DOCKER_IMAGE_PINNED", "1")
    assert terminal_tool._get_env_config()["docker_image_pinned"] is False


def test_podman_builder_receives_the_pin(monkeypatch):
    import tools.terminal_tool_backends as backends

    seen = {}
    monkeypatch.setattr("tools.environments.podman.PodmanEnvironment", lambda **kw: seen.update(kw) or SimpleNamespace())
    monkeypatch.setattr(terminal_tool, "_maybe_reap_podman_orphans", lambda cc: None)
    backends._build_podman_env(image="img", cwd="/root", timeout=10, cc={"docker_image_pinned": True},
                               task_id="default", host_cwd=None)
    assert seen["image_pinned"] is True


@pytest.mark.parametrize(("image_key", "image_var"),
                         [("docker_image", "TERMINAL_DOCKER_IMAGE"), ("podman_image", "TERMINAL_PODMAN_IMAGE")])
def test_image_pinned_verdict_per_runtime(_home, monkeypatch, image_key, image_var):
    from hermes_cli import sandbox_image_switch as sw

    _h, write = _home
    write({"backend": "podman"})
    assert sw._image_pinned({image_key: "dflt"}, image_key) is False
    monkeypatch.setenv(image_var, "ghcr.io/op/x:2")
    assert sw._image_pinned({image_key: "dflt"}, image_key) is True
    monkeypatch.delenv(image_var)
    write({"backend": "podman", image_key: "ghcr.io/me/img:1"})
    assert sw._image_pinned({image_key: "dflt"}, image_key) is True


def test_podman_volume_mount_keeps_dangerous_command_guards_end_to_end(monkeypatch):
    _podman(monkeypatch)
    monkeypatch.setenv("TERMINAL_PODMAN_VOLUMES", '["/home/u:/w"]')
    cfg = terminal_tool._get_env_config()
    assert cfg["env_type"] == "podman"
    assert _docker_has_host_access(cfg) is True
    assert _should_skip_container_guards("podman", True) is False


def test_cli_bridges_podman_yaml_keys():
    from hermes_cli.cli_config_load import _TERMINAL_ENV_MAPPINGS
    from hermes_cli.config import TERMINAL_CONFIG_ENV_MAP

    podman = {k: v for k, v in TERMINAL_CONFIG_ENV_MAP.items() if k.startswith("podman_")}
    assert {k: _TERMINAL_ENV_MAPPINGS.get(k) for k in podman} == podman


# ── gateway/session_policy.py: terminal_uses_host_cwd ────────────────────────────────────────────

@pytest.mark.parametrize("mount", ["true", "false"])
def test_terminal_uses_host_cwd_reads_the_podman_mount_flag(mount):
    from gateway.session_policy import terminal_uses_host_cwd
    pod = terminal_uses_host_cwd({"TERMINAL_ENV": "podman", "TERMINAL_PODMAN_MOUNT_CWD_TO_WORKSPACE": mount})
    dock = terminal_uses_host_cwd({"TERMINAL_ENV": "docker", "TERMINAL_DOCKER_MOUNT_CWD_TO_WORKSPACE": mount})
    assert pod == dock == (mount == "true")
    # The Docker slot never drives the podman backend.
    assert terminal_uses_host_cwd({"TERMINAL_ENV": "podman", "TERMINAL_DOCKER_MOUNT_CWD_TO_WORKSPACE": "true"}) is False


# ── tools/terminal_scope.py: _resolve_scope_cwd_placeholder ──────────────────────────────────────

@pytest.mark.parametrize(("backend", "var"), [("docker", "TERMINAL_DOCKER_MOUNT_CWD_TO_WORKSPACE"),
                                              ("podman", "TERMINAL_PODMAN_MOUNT_CWD_TO_WORKSPACE")])
def test_scope_cwd_placeholder_reads_the_runtime_mount_flag(monkeypatch, backend, var):
    import gateway.cwd_placeholder as placeholder
    from tools.terminal_scope import _resolve_scope_cwd_placeholder
    seen = {}

    def _capture(**kwargs):
        seen.update(kwargs)

    monkeypatch.setattr(placeholder, "resolve_placeholder_terminal_cwd", _capture)
    scope = {"TERMINAL_ENV": backend, var: "true"}
    _resolve_scope_cwd_placeholder(scope)
    assert seen["terminal_backend"] == backend and seen["docker_mount_cwd_to_workspace"] is True
    assert "TERMINAL_CWD" not in scope


# ── tui_gateway/session_workdir.py: unmounted container cwd registration ─────────────────────────

@pytest.mark.parametrize("backend", ["docker", "podman"])
@pytest.mark.parametrize("mount", [False, True])
def test_unmounted_container_registers_host_workspace(monkeypatch, tmp_path, backend, mount):
    from tui_gateway import server
    monkeypatch.setenv("TERMINAL_ENV", backend)
    monkeypatch.setenv(f"TERMINAL_{backend.upper()}_MOUNT_CWD_TO_WORKSPACE", str(mount).lower())
    workspace = tmp_path / "host-project"
    workspace.mkdir()
    session = {"session_key": f"wd-{backend}", "cwd": str(workspace), "explicit_cwd": True, "source": "desktop"}
    vars(server)["_register_session_cwd"](session)
    try:
        overrides = terminal_tool.resolve_task_overrides(f"wd-{backend}")
    finally:
        terminal_tool.clear_task_env_overrides(f"wd-{backend}")
    assert overrides == (
        {"cwd": str(workspace), "cwd_source": "session"} if mount
        else {"cwd": "", "cwd_source": "process", "host_workspace": str(workspace)})


# ── hermes_cli/doctor_tools.py: in-container check keeps an explicit podman backend ──────────────

@pytest.mark.parametrize("backend", ["docker", "podman", "local"])
def test_doctor_in_container_keeps_explicit_container_backend(monkeypatch, backend):
    import hermes_constants
    from hermes_cli import doctor_tools
    seen = {}
    monkeypatch.setenv("TERMINAL_ENV", backend)
    monkeypatch.setattr(hermes_constants, "is_container", lambda: True)
    monkeypatch.setattr(doctor_tools, "_check_docker_backend", lambda env, *_: seen.setdefault("docker", env))
    monkeypatch.setattr(doctor_tools, "_check_podman_backend", lambda env, *_: seen.setdefault("podman", env))
    doctor_tools._check_terminal_backend(False)
    expected = backend if backend in ("docker", "podman") else "local"
    assert seen == {"docker": expected, "podman": expected}
