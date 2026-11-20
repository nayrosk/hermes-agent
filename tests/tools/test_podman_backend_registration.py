"""Registration of the podman terminal backend (dispatch, requirements, reaper, atexit)."""

from unittest.mock import patch

import pytest

from tools import terminal_tool, terminal_tool_backends as backends
from tools.environments import podman_posture
from tools.environments.podman import PodmanEnvironment
from tools.terminal_tool_backends import _create_environment


class Recorder:
    def __init__(self, **kwargs):
        self.kwargs = kwargs


_REAL_MAYBE_REAP_PODMAN = terminal_tool._maybe_reap_podman_orphans


@pytest.fixture(autouse=True)
def _no_reaper(monkeypatch):
    monkeypatch.setattr(terminal_tool, "_maybe_reap_podman_orphans", lambda cc: None)


def test_create_environment_podman(monkeypatch):
    monkeypatch.setattr("tools.environments.podman.PodmanEnvironment", Recorder)
    env = _create_environment("podman", image="img", cwd="/root", timeout=60,
                              container_config={"podman_userns": "auto", "podman_strict": True})
    assert isinstance(env, Recorder)
    assert env.kwargs["userns"] == "auto" and env.kwargs["strict"] is True
    assert env.kwargs["image"] == "img"
    assert "run_as_host_user" not in env.kwargs and "snap_compat" not in env.kwargs


def test_container_config_carries_podman_keys():
    cc = backends._container_config_from_config({"podman_userns": "keep-id", "podman_strict": True})
    assert cc["podman_userns"] == "keep-id" and cc["podman_strict"] is True
    assert backends._container_config_from_config({})["podman_userns"] == ""


def test_podman_session_isolation(monkeypatch):
    monkeypatch.setattr("tools.environments.podman.PodmanEnvironment", Recorder)
    monkeypatch.setattr(terminal_tool, "_docker_session_isolation_enabled", lambda: True)
    env = _create_environment("podman", image="img", cwd="/root", timeout=60,
                              task_id="sess-1", container_config={})
    assert env.kwargs["persist_across_processes"] is False
    assert env._session_scoped is True


def test_requirements_missing_binary(monkeypatch):
    monkeypatch.setattr(podman_posture, "find_podman", lambda: None)
    assert backends._REQUIREMENT_CHECKERS["podman"]({}) is False
    assert "Podman is not installed" in terminal_tool.terminal_backend_unavailable_reason()


def test_requirements_probe_failed(monkeypatch):
    monkeypatch.setattr(podman_posture, "find_podman", lambda: "/usr/bin/podman")

    class R:
        returncode = 125

    monkeypatch.setattr(backends.subprocess, "run", lambda *a, **k: R())
    assert backends._REQUIREMENT_CHECKERS["podman"]({}) is False
    assert "Podman is installed but not reachable" in terminal_tool.terminal_backend_unavailable_reason()


def test_builtin_name_and_remote():
    from agent.terminal_env_registry import BUILTIN_BACKEND_NAMES
    from tools import env_probe
    assert "podman" in BUILTIN_BACKEND_NAMES
    assert "podman" in env_probe._REMOTE_BACKENDS


def test_docker_reaper_never_lists_podman_containers():
    from tools.environments import docker
    seen = []

    def fake_query(argv, **kw):
        seen.append(argv)

    with patch.object(docker, "_docker_query", fake_query):
        docker.reap_orphan_containers(max_age_seconds=600, profile_filter="default",
                                      docker_exe="/usr/bin/podman")
    assert "label=hermes-agent=1" in seen[0]
    assert not any("hermes-podman" in a for a in seen[0])


def test_podman_reaper_gates(monkeypatch):
    # The real gate (the autouse fixture stubs it); the once-per-process flag is restored by
    # monkeypatch even when an assertion fails.
    monkeypatch.setattr(terminal_tool, "_maybe_reap_podman_orphans", _REAL_MAYBE_REAP_PODMAN)
    monkeypatch.setattr(terminal_tool, "_podman_orphan_reaper_ran", False)
    calls = []
    monkeypatch.setattr("tools.environments.podman.reap_podman_orphans",
                        lambda **kw: calls.append(kw) or 0)
    terminal_tool._maybe_reap_podman_orphans({"docker_orphan_reaper": False})
    assert calls == []
    terminal_tool._maybe_reap_podman_orphans({"docker_orphan_reaper": True})
    terminal_tool._maybe_reap_podman_orphans({"docker_orphan_reaper": True})
    assert len(calls) == 1 and calls[0]["max_age_seconds"] >= 120


def test_atexit_drains_podman_teardowns(monkeypatch):
    called = []
    monkeypatch.setattr(PodmanEnvironment, "wait_for_all_teardowns",
                        staticmethod(lambda timeout: called.append(timeout) or True))
    terminal_tool._atexit_cleanup()
    assert called == [15.0]
