import pytest

from hermes_cli.config import TERMINAL_CONFIG_ENV_MAP
from hermes_cli.config_defaults import DEFAULT_CONFIG, DEFAULT_SANDBOX_IMAGE
from tools.terminal_tool import _get_env_config
from tools.terminal_tool_config import _CONTAINER_BACKENDS, is_docker_like_backend


def test_podman_is_container_and_docker_like():
    assert "podman" in _CONTAINER_BACKENDS
    assert is_docker_like_backend("podman") and is_docker_like_backend("docker")
    assert not is_docker_like_backend("modal") and not is_docker_like_backend(None)


def test_podman_yaml_keys_bridge_to_env():
    assert TERMINAL_CONFIG_ENV_MAP["podman_volumes"] == "TERMINAL_PODMAN_VOLUMES"
    assert TERMINAL_CONFIG_ENV_MAP["podman_strict"] == "TERMINAL_PODMAN_STRICT"


def test_get_env_config_podman_fills_container_slots(monkeypatch):
    monkeypatch.setenv("TERMINAL_ENV", "podman")
    monkeypatch.setenv("TERMINAL_PODMAN_VOLUMES", '["/srv/data:/data"]')
    monkeypatch.setenv("TERMINAL_PODMAN_USERNS", "keep-id")
    monkeypatch.setenv("TERMINAL_DOCKER_VOLUMES", '["/ignored:/x"]')
    cfg = _get_env_config()
    assert cfg["docker_volumes"] == ["/srv/data:/data"]
    assert cfg["podman_userns"] == "keep-id" and cfg["podman_strict"] is False
    assert cfg["podman_image"] == DEFAULT_SANDBOX_IMAGE


def test_get_env_config_docker_unchanged(monkeypatch):
    monkeypatch.setenv("TERMINAL_ENV", "docker")
    monkeypatch.setenv("TERMINAL_PODMAN_VOLUMES", '["/ignored:/x"]')
    monkeypatch.setenv("TERMINAL_DOCKER_VOLUMES", '["/a:/b"]')
    assert _get_env_config()["docker_volumes"] == ["/a:/b"]


def test_enforce_on_podman_default_true():
    assert DEFAULT_CONFIG["proxy"]["enforce_on_podman"] is True


def test_invalid_podman_userns_rejected(monkeypatch):
    monkeypatch.setenv("TERMINAL_ENV", "podman")
    monkeypatch.setenv("TERMINAL_PODMAN_USERNS", "host")
    with pytest.raises(ValueError, match="podman_userns"):
        _get_env_config()
