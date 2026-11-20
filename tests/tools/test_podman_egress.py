"""Egress (iron-proxy) plumbing for the Podman backend, and the shared resolution
extracted from the Docker path (whose output must stay byte-identical)."""

import json
import logging
from dataclasses import replace
from pathlib import Path

import pytest

import hermes_cli.config as hermes_config
from agent.proxy_sources import iron_proxy as ip
from tools.environments.docker_egress import (
    ResolvedEgress,
    _egress_proxy_args_for_docker,
    proxy_env,
    resolve_egress,
)
from tools.environments.podman_egress import egress_args_for_podman, egress_enforce_on_podman
from tools.environments.podman_posture import parse_posture

FIX = Path(__file__).parent / "fixtures"
_CA_IN_CONTAINER = "/etc/ssl/certs/hermes-egress-ca.crt"

_MAPPINGS = [
    ip.TokenMapping(
        proxy_token="hermes-proxy-openai-tok", real_env_name="OPENAI_API_KEY",
        upstream_hosts=("api.openai.com",)),
    ip.TokenMapping(
        proxy_token="hermes-proxy-gemini-tok", real_env_name="GEMINI_API_KEY",
        upstream_hosts=("generativelanguage.googleapis.com",),
        match_headers=("x-goog-api-key",), alias_env_names=("GOOGLE_API_KEY",)),
]


# Recorded by running the PRE-refactor ``_egress_proxy_args_for_docker()`` against the
# ``golden_proxy`` fixture below (tunnel_port 8443). ``{ca}`` is the fixture's CA path.
# This is a regression pin: do not regenerate it from the current implementation.
_GOLDEN_DOCKER_VOLUME_ARGS = ["-v", "{ca}:/etc/ssl/certs/hermes-egress-ca.crt:ro"]
_GOLDEN_DOCKER_ENV = {
    "HTTPS_PROXY": "http://host.docker.internal:8443",
    "https_proxy": "http://host.docker.internal:8443",
    "HTTP_PROXY": "http://host.docker.internal:8444",
    "http_proxy": "http://host.docker.internal:8444",
    "NO_PROXY": "127.0.0.1,localhost,::1",
    "no_proxy": "127.0.0.1,localhost,::1",
    "REQUESTS_CA_BUNDLE": "/etc/ssl/certs/hermes-egress-ca.crt",
    "SSL_CERT_FILE": "/etc/ssl/certs/hermes-egress-ca.crt",
    "CURL_CA_BUNDLE": "/etc/ssl/certs/hermes-egress-ca.crt",
    "NODE_EXTRA_CA_CERTS": "/etc/ssl/certs/hermes-egress-ca.crt",
    "HERMES_EGRESS_PROXY": "1",
    "_HERMES_EGRESS_NODE_OPTIONS_APPEND": "--use-openssl-ca",
    "OPENAI_API_KEY": "hermes-proxy-openai-tok",
    "HERMES_PROXY_TOKEN_OPENAI_API_KEY": "hermes-proxy-openai-tok",
    "GEMINI_API_KEY": "hermes-proxy-gemini-tok",
    "HERMES_PROXY_TOKEN_GEMINI_API_KEY": "hermes-proxy-gemini-tok",
    "GOOGLE_API_KEY": "hermes-proxy-gemini-tok",
}
_GOLDEN_DOCKER_ENV_KEY_ORDER = list(_GOLDEN_DOCKER_ENV)
_GOLDEN_DOCKER_HOST_ARGS = ["--add-host", "host.docker.internal:host-gateway"]


def _posture(name, *, pasta):
    return parse_posture(json.loads((FIX / name).read_text()), pasta_available=pasta)


@pytest.fixture
def posture_ok():
    return _posture("podman_info_6_2_rootless.json", pasta=True)


@pytest.fixture
def posture_selinux():
    return _posture("podman_info_selinux.json", pasta=True)


@pytest.fixture
def posture_slirp():
    return _posture("podman_info_4_9_rootless.json", pasta=False)


@pytest.fixture
def listen():
    return ("127.0.0.1", 8443)


@pytest.fixture
def enforce_on_podman():
    return True


@pytest.fixture
def enforce_on_docker():
    return True


@pytest.fixture
def proxy_config(enforce_on_podman, enforce_on_docker, monkeypatch):
    cfg = {"proxy": {"enabled": True, "enforce_on_docker": enforce_on_docker,
                     "enforce_on_podman": enforce_on_podman}}
    monkeypatch.setattr(hermes_config, "load_config", lambda: cfg)
    return cfg


@pytest.fixture
def fake_status(tmp_path, listen):
    ca = tmp_path / "ca.crt"
    ca.write_text("fake-ca")
    cfg = tmp_path / "proxy.yaml"
    cfg.write_text("proxy: {}\n")
    return ip.ProxyStatus(enabled=True, config_path=cfg, ca_cert_path=ca, pid=4242,
                          listening=True, tunnel_port=listen[1])


@pytest.fixture
def golden_proxy(fake_status, listen, proxy_config, monkeypatch):
    """Fake running iron-proxy: status, mappings, listen address and hermes config."""
    monkeypatch.setattr(ip, "get_status", lambda: fake_status)
    monkeypatch.setattr(ip, "load_mappings", lambda: list(_MAPPINGS))
    monkeypatch.setattr(ip, "_probe_target", lambda: listen)
    return fake_status


@pytest.fixture
def proxy_disabled(monkeypatch):
    monkeypatch.setattr(hermes_config, "load_config", lambda: {"proxy": {"enabled": False}})

    def _must_not_probe():
        raise AssertionError("proxy disabled: iron-proxy must not be probed")

    monkeypatch.setattr(ip, "get_status", _must_not_probe)


# --------------------------------------------------------------------------- Docker pin


def test_docker_egress_output_unchanged(golden_proxy):
    ca = str(golden_proxy.ca_cert_path)
    vols, env, host = _egress_proxy_args_for_docker()
    assert vols == [a.replace("{ca}", ca) for a in _GOLDEN_DOCKER_VOLUME_ARGS]
    assert env == _GOLDEN_DOCKER_ENV
    assert list(env) == _GOLDEN_DOCKER_ENV_KEY_ORDER
    assert host == _GOLDEN_DOCKER_HOST_ARGS


def test_docker_egress_ignores_listen_host(golden_proxy, monkeypatch):
    # The Docker path always targets host.docker.internal, whatever the bind address.
    monkeypatch.setattr(ip, "_probe_target", lambda: ("172.17.0.1", 8443))
    assert _egress_proxy_args_for_docker()[0:3:2] == (
        [a.replace("{ca}", str(golden_proxy.ca_cert_path)) for a in _GOLDEN_DOCKER_VOLUME_ARGS],
        _GOLDEN_DOCKER_HOST_ARGS)


@pytest.mark.parametrize("enforce_on_docker", [False])
def test_docker_not_running_warning_text_unchanged(golden_proxy, caplog):
    golden_proxy.pid = None
    with caplog.at_level(logging.WARNING, logger="tools.environments.docker"):
        assert _egress_proxy_args_for_docker() == ([], {}, [])
    assert caplog.messages == [
        "iron-proxy is enabled but not running on port 8443. Start it with `hermes egress start`."
        " — continuing without proxy (enforce_on_docker=false)."]


def test_docker_not_running_raises_unchanged(golden_proxy):
    golden_proxy.listening = False
    with pytest.raises(RuntimeError) as exc:
        _egress_proxy_args_for_docker()
    assert str(exc.value) == (
        "iron-proxy is enabled but not running on port 8443. Start it with `hermes egress start`.")


def test_docker_empty_mappings_raises_unchanged(golden_proxy, monkeypatch):
    monkeypatch.setattr(ip, "load_mappings", list)
    with pytest.raises(RuntimeError) as exc:
        _egress_proxy_args_for_docker()
    assert str(exc.value) == (
        "iron-proxy is configured but mappings.json is empty or corrupt.  Re-run "
        "`hermes egress setup` to mint provider tokens before starting a sandbox.")


def test_docker_proxy_disabled_returns_empty(proxy_disabled):
    assert _egress_proxy_args_for_docker() == ([], {}, [])


# --------------------------------------------------------------------------- shared resolution


def test_resolve_egress_returns_resolved_state(golden_proxy):
    r = resolve_egress("enforce_on_podman")
    assert r == ResolvedEgress(
        ca_cert_path=golden_proxy.ca_cert_path, tunnel_port=8443, listen_host="127.0.0.1",
        token_env={
            "OPENAI_API_KEY": "hermes-proxy-openai-tok",
            "HERMES_PROXY_TOKEN_OPENAI_API_KEY": "hermes-proxy-openai-tok",
            "GEMINI_API_KEY": "hermes-proxy-gemini-tok",
            "HERMES_PROXY_TOKEN_GEMINI_API_KEY": "hermes-proxy-gemini-tok",
            "GOOGLE_API_KEY": "hermes-proxy-gemini-tok"})


@pytest.mark.parametrize("enforce_on_podman", [False])
def test_resolve_egress_warning_names_the_key(golden_proxy, caplog):
    golden_proxy.ca_cert_path.unlink()
    with caplog.at_level(logging.WARNING):
        assert resolve_egress("enforce_on_podman") is None
    assert len(caplog.messages) == 1
    assert caplog.messages[0].endswith("— continuing without proxy (enforce_on_podman=false).")


def test_resolve_egress_reads_the_named_key(golden_proxy, proxy_config):
    golden_proxy.pid = None
    proxy_config["proxy"]["enforce_on_docker"] = False
    with pytest.raises(RuntimeError, match="not running"):
        resolve_egress("enforce_on_podman")
    assert resolve_egress("enforce_on_docker") is None


def test_proxy_env_brackets_ipv6_host():
    env = proxy_env("::1", 8443, {})
    assert env["HTTPS_PROXY"] == "http://[::1]:8443" and env["http_proxy"] == "http://[::1]:8444"


# --------------------------------------------------------------------------- Podman


def test_loopback_listen_uses_pasta_port_forward_only(golden_proxy, posture_ok):
    vols, env, net = egress_args_for_podman(posture_ok, network=True)
    assert net == ["--network=pasta:-T,8443,-T,8444"]
    assert env["HTTPS_PROXY"] == "http://127.0.0.1:8443" and env["HTTP_PROXY"] == "http://127.0.0.1:8444"
    assert env["https_proxy"] == "http://127.0.0.1:8443" and env["http_proxy"] == "http://127.0.0.1:8444"
    assert vols == ["-v", f"{golden_proxy.ca_cert_path}:{_CA_IN_CONTAINER}:ro"]


def test_podman_env_carries_proxy_tokens_not_real_keys(golden_proxy, posture_ok, monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "sk-real-secret")
    _, env, _ = egress_args_for_podman(posture_ok, network=True)
    assert env["OPENAI_API_KEY"] == "hermes-proxy-openai-tok"
    assert env["GOOGLE_API_KEY"] == "hermes-proxy-gemini-tok"
    assert "sk-real-secret" not in env.values()
    assert env["SSL_CERT_FILE"] == _CA_IN_CONTAINER
    assert env["_HERMES_EGRESS_NODE_OPTIONS_APPEND"] == "--use-openssl-ca"


@pytest.mark.parametrize("listen", [("::1", 9000), ("[::1]", 9000), ("localhost", 9000)])
def test_other_loopback_spellings_use_port_forward(golden_proxy, posture_ok, listen):
    _, env, net = egress_args_for_podman(posture_ok, network=True)
    assert net == ["--network=pasta:-T,9000,-T,9001"]
    assert env["HTTPS_PROXY"] in ("http://[::1]:9000", "http://127.0.0.1:9000")


@pytest.mark.parametrize("listen", [("172.17.0.1", 8443)])
def test_private_ip_listen_targets_ip_directly(golden_proxy, posture_ok, listen):
    _, env, net = egress_args_for_podman(posture_ok, network=True)
    assert net == ["--network=pasta"] and env["HTTPS_PROXY"] == "http://172.17.0.1:8443"
    assert env["HTTP_PROXY"] == "http://172.17.0.1:8444"


@pytest.mark.parametrize("listen", [
    ("0.0.0.0", 8443), ("::", 8443), ("8.8.8.8", 8443), ("2001:4860::8888", 8443),
    ("169.254.1.1", 8443), ("224.0.0.1", 8443), ("proxy.example.com", 8443)])
def test_unsafe_listen_refused_when_enforced(golden_proxy, posture_ok, listen):
    with pytest.raises(RuntimeError, match="enforce_on_podman"):
        egress_args_for_podman(posture_ok, network=True)


@pytest.mark.parametrize("listen", [("0.0.0.0", 8443), ("8.8.8.8", 8443)])
@pytest.mark.parametrize("enforce_on_podman", [False])
def test_unsafe_listen_warns_when_not_enforced(golden_proxy, posture_ok, listen, caplog):
    with caplog.at_level(logging.WARNING):
        assert egress_args_for_podman(posture_ok, network=True) == ([], {}, [])
    assert any("enforce_on_podman=false" in m for m in caplog.messages)


def test_no_pasta_refuses_when_enforced(golden_proxy, posture_slirp):
    with pytest.raises(RuntimeError, match="enforce_on_podman"):
        egress_args_for_podman(posture_slirp, network=True)


@pytest.mark.parametrize("enforce_on_podman", [False])
def test_no_pasta_warns_when_not_enforced(golden_proxy, posture_slirp, caplog):
    with caplog.at_level(logging.WARNING):
        assert egress_args_for_podman(posture_slirp, network=True) == ([], {}, [])
    assert any("pasta" in m and "enforce_on_podman=false" in m for m in caplog.messages)


@pytest.mark.parametrize("enforce_on_podman", [False])
def test_never_allow_host_loopback(golden_proxy, posture_slirp):
    _vols, env, net = egress_args_for_podman(posture_slirp, network=True)
    # (tmp CA path is excluded: pytest names it after this test.)
    flat = " ".join(net + [v for k, v in env.items() if "proxy" in k.lower()])
    assert "allow_host_loopback" not in flat and "slirp4netns" not in flat


@pytest.mark.parametrize("listen", [("127.0.0.1", 8443), ("172.17.0.1", 8443)])
def test_never_allow_host_loopback_with_pasta(golden_proxy, posture_ok, listen):
    _vols, env, net = egress_args_for_podman(posture_ok, network=True)
    # (tmp CA path is excluded: pytest names it after this test.)
    flat = " ".join(net + [v for k, v in env.items() if "proxy" in k.lower()])
    assert "allow_host_loopback" not in flat and "slirp4netns" not in flat


def test_air_gapped_skips_egress(golden_proxy, posture_ok, monkeypatch):
    monkeypatch.setattr(ip, "get_status", lambda: pytest.fail("network=False must not probe"))
    assert egress_args_for_podman(posture_ok, network=False) == ([], {}, [])


def test_proxy_disabled_returns_empty(proxy_disabled, posture_ok):
    assert egress_args_for_podman(posture_ok, network=True) == ([], {}, [])


def test_half_configured_proxy_refuses_on_podman(golden_proxy, posture_ok):
    golden_proxy.listening = False
    with pytest.raises(RuntimeError, match="not running"):
        egress_args_for_podman(posture_ok, network=True)


def test_selinux_labels_ca_mount_shared(golden_proxy, posture_selinux):
    vols, _, _ = egress_args_for_podman(posture_selinux, network=True)
    assert vols == ["-v", f"{golden_proxy.ca_cert_path}:{_CA_IN_CONTAINER}:ro,z"]


def test_rootful_pasta_posture_is_not_special_cased(golden_proxy, posture_ok):
    # Posture rootless flag does not change the network plumbing.
    _, _, net = egress_args_for_podman(replace(posture_ok, rootless=False), network=True)
    assert net == ["--network=pasta:-T,8443,-T,8444"]


@pytest.mark.parametrize("cfg,expected", [
    ({"proxy": {"enforce_on_podman": False}}, False),
    ({"proxy": {"enforce_on_podman": True}}, True),
    ({"proxy": {}}, True),
    ({"proxy": 5}, True),
    ({}, True)])
def test_egress_enforce_on_podman(monkeypatch, cfg, expected):
    monkeypatch.setattr(hermes_config, "load_config", lambda: cfg)
    assert egress_enforce_on_podman() is expected


def test_egress_enforce_on_podman_fails_safe(monkeypatch):
    def _boom():
        raise ValueError("malformed config.yaml")

    monkeypatch.setattr(hermes_config, "load_config", _boom)
    assert egress_enforce_on_podman() is True
