import json
import logging
from dataclasses import replace
from pathlib import Path

import pytest

from tools.environments.base import EnvironmentConnectionError

from tools.environments.podman_posture import (
    PodmanPostureError,
    cgroup_limits_supported,
    enforce_posture,
    find_podman,
    parse_posture,
    probe_posture,
    _posture_cache,
    posture_warnings,
)

FIX = Path(__file__).parent / "fixtures"


def _load(name):
    info = json.loads((FIX / name).read_text())
    return parse_posture(info, pasta_available="4_9" not in name)


def test_rootless_6_2_has_no_warnings():
    p = _load("podman_info_6_2_rootless.json")
    assert p.network_cmd == "pasta" and p.pasta_available and p.version == "6.2.0"
    assert posture_warnings(p) == []


def test_4_9_parses_and_reports_slirp_no_pasta():
    p = _load("podman_info_4_9_rootless.json")
    assert p.rootless and p.network_cmd == "slirp4netns" and not p.pasta_available


def test_selinux_detected():
    assert _load("podman_info_selinux.json").selinux
    assert not _load("podman_info_6_2_rootless.json").selinux


def test_rootful_warns_real_root():
    (w,) = posture_warnings(_load("podman_info_rootful.json"))
    assert "rootful" in w and "real root" in w


def test_cgroup_v1_warns_limits_lost():
    p = _load("podman_info_cgroup_v1.json")
    assert not cgroup_limits_supported(p)
    assert any("CPU/memory/PID limits" in w for w in posture_warnings(p))


def test_cgroup_v2_supported():
    assert cgroup_limits_supported(_load("podman_info_6_2_rootless.json"))


def test_split_adjacent_subuid_extents_warn_with_merge_fix():
    ws = posture_warnings(_load("podman_info_split_subuid.json"))
    assert any("/etc/subuid" in w and "single line" in w for w in ws)


def test_small_subid_range_warns():
    p = replace(_load("podman_info_6_2_rootless.json"), uid_extents=((0, 1000, 1), (1, 100000, 1000)))
    assert any("subuid" in w and "65536" in w for w in posture_warnings(p))


def test_strict_refuses_with_all_warnings():
    with pytest.raises(PodmanPostureError, match="rootful"):
        enforce_posture(_load("podman_info_rootful.json"), strict=True, log=logging.getLogger("t"))


def test_non_strict_continues():
    assert enforce_posture(_load("podman_info_rootful.json"), strict=False, log=logging.getLogger("t"))


def test_zero_size_extent_is_not_a_split():
    p = replace(_load("podman_info_6_2_rootless.json"), uid_extents=((0, 1000, 1), (1, 100000, 65536), (5, 7, 0)))
    assert posture_warnings(p) == []


def _fake_podman(tmp_path, body):
    exe = tmp_path / "podman"
    exe.write_text("#!/bin/sh\n" + body)
    exe.chmod(0o755)
    return str(exe)


@pytest.fixture(autouse=True)
def _clear_caches():
    _posture_cache.clear()
    find_podman.cache_clear()
    yield
    _posture_cache.clear()
    find_podman.cache_clear()


def test_probe_nonzero_exit_names_machine_start(tmp_path):
    exe = _fake_podman(tmp_path, "echo boom >&2\nexit 125\n")
    with pytest.raises(EnvironmentConnectionError, match="podman machine start"):
        probe_posture(exe)


def test_probe_invalid_json(tmp_path):
    exe = _fake_podman(tmp_path, "echo not-json\n")
    with pytest.raises(EnvironmentConnectionError):
        probe_posture(exe)


def test_probe_valid_json_and_cached(tmp_path):
    doc = (FIX / "podman_info_6_2_rootless.json").read_text()
    exe = _fake_podman(tmp_path, f"cat <<'EOF'\n{doc}\nEOF\n")
    p = probe_posture(exe)
    assert p.rootless and p.version == "6.2.0"
    assert probe_posture(exe) is p


def test_find_podman_uses_path(tmp_path, monkeypatch):
    exe = _fake_podman(tmp_path, "exit 0\n")
    monkeypatch.setenv("PATH", str(tmp_path))
    assert find_podman() == exe
