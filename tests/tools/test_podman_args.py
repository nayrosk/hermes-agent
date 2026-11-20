import json
from pathlib import Path

import pytest

from tools.environments.podman_args import (
    label_volume,
    qualify_image,
    resource_args,
    security_args,
)
from tools.environments.podman_posture import parse_posture

FIX = Path(__file__).parent / "fixtures"


def _posture(name):
    return parse_posture(json.loads((FIX / name).read_text()), pasta_available=True)


@pytest.fixture
def posture_ok():
    return _posture("podman_info_6_2_rootless.json")


@pytest.fixture
def posture_v1():
    return _posture("podman_info_cgroup_v1.json")


@pytest.mark.parametrize("image,expected", [
    ("nousresearch/hermes-sandbox:desktop", "docker.io/nousresearch/hermes-sandbox:desktop"),
    ("debian:13-slim", "docker.io/library/debian:13-slim"),
    ("ghcr.io/x/y:1", "ghcr.io/x/y:1"),
    ("localhost/mine:dev", "localhost/mine:dev"),
    ("quay.io/a/b@sha256:" + "0" * 64, "quay.io/a/b@sha256:" + "0" * 64)])
def test_qualify_image(image, expected):
    assert qualify_image(image) == expected


def test_default_userns_is_pinned_to_host_with_root_caps():
    """No flag would let a containers.conf ``userns = "auto"`` default replace the rootless
    namespace, so container root would no longer be the host user."""
    args = security_args("", s6_init=False, rootless=True)
    assert [a for a in args if a.startswith("--userns")] == ["--userns=host"]
    assert args[:2] == ["--cap-drop", "ALL"] and "no-new-privileges" in args
    assert "SETUID" in args  # container root may drop privileges


def test_default_userns_on_rootful_emits_no_flag():
    """Rootful ``--userns=host`` is the real host namespace (container root = host root) and
    would override an admin's containers.conf ``userns`` protection: leave it to containers.conf."""
    args = security_args("", s6_init=False, rootless=False)
    assert not any(a.startswith("--userns") for a in args)


@pytest.mark.parametrize("rootless", [True, False])
@pytest.mark.parametrize("userns", ["keep-id", "auto"])
def test_explicit_userns_is_kept_in_both_postures(userns, rootless):
    args = security_args(userns, s6_init=False, rootless=rootless)
    assert [a for a in args if a.startswith("--userns")] == [f"--userns={userns}"]


def test_keep_id_and_auto():
    assert "--userns=keep-id" in security_args("keep-id", s6_init=False, rootless=True)
    assert "SETUID" not in security_args("keep-id", s6_init=False, rootless=True)
    assert "--userns=auto" in security_args("auto", s6_init=False, rootless=True)


def test_tmp_tmpfs_has_explicit_exec():
    args = security_args("", s6_init=False, rootless=True)
    tmp = args[args.index("--tmpfs") + 1]
    assert tmp.startswith("/tmp:") and ",exec," in f",{tmp.split(':', 1)[1]},"


def test_s6_init_mounts_run_exec():
    args = security_args("", s6_init=True, rootless=True)
    assert any(a.startswith("/run:") and ",exec," in a for a in args)


def test_limits_only_when_controllers_delegated(posture_ok, posture_v1):
    assert "--pids-limit" in resource_args(posture_ok, cpu=2, memory=1024, shm_size="1g", network=True, extra_args=[])
    assert "--pids-limit" not in resource_args(posture_v1, cpu=2, memory=1024, shm_size="1g", network=True, extra_args=[])


def test_cpu_memory_shm_and_no_disk(posture_ok):
    args = resource_args(posture_ok, cpu=2, memory=1024, shm_size="1g", network=True, extra_args=[])
    assert args[args.index("--cpus") + 1] == "2"
    assert args[args.index("--memory") + 1] == "1024m"
    assert args[args.index("--shm-size") + 1] == "1g"
    assert "--storage-opt" not in args and not any(a.startswith("--network") for a in args)


def test_shm_skipped_when_user_sets_it(posture_ok):
    args = resource_args(posture_ok, cpu=0, memory=0, shm_size="1g", network=True, extra_args=["--shm-size=2g"])
    assert "--shm-size" not in args


def test_network_false_adds_none(posture_ok):
    assert "--network=none" in resource_args(posture_ok, cpu=0, memory=0, shm_size="", network=False, extra_args=[])
    assert "--network=none" not in resource_args(
        posture_ok, cpu=0, memory=0, shm_size="", network=False, extra_args=["--network=none"])


def test_network_false_conflicting_extra_args_fails_closed(posture_ok):
    with pytest.raises(RuntimeError, match="podman_network"):
        resource_args(posture_ok, cpu=0, memory=0, shm_size="", network=False, extra_args=["--network=pasta"])


@pytest.mark.parametrize("spec,selinux,private,expected", [
    ("/h:/c", True, False, "/h:/c:z"),
    ("/h:/c", True, True, "/h:/c:Z"),
    ("/h:/c:ro", True, False, "/h:/c:ro,z"),
    ("/h:/c:ro", True, True, "/h:/c:ro,Z"),
    ("/h:/c:rw", True, False, "/h:/c:rw,z"),
    ("/h:/c:ro,Z", True, False, "/h:/c:ro,Z"),
    ("/h:/c:z", True, True, "/h:/c:z"),
    ("/h:/c", False, False, "/h:/c"),
    ("/h:/c:ro", False, True, "/h:/c:ro"),
    ("named:/c", True, False, "named:/c"),
    ("named:/c:ro", True, True, "named:/c:ro"),
    ("rel/dir:/c", True, False, "rel/dir:/c")])
def test_label_volume(spec, selinux, private, expected):
    assert label_volume(spec, selinux, private=private) == expected
