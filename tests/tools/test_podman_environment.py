"""PodmanEnvironment: argv construction, label-based reuse, gone-container recovery,
posture enforcement and the orphan reaper, with every podman call mocked."""

import json
import re
import subprocess
import time
from pathlib import Path

import pytest

from tools.environments import podman as podman_mod
from tools.environments import podman_posture
from tools.environments.base import EnvironmentConnectionError
from tools.environments.docker_egress import _egress_reuse_fingerprint
from tools.environments.podman import PodmanEnvironment, reap_podman_orphans
from tools.environments.podman_posture import PodmanPostureError

FIX = Path(__file__).parent / "fixtures"
PODMAN = "/usr/bin/podman"
DEFAULT_IMAGE = "nousresearch/hermes-sandbox:desktop"
QUALIFIED = "docker.io/nousresearch/hermes-sandbox:desktop"


class MockPodman:
    """Routes ``subprocess.run`` (podman CLI) and exec spawns (``_popen_bash``)."""

    def __init__(self):
        self.calls: list[tuple[list[str], dict]] = []
        self.execs: list[tuple[list[str], dict]] = []
        self._info = "podman_info_6_2_rootless.json"
        self._ps = "[]"
        self._exec_queue: list[tuple[int, str]] = []
        self._exists = True
        self._run_n = 0
        self.image_name = QUALIFIED
        self.network_mode = "pasta"
        self.running = True
        self.start_rc = 0

    # --- configuration ---
    def info(self, fixture):
        self._info = fixture

    def ps_returns(self, fixture_or_json):
        path = FIX / fixture_or_json
        self._ps = path.read_text() if path.exists() else fixture_or_json

    def exec_returns(self, code, output):
        self._exec_queue.append((code, output))

    def container_exists(self, exists):
        self._exists = exists

    @staticmethod
    def running_id(fixture):
        rows = json.loads((FIX / fixture).read_text())
        return next(r.get("Id") or r.get("ID") for r in rows if r["State"] == "running")

    # --- inspection ---
    def all_argvs(self):
        return [c for c, _ in self.calls] + [c for c, _ in self.execs]

    def _by_verb(self, verb):
        return [c for c, _ in self.calls if len(c) > 1 and c[1] == verb]

    def run_argv(self):
        return self._by_verb("run")[-1]

    def run_count(self):
        return len(self._by_verb("run"))

    def ps_argv(self):
        return self._by_verb("ps")[-1]

    def exec_count(self):
        # Non-login execs only: init_session's snapshot bootstrap runs under ``bash -l``.
        return sum(1 for c, _ in self.execs if c[-3] != "-l")

    # --- fakes ---
    def run(self, cmd, **kwargs):
        cmd = list(cmd)
        self.calls.append((cmd, kwargs))
        verb = cmd[1] if len(cmd) > 1 else ""
        out, rc = "", 0
        if verb == "info":
            out = (FIX / self._info).read_text()
        elif verb == "ps":
            out = self._ps
        elif verb == "run":
            self._run_n += 1
            out = f"fake-id-{self._run_n}\n"
        elif verb == "container" and cmd[2] == "exists":
            rc = {True: 0, False: 1}.get(self._exists, 125)
        elif verb == "image":
            rc = 1  # no local image metadata: hardened defaults (no s6)
        elif verb == "inspect":
            out = json.dumps([{"ImageName": self.image_name, "State": {"Running": self.running},
                               "HostConfig": {"NetworkMode": self.network_mode}}])
        elif verb == "start":
            rc = self.start_rc
        return subprocess.CompletedProcess(cmd, rc, stdout=out, stderr="")

    def popen(self, cmd, stdin_data=None, **kwargs):
        cmd = list(cmd)
        self.execs.append((cmd, kwargs))
        code, out = 0, ""
        if cmd[-3] != "-l" and self._exec_queue:
            code, out = self._exec_queue.pop(0)
        return subprocess.Popen(
            ["bash", "-c", 'printf %s "$1"; exit "$2"', "_", out, str(code)],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL,
            text=True)


@pytest.fixture
def mock_podman(monkeypatch, tmp_path):
    mock = MockPodman()
    monkeypatch.setattr(podman_mod, "find_podman", lambda: PODMAN)
    monkeypatch.setattr(podman_mod.subprocess, "run", mock.run)
    monkeypatch.setattr(podman_mod, "_popen_bash", mock.popen)
    monkeypatch.setattr(podman_mod, "_readonly_skill_mount_args", list)
    monkeypatch.setattr(podman_mod, "egress_args_for_podman", lambda p, *, network: ([], {}, []))
    monkeypatch.setenv("TERMINAL_SANDBOX_DIR", str(tmp_path / "sandboxes"))
    podman_posture._posture_cache.clear()
    podman_mod._WARNED_POSTURES.clear()
    yield mock
    PodmanEnvironment.wait_for_all_teardowns(timeout=5)


def make_env(**kwargs):
    kwargs.setdefault("image", DEFAULT_IMAGE)
    kwargs.setdefault("task_id", "test-task")
    return PodmanEnvironment(**kwargs)


def _v_specs(argv):
    return [argv[i + 1] for i, a in enumerate(argv[:-1]) if a == "-v"]


def _labels(argv):
    return dict(argv[i + 1].split("=", 1) for i, a in enumerate(argv[:-1]) if a == "--label")


# --- run argv ---
def test_run_argv_rootless_defaults(mock_podman):
    make_env(image=DEFAULT_IMAGE)
    run = mock_podman.run_argv()
    assert run[:3] == [PODMAN, "run", "-d"] and "--label" in run
    assert "hermes-podman=1" in run and "hermes-agent=1" not in run
    assert run[-3:] == [QUALIFIED, "sleep", "infinity"]
    assert [a for a in run if a.startswith("--userns")] == ["--userns=host"]
    assert "--init" in run and "--pids-limit" in run


def test_rootful_default_userns_leaves_containers_conf_in_charge(mock_podman):
    mock_podman.info("podman_info_rootful.json")
    make_env()  # non-strict: rootful only warns
    assert not any(a.startswith("--userns") for a in mock_podman.run_argv())


def test_labels_and_posture_hash(mock_podman):
    make_env()
    labels = _labels(mock_podman.run_argv())
    assert labels["hermes-podman"] == "1" and "hermes-agent" not in labels
    assert labels["hermes-task-id"] == "test-task"
    assert labels["hermes-egress"] == "off"
    assert "hermes-profile" in labels and "hermes-environment" in labels
    assert re.fullmatch(r"[0-9a-f]{16}", labels["hermes-podman-posture"])


def test_posture_hash_depends_on_userns_and_limits(mock_podman):
    make_env()
    default = _labels(mock_podman.run_argv())["hermes-podman-posture"]
    make_env(userns="keep-id")
    keep_id = _labels(mock_podman.run_argv())["hermes-podman-posture"]
    assert "--userns=keep-id" in mock_podman.run_argv()
    mock_podman.info("podman_info_cgroup_v1.json")
    podman_posture._posture_cache.clear()
    make_env()
    no_limits = _labels(mock_podman.run_argv())["hermes-podman-posture"]
    assert "--pids-limit" not in mock_podman.run_argv()
    assert len({default, keep_id, no_limits}) == 3


def test_posture_hash_depends_on_network(mock_podman):
    """An air-gapped sandbox never adopts a networked container on reuse or recovery: the network
    setting is part of the posture label the reuse lookup filters on."""
    make_env(network=True)
    networked = _labels(mock_podman.run_argv())["hermes-podman-posture"]
    make_env(network=False)
    air_gapped = _labels(mock_podman.run_argv())["hermes-podman-posture"]
    assert networked != air_gapped
    assert f"label=hermes-podman-posture={air_gapped}" in mock_podman.ps_argv()


def test_shared_container_key_drops_environment_label(mock_podman):
    make_env(shared_container_key="team")
    assert "hermes-environment" not in _labels(mock_podman.run_argv())


def test_network_false_is_air_gapped(mock_podman):
    make_env(network=False)
    assert "--network=none" in mock_podman.run_argv()


def test_persistent_sandbox_dirs_under_podman(mock_podman, tmp_path):
    env = make_env(persistent_filesystem=True, task_id="a:b")
    root = tmp_path / "sandboxes" / "podman"
    specs = _v_specs(mock_podman.run_argv())
    assert any(s.startswith(str(root)) and s.endswith(":/root") for s in specs)
    assert any(s.endswith(":/workspace") for s in specs)
    assert env._home_dir and env._home_dir.startswith(str(root))
    assert Path(env._home_dir).is_dir()


@pytest.mark.parametrize("info, suffix", [("podman_info_6_2_rootless.json", ":U"),
                                           ("podman_info_selinux.json", ":U,Z")])
def test_userns_auto_chowns_only_hermes_sandbox_dirs(mock_podman, tmp_path, info, suffix):
    """Under userns=auto container root is a subuid: without ``U`` it cannot write to (or
    create mountpoints in) its host-user-owned /root and /workspace. User paths are never chowned."""
    mock_podman.info(info)
    make_env(persistent_filesystem=True, userns="auto", volumes=["/srv:/srv"])
    by_target = {s.split(":")[1]: s for s in _v_specs(mock_podman.run_argv())}
    assert by_target["/root"].endswith(":/root" + suffix)
    assert by_target["/workspace"].endswith(":/workspace" + suffix)
    assert _has_chown(by_target["/root"]) and not _has_chown(by_target["/srv"])


def _has_chown(spec):
    """Whether Podman's ``U`` option is in the spec's option field (not merely a trailing letter)."""
    return spec.count(":") >= 2 and "U" in spec.rsplit(":", 1)[-1].split(",")


_INFO_FIXTURES = ["podman_info_6_2_rootless.json", "podman_info_selinux.json"]


@pytest.mark.parametrize("info", _INFO_FIXTURES)
@pytest.mark.parametrize("userns", ["", "keep-id"])
def test_other_userns_never_chown(mock_podman, info, userns):
    mock_podman.info(info)
    make_env(persistent_filesystem=True, userns=userns, volumes=["/srv:/srv"])
    specs = _v_specs(mock_podman.run_argv())
    assert specs and not any(_has_chown(s) for s in specs), specs


@pytest.mark.parametrize("info", _INFO_FIXTURES)
def test_userns_auto_never_chowns_the_host_cwd(mock_podman, tmp_path, info):
    """The auto-mounted host project dir belongs to the user: ``U`` would hand it to a subuid."""
    mock_podman.info(info)
    project = tmp_path / "proj"
    project.mkdir()
    make_env(cwd="/workspace", host_cwd=str(project), auto_mount_cwd=True, userns="auto",
             persistent_filesystem=True)
    specs = _v_specs(mock_podman.run_argv())
    host_cwd_specs = [s for s in specs if s.startswith(f"{project}:")]
    assert host_cwd_specs and not any(_has_chown(s) for s in host_cwd_specs), specs
    # The Hermes-created /root still gets it: the case is genuinely the auto path.
    assert any(_has_chown(s) for s in specs if s.split(":")[1] == "/root"), specs


def test_tmpfs_workspace_when_not_persistent(mock_podman):
    make_env()
    run = mock_podman.run_argv()
    assert "/workspace:rw,exec,size=10g" in run
    assert "/tmp:rw,exec,nosuid,size=512m" in run


def test_host_cwd_mount_followed(mock_podman, tmp_path):
    project = tmp_path / "proj"
    project.mkdir()
    env = make_env(cwd="/workspace", host_cwd=str(project), auto_mount_cwd=True)
    assert f"{project}:/workspace" in _v_specs(mock_podman.run_argv())
    assert env.host_cwd_mount == "/workspace"


def test_disk_is_ignored(mock_podman):
    make_env(disk=1024)
    assert not any("storage-opt" in a for a in mock_podman.run_argv())


def test_selinux_labels_every_bind_mount(mock_podman, tmp_path, monkeypatch):
    mock_podman.info("podman_info_selinux.json")
    skills = tmp_path / "skills"
    skills.mkdir()
    monkeypatch.setattr(podman_mod, "_readonly_skill_mount_args",
                        lambda: ["-v", f"{skills}:/root/.hermes/skills:ro"])
    make_env(persistent_filesystem=True, volumes=["/srv:/srv", "/ro:/ro:ro"])
    specs = _v_specs(mock_podman.run_argv())
    assert specs and all(re.search(r":([a-z,]*,)?[zZ]$", s) for s in specs), specs
    by_target = {s.split(":")[1]: s for s in specs}
    # Hermes-created per-sandbox dirs: private; everything else: shared.
    assert by_target["/root"].endswith(":Z") and by_target["/workspace"].endswith(":Z")
    assert by_target["/srv"] == "/srv:/srv:z"
    assert by_target["/ro"] == "/ro:/ro:ro,z"
    assert by_target["/root/.hermes/skills"] == f"{skills}:/root/.hermes/skills:ro,z"
    # tmpfs specs are never relabelled
    assert not any(a.endswith((":z", ":Z")) and not a.startswith("/") for a in mock_podman.run_argv())
    assert "/tmp:rw,exec,nosuid,size=512m" in mock_podman.run_argv()


def test_no_selinux_leaves_mounts_unlabelled(mock_podman):
    make_env(volumes=["/srv:/srv"])
    assert "/srv:/srv" in _v_specs(mock_podman.run_argv())


# --- posture ---
def test_strict_refuses_rootful(mock_podman):
    mock_podman.info("podman_info_rootful.json")
    with pytest.raises(PodmanPostureError):
        make_env(strict=True)
    assert mock_podman.run_count() == 0


def test_non_strict_warns_and_continues(mock_podman):
    mock_podman.info("podman_info_rootful.json")
    env = make_env()
    assert env.posture.rootless is False
    assert any("rootful" in w for w in env.posture_warnings)
    assert mock_podman.run_count() == 1


def test_posture_warnings_logged_once(mock_podman, caplog):
    mock_podman.info("podman_info_cgroup_v1.json")
    make_env()
    make_env()
    assert sum("CPU/memory/PID limits" in r.message for r in caplog.records) == 1


def test_rootful_posture_is_one_user_visible_notice_per_process(mock_podman):
    """Spec §5: a degraded posture is never silent. Each warning reaches the startup-notice channel
    the CLI and gateway show the user (not only the --verbose log), once per process."""
    from types import SimpleNamespace

    from agent.status_output import deliver_kept_startup_notices
    from hermes_cli.left_core_migration import claim_kept_notices

    claim_kept_notices()  # start from an empty notice store
    mock_podman.info("podman_info_rootful.json")
    make_env()
    make_env()
    shown: list[str] = []
    agent = SimpleNamespace(platform="cli", _emit_startup_warning=shown.append)
    deliver_kept_startup_notices(agent)
    rootful = [m for m in shown if "rootful" in m]
    assert len(rootful) == 1, shown
    assert rootful[0].startswith("Podman posture: Podman is rootful")
    make_env()
    deliver_kept_startup_notices(agent)
    assert len([m for m in shown if "rootful" in m]) == 1, shown


def test_healthy_posture_queues_no_notice(mock_podman):
    from hermes_cli.left_core_migration import claim_kept_notices

    claim_kept_notices()
    make_env()
    assert not [m for m in claim_kept_notices() if m.startswith("Podman posture:")]


def test_missing_podman_raises_connection_error(mock_podman, monkeypatch):
    monkeypatch.setattr(podman_mod, "find_podman", lambda: None)
    with pytest.raises(EnvironmentConnectionError):
        make_env()
    assert mock_podman.calls == []


def test_docker_exe_attribute_is_podman(mock_podman):
    assert make_env()._docker_exe == PODMAN


# --- reuse ---
def test_reuse_filters_podman_label_and_posture(mock_podman):
    make_env()
    ps = mock_podman.ps_argv()
    assert "label=hermes-podman=1" in ps and any(a.startswith("label=hermes-podman-posture=") for a in ps)
    assert "label=hermes-agent=1" not in ps
    assert ps[ps.index("--format") + 1] == "json"


@pytest.mark.parametrize("fixture", ["podman_ps_4_9.json", "podman_ps_6_2.json"])
def test_reuse_parses_json_prefers_running(mock_podman, fixture):
    mock_podman.ps_returns(fixture)
    assert make_env()._container_id == mock_podman.running_id(fixture)
    assert mock_podman.run_count() == 0


def test_reuse_starts_stopped_container(mock_podman):
    rows = json.loads((FIX / "podman_ps_6_2.json").read_text())[:1]
    mock_podman.ps_returns(json.dumps(rows))
    env = make_env()
    assert env._container_id == rows[0]["Id"]
    assert mock_podman._by_verb("start")[-1][-1] == rows[0]["Id"]


def test_no_reuse_when_persist_across_processes_off(mock_podman):
    mock_podman.ps_returns("podman_ps_6_2.json")
    make_env(persist_across_processes=False)
    assert mock_podman.run_count() == 1 and not mock_podman._by_verb("ps")


def test_reuse_replaces_air_gap_mismatch(mock_podman):
    mock_podman.ps_returns("podman_ps_6_2.json")
    env = make_env(network=False)
    assert mock_podman._by_verb("rm")
    assert env._container_id == "fake-id-1"


def test_reuse_keeps_unpinned_image_mismatch(mock_podman):
    mock_podman.ps_returns("podman_ps_6_2.json")
    mock_podman.image_name = "docker.io/library/debian:13"
    env = make_env()
    assert env._container_id == mock_podman.running_id("podman_ps_6_2.json")


_DIGEST = "sha256:" + "a" * 64


@pytest.mark.parametrize("image", [f"debian:trixie-slim@{_DIGEST}", f"docker.io/library/debian@{_DIGEST}"])
def test_reuse_matches_pinned_digest_ref_as_podman_records_it(mock_podman, image):
    """Podman records ``name:tag@digest`` as ``name@digest``: a pinned digest ref must still
    reuse its own container instead of replacing it in every new process."""
    mock_podman.ps_returns("podman_ps_6_2.json")
    mock_podman.image_name = f"docker.io/library/debian@{_DIGEST}"
    env = make_env(image=image, image_pinned=True)
    assert env._container_id == mock_podman.running_id("podman_ps_6_2.json")
    assert not mock_podman._by_verb("rm") and mock_podman.run_count() == 0


def test_reuse_replaces_pinned_image_with_another_digest(mock_podman):
    mock_podman.ps_returns("podman_ps_6_2.json")
    mock_podman.image_name = "docker.io/library/debian@sha256:" + "b" * 64
    env = make_env(image=f"debian:trixie-slim@{_DIGEST}", image_pinned=True)  # the mock's pull succeeds
    assert mock_podman._by_verb("rm") and env._container_id == "fake-id-1"


def test_malformed_ps_json_starts_fresh(mock_podman):
    mock_podman.ps_returns("not json")
    assert make_env()._container_id == "fake-id-1"


# --- exec / recovery ---
def test_output_containing_not_running_does_not_retry(mock_podman):
    env = make_env()
    mock_podman.exec_returns(1, "service is not running")
    mock_podman.container_exists(True)
    env.execute("systemctl status x")
    assert mock_podman.exec_count() == 1
    assert mock_podman._by_verb("container")[-1] == [PODMAN, "container", "exists", "fake-id-1"]


def test_existence_probe_error_is_not_gone(mock_podman):
    env = make_env()
    mock_podman.exec_returns(125, "")
    mock_podman.container_exists(None)  # podman itself failed: not proof the container is gone
    env.execute("true")
    assert mock_podman.run_count() == 1 and mock_podman.exec_count() == 1


def test_stopped_container_is_restarted_and_retried_once(mock_podman):
    env = make_env()
    mock_podman.exec_returns(125, "")
    mock_podman.container_exists(True)
    mock_podman.running = False
    result = env.execute("true")
    assert mock_podman._by_verb("start") == [[PODMAN, "start", "fake-id-1"]]
    assert mock_podman.exec_count() == 2 and mock_podman.run_count() == 1
    assert env._container_id == "fake-id-1"
    assert result["returncode"] == 0 and result.get("environment_recreated") is True


def test_running_container_failure_is_not_retried(mock_podman):
    env = make_env()
    mock_podman.exec_returns(1, "")
    mock_podman.container_exists(True)
    mock_podman.running = True
    result = env.execute("false")
    assert not mock_podman._by_verb("start")
    assert mock_podman.exec_count() == 1 and result["returncode"] == 1


def test_failed_restart_falls_back_to_recreate(mock_podman):
    env = make_env()
    mock_podman.exec_returns(125, "")
    mock_podman.container_exists(True)
    mock_podman.running = False
    mock_podman.start_rc = 125
    result = env.execute("true")
    assert mock_podman._by_verb("start")[0] == [PODMAN, "start", "fake-id-1"]
    assert mock_podman._by_verb("rm")[-1] == [PODMAN, "rm", "-f", "fake-id-1"]
    assert mock_podman.run_count() == 2 and mock_podman.exec_count() == 2
    assert env._container_id == "fake-id-2" and result["returncode"] == 0


def test_import_has_no_logging_side_effects():
    import logging
    names = [n for n in logging.root.manager.loggerDict if n.startswith("tools.environments.podman")]
    assert all(not logging.getLogger(n).disabled for n in names)
    assert not hasattr(podman_mod, "_SILENT_LOG")


def test_successful_exec_never_probes_existence(mock_podman):
    env = make_env()
    env.execute("true")
    assert not mock_podman._by_verb("container")


def test_gone_container_is_recreated_once(mock_podman):
    env = make_env()
    mock_podman.exec_returns(125, "")
    mock_podman.container_exists(False)
    result = env.execute("true")
    assert mock_podman.run_count() == 2 and mock_podman.exec_count() == 2
    assert env._container_id == "fake-id-2"
    assert result.get("environment_recreated") is True


def test_exec_argv_and_secrets_never_in_argv(mock_podman, monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "sk-secret")
    env = make_env(forward_env=["OPENAI_API_KEY"], env={"PLAIN": "v"})
    env.execute("true")
    assert all("sk-secret" not in " ".join(c) for c in mock_podman.all_argvs())
    cmd, kwargs = mock_podman.execs[-1]
    assert cmd[:4] == [PODMAN, "exec", "-w", "/"]
    assert "OPENAI_API_KEY" in cmd and kwargs["env"]["OPENAI_API_KEY"] == "sk-secret"
    run_argv = mock_podman.run_argv()
    assert "PLAIN" in run_argv and not any("PLAIN=" in a for a in run_argv)
    run_env = [k for c, k in mock_podman.calls if c[1] == "run"][-1]["env"]
    assert run_env["PLAIN"] == "v"


def test_podman_cli_never_inherits_scratch_tmpdir(mock_podman, monkeypatch, tmp_path):
    """Hermes exports TMPDIR=<home>/cache/scratch (0700); rootless crun puts its intermediate
    mountpoint there and every ``podman run``/``start`` then fails with OCI permission denied."""
    for name in ("TMPDIR", "TMP", "TEMP"):
        monkeypatch.setenv(name, str(tmp_path / "scratch"))
    monkeypatch.setenv("HERMES_RB_KEEP", "kept")
    make_env(env={"PLAIN": "v"})
    rows = json.loads((FIX / "podman_ps_6_2.json").read_text())[:1]
    mock_podman.ps_returns(json.dumps(rows))
    make_env(task_id="other")  # attaches to the stopped container: ``podman start``
    for verb in ("run", "start", "ps"):
        env = [k for c, k in mock_podman.calls if c[1] == verb][-1]["env"]
        assert not {"TMPDIR", "TMP", "TEMP"} & env.keys(), verb
        assert env["HERMES_RB_KEEP"] == "kept"
    assert [k for c, k in mock_podman.calls if c[1] == "run"][-1]["env"]["PLAIN"] == "v"


# --- egress ---
_EGRESS = (["-v", "/ca.crt:/etc/ssl/certs/hermes-egress-ca.crt:ro"],
           {"HTTPS_PROXY": "http://127.0.0.1:8443", "_HERMES_EGRESS_NODE_OPTIONS_APPEND": "--use-openssl-ca"},
           ["--network=pasta:-T,8443,-T,8444"])


def _with_egress(monkeypatch, enforce=True):
    monkeypatch.setattr(podman_mod, "egress_args_for_podman", lambda p, *, network: _EGRESS)
    monkeypatch.setattr(podman_mod, "egress_enforce_on_podman", lambda: enforce)


def test_egress_network_and_fingerprint(mock_podman, monkeypatch):
    _with_egress(monkeypatch)
    make_env()
    run = mock_podman.run_argv()
    assert "--network=pasta:-T,8443,-T,8444" in run
    assert "/ca.crt:/etc/ssl/certs/hermes-egress-ca.crt:ro" in _v_specs(run)
    assert _labels(run)["hermes-egress"] == _egress_reuse_fingerprint(*_EGRESS)
    assert _labels(run)["hermes-egress"] != _egress_reuse_fingerprint(_EGRESS[0], _EGRESS[1], [])
    run_env = [k for c, k in mock_podman.calls if c[1] == "run"][-1]["env"]
    assert run_env["HTTPS_PROXY"] == "http://127.0.0.1:8443"
    assert run_env["NODE_OPTIONS"] == "--use-openssl-ca"
    assert "_HERMES_EGRESS_NODE_OPTIONS_APPEND" not in run


def test_egress_with_user_network_refuses_when_enforced(mock_podman, monkeypatch):
    _with_egress(monkeypatch, enforce=True)
    with pytest.raises(RuntimeError, match="enforce_on_podman"):
        make_env(extra_args=["--network", "host"])
    assert mock_podman.run_count() == 0


def test_egress_with_user_network_dropped_when_not_enforced(mock_podman, monkeypatch, caplog):
    _with_egress(monkeypatch, enforce=False)
    make_env(extra_args=["--network=host"])
    run = mock_podman.run_argv()
    assert not any(a.startswith("--network=pasta") for a in run)
    assert "/ca.crt:/etc/ssl/certs/hermes-egress-ca.crt:ro" not in _v_specs(run)
    assert _labels(run)["hermes-egress"] == "off"
    assert "--network=host" in run
    assert any("enforce_on_podman" in r.message for r in caplog.records)


def test_egress_forward_env_collision_refused(mock_podman, monkeypatch):
    _with_egress(monkeypatch, enforce=True)
    with pytest.raises(RuntimeError):
        make_env(forward_env=["HTTPS_PROXY"])


# --- teardown ---
def test_cleanup_persist_mode_keeps_container(mock_podman):
    env = make_env()
    env.cleanup()
    assert env._container_id is None
    assert not mock_podman._by_verb("stop") and not mock_podman._by_verb("rm")


def test_cleanup_force_remove_stops_and_removes(mock_podman):
    env = make_env()
    env.cleanup(force_remove=True)
    assert env.wait_for_cleanup(timeout=5)
    assert mock_podman._by_verb("stop")[-1][-1] == "fake-id-1"
    assert mock_podman._by_verb("rm")[-1] == [PODMAN, "rm", "-f", "fake-id-1"]


def test_cleanup_without_cross_process_persistence_removes_container(mock_podman):
    env = make_env(persistent_filesystem=False, persist_across_processes=False)
    env.cleanup()
    assert PodmanEnvironment.wait_for_all_teardowns(timeout=5)
    assert mock_podman._by_verb("rm")


def test_stop_idle_stops_without_removing(mock_podman):
    env = make_env()
    env.stop_idle()
    assert env.wait_for_cleanup(timeout=5)
    assert mock_podman._by_verb("stop") and not mock_podman._by_verb("rm")
    assert env._container_id is None


def test_teardown_registry_is_podman_only(mock_podman):
    from tools.environments import docker as docker_mod
    env = make_env()
    env.stop_idle()
    assert env._cleanup_thread not in docker_mod._TEARDOWN_THREADS


# --- orphan reaper ---
def test_orphan_reaper_only_touches_podman_label(mock_podman):
    reap_podman_orphans(max_age_seconds=600, profile_filter="default", podman_exe=PODMAN)
    ps = mock_podman.ps_argv()
    assert "label=hermes-podman=1" in ps and "label=hermes-agent=1" not in ps
    assert "status=exited" in ps and "label=hermes-profile=default" in ps
    assert ps[ps.index("--format") + 1] == "json"


def test_orphan_reaper_removes_old_exited_only(mock_podman):
    now = int(time.time())
    rows = [
        {"Id": "old", "State": "exited", "ExitedAt": now - 3600, "Labels": {}},
        {"Id": "young", "State": "exited", "ExitedAt": now - 10, "Labels": {}},
        {"ID": "ws", "State": "exited", "ExitedAt": now - 3600,
         "Labels": {"hermes-workspace": "0123456789abcdef"}},
        {"Id": "never", "State": "created", "ExitedAt": -62135596800, "Labels": {}},
    ]
    mock_podman.ps_returns(json.dumps(rows))
    removed = reap_podman_orphans(max_age_seconds=600, profile_filter=None, podman_exe=PODMAN)
    assert removed == 1
    assert mock_podman._by_verb("rm") == [[PODMAN, "rm", "old"]]


def test_orphan_reaper_survives_ps_failure(mock_podman):
    mock_podman.ps_returns("garbage")
    assert reap_podman_orphans(max_age_seconds=600, profile_filter=None, podman_exe=PODMAN) == 0
