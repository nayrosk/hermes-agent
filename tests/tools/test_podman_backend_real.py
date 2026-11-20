"""The rootless Podman terminal backend against real rootless Podman.

Every other Podman backend test mocks ``subprocess`` or feeds hand-built ``podman info``
JSON. These start real containers through ``PodmanEnvironment`` (and ``terminal_tool`` with
``TERMINAL_ENV=podman``) and check the rootless guarantees on the running sandbox: container
root is the host user, capabilities are dropped, cgroup limits are applied, a second process
reuses the container, ``userns=auto`` gives each sandbox its own UID range, cleanup removes
the container, and the egress pasta forward reaches only its own ports.

Armed by ``HERMES_TEST_PODMAN_IMAGE`` (a small public image with bash, e.g.
``docker.io/library/debian:13-slim``); the remote-backends CI lane sets it. Skipped otherwise.
Once armed a missing ``podman`` FAILS rather than skips. Every sandbox runs with
``strict=True``: a degraded rootless posture (rootful, undelegated cgroups, short or split
subuid ranges) refuses to start, so this file cannot pass on a host that does not provide the
guarantees it checks.

Host safety: the tests only ever touch containers they created, found by their own unique
``hermes-task-id`` label, and keep all sandbox state under ``tmp_path``.
"""

import http.server
import json
import os
import socket
import subprocess
import sys
import threading
import uuid
from pathlib import Path

import pytest

_IMAGE = os.getenv("HERMES_TEST_PODMAN_IMAGE", "")
_REPO_ROOT = Path(__file__).resolve().parents[2]

pytestmark = [pytest.mark.platforms("linux"),  # rootless Podman, /proc and cgroup v2
              pytest.mark.skipif(not _IMAGE, reason="HERMES_TEST_PODMAN_IMAGE not set")]

_CAP_SYS_ADMIN = 21


def find_podman() -> str:
    from tools.environments.podman_posture import find_podman as _find

    _find.cache_clear()
    exe = _find()
    assert exe, "HERMES_TEST_PODMAN_IMAGE is set but `podman` is not on PATH"
    return exe


def _podman(*args: str, timeout: float = 60) -> subprocess.CompletedProcess:
    return subprocess.run([find_podman(), *args], capture_output=True, text=True,
                          timeout=timeout, stdin=subprocess.DEVNULL, check=False)


def _own_container_ids(task_id: str) -> list[str]:
    rows = json.loads(_podman("ps", "-a", "--filter", "label=hermes-podman=1",
                              "--filter", f"label=hermes-task-id={task_id}",
                              "--format", "json").stdout or "[]")
    return [cid for row in rows if (cid := row.get("Id") or row.get("ID"))]


def _remove_own_containers(task_id: str) -> None:
    """Belt-and-braces teardown: force-remove only containers labelled with *task_id*."""
    for cid in _own_container_ids(task_id):
        _podman("rm", "-f", cid)


def _remove_sandbox_root(sandbox_root: Path) -> None:
    """``userns=auto`` chowns the sandbox dirs to a subuid (``:U``); only the rootless namespace
    can delete them. Confined to this test's own sandbox root."""
    if sandbox_root.exists():
        _podman("unshare", "rm", "-rf", "--", str(sandbox_root))


def _teardown(task_ids: list[str], sandbox_root: Path, graceful) -> None:
    """Run *graceful* (the backend's own cleanup; returns whether it drained), then ALWAYS the
    label-scoped removal and the sandbox-root wipe, and only then assert: a failed teardown
    never leaks containers or subuid-owned dirs."""
    try:
        drained = graceful()
    finally:  # runs even when graceful() raised; that error then propagates
        for task_id in task_ids:
            _remove_own_containers(task_id)
        _remove_sandbox_root(sandbox_root)
    assert drained, "podman teardown workers did not finish"
    leaked = {t: ids for t in task_ids if (ids := _own_container_ids(t))}
    assert not leaked, f"containers left after teardown: {leaked}"


@pytest.fixture
def podman_sandbox_dir(monkeypatch, tmp_path):
    """Sandbox bind dirs under this test's tmp path, never the user's Hermes home."""
    sandboxes = tmp_path / "sandboxes"
    monkeypatch.setenv("TERMINAL_SANDBOX_DIR", str(sandboxes))
    return sandboxes


@pytest.fixture
def podman_task_factory(podman_sandbox_dir):
    """Build strict ``PodmanEnvironment`` sandboxes; every one is removed afterwards."""
    from tools.environments.podman import PodmanEnvironment

    find_podman()
    created: list[tuple[str, PodmanEnvironment | None]] = []

    def make(*, userns: str = "", persist: bool = False, task_id: str | None = None, **kwargs):
        task_id = task_id or f"rb-podman-{uuid.uuid4().hex[:8]}"
        created.append((task_id, None))
        env = PodmanEnvironment(
            image=_IMAGE, task_id=task_id, persistent_filesystem=True,
            persist_across_processes=persist, image_pinned=True, userns=userns, strict=True,
            **kwargs)
        created[-1] = (task_id, env)
        return env

    yield make

    def graceful() -> bool:
        try:
            for _task_id, env in created:
                if env is not None:
                    env.cleanup(force_remove=True)
        finally:
            drained = PodmanEnvironment.wait_for_all_teardowns(timeout=60)
        return drained

    _teardown([task_id for task_id, _ in created], podman_sandbox_dir, graceful)


@pytest.fixture
def podman_task(podman_task_factory):
    return podman_task_factory()


def container_id(env) -> str:
    cid = env._container_id
    assert cid, "sandbox has no container"
    return cid


def run_in_task(env, command: str) -> str:
    result = env.execute(command)
    assert result["returncode"] == 0, result
    return result["output"]


def sandbox_workspace(env) -> Path:
    assert env._workspace_dir, "persistent sandbox has no host workspace dir"
    return Path(env._workspace_dir)


def host_uid_of_root(env) -> int:
    """Host UID that container root maps to.

    Read from the host side: ``/proc/<pid>/uid_map`` opened from the initial user namespace
    shows host UIDs, whatever namespaces sit between (rootless, then ``userns=auto``)."""
    pid = json.loads(_podman("inspect", "--format", "json", container_id(env)).stdout)[0]["State"]["Pid"]
    for line in Path(f"/proc/{pid}/uid_map").read_text().splitlines():
        inside, outer, _size = (int(x) for x in line.split())
        if inside == 0:
            return outer
    raise AssertionError(f"container {container_id(env)} maps no uid 0")


def container_id_from_new_process(env) -> str:
    """Construct the same sandbox in a fresh Python process; return the container it uses."""
    script = (
        "import sys\n"
        "from tools.environments.podman import PodmanEnvironment\n"
        "env = PodmanEnvironment(image=sys.argv[1], task_id=sys.argv[2], persistent_filesystem=True,"
        " persist_across_processes=True, image_pinned=True, strict=True)\n"
        "print('CID=' + env._container_id)\n"
        "env.cleanup()\n"  # persist mode: leaves the container running
    )
    proc = subprocess.run([sys.executable, "-c", script, _IMAGE, env._task_id],
                          cwd=_REPO_ROOT, capture_output=True, text=True, timeout=300,
                          stdin=subprocess.DEVNULL, check=False)
    assert proc.returncode == 0, proc.stderr[-2000:]
    cids = [ln[4:] for ln in proc.stdout.splitlines() if ln.startswith("CID=")]
    assert cids, proc.stdout[-2000:]
    return cids[-1]


# --- rootless guarantees --------------------------------------------------------------------


def test_podman_is_rootless_and_posture_is_clean(podman_task):
    info = json.loads(_podman("info", "--format", "json").stdout)
    assert info["host"]["security"]["rootless"] is True
    assert podman_task.posture.rootless
    assert podman_task.posture_warnings == []


def test_runs_rootless_and_files_owned_by_host_user(podman_task):
    out = run_in_task(podman_task, "id -u; touch /workspace/f")
    assert out.strip().splitlines()[0] == "0"
    assert (sandbox_workspace(podman_task) / "f").stat().st_uid == os.getuid()
    # Default userns: container root is the host user itself, never host root.
    assert host_uid_of_root(podman_task) == os.getuid() != 0


def test_caps_dropped(podman_task):
    capeff = int(run_in_task(podman_task, "grep CapEff /proc/self/status | awk '{print $2}'"), 16)
    assert not capeff & (1 << _CAP_SYS_ADMIN)
    assert run_in_task(podman_task, "grep NoNewPrivs /proc/self/status | awk '{print $2}'").strip() == "1"


def test_pids_limit_applied(podman_task):
    assert run_in_task(podman_task, "cat /sys/fs/cgroup/pids.max").strip() == "2048"


def test_cpu_and_memory_limits_applied(podman_task_factory):
    env = podman_task_factory(cpu=1, memory=512)
    assert run_in_task(env, "cat /sys/fs/cgroup/memory.max").strip() == str(512 * 1024 * 1024)
    quota, period = run_in_task(env, "cat /sys/fs/cgroup/cpu.max").split()
    assert int(quota) == int(period)  # one CPU


def test_reuse_across_processes(podman_task_factory):
    env = podman_task_factory(persist=True)
    run_in_task(env, "echo mark > /tmp/reused")
    assert container_id_from_new_process(env) == container_id(env)
    assert run_in_task(env, "cat /tmp/reused").strip() == "mark"


def test_userns_auto_isolates_uid_ranges(podman_task_factory):
    a, b = podman_task_factory(userns="auto"), podman_task_factory(userns="auto")
    uid_a, uid_b = host_uid_of_root(a), host_uid_of_root(b)
    assert uid_a != uid_b
    # Neither sandbox's root is the host user (nor host root).
    assert os.getuid() not in (uid_a, uid_b) and 0 not in (uid_a, uid_b)


def test_cleanup_removes_container(podman_task):
    cid = container_id(podman_task)
    podman_task.cleanup(force_remove=True)
    assert podman_task.wait_for_cleanup()
    assert _podman("container", "exists", cid).returncode == 1


# --- egress: the pasta forward reaches only the proxy's ports -------------------------------


class _Hello(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        body = f"hello-from-{self.server.server_port}".encode()
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


def _listeners_on_consecutive_ports():
    """HTTP servers on 127.0.0.1 at ``port`` and ``port + 1`` (the proxy's two ports)."""
    for _ in range(50):
        first = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _Hello)
        try:
            second = http.server.ThreadingHTTPServer(("127.0.0.1", first.server_port + 1), _Hello)
        except OSError:
            first.server_close()
            continue
        return first, second
    pytest.fail("no two consecutive free loopback ports")


def _http_get_from_sandbox(env, port: int) -> dict:
    return env.execute(
        f"exec 3<>/dev/tcp/127.0.0.1/{port} && printf 'GET / HTTP/1.0\\r\\n\\r\\n' >&3 && cat <&3")


def test_egress_forward_reaches_only_the_proxy_ports(podman_task_factory, monkeypatch, tmp_path):
    from tools.environments import podman_egress
    from tools.environments.docker_egress import ResolvedEgress

    proxy, plain = _listeners_on_consecutive_ports()
    other = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _Hello)  # not forwarded
    servers = (proxy, plain, other)
    for server in servers:
        threading.Thread(target=server.serve_forever, daemon=True).start()
    ca = tmp_path / "ca.crt"
    ca.write_text("not a real CA\n")
    monkeypatch.setattr(podman_egress, "resolve_egress", lambda _key: ResolvedEgress(
        ca_cert_path=ca, tunnel_port=proxy.server_port, listen_host="127.0.0.1", token_env={}))
    try:
        env = podman_task_factory()
        assert f"--network=pasta:-T,{proxy.server_port},-T,{plain.server_port}" in env._all_run_args
        assert run_in_task(env, 'echo "$HTTPS_PROXY"').strip() == f"http://127.0.0.1:{proxy.server_port}"
        for server in (proxy, plain):
            reached = _http_get_from_sandbox(env, server.server_port)
            assert reached["returncode"] == 0, reached
            assert f"hello-from-{server.server_port}" in reached["output"]
        # Sanity: the host side really serves the unforwarded port...
        with socket.create_connection(("127.0.0.1", other.server_port), timeout=5):
            pass
        # ...but the sandbox cannot reach it.
        refused = _http_get_from_sandbox(env, other.server_port)
        assert refused["returncode"] != 0, refused
        assert f"hello-from-{other.server_port}" not in refused["output"]
    finally:
        for server in servers:
            server.shutdown()
            server.server_close()


# --- terminal_tool end to end with TERMINAL_ENV=podman --------------------------------------


@pytest.fixture
def podman_tool_task(monkeypatch, podman_sandbox_dir):
    find_podman()
    monkeypatch.setenv("TERMINAL_ENV", "podman")
    monkeypatch.setenv("TERMINAL_PODMAN_IMAGE", _IMAGE)
    monkeypatch.setenv("TERMINAL_PODMAN_IMAGE_PINNED", "1")
    monkeypatch.setenv("TERMINAL_PODMAN_STRICT", "true")
    # Remove the container at cleanup, and never sweep the host's other hermes containers.
    monkeypatch.setenv("TERMINAL_PODMAN_PERSIST_ACROSS_PROCESSES", "false")
    monkeypatch.setenv("TERMINAL_PODMAN_ORPHAN_REAPER", "false")
    monkeypatch.setenv("TERMINAL_CONTAINER_DISK", "0")
    monkeypatch.setenv("TERMINAL_PODMAN_ENV", json.dumps({"HERMES_RB_STATIC": "from-config"}))
    monkeypatch.setenv("TERMINAL_PODMAN_FORWARD_ENV", json.dumps(["HERMES_RB_FORWARDED"]))
    monkeypatch.setenv("HERMES_RB_FORWARDED", "from-host")
    monkeypatch.setenv("HERMES_RB_NOT_FORWARDED", "must-stay-on-host")
    task_id = f"rb-podman-tool-{uuid.uuid4().hex[:8]}"
    yield task_id
    from tools.environments.podman import PodmanEnvironment
    from tools.terminal_tool import _active_environments, _resolve_container_task_id
    from tools.terminal_tool_lifecycle import cleanup_vm

    key = _resolve_container_task_id(task_id)
    env = _active_environments.get(key)
    own_label = getattr(env, "_labels", {}).get("hermes-task-id")

    def graceful() -> bool:
        try:
            cleanup_vm(key, force_remove=True)
        finally:
            drained = PodmanEnvironment.wait_for_all_teardowns(timeout=60)
        return drained

    _teardown([own_label] if own_label else [], podman_sandbox_dir, graceful)


def _tool(command, task_id, **kwargs):
    from tools.terminal_tool import terminal_tool

    return json.loads(terminal_tool(command, task_id=task_id, **kwargs))


def _tool_env(task_id):
    from tools.terminal_tool import _active_environments, _resolve_container_task_id

    return _active_environments.get(_resolve_container_task_id(task_id))


def test_terminal_tool_runs_in_a_podman_sandbox(podman_tool_task):
    from tools.environments.podman import PodmanEnvironment

    r = _tool("echo hello-podman; id -u; head -1 /etc/os-release", podman_tool_task)
    assert r["exit_code"] == 0, r
    assert "hello-podman" in r["output"] and "Debian" in r["output"]
    env = _tool_env(podman_tool_task)
    assert isinstance(env, PodmanEnvironment)
    labels = json.loads(_podman("inspect", "--format", "json", container_id(env)).stdout)[0][
        "Config"]["Labels"]
    assert labels["hermes-podman"] == "1" and "hermes-agent" not in labels

    failed = _tool("echo before; exit 7", podman_tool_task)
    assert failed["exit_code"] == 7 and "before" in failed["output"]


def test_terminal_tool_cwd_and_env_forwarding(podman_tool_task):
    _tool("mkdir -p /workspace/proj && cd /workspace/proj", podman_tool_task)
    assert _tool("pwd", podman_tool_task)["output"].strip() == "/workspace/proj"
    r = _tool('echo "s=$HERMES_RB_STATIC f=$HERMES_RB_FORWARDED n=${HERMES_RB_NOT_FORWARDED:-unset}"',
              podman_tool_task)
    assert r["output"].strip() == "s=from-config f=from-host n=unset"


def test_file_tools_write_and_read_inside_the_sandbox(podman_tool_task):
    from tools.file_tools import read_file_tool, write_file_tool

    content = "first line\nsecond: ünïcödé ✓\n"
    wrote = json.loads(write_file_tool("/workspace/notes.txt", content, task_id=podman_tool_task))
    assert wrote.get("success", True) and "error" not in wrote, wrote
    assert _tool("cat /workspace/notes.txt", podman_tool_task)["output"] == content.rstrip("\n")
    read = json.loads(read_file_tool("/workspace/notes.txt", task_id=podman_tool_task))
    assert "second: ünïcödé ✓" in read["content"], read
    host_file = sandbox_workspace(_tool_env(podman_tool_task)) / "notes.txt"
    assert host_file.read_text(encoding="utf-8") == content
    assert host_file.stat().st_uid == os.getuid()
