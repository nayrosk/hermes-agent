"""Doctor, setup wizard and dashboard surfaces for the podman terminal backend."""
import json
from pathlib import Path

import pytest

from hermes_cli import doctor_tools, setup_terminal
from tools.environments.base import EnvironmentConnectionError
from tools.environments.podman_posture import parse_posture

FIX = Path(__file__).parents[1] / "tools" / "fixtures"


def _posture(name, pasta):
    return parse_posture(json.loads((FIX / name).read_text()), pasta_available=pasta)


@pytest.fixture
def podman_on_path(monkeypatch):
    monkeypatch.setattr(doctor_tools, "find_podman", lambda: "/usr/bin/podman")


def _config(monkeypatch, *, strict=False, proxy=False):
    cfg = {"terminal": {"podman_strict": strict}, "proxy": {"enabled": proxy}}
    monkeypatch.setattr("hermes_cli.config.load_config_readonly", lambda: cfg)


def _probe(monkeypatch, posture):
    monkeypatch.setattr(doctor_tools, "probe_posture", lambda exe: posture)


def test_doctor_lists_each_posture_warning(capsys, monkeypatch, podman_on_path):
    _config(monkeypatch)
    _probe(monkeypatch, _posture("podman_info_rootful.json", True))
    issues = []
    doctor_tools._check_podman_backend("podman", issues)
    out = capsys.readouterr().out
    assert "rootful" in out and issues == []  # warn, not fail


def test_doctor_strict_with_warnings_is_an_issue(monkeypatch, podman_on_path):
    _config(monkeypatch, strict=True)
    _probe(monkeypatch, _posture("podman_info_rootful.json", True))
    issues = []
    doctor_tools._check_podman_backend("podman", issues)
    assert any("podman_strict" in i for i in issues)


def test_doctor_egress_without_pasta_is_an_issue(monkeypatch, podman_on_path):
    _config(monkeypatch, proxy=True)
    _probe(monkeypatch, _posture("podman_info_4_9_rootless.json", False))
    issues = []
    doctor_tools._check_podman_backend("podman", issues)
    assert any("pasta" in i for i in issues)


def test_doctor_clean_rootless_has_no_issues(monkeypatch, podman_on_path):
    _config(monkeypatch, strict=True, proxy=True)
    _probe(monkeypatch, _posture("podman_info_6_2_rootless.json", True))
    issues = []
    doctor_tools._check_podman_backend("podman", issues)
    assert issues == []


def test_doctor_missing_podman_is_reported_not_raised(monkeypatch):
    monkeypatch.setattr(doctor_tools, "find_podman", lambda: None)
    issues = []
    doctor_tools._check_podman_backend("podman", issues)
    assert issues


def test_doctor_failed_podman_info_is_reported_not_raised(monkeypatch, podman_on_path):
    _config(monkeypatch)

    def boom(exe):
        raise EnvironmentConnectionError("podman info failed")

    monkeypatch.setattr(doctor_tools, "probe_posture", boom)
    issues = []
    doctor_tools._check_podman_backend("podman", issues)
    assert issues


def test_doctor_skips_podman_when_another_backend_is_selected(monkeypatch):
    monkeypatch.setattr(doctor_tools, "find_podman", lambda: pytest.fail("must not probe"))
    issues = []
    doctor_tools._check_podman_backend("docker", issues)
    assert issues == []


def test_setup_podman_sets_enforce(monkeypatch):
    monkeypatch.setattr(setup_terminal, "find_podman", lambda: "/usr/bin/podman")
    monkeypatch.setattr(setup_terminal, "probe_posture",
                        lambda exe: _posture("podman_info_rootful.json", True))
    monkeypatch.setattr(setup_terminal._setup, "prompt_yes_no", lambda *a, **k: True)
    cfg = {"terminal": {}}
    setup_terminal._setup_backend_podman(cfg)
    assert cfg["proxy"]["enabled"] is True
    assert cfg["proxy"]["enforce_on_podman"] is True and cfg["terminal"]["podman_image"]


def test_setup_podman_survives_missing_binary(monkeypatch):
    monkeypatch.setattr(setup_terminal, "find_podman", lambda: None)
    monkeypatch.setattr(setup_terminal._setup, "prompt_yes_no", lambda *a, **k: False)
    cfg = {"terminal": {}}
    setup_terminal._setup_backend_podman(cfg)
    assert cfg["terminal"]["podman_image"]


def test_backend_choices_include_podman_separately():
    labels = dict(setup_terminal._BUILTIN_TERMINAL_BACKENDS)
    assert "Podman" in labels["podman"] and "Podman" not in labels["docker"]
    assert "podman" in setup_terminal._TERMINAL_BACKEND_SETUP


def test_dashboard_lists_podman_backend_with_probe():
    from hermes_cli.web_routers import tools as web_tools
    from hermes_cli.web_server_profiles import _TERMINAL_BACKENDS

    rows = {r["name"]: r for r in _TERMINAL_BACKENDS}
    assert "Podman" in rows["podman"]["label"] and "Podman" not in rows["docker"]["label"]
    assert "podman" in web_tools._BACKEND_PROBES


def test_dashboard_probe_reports_missing_podman(monkeypatch):
    from hermes_cli.web_routers import tools as web_tools

    monkeypatch.setattr(web_tools, "find_podman", lambda: None)
    status, detail = web_tools._probe_podman_backend({})
    assert status == "needs_setup" and "Podman" in detail


def test_dashboard_config_schema_offers_podman():
    from hermes_cli.web_server_config import _SCHEMA_OVERRIDES as ov
    assert "podman" in ov["terminal.backend"]["options"]
    assert "proxy.enforce_on_podman" in ov
