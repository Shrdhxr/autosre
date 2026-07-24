"""
Tests for chaos_fixtures.py

These tests never touch a real cluster — subprocess/kubectl calls are
mocked out — so any team member can run them locally or in CI to verify
the fixtures are well-formed and behave deterministically *before*
pointing them at a real environment.

Run with:
    pip install pytest pyyaml --break-system-packages
    cd agent && python3 -m pytest tests/ -v
"""
import subprocess
import sys
from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import chaos_fixtures as cf

try:
    import yaml
    _HAS_YAML = True
except ImportError:
    _HAS_YAML = False


# ── Manifest well-formedness ────────────────────────────────────────────────
@pytest.mark.parametrize("scenario", list(cf.SCENARIOS.keys()))
def test_manifest_is_valid_yaml(scenario):
    if not _HAS_YAML:
        pytest.skip("pyyaml not installed")
    text = cf.SCENARIOS[scenario]["manifest_fn"]()
    docs = [d for d in yaml.safe_load_all(text) if d]
    assert docs, f"{scenario} produced no YAML documents"
    for doc in docs:
        assert doc["metadata"]["namespace"] == cf.NAMESPACE
        labels = doc["metadata"]["labels"]
        assert labels["app"] == cf.FIXTURE_APP_LABEL
        assert labels["scenario"] == scenario


@pytest.mark.parametrize("scenario", list(cf.SCENARIOS.keys()))
def test_manifest_name_is_deterministic(scenario):
    """Calling the manifest builder twice must produce byte-identical
    output — this is what makes runs reproducible across the team."""
    a = cf.SCENARIOS[scenario]["manifest_fn"]()
    b = cf.SCENARIOS[scenario]["manifest_fn"]()
    assert a == b
    assert f"autosre-fixture-{scenario}" in a


def test_all_scenario_names_are_unique_and_prefixed():
    names = set()
    for scenario, spec in cf.SCENARIOS.items():
        text = spec["manifest_fn"]()
        assert f"scenario: {scenario}" in text
        names.add(scenario)
    assert len(names) == len(cf.SCENARIOS)


def test_expected_scenario_count():
    # Task requirement: 5-6 canned scenarios covering OOM, crash loop,
    # latency injection, plus extras.
    assert 5 <= len(cf.SCENARIOS) <= 6
    for required in ("oom_kill", "crash_loop", "latency_injection"):
        assert required in cf.SCENARIOS


# ── Detector alignment: manifests must match the PromQL/LogQL the ──────────
# ── existing anomaly_detector.py / telemetry_collector.py already run ──────
def test_oom_kill_has_tight_memory_limit_below_typical_service_limits():
    text = cf.manifest_oom_kill()
    assert "memory: \"40Mi\"" in text  # small limit -> reliably OOMs fast


def test_crash_loop_exits_nonzero_immediately():
    text = cf.manifest_crash_loop()
    assert "exit 1" in text


def test_high_cpu_requests_more_than_the_0_8_core_detection_threshold():
    text = cf.manifest_high_cpu()
    assert 'cpu: "900m"' in text  # > 0.8 cores, matches detect_high_cpu()'s threshold


def test_high_memory_never_exceeds_its_own_limit():
    text = cf.manifest_high_memory()
    assert "TARGET_MB = 85" in text
    assert 'limits: {memory: "100Mi"' in text  # 85/100 = 0.85 > 0.8 threshold, no OOM


def test_restart_storm_uses_persisted_counter_for_flapping_liveness():
    text = cf.manifest_restart_storm()
    assert "emptyDir" in text
    assert "% 3" in text


def test_latency_injection_includes_sleep_and_client_timeout():
    text = cf.manifest_latency_injection()
    assert "time.sleep(5)" in text
    assert "--max-time 2" in text
    assert "timed out" in text


# ── Repeatability: run always cleans up before re-applying ────────────────
def test_run_scenario_deletes_before_applying(monkeypatch):
    calls = []

    def fake_delete_by_label(scenario, dry_run=False, wait=True):
        calls.append(("delete", scenario))

    def fake_apply_manifest(manifest, dry_run=False):
        calls.append(("apply", None))

    monkeypatch.setattr(cf, "delete_by_label", fake_delete_by_label)
    monkeypatch.setattr(cf, "apply_manifest", fake_apply_manifest)

    cf.run_scenario("crash_loop", dry_run=True, wait=False)

    assert calls[0] == ("delete", "crash_loop")
    assert calls[1] == ("apply", None)


def test_cleanup_scenario_calls_delete_by_label(monkeypatch):
    calls = []
    monkeypatch.setattr(
        cf, "delete_by_label",
        lambda scenario, dry_run=False, wait=True: calls.append(scenario),
    )
    cf.cleanup_scenario("high_cpu", dry_run=True)
    assert calls == ["high_cpu"]


# ── kubectl wrapper behavior ────────────────────────────────────────────────
def test_run_kubectl_raises_on_nonzero_exit(monkeypatch):
    fake_result = MagicMock(returncode=1, stderr="boom", stdout="")
    monkeypatch.setattr(subprocess, "run", lambda *a, **kw: fake_result)
    with pytest.raises(cf.KubectlError):
        cf.run_kubectl(["get", "pods"])


def test_run_kubectl_ok_on_zero_exit(monkeypatch):
    fake_result = MagicMock(returncode=0, stderr="", stdout="ok")
    monkeypatch.setattr(subprocess, "run", lambda *a, **kw: fake_result)
    proc = cf.run_kubectl(["get", "pods"])
    assert proc.stdout == "ok"


def test_delete_by_label_uses_scenario_selector(monkeypatch):
    captured = {}

    def fake_run_kubectl(args, input_text=None, check=True):
        captured["args"] = args
        return MagicMock(returncode=0, stdout="", stderr="")

    monkeypatch.setattr(cf, "run_kubectl", fake_run_kubectl)
    cf.delete_by_label("oom_kill", dry_run=False)
    assert "-l" in captured["args"]
    idx = captured["args"].index("-l")
    assert captured["args"][idx + 1] == "app=autosre-fixture,scenario=oom_kill"


# ── CLI wiring ───────────────────────────────────────────────────────────
def test_resolve_scenarios_all_returns_every_key():
    assert set(cf._resolve_scenarios("all")) == set(cf.SCENARIOS.keys())


def test_resolve_scenarios_single():
    assert cf._resolve_scenarios("oom_kill") == ["oom_kill"]


def test_resolve_scenarios_unknown_exits():
    with pytest.raises(SystemExit):
        cf._resolve_scenarios("not_a_real_scenario")


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-v"]))