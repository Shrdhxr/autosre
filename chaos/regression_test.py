import subprocess
import time
import json
import os
from datetime import datetime

CHAOS_DIR = os.path.join(os.path.dirname(__file__), "experiments")
AGENT_DIR = os.path.join(os.path.dirname(__file__), "..", "agent")
ANOMALY_EVENTS_FILE = os.path.join(AGENT_DIR, "anomaly_events.json")
AUDIT_LOG_FILE = os.path.join(AGENT_DIR, "audit_log.jsonl")
REPORT_FILE = os.path.join(os.path.dirname(__file__), "regression_report.jsonl")

# Each scenario: (file, expected_service, wait_seconds)
# wait_seconds = chaos duration + buffer for detection (30s poll) + LLM/operator processing
SCENARIOS = [
    ("01-pod-kill.yaml",           ["cartservice", "paymentservice"],            60),
    ("02-pod-failure.yaml",        ["checkoutservice", "frontend"],              120),
    ("03-network-latency.yaml",    ["productcatalogservice", "recommendationservice"], 120),
    ("04-cpu-stress.yaml",         ["currencyservice", "adservice"],             120),
    ("05-memory-stress.yaml",      ["emailservice", "shippingservice"],          120),
    ("06-network-partition.yaml",  ["redis-cart"],                               90),
]


def run(cmd):
    return subprocess.run(cmd, shell=True, capture_output=True, text=True)


def count_lines(path):
    if not os.path.exists(path):
        return 0
    with open(path) as f:
        return sum(1 for _ in f)


def get_new_lines(path, start_count):
    if not os.path.exists(path):
        return []
    with open(path) as f:
        lines = f.readlines()
    return lines[start_count:]


def check_detection(services, before_anomaly_count, before_audit_count):
    """Checks whether the anomaly detector and audit log recorded activity
    for any of the target services during this scenario's window."""
    new_anomalies = get_new_lines(ANOMALY_EVENTS_FILE, before_anomaly_count)
    new_audit = get_new_lines(AUDIT_LOG_FILE, before_audit_count)

    detected_services = set()
    for line in new_anomalies:
        try:
            event = json.loads(line)
            if event.get("service") in services:
                detected_services.add(event["service"])
        except json.JSONDecodeError:
            continue

    remediated_services = set()
    for line in new_audit:
        try:
            entry = json.loads(line)
            if entry.get("service") in services and entry.get("event") in ("SUCCEEDED", "AUTO_APPROVED"):
                remediated_services.add(entry["service"])
        except json.JSONDecodeError:
            continue

    return detected_services, remediated_services


def run_scenario(filename, services, wait_seconds):
    path = os.path.join(CHAOS_DIR, filename)
    print(f"\n{'='*60}")
    print(f"  Scenario: {filename}")
    print(f"  Targets : {', '.join(services)}")
    print(f"{'='*60}")

    before_anomaly_count = count_lines(ANOMALY_EVENTS_FILE)
    before_audit_count = count_lines(AUDIT_LOG_FILE)

    apply_result = run(f"kubectl apply -f {path}")
    if apply_result.returncode != 0:
        print(f"  ✗ Failed to apply chaos manifest: {apply_result.stderr}")
        return {"scenario": filename, "result": "ERROR", "reason": "apply failed"}

    print(f"  ⏳ Waiting {wait_seconds}s for detection + diagnosis + remediation...")
    time.sleep(wait_seconds)

    detected, remediated = check_detection(services, before_anomaly_count, before_audit_count)

    # Cleanup
    run(f"kubectl delete -f {path}")

    result = {
        "scenario":   filename,
        "targets":    services,
        "detected":   sorted(detected),
        "remediated": sorted(remediated),
        "timestamp":  datetime.now().isoformat(),
    }

    if detected:
        result["result"] = "PASS"
        print(f"  ✅ PASS — detected: {sorted(detected)}")
        if remediated:
            print(f"     remediated: {sorted(remediated)}")
    else:
        result["result"] = "FAIL"
        print(f"  ❌ FAIL — no anomaly detected for {services}")

    return result

KNOWN_LIMITATIONS = {
    "01-pod-kill.yaml": "Single pod-kill produces only 1 restart; below the >2-in-15m detection threshold by design (avoids false positives on routine restarts).",
    "04-cpu-stress.yaml": "Requires the target container to have an explicit CPU limit set; unlimited containers won't cross the ratio-based threshold.",
    "05-memory-stress.yaml": "Requires the target container to have an explicit memory limit set; unlimited containers won't cross the ratio-based threshold.",
}

def run_battery():
    print("=" * 60)
    print("  AutoSRE — Chaos Regression Test Battery")
    print(f"  {len(SCENARIOS)} scenarios")
    print("=" * 60)

    results = []
    for filename, services, wait_seconds in SCENARIOS:
        result = run_scenario(filename, services, wait_seconds)
        results.append(result)
        with open(REPORT_FILE, "a") as f:
            f.write(json.dumps(result) + "\n")
        time.sleep(20)  # brief cooldown between scenarios

    # Summary
    print("\n" + "=" * 60)
    print("  REGRESSION SUMMARY")
    print("=" * 60)
    passed = sum(1 for r in results if r["result"] == "PASS")
    failed = sum(1 for r in results if r["result"] == "FAIL")
    for r in results:
        icon = "✅" if r["result"] == "PASS" else "❌"
        note = KNOWN_LIMITATIONS.get(r["scenario"], "")
        print(f"  {icon} {r['scenario']:35s} {r['result']}" + (f"  — {note}" if note else ""))
    print("-" * 60)
    print(f"  Total: {len(results)}  |  Passed: {passed}  |  Failed: {failed}")
    print(f"  Full report saved to: {REPORT_FILE}")
    print("=" * 60)


if __name__ == "__main__":
    run_battery()