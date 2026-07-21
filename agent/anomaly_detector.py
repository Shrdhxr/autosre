import requests
import time
import json
from datetime import datetime
from telemetry_collector import build_snapshot

# ── Config ────────────────────────────────────────────────────────
PROMETHEUS_URL = "http://localhost:9090"
POLL_INTERVAL  = 30  # seconds

# ── Prometheus query helper ───────────────────────────────────────
def query(promql):
    try:
        response = requests.get(
            f"{PROMETHEUS_URL}/api/v1/query",
            params={"query": promql},
            timeout=10
        )
        data = response.json()
        if data["status"] == "success":
            return data["data"]["result"]
        return []
    except Exception as e:
        print(f"[ERROR] Prometheus query failed: {e}")
        return []

# ── Detection functions ───────────────────────────────────────────
def detect_pod_restarts():
    results = query(
        'kube_pod_container_status_restarts_total{namespace="default"} > 3'
    )
    anomalies = []
    for r in results:
        pod = r["metric"].get("pod", "unknown")
        val = float(r["value"][1])
        anomalies.append({
            "type":     "POD_RESTART",
            "service":  pod,
            "value":    val,
            "message":  f"Pod {pod} has restarted {int(val)} times",
            "severity": "HIGH"
        })
    return anomalies

def detect_high_cpu():
    results = query(
        'sum(rate(container_cpu_usage_seconds_total{namespace="default", container!=""}[5m])) by (pod) > 0.8'
    )
    anomalies = []
    for r in results:
        pod = r["metric"].get("pod", "unknown")
        val = float(r["value"][1])
        anomalies.append({
            "type":     "HIGH_CPU",
            "service":  pod,
            "value":    round(val * 100, 2),
            "message":  f"Pod {pod} CPU usage at {round(val*100, 2)}%",
            "severity": "MEDIUM"
        })
    return anomalies

def detect_high_memory():
    results = query(
        '''
        (
          container_memory_working_set_bytes{namespace="default", container!=""}
          /
          container_spec_memory_limit_bytes{namespace="default", container!=""}
        ) > 0.8
        '''
    )
    anomalies = []
    for r in results:
        pod = r["metric"].get("pod", "unknown")
        val = float(r["value"][1])
        anomalies.append({
            "type":     "HIGH_MEMORY",
            "service":  pod,
            "value":    round(val * 100, 2),
            "message":  f"Pod {pod} memory usage at {round(val*100, 2)}%",
            "severity": "MEDIUM"
        })
    return anomalies

def detect_pod_crashes():
    results = query(
        'kube_pod_container_status_waiting_reason{namespace="default", reason="CrashLoopBackOff"} == 1'
    )
    anomalies = []
    for r in results:
        pod = r["metric"].get("pod", "unknown")
        anomalies.append({
            "type":     "CRASH_LOOP",
            "service":  pod,
            "value":    1,
            "message":  f"Pod {pod} is in CrashLoopBackOff",
            "severity": "CRITICAL"
        })
    return anomalies

# ── Handle anomaly ────────────────────────────────────────────────
def handle_anomaly(anomaly):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    anomaly["timestamp"] = timestamp

    # Print alert
    print(f"\n  🚨 ANOMALY DETECTED")
    print(f"     Type     : {anomaly['type']}")
    print(f"     Service  : {anomaly['service']}")
    print(f"     Severity : {anomaly['severity']}")
    print(f"     Message  : {anomaly['message']}")

    # Save anomaly event
    with open("anomaly_events.json", "a") as f:
        f.write(json.dumps(anomaly) + "\n")

    # Trigger telemetry collector
    print(f"\n  📡 Collecting telemetry snapshot for {anomaly['service']}...")
    snapshot = build_snapshot(anomaly_event=anomaly)

    # Save snapshot with timestamp in filename
    filename = f"snapshot_{anomaly['type']}_{timestamp.replace(' ', '_').replace(':', '-')}.json"
    with open(filename, "w") as f:
        json.dump(snapshot, f, indent=2)

    print(f"  💾 Snapshot saved to {filename}")
    print(f"  ⏳ Waiting for LLM agent to process...\n")

    # Save latest snapshot for LLM agent to always read
    with open("latest_snapshot.json", "w") as f:
        json.dump(snapshot, f, indent=2)

# ── Main loop ─────────────────────────────────────────────────────
def run():
    print("=" * 55)
    print("  AutoSRE Anomaly Detector — Started")
    print(f"  Polling Prometheus every {POLL_INTERVAL}s")
    print("=" * 55)

    # Track seen anomalies to avoid duplicate triggers
    seen = set()

    while True:
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        print(f"\n[{timestamp}] Running detection scan...")

        all_anomalies = (
            detect_pod_restarts() +
            detect_high_cpu()     +
            detect_high_memory()  +
            detect_pod_crashes()
        )

        if not all_anomalies:
            print("  ✓ All systems healthy — no anomalies detected")
            seen.clear()  # reset when cluster is healthy
        else:
            for anomaly in all_anomalies:
                # Deduplicate — don't re-trigger same anomaly every 30s
                key = f"{anomaly['type']}_{anomaly['service']}"
                if key not in seen:
                    seen.add(key)
                    handle_anomaly(anomaly)
                else:
                    print(f"  ⚠ Ongoing: {anomaly['type']} on {anomaly['service']} (already triggered)")

        time.sleep(POLL_INTERVAL)

if __name__ == "__main__":
    run()