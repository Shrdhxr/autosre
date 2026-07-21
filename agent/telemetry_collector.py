import requests
import json
from datetime import datetime, timedelta

# ── Config ────────────────────────────────────────────────────────
PROMETHEUS_URL = "http://localhost:9090"
LOKI_URL       = "http://localhost:3100"
NAMESPACE      = "default"

# ── Prometheus helpers ────────────────────────────────────────────
def prometheus_query(promql):
    try:
        r = requests.get(
            f"{PROMETHEUS_URL}/api/v1/query",
            params={"query": promql},
            timeout=10
        )
        data = r.json()
        if data["status"] == "success":
            return data["data"]["result"]
        return []
    except Exception as e:
        print(f"[ERROR] Prometheus query failed: {e}")
        return []

def get_metrics_snapshot():
    metrics = {}

    # CPU usage per pod
    cpu = prometheus_query(
        f'sum(rate(container_cpu_usage_seconds_total{{namespace="{NAMESPACE}",container!=""}}[5m])) by (pod)'
    )
    metrics["cpu_usage"] = [
        {"pod": r["metric"].get("pod"), "cpu_cores": round(float(r["value"][1]), 4)}
        for r in cpu
    ]

    # Memory usage per pod
    mem = prometheus_query(
        f'container_memory_working_set_bytes{{namespace="{NAMESPACE}",container!=""}}'
    )
    metrics["memory_usage"] = [
        {"pod": r["metric"].get("pod"), "memory_mb": round(float(r["value"][1]) / 1024 / 1024, 2)}
        for r in mem
    ]

    # Pod restart counts
    restarts = prometheus_query(
        f'kube_pod_container_status_restarts_total{{namespace="{NAMESPACE}"}}'
    )
    metrics["restart_counts"] = [
        {"pod": r["metric"].get("pod"), "restarts": int(float(r["value"][1]))}
        for r in restarts if int(float(r["value"][1])) > 0
    ]

    # Pod statuses
    statuses = prometheus_query(
        f'kube_pod_status_phase{{namespace="{NAMESPACE}"}}'
    )
    metrics["pod_statuses"] = [
        {"pod": r["metric"].get("pod"), "phase": r["metric"].get("phase")}
        for r in statuses if float(r["value"][1]) == 1
    ]

    # CrashLoopBackOff pods
    crashes = prometheus_query(
        f'kube_pod_container_status_waiting_reason{{namespace="{NAMESPACE}",reason="CrashLoopBackOff"}} == 1'
    )
    metrics["crash_loop_pods"] = [
        {"pod": r["metric"].get("pod")}
        for r in crashes
    ]

    return metrics

# ── Loki helpers ──────────────────────────────────────────────────
def get_logs_snapshot(service=None, limit=50):
    try:
        # Time range: last 10 minutes
        end   = datetime.utcnow()
        start = end - timedelta(minutes=10)

        if service:
            query = f'{{namespace="{NAMESPACE}", pod=~"{service}.*"}} |= "error"'
        else:
            query = f'{{namespace="{NAMESPACE}"}} |= "error"'

        r = requests.get(
            f"{LOKI_URL}/loki/api/v1/query_range",
            params={
                "query": query,
                "start": int(start.timestamp()),
                "end":   int(end.timestamp()),
                "limit": limit
            },
            timeout=10
        )
        data = r.json()
        logs = []
        if data.get("status") == "success":
            for stream in data["data"]["result"]:
                for entry in stream["values"]:
                    logs.append({
                        "timestamp": entry[0],
                        "line":      entry[1][:300]  # truncate long lines
                    })
        return logs[-limit:]  # return most recent
    except Exception as e:
        print(f"[ERROR] Loki query failed: {e}")
        return []

# ── Kubernetes state helper ───────────────────────────────────────
def get_k8s_events():
    events = prometheus_query(
        f'kube_pod_container_status_restarts_total{{namespace="{NAMESPACE}"}} > 0'
    )
    return [
        {
            "pod":      r["metric"].get("pod"),
            "restarts": int(float(r["value"][1]))
        }
        for r in events
    ]

# ── Main snapshot builder ─────────────────────────────────────────
def build_snapshot(anomaly_event=None):
    print("[Telemetry] Building snapshot...")

    snapshot = {
        "timestamp":     datetime.utcnow().isoformat(),
        "namespace":     NAMESPACE,
        "anomaly_event": anomaly_event,
        "metrics":       get_metrics_snapshot(),
        "recent_errors": get_logs_snapshot(
            service=anomaly_event["service"] if anomaly_event else None
        ),
        "k8s_events":    get_k8s_events()
    }

    print(f"[Telemetry] Snapshot built — "
          f"{len(snapshot['metrics']['cpu_usage'])} pods, "
          f"{len(snapshot['recent_errors'])} error logs")

    return snapshot

# ── Test run ──────────────────────────────────────────────────────
if __name__ == "__main__":
    # Simulate an anomaly event from the detector
    test_anomaly = {
        "type":      "CRASH_LOOP",
        "service":   "paymentservice",
        "severity":  "CRITICAL",
        "message":   "Pod paymentservice is in CrashLoopBackOff",
        "timestamp": datetime.utcnow().isoformat()
    }

    snapshot = build_snapshot(anomaly_event=test_anomaly)

    # Save to file
    with open("telemetry_snapshot.json", "w") as f:
        json.dump(snapshot, f, indent=2)

    print("\n[Telemetry] Snapshot saved to telemetry_snapshot.json")
    print(json.dumps(snapshot, indent=2)[:1000])  # preview first 1000 chars