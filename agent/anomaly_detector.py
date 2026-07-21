import requests
import time
import json
from datetime import datetime

# ── Config ────────────────────────────────────────────────────────
PROMETHEUS_URL = "http://localhost:9090"
POLL_INTERVAL  = 30  # seconds
THRESHOLDS = {
    "cpu":     0.80,  # 80% CPU usage
    "memory":  0.80,  # 80% memory usage
    "restarts": 3,    # pod restart count
}

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
        pod  = r["metric"].get("pod", "unknown")
        val  = float(r["value"][1])
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

# ── Main loop ─────────────────────────────────────────────────────
def run():
    print("=" * 55)
    print("  AutoSRE Anomaly Detector — Started")
    print(f"  Polling Prometheus every {POLL_INTERVAL}s")
    print("=" * 55)

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
        else:
            for anomaly in all_anomalies:
                print(f"\n  🚨 ANOMALY DETECTED")
                print(f"     Type     : {anomaly['type']}")
                print(f"     Service  : {anomaly['service']}")
                print(f"     Severity : {anomaly['severity']}")
                print(f"     Message  : {anomaly['message']}")

                # Save to file for the LLM agent to read
                with open("anomaly_events.json", "a") as f:
                    anomaly["timestamp"] = timestamp
                    f.write(json.dumps(anomaly) + "\n")

        time.sleep(POLL_INTERVAL)

if __name__ == "__main__":
    run()