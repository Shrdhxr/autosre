#!/usr/bin/env python3
"""
AutoSRE — Chaos Fixture Generator
==================================
Reproducible failure-injection fixtures for exercising the existing
AutoSRE pipeline end to end:

    chaos_fixtures.py  --(kubectl apply, real k8s failure)-->  cluster
                                    |
                                    v
                     anomaly_detector.py  (polls Prometheus every 30s)
                                    |
                                    v
                     telemetry_collector.py  (snapshot on anomaly)
                                    |
                                    v
                     llm_diagnosis_agent.py  (diagnosis + log)

This file is designed to sit in the same `agent/` folder as
`telemetry_collector.py` / `anomaly_detector.py` / `llm_diagnosis_agent.py`.
It does not modify those files. It reuses the exact same NAMESPACE and
Prometheus/Loki targets they already read from, so scenarios triggered
here are picked up by the existing detector without any code changes.

Every scenario is keyed to the concrete PromQL/LogQL queries already used
by anomaly_detector.py / telemetry_collector.py:

  oom_kill            -> memory ratio query in detect_high_memory(),
                         then restarts in detect_pod_restarts()
                         (container_memory_working_set_bytes /
                          container_spec_memory_limit_bytes)
  crash_loop          -> detect_pod_crashes()
                         (kube_pod_container_status_waiting_reason
                          == "CrashLoopBackOff")
  high_cpu            -> detect_high_cpu()
                         (sum(rate(container_cpu_usage_seconds_total...)) > 0.8)
  high_memory         -> detect_high_memory() without ever OOM-killing
                         (working_set/limit > 0.8, held steady)
  restart_storm       -> detect_pod_restarts()
                         (increase(kube_pod_container_status_restarts_total
                          [5m]) > 0) via a flapping livenessProbe
  latency_injection   -> exercises get_logs_snapshot() / the Loki
                         `|= "error"` query — a slow backend + a client
                         that times out and logs "ERROR: ... timed out"

SCENARIOS ARE REPEATABLE
-------------------------
  * Every resource uses a fixed, deterministic name
    (`autosre-fixture-<scenario>`), labeled `app=autosre-fixture,
    scenario=<scenario>`.
  * `run` always deletes any previous instance of the scenario first and
    waits for full termination before re-applying, so re-running the same
    scenario always starts from the same clean state — no matter who on
    the team runs it, or how many times.
  * `cleanup` removes everything a scenario created, restoring the
    cluster to a healthy baseline so the next scenario (or the next
    person) starts clean.

USAGE
-----
    python3 chaos_fixtures.py list
    python3 chaos_fixtures.py run oom_kill
    python3 chaos_fixtures.py run all --wait
    python3 chaos_fixtures.py status
    python3 chaos_fixtures.py cleanup crash_loop
    python3 chaos_fixtures.py cleanup all

    # print manifests only, do not touch the cluster
    python3 chaos_fixtures.py run oom_kill --dry-run

RUN ALONGSIDE THE EXISTING PIPELINE
------------------------------------
Terminal 1:  python3 anomaly_detector.py
Terminal 2:  python3 llm_diagnosis_agent.py --watch
Terminal 3:  python3 chaos_fixtures.py run oom_kill --wait
"""

import argparse
import json
import subprocess
import sys
import time
from datetime import datetime

# ── Config — kept in sync with telemetry_collector.py / anomaly_detector.py
NAMESPACE = "default"
KUBECTL = "kubectl"
FIXTURE_APP_LABEL = "autosre-fixture"


# ── kubectl plumbing ──────────────────────────────────────────────────────
class KubectlError(RuntimeError):
    pass


def run_kubectl(args, input_text=None, check=True):
    """Run a kubectl command, return CompletedProcess. Raises KubectlError
    on non-zero exit (unless check=False)."""
    cmd = [KUBECTL] + args
    proc = subprocess.run(
        cmd,
        input=input_text,
        capture_output=True,
        text=True,
    )
    if check and proc.returncode != 0:
        raise KubectlError(
            f"`{' '.join(cmd)}` failed (exit {proc.returncode}):\n{proc.stderr.strip()}"
        )
    return proc


def kubectl_available():
    try:
        run_kubectl(["version", "--client", "-o", "json"], check=True)
        run_kubectl(["cluster-info"], check=True)
        return True
    except (KubectlError, FileNotFoundError, OSError):
        return False


def apply_manifest(manifest_yaml, dry_run=False):
    if dry_run:
        print(manifest_yaml)
        return
    run_kubectl(["apply", "-n", NAMESPACE, "-f", "-"], input_text=manifest_yaml)


def delete_by_label(scenario, dry_run=False, wait=True):
    selector = f"app={FIXTURE_APP_LABEL},scenario={scenario}"
    if dry_run:
        print(f"# would run: kubectl delete all,cm -n {NAMESPACE} -l {selector} --ignore-not-found")
        return
    run_kubectl(
        [
            "delete", "deploy,job,pod,svc,cm",
            "-n", NAMESPACE,
            "-l", selector,
            "--ignore-not-found",
            "--wait=" + ("true" if wait else "false"),
            "--timeout=90s",
        ],
        check=False,
    )


def get_pods(scenario):
    selector = f"app={FIXTURE_APP_LABEL},scenario={scenario}"
    proc = run_kubectl(
        ["get", "pods", "-n", NAMESPACE, "-l", selector, "-o", "json"],
        check=False,
    )
    if proc.returncode != 0:
        return []
    try:
        return json.loads(proc.stdout).get("items", [])
    except json.JSONDecodeError:
        return []


def wait_for(predicate, timeout, poll, description):
    """Poll `predicate()` (returns bool) until True or timeout. Returns
    True/False and prints progress so runs are observable/repeatable in
    CI logs."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        if predicate():
            print(f"  ✓ {description}")
            return True
        time.sleep(poll)
    print(f"  ✗ timed out waiting for: {description}")
    return False


# ── Scenario condition checks (used by --wait) ────────────────────────────
def _pod_restart_count_at_least(scenario, n):
    def check():
        pods = get_pods(scenario)
        for pod in pods:
            for cs in pod.get("status", {}).get("containerStatuses", []):
                if cs.get("restartCount", 0) >= n:
                    return True
        return False
    return check


def _pod_waiting_reason(scenario, reason):
    def check():
        pods = get_pods(scenario)
        for pod in pods:
            for cs in pod.get("status", {}).get("containerStatuses", []):
                waiting = cs.get("state", {}).get("waiting", {})
                if waiting.get("reason") == reason:
                    return True
                last = cs.get("lastState", {}).get("terminated", {})
                if last.get("reason") == reason:
                    return True
        return False
    return check


def _pod_running(scenario):
    def check():
        pods = get_pods(scenario)
        return any(p.get("status", {}).get("phase") == "Running" for p in pods)
    return check


def _job_active_or_succeeded(scenario):
    def check():
        proc = run_kubectl(
            ["get", "job", f"autosre-fixture-{scenario.replace('_', '-')}-client",
             "-n", NAMESPACE, "-o", "json"],
            check=False,
        )
        if proc.returncode != 0:
            return False
        try:
            data = json.loads(proc.stdout)
        except json.JSONDecodeError:
            return False
        status = data.get("status", {})
        return status.get("active", 0) > 0 or status.get("succeeded", 0) > 0
    return check


# ── Manifest builders ──────────────────────────────────────────────────────
def _labels(scenario, extra_name=None):
    clean_scenario = scenario.replace("_", "-")
    name = f"autosre-fixture-{clean_scenario}" if not extra_name else f"autosre-fixture-{clean_scenario}-{extra_name}"
    return name


def manifest_oom_kill():
    """Allocates memory in an unbounded loop against a tight limit until
    the kernel OOM-kills the container. Feeds detect_high_memory() (ratio
    climbs toward 1.0) and detect_pod_restarts()/detect_pod_crashes()
    once it starts repeatedly getting OOMKilled."""
    name = _labels("oom_kill")
    return f"""\
apiVersion: apps/v1
kind: Deployment
metadata:
  name: {name}
  namespace: {NAMESPACE}
  labels:
    app: {FIXTURE_APP_LABEL}
    scenario: oom_kill
spec:
  replicas: 1
  selector:
    matchLabels:
      app: {FIXTURE_APP_LABEL}
      scenario: oom_kill
  template:
    metadata:
      labels:
        app: {FIXTURE_APP_LABEL}
        scenario: oom_kill
    spec:
      containers:
        - name: mem-hog
          image: python:3.11-slim
          command: ["python3", "-c"]
          args:
            - |
              import time
              print("starting memory hog", flush=True)
              chunks = []
              while True:
                  chunks.append(bytearray(10 * 1024 * 1024))  # +10MB
                  print("error: memory allocation growing, risk of OOM", flush=True)
                  time.sleep(0.2)
          resources:
            requests:
              memory: "20Mi"
              cpu: "50m"
            limits:
              memory: "40Mi"
              cpu: "200m"
"""


def manifest_crash_loop():
    """Container exits non-zero immediately on every start. kubelet backs
    off restarts -> CrashLoopBackOff, caught directly by
    detect_pod_crashes()."""
    name = _labels("crash_loop")
    return f"""\
apiVersion: apps/v1
kind: Deployment
metadata:
  name: {name}
  namespace: {NAMESPACE}
  labels:
    app: {FIXTURE_APP_LABEL}
    scenario: crash_loop
spec:
  replicas: 1
  selector:
    matchLabels:
      app: {FIXTURE_APP_LABEL}
      scenario: crash_loop
  template:
    metadata:
      labels:
        app: {FIXTURE_APP_LABEL}
        scenario: crash_loop
    spec:
      containers:
        - name: crasher
          image: busybox:1.36
          command: ["sh", "-c"]
          args:
            - "echo 'error: fatal simulated crash on startup' 1>&2; exit 1"
          resources:
            requests: {{memory: "10Mi", cpu: "10m"}}
            limits: {{memory: "20Mi", cpu: "50m"}}
"""


def manifest_high_cpu():
    """Pins ~1 CPU core continuously. Feeds detect_high_cpu(), which fires
    on sum(rate(container_cpu_usage_seconds_total[5m])) > 0.8 (absolute
    cores, not a ratio of the limit)."""
    name = _labels("high_cpu")
    return f"""\
apiVersion: apps/v1
kind: Deployment
metadata:
  name: {name}
  namespace: {NAMESPACE}
  labels:
    app: {FIXTURE_APP_LABEL}
    scenario: high_cpu
spec:
  replicas: 1
  selector:
    matchLabels:
      app: {FIXTURE_APP_LABEL}
      scenario: high_cpu
  template:
    metadata:
      labels:
        app: {FIXTURE_APP_LABEL}
        scenario: high_cpu
    spec:
      containers:
        - name: cpu-hog
          image: polinux/stress
          command: ["stress"]
          args: ["--cpu", "2", "--timeout", "1800s"]
          resources:
            requests: {{cpu: "900m", memory: "32Mi"}}
            limits: {{cpu: "1200m", memory: "64Mi"}}
"""


def manifest_high_memory():
    """Climbs to ~85% of its memory limit and then holds steady (never
    exceeds the limit), so it triggers detect_high_memory() (ratio > 0.8)
    without ever being OOM-killed — a distinct, less catastrophic
    scenario from oom_kill."""
    name = _labels("high_memory")
    return f"""\
apiVersion: apps/v1
kind: Deployment
metadata:
  name: {name}
  namespace: {NAMESPACE}
  labels:
    app: {FIXTURE_APP_LABEL}
    scenario: high_memory
spec:
  replicas: 1
  selector:
    matchLabels:
      app: {FIXTURE_APP_LABEL}
      scenario: high_memory
  template:
    metadata:
      labels:
        app: {FIXTURE_APP_LABEL}
        scenario: high_memory
    spec:
      containers:
        - name: mem-pressure
          image: python:3.11-slim
          command: ["python3", "-c"]
          args:
            - |
              import time
              TARGET_MB = 85          # ~85% of the 100Mi limit below
              chunk = bytearray(1024 * 1024)
              held = []
              for _ in range(TARGET_MB):
                  held.append(bytearray(1024 * 1024))
                  time.sleep(0.05)
              print("error: memory usage holding near limit", flush=True)
              while True:
                  time.sleep(5)
          resources:
            requests: {{memory: "64Mi", cpu: "50m"}}
            limits: {{memory: "100Mi", cpu: "200m"}}
"""


def manifest_restart_storm():
    """The process itself never exits — instead a flapping livenessProbe
    fails roughly 1 out of every 3 checks (counter persisted in an
    emptyDir so it survives container restarts), causing kubelet to
    restart the container repeatedly. This isolates
    detect_pod_restarts()'s restart-count signal from
    detect_pod_crashes()'s CrashLoopBackOff signal (scenario 2)."""
    name = _labels("restart_storm")
    return f"""\
apiVersion: apps/v1
kind: Deployment
metadata:
  name: {name}
  namespace: {NAMESPACE}
  labels:
    app: {FIXTURE_APP_LABEL}
    scenario: restart_storm
spec:
  replicas: 1
  selector:
    matchLabels:
      app: {FIXTURE_APP_LABEL}
      scenario: restart_storm
  template:
    metadata:
      labels:
        app: {FIXTURE_APP_LABEL}
        scenario: restart_storm
    spec:
      volumes:
        - name: counter
          emptyDir: {{}}
      containers:
        - name: flapper
          image: busybox:1.36
          command: ["sh", "-c", "echo 'error: flapping service started' 1>&2; sleep infinity"]
          volumeMounts:
            - name: counter
              mountPath: /data
          livenessProbe:
            exec:
              command:
                - sh
                - -c
                - |
                  N=$(cat /data/count 2>/dev/null || echo 0)
                  N=$((N + 1))
                  echo $N > /data/count
                  test $((N % 3)) -ne 0
            initialDelaySeconds: 5
            periodSeconds: 5
            failureThreshold: 1
          resources:
            requests: {{memory: "10Mi", cpu: "10m"}}
            limits: {{memory: "20Mi", cpu: "50m"}}
"""


def manifest_latency_injection():
    """A backend that sleeps before every response, plus a client Job
    that repeatedly calls it with a tight timeout. Timed-out calls are
    logged as 'ERROR: ... timed out' — exercising the Loki `|= "error"`
    query in telemetry_collector.get_logs_snapshot(), which is what
    build_snapshot() attaches as recent_errors for the LLM diagnosis
    agent."""
    server_name = _labels("latency_injection", "server")
    client_name = _labels("latency_injection", "client")
    return f"""\
apiVersion: apps/v1
kind: Deployment
metadata:
  name: {server_name}
  namespace: {NAMESPACE}
  labels:
    app: {FIXTURE_APP_LABEL}
    scenario: latency_injection
spec:
  replicas: 1
  selector:
    matchLabels:
      app: {FIXTURE_APP_LABEL}
      scenario: latency_injection
      role: server
  template:
    metadata:
      labels:
        app: {FIXTURE_APP_LABEL}
        scenario: latency_injection
        role: server
    spec:
      containers:
        - name: slow-server
          image: python:3.11-slim
          command: ["python3", "-c"]
          args:
            - |
              import http.server, time
              class Slow(http.server.BaseHTTPRequestHandler):
                  def do_GET(self):
                      time.sleep(5)  # artificial latency injection
                      self.send_response(200)
                      self.end_headers()
                      self.wfile.write(b"ok")
                  def log_message(self, fmt, *args):
                      print("info: request served after 5s delay", flush=True)
              http.server.HTTPServer(("0.0.0.0", 8080), Slow).serve_forever()
          ports:
            - containerPort: 8080
          resources:
            requests: {{memory: "32Mi", cpu: "50m"}}
            limits: {{memory: "64Mi", cpu: "200m"}}
---
apiVersion: v1
kind: Service
metadata:
  name: {server_name}
  namespace: {NAMESPACE}
  labels:
    app: {FIXTURE_APP_LABEL}
    scenario: latency_injection
spec:
  selector:
    app: {FIXTURE_APP_LABEL}
    scenario: latency_injection
    role: server
  ports:
    - port: 8080
      targetPort: 8080
---
apiVersion: batch/v1
kind: Job
metadata:
  name: {client_name}
  namespace: {NAMESPACE}
  labels:
    app: {FIXTURE_APP_LABEL}
    scenario: latency_injection
    role: client
spec:
  backoffLimit: 0
  template:
    metadata:
      labels:
        app: {FIXTURE_APP_LABEL}
        scenario: latency_injection
        role: client
    spec:
      restartPolicy: Never
      containers:
        - name: impatient-client
          image: curlimages/curl:8.8.0
          command: ["sh", "-c"]
          args:
            - |
              for i in $(seq 1 20); do
                curl -sS --max-time 2 http://{server_name}:8080/ \\
                  || echo "error: request to {server_name} timed out (attempt $i)"
                sleep 1
              done
          resources:
            requests: {{memory: "8Mi", cpu: "10m"}}
            limits: {{memory: "16Mi", cpu: "50m"}}
"""


# ── Scenario registry ───────────────────────────────────────────────────────
SCENARIOS = {
    "oom_kill": {
        "description": "Container leaks memory until the kernel OOM-kills it",
        "manifest_fn": manifest_oom_kill,
        "expects": "HIGH_MEMORY -> restarts (detect_high_memory / detect_pod_restarts)",
        "wait_fn": lambda: _pod_restart_count_at_least("oom_kill", 1),
        "wait_timeout": 180,
    },
    "crash_loop": {
        "description": "Container exits 1 on every start -> CrashLoopBackOff",
        "manifest_fn": manifest_crash_loop,
        "expects": "CRASH_LOOP (detect_pod_crashes)",
        "wait_fn": lambda: _pod_waiting_reason("crash_loop", "CrashLoopBackOff"),
        "wait_timeout": 180,
    },
    "high_cpu": {
        "description": "Pins ~1 CPU core continuously (stress --cpu 2)",
        "manifest_fn": manifest_high_cpu,
        "expects": "HIGH_CPU (detect_high_cpu)",
        "wait_fn": lambda: _pod_running("high_cpu"),
        "wait_timeout": 120,
    },
    "high_memory": {
        "description": "Holds memory at ~85% of its limit without OOM-killing",
        "manifest_fn": manifest_high_memory,
        "expects": "HIGH_MEMORY (detect_high_memory) without a restart",
        "wait_fn": lambda: _pod_running("high_memory"),
        "wait_timeout": 120,
    },
    "restart_storm": {
        "description": "Flapping livenessProbe restarts the container ~every 15s",
        "manifest_fn": manifest_restart_storm,
        "expects": "POD_RESTART (detect_pod_restarts), repeatedly",
        "wait_fn": lambda: _pod_restart_count_at_least("restart_storm", 1),
        "wait_timeout": 120,
    },
    "latency_injection": {
        "description": "Slow backend (5s/response) + impatient client timing out",
        "manifest_fn": manifest_latency_injection,
        "expects": "error-tagged log lines picked up by get_logs_snapshot()'s Loki query",
        "wait_fn": lambda: _job_active_or_succeeded("latency_injection"),
        "wait_timeout": 90,
    },
}


# ── Commands ────────────────────────────────────────────────────────────────
def cmd_list(_args):
    print(f"{'SCENARIO':<20} {'DETECTOR SIGNAL':<55} DESCRIPTION")
    print("-" * 110)
    for key, spec in SCENARIOS.items():
        print(f"{key:<20} {spec['expects']:<55} {spec['description']}")


def _resolve_scenarios(name):
    if name == "all":
        return list(SCENARIOS.keys())
    if name not in SCENARIOS:
        print(f"[ERROR] unknown scenario '{name}'. Run `list` to see options.")
        sys.exit(1)
    return [name]


def run_scenario(scenario, dry_run=False, wait=False, wait_timeout=None):
    spec = SCENARIOS[scenario]
    print(f"\n=== run: {scenario} — {spec['description']} ===")

    # Repeatability: always tear down any previous instance first so every
    # run starts from the same clean baseline, regardless of prior state.
    print(f"  cleaning up any previous '{scenario}' fixture...")
    delete_by_label(scenario, dry_run=dry_run, wait=True)

    manifest = spec["manifest_fn"]()
    print(f"  applying manifest ({len(manifest.splitlines())} lines)...")
    apply_manifest(manifest, dry_run=dry_run)

    if dry_run:
        print(f"  [dry-run] nothing was sent to the cluster.")
        return

    print(f"  triggered at {datetime.now().isoformat(timespec='seconds')}")
    print(f"  expected detector signal: {spec['expects']}")

    if wait:
        predicate = spec["wait_fn"]()
        timeout = wait_timeout or spec["wait_timeout"]
        wait_for(predicate, timeout=timeout, poll=3,
                 description=f"{scenario} to reach its target failure state")


def cleanup_scenario(scenario, dry_run=False):
    print(f"cleaning up: {scenario}")
    delete_by_label(scenario, dry_run=dry_run, wait=True)


def cmd_run(args):
    if not args.dry_run and not kubectl_available():
        print("[ERROR] kubectl is not configured or the cluster is unreachable.")
        print("        Use --dry-run to preview manifests without a cluster.")
        sys.exit(1)
    for scenario in _resolve_scenarios(args.scenario):
        run_scenario(scenario, dry_run=args.dry_run, wait=args.wait,
                     wait_timeout=args.timeout)
    if not args.dry_run:
        print("\nanomaly_detector.py polls every 30s — it will pick these up on "
              "its next scan (or already has, if it's running).")


def cmd_cleanup(args):
    if not args.dry_run and not kubectl_available():
        print("[ERROR] kubectl is not configured or the cluster is unreachable.")
        sys.exit(1)
    for scenario in _resolve_scenarios(args.scenario):
        cleanup_scenario(scenario, dry_run=args.dry_run)


def cmd_status(_args):
    if not kubectl_available():
        print("[ERROR] kubectl is not configured or the cluster is unreachable.")
        sys.exit(1)
    print(f"{'SCENARIO':<20} {'PODS':<6} {'PHASES / REASONS':<40} RESTARTS")
    print("-" * 90)
    for scenario in SCENARIOS:
        pods = get_pods(scenario)
        if not pods:
            print(f"{scenario:<20} {'0':<6} {'(not deployed)':<40} -")
            continue
        phases = []
        restarts = 0
        for p in pods:
            phase = p.get("status", {}).get("phase", "Unknown")
            reasons = []
            for cs in p.get("status", {}).get("containerStatuses", []):
                restarts += cs.get("restartCount", 0)
                waiting = cs.get("state", {}).get("waiting", {}).get("reason")
                if waiting:
                    reasons.append(waiting)
            phases.append(phase + (f"({','.join(reasons)})" if reasons else ""))
        print(f"{scenario:<20} {len(pods):<6} {', '.join(phases):<40} {restarts}")


def main():
    parser = argparse.ArgumentParser(
        description="AutoSRE — reproducible chaos fixtures for the anomaly "
                     "detector / telemetry collector / LLM diagnosis pipeline",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p_list = sub.add_parser("list", help="List available scenarios")
    p_list.set_defaults(func=cmd_list)

    p_run = sub.add_parser("run", help="Trigger a scenario (or 'all')")
    p_run.add_argument("scenario", choices=list(SCENARIOS.keys()) + ["all"])
    p_run.add_argument("--dry-run", action="store_true",
                        help="Print manifests only; do not touch the cluster")
    p_run.add_argument("--wait", action="store_true",
                        help="Block until the failure condition is observed")
    p_run.add_argument("--timeout", type=int, default=None,
                        help="Override the default wait timeout (seconds)")
    p_run.set_defaults(func=cmd_run)

    p_cleanup = sub.add_parser("cleanup", help="Tear down a scenario (or 'all')")
    p_cleanup.add_argument("scenario", choices=list(SCENARIOS.keys()) + ["all"])
    p_cleanup.add_argument("--dry-run", action="store_true")
    p_cleanup.set_defaults(func=cmd_cleanup)

    p_status = sub.add_parser("status", help="Show current state of all fixtures")
    p_status.set_defaults(func=cmd_status)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()