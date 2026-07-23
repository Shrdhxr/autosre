"""
AutoSRE — LLM Diagnosis Agent
==============================
Sprint 1 deliverable covering all 5 module areas:

  1. Ollama API Client              -> OllamaClient
  2. Diagnosis Prompt & Schema      -> build_diagnosis_prompt(), DIAGNOSIS_SCHEMA
  3. Validation & Reliability       -> validate_diagnosis(), diagnose_with_retry()
  4. Terminal Output Layer          -> render_diagnosis()  (rich, falls back to plain text)
  5. Accuracy Validation            -> --log-only / diagnosis_log.jsonl + --replay

This file is designed to sit in the same `agent/` folder as the existing
`telemetry_collector.py` and `anomaly_detector.py`. It does not modify those
files — it *consumes* what they already produce:

    anomaly_detector.py  --(detects anomaly, calls)-->  telemetry_collector.py
                                    |
                                    v
                         latest_snapshot.json / snapshot_<TYPE>_<TS>.json
                                    |
                                    v
                          llm_diagnosis_agent.py   <-- (this file)
                                    |
                                    v
                     color-coded terminal diagnosis + diagnosis_log.jsonl

USAGE
-----
    # One-shot: diagnose whatever is currently in latest_snapshot.json
    python3 llm_diagnosis_agent.py

    # Point at a specific snapshot file
    python3 llm_diagnosis_agent.py --snapshot snapshot_CRASH_LOOP_2026-07-21_22-14-01.json

    # Watch mode: run alongside anomaly_detector.py, re-diagnose whenever
    # latest_snapshot.json changes on disk
    python3 llm_diagnosis_agent.py --watch

    # Use a different Ollama model / host
    python3 llm_diagnosis_agent.py --model llama3.1 --host http://localhost:11434

    # Accuracy-validation helper: replay every saved snapshot_*.json in the
    # agent folder and log diagnoses for manual review (module 5)
    python3 llm_diagnosis_agent.py --replay

RUN ALONGSIDE THE EXISTING PIPELINE
------------------------------------
Terminal 1:
    python3 anomaly_detector.py

Terminal 2:
    python3 llm_diagnosis_agent.py --watch
"""

import argparse
import json
import os
import sys
import time
from datetime import datetime

import requests

try:
    from jsonschema import validate as _jsonschema_validate
    from jsonschema import ValidationError
    _HAS_JSONSCHEMA = True
except ImportError:
    _HAS_JSONSCHEMA = False

try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table
    from rich.text import Text
    _HAS_RICH = True
except ImportError:
    _HAS_RICH = False
    try:
        import colorama
        colorama.init()
        _HAS_COLORAMA = True
    except ImportError:
        _HAS_COLORAMA = False

AGENT_DIR = os.path.dirname(os.path.abspath(__file__))

# ── Module 1: Ollama API Client ──────────────────────────────────────────
class OllamaClient:
    """Thin wrapper around the Ollama /api/generate endpoint.

    Reuses a single requests.Session for connection pooling and exposes
    the model params (temperature, num_predict, etc.) needed to keep
    diagnosis output short, deterministic, and JSON-only.
    """

    def __init__(self, host="http://localhost:11434", model="llama3.1",
                 timeout=30, temperature=0.2, num_predict=400):
        self.host = host.rstrip("/")
        self.model = model
        self.timeout = timeout
        self.temperature = temperature
        self.num_predict = num_predict
        self.session = requests.Session()

    def is_available(self):
        """Quick health check so we can fail fast with a clear message."""
        try:
            r = self.session.get(f"{self.host}/api/tags", timeout=5)
            return r.status_code == 200
        except requests.exceptions.RequestException:
            return False

    def generate(self, prompt, model=None, json_mode=True, extra_options=None):
        """Send a prompt to Ollama and return the raw text response.

        Raises OllamaTimeoutError / OllamaConnectionError on failure so the
        caller (module 3) can decide how to degrade gracefully.
        """
        options = {"temperature": self.temperature, "num_predict": self.num_predict}
        if extra_options:
            options.update(extra_options)

        payload = {
            "model": model or self.model,
            "prompt": prompt,
            "stream": False,
            "options": options,
        }
        if json_mode:
            payload["format"] = "json"

        try:
            r = self.session.post(
                f"{self.host}/api/generate",
                json=payload,
                timeout=self.timeout,
            )
            r.raise_for_status()
            data = r.json()
            return data.get("response", "")
        except requests.exceptions.Timeout as e:
            raise OllamaTimeoutError(f"Ollama request timed out after {self.timeout}s") from e
        except requests.exceptions.ConnectionError as e:
            raise OllamaConnectionError(
                f"Could not reach Ollama at {self.host} — is `ollama serve` running?"
            ) from e
        except requests.exceptions.RequestException as e:
            raise OllamaConnectionError(f"Ollama request failed: {e}") from e


class OllamaTimeoutError(Exception):
    pass


class OllamaConnectionError(Exception):
    pass


# ── Module 2: Diagnosis Prompt & Schema ──────────────────────────────────
DIAGNOSIS_SCHEMA = {
    "type": "object",
    "properties": {
        "severity": {
            "type": "string",
            "enum": ["CRITICAL", "HIGH", "MEDIUM", "LOW"],
        },
        "affected_service": {"type": "string", "minLength": 1},
        "probable_cause": {"type": "string", "minLength": 1},
        "human_readable_summary": {"type": "string", "minLength": 1},
    },
    "required": [
        "severity",
        "affected_service",
        "probable_cause",
        "human_readable_summary",
    ],
    "additionalProperties": False,
}


def _summarize_metrics(metrics, limit=5):
    """Trim the raw telemetry lists to the top-N most relevant entries so
    the prompt stays small and cheap, and so the model isn't drowned in
    noise from healthy pods."""
    cpu = sorted(metrics.get("cpu_usage", []), key=lambda x: x.get("cpu_cores", 0), reverse=True)[:limit]
    mem = sorted(metrics.get("memory_usage", []), key=lambda x: x.get("memory_mb", 0), reverse=True)[:limit]
    restarts = sorted(metrics.get("restart_counts", []), key=lambda x: x.get("restarts", 0), reverse=True)[:limit]
    crash_loop = metrics.get("crash_loop_pods", [])
    statuses = [s for s in metrics.get("pod_statuses", []) if s.get("phase") != "Running"][:limit]
    return {
        "top_cpu": cpu,
        "top_memory": mem,
        "top_restarts": restarts,
        "crash_loop_pods": crash_loop,
        "non_running_pods": statuses,
    }


def build_diagnosis_prompt(snapshot):
    """Turn a telemetry snapshot (as produced by telemetry_collector.py)
    into a diagnosis prompt with a strict JSON output contract.

    Handles partial/empty snapshots gracefully — missing sections are
    simply reported as "no data available" rather than raising.
    """
    anomaly = snapshot.get("anomaly_event") or {}
    metrics = snapshot.get("metrics") or {}
    errors = snapshot.get("recent_errors") or []
    k8s_events = snapshot.get("k8s_events") or []

    summarized = _summarize_metrics(metrics)

    error_lines = "\n".join(f"  - {e.get('line', e)}" for e in errors[:10]) or "  (no recent error logs captured)"
    restart_lines = "\n".join(
        f"  - {r['pod']}: {r['restarts']} restarts" for r in summarized["top_restarts"]
    ) or "  (no restart data)"
    cpu_lines = "\n".join(
        f"  - {c['pod']}: {c['cpu_cores']} cores" for c in summarized["top_cpu"]
    ) or "  (no CPU data)"
    mem_lines = "\n".join(
        f"  - {m['pod']}: {m['memory_mb']} MB" for m in summarized["top_memory"]
    ) or "  (no memory data)"
    crash_lines = "\n".join(
        f"  - {c['pod']}" for c in summarized["crash_loop_pods"]
    ) or "  (none)"
    non_running = "\n".join(
        f"  - {p['pod']}: {p['phase']}" for p in summarized["non_running_pods"]
    ) or "  (all pods Running)"

    prompt = f"""You are an expert Site Reliability Engineer diagnosing a Kubernetes incident.

TRIGGERING ANOMALY:
  Type      : {anomaly.get('type', 'UNKNOWN')}
  Service   : {anomaly.get('service', 'unknown')}
  Severity  : {anomaly.get('severity', 'UNKNOWN')}
  Message   : {anomaly.get('message', 'n/a')}
  Timestamp : {anomaly.get('timestamp', snapshot.get('timestamp', 'n/a'))}

CLUSTER TELEMETRY (namespace: {snapshot.get('namespace', 'default')}):

Pods in CrashLoopBackOff:
{crash_lines}

Pods not in Running phase:
{non_running}

Top restart counts:
{restart_lines}

Top CPU usage:
{cpu_lines}

Top memory usage:
{mem_lines}

Recent error logs (namespace-wide, truncated):
{error_lines}

Additional k8s restart events observed: {len(k8s_events)}

TASK:
Diagnose the most likely root cause of this incident. Respond with ONLY a
single JSON object — no markdown, no code fences, no commentary — matching
exactly this schema:

{{
  "severity": "CRITICAL" | "HIGH" | "MEDIUM" | "LOW",
  "affected_service": "<the pod/service most responsible>",
  "probable_cause": "<concise technical root-cause hypothesis>",
  "human_readable_summary": "<1-2 sentence plain-English summary for an on-call engineer>"
}}

If telemetry is sparse or missing, say so honestly in probable_cause rather
than inventing details."""
    return prompt


# ── Module 3: Validation & Reliability ───────────────────────────────────
def _strip_code_fences(text):
    text = text.strip()
    if text.startswith("```"):
        lines = text.splitlines()
        lines = [l for l in lines if not l.strip().startswith("```")]
        text = "\n".join(lines).strip()
    return text


def parse_and_validate(raw_text):
    """Parse the model's raw text as JSON and validate against
    DIAGNOSIS_SCHEMA. Raises ValueError with a human-readable reason on
    any failure so the retry loop can feed that reason back to the model.
    """
    cleaned = _strip_code_fences(raw_text)
    try:
        data = json.loads(cleaned)
    except json.JSONDecodeError as e:
        raise ValueError(f"response was not valid JSON: {e}")

    if not isinstance(data, dict):
        raise ValueError("response JSON must be an object")

    if _HAS_JSONSCHEMA:
        try:
            _jsonschema_validate(instance=data, schema=DIAGNOSIS_SCHEMA)
        except ValidationError as e:
            raise ValueError(f"schema validation failed: {e.message}")
    else:
        # Minimal manual fallback if jsonschema isn't installed
        for field in DIAGNOSIS_SCHEMA["required"]:
            if field not in data or not str(data[field]).strip():
                raise ValueError(f"missing required field '{field}'")
        if data.get("severity") not in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
            raise ValueError("severity must be one of CRITICAL/HIGH/MEDIUM/LOW")

    return data


def validate_diagnosis(data):
    """Public helper matching the module-3 spec name; re-validates an
    already-parsed dict (useful for --replay / testing)."""
    if _HAS_JSONSCHEMA:
        _jsonschema_validate(instance=data, schema=DIAGNOSIS_SCHEMA)
    else:
        for field in DIAGNOSIS_SCHEMA["required"]:
            if field not in data:
                raise ValueError(f"missing required field '{field}'")
    return True


def _rule_based_fallback(snapshot, reason):
    """Last-resort diagnosis when Ollama is unreachable or every retry
    produced malformed output. Keeps the pipeline useful even with the
    LLM offline, and makes the failure mode visible instead of crashing."""
    anomaly = snapshot.get("anomaly_event") or {}
    metrics = snapshot.get("metrics") or {}
    crash_pods = metrics.get("crash_loop_pods", [])

    if crash_pods:
        service = crash_pods[0].get("pod", anomaly.get("service", "unknown"))
        cause = "Pod is in CrashLoopBackOff — likely a startup/config error or repeated container crash."
    elif anomaly:
        service = anomaly.get("service", "unknown")
        cause = anomaly.get("message", "Unspecified anomaly detected by anomaly_detector.py.")
    else:
        service = "unknown"
        cause = "No anomaly event or crash-loop data present in snapshot."

    return {
        "severity": anomaly.get("severity", "MEDIUM"),
        "affected_service": service,
        "probable_cause": f"[FALLBACK — LLM unavailable: {reason}] {cause}",
        "human_readable_summary": (
            "LLM diagnosis unavailable; showing a rule-based best guess from raw telemetry. "
            "Check Ollama connectivity and re-run for a full diagnosis."
        ),
        "_fallback": True,
    }


def diagnose_with_retry(client, snapshot, max_retries=3):
    """Module 3 entry point: get a schema-valid diagnosis from Ollama,
    retrying with the validation error fed back into the prompt on
    malformed output. Falls back to a rule-based diagnosis if Ollama is
    unreachable or every retry still fails.
    """
    if not client.is_available():
        return _rule_based_fallback(
            snapshot, f"no response from {client.host} (connection check failed)"
        )

    base_prompt = build_diagnosis_prompt(snapshot)
    prompt = base_prompt
    last_error = None

    for attempt in range(1, max_retries + 1):
        try:
            raw = client.generate(prompt)
        except (OllamaTimeoutError, OllamaConnectionError) as e:
            last_error = str(e)
            # Don't burn retries on a dead connection — degrade immediately
            return _rule_based_fallback(snapshot, last_error)

        try:
            data = parse_and_validate(raw)
            data["_attempt"] = attempt
            data["_fallback"] = False
            return data
        except ValueError as e:
            last_error = str(e)
            prompt = (
                f"{base_prompt}\n\nYour previous response was invalid: {last_error}\n"
                f"Previous response was:\n{raw}\n\n"
                f"Return ONLY the corrected JSON object, matching the schema exactly."
            )

    return _rule_based_fallback(snapshot, f"model failed to produce valid JSON after {max_retries} attempts ({last_error})")


# ── Module 4: Terminal Output Layer ──────────────────────────────────────
_SEVERITY_COLOR_RICH = {
    "CRITICAL": "bold white on red",
    "HIGH": "bold red",
    "MEDIUM": "bold yellow",
    "LOW": "bold green",
}
_SEVERITY_COLOR_ANSI = {
    "CRITICAL": "\033[1;97;41m",
    "HIGH": "\033[1;31m",
    "MEDIUM": "\033[1;33m",
    "LOW": "\033[1;32m",
}
_ANSI_RESET = "\033[0m"


def render_diagnosis(diagnosis, snapshot=None):
    severity = diagnosis.get("severity", "UNKNOWN")

    if _HAS_RICH:
        console = Console()
        table = Table.grid(padding=(0, 1))
        table.add_column(style="bold")
        table.add_column()
        table.add_row("Severity:", Text(severity, style=_SEVERITY_COLOR_RICH.get(severity, "bold")))
        table.add_row("Service:", diagnosis.get("affected_service", "unknown"))
        table.add_row("Cause:", diagnosis.get("probable_cause", "n/a"))
        table.add_row("Summary:", diagnosis.get("human_readable_summary", "n/a"))
        if diagnosis.get("_fallback"):
            table.add_row("Mode:", "[italic]rule-based fallback (LLM unavailable)[/italic]")

        border_style = {
            "CRITICAL": "red",
            "HIGH": "red",
            "MEDIUM": "yellow",
            "LOW": "green",
        }.get(severity, "white")

        console.print(
            Panel(
                table,
                title="[bold]AutoSRE Diagnosis[/bold]",
                subtitle=diagnosis.get("_attempt") and f"resolved on attempt {diagnosis['_attempt']}",
                border_style=border_style,
            )
        )
    else:
        color = _SEVERITY_COLOR_ANSI.get(severity, "") if (_HAS_COLORAMA or sys.platform != "win32") else ""
        reset = _ANSI_RESET if color else ""
        print("\n" + "=" * 60)
        print(f"  AutoSRE Diagnosis")
        print("=" * 60)
        print(f"  Severity : {color}{severity}{reset}")
        print(f"  Service  : {diagnosis.get('affected_service', 'unknown')}")
        print(f"  Cause    : {diagnosis.get('probable_cause', 'n/a')}")
        print(f"  Summary  : {diagnosis.get('human_readable_summary', 'n/a')}")
        if diagnosis.get("_fallback"):
            print("  Mode     : rule-based fallback (LLM unavailable)")
        print("=" * 60 + "\n")


# ── Module 5: Accuracy Validation ────────────────────────────────────────
def log_diagnosis(snapshot, diagnosis, log_path=None):
    """Append every diagnosis (with the anomaly that triggered it) to a
    JSONL log so it can be manually reviewed against real induced
    failures later — this is the artifact module 5 validates against."""
    log_path = log_path or os.path.join(AGENT_DIR, "diagnosis_log.jsonl")
    entry = {
        "logged_at": datetime.now().isoformat(),
        "anomaly_event": snapshot.get("anomaly_event"),
        "diagnosis": {k: v for k, v in diagnosis.items() if not k.startswith("_")},
        "fallback": diagnosis.get("_fallback", False),
    }
    with open(log_path, "a") as f:
        f.write(json.dumps(entry) + "\n")
    return log_path


def replay_all_snapshots(client, max_retries):
    """Module 5 helper: re-run diagnosis on every snapshot_*.json file
    already sitting in the agent folder, so you can compare LLM output
    against the failures you actually induced during testing."""
    snapshot_files = sorted(
        f for f in os.listdir(AGENT_DIR)
        if f.startswith("snapshot_") and f.endswith(".json")
    )
    if not snapshot_files:
        print("No snapshot_*.json files found to replay in", AGENT_DIR)
        return

    print(f"Replaying {len(snapshot_files)} saved snapshot(s) for accuracy validation...\n")
    for fname in snapshot_files:
        path = os.path.join(AGENT_DIR, fname)
        print(f"--- {fname} ---")
        try:
            with open(path) as f:
                snapshot = json.load(f)
        except (OSError, json.JSONDecodeError) as e:
            print(f"  [skip] could not read snapshot: {e}")
            continue

        diagnosis = diagnose_with_retry(client, snapshot, max_retries=max_retries)
        render_diagnosis(diagnosis, snapshot)
        log_diagnosis(snapshot, diagnosis)


# ── Main / CLI ────────────────────────────────────────────────────────────
def load_snapshot(path):
    with open(path) as f:
        return json.load(f)


def diagnose_once(client, snapshot_path, max_retries, log_path=None):
    if not os.path.exists(snapshot_path):
        print(f"[ERROR] Snapshot file not found: {snapshot_path}")
        print("Run anomaly_detector.py (or telemetry_collector.py) first to generate one.")
        return
    try:
        snapshot = load_snapshot(snapshot_path)
    except json.JSONDecodeError as e:
        print(f"[ERROR] {snapshot_path} is not valid JSON (partial write?): {e}")
        return

    diagnosis = diagnose_with_retry(client, snapshot, max_retries=max_retries)
    render_diagnosis(diagnosis, snapshot)
    log_diagnosis(snapshot, diagnosis, log_path)


def watch_snapshot(client, snapshot_path, max_retries, interval, log_path=None):
    print(f"[Watch] Watching {snapshot_path} for changes (Ctrl+C to stop)...")
    last_mtime = None
    try:
        while True:
            if os.path.exists(snapshot_path):
                mtime = os.path.getmtime(snapshot_path)
                if mtime != last_mtime:
                    last_mtime = mtime
                    print(f"\n[Watch] Change detected at {datetime.now().strftime('%H:%M:%S')} — diagnosing...")
                    diagnose_once(client, snapshot_path, max_retries, log_path)
            time.sleep(interval)
    except KeyboardInterrupt:
        print("\n[Watch] Stopped.")


def main():
    parser = argparse.ArgumentParser(description="AutoSRE LLM Diagnosis Agent")
    parser.add_argument(
        "--snapshot", default=os.path.join(AGENT_DIR, "latest_snapshot.json"),
        help="Path to a telemetry snapshot JSON (default: latest_snapshot.json next to this script)",
    )
    parser.add_argument("--host", default=os.environ.get("OLLAMA_HOST", "http://localhost:11434"),
                        help="Ollama host URL")
    parser.add_argument("--model", default=os.environ.get("OLLAMA_MODEL", "llama3.1"),
                        help="Ollama model name")
    parser.add_argument("--max-retries", type=int, default=3,
                        help="Max retries when the model returns malformed/invalid JSON")
    parser.add_argument("--timeout", type=int, default=30, help="Ollama request timeout in seconds")
    parser.add_argument("--watch", action="store_true",
                        help="Continuously watch the snapshot file and re-diagnose on change")
    parser.add_argument("--interval", type=int, default=5, help="Poll interval in seconds for --watch")
    parser.add_argument("--replay", action="store_true",
                        help="Replay every saved snapshot_*.json for accuracy validation")
    parser.add_argument("--log", default=None, help="Path to diagnosis log JSONL (default: diagnosis_log.jsonl)")
    args = parser.parse_args()

    client = OllamaClient(host=args.host, model=args.model, timeout=args.timeout)

    print("=" * 60)
    print("  AutoSRE — LLM Diagnosis Agent")
    print(f"  Ollama: {args.host}  |  Model: {args.model}")
    print("=" * 60)

    if args.replay:
        replay_all_snapshots(client, args.max_retries)
    elif args.watch:
        watch_snapshot(client, args.snapshot, args.max_retries, args.interval, args.log)
    else:
        diagnose_once(client, args.snapshot, args.max_retries, args.log)


if __name__ == "__main__":
    main()