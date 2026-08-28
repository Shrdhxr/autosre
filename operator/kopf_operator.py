import kopf
import kubernetes
from kubernetes import client, config
import logging
import sys
import os
import time
from datetime import datetime, timedelta

sys.path.append(os.path.join(os.path.dirname(__file__), "..", "agent"))
from vector_memory import store_incident

# ── Human Approval Gate ──────────────────────────────────────────
# "manual" = pause and ask before every action
# "auto"   = execute immediately, no human gate
APPROVAL_MODE = os.getenv("AUTOSRE_APPROVAL_MODE", "manual")

# ── Namespace allow-list ──────────────────────────────────────────
ALLOWED_NAMESPACES = os.getenv("AUTOSRE_ALLOWED_NAMESPACES", "default").split(",")

def is_namespace_allowed(namespace):
    return namespace in ALLOWED_NAMESPACES


# ── Audit log ──────────────────────────────────────────────────────
AUDIT_LOG_PATH = os.path.join(os.path.dirname(__file__), "..", "agent", "audit_log.jsonl")

def audit_log(incident_name, service, namespace, action, event, details=""):
    """Appends a structured record of every operator decision to an audit trail."""
    import json
    entry = {
        "timestamp":     datetime.now().isoformat(),
        "incident":      incident_name,
        "service":       service,
        "namespace":     namespace,
        "action":        action,
        "event":         event,   # e.g. BLOCKED, APPROVED, DENIED, SUCCEEDED, FAILED, CIRCUIT_BREAKER
        "details":       details,
    }
    try:
        with open(AUDIT_LOG_PATH, "a") as f:
            f.write(json.dumps(entry) + "\n")
    except Exception as e:
        print(f"[AuditLog] Warning: failed to write audit entry: {e}")

def request_approval(incident_name, service, action, severity, diagnosis):
    """Blocks and asks a human to approve or deny a remediation action."""
    print("\n" + "=" * 60)
    print("  🔒 APPROVAL REQUIRED")
    print("=" * 60)
    print(f"  Incident : {incident_name}")
    print(f"  Service  : {service}")
    print(f"  Action   : {action}")
    print(f"  Severity : {severity}")
    print(f"  Reason   : {diagnosis}")
    print("=" * 60)
    while True:
        answer = input("  Approve this remediation action? [y/n]: ").strip().lower()
        if answer in ("y", "yes"):
            return True
        if answer in ("n", "no"):
            return False
        print("  Please type 'y' or 'n'.")

# Import our event bus so the operator can publish completion events
sys.path.append(os.path.join(os.path.dirname(__file__), "..", "agent"))
from event_bus import publish_remediation_completed

# ── Load Kubernetes config ────────────────────────────────────────
# Since we're running this from outside the cluster (on your laptop),
# we use the local kubeconfig (~/.kube/config) instead of in-cluster config
config.load_kube_config()

apps_v1 = client.AppsV1Api()
core_v1 = client.CoreV1Api()
custom_api = client.CustomObjectsApi()

logging.basicConfig(level=logging.INFO)


# ── Remediation Actions ───────────────────────────────────────────
def restart_pod(service, namespace="default"):
    """Performs a rolling restart of a deployment by patching an annotation."""
    try:
        now = datetime.now().isoformat()
        body = {
            "spec": {
                "template": {
                    "metadata": {
                        "annotations": {
                            "autosre.io/restartedAt": now
                        }
                    }
                }
            }
        }
        apps_v1.patch_namespaced_deployment(
            name=service,
            namespace=namespace,
            body=body
        )
        return True, f"Deployment {service} restarted successfully"
    except client.exceptions.ApiException as e:
        return False, f"Failed to restart {service}: {e.reason}"


def scale_deployment(service, namespace="default", replicas=3):
    """Scales a deployment to the specified replica count."""
    try:
        body = {"spec": {"replicas": replicas}}
        apps_v1.patch_namespaced_deployment_scale(
            name=service,
            namespace=namespace,
            body=body
        )
        return True, f"Deployment {service} scaled to {replicas} replicas"
    except client.exceptions.ApiException as e:
        return False, f"Failed to scale {service}: {e.reason}"


def rollback_deployment(service, namespace="default"):
    """Rolls back a deployment to its previous revision."""
    try:
        # Get the deployment's rollout history
        apps_v1.read_namespaced_deployment(name=service, namespace=namespace)

        # Kubernetes Python client doesn't have a direct "rollback" call,
        # so we use kubectl under the hood for this specific action
        import subprocess
        result = subprocess.run(
            ["kubectl", "rollout", "undo", f"deployment/{service}", "-n", namespace],
            capture_output=True, text=True
        )
        if result.returncode == 0:
            return True, f"Deployment {service} rolled back successfully"
        else:
            return False, f"Rollback failed: {result.stderr}"
    except Exception as e:
        return False, f"Failed to rollback {service}: {str(e)}"


# ── Action Dispatcher ─────────────────────────────────────────────
ACTION_MAP = {
    "restart_pod":         restart_pod,
    "scale_deployment":    scale_deployment,
    "rollback_deployment": rollback_deployment,
}


def execute_action(action, service, namespace="default"):
    """Looks up and executes the correct remediation function."""
    handler = ACTION_MAP.get(action)
    if not handler:
        return False, f"Unknown action: {action}"
    return handler(service, namespace)


# ── In-memory cooldown tracker ────────────────────────────────────
# Tracks the last time each service was remediated to prevent thrashing
_last_remediation = {}  # { "service_name": datetime }
COOLDOWN_SECONDS = 60  # don't remediate the same service twice within 60s


def is_in_cooldown(service):
    """Check if this service was remediated too recently."""
    last_time = _last_remediation.get(service)
    if last_time is None:
        return False
    elapsed = (datetime.now() - last_time).total_seconds()
    return elapsed < COOLDOWN_SECONDS


def mark_remediated(service):
    """Record that this service was just remediated."""
    _last_remediation[service] = datetime.now()


# ── kopf Handler with Retry + Idempotency ─────────────────────────
@kopf.on.create('autosre.io', 'v1', 'autosreincidents')
def on_incident_created(spec, status, namespace, name, patch, logger, retry, **kwargs):
    service   = spec.get("service")
    action    = spec.get("recommendedAction", "none")
    severity  = spec.get("severity")

    logger.info(f"🔔 Incident received: {name} | service={service} | action={action} | attempt={retry + 1}")

    # ── Namespace allow-list guard ───────────────────────────────
    if not is_namespace_allowed(namespace):
        patch.status["phase"] = "Failed"
        patch.status["message"] = f"Namespace '{namespace}' is not in the allowed list — action blocked"
        logger.error(f"🚫 BLOCKED: namespace '{namespace}' not allowed for {name}")
        audit_log(name, service, namespace, action, "BLOCKED", f"Namespace '{namespace}' not in allow-list")
        publish_remediation_completed(
            service=service, action=action, success=False,
            details=f"Blocked — namespace '{namespace}' not allowed"
        )
        return

    # ── Idempotency Guard 1: Already completed? ────────────────────
    if status.get("phase") == "Completed":
        logger.info(f"⏭️  Incident {name} already marked Completed — skipping duplicate execution")
        return

    # ── Idempotency Guard 2: Max retries exceeded? ──────────────────
    MAX_RETRIES = 3
    if retry >= MAX_RETRIES:
        patch.status["phase"] = "Failed"
        patch.status["message"] = f"Exceeded max retries ({MAX_RETRIES}) — circuit breaker triggered"
        logger.error(f"🛑 Circuit breaker: {name} failed {MAX_RETRIES} times, giving up")
        audit_log(name, service, namespace, action, "CIRCUIT_BREAKER", f"Failed {MAX_RETRIES} times")
        publish_remediation_completed(
            service=service, action=action, success=False,
            details=f"Circuit breaker triggered after {MAX_RETRIES} failed attempts"
        )
        return

    # ── Cooldown Guard: Was this service JUST remediated? ───────────
    if is_in_cooldown(service):
        patch.status["phase"] = "Skipped"
        patch.status["message"] = f"Service {service} was remediated within the last {COOLDOWN_SECONDS}s — skipping to prevent thrashing"
        logger.warning(f"⏳ Cooldown active for {service} — skipping to prevent thrashing")
        audit_log(name, service, namespace, action, "COOLDOWN_SKIPPED", f"Within {COOLDOWN_SECONDS}s cooldown window")
        return

    if action == "none" or not action:
        patch.status["phase"] = "Completed"
        patch.status["message"] = "No action required"
        logger.info(f"No remediation action needed for {name}")
        audit_log(name, service, namespace, action, "NO_ACTION", "LLM recommended no action")
        return

    # ── Human approval gate ──────────────────────────────────────
    if APPROVAL_MODE == "manual":
        patch.status["phase"] = "AwaitingApproval"
        patch.status["approvalState"] = "Waiting"
        approved = request_approval(
            name, service, action, severity, spec.get("diagnosis", "")
        )
        if not approved:
            patch.status["phase"] = "Failed"
            patch.status["approvalState"] = "Denied"
            patch.status["message"] = "Remediation denied by operator (human approval gate)"
            logger.warning(f"🙅 Remediation denied by human for {name}")
            audit_log(name, service, namespace, action, "DENIED", "Human denied via approval gate")
            publish_remediation_completed(
                service=service, action=action, success=False,
                details="Denied by human approval gate"
            )
            return
        patch.status["approvalState"] = "Approved"
        audit_log(name, service, namespace, action, "APPROVED", "Human approved via approval gate")
    else:
        patch.status["approvalState"] = "NotRequired"
        audit_log(name, service, namespace, action, "AUTO_APPROVED", "AUTOSRE_APPROVAL_MODE=auto")

    patch.status["phase"] = "Executing"

    # ── Execute the remediation action ──────────────────────────────
    logger.info(f"⚙️  Executing action '{action}' on service '{service}'...")
    success, message = execute_action(action, service, namespace)

    if success:
        patch.status["phase"] = "Completed"
        patch.status["message"] = message
        mark_remediated(service)
        logger.info(f"✅ {message}")
        audit_log(name, service, namespace, action, "SUCCEEDED", message)

        try:
            anomaly_event_for_memory = {
                "type": spec.get("anomalyType", "UNKNOWN"),
                "service": service,
                "message": spec.get("diagnosis", "")
            }
            diagnosis_for_memory = {
                "severity": severity,
                "probable_cause": spec.get("diagnosis", ""),
                "human_readable_summary": spec.get("diagnosis", "")
            }
            store_incident(anomaly_event_for_memory, diagnosis_for_memory, action, success=True, details=message)
        except Exception as e:
            logger.warning(f"Could not store incident in vector memory: {e}")
            
    else:
        patch.status["phase"] = "Retrying"
        patch.status["message"] = f"Attempt {retry + 1} failed: {message}"
        logger.warning(f"⚠️  Attempt {retry + 1} failed: {message}")
        audit_log(name, service, namespace, action, "FAILED", f"Attempt {retry + 1}: {message}")

        publish_remediation_completed(
            service=service, action=action, success=False,
            details=f"Attempt {retry + 1}: {message}"
        )

        raise kopf.TemporaryError(message, delay=10)

    try:
        publish_remediation_completed(
            service=service, action=action, success=success, details=message
        )
    except Exception as e:
        logger.warning(f"Could not publish to event bus: {e}")


@kopf.on.update('autosre.io', 'v1', 'autosreincidents')
def on_incident_updated(spec, old, new, diff, logger, **kwargs):
    """Triggered whenever an existing incident is modified."""
    logger.info(f"Incident updated: {diff}")


if __name__ == "__main__":
    kopf.run()