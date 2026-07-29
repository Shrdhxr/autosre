import kopf
import kubernetes
from kubernetes import client, config
import logging
import sys
import os
import time
from datetime import datetime, timedelta

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
    """
    Triggered automatically whenever a new AutoSREIncident object
    is created. Includes idempotency checks and retry-aware logic.

    `retry` is provided automatically by kopf — it's the number of
    times this specific handler has been retried for this object.
    """
    service   = spec.get("service")
    action    = spec.get("recommendedAction", "none")
    severity  = spec.get("severity")

    logger.info(f"🔔 Incident received: {name} | service={service} | action={action} | attempt={retry + 1}")

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
        return

    patch.status["phase"] = "Executing"

    if action == "none" or not action:
        patch.status["phase"] = "Completed"
        patch.status["message"] = "No action required"
        logger.info(f"No remediation action needed for {name}")
        return

    # ── Execute the remediation action ──────────────────────────────
    logger.info(f"⚙️  Executing action '{action}' on service '{service}'...")
    success, message = execute_action(action, service, namespace)

    if success:
        patch.status["phase"] = "Completed"
        patch.status["message"] = message
        mark_remediated(service)  # start the cooldown timer
        logger.info(f"✅ {message}")
    else:
        # Let kopf retry automatically by raising an exception.
        # kopf will re-run this handler with retry+1 next time,
        # respecting the MAX_RETRIES guard above.
        patch.status["phase"] = "Retrying"
        patch.status["message"] = f"Attempt {retry + 1} failed: {message}"
        logger.warning(f"⚠️  Attempt {retry + 1} failed: {message}")

        publish_remediation_completed(
            service=service, action=action, success=False,
            details=f"Attempt {retry + 1}: {message}"
        )

        raise kopf.TemporaryError(message, delay=10)  # retry after 10s

    # ── Publish success event ────────────────────────────────────────
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