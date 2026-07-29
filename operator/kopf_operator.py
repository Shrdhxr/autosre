import kopf
import kubernetes
from kubernetes import client, config
import logging
import sys
import os

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
        import datetime
        now = datetime.datetime.utcnow().isoformat()
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


# ── kopf Handlers ─────────────────────────────────────────────────
@kopf.on.create('autosre.io', 'v1', 'autosreincidents')
def on_incident_created(spec, status, namespace, name, patch, logger, **kwargs):
    """
    Triggered automatically whenever a new AutoSREIncident object
    is created in the cluster.
    """
    service           = spec.get("service")
    action            = spec.get("recommendedAction", "none")
    severity          = spec.get("severity")
    diagnosis         = spec.get("diagnosis", "")

    logger.info(f"🔔 New incident received: {name} | service={service} | action={action}")

    # Update status to show we're processing it
    patch.status["phase"] = "Executing"

    if action == "none" or not action:
        patch.status["phase"] = "Completed"
        patch.status["message"] = "No action required"
        logger.info(f"No remediation action needed for {name}")
        return

    # Execute the remediation action
    logger.info(f"⚙️  Executing action '{action}' on service '{service}'...")
    success, message = execute_action(action, service, namespace)

    # Update the incident's status
    if success:
        patch.status["phase"] = "Completed"
        patch.status["message"] = message
        logger.info(f"✅ {message}")
    else:
        patch.status["phase"] = "Failed"
        patch.status["message"] = message
        logger.error(f"❌ {message}")

    # Publish completion event to Redis Streams
    try:
        publish_remediation_completed(
            service=service,
            action=action,
            success=success,
            details=message
        )
    except Exception as e:
        logger.warning(f"Could not publish to event bus: {e}")


@kopf.on.update('autosre.io', 'v1', 'autosreincidents')
def on_incident_updated(spec, old, new, diff, logger, **kwargs):
    """Triggered whenever an existing incident is modified."""
    logger.info(f"Incident updated: {diff}")


if __name__ == "__main__":
    kopf.run()