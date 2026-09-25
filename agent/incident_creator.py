from kubernetes import client, config
from kubernetes.client.rest import ApiException
import uuid
from datetime import datetime

# ── Load Kubernetes config ────────────────────────────────────────
try:
    config.load_kube_config()
except Exception:
    config.load_incluster_config()  # fallback if ever run inside the cluster

custom_api = client.CustomObjectsApi()

GROUP    = "autosre.io"
VERSION  = "v1"
PLURAL   = "autosreincidents"
NAMESPACE = "default"


def create_incident(diagnosis, anomaly_event=None):
    """
    Takes a diagnosis dict (from llm_diagnosis_agent.py) and creates
    an AutoSREIncident object in Kubernetes. The kopf operator will
    automatically pick this up and execute the recommended action.
    """
    incident_name = f"incident-{uuid.uuid4().hex[:8]}"

    body = {
        "apiVersion": f"{GROUP}/{VERSION}",
        "kind": "AutoSREIncident",
        "metadata": {
            "name": incident_name,
            "namespace": NAMESPACE,
            "labels": {
                "autosre.io/created-by": "llm-diagnosis-agent",
            }
        },
        "spec": {
            "service":           diagnosis.get("affected_service", "unknown"),
            "anomalyType":       (anomaly_event or {}).get("type", "UNKNOWN"),
            "severity":          diagnosis.get("severity", "MEDIUM"),
            "diagnosis":         diagnosis.get("probable_cause", ""),
            "recommendedAction": diagnosis.get("recommended_action", "none"),
            "confidence":        float(diagnosis.get("confidence", 0.5)),
        },
        "status": {
            "phase": "Pending",
        }
    }

    try:
        result = custom_api.create_namespaced_custom_object(
            group=GROUP,
            version=VERSION,
            namespace=NAMESPACE,
            plural=PLURAL,
            body=body,
        )
        print(f"[IncidentCreator] ✅ Created AutoSREIncident: {incident_name}")
        print(f"[IncidentCreator]    service={body['spec']['service']} action={body['spec']['recommendedAction']}")
        return incident_name
    except ApiException as e:
        print(f"[IncidentCreator] ❌ Failed to create incident: {e.reason}")
        return None


if __name__ == "__main__":
    # Quick manual test
    test_diagnosis = {
        "severity": "CRITICAL",
        "affected_service": "loadgenerator",
        "probable_cause": "Test — verifying incident_creator.py works end to end",
        "human_readable_summary": "This is a manual test of the incident creator.",
        "recommended_action": "restart_pod",
        "confidence": 0.9,
    }
    create_incident(test_diagnosis)