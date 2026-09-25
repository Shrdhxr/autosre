import redis
import json
import os
from datetime import datetime

# ── Config ────────────────────────────────────────────────────────
REDIS_HOST = os.getenv("REDIS_HOST", "localhost")
REDIS_PORT = int(os.getenv("REDIS_PORT", 6379))

# Stream names — our three event types
STREAM_INCIDENT_DETECTED     = "incident.detected"
STREAM_REMEDIATION_REQUESTED = "remediation.requested"
STREAM_REMEDIATION_COMPLETED = "remediation.completed"

# ── Redis connection ──────────────────────────────────────────────
def get_client():
    return redis.Redis(
        host=REDIS_HOST,
        port=REDIS_PORT,
        decode_responses=True  # returns strings instead of bytes
    )

# ── Publish events ────────────────────────────────────────────────
def publish_incident_detected(anomaly_event, snapshot_file=None):
    """Called by anomaly_detector.py when a new anomaly is found."""
    client = get_client()
    event = {
        "event_type":    STREAM_INCIDENT_DETECTED,
        "timestamp":     datetime.now().isoformat(),
        "anomaly_type":  anomaly_event.get("type"),
        "service":       anomaly_event.get("service"),
        "severity":      anomaly_event.get("severity"),
        "message":       anomaly_event.get("message"),
        "snapshot_file": snapshot_file or "",
    }
    event_id = client.xadd(STREAM_INCIDENT_DETECTED, event)
    print(f"[EventBus] Published incident.detected — id={event_id} service={event['service']}")
    return event_id

def publish_remediation_requested(service, action, diagnosis_summary="", confidence=0.0):
    """Called by the LLM agent after it decides on a fix."""
    client = get_client()
    event = {
        "event_type":        STREAM_REMEDIATION_REQUESTED,
        "timestamp":         datetime.now().isoformat(),
        "service":           service,
        "action":            action,  # restart_pod | scale_deployment | rollback_deployment
        "diagnosis_summary": diagnosis_summary,
        "confidence":        str(confidence),
    }
    event_id = client.xadd(STREAM_REMEDIATION_REQUESTED, event)
    print(f"[EventBus] Published remediation.requested — id={event_id} action={action} service={service}")
    return event_id

def publish_remediation_completed(service, action, success, details=""):
    """Called by the kopf operator after executing a fix."""
    client = get_client()
    event = {
        "event_type": STREAM_REMEDIATION_COMPLETED,
        "timestamp":  datetime.now().isoformat(),
        "service":    service,
        "action":     action,
        "success":    str(success),
        "details":    details,
    }
    event_id = client.xadd(STREAM_REMEDIATION_COMPLETED, event)
    print(f"[EventBus] Published remediation.completed — id={event_id} success={success}")
    return event_id

# ── Read events ───────────────────────────────────────────────────
def read_stream(stream_name, count=10, last_id="0"):
    """Read events from a stream starting after last_id."""
    client = get_client()
    results = client.xrange(stream_name, min=f"({last_id}" if last_id != "0" else "-", max="+", count=count)
    return results

def read_latest(stream_name, count=5):
    """Read the most recent N events from a stream."""
    client = get_client()
    results = client.xrevrange(stream_name, count=count)
    return list(reversed(results))  # oldest to newest

# ── Test / Demo ───────────────────────────────────────────────────
if __name__ == "__main__":
    print("=" * 55)
    print("  AutoSRE Event Bus — Test")
    print("=" * 55)

    # Test connection
    client = get_client()
    try:
        client.ping()
        print("✓ Connected to Redis successfully\n")
    except redis.exceptions.ConnectionError:
        print("✗ Could not connect to Redis. Is the port-forward running?")
        exit(1)

    # Publish a test incident
    test_anomaly = {
        "type":     "CRASH_LOOP",
        "service":  "test-service",
        "severity": "CRITICAL",
        "message":  "Test anomaly for event bus verification"
    }
    publish_incident_detected(test_anomaly, snapshot_file="test_snapshot.json")

    # Publish a test remediation request
    publish_remediation_requested(
        service="test-service",
        action="restart_pod",
        diagnosis_summary="Test diagnosis",
        confidence=0.85
    )

    # Publish a test completion
    publish_remediation_completed(
        service="test-service",
        action="restart_pod",
        success=True,
        details="Pod restarted successfully"
    )

    # Read back the events
    print("\n--- Reading back incident.detected stream ---")
    events = read_latest(STREAM_INCIDENT_DETECTED, count=5)
    for event_id, fields in events:
        print(f"  {event_id}: {fields}")

    print("\n--- Reading back remediation.requested stream ---")
    events = read_latest(STREAM_REMEDIATION_REQUESTED, count=5)
    for event_id, fields in events:
        print(f"  {event_id}: {fields}")

    print("\n--- Reading back remediation.completed stream ---")
    events = read_latest(STREAM_REMEDIATION_COMPLETED, count=5)
    for event_id, fields in events:
        print(f"  {event_id}: {fields}")