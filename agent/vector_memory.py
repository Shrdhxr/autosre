import requests
import os
import uuid
import json
from datetime import datetime

# ── Config ────────────────────────────────────────────────────────
QDRANT_URL     = os.getenv("QDRANT_URL", "http://localhost:6333")
COLLECTION     = "incidents"
_raw_host      = os.environ.get("OLLAMA_HOST", "localhost:11434")
OLLAMA_URL     = _raw_host if _raw_host.startswith("http") else f"http://{_raw_host}"
EMBED_MODEL    = "nomic-embed-text"


# ── Embedding ─────────────────────────────────────────────────────
def embed_text(text):
    """
    Sends text to Ollama's nomic-embed-text model and returns a
    768-dimensional vector representing its meaning.
    """
    try:
        r = requests.post(
            f"{OLLAMA_URL}/api/embeddings",
            json={"model": EMBED_MODEL, "prompt": text},
            timeout=60
        )
        r.raise_for_status()
        data = r.json()
        return data.get("embedding")
    except Exception as e:
        print(f"[VectorMemory] Embedding failed: {e}")
        return None


# ── Build a text summary of an incident (this is what gets embedded) ──
def build_incident_text(anomaly_event, diagnosis, action, success):
    """
    Turns an incident into a single text blob capturing its essential
    meaning — this is what gets embedded, not the raw JSON.
    """
    parts = [
        f"Service: {anomaly_event.get('service', 'unknown')}",
        f"Anomaly type: {anomaly_event.get('type', 'unknown')}",
        f"Severity: {diagnosis.get('severity', 'unknown')}",
        f"Root cause: {diagnosis.get('probable_cause', '')}",
        f"Action taken: {action}",
        f"Outcome: {'succeeded' if success else 'failed'}",
    ]
    return " | ".join(parts)


# ── Store an incident in Qdrant ────────────────────────────────────
def store_incident(anomaly_event, diagnosis, action, success, details=""):
    """
    Embeds and stores a completed incident in Qdrant. Called after
    remediation.completed — this is how the system builds memory.
    """
    text = build_incident_text(anomaly_event, diagnosis, action, success)
    vector = embed_text(text)

    if vector is None:
        print("[VectorMemory] Skipping storage — embedding failed")
        return None

    point_id = str(uuid.uuid4())
    payload = {
        "service":        anomaly_event.get("service", "unknown"),
        "anomaly_type":   anomaly_event.get("type", "unknown"),
        "severity":       diagnosis.get("severity", "unknown"),
        "probable_cause": diagnosis.get("probable_cause", ""),
        "summary":        diagnosis.get("human_readable_summary", ""),
        "action":         action,
        "success":        success,
        "details":        details,
        "text":           text,
        "timestamp":      datetime.now().isoformat(),
    }

    try:
        r = requests.put(
            f"{QDRANT_URL}/collections/{COLLECTION}/points",
            json={
                "points": [
                    {"id": point_id, "vector": vector, "payload": payload}
                ]
            },
            timeout=10
        )
        r.raise_for_status()
        print(f"[VectorMemory] ✅ Stored incident {point_id} — {payload['service']} / {payload['action']} / success={success}")
        return point_id
    except Exception as e:
        print(f"[VectorMemory] Failed to store incident: {e}")
        return None


# ── Retrieve similar past incidents ────────────────────────────────
def find_similar_incidents(anomaly_event, top_k=3):
    """
    Embeds the current anomaly and searches Qdrant for the most
    semantically similar past incidents. Used by the LLM diagnosis
    agent to ground its reasoning in real history.
    """
    query_text = (
        f"Service: {anomaly_event.get('service', 'unknown')} | "
        f"Anomaly type: {anomaly_event.get('type', 'unknown')} | "
        f"Message: {anomaly_event.get('message', '')}"
    )
    vector = embed_text(query_text)
    if vector is None:
        return []

    try:
        r = requests.post(
            f"{QDRANT_URL}/collections/{COLLECTION}/points/search",
            json={
                "vector": vector,
                "limit": top_k,
                "with_payload": True
            },
            timeout=10
        )
        r.raise_for_status()
        results = r.json().get("result", [])
        return [
            {"score": r["score"], **r["payload"]}
            for r in results
        ]
    except Exception as e:
        print(f"[VectorMemory] Search failed: {e}")
        return []


# ── Test ──────────────────────────────────────────────────────────
if __name__ == "__main__":
    print("=" * 55)
    print("  AutoSRE Vector Memory — Test")
    print("=" * 55)

    test_anomaly = {
        "type": "CRASH_LOOP",
        "service": "loadgenerator",
        "message": "Pod loadgenerator is in CrashLoopBackOff"
    }
    test_diagnosis = {
        "severity": "CRITICAL",
        "probable_cause": "Container exits immediately due to a bad image after a deployment change",
        "human_readable_summary": "The loadgenerator pod crashes on startup because of an image issue."
    }

    print("\n[1] Storing a test incident...")
    store_incident(test_anomaly, test_diagnosis, action="restart_pod", success=True)

    print("\n[2] Searching for similar incidents...")
    similar = find_similar_incidents(test_anomaly, top_k=3)
    for s in similar:
        print(f"  score={s['score']:.4f}  service={s['service']}  action={s['action']}  success={s['success']}")
        print(f"    cause: {s['probable_cause']}")