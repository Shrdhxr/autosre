# AutoSRE

AutoSRE is an autonomous Site Reliability Engineering platform built on Kubernetes. It detects anomalies in a live cluster, diagnoses their root cause using a locally-hosted LLM, and executes remediation actions — with an optional human approval step before anything is changed.

## How It Works

The system operates as a continuous closed-loop pipeline across four components.

**Detection** — `anomaly_detector.py` polls Prometheus every 30 seconds for signals across six categories: pod crash loops, high restart counts, excessive CPU or memory usage, pods in a non-running state, and high HTTP latency. When a threshold is crossed, `telemetry_collector.py` assembles a rich snapshot of the affected service — metrics, restart history, and recent Loki logs — and writes it to `latest_snapshot.json`.

**Diagnosis** — `llm_diagnosis_agent.py` watches for new snapshots and submits them to a locally-running Ollama model (`qwen2.5:14b`). Before constructing the prompt, it queries Qdrant for the three most semantically similar past incidents so the model can reason against real operational history. The response is validated against a JSON schema and retried up to three times. A passing diagnosis includes a probable root cause, severity rating, recommended action, and a confidence score.

**Incident creation** — `incident_creator.py` writes the diagnosis as an `AutoSREIncident` custom resource to the cluster. This decouples the diagnosis step from remediation and creates a durable, inspectable record of every incident.

**Remediation** — `kopf_operator.py` watches for new `AutoSREIncident` resources and executes the recommended action. In `manual` mode (the default) it pauses and asks a human to approve before proceeding. Actions include restarting a pod, scaling a deployment, or rolling back to the previous revision. Every decision — approved, denied, succeeded, or failed — is appended to `audit_log.jsonl` and the outcome is stored back in Qdrant for future retrieval.

## Architecture

```
Prometheus / Loki
       |
       v
 anomaly_detector.py  ──►  telemetry_collector.py  ──►  latest_snapshot.json
                                                               |
                                                               v
                                                   llm_diagnosis_agent.py
                                                    |         |
                                              vector_memory  event_bus
                                                    |
                                                    v
                                            AutoSREIncident (CRD)
                                                    |
                                                    v
                                            kopf_operator.py
                                             |     |      |
                                        restart  scale  rollback
                                                    |
                                               audit_log.jsonl
```

## Key Features

- **Local-first LLM** — all inference runs on-device via Ollama, no data leaves the machine
- **Vector memory** — incidents are embedded with `nomic-embed-text` and stored in Qdrant; similar past incidents are retrieved and injected into each new diagnosis prompt
- **Human approval gate** — by default the operator pauses before executing any action; set `AUTOSRE_APPROVAL_MODE=auto` for fully autonomous operation
- **Namespace allow-list** — remediation is restricted to explicitly permitted namespaces
- **Circuit breaker** — after 3 failed remediations on the same service within 10 minutes, the operator stops retrying until the window clears
- **Event bus** — the three pipeline stages communicate through Redis Streams (`incident.detected`, `remediation.requested`, `remediation.completed`), keeping each component independently restartable
- **Chaos regression suite** — six Chaos Mesh experiments (pod kill, pod failure, network latency, CPU stress, memory stress, network partition) with an automated regression runner

## Stack

| Layer | Technology |
|---|---|
| Cluster orchestration | Kubernetes + Kopf |
| Metrics | Prometheus |
| Logs | Loki |
| LLM inference | Ollama (`qwen2.5:14b`) |
| Embeddings | Ollama (`nomic-embed-text`) |
| Vector store | Qdrant |
| Event bus | Redis Streams |
| Chaos engineering | Chaos Mesh |
| Observability | Grafana |

## Project Structure

```
autosre/
  agent/               anomaly detection, telemetry, LLM diagnosis, vector memory, event bus
  operator/            Kopf operator, AutoSREIncident CRD, RBAC
  infrastructure/      Prometheus alert rules, Grafana dashboards
  chaos/               Chaos Mesh experiments, regression test runner
  qdrant_storage/      local Qdrant data volume
```

## Prerequisites

- A running Kubernetes cluster with `~/.kube/config` configured
- Ollama with `qwen2.5:14b` and `nomic-embed-text` pulled
- Qdrant on port 6333, Redis on port 6379
- Prometheus on port 9090, Loki on port 3100 (port-forwarded from the cluster)
- Python 3.10+

## Getting Started

Apply the CRD and RBAC, then start the three components in separate terminals:

```bash
kubectl apply -f operator/crd.yaml
kubectl apply -f operator/rbac.yaml

# Terminal 1
python3 agent/anomaly_detector.py

# Terminal 2
python3 agent/llm_diagnosis_agent.py --watch

# Terminal 3
python3 operator/kopf_operator.py
```

Set `AUTOSRE_APPROVAL_MODE=auto` to skip the human gate, or `AUTOSRE_ALLOWED_NAMESPACES=ns1,ns2` to extend the namespace allow-list.

## Inspecting Incidents

```bash
kubectl get autosreincidents
kubectl describe autosreincident <name>
```

Each resource captures the affected service, anomaly type, severity, diagnosis, recommended action, confidence score, and the full remediation lifecycle phase.

## License

MIT
