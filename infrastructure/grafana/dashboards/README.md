# Grafana Dashboards

## How to Import

1. Open Grafana at http://localhost:3000
2. Go to Dashboards → Import
3. Click "Upload dashboard JSON file"
4. Select any .json file from this folder
5. Select Prometheus as the data source
6. Click Import

## Dashboards

- cluster-overview.json — Cluster-wide CPU, memory, pod count
- per-service-health.json — Per-service metrics for all 12 Online Boutique services  
- combined-metrics-logs.json — Combined metrics and Loki logs view
