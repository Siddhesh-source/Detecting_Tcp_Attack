# New API Endpoints

## SHAP Explainability
GET /explain/{flow_id} - Get SHAP explanation for specific flow
GET /explain/global - Get global feature importance

## Network Topology
GET /topology/graph - Get network graph data for visualization
GET /topology/centrality - Get node centrality metrics
GET /topology/communities - Get detected network communities
GET /topology/top-talkers - Get highest traffic nodes

## Behavioral Baseline
GET /baseline/stats - Get baseline statistics
GET /baseline/profile/{ip} - Get traffic profile for IP
GET /baseline/circadian/{ip} - Get hourly activity pattern

## Forensics
GET /forensics/timeline/{flow_id} - Get forensic timeline
GET /forensics/evidence - List captured evidence files
POST /forensics/cleanup - Clean old evidence files

## Threat Intelligence
GET /threat-intel/lookup/{ip} - Lookup IP reputation
GET /threat-intel/stats - Get threat intel statistics

## Alert Configuration
GET /alerts/config - Get current alert configuration
POST /alerts/config - Update alert configuration
POST /alerts/test - Send test alert email
