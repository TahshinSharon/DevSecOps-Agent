# Architecture

DevSecOps Agent follows the same pattern as a cloud-cost detective application but targets Docker runtime inspection on an AWS EC2 machine.

## Components

1. React frontend
   - Login/signup
   - Dashboard
   - WebSocket progress
   - Report and history views

2. FastAPI backend
   - Auth endpoints
   - Inspection endpoint
   - WebSocket progress endpoint
   - Docker scanner
   - AI/rule analyzer
   - SQLite persistence

3. Docker scanner
   - Connects to local Docker daemon
   - Reads containers, images, networks, volumes, stats, and optional logs
   - Does not modify resources

4. Analyzer
   - OpenAI mode if API key is present
   - Rule-based fallback if not

## Request Flow

```text
POST /api/inspect
  -> create inspection row
  -> background scan job
  -> websocket progress events
  -> docker scanner reads daemon
  -> analyzer creates findings
  -> result stored in SQLite
  -> frontend redirects to report
```
