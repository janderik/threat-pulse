# ThreatPulse

[![CI](https://github.com/janderik/threat-pulse/actions/workflows/ci.yml/badge.svg)](https://github.com/janderik/threat-pulse/actions/workflows/ci.yml)
[![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Ruff](https://img.shields.io/badge/code%20style-ruff-000000.svg)](https://github.com/astral-sh/ruff)

**ThreatPulse** is an open-source **Threat Intelligence Platform (TIP)** that collects, analyzes, correlates, and stores threat indicators (IOCs) from multiple OSINT sources. It provides a REST API for querying and managing threat data, and includes a scoring engine to prioritize the most dangerous threats.

---

## Architecture

```
                    ┌─────────────────────────────┐
                    │     OSINT Collectors         │
                    │  ┌─────┐ ┌──────┐ ┌───────┐ │
                    │  │OTX  │ │Abuse │ │ MITRE │ │
                    │  │Feed │ │IPDB  │ │ATT&CK │ │
                    │  └──┬──┘ └──┬───┘ └───┬───┘ │
                    │     │       │         │      │
                    │  ┌──┴───────┴─────────┴──┐  │
                    │  │    Custom Feeds       │  │
                    │  └───────────────────────┘  │
                    └──────────┬──────────────────┘
                               │
                    ┌──────────▼──────────────────┐
                    │    Correlation Engine        │
                    │    ┌──────────────────┐     │
                    │    │  Threat Scorer   │     │
                    │    └──────────────────┘     │
                    └──────────┬──────────────────┘
                               │
                    ┌──────────▼──────────────────┐
                    │        Database             │
                    │   (PostgreSQL / SQLite)      │
                    └──────────┬──────────────────┘
                               │
                    ┌──────────▼──────────────────┐
                    │     FastAPI REST API         │
                    │  ┌──────────────────────┐   │
                    │  │  /api/v1/iocs         │   │
                    │  │  /api/v1/threats      │   │
                    │  │  /api/v1/search       │   │
                    │  │  /api/v1/stats        │   │
                    │  └──────────────────────┘   │
                    └─────────────────────────────┘
```

---

## Features

- **OSINT Feed Collectors** — AlienVault OTX, AbuseIPDB, MITRE ATT&CK, custom JSON/YAML/CSV feeds
- **IOC Management** — IPs, domains, URLs, hashes (MD5/SHA1/SHA256), CVEs, emails
- **Threat Scoring Engine** — Weighted scoring based on confidence, type, source, tags
- **Correlation Engine** — Links related IOCs by shared tags, MITRE IDs, sources
- **MITRE ATT&CK Integration** — Maps threats to techniques, tactics, groups, and software
- **REST API** — Full CRUD for IOCs and threats, search, statistics
- **PostgreSQL + SQLite** — PostgreSQL in production, SQLite fallback for development
- **Async Collectors** — Concurrent feed fetching with configurable intervals
- **Docker Support** — Containerized deployment with docker-compose

---

## Quick Start

### Local Development

```bash
# Clone and install
git clone https://github.com/janderik/threat-pulse.git
cd threat-pulse
pip install -r requirements.txt
pip install -e .

# Start the API server
python -m src.main server

# Or: run collectors once
python -m src.main collect-once
```

The API will be available at `http://localhost:8000`.

### Docker Deployment

```bash
docker-compose up --build
```

---

## Configuration

Set environment variables or place them in a `.env` file:

| Variable | Default | Description |
|---|---|---|
| `DATABASE_URL` | `sqlite:///data/threatpulse.db` | PostgreSQL or SQLite DSN |
| `ALIENVAULT_API_KEY` | `""` | AlienVault OTX API key |
| `ABUSEIPDB_API_KEY` | `""` | AbuseIPDB API key |
| `COLLECTOR_INTERVAL_MINUTES` | `15` | Collector run interval |
| `LOG_LEVEL` | `INFO` | Logging level |
| `HOST` | `0.0.0.0` | API bind address |
| `PORT` | `8000` | API port |

---

## API Endpoints

### IOCs

| Method | Path | Description |
|---|---|---|
| `POST` | `/api/v1/iocs` | Create a new IOC |
| `GET` | `/api/v1/iocs` | List/search IOCs |
| `GET` | `/api/v1/iocs/{id}` | Get IOC by ID |
| `DELETE` | `/api/v1/iocs/{id}` | Delete an IOC |

Query parameters for `GET /api/v1/iocs`:
- `value` — partial value match
- `ioc_type` — filter by type (`ip`, `domain`, `url`, `md5`, `sha256`, `cve`, `email`)
- `source` — filter by source
- `confidence` — filter by confidence (`low`, `medium`, `high`, `critical`)
- `active_only` — only active IOCs (default: `true`)
- `limit` / `offset` — pagination

### Threats

| Method | Path | Description |
|---|---|---|
| `POST` | `/api/v1/threats` | Create a new threat |
| `GET` | `/api/v1/threats` | List/search threats |
| `GET` | `/api/v1/threats/{id}` | Get threat by ID |
| `PATCH` | `/api/v1/threats/{id}/status` | Update threat status |
| `DELETE` | `/api/v1/threats/{id}` | Delete a threat |

### Search & Stats

| Method | Path | Description |
|---|---|---|
| `GET` | `/api/v1/search?q=...` | Full-text search across IOCs and threats |
| `GET` | `/api/v1/stats` | Platform statistics |
| `GET` | `/api/v1/health` | Health check |

---

## Example Usage

```bash
# Add an IOC
curl -X POST http://localhost:8000/api/v1/iocs \
  -H "Content-Type: application/json" \
  -d '{"type": "ip", "value": "185.220.101.42", "confidence": "high", "tags": ["c2", "emotet"]}'

# Search for IOCs
curl "http://localhost:8000/api/v1/iocs?value=185.&ioc_type=ip"

# Create a threat
curl -X POST http://localhost:8000/api/v1/threats \
  -H "Content-Type: application/json" \
  -d '{"name": "Emotet Campaign", "tags": ["emotet", "malware"]}'

# Search everything
curl "http://localhost:8000/api/v1/search?q=emotet"

# Check stats
curl http://localhost:8000/api/v1/stats
```

---

## Testing

```bash
pytest tests/ -v --cov=src
```

---

## License

MIT
