# DARPA Theia Telemetry → Neo4j Setup Guide

## Overview

This project loads the **DARPA TC Engagement 5 Theia** dataset (CDM v20 Avro format)
into **Neo4j** for provenance graph analysis and APT (Advanced Persistent Threat) detection.

### Files

| File | Purpose |
|---|---|
| `setup_neo4j.py` | Download & start Neo4j 4.4 Community Edition |
| `theia_to_neo4j.py` | Load Theia Avro data into Neo4j (two-pass: nodes then edges) |
| `theia_explore.py` | Interactive query explorer with 12 pre-built Cypher queries |
| `data.py` | Quick Avro record preview (standalone, no Neo4j needed) |

---

## Step 1 — Start Neo4j

### Option A: Automated Setup (recommended)
Downloads and starts Neo4j 4.4 locally (requires Java 8+):
```powershell
python setup_neo4j.py
```
This will:
- Download Neo4j 4.4 Community (~100 MB) into `./neo4j/`
- Disable auth for local use
- Tune memory settings (heap 4 GB, pagecache 2 GB)
- Start Neo4j at `bolt://localhost:7687`

### Option B: Neo4j Desktop
1. Download from https://neo4j.com/download/
2. Create a project → Add a local DBMS (version 4.4)
3. Start the database
4. Open settings → disable auth or set password

### Option C: Docker
```powershell
docker run --name neo4j-theia -p 7474:7474 -p 7687:7687 `
  -e NEO4J_AUTH=none `
  -e NEO4J_dbms_memory_heap_max__size=4G `
  neo4j:4.4
```

---

## Step 2 — Load the Data

```powershell
python theia_to_neo4j.py
```

**Options:**
```
--file     Path to .bin.1.gz file  (default: DARPA_TC\ta1-theia-1-e5-official-1.bin.1.gz)
--uri      Neo4j URI               (default: bolt://localhost:7687)
--user     Neo4j username          (default: neo4j)
--password Neo4j password          (default: neo4j)
--batch    Records per transaction (default: 1000)
--limit    Max records to load     (useful for testing, e.g. --limit 50000)
```

**Quick test (load first 10,000 records):**
```powershell
python theia_to_neo4j.py --limit 10000
```

**Full load:**
```powershell
python theia_to_neo4j.py
```
> Expected: millions of records, may take 10–30 minutes depending on hardware.

---

## Step 3 — Explore in Neo4j Browser

Open http://localhost:7474 in your browser.

### Verify the load
```cypher
// Count all nodes by label
MATCH (n) RETURN labels(n) AS type, count(n) AS count ORDER BY count DESC

// Count all events
MATCH ()-[e:EVENT]->() RETURN e.type, count(e) AS count ORDER BY count DESC LIMIT 20

// View a Subject node
MATCH (s:Subject) RETURN s LIMIT 5
```

---

## Step 4 — Interactive Explorer

```powershell
python theia_explore.py
```

### Available pre-built queries:

| # | Query |
|---|---|
| 1 | Node & edge counts by type |
| 2 | Top 20 most active processes |
| 3 | File write events (last 100) |
| 4 | All network connections |
| 5 | Process execution chains (fork/exec) |
| 6 | All distinct event types and counts |
| 7 | Potential data exfiltration (writes to network) |
| 8 | Files read by a specific process (by UUID) |
| 9 | Graph summary |
| 10 | Export subgraph to JSON |
| 11 | Sensitive file access (/etc/passwd, /etc/shadow) |
| 12 | Suspicious shell spawning (bash, python, curl, wget) |
| c | Enter any custom Cypher query |

---

## Graph Schema

```
(:Subject)-[:EVENT {type, timestamp, names, size}]->(:FileObject)
(:Subject)-[:EVENT {type, timestamp, names}]->(:NetFlowObject)
(:Subject)-[:EVENT {type, timestamp}]->(:Subject)
(:Subject)-[:DEPENDS_ON]->(:Subject)
```

### Node properties

| Label | Key properties |
|---|---|
| `Subject` | `uuid`, `type`, `pid`, `cmdLine`, `hostId` |
| `FileObject` | `uuid`, `url` (path), `fileDescriptor`, `hostId` |
| `NetFlowObject` | `uuid`, `localAddress`, `localPort`, `remoteAddress`, `remotePort` |
| `IpcObject` | `uuid`, `type` |
| `Host` | `uuid`, `hostName`, `osDetails` |
| `Principal` | `uuid`, `userId`, `groupIds` |

### EVENT relationship properties

| Property | Description |
|---|---|
| `type` | CDM event type (e.g. `EVENT_WRITE`, `EVENT_READ`, `EVENT_EXECUTE`) |
| `timestamp` | nanosecond-precision Unix timestamp |
| `names` | syscall name(s) |
| `size` | bytes transferred (if applicable) |
| `sequence` | global sequence number |
| `hostId` | host UUID |
| `source` | always `SOURCE_LINUX_THEIA` |

---

## Useful Cypher Recipes

### Find attack path from process to sensitive file
```cypher
MATCH path = (s:Subject)-[:EVENT*1..5]->(f:FileObject)
WHERE f.url CONTAINS '/etc/passwd'
RETURN path LIMIT 10
```

### Find processes that connected outbound and then wrote a file
```cypher
MATCH (s:Subject)-[:EVENT {type:'EVENT_WRITE'}]->(f:FileObject),
      (s)-[:EVENT]->(n:NetFlowObject)
RETURN s.uuid, f.url, n.remoteAddress, n.remotePort
LIMIT 20
```

### Visualize process ancestry
```cypher
MATCH path = (ancestor:Subject)-[:EVENT*1..4 {type:'EVENT_FORK'}]->(child:Subject)
RETURN path LIMIT 5
```

---

## Troubleshooting

| Issue | Fix |
|---|---|
| `ConnectionRefusedError` on port 7687 | Run `setup_neo4j.py` or start Neo4j Desktop |
| `ModuleNotFoundError: avro` | Run `pip install avro-python3 neo4j` |
| Slow loading | Increase `--batch` to 2000, reduce `--limit` for testing |
| Out of memory | Reduce Neo4j heap in `neo4j.conf` or close other apps |
| `.bin.1` read error (EOFError) | Always use the `.bin.1.gz` file instead |
