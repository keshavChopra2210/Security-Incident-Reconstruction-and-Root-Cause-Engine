"""
theia_explore.py
================
Interactive exploration of the DARPA Theia provenance graph in Neo4j.
Run after theia_to_neo4j.py has loaded the data.

Usage:
    python theia_explore.py [--uri bolt://localhost:7687] [--user neo4j] [--password neo4j]
"""

import os
import sys
import json
import argparse
from neo4j import GraphDatabase

DEFAULT_URI  = os.environ.get("NEO4J_URI",  "bolt://localhost:7687")
DEFAULT_USER = os.environ.get("NEO4J_USER", "neo4j")
DEFAULT_PASS = os.environ.get("NEO4J_PASS", "neo4j")

# ---------------------------------------------------------------------------
# Query library
# ---------------------------------------------------------------------------

QUERIES = {
    "1": {
        "name": "Graph summary — node and edge counts",
        "cypher": """
            MATCH (n) RETURN labels(n) AS nodeType, count(n) AS count ORDER BY count DESC
        """
    },
    "2": {
        "name": "Top 20 most active entities (by outgoing event count)",
        "cypher": """
            MATCH (s:Entity)-[e:EVENT]->()
            WITH s.uuid AS uuid, count(e) AS eventCount,
                 collect(DISTINCT e.type)[0..5] AS sampleTypes
            ORDER BY eventCount DESC LIMIT 20
            RETURN uuid, eventCount, sampleTypes
        """
    },
    "3": {
        "name": "All distinct event types and their counts",
        "cypher": """
            MATCH ()-[e:EVENT]->()
            RETURN e.type AS eventType, count(e) AS count
            ORDER BY count DESC
        """
    },
    "4": {
        "name": "Most recent 50 events (by timestamp)",
        "cypher": """
            MATCH (s:Entity)-[e:EVENT]->(o:Entity)
            WHERE e.timestamp IS NOT NULL
            RETURN s.uuid AS subject, e.type AS eventType,
                   e.names AS syscall, e.size AS bytes,
                   o.uuid AS object, e.timestamp AS ts
            ORDER BY e.timestamp DESC LIMIT 50
        """
    },
    "5": {
        "name": "File write events (write syscall, ordered by size)",
        "cypher": """
            MATCH (s:Entity)-[e:EVENT]->(o:Entity)
            WHERE e.type = 'EVENT_WRITE'
            RETURN s.uuid AS subject, o.uuid AS object,
                   e.size AS bytes, e.timestamp AS ts,
                   e.names AS syscall
            ORDER BY bytes DESC LIMIT 50
        """
    },
    "6": {
        "name": "Execute/fork/clone events (process spawning)",
        "cypher": """
            MATCH (s:Entity)-[e:EVENT]->(t:Entity)
            WHERE e.type IN ['EVENT_EXECUTE', 'EVENT_FORK', 'EVENT_CLONE']
            RETURN s.uuid AS parent, e.type AS how, t.uuid AS child,
                   e.timestamp AS ts
            ORDER BY ts ASC LIMIT 50
        """
    },
    "7": {
        "name": "Network-related events (connect/send/recv)",
        "cypher": """
            MATCH (s:Entity)-[e:EVENT]->(o:Entity)
            WHERE e.type IN ['EVENT_CONNECT','EVENT_ACCEPT','EVENT_SENDMSG',
                             'EVENT_RECVMSG','EVENT_SENDTO','EVENT_RECVFROM']
            RETURN s.uuid AS subject, e.type AS eventType,
                   o.uuid AS netObject, e.timestamp AS ts
            ORDER BY ts ASC LIMIT 50
        """
    },
    "8": {
        "name": "All events for a specific entity UUID (enter UUID when prompted)",
        "cypher": """
            MATCH (s:Entity {uuid: $uuid})-[e:EVENT]->(o:Entity)
            RETURN e.type AS eventType, e.names AS syscall,
                   o.uuid AS target, e.size AS bytes, e.timestamp AS ts
            ORDER BY ts ASC LIMIT 100
        """,
        "params": ["uuid"]
    },
    "9": {
        "name": "Entity connectivity — nodes with most connections",
        "cypher": """
            MATCH (n:Entity)
            RETURN n.uuid AS uuid,
                   size([(n)-[:EVENT]->() | 1]) AS outgoing,
                   size([()-[:EVENT]->(n) | 1]) AS incoming
            ORDER BY outgoing + incoming DESC LIMIT 20
        """
    },
    "10": {
        "name": "Export event subgraph to JSON (first 500 edges, ordered by time)",
        "cypher": """
            MATCH (s:Entity)-[e:EVENT]->(o:Entity)
            WHERE e.timestamp IS NOT NULL
            RETURN s.uuid AS source, o.uuid AS target,
                   e.type AS eventType, e.timestamp AS timestamp,
                   e.names AS names, e.size AS bytes
            ORDER BY e.timestamp ASC LIMIT 500
        """,
        "export": "subgraph_export.json"
    },
    "11": {
        "name": "Events between the same two nodes (repeated interactions)",
        "cypher": """
            MATCH (s:Entity)-[e:EVENT]->(o:Entity)
            WITH s.uuid AS src, o.uuid AS dst, count(e) AS interactions,
                 collect(DISTINCT e.type) AS types
            WHERE interactions > 5
            ORDER BY interactions DESC LIMIT 30
            RETURN src, dst, interactions, types
        """
    },
    "12": {
        "name": "Labeled node details (Subject/FileObject/NetFlowObject if present)",
        "cypher": """
            MATCH (n)
            WHERE size(labels(n)) > 1
            RETURN labels(n) AS labels, n.uuid AS uuid,
                   coalesce(n.cmdLine, n.url, n.localAddress, 'N/A') AS detail
            LIMIT 50
        """
    },
    "13": {
        "name": "Timeline: event counts per second (activity heatmap)",
        "cypher": """
            MATCH ()-[e:EVENT]->()
            WHERE e.timestamp IS NOT NULL
            WITH toInteger(e.timestamp / 1000000000) AS second, count(e) AS cnt
            ORDER BY second ASC
            RETURN datetime({epochSeconds: second}) AS time, cnt
            LIMIT 100
        """
    },
}

# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------

def run_query(session, query_def):
    cypher = query_def.get("cypher")
    params = {}
    for p in query_def.get("params", []):
        params[p] = input(f"  Enter {p}: ").strip()

    try:
        result = session.run(cypher, **params)
        rows = list(result)
    except Exception as e:
        # Fallback query (e.g., APOC not available)
        fb = query_def.get("fallback")
        if fb:
            print(f"  [!] Primary query failed ({e}), using fallback...")
            result = session.run(fb, **params)
            rows = list(result)
        else:
            raise

    if not rows:
        print("  (no results)")
        return

    # Export to JSON if requested
    export_path = query_def.get("export")
    if export_path:
        data = [dict(r) for r in rows]
        with open(export_path, "w") as f:
            json.dump(data, f, indent=2, default=str)
        print(f"  [OK] Exported {len(data)} rows to {export_path}")
        return

    # Print as table
    keys = list(rows[0].keys())
    col_widths = {k: max(len(k), max(len(str(r[k])) for r in rows)) for k in keys}
    col_widths = {k: min(v, 50) for k, v in col_widths.items()}

    header = " | ".join(k.ljust(col_widths[k]) for k in keys)
    sep    = "-+-".join("-" * col_widths[k] for k in keys)
    print(f"\n  {header}")
    print(f"  {sep}")
    for row in rows:
        line = " | ".join(str(row[k])[:col_widths[k]].ljust(col_widths[k]) for k in keys)
        print(f"  {line}")
    print(f"\n  ({len(rows)} rows)")


# ---------------------------------------------------------------------------
# Main interactive loop
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="Explore DARPA Theia graph in Neo4j")
    parser.add_argument("--uri",      default=DEFAULT_URI)
    parser.add_argument("--user",     default=DEFAULT_USER)
    parser.add_argument("--password", default=DEFAULT_PASS)
    args = parser.parse_args()

    driver = GraphDatabase.driver(args.uri, auth=(args.user, args.password))
    try:
        driver.verify_connectivity()
    except Exception as e:
        print(f"[FAIL] Cannot connect to Neo4j: {e}")
        sys.exit(1)

    print("\n" + "=" * 60)
    print("  DARPA Theia — Neo4j Provenance Explorer")
    print("=" * 60)
    print(f"  Connected to: {args.uri}")
    print()

    while True:
        print("\nAvailable queries:")
        for key, q in QUERIES.items():
            print(f"  [{key:>2}] {q['name']}")
        print("  [ q] Quit")
        print("  [ c] Custom Cypher query")
        print()

        choice = input("Select query > ").strip().lower()

        if choice == "q":
            break
        elif choice == "c":
            cypher = input("Enter Cypher query: ").strip()
            if not cypher:
                continue
            with driver.session() as session:
                run_query(session, {"cypher": cypher})
        elif choice in QUERIES:
            q = QUERIES[choice]
            print(f"\n--- {q['name']} ---")
            with driver.session() as session:
                try:
                    run_query(session, q)
                except Exception as e:
                    print(f"  [ERROR] {e}")
        else:
            print("  Unknown choice, try again.")

    driver.close()
    print("\n[OK] Bye!")

if __name__ == "__main__":
    main()
