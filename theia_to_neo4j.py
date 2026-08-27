"""
theia_to_neo4j.py
=================
Loads the DARPA TC Engagement 5 Theia provenance dataset (CDM20 Avro format)
into a Neo4j graph database for provenance/APT analysis.

Usage:
    python theia_to_neo4j.py [--uri bolt://localhost:7687] [--user neo4j] [--password neo4j]
                             [--file PATH_TO_.bin.1.gz] [--limit N] [--batch 1000]

Environment variables (override defaults):
    NEO4J_URI, NEO4J_USER, NEO4J_PASS

Node labels created:
    Host, Principal, Subject, FileObject, NetFlowObject, IpcObject,
    MemoryObject, RegistryKeyObject, PacketSocketObject, SrcSinkObject,
    ProvenanceTagNode, UnknownProvenanceNode, TimeMarker, EndMarker, UnitDependency

Relationship type created:
    EVENT  (subject)-[:EVENT {type, timestamp, names, size, ...}]->(predicateObject)
"""

import os
import sys
import gzip
import argparse
import time
import traceback
from collections import defaultdict, Counter

from avro.datafile import DataFileReader
from avro.io import DatumReader
from neo4j import GraphDatabase

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
DEFAULT_FILE = r"E:\Major Project\DARPA_TC\ta1-theia-1-e5-official-1.bin.1.gz"
DEFAULT_URI  = os.environ.get("NEO4J_URI",  "bolt://localhost:7687")
DEFAULT_USER = os.environ.get("NEO4J_USER", "neo4j")
DEFAULT_PASS = os.environ.get("NEO4J_PASS", "neo4j")
BATCH_SIZE   = 1000
PROGRESS_EVERY = 10_000

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def uuid_to_hex(val):
    """Convert raw UUID bytes or string to a stable hex string."""
    if val is None:
        return None
    if isinstance(val, (bytes, bytearray)):
        return val.hex()
    return str(val)

def _safe_val(v):
    """Convert any value to a Neo4j-safe primitive (no nested maps)."""
    if v is None:
        return None
    if isinstance(v, (bytes, bytearray)):
        return v.hex()
    if isinstance(v, bool):
        return v
    if isinstance(v, (int, float, str)):
        return v
    if isinstance(v, dict):
        # Flatten nested map to JSON string
        return str({k2: _safe_val(v2) for k2, v2 in v.items() if v2 is not None})[:500]
    if isinstance(v, list):
        items = [_safe_val(x) for x in v if x is not None]
        # Neo4j lists must be homogeneous primitives
        if all(isinstance(x, str) for x in items):
            return items
        return [str(x) for x in items]
    return str(v)[:500]

def clean_props(d: dict, keep_keys=None) -> dict:
    """Flatten a dict to Neo4j-safe primitives. Nested dicts are flattened one level."""
    out = {}
    for k, v in d.items():
        if keep_keys and k not in keep_keys:
            continue
        if v is None:
            continue
        if isinstance(v, dict):
            # Flatten one level (e.g., the CDM 'properties' map)
            for sk, sv in v.items():
                safe = _safe_val(sv)
                if safe is not None:
                    out[f"prop_{sk}"] = safe
        else:
            safe = _safe_val(v)
            if safe is not None:
                out[k] = safe
    return out

# ---------------------------------------------------------------------------
# Schema / index setup
# ---------------------------------------------------------------------------
INDEXES = [
    "CREATE INDEX entity_uuid       IF NOT EXISTS FOR (n:Entity)              ON (n.uuid)",
    "CREATE INDEX subject_uuid      IF NOT EXISTS FOR (n:Subject)             ON (n.uuid)",
    "CREATE INDEX fileobj_uuid      IF NOT EXISTS FOR (n:FileObject)          ON (n.uuid)",
    "CREATE INDEX netflow_uuid      IF NOT EXISTS FOR (n:NetFlowObject)       ON (n.uuid)",
    "CREATE INDEX ipc_uuid          IF NOT EXISTS FOR (n:IpcObject)           ON (n.uuid)",
    "CREATE INDEX mem_uuid          IF NOT EXISTS FOR (n:MemoryObject)        ON (n.uuid)",
    "CREATE INDEX reg_uuid          IF NOT EXISTS FOR (n:RegistryKeyObject)   ON (n.uuid)",
    "CREATE INDEX srcsink_uuid      IF NOT EXISTS FOR (n:SrcSinkObject)       ON (n.uuid)",
    "CREATE INDEX pktSocket_uuid    IF NOT EXISTS FOR (n:PacketSocketObject)  ON (n.uuid)",
    "CREATE INDEX provtag_uuid      IF NOT EXISTS FOR (n:ProvenanceTagNode)   ON (n.uuid)",
    "CREATE INDEX unknprov_uuid     IF NOT EXISTS FOR (n:UnknownProvenanceNode) ON (n.uuid)",
    "CREATE INDEX host_uuid         IF NOT EXISTS FOR (n:Host)                ON (n.uuid)",
    "CREATE INDEX principal_uuid    IF NOT EXISTS FOR (n:Principal)           ON (n.uuid)",
]

def create_indexes(session):
    print("[->] Creating indexes...")
    for idx in INDEXES:
        session.run(idx)
    print("[OK] Indexes ready.")

# ---------------------------------------------------------------------------
# Node writers (one per CDM record type)
# ---------------------------------------------------------------------------

def write_host(tx, datum, meta):
    uuid = uuid_to_hex(datum.get("uuid"))
    tx.run("""
        MERGE (n:Entity {uuid: $uuid})
        SET n:Host, n += $props
    """, uuid=uuid, props=clean_props(datum))

def write_principal(tx, datum, meta):
    uuid = uuid_to_hex(datum.get("uuid"))
    tx.run("""
        MERGE (n:Entity {uuid: $uuid})
        SET n:Principal, n += $props
    """, uuid=uuid, props=clean_props(datum))

def write_subject(tx, datum, meta):
    uuid = uuid_to_hex(datum.get("uuid"))
    props = clean_props(datum)
    props["hostId"] = uuid_to_hex(meta.get("hostId"))
    props["source"] = meta.get("source")
    tx.run("""
        MERGE (n:Entity {uuid: $uuid})
        SET n:Subject, n += $props
    """, uuid=uuid, props=props)

def write_file_object(tx, datum, meta):
    uuid = uuid_to_hex(datum.get("uuid"))
    props = clean_props(datum)
    props["hostId"] = uuid_to_hex(meta.get("hostId"))
    tx.run("""
        MERGE (n:Entity {uuid: $uuid})
        SET n:FileObject, n += $props
    """, uuid=uuid, props=props)

def write_netflow_object(tx, datum, meta):
    uuid = uuid_to_hex(datum.get("uuid"))
    props = clean_props(datum)
    props["hostId"] = uuid_to_hex(meta.get("hostId"))
    tx.run("""
        MERGE (n:Entity {uuid: $uuid})
        SET n:NetFlowObject, n += $props
    """, uuid=uuid, props=props)

def write_ipc_object(tx, datum, meta):
    uuid = uuid_to_hex(datum.get("uuid"))
    tx.run("""
        MERGE (n:Entity {uuid: $uuid})
        SET n:IpcObject, n += $props
    """, uuid=uuid, props=clean_props(datum))

def write_memory_object(tx, datum, meta):
    uuid = uuid_to_hex(datum.get("uuid"))
    tx.run("""
        MERGE (n:Entity {uuid: $uuid})
        SET n:MemoryObject, n += $props
    """, uuid=uuid, props=clean_props(datum))

def write_registry_key_object(tx, datum, meta):
    uuid = uuid_to_hex(datum.get("uuid"))
    tx.run("""
        MERGE (n:Entity {uuid: $uuid})
        SET n:RegistryKeyObject, n += $props
    """, uuid=uuid, props=clean_props(datum))

def write_packet_socket_object(tx, datum, meta):
    uuid = uuid_to_hex(datum.get("uuid"))
    tx.run("""
        MERGE (n:Entity {uuid: $uuid})
        SET n:PacketSocketObject, n += $props
    """, uuid=uuid, props=clean_props(datum))

def write_srcsink_object(tx, datum, meta):
    uuid = uuid_to_hex(datum.get("uuid"))
    tx.run("""
        MERGE (n:Entity {uuid: $uuid})
        SET n:SrcSinkObject, n += $props
    """, uuid=uuid, props=clean_props(datum))

def write_provenance_tag_node(tx, datum, meta):
    uuid = uuid_to_hex(datum.get("uuid"))
    tx.run("""
        MERGE (n:Entity {uuid: $uuid})
        SET n:ProvenanceTagNode, n += $props
    """, uuid=uuid, props=clean_props(datum))

def write_unknown_provenance_node(tx, datum, meta):
    uuid = uuid_to_hex(datum.get("uuid"))
    tx.run("""
        MERGE (n:Entity {uuid: $uuid})
        SET n:UnknownProvenanceNode, n += $props
    """, uuid=uuid, props=clean_props(datum))

def write_time_marker(tx, datum, meta):
    uuid = uuid_to_hex(datum.get("uuid", b'\x00'*16))
    tx.run("""
        MERGE (n:Entity {uuid: $uuid})
        SET n:TimeMarker, n += $props
    """, uuid=uuid, props=clean_props(datum))

def write_end_marker(tx, datum, meta):
    tx.run("CREATE (n:EndMarker) SET n += $props", props=clean_props(datum))

def write_unit_dependency(tx, datum, meta):
    """UnitDependency is an edge between two Subject units."""
    unit = uuid_to_hex(datum.get("unit"))
    dep  = uuid_to_hex(datum.get("dependentUnit"))
    if unit and dep:
        tx.run("""
            MERGE (a:Entity {uuid: $unit})
            MERGE (b:Entity {uuid: $dep})
            MERGE (a)-[:DEPENDS_ON]->(b)
        """, unit=unit, dep=dep)

# ---------------------------------------------------------------------------
# Event writer — creates an EVENT relationship
# ---------------------------------------------------------------------------
ALL_OBJECT_LABELS = [
    "Subject", "FileObject", "NetFlowObject", "IpcObject",
    "MemoryObject", "RegistryKeyObject", "PacketSocketObject", "SrcSinkObject",
    "ProvenanceTagNode", "UnknownProvenanceNode"
]

def write_event(tx, datum, meta):
    subject_uuid = uuid_to_hex(datum.get("subject"))
    obj_uuid     = uuid_to_hex(datum.get("predicateObject"))
    obj2_uuid    = uuid_to_hex(datum.get("predicateObject2"))

    if not subject_uuid or not obj_uuid:
        return

    event_props = {
        "uuid":      uuid_to_hex(datum.get("uuid")),
        "type":      datum.get("type"),
        "sequence":  datum.get("sequence"),
        "threadId":  datum.get("threadId"),
        "timestamp": datum.get("timestampNanos"),
        "names":     datum.get("names") or [],
        "size":      datum.get("size"),
        "location":  datum.get("location"),
        "hostId":    uuid_to_hex(meta.get("hostId")),
        "source":    meta.get("source"),
    }
    event_props = {k: v for k, v in event_props.items() if v is not None}

    # MERGE on :Entity so node writers can later promote to Subject/FileObject/etc.
    # using SET n:Subject without creating a duplicate node.
    tx.run("""
        MERGE (s:Entity {uuid: $sub})
        MERGE (o:Entity {uuid: $obj})
        CREATE (s)-[:EVENT $props]->(o)
    """, sub=subject_uuid, obj=obj_uuid, props=event_props)

    # Optional second predicate object (skip null UUID)
    if obj2_uuid and obj2_uuid != "0" * 32:
        tx.run("""
            MERGE (s:Entity {uuid: $sub})
            MERGE (o:Entity {uuid: $obj2})
            CREATE (s)-[:EVENT2 $props]->(o)
        """, sub=subject_uuid, obj2=obj2_uuid, props=event_props)

# ---------------------------------------------------------------------------
# Dispatch map: CDM record type -> writer function
# ---------------------------------------------------------------------------
WRITERS = {
    "Host":                   write_host,
    "Principal":              write_principal,
    "Subject":                write_subject,
    "FileObject":             write_file_object,
    "NetFlowObject":          write_netflow_object,
    "IpcObject":              write_ipc_object,
    "MemoryObject":           write_memory_object,
    "RegistryKeyObject":      write_registry_key_object,
    "PacketSocketObject":     write_packet_socket_object,
    "SrcSinkObject":          write_srcsink_object,
    "ProvenanceTagNode":      write_provenance_tag_node,
    "UnknownProvenanceNode":  write_unknown_provenance_node,
    "TimeMarker":             write_time_marker,
    "EndMarker":              write_end_marker,
    "UnitDependency":         write_unit_dependency,
    "Event":                  write_event,
}

# ---------------------------------------------------------------------------
# Batched loader
# ---------------------------------------------------------------------------
TYPE_MAP = {
    "HOST":                   "Host",
    "PRINCIPAL":              "Principal",
    "SUBJECT":                "Subject",
    "FILEOBJECT":             "FileObject",
    "NETFLOWOBJECT":          "NetFlowObject",
    "IPCOBJECT":              "IpcObject",
    "MEMORYOBJECT":           "MemoryObject",
    "REGISTRYKEYOBJECT":      "RegistryKeyObject",
    "PACKETSOCKETOBJECT":     "PacketSocketObject",
    "SRCSINKOBJECT":          "SrcSinkObject",
    "PROVENANCETAGNODE":      "ProvenanceTagNode",
    "UNKNOWNPROVENANCENODE":  "UnknownProvenanceNode",
    "TIMEMARKER":             "TimeMarker",
    "ENDMARKER":              "EndMarker",
    "UNITDEPENDENCY":         "UnitDependency",
    "EVENT":                  "Event",
}

def resolve_type(rec_type):
    raw = rec_type.replace("RECORD_", "").upper().replace("_", "")
    return TYPE_MAP.get(raw, raw)

def load_file(driver, avro_path: str, batch_size: int, limit: int = None):
    """
    Single-pass strategy: process all records in stream order.
    Events create :Entity placeholder nodes; node records (Subject, FileObject, etc.)
    promote those same :Entity nodes by adding the correct label with SET n:Label.
    This handles sparse/interleaved node definitions correctly regardless of file structure.
    """
    print(f"\n[->] Loading: {avro_path}")
    print(f"     Batch size: {batch_size}")
    if limit:
        print(f"     Record limit: {limit:,}")
    print()

    stats   = Counter()
    errors  = Counter()
    t0      = time.time()
    batch   = []

    open_fn = gzip.open if avro_path.endswith(".gz") else open

    def flush_batch(session, b):
        if not b:
            return
        with session.begin_transaction() as tx:
            for inner_type, datum, meta in b:
                try:
                    WRITERS[inner_type](tx, datum, meta)
                    stats[inner_type] += 1
                except Exception as e:
                    errors[inner_type] += 1
                    # Non-fatal: log first occurrence of each error type
                    err_key = f"{inner_type}:{type(e).__name__}"
                    if errors[err_key] == 0:
                        print(f"  [WARN] {inner_type} write error: {e}")
                    errors[err_key] += 1
            tx.commit()

    print("=== Single-pass load (nodes + events in stream order) ===")

    with driver.session() as session:
        create_indexes(session)

    with driver.session() as session:
        with open_fn(avro_path, "rb") as f:
            reader = DataFileReader(f, DatumReader())
            total = 0
            for record in reader:
                if limit and total >= limit:
                    break
                total += 1

                rec_type   = record.get("type", "")
                datum      = record.get("datum") or {}
                inner_type = resolve_type(rec_type)

                if inner_type not in WRITERS:
                    continue

                batch.append((inner_type, datum, record))
                if len(batch) >= batch_size:
                    flush_batch(session, batch)
                    batch = []

                if total % PROGRESS_EVERY == 0:
                    elapsed = time.time() - t0
                    node_cnt  = sum(v for k, v in stats.items() if k != "Event")
                    event_cnt = stats.get("Event", 0)
                    print(f"  {total:>10,} records | {elapsed:6.1f}s"
                          f" | nodes: {node_cnt:,} | events: {event_cnt:,}")

            flush_batch(session, batch)
            reader.close()

    elapsed = time.time() - t0
    node_cnt  = sum(v for k, v in stats.items() if k != "Event")
    event_cnt = stats.get("Event", 0)
    total_written = sum(stats.values())

    print(f"\n=== LOAD COMPLETE in {elapsed:.1f}s ===")
    print(f"  Total records written : {total_written:,}")
    print(f"  Node records          : {node_cnt:,}")
    print(f"  Event edges           : {event_cnt:,}")
    print(f"\nBreakdown:")
    for k, v in sorted(stats.items(), key=lambda x: -x[1]):
        print(f"  {k:<30} {v:>10,}")
    if errors:
        print(f"\nErrors ({sum(errors.values()):,} total):")
        for k, v in sorted(errors.items(), key=lambda x: -x[1]):
            print(f"  {k:<30} {v:>10,}")

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(description="Load DARPA Theia CDM20 Avro into Neo4j")
    parser.add_argument("--file",     default=DEFAULT_FILE, help="Path to .bin.1.gz Avro file")
    parser.add_argument("--uri",      default=DEFAULT_URI,  help="Neo4j Bolt URI")
    parser.add_argument("--user",     default=DEFAULT_USER, help="Neo4j username")
    parser.add_argument("--password", default=DEFAULT_PASS, help="Neo4j password")
    parser.add_argument("--batch",    type=int, default=BATCH_SIZE, help="Records per transaction")
    parser.add_argument("--limit",    type=int, default=None, help="Max records to process (for testing)")
    args = parser.parse_args()

    print("=" * 60)
    print("  DARPA Theia CDM20 -> Neo4j Loader")
    print("=" * 60)
    print(f"  File:    {args.file}")
    print(f"  Neo4j:   {args.uri}")
    print(f"  Auth:    {args.user} / {'*' * len(args.password)}")
    print()

    driver = GraphDatabase.driver(args.uri, auth=(args.user, args.password))
    try:
        driver.verify_connectivity()
        print(f"[OK] Connected to Neo4j at {args.uri}\n")
    except Exception as e:
        print(f"[FAIL] Cannot connect to Neo4j: {e}")
        print("       Run setup_neo4j.py first, or start Neo4j Desktop.")
        sys.exit(1)

    load_file(driver, args.file, args.batch, args.limit)
    driver.close()

if __name__ == "__main__":
    main()
