"""
data.py -- DARPA Theia CDM20 Avro Quick Viewer
==============================================
Pretty-prints records with colour-coded human-readable output, clean JSON export,
or a full dataset statistics summary.

Modes:
    python data.py                          # pretty-print first 10 records
    python data.py --json                   # clean JSON output (one object per record)
    python data.py --stats                  # dataset-wide statistics summary

Filters (work with all modes):
    --limit N        Max records to show/scan (default: 10, use 0 for all)
    --offset N       Skip first N records
    --type TYPE      Filter by record type  e.g. RECORD_EVENT, RECORD_SUBJECT
    --search TEXT    Only show records containing this keyword

Output:
    --out FILE       Save output to a file instead of printing
    --no-meta        Hide the CDM host/session metadata header line

Examples:
    python data.py --limit 5
    python data.py --type RECORD_EVENT --limit 100 --json --out events.json
    python data.py --stats --limit 0
    python data.py --search EVENT_EXECUTE --limit 20
    python data.py --offset 50000 --limit 10
"""

import gzip
import json
import argparse
import sys
from datetime import datetime, timezone
from collections import Counter, defaultdict
from avro.datafile import DataFileReader
from avro.io import DatumReader

# ── File path ─────────────────────────────────────────────────────────────────
AVRO_PATH = r"E:\Major Project\DARPA_TC\ta1-theia-1-e5-official-1.bin.1.gz"

# Force UTF-8 output on Windows terminals
if sys.stdout.encoding and sys.stdout.encoding.lower() not in ('utf-8', 'utf8'):
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')

# -- ANSI colours (auto-disabled on Windows if not supported) --
try:
    import ctypes
    ctypes.windll.kernel32.SetConsoleMode(ctypes.windll.kernel32.GetStdHandle(-11), 7)
    USE_COLOR = True
except Exception:
    USE_COLOR = sys.stdout.isatty()

RESET  = "\033[0m"  if USE_COLOR else ""
BOLD   = "\033[1m"  if USE_COLOR else ""
DIM    = "\033[2m"  if USE_COLOR else ""
CYAN   = "\033[96m" if USE_COLOR else ""
GREEN  = "\033[92m" if USE_COLOR else ""
YELLOW = "\033[93m" if USE_COLOR else ""
RED    = "\033[91m" if USE_COLOR else ""
BLUE   = "\033[94m" if USE_COLOR else ""
MAGENTA= "\033[95m" if USE_COLOR else ""
SEP    = "-" * 60

# ── Colour map by record type ─────────────────────────────────────────────────
TYPE_COLOR = {
    "RECORD_EVENT":               CYAN,
    "RECORD_SUBJECT":             GREEN,
    "RECORD_FILE_OBJECT":         YELLOW,
    "RECORD_NET_FLOW_OBJECT":     MAGENTA,
    "RECORD_IPC_OBJECT":          BLUE,
    "RECORD_MEMORY_OBJECT":       DIM,
    "RECORD_HOST":                RED,
    "RECORD_PRINCIPAL":           GREEN,
    "RECORD_SRCSINK_OBJECT":      DIM,
    "RECORD_REGISTRY_KEY_OBJECT": YELLOW,
    "RECORD_TIME_MARKER":         DIM,
    "RECORD_END_MARKER":          DIM,
}

EVENT_COLOR = {
    "EVENT_WRITE":    RED,
    "EVENT_READ":     GREEN,
    "EVENT_EXECUTE":  YELLOW,
    "EVENT_FORK":     MAGENTA,
    "EVENT_CLONE":    MAGENTA,
    "EVENT_CONNECT":  CYAN,
    "EVENT_ACCEPT":   CYAN,
    "EVENT_SENDMSG":  RED,
    "EVENT_RECVMSG":  GREEN,
    "EVENT_OPEN":     BLUE,
    "EVENT_MMAP":     DIM,
    "EVENT_UNLINK":   RED,
}

# ── Helpers ───────────────────────────────────────────────────────────────────
def uuid_hex(val):
    """Convert raw bytes UUID to readable hex string."""
    if val is None:
        return "null"
    if isinstance(val, (bytes, bytearray)):
        h = val.hex()
        return f"{h[:8]}-{h[8:12]}-{h[12:16]}-{h[16:20]}-{h[20:]}"
    return str(val)

def fmt_timestamp(ns):
    """Convert nanosecond timestamp to human-readable UTC datetime."""
    if not ns:
        return "N/A"
    try:
        dt = datetime.fromtimestamp(ns / 1e9, tz=timezone.utc)
        return dt.strftime("%Y-%m-%d %H:%M:%S.%f UTC")
    except Exception:
        return str(ns)

def fmt_bytes(n):
    """Format byte count in human units."""
    if n is None:
        return "N/A"
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024:
            return f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} TB"

def color_event_type(t):
    c = EVENT_COLOR.get(t, CYAN)
    return f"{BOLD}{c}{t}{RESET}"

def color_record_type(t):
    c = TYPE_COLOR.get(t, RESET)
    return f"{BOLD}{c}{t}{RESET}"

# ── Record renderers ──────────────────────────────────────────────────────────
def render_event(datum, meta):
    etype = datum.get("type", "?")
    lines = [
        f"  {BOLD}Event Type :{RESET} {color_event_type(etype)}",
        f"  {BOLD}Sequence   :{RESET} {datum.get('sequence', 'N/A')}",
        f"  {BOLD}Thread ID  :{RESET} {datum.get('threadId', 'N/A')}",
        f"  {BOLD}Timestamp  :{RESET} {fmt_timestamp(datum.get('timestampNanos'))}",
        f"  {BOLD}Syscalls   :{RESET} {', '.join(datum.get('names') or []) or 'N/A'}",
        f"  {BOLD}Subject    :{RESET} {uuid_hex(datum.get('subject'))}",
        f"  {BOLD}Pred Obj   :{RESET} {uuid_hex(datum.get('predicateObject'))}",
    ]
    path = datum.get("predicateObjectPath")
    if path:
        lines.append(f"  {BOLD}Path       :{RESET} {GREEN}{path}{RESET}")
    obj2 = datum.get("predicateObject2")
    if obj2 and isinstance(obj2, (bytes,bytearray)) and any(b != 0 for b in obj2):
        lines.append(f"  {BOLD}Pred Obj 2 :{RESET} {uuid_hex(obj2)}")
    size = datum.get("size")
    if size is not None:
        lines.append(f"  {BOLD}Size       :{RESET} {fmt_bytes(size)}")
    loc = datum.get("location")
    if loc is not None:
        lines.append(f"  {BOLD}Location   :{RESET} {loc}")
    props = datum.get("properties") or {}
    if props:
        for k, v in props.items():
            lines.append(f"  {DIM}prop.{k:<10}{RESET}: {v}")
    return "\n".join(lines)

def render_subject(datum, meta):
    lines = [
        f"  {BOLD}Subject Type:{RESET} {datum.get('type', 'N/A')}",
        f"  {BOLD}UUID        :{RESET} {uuid_hex(datum.get('uuid'))}",
        f"  {BOLD}PID/TID     :{RESET} {datum.get('pid', 'N/A')} / {datum.get('unitId', 'N/A')}",
        f"  {BOLD}CmdLine     :{RESET} {GREEN}{datum.get('cmdLine') or 'N/A'}{RESET}",
        f"  {BOLD}Start Time  :{RESET} {fmt_timestamp(datum.get('startTimestampNanos'))}",
        f"  {BOLD}Parent UUID :{RESET} {uuid_hex(datum.get('parentSubject'))}",
        f"  {BOLD}Principal   :{RESET} {uuid_hex(datum.get('localPrincipal'))}",
    ]
    props = datum.get("properties") or {}
    if props:
        for k, v in props.items():
            lines.append(f"  {DIM}prop.{k:<10}{RESET}: {v}")
    return "\n".join(lines)

def render_file_object(datum, meta):
    return "\n".join([
        f"  {BOLD}UUID        :{RESET} {uuid_hex(datum.get('uuid'))}",
        f"  {BOLD}Path/URL    :{RESET} {YELLOW}{datum.get('url') or 'N/A'}{RESET}",
        f"  {BOLD}Type        :{RESET} {datum.get('type', 'N/A')}",
        f"  {BOLD}File Desc   :{RESET} {datum.get('fileDescriptor', 'N/A')}",
        f"  {BOLD}Owner       :{RESET} {uuid_hex(datum.get('localPrincipal'))}",
        f"  {BOLD}Size        :{RESET} {fmt_bytes(datum.get('size'))}",
    ])

def render_netflow(datum, meta):
    return "\n".join([
        f"  {BOLD}UUID        :{RESET} {uuid_hex(datum.get('uuid'))}",
        f"  {BOLD}Local       :{RESET} {MAGENTA}{datum.get('localAddress', '?')}:{datum.get('localPort', '?')}{RESET}",
        f"  {BOLD}Remote      :{RESET} {MAGENTA}{datum.get('remoteAddress', '?')}:{datum.get('remotePort', '?')}{RESET}",
        f"  {BOLD}IP Protocol :{RESET} {datum.get('ipProtocol', 'N/A')}",
    ])

def render_host(datum, meta):
    return "\n".join([
        f"  {BOLD}UUID        :{RESET} {uuid_hex(datum.get('uuid'))}",
        f"  {BOLD}Hostname    :{RESET} {RED}{datum.get('hostName', 'N/A')}{RESET}",
        f"  {BOLD}OS          :{RESET} {datum.get('osDetails', 'N/A')}",
        f"  {BOLD}Host Type   :{RESET} {datum.get('hostType', 'N/A')}",
    ])

def render_principal(datum, meta):
    return "\n".join([
        f"  {BOLD}UUID        :{RESET} {uuid_hex(datum.get('uuid'))}",
        f"  {BOLD}User ID     :{RESET} {GREEN}{datum.get('userId', 'N/A')}{RESET}",
        f"  {BOLD}Group IDs   :{RESET} {datum.get('groupIds', [])}",
        f"  {BOLD}Type        :{RESET} {datum.get('type', 'N/A')}",
    ])

def render_generic(datum, meta):
    """Fallback renderer for all other record types."""
    lines = []
    for k, v in (datum or {}).items():
        if v is None:
            continue
        if isinstance(v, (bytes, bytearray)):
            v = uuid_hex(v)
        lines.append(f"  {BOLD}{k:<14}{RESET}: {v}")
    return "\n".join(lines) if lines else "  (empty)"

RENDERERS = {
    "RECORD_EVENT":               render_event,
    "RECORD_SUBJECT":             render_subject,
    "RECORD_FILE_OBJECT":         render_file_object,
    "RECORD_NET_FLOW_OBJECT":     render_netflow,
    "RECORD_HOST":                render_host,
    "RECORD_PRINCIPAL":           render_principal,
}

# ── Printer ───────────────────────────────────────────────────────────────────
def print_record(i, record, show_meta=True):
    rec_type = record.get("type", "UNKNOWN")
    datum = record.get("datum") or {}
    color = TYPE_COLOR.get(rec_type, RESET)

    # Header
    print(f"\n{BOLD}{color}{SEP}{RESET}")
    print(f"{BOLD}{color}  RECORD #{i+1}  |  {rec_type}{RESET}")
    if show_meta:
        print(f"  {DIM}CDM v{record.get('CDMVersion','?')}  |"
              f" Host: {uuid_hex(record.get('hostId'))}  |"
              f" Session: {record.get('sessionNumber','?')}  |"
              f" Source: {record.get('source','?')}{RESET}")
    print(f"{BOLD}{color}{SEP}{RESET}")

    # Body
    renderer = RENDERERS.get(rec_type, render_generic)
    print(renderer(datum, record))


# ── JSON helpers ──────────────────────────────────────────────────────────────
def _to_json_safe(obj):
    """Recursively make any value JSON-serialisable."""
    if obj is None:
        return None
    if isinstance(obj, (bytes, bytearray)):
        h = obj.hex()
        if len(obj) == 16:
            return f"{h[:8]}-{h[8:12]}-{h[12:16]}-{h[16:20]}-{h[20:]}"
        return h
    if isinstance(obj, dict):
        return {k: _to_json_safe(v) for k, v in obj.items() if v is not None}
    if isinstance(obj, list):
        return [_to_json_safe(x) for x in obj]
    return obj

def record_to_json(record):
    """Convert a raw Avro CDM record to a clean JSON-serialisable dict."""
    datum = record.get("datum") or {}
    rec_type = record.get("type", "")
    clean = _to_json_safe(dict(datum))

    # Decode timestamps to human-readable
    for ts_key in ("timestampNanos", "startTimestampNanos"):
        ts = clean.get(ts_key)
        if ts:
            try:
                clean[f"{ts_key}_utc"] = datetime.fromtimestamp(
                    ts / 1e9, tz=timezone.utc
                ).strftime("%Y-%m-%d %H:%M:%S.%f UTC")
            except Exception:
                pass

    return {
        "record_type": rec_type,
        "cdm_version":  record.get("CDMVersion"),
        "session":      record.get("sessionNumber"),
        "source":       record.get("source"),
        "host_id":      _to_json_safe(record.get("hostId")),
        "datum":        clean,
    }


# ── Stats mode ────────────────────────────────────────────────────────────────
def run_stats(avro_path, limit, rec_type_filter, search):
    """Scan the dataset and print a statistics summary."""
    open_fn = gzip.open if avro_path.endswith(".gz") else open
    rec_counts  = Counter()
    event_types = Counter()
    timestamps  = []
    active_uuids = Counter()
    total = 0

    print(f"\n{BOLD}Scanning dataset for statistics...{RESET}  {DIM}(Ctrl+C to stop early){RESET}\n")

    with open_fn(avro_path, "rb") as f:
        reader = DataFileReader(f, DatumReader())
        try:
            for record in reader:
                total += 1
                if limit and total > limit:
                    break
                rec_type = record.get("type", "")
                if rec_type_filter and rec_type != rec_type_filter:
                    continue
                if search and search.lower() not in str(record).lower():
                    continue
                rec_counts[rec_type] += 1
                datum = record.get("datum") or {}
                if rec_type == "RECORD_EVENT":
                    event_types[datum.get("type", "?")] += 1
                    ts = datum.get("timestampNanos")
                    if ts:
                        timestamps.append(ts)
                    subj = datum.get("subject")
                    if subj:
                        active_uuids[uuid_hex(subj)] += 1
                if total % 100000 == 0:
                    print(f"  {DIM}Scanned {total:,} records...{RESET}")
        except KeyboardInterrupt:
            print(f"\n  {YELLOW}Scan stopped early at {total:,} records.{RESET}")
        reader.close()

    print(f"\n{BOLD}{SEP}{RESET}")
    print(f"{BOLD}  DATASET STATISTICS REPORT{RESET}")
    print(f"{BOLD}{SEP}{RESET}")
    print(f"  Total records scanned : {BOLD}{total:,}{RESET}\n")

    print(f"{BOLD}  Record type breakdown:{RESET}")
    for k, v in rec_counts.most_common():
        bar = '#' * min(40, v * 40 // max(rec_counts.values()))
        pct = v * 100 / total if total else 0
        print(f"  {k:<30} {v:>10,}  ({pct:5.1f}%)  {DIM}{bar}{RESET}")

    if event_types:
        print(f"\n{BOLD}  Event type breakdown:{RESET}")
        max_v = event_types.most_common(1)[0][1]
        for k, v in event_types.most_common(20):
            bar = '#' * min(40, v * 40 // max_v)
            print(f"  {k:<30} {v:>10,}  {DIM}{bar}{RESET}")

    if timestamps:
        print(f"\n{BOLD}  Time range:{RESET}")
        print(f"  Start : {GREEN}{fmt_timestamp(min(timestamps))}{RESET}")
        print(f"  End   : {GREEN}{fmt_timestamp(max(timestamps))}{RESET}")
        span = (max(timestamps) - min(timestamps)) / 1e9
        print(f"  Span  : {span/3600:.2f} hours  ({span:.0f}s)")

    if active_uuids:
        print(f"\n{BOLD}  Top 10 most active subject UUIDs:{RESET}")
        for uid, cnt in active_uuids.most_common(10):
            print(f"  {CYAN}{uid}{RESET}  {cnt:,} events")

    print(f"\n{DIM}{SEP}{RESET}\n")

# -- Main ---------------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(
        description="DARPA Theia CDM20 Avro Viewer",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__
    )
    parser.add_argument("--file",    default=AVRO_PATH,      help="Path to .bin.1.gz")
    parser.add_argument("--limit",   type=int, default=10,   help="Max records (0 = all)")
    parser.add_argument("--offset",  type=int, default=0,    help="Skip first N records")
    parser.add_argument("--type",    default=None,           help="Filter by type e.g. RECORD_EVENT")
    parser.add_argument("--search",  default=None,           help="Keyword filter")
    parser.add_argument("--no-meta", action="store_true",    help="Hide host/session metadata")
    parser.add_argument("--json",    action="store_true",    help="Output clean JSON instead of pretty-print")
    parser.add_argument("--stats",   action="store_true",    help="Show dataset statistics summary")
    parser.add_argument("--out",     default=None,           help="Save output to file")
    args = parser.parse_args()

    # Redirect output to file if requested
    out_file = None
    if args.out:
        out_file = open(args.out, "w", encoding="utf-8")
        sys.stdout = out_file

    limit = args.limit if args.limit != 0 else None

    try:
        # -- Stats mode
        if args.stats:
            run_stats(args.file, limit, args.type, args.search)
            return

        open_fn = gzip.open if args.file.endswith(".gz") else open
        shown      = 0
        skipped    = 0
        total_read = 0
        json_records = [] if args.json else None

        if not args.json:
            print(f"\n{BOLD}DARPA Theia CDM20 Viewer{RESET}  {DIM}({args.file}){RESET}")
            if args.type:   print(f"  Filter: {CYAN}{args.type}{RESET}")
            if args.search: print(f"  Search: {YELLOW}\"{args.search}\"{RESET}")
            if args.offset: print(f"  Offset: {args.offset}")
            print(f"  Limit:  {limit or 'all'}")

        try:
            with open_fn(args.file, "rb") as f:
                reader = DataFileReader(f, DatumReader())
                for record in reader:
                    total_read += 1

                    rec_type = record.get("type", "")
                    if args.type and rec_type != args.type:
                        continue
                    if args.search and args.search.lower() not in str(record).lower():
                        continue
                    if skipped < args.offset:
                        skipped += 1
                        continue

                    if args.json:
                        json_records.append(record_to_json(record))
                    else:
                        print_record(total_read - 1, record, show_meta=not args.no_meta)

                    shown += 1
                    if limit and shown >= limit:
                        break

                reader.close()
        except KeyboardInterrupt:
            if not args.json:
                print(f"\n{YELLOW}Interrupted.{RESET}")

        # -- JSON output
        if args.json:
            output = json.dumps(json_records, indent=2, ensure_ascii=False)
            print(output)
            if not args.out:
                sys.stderr.write(f"\n{shown} records serialised to JSON.\n")
        else:
            print(f"\n{DIM}{SEP}{RESET}")
            print(f"  Showed {BOLD}{shown}{RESET} record(s)  |  Read {total_read:,} total from file")
            print()

    finally:
        if out_file:
            out_file.close()
            sys.stdout = sys.__stdout__
            print(f"[OK] Output saved to: {args.out}  ({shown} records)")

if __name__ == "__main__":
    main()