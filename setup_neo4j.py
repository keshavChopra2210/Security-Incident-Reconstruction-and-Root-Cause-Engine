"""
setup_neo4j.py -- Download, configure, and start Neo4j 4.4 Community Edition (Windows)
Automatically downloads a portable OpenJDK 11 if the system Java is too old.
No admin rights required.
"""

import os
import sys
import subprocess
import urllib.request
import zipfile
import time

BASE_DIR     = os.path.dirname(os.path.abspath(__file__))
NEO4J_VERSION = "4.4.30"
NEO4J_ZIP    = f"neo4j-community-{NEO4J_VERSION}-windows.zip"
NEO4J_URL    = f"https://dist.neo4j.org/neo4j-community-{NEO4J_VERSION}-windows.zip"
# Use a path WITHOUT spaces -- the JVM fails to load java.security when PATH has spaces
INSTALL_ROOT = r"C:\neo4j_theia"
NEO4J_DIR    = os.path.join(INSTALL_ROOT, "neo4j")
NEO4J_HOME   = os.path.join(NEO4J_DIR, f"neo4j-community-{NEO4J_VERSION}")

# Portable OpenJDK 11 full JDK (Adoptium / Eclipse Temurin) -- no install needed
# Using full JDK (not JRE) to avoid java.security/JFR errors on Windows
JDK_VERSION  = "11.0.23+9"
JDK_SLUG     = "11.0.23_9"
JDK_ZIP      = f"OpenJDK11U-jdk_x64_windows_hotspot_{JDK_SLUG}.zip"
JDK_URL      = (
    f"https://github.com/adoptium/temurin11-binaries/releases/download/"
    f"jdk-{JDK_VERSION.replace('+', '%2B')}/"
    f"{JDK_ZIP}"
)
JDK_DIR      = os.path.join(INSTALL_ROOT, "jdk11")
JDK_HOME     = os.path.join(JDK_DIR, f"jdk-{JDK_VERSION}")

# ── Helpers ───────────────────────────────────────────────────────────────────
def reporthook(block, block_size, total):
    downloaded = min(block * block_size, total)
    pct = downloaded * 100 // total if total > 0 else 0
    mb_done = downloaded // 1024 // 1024
    mb_total = total // 1024 // 1024
    print(f"\r  {pct:3d}%  {mb_done}MB / {mb_total}MB", end="", flush=True)

def get_java_version(java_exe):
    """Return (major, minor) or None if not parseable."""
    try:
        out = subprocess.check_output(
            [java_exe, "-version"], stderr=subprocess.STDOUT, timeout=5
        ).decode(errors="replace")
        # 'java version "11.0.23"' or 'openjdk version "11.0.23"'
        import re
        m = re.search(r'"(\d+)[\._](\d+)', out)
        if m:
            major = int(m.group(1))
            minor = int(m.group(2))
            # Java 9+ uses major directly; Java 1.8 reports major=1
            if major == 1:
                major = minor
            return major
    except Exception:
        pass
    return None

# ── Step 1: Java ─────────────────────────────────────────────────────────────
def ensure_java():
    """Return path to a Java 11+ executable, downloading if needed."""
    # Check portable JDK first
    portable = os.path.join(JDK_HOME, "bin", "java.exe")
    if os.path.exists(portable):
        ver = get_java_version(portable)
        if ver and ver >= 11:
            print(f"[OK] Portable JDK found: Java {ver} at {portable}")
            return portable

    # Check system Java
    system_java = "java"
    ver = get_java_version(system_java)
    if ver and ver >= 11:
        print(f"[OK] System Java {ver} is compatible.")
        return system_java

    # Need to download
    ver_str = f"Java {ver}" if ver else "unknown"
    print(f"[!] System Java ({ver_str}) is too old for Neo4j 4.4 (needs Java 11+).")
    print(f"[->] Downloading portable OpenJDK 11 (~44MB, no install needed)...")

    os.makedirs(JDK_DIR, exist_ok=True)
    zip_path = os.path.join(JDK_DIR, JDK_ZIP)

    if not os.path.exists(zip_path):
        try:
            urllib.request.urlretrieve(JDK_URL, zip_path, reporthook=reporthook)
            print()
        except Exception as e:
            print(f"\n[FAIL] Could not download JDK: {e}")
            print("       Please install Java 11+ from https://adoptium.net/ and retry.")
            sys.exit(1)
    else:
        print(f"[OK] JDK zip already present: {zip_path}")

    print(f"[->] Extracting JDK to {JDK_DIR}...")
    with zipfile.ZipFile(zip_path, 'r') as zf:
        zf.extractall(JDK_DIR)

    # Find the extracted java.exe (folder name may vary slightly)
    for root, dirs, files in os.walk(JDK_DIR):
        if "java.exe" in files and os.path.basename(root) == "bin":
            java_exe = os.path.join(root, "java.exe")
            ver = get_java_version(java_exe)
            if ver and ver >= 11:
                print(f"[OK] Portable JDK 11 ready: {java_exe}")
                return java_exe

    print("[FAIL] Could not locate java.exe after extraction.")
    sys.exit(1)

# ── Step 2: Neo4j ─────────────────────────────────────────────────────────────
def download_neo4j():
    zip_path = os.path.join(NEO4J_DIR, NEO4J_ZIP)
    os.makedirs(NEO4J_DIR, exist_ok=True)

    if os.path.exists(NEO4J_HOME):
        print(f"[OK] Neo4j already extracted at {NEO4J_HOME}")
        return

    if not os.path.exists(zip_path):
        print(f"[->] Downloading Neo4j {NEO4J_VERSION} (~113MB)...")
        urllib.request.urlretrieve(NEO4J_URL, zip_path, reporthook=reporthook)
        print()
    else:
        print(f"[OK] Neo4j zip already present: {zip_path}")

    print(f"[->] Extracting to {NEO4J_DIR}...")
    with zipfile.ZipFile(zip_path, 'r') as zf:
        zf.extractall(NEO4J_DIR)
    print("[OK] Extraction complete.")

def configure_neo4j(java_exe):
    conf_path = os.path.join(NEO4J_HOME, "conf", "neo4j.conf")

    # Restore conf from zip if it was deleted
    if not os.path.exists(conf_path):
        print("[!] neo4j.conf missing — restoring from zip...")
        zip_path = os.path.join(NEO4J_DIR, NEO4J_ZIP)
        conf_zip_name = f"neo4j-community-{NEO4J_VERSION}/conf/neo4j.conf"
        with zipfile.ZipFile(zip_path, 'r') as zf:
            zf.extract(conf_zip_name, NEO4J_DIR)
        print("[OK] neo4j.conf restored.")

    with open(conf_path, "r") as f:
        conf = f.read()

    changes = {
        "#dbms.security.auth_enabled=false": "dbms.security.auth_enabled=false",
        "#dbms.memory.heap.initial_size=512m": "dbms.memory.heap.initial_size=1g",
        "#dbms.memory.heap.max_size=512m":    "dbms.memory.heap.max_size=4g",
        "#dbms.memory.pagecache.size=10g":    "dbms.memory.pagecache.size=2g",
        "#dbms.connector.bolt.listen_address=:7687": "dbms.connector.bolt.listen_address=:7687",
    }
    for old, new in changes.items():
        if old in conf:
            conf = conf.replace(old, new)
        elif new not in conf:
            conf += f"\n{new}"

    # Disable JFR (Flight Recorder) which conflicts with portable JDK on Windows
    # Do NOT set -Djava.home here -- it breaks java.security loading.
    # JAVA_HOME is set correctly via the subprocess environment in start_neo4j().
    extras = [
        "dbms.jvm.additional=-XX:-FlightRecorder",
        "dbms.jvm.additional=-Djdk.attach.allowAttachSelf=true",
    ]
    for line in extras:
        if line not in conf:
            conf += f"\n{line}"

    with open(conf_path, "w") as f:
        f.write(conf)
    print("[OK] Neo4j configured (auth disabled, 4GB heap, Java 11 path set).")

def start_neo4j(java_exe):
    java_home = os.path.dirname(os.path.dirname(java_exe))
    env = os.environ.copy()
    env["JAVA_HOME"] = java_home
    env["PATH"] = os.path.dirname(java_exe) + os.pathsep + env.get("PATH", "")

    neo4j_ps1 = os.path.join(NEO4J_HOME, "bin", "neo4j.bat")
    print(f"[->] Starting Neo4j with Java 11...")
    proc = subprocess.Popen(
        [neo4j_ps1, "console"],
        env=env,
        cwd=NEO4J_HOME,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )

    print("[->] Waiting for Neo4j to be ready (up to 90s)...")
    for i in range(90):
        time.sleep(1)
        # Check if process died
        if proc.poll() is not None:
            out, err = proc.communicate()
            print(f"\n[FAIL] Neo4j process exited unexpectedly.")
            print("STDOUT:", out.decode(errors="replace")[-1000:])
            print("STDERR:", err.decode(errors="replace")[-1000:])
            sys.exit(1)
        try:
            from neo4j import GraphDatabase
            d = GraphDatabase.driver("bolt://localhost:7687", auth=("neo4j", "neo4j"))
            d.verify_connectivity()
            d.close()
            print(f"\n[OK] Neo4j is running!")
            print(f"     Bolt:    bolt://localhost:7687")
            print(f"     Browser: http://localhost:7474")
            return proc
        except Exception:
            print(f"\r  Waiting... {i+1}s", end="", flush=True)

    print("\n[FAIL] Neo4j did not respond within 90s.")
    print(f"       Check logs: {NEO4J_HOME}\\logs\\")
    return proc

# ── Main ──────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    print("=" * 60)
    print("  Neo4j 4.4 Setup for DARPA Theia Analysis")
    print("=" * 60)

    java_exe = ensure_java()
    download_neo4j()
    configure_neo4j(java_exe)
    proc = start_neo4j(java_exe)

    print("\n[->] Neo4j is running. Press Ctrl+C to stop.")
    try:
        proc.wait()
    except KeyboardInterrupt:
        proc.terminate()
        print("\n[OK] Neo4j stopped.")
