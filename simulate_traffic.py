import json
import urllib.request
import urllib.error
import time

API_URL = "http://localhost:8080/api/v1/logs/ingest"

print("=====================================================================")
print("  AI-Assisted Forensic Engine: UNSW-NB15 Live Traffic Ingestion Demo  ")
print("=====================================================================")

count = 0
with open("UNSW-NB15_1.csv", "r") as f:
    for line in f:
        line = line.strip()
        if not line:
            continue
            
        payload = {
            "source": "UNSW_NB15",
            "rawLog": line
        }
        
        data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(API_URL, data=data, headers={"Content-Type": "application/json"})
        
        try:
            with urllib.request.urlopen(req, timeout=5) as response:
                if response.status == 200:
                    res = json.loads(response.read().decode())
                    event = res.get("normalizedEvent", {})
                    sub = event.get("subject", "N/A")
                    rel = event.get("relationship", "CONNECTED")
                    obj = event.get("object", "N/A")
                    root_hash = res.get("merkleRoot", "")[:12]
                    leaf_hash = res.get("eventHash", "")[:12]
                    
                    print(f"[{count+1:02d}] {sub:15} --[{rel:12}]--> {obj:15} | Leaf: {leaf_hash}.. | MerkleRoot: {root_hash}..")
                else:
                    print(f"Error {response.status}")
        except urllib.error.HTTPError as e:
            err_msg = e.read().decode()
            print(f"HTTP Error {e.code}: {err_msg}")
            break
        except Exception as e:
            print(f"Failed to connect to API. Is the Spring Boot server running? ({e})")
            break
            
        count += 1
        if count >= 30: # 30 events is clean, fast, and builds a great graph
            break
            
        time.sleep(0.1)

print("=====================================================================")
print(f"  Ingestion Complete: {count} events parsed, cryptographically chained,")
print("  and persisted to Neo4j Aura Graph Database.")
print("=====================================================================")
