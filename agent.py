import json
import time
import logging
import psutil
import socket
import subprocess
import requests
from datetime import datetime, timezone
from pymongo import MongoClient
from pygtail import Pygtail
import re


# ---------------- CONFIG ---------------- #

MONGO_URI = "mongodb://localhost:27017"
MONGO_LOG_FILE = "./data/mongod.log"
AGGREGATOR_URL = "http://JUMP_SERVER:8000/collect"

SLOW_QUERY_THRESHOLD_MS = 500

HOST_METRIC_INTERVAL = 300        # 5 min
SERVERSTATUS_INTERVAL = 900       # 15 min
INDEX_INTERVAL = 86400            # daily
PACKAGE_INTERVAL = 86400          # daily
SEND_INTERVAL = 60                # batch send

# --------------------------------------- #

logging.basicConfig(level=logging.INFO)

hostname = socket.gethostname()
client = MongoClient(MONGO_URI)

buffer = {
    "slow_logs": [],
    "errors": [],
    "warnings": [],
    "host_metrics": [],
    "server_status": [],
    "indexes": None,
    "packages": None,
    "mongo_version": None
}

last = {
    "host": 0,
    "server": 0,
    "index": 0,
    "package": 0,
    "send": 0
}

# ---------------- Mongo Helpers ---------------- #

def detect_topology():
    hello = client.admin.command("hello")
    if hello.get("msg") == "isdbgrid":
        return {"type": "sharded", "id": "cluster"}
    if "setName" in hello:
        return {"type": "replicaset", "id": hello["setName"]}
    return {"type": "standalone", "id": hostname}

TOPOLOGY = detect_topology()

def collect_server_status():
    ss = client.admin.command("serverStatus")
    data = {
        "timestamp": time.time(),
        "connections": ss["connections"],
        "opcounters": ss["opcounters"],
        "locks": ss.get("locks", {}),
        "wiredTiger_cache": ss.get("wiredTiger", {}).get("cache", {}),
    }

    # replication lag
    if TOPOLOGY["type"] == "replicaset":
        status = client.admin.command("replSetGetStatus")
        primary = next(m for m in status["members"] if m["stateStr"] == "PRIMARY")
        lag = {}
        for m in status["members"]:
            if m["stateStr"] == "SECONDARY":
                lag[m["name"]] = primary["optimeDate"] - m["optimeDate"]
        data["replication_lag"] = {k: v.total_seconds() for k, v in lag.items()}

    return data

def collect_indexes():
    result = {}
    for db in client.list_database_names():
        result[db] = {}
        for coll in client[db].list_collection_names():
            result[db][coll] = list(client[db][coll].list_indexes())
    return result

def mongo_version():
    return client.server_info()["version"]
    
def extract_query_shape(log):
    attr = log.get("attr", {})
    command = attr.get("command", {})
    if not command:
        return None

    return {
        "db": attr.get("ns", "").split(".")[0],
        "collection": attr.get("ns", "").split(".")[1],
        "filter": command.get("filter", {}),
        "sort": command.get("sort", {}),
        "duration_ms": attr.get("durationMillis", 0),
        "planSummary": attr.get("planSummary", "")
    }

# ---------------- Host Helpers ---------------- #

def collect_host_metrics():
    return {
        "timestamp": time.time(),
        "cpu": psutil.cpu_percent(),
        "memory": psutil.virtual_memory().percent,
        "disk": [
            {
                "mount": p.mountpoint,
                "used": psutil.disk_usage(p.mountpoint).percent
            }
            for p in psutil.disk_partitions(all=False)
        ]
    }

def collect_packages():
    try:
        out = subprocess.check_output(["rpm", "-qa"], stderr=subprocess.DEVNULL)
        return out.decode().splitlines()
    except Exception:
        return []

# ---------------- Log Processing ---------------- #

def process_logs():
    for line in Pygtail(MONGO_LOG_FILE):
        try:
            log = json.loads(line)
        except:
            continue

        msg = log.get("msg", "")
        sev = log.get("s")

        if sev == "E":
            buffer["errors"].append(log)
        elif sev == "W":
            buffer["warnings"].append(log)
        elif msg == "Slow query":
            dur = log.get("attr", {}).get("durationMillis", 0)
            if dur >= SLOW_QUERY_THRESHOLD_MS:
                shape = extract_query_shape(log)
                if shape:
                    buffer["slow_logs"].append(shape)

# ---------------- Main Loop ---------------- #

while True:
    now = time.time()

    process_logs()

    if now - last["host"] >= HOST_METRIC_INTERVAL:
        buffer["host_metrics"].append(collect_host_metrics())
        last["host"] = now

    if now - last["server"] >= SERVERSTATUS_INTERVAL:
        buffer["server_status"].append(collect_server_status())
        last["server"] = now

    if now - last["index"] >= INDEX_INTERVAL:
        buffer["indexes"] = collect_indexes()
        last["index"] = now

    if now - last["package"] >= PACKAGE_INTERVAL:
        buffer["packages"] = collect_packages()
        buffer["mongo_version"] = mongo_version()
        last["package"] = now

    if now - last["send"] >= SEND_INTERVAL:
        payload = {
            "host": hostname,
            "topology": TOPOLOGY,
            "data": buffer
        }
        try:
            requests.post(AGGREGATOR_URL, json=payload, timeout=5)
            buffer = {k: [] if isinstance(v, list) else None for k, v in buffer.items()}
        except Exception as e:
            logging.error(e)
        last["send"] = now

    time.sleep(1)
