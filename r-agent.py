#!/usr/bin/env python3

import json
import yaml
import time
import socket
import subprocess
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List

import psutil
import requests
from pymongo import MongoClient
from pygtail import Pygtail
from logging.handlers import RotatingFileHandler

# =========================================================
# CONFIG
# =========================================================

CONFIG_PATH = "/opt/monsum/config.yaml"

with open(CONFIG_PATH, "r") as f:
    CONFIG = yaml.safe_load(f)

AGENT = CONFIG["agent"]

AGENT_ID = AGENT["id"]
DEPLOYMENT_ID = AGENT["deployment_id"]
AGGREGATOR_URL = AGENT["aggregator_url"]

LOG_FILE = AGENT["mongo"]["log_file"]
OFFSET_DIR = AGENT["paths"]["offset_dir"]

MONGO_URI = AGENT["mongo"]["uri"]
SLOW_QUERY_THRESHOLD_MS = AGENT["mongo"]["slow_ms"]

SEND_INTERVAL = AGENT["send_interval"]

# =========================================================
# LOGGING
# =========================================================

def setup_logging(cfg):
    log_cfg = cfg["logging"]

    Path(log_cfg["file"]).parent.mkdir(parents=True, exist_ok=True)

    handler = RotatingFileHandler(
        log_cfg["file"],
        maxBytes=log_cfg["max_size_mb"] * 1024 * 1024,
        backupCount=log_cfg["backup_count"]
    )
    handler.setFormatter(logging.Formatter(log_cfg["format"]))

    root = logging.getLogger()
    root.setLevel(getattr(logging, log_cfg["level"]))
    root.addHandler(handler)

setup_logging(CONFIG)
logger = logging.getLogger("agent")

# =========================================================
# MONGO CONNECTION
# =========================================================

client = MongoClient(MONGO_URI, serverSelectionTimeoutMS=3000)

# =========================================================
# UTILITIES
# =========================================================

def now():
    return datetime.now(timezone.utc).isoformat()

# =========================================================
# TOPOLOGY
# =========================================================

def detect_topology() -> dict:
    try:
        hello = client.admin.command("hello")
        if hello.get("msg") == "isdbgrid":
            return {"sharded": True, "cluster": hello.get("setName")}
        if hello.get("setName"):
            return {"replicaSet": hello.get("setName")}
    except Exception:
        pass
    return {}

# =========================================================
# SERVER STATUS
# =========================================================

def collect_server_status() -> dict:
    try:
        ss = client.admin.command("serverStatus")
        return {
            "connections": ss.get("connections"),
            "opcounters": ss.get("opcounters"),
            "queues": ss.get("globalLock", {}).get("currentQueue"),
            "wiredTiger": ss.get("wiredTiger", {}).get("cache")
        }
    except Exception as e:
        logger.debug("serverStatus failed: %s", e)
        return {}

# =========================================================
# REPLICATION LAG
# =========================================================

def collect_replication_lag() -> dict:
    try:
        rs = client.admin.command("replSetGetStatus")
    except Exception:
        return {}

    primary_optime = None
    members = {}

    for m in rs.get("members", []):
        if m.get("stateStr") == "PRIMARY":
            primary_optime = m.get("optimeDate")
        else:
            members[m["name"]] = m.get("optimeDate")

    if not primary_optime:
        return {}

    return {
        host: int((primary_optime - opt).total_seconds())
        for host, opt in members.items()
        if opt
    }

# =========================================================
# INDEXES
# =========================================================

def collect_indexes(client):
    indexes = {}

    for db in client.list_database_names():
        if db in ("admin", "local", "config"):
            continue

        for coll in client[db].list_collection_names():
            idx_list = []
            for idx in client[db][coll].list_indexes():
                idx_list.append({
                    "name": idx["name"],
                    "key": dict(idx["key"])
                })

            indexes[f"{db}.{coll}"] = idx_list

    return indexes

# =========================================================
# MONGO VERSION
# =========================================================

def collect_mongo_version() -> str:
    try:
        return client.server_info()["version"]
    except Exception:
        return "unknown"

# =========================================================
# LOG PROCESSING
# =========================================================

def extract_query_shape(attr: dict) -> dict:
    return {
        "filter": list(attr.get("command", {}).get("filter", {}).keys())
    }

def process_logs() -> List[dict]:
    slow = []
    offset = Path(OFFSET_DIR) / "mongod.offset"

    for line in Pygtail(LOG_FILE, offset_file=str(offset)):
        try:
            log = json.loads(line)
        except Exception:
            continue

        if log.get("msg") == "Slow query":
            dur = log.get("attr", {}).get("durationMillis", 0)
            if dur >= SLOW_QUERY_THRESHOLD_MS:
                slow.append({
                    "ns": log.get("attr", {}).get("ns"),
                    "duration_ms": dur,
                    **extract_query_shape(log.get("attr", {}))
                })

    return slow

def collect_mongo_errors() -> dict:
    errors, warnings = [], []
    offset = Path(OFFSET_DIR) / "mongod.errwarn.offset"

    for line in Pygtail(LOG_FILE, offset_file=str(offset)):
        try:
            log = json.loads(line)
        except Exception:
            continue

        entry = {
            "ts": log.get("t", {}).get("$date"),
            "msg": log.get("msg")
        }

        if log.get("s") == "E":
            errors.append(entry)
        elif log.get("s") == "W":
            warnings.append(entry)

    return {
        "errors": errors[-50:],
        "warnings": warnings[-50:]
    }

# =========================================================
# HOST METRICS
# =========================================================

def collect_host_metrics() -> dict:
    return {
        "cpu_percent": psutil.cpu_percent(),
        "memory": psutil.virtual_memory()._asdict(),
        "disk": {
            p.mountpoint: psutil.disk_usage(p.mountpoint)._asdict()
            for p in psutil.disk_partitions()
        }
    }

# =========================================================
# PACKAGES
# =========================================================

def collect_packages() -> List[dict]:
    pkgs = []
    try:
        out = subprocess.check_output(["rpm", "-qa"], text=True)
        for p in out.splitlines():
            pkgs.append({"name": p})
    except Exception:
        pass
    return pkgs

# =========================================================
# PAYLOAD
# =========================================================

def build_payload() -> dict:
    return {
        "agent_id": AGENT_ID,
        "deployment_id": DEPLOYMENT_ID,
        "host": socket.gethostname(),
        "timestamp": now(),

        "topology": detect_topology(),
        "mongo_version": collect_mongo_version(),
        "server_status": collect_server_status(),
        "replication_lag": collect_replication_lag(),
        "indexes": collect_indexes(client),
        "slow_queries": process_logs(),
        "mongo_log_health": collect_mongo_errors(),
        "host_metrics": collect_host_metrics(),
        "packages": collect_packages()
    }

# =========================================================
# MAIN LOOP
# =========================================================

#logger.info("Agent started | id=%s deployment=%s", AGENT_ID, DEPLOYMENT_ID)
payload = build_payload()
logger.info("Agent started | id=%s deployment=%s", AGENT_ID, DEPLOYMENT_ID, payload.get("slow_queries"))

while True:
    payload = build_payload()

    try:
        r = requests.post(f"{AGGREGATOR_URL}/ingest", json=payload, timeout=5)
        logger.info("Payload sent | status=%s", r.status_code)
    except Exception:
        logger.exception("Failed to send payload")

    time.sleep(SEND_INTERVAL)
