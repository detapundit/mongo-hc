import os
import json
import time
import yaml
import socket
import psutil
import requests
from datetime import datetime, timezone
from pymongo import MongoClient
from typing import Dict, Any
import logging
from logging.handlers import RotatingFileHandler


# ---------------- LOGGING ---------------- #
LOG_DIR = "/opt/monsum/logs"
os.makedirs(LOG_DIR, exist_ok=True)

LOG_FILE = os.path.join(LOG_DIR, "agent.log")

logging.basicConfig(level=logging.INFO)

file_handler = RotatingFileHandler(
    LOG_FILE,
    maxBytes=10 * 1024 * 1024,  # 10 MB
    backupCount=5
)

formatter = logging.Formatter(
    "%(asctime)s %(levelname)s %(message)s"
)
file_handler.setFormatter(formatter)

logger = logging.getLogger("monsum-agent")
logger.addHandler(file_handler)

# ---------------- CONFIG LOADER ---------------- #

def load_config(path="config.yaml") -> dict:
    with open(path) as f:
        return yaml.safe_load(f)

CONFIG = load_config()

# ---------------- GLOBALS FROM CONFIG ---------------- #

AGENT_ID = CONFIG["agent"]["id"]
INTERVAL = CONFIG["agent"]["interval_seconds"]

DATA_DIR = CONFIG["paths"]["data_dir"]
OFFSET_DIR = os.path.join(DATA_DIR, "offsets")
BUFFER_DIR = os.path.join(DATA_DIR, "buffers")
INVENTORY_DIR = os.path.join(DATA_DIR, "inventory")

MONGO_LOG_FILE = CONFIG["logs"]["mongod_log"]
SLOW_QUERY_MS = CONFIG["logs"]["slow_query_threshold_ms"]

MONGO_URI = CONFIG["mongo"]["uri"]
CONNECT_TIMEOUT = CONFIG["mongo"]["connect_timeout_ms"]

AGG_ENDPOINT = CONFIG["aggregator"]["endpoint"]
AGG_TIMEOUT = CONFIG["aggregator"]["timeout_seconds"]

HOSTNAME = socket.gethostname()

# Ensure dirs exist
for d in [OFFSET_DIR, BUFFER_DIR, INVENTORY_DIR]:
    os.makedirs(d, exist_ok=True)

# ---------------- UTILS ---------------- #

def utc_now():
    return datetime.now(timezone.utc).isoformat()

# ---------------- TOPOLOGY DETECTION ---------------- #

def detect_mongo_topology(client: MongoClient) -> dict:
    try:
        hello = client.admin.command("hello")
        if "setName" in hello:
            return {
                "type": "replicaset",
                "replicaSet": hello["setName"],
                "me": hello.get("me"),
                "primary": hello.get("primary")
            }

        shards = client.admin.command("listShards")
        return {
            "type": "sharded",
            "cluster": True,
            "shards": [s["_id"] for s in shards["shards"]]
        }
    except Exception:
        return {"type": "standalone"}

# ---------------- HOST METRICS ---------------- #

def collect_host_metrics() -> dict:
    return {
        "cpu_percent": psutil.cpu_percent(interval=1),
        "memory": psutil.virtual_memory()._asdict(),
        "disk": [
            {
                "mount": p.mountpoint,
                "used_percent": psutil.disk_usage(p.mountpoint).percent
            }
            for p in psutil.disk_partitions()
        ]
    }

# ---------------- MONGO METRICS ---------------- #

def collect_mongo_metrics(client: MongoClient) -> dict:
    server_status = client.admin.command("serverStatus")
    return {
        "version": server_status["version"],
        "connections": server_status["connections"],
        "opcounters": server_status["opcounters"]
    }

# ---------------- INDEX INVENTORY ---------------- #

def collect_index_inventory(client: MongoClient) -> dict:
    inventory = {}
    for db in client.list_database_names():
        if db in ("admin", "local", "config"):
            continue
        inventory[db] = {}
        for coll in client[db].list_collection_names():
            inventory[db][coll] = list(client[db][coll].list_indexes())
    return inventory

# ---------------- PACKAGE INVENTORY ---------------- #

def collect_packages() -> list:
    pkgs = []
    try:
        for p in os.popen("rpm -qa --qf '%{NAME} %{VERSION}\n'"):
            name, version = p.strip().split()
            pkgs.append({"name": name, "version": version})
    except Exception:
        pass
    return pkgs

# ---------------- PAYLOAD BUILDER ---------------- #

def build_payload() -> Dict[str, Any]:
    payload = {
        "deployment_id": AGENT_ID,
        "host": HOSTNAME,
        "timestamp": utc_now(),
    }

    with MongoClient(
        MONGO_URI,
        serverSelectionTimeoutMS=CONNECT_TIMEOUT
    ) as client:

        payload["topology"] = detect_mongo_topology(client)

        if CONFIG["features"]["collect_mongo_metrics"]:
            payload["mongo_metrics"] = collect_mongo_metrics(client)

        if CONFIG["features"]["collect_indexes"]:
            payload["index_inventory"] = collect_index_inventory(client)

    if CONFIG["features"]["collect_host_metrics"]:
        payload["host_metrics"] = collect_host_metrics()

    if CONFIG["features"]["collect_packages"]:
        payload["package_inventory"] = collect_packages()

    return payload

# ---------------- HTTP SENDER ---------------- #

def send_payload(payload: dict):
    try:
        r = requests.post(
            AGG_ENDPOINT,
            json=payload,
            timeout=AGG_TIMEOUT
        )
        r.raise_for_status()
    except Exception as e:
        fname = f"{BUFFER_DIR}/{int(time.time())}.json"
        with open(fname, "w") as f:
            json.dump(payload, f)

# ---------------- MAIN LOOP ---------------- #

def main():
    logger.info("Mongo agent started")

    while True:
        try:
            payload = build_payload()
            logger.info("Payload built successfully")
            send_payload(payload)
            logger.info("Payload sent to aggregator")
        except Exception as e:
            logger.exception("Agent loop failure")
        time.sleep(INTERVAL)

if __name__ == "__main__":
    main()
