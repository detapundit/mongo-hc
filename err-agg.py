#!/usr/bin/env python3

import json
import yaml
import os
import logging
from logging.handlers import RotatingFileHandler
from datetime import datetime, timezone
from collections import defaultdict
from typing import Dict, List

import requests
from flask import Flask, request, jsonify
from dotenv import load_dotenv
from openai import OpenAI
import tiktoken

# =========================================================
# CONFIG
# =========================================================

CONFIG_PATH = "/opt/agg-monsum/config.yaml"
with open(CONFIG_PATH, "r") as f:
    CONFIG = yaml.safe_load(f)

setup_logging(CONFIG)
logger = logging.getLogger("aggregator")

def setup_logging(cfg: dict):
    log_cfg = cfg.get("logging")

    # If logging not defined, fall back to basicConfig
    if not log_cfg:
        logging.basicConfig(
            level=logging.INFO,
            format="%(asctime)s | %(levelname)s | %(name)s | %(message)s"
        )
        logging.getLogger("werkzeug").setLevel(logging.WARNING)
        logging.getLogger("urllib3").setLevel(logging.WARNING)
        return

    level = getattr(logging, log_cfg.get("level", "INFO").upper())
    log_file = log_cfg.get("file", "/opt/monsum/logs/aggregator.log")
    max_mb = log_cfg.get("max_size_mb", 20)
    backups = log_cfg.get("backup_count", 5)
    fmt = log_cfg.get(
        "format",
        "%(asctime)s | %(levelname)s | %(name)s | %(message)s"
    )

    os.makedirs(os.path.dirname(log_file), exist_ok=True)

    handler = RotatingFileHandler(
        log_file,
        maxBytes=max_mb * 1024 * 1024,
        backupCount=backups
    )
    handler.setFormatter(logging.Formatter(fmt))

    root = logging.getLogger()
    root.setLevel(level)
    root.addHandler(handler)

    logging.getLogger("werkzeug").setLevel(logging.WARNING)
    logging.getLogger("urllib3").setLevel(logging.WARNING)



 logger.info("Aggregator starting")

 AGG = CONFIG["aggregator"]

 AGGREGATOR_ID = AGG["id"]
 OPENAI_MODEL = AGG["ai"]["model"]
 MAX_AI_TOKENS = AGG["ai"]["max_tokens"]
 AI_TEMPERATURE = AGG["ai"]["temperature"]

 OSV_API = AGG["feeds"]["osv_api"]
 MONGO_CVE_FEED = AGG["feeds"]["mongo_cve"]

 SUPPORTED_MAJORS = AGG["mongo"]["supported_majors"]
 PREFERRED_MAJOR = AGG["mongo"]["preferred_major"]

 TRIM_FIELDS = set(AGG["trimming"]["drop_fields"])

# =========================================================
# LOGGING
# =========================================================

def setup_logging(cfg: dict):
    log_cfg = cfg.get("logging")

    # If logging not defined, fall back to basicConfig
    if not log_cfg:
        logging.basicConfig(
            level=logging.INFO,
            format="%(asctime)s | %(levelname)s | %(name)s | %(message)s"
        )
        logging.getLogger("werkzeug").setLevel(logging.WARNING)
        logging.getLogger("urllib3").setLevel(logging.WARNING)
        return

    level = getattr(logging, log_cfg.get("level", "INFO").upper())
    log_file = log_cfg.get("file", "/opt/monsum/logs/aggregator.log")
    max_mb = log_cfg.get("max_size_mb", 20)
    backups = log_cfg.get("backup_count", 5)
    fmt = log_cfg.get(
        "format",
        "%(asctime)s | %(levelname)s | %(name)s | %(message)s"
    )

    os.makedirs(os.path.dirname(log_file), exist_ok=True)

    handler = RotatingFileHandler(
        log_file,
        maxBytes=max_mb * 1024 * 1024,
        backupCount=backups
    )
    handler.setFormatter(logging.Formatter(fmt))

    root = logging.getLogger()
    root.setLevel(level)
    root.addHandler(handler)

    logging.getLogger("werkzeug").setLevel(logging.WARNING)
    logging.getLogger("urllib3").setLevel(logging.WARNING)

# =========================================================
# APP INIT
# =========================================================

app = Flask(__name__)
load_dotenv("/opt/agg-monsum/aggregator.env")

client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))

DEPLOYMENTS: Dict[str, dict] = {}

# =========================================================
# TOKEN CONTROL
# =========================================================

def count_tokens(text: str) -> int:
    enc = tiktoken.encoding_for_model(OPENAI_MODEL)
    return len(enc.encode(text))

def trim_payload(payload: dict) -> dict:
    serialized = json.dumps(payload)
    if count_tokens(serialized) <= MAX_AI_TOKENS:
        return payload

    trimmed = payload.copy()
    for f in TRIM_FIELDS:
        trimmed.pop(f, None)
    return trimmed

# =========================================================
# TOPOLOGY
# =========================================================

def detect_topology(agent_payload: dict) -> dict:
    topo = agent_payload.get("topology", {})
    if topo.get("sharded"):
        return {"type": "sharded", "cluster": topo.get("cluster")}
    if topo.get("replicaSet"):
        return {"type": "replicaset", "rs": topo.get("replicaSet")}
    return {"type": "standalone"}

# =========================================================
# METRIC SUMMARIZERS
# =========================================================

def summarize_host_metrics(hosts: dict) -> dict:
    cpu, mem = [], []

    for h in hosts.values():
        m = h.get("host_metrics", {})
        if "cpu_percent" in m:
            cpu.append(m["cpu_percent"])
        if "memory" in m:
            mem.append(m["memory"].get("percent"))

    return {
        "cpu_avg": round(sum(cpu) / len(cpu), 2) if cpu else None,
        "cpu_max": max(cpu) if cpu else None,
        "memory_avg": round(sum(mem) / len(mem), 2) if mem else None
    }

def summarize_server_status(hosts: dict) -> dict:
    conns, queues = [], []

    for h in hosts.values():
        ss = h.get("server_status", {})
        if ss.get("connections"):
            conns.append(ss["connections"].get("current"))
        if ss.get("queues"):
            queues.append(sum(ss["queues"].values()))

    return {
        "connections_avg": round(sum(conns)/len(conns), 2) if conns else None,
        "queue_max": max(queues) if queues else None
    }

def summarize_replication(hosts: dict) -> dict:
    lags = []
    for h in hosts.values():
        for lag in h.get("replication_lag", {}).values():
            lags.append(lag)

    return {
        "max_lag_seconds": max(lags) if lags else 0,
        "replication_healthy": max(lags) < 10 if lags else True
    }

def summarize_slow_queries(hosts: dict) -> List[dict]:
    agg = defaultdict(list)

    for h in hosts.values():
        for q in h.get("slow_queries", []):
            agg[q["ns"]].append(q["duration_ms"])

    return [
        {
            "ns": ns,
            "count": len(v),
            "avg_ms": round(sum(v)/len(v), 2),
            "max_ms": max(v)
        }
        for ns, v in agg.items()
    ]

def summarize_log_health(hosts: dict) -> dict:
    errors, warnings = 0, 0
    for h in hosts.values():
        mh = h.get("mongo_log_health", {})
        errors += len(mh.get("errors", []))
        warnings += len(mh.get("warnings", []))

    return {
        "errors": errors,
        "warnings": warnings
    }

# =========================================================
# INDEX ANALYSIS
# =========================================================

def analyze_indexes(slow_queries: List[dict], indexes: dict) -> dict:
    recommendations, redundant = [], []
    seen = set()

    for q in slow_queries:
        shape = tuple(q.get("filter", []))
        if not shape or shape in seen:
            continue
        seen.add(shape)
        recommendations.append({
            "namespace": q["ns"],
            "suggested_index": list(shape),
            "reason": "Seen in slow query filter"
        })

    idx_map = defaultdict(list)
    for ns, idxs in indexes.items():
        for idx in idxs:
            key = tuple(idx["key"].keys())
            idx_map[(ns, key)].append(idx["name"])

    for (ns, key), names in idx_map.items():
        if len(names) > 1:
            redundant.append({
                "namespace": ns,
                "index_keys": list(key),
                "indexes": names
            })

    return {
        "recommended_indexes": recommendations,
        "redundant_indexes": redundant
    }

# =========================================================
# VERSION ADVISOR
# =========================================================

def mongo_upgrade_advisor(version: str) -> dict:
    if not version or version == "unknown":
        return {"status": "unknown"}

    major = ".".join(version.split(".")[:2])
    if major == PREFERRED_MAJOR:
        return {"status": "optimal", "current": version}
    if major in SUPPORTED_MAJORS:
        return {"status": "supported_not_preferred", "current": version, "recommended": PREFERRED_MAJOR}
    return {"status": "upgrade_required", "current": version, "recommended": PREFERRED_MAJOR}

# =========================================================
# AI SUMMARY
# =========================================================

def generate_ai_summary(summary: dict) -> str:
    trimmed = trim_payload(summary)

    logger.info(
        "AI summary | deployment=%s | tokens=%d",
        summary["deployment_id"],
        count_tokens(json.dumps(trimmed))
    )

    prompt = """
You are a senior MongoDB SRE.
Analyze the deployment health and provide:
- Key risks
- Performance bottlenecks
- Replication issues
- Index recommendations
- Log error interpretation
- Upgrade guidance
Be concise and actionable.
"""

    try:
        resp = client.chat.completions.create(
            model=OPENAI_MODEL,
            temperature=AI_TEMPERATURE,
            messages=[
                {"role": "system", "content": prompt},
                {"role": "user", "content": json.dumps(trimmed, indent=2)}
            ]
        )
        return resp.choices[0].message.content
    except Exception:
        logger.exception("AI summary failed")
        return "AI summary unavailable"

# =========================================================
# INGEST
# =========================================================

@app.route("/ingest", methods=["POST"])
def ingest():
    payload = request.json
    if not payload:
        return jsonify({"error": "empty payload"}), 400

    did, host = payload.get("deployment_id"), payload.get("host")
    if not did or not host:
        logger.warning("Invalid payload: %s", payload)
        return jsonify({"error": "invalid payload"}), 400

    DEPLOYMENTS.setdefault(did, {"hosts": {}, "created": datetime.now(timezone.utc).isoformat()})
    DEPLOYMENTS[did]["hosts"][host] = payload

    logger.info("Payload ingested | deployment=%s | host=%s", deployment_id, host)
    return jsonify({"status": "ok", "aggregator": AGGREGATOR_ID})

# =========================================================
# SUMMARY
# =========================================================

@app.route("/summary/<deployment_id>")
def summary(deployment_id):
    d = DEPLOYMENTS.get(deployment_id)
    if not d:
        return jsonify({"error": "unknown deployment"}), 404

    hosts = d["hosts"]
    versions = {h.get("mongo_version") for h in hosts.values()}

    deployment_summary = {
        "deployment_id": deployment_id,
        "topology": detect_topology(next(iter(hosts.values()))),
        "mongo_versions": list(versions),
        "host_metrics": summarize_host_metrics(hosts),
        "mongo_metrics": summarize_server_status(hosts),
        "replication": summarize_replication(hosts),
        "slow_queries": summarize_slow_queries(hosts),
        "log_health": summarize_log_health(hosts),
        "index_analysis": analyze_indexes(
            summarize_slow_queries(hosts),
            {k: v for h in hosts.values() for k, v in h.get("indexes", {}).items()}
        ),
        "upgrade_advisor": mongo_upgrade_advisor(next(iter(versions)))
    }

    deployment_summary["ai_summary"] = generate_ai_summary(deployment_summary)
    return jsonify(deployment_summary)

# =========================================================
# MAIN
# =========================================================

if __name__ == "__main__":
    app.run(
        host=AGG["server"]["bind_host"],
        port=AGG["server"]["port"]
    )
