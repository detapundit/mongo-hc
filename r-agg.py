import json
import yaml
import requests
from datetime import datetime, timezone
from collections import defaultdict
from typing import Dict, List
from dotenv import load_dotenv
import os
import logging
from logging.handlers import RotatingFileHandler

from flask import Flask, request, jsonify
from openai import OpenAI
import tiktoken

# ---------------- CONFIG LOADING ---------------- #

CONFIG_PATH = "/opt/agg-monsum/config.yaml"
with open(CONFIG_PATH, "r") as f:
    CONFIG = yaml.safe_load(f)

AGG = CONFIG["aggregator"]

AGGREGATOR_ID = AGG["id"]
OPENAI_MODEL = AGG["ai"]["model"]
MAX_AI_TOKENS = AGG["ai"]["max_tokens"]
AI_TEMPERATURE = AGG["ai"]["temperature"]

MONGO_CVE_FEED = AGG["feeds"]["mongo_cve"]
OSV_API = AGG["feeds"]["osv_api"]

LATEST_MONGO_MAJOR = AGG["mongo"]["preferred_major"]
TRIM_FIELDS = set(AGG["trimming"]["drop_fields"])

# ---------------- LOGGING SETUP ---------------- #

def setup_logging(cfg: dict):
    log_cfg = cfg.get("logging", {})
    level = getattr(logging, log_cfg.get("level", "INFO").upper())
    log_file = log_cfg.get("file", "/opt/agg-monsum/logs/aggregator.log")
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

setup_logging(CONFIG)
logger = logging.getLogger("aggregator")
logger.info("Aggregator starting | ID=%s", AGGREGATOR_ID)

# ---------------- APP INIT ---------------- #

app = Flask(__name__)
load_dotenv("/opt/agg-monsum/aggregator.env")
client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))
raw_key = os.getenv("OPENAI_API_KEY")
logger.info(
        "OpenAI key debug | len=%d | prefix=%s | suffix=%s",
        len(raw_key) if raw_key else -1,
        raw_key[:10] if raw_key else "NONE",
        raw_key[-6]  if raw_key else "NONE",
)
DEPLOYMENTS: Dict[str, dict] = {}

# ---------------- TOKEN CONTROL ---------------- #

def count_tokens(text: str) -> int:
    enc = tiktoken.encoding_for_model(OPENAI_MODEL)
    return len(enc.encode(text))

def trim_payload(payload: dict, max_tokens: int) -> dict:
    serialized = json.dumps(payload)
    if count_tokens(serialized) <= max_tokens:
        return payload

    trimmed = payload.copy()
    for field in TRIM_FIELDS:
        trimmed.pop(field, None)

    return trimmed

# ---------------- TOPOLOGY ---------------- #

def detect_topology(agent_payload: dict) -> dict:
    topo = agent_payload.get("topology", {})
    if topo.get("sharded"):
        return {"type": "sharded", "cluster": topo.get("cluster")}
    if topo.get("replicaSet"):
        return {"type": "replicaset", "rs": topo.get("replicaSet")}
    return {"type": "standalone"}

# ---------------- INDEX ADVISOR ---------------- #

def analyze_indexes(slow_queries: List[dict], indexes: dict) -> dict:
    recommendations = []
    redundant = []

    seen_patterns = set()

    # ---------- Index recommendations from slow queries ----------
    for q in slow_queries:
        filt = q.get("filter", {})
        if not isinstance(filt, dict) or not filt:
            continue

        shape = tuple(sorted(filt.keys()))
        if shape in seen_patterns:
            continue
        seen_patterns.add(shape)

        recommendations.append({
            "namespace": q.get("ns"),
            "suggested_index": list(shape),
            "reason": "Observed in slow query filter"
        })

    # ---------- Redundant index detection ----------
    index_keys = defaultdict(list)

    for ns, idxs in indexes.items():
        if not isinstance(idxs, list):
            continue

        for idx in idxs:
            # Case 1: Proper index dict
            if isinstance(idx, dict) and "key" in idx:
                key_tuple = tuple(idx["key"].keys())
                index_keys[(ns, key_tuple)].append(idx.get("name", "unknown"))

            # Case 2: String index → skip (cannot analyze redundancy)
            else:
                continue

    for (ns, key), names in index_keys.items():
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

# ---------------- CVE LOOKUP ---------------- #

def lookup_os_cves(packages: List[dict]) -> List[dict]:
    findings = []
    logger.info("OS CVE lookup | packages=%d", len(packages))
    for p in packages:
        try:
            r = requests.post(OSV_API, json={"package": {"name": p["name"], "ecosystem": "Linux"}}, timeout=5)
            if not r.ok:
                logger.debug("OSV lookup failed for %s", p["name"])
                continue
            for v in r.json().get("vulns", []):
                findings.append({"package": p["name"], "cve": v["id"], "summary": v.get("summary")})
        except Exception as e:
            logger.debug("OSV exception for %s: %s", p["name"], e)
    logger.info("OS CVE findings=%d", len(findings))
    return findings

def lookup_mongo_cves(mongo_version: str) -> List[dict]:
    try:
        r = requests.get(MONGO_CVE_FEED, timeout=10)
        if not r.ok:
            return []
    except Exception:
        return []

    findings = []
    for item in r.json():
        if mongo_version in item.get("affected_versions", []):
            findings.append({"cve": item["cve"], "severity": item.get("severity"), "description": item.get("description")})
    return findings

# ---------------- VERSION ADVISOR ---------------- #

SUPPORTED_MAJORS = AGG["mongo"]["supported_majors"]
PREFERRED_MAJOR = AGG["mongo"]["preferred_major"]

def mongo_upgrade_advisor(current_version: str) -> dict:
    current_major = ".".join(current_version.split(".")[:2])
    if current_major in SUPPORTED_MAJORS:
        if current_major == PREFERRED_MAJOR:
            return {"status": "optimal", "current": current_version}
        return {"status": "supported_but_not_preferred", "current": current_version, "recommended": PREFERRED_MAJOR}
    return {"status": "upgrade_required", "current": current_version, "recommended": PREFERRED_MAJOR}

# ---------------- AI SUMMARY ---------------- #

def generate_ai_summary(deployment: dict) -> str:
    trimmed = trim_payload(deployment, MAX_AI_TOKENS)
    logger.info("Generating AI summary | deployment=%s | tokens=%d", deployment.get("deployment_id"), count_tokens(json.dumps(trimmed)))
    system_prompt = """
You are a senior MongoDB SRE.
Analyze the deployment summary and provide:
- Key risks
- Performance bottlenecks
- Index recommendations
- Security vulnerabilities (MongoDB + OS)
- Upgrade advice
- Overall health verdict
Be concise and technical.
"""
    try:
        response = client.chat.completions.create(
            model=OPENAI_MODEL,
            messages=[{"role": "system", "content": system_prompt}, {"role": "user", "content": json.dumps(trimmed, indent=2)}],
            temperature=AI_TEMPERATURE
        )
        return response.choices[0].message.content
    except Exception:
        logger.exception("AI summary generation failed")
        return "AI summary unavailable"

# ---------------- INGEST API ---------------- #

@app.route("/ingest", methods=["POST"])
def ingest():
    payload = request.json
    if not payload:
        logger.warning("Empty ingest payload")
        return jsonify({"error": "empty payload"}), 400

    deployment_id = payload.get("deployment_id")
    host = payload.get("host")
    if not deployment_id or not host:
        logger.warning("Invalid ingest payload: %s", payload)
        return jsonify({"error": "invalid payload"}), 400

    DEPLOYMENTS.setdefault(deployment_id, {"hosts": {}, "created": datetime.now(timezone.utc).isoformat()})
    DEPLOYMENTS[deployment_id]["hosts"][host] = payload
    logger.info("Payload ingested | deployment=%s | host=%s", deployment_id, host)
    return jsonify({"status": "ok", "aggregator": AGGREGATOR_ID})

# ---------------- SUMMARY API ---------------- #

@app.route("/summary/<deployment_id>")
def summary(deployment_id):
    logger.info("Summary requested | deployment=%s", deployment_id)
    d = DEPLOYMENTS.get(deployment_id)
    if not d:
        logger.warning("Unknown deployment requested: %s", deployment_id)
        return jsonify({"error": "unknown deployment"}), 404

    slow, indexes, os_packages = [], {}, []
    mongo_versions = set()
    for h in d["hosts"].values():
        slow.extend(h.get("slow_queries", []))
        indexes.update(h.get("indexes", {}))
        os_packages.extend(h.get("packages", []))
        mongo_versions.add(h.get("mongo_version"))

    version = next(iter(mongo_versions))
    deployment_summary = {
        "deployment_id": deployment_id,
        "topology": detect_topology(next(iter(d["hosts"].values()))),
        "mongo_version": list(mongo_versions),
        "index_analysis": analyze_indexes(slow, indexes),
        "security": {"os_cves": lookup_os_cves(os_packages), "mongo_cves": lookup_mongo_cves(version)},
        "upgrade_advisor": mongo_upgrade_advisor(version)
    }
    deployment_summary["ai_summary"] = generate_ai_summary(deployment_summary)
    return jsonify(deployment_summary)

# ---------------- COMPARISON API ---------------- #

@app.route("/compare")
def compare():
    logger.info("Multi-deployment comparison requested")
    return jsonify({
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "deployments": [
            {
                "deployment": did,
                "hosts": len(d["hosts"]),
                "mongo_versions": list(set(h.get("mongo_version") for h in d["hosts"].values()))
            } for did, d in DEPLOYMENTS.items()
        ]
    })

# ---------------- MAIN ---------------- #

if __name__ == "__main__":
    app.run(host=AGG["server"]["bind_host"], port=AGG["server"]["port"])
