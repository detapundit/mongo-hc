
  File "/opt/agg-monsum/agg_ai.py", line 68, in <module>
    client = OpenAI()
             ^^^^^^^^
  File "/opt/agg-monsum/venv/lib64/python3.12/site-packages/openai/_client.py", line 137, in __init__
    raise OpenAIError(
openai.OpenAIError: The api_key client option must be set either by passing api_key to the client or by setting the OPENAI_API_KEY environment variable



import logging
from logging.handlers import RotatingFileHandler
import os


def setup_logging(cfg: dict):
    log_cfg = cfg.get("logging", {})

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


setup_logging(CONFIG)
logger = logging.getLogger("aggregator")

logger.info("Aggregator starting")
logger.info("Aggregator ID: %s", AGGREGATOR_ID)
logger.info("Listening on %s:%s",
            AGG["server"]["bind_host"],
            AGG["server"]["port"])


@app.route("/ingest", methods=["POST"])
def ingest():
    payload = request.json

    if not payload:
        logger.warning("Empty ingest payload received")
        return jsonify({"error": "empty payload"}), 400

    deployment_id = payload.get("deployment_id")
    host = payload.get("host")

    if not deployment_id or not host:
        logger.warning("Invalid ingest payload: %s", payload)
        return jsonify({"error": "invalid payload"}), 400

    DEPLOYMENTS.setdefault(deployment_id, {
        "hosts": {},
        "created": datetime.now(timezone.utc).isoformat()
    })

    DEPLOYMENTS[deployment_id]["hosts"][host] = payload

    logger.info(
        "Ingested payload | deployment=%s | host=%s",
        deployment_id, host
    )

    return jsonify({"status": "ok", "aggregator": AGGREGATOR_ID})

@app.route("/summary/<deployment_id>")
def summary(deployment_id):
    logger.info("Summary requested for deployment %s", deployment_id)

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


def lookup_os_cves(packages: List[dict]) -> List[dict]:
    findings = []

    logger.info("OS CVE lookup started | packages=%d", len(packages))

    for p in packages:
        try:
            r = requests.post(OSV_API, json={
                "package": {"name": p["name"], "ecosystem": "Linux"}
            }, timeout=5)

            if not r.ok:
                logger.debug("OSV lookup failed for package %s", p["name"])
                continue

            for v in r.json().get("vulns", []):
                findings.append({
                    "package": p["name"],
                    "cve": v["id"],
                    "summary": v.get("summary")
                })

        except Exception as e:
            logger.debug("OSV exception for %s: %s", p["name"], e)

    logger.info("OS CVE findings=%d", len(findings))
    return findings


def generate_ai_summary(deployment: dict) -> str:
    trimmed = trim_payload(deployment, MAX_AI_TOKENS)

    logger.info(
        "Generating AI summary | deployment=%s | tokens=%d",
        deployment.get("deployment_id"),
        count_tokens(json.dumps(trimmed))
    )


try:
        response = client.chat.completions.create(
            model=OPENAI_MODEL,
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": json.dumps(trimmed, indent=2)}
            ],
            temperature=AI_TEMPERATURE
        )
        return response.choices[0].message.content

    except Exception:
        logger.exception("AI summary generation failed")
        return "AI summary unavailable"



@app.route("/compare")
def compare():
    logger.info("Multi-deployment comparison requested")

    return jsonify({
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "deployments": [...]
    })



'''
[Service]
ExecStart=/opt/agg-monsum/venv/bin/python aggregator.py
WorkingDirectory=/opt/agg-monsum
Restart=always
User=monsum
Group=monsum

# Safety
LimitNOFILE=65536

# Environment
Environment=CONFIG_FILE=/etc/monsum/config.yaml

logging:
  level: INFO
  file: /opt/monsum/logs/aggregator.log
  max_size_mb: 20
  backup_count: 5
  format: "%(asctime)s | %(levelname)s | %(name)s | %(message)s"
'''
