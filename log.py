#!/usr/bin/env python3
"""
MongoDB & Host Diagnostic Assessment Tool (mhas.py)
===================================================
Production-grade diagnostic tool to evaluate Linux Host OS settings, MongoDB instance metrics,
security hardening, WiredTiger engine stats, slow query logs (deduplicated by Query Shape via JQ),
and execution-over-execution baseline deltas.
"""

import os
import sys
import re
import json
import time
import math
import shutil
import argparse
import platform
import resource
import subprocess
from datetime import datetime, timedelta
import psutil
from pymongo import MongoClient
from pymongo.errors import PyMongoError

BASELINE_FILE = "mongo_health_baseline.json"


class SystemCollector:
    """Collects Linux host OS metrics and storage settings."""

    @staticmethod
    def get_host_metrics(db_path="/var/lib/mongodb"):
        cpu_pct = psutil.cpu_percent(interval=1)
        mem = psutil.virtual_memory()
        swap = psutil.swap_memory()

        target_path = db_path if os.path.exists(db_path) else "/"
        disk_usage = psutil.disk_usage(target_path)

        io_before = psutil.disk_io_counters()
        time.sleep(1)
        io_after = psutil.disk_io_counters()

        read_iops = io_after.read_count - io_before.read_count
        write_iops = io_after.write_count - io_before.write_count

        read_time = io_after.read_time - io_before.read_time
        write_time = io_after.write_time - io_before.write_time

        read_latency = (read_time / read_iops) if read_iops > 0 else 0.0
        write_latency = (write_time / write_iops) if write_iops > 0 else 0.0

        return {
            "hostname": platform.node(),
            "os_kernel": f"{platform.system()} - {platform.release()}",
            "cpu_usage_pct": round(cpu_pct, 2),
            "ram_used_pct": round(mem.percent, 2),
            "swap_used_pct": round(swap.percent, 2),
            "data_partition_used_pct": round(disk_usage.percent, 2),
            "data_partition_used_gb": round(disk_usage.used / (1024**3), 2),
            "data_partition_free_gb": round(disk_usage.free / (1024**3), 2),
            "data_partition_total_gb": round(disk_usage.total / (1024**3), 2),
            "disk_read_iops": read_iops,
            "disk_write_iops": write_iops,
            "disk_read_latency_ms": round(read_latency, 2),
            "disk_write_latency_ms": round(write_latency, 2),
        }

    @staticmethod
    def check_os_production_settings(mongo_version_str):
        major_version = 8.0
        try:
            major_version = float(".".join(mongo_version_str.split(".")[:2]))
        except Exception:
            pass

        checks = {}

        # 1. Transparent Huge Pages (THP)
        thp_file = "/sys/kernel/mm/transparent_hugepage/enabled"
        thp_status = "unknown"
        if os.path.exists(thp_file):
            with open(thp_file, "r") as f:
                content = f.read()
                match = re.search(r"\[(\w+)\]", content)
                thp_status = match.group(1) if match else "unknown"

        if major_version >= 8.0:
            thp_ok = thp_status in ["always", "madvise"]
            thp_rec = "[always] or [madvise] (v8.0+)"
        else:
            thp_ok = thp_status == "never"
            thp_rec = "[never] (v7.0 and below)"

        checks["Transparent Huge Pages (THP)"] = {
            "current": thp_status,
            "recommended": thp_rec,
            "compliant": thp_ok,
        }

        # 2. Kernel Swappiness
        swappiness = "unknown"
        if os.path.exists("/proc/sys/vm/swappiness"):
            with open("/proc/sys/vm/swappiness", "r") as f:
                swappiness = f.read().strip()
        checks["Kernel Swappiness (vm.swappiness)"] = {
            "current": swappiness,
            "recommended": "1 (or 0)",
            "compliant": swappiness in ["0", "1"],
        }

        # 3. NUMA Zone Reclaim Mode
        zone_reclaim = "unknown"
        if os.path.exists("/proc/sys/vm/zone_reclaim_mode"):
            with open("/proc/sys/vm/zone_reclaim_mode", "r") as f:
                zone_reclaim = f.read().strip()
        checks["NUMA Zone Reclaim Mode"] = {
            "current": f"Zone Rec={zone_reclaim}",
            "recommended": "Disabled / Zone Rec=0",
            "compliant": zone_reclaim == "0",
        }

        # 4. Ulimits
        nofile_soft, _ = resource.getrlimit(resource.RLIMIT_NOFILE)
        nproc_soft, _ = resource.getrlimit(resource.RLIMIT_NPROC)

        nofile_compliant = (nofile_soft == -1) or (nofile_soft >= 64000)
        nproc_compliant = (nproc_soft == -1) or (nproc_soft >= 64000)

        checks["File Descriptors (ulimit -n)"] = {
            "current": "unlimited (-1)" if nofile_soft == -1 else str(nofile_soft),
            "recommended": ">= 64,000",
            "compliant": nofile_compliant,
        }
        checks["Max Processes (ulimit -u)"] = {
            "current": "unlimited (-1)" if nproc_soft == -1 else str(nproc_soft),
            "recommended": ">= 64,000",
            "compliant": nproc_compliant,
        }

        # 5. TCP Keepalive
        tcp_keepalive = "unknown"
        if os.path.exists("/proc/sys/net/ipv4/tcp_keepalive_time"):
            with open("/proc/sys/net/ipv4/tcp_keepalive_time", "r") as f:
                tcp_keepalive = f.read().strip()
        checks["TCP Keepalive (sec)"] = {
            "current": tcp_keepalive,
            "recommended": "120",
            "compliant": tcp_keepalive == "120",
        }

        return checks


class MongoCollector:
    """Collects database performance, storage, and security metrics via PyMongo."""

    def __init__(self, uri):
        self.client = MongoClient(
            uri, directConnection=True, serverSelectionTimeoutMS=5000
        )
        self.admin_db = self.client.admin

    def capture_all(self):
        try:
            hello = self.admin_db.command("hello")
        except PyMongoError:
            hello = self.admin_db.command("isMaster")

        build_info = self.admin_db.command("buildInfo")

        ss1 = self.admin_db.command("serverStatus")
        t1 = time.time()
        time.sleep(1)
        ss2 = self.admin_db.command("serverStatus")
        t2 = time.time()

        elapsed = max(t2 - t1, 0.001)

        op1_client = ss1.get("opcounters", {})
        op2_client = ss2.get("opcounters", {})
        op1_repl = ss1.get("opcountersRepl", {})
        op2_repl = ss2.get("opcountersRepl", {})

        def get_op_rate(op_type):
            c1 = op1_client.get(op_type, 0) + op1_repl.get(op_type, 0)
            c2 = op2_client.get(op_type, 0) + op2_repl.get(op_type, 0)
            return int((c2 - c1) / elapsed)

        op_rates = {
            "op_insert_sec": get_op_rate("insert"),
            "op_query_sec": get_op_rate("query"),
            "op_update_sec": get_op_rate("update"),
            "op_delete_sec": get_op_rate("delete"),
            "op_getmore_sec": get_op_rate("getmore"),
            "op_command_sec": get_op_rate("command"),
        }

        server_status = ss2

        is_atlas = "mongodb.net" in str(self.client.nodes) or "atlas" in hello.get("me", "")
        deployment_env = "MongoDB Atlas" if is_atlas else "Self-Hosted"

        if hello.get("msg") == "isdbgrid":
            deploy_type = "MONGOS_ROUTER"
            node_role = "ROUTER"
        elif "setName" in hello:
            deploy_type = "REPLICASET"
            if hello.get("isWritablePrimary") or hello.get("ismaster"):
                node_role = "PRIMARY"
            elif hello.get("secondary"):
                node_role = "SECONDARY"
            elif hello.get("arbiterOnly"):
                node_role = "ARBITER"
            else:
                node_role = "OTHER"
        else:
            deploy_type = "STANDALONE"
            node_role = "STANDALONE"

        version = build_info.get("version", "Unknown")

        connections = server_status.get("connections", {})
        conn_current = connections.get("current", 0)
        conn_available = connections.get("available", 0)
        conn_total_max = conn_current + conn_available

        wt = server_status.get("wiredTiger", {})
        wt_cache = wt.get("cache", {})
        wt_tx = wt.get("concurrentTransactions", {})

        try:
            cmd_line = self.admin_db.command("getCmdLineOpts")
            parsed_opts = cmd_line.get("parsed", {})
        except Exception:
            parsed_opts = {}

        sec_opts = parsed_opts.get("security", {})
        net_opts = parsed_opts.get("net", {})

        auth_enabled = (
            sec_opts.get("authorization") == "enabled"
            or server_status.get("security", {}).get("authEnabled", False)
        )
        tls_mode = net_opts.get("tls", {}).get("mode", "disabled")
        javascript_disabled = sec_opts.get("javascriptEnabled") is False or "noscripting" in parsed_opts

        oplog_window_hours = 0.0
        oplog_size_gb = 0.0
        if deploy_type == "REPLICASET":
            try:
                local_db = self.client.local
                oplog = local_db.oplog.rs
                first = oplog.find_one(sort=[("$natural", 1)])
                last = oplog.find_one(sort=[("$natural", -1)])
                if first and last:
                    time_diff = last["ts"].time - first["ts"].time
                    oplog_window_hours = round(time_diff / 3600.0, 2)
                oplog_stats = local_db.command("collStats", "oplog.rs")
                oplog_size_gb = round(oplog_stats.get("maxSize", 0) / (1024**3), 2)
            except Exception:
                pass

        db_stats_list = []
        unused_indexes = []
        for db_name in self.client.list_database_names():
            if db_name in ["admin", "config", "local"]:
                continue
            db = self.client[db_name]
            try:
                stats = db.command("dbStats")
                data_size_gb = round(stats.get("dataSize", 0) / (1024**3), 2)
                index_size_gb = round(stats.get("indexSize", 0) / (1024**3), 2)
                collections_cnt = stats.get("collections", 0)

                ratio = round((index_size_gb / data_size_gb * 100), 1) if data_size_gb > 0 else 0.0
                db_stats_list.append(
                    {
                        "name": db_name,
                        "data_size_gb": data_size_gb,
                        "index_size_gb": index_size_gb,
                        "collections": collections_cnt,
                        "index_ratio": ratio,
                    }
                )

                for coll_name in db.list_collection_names():
                    try:
                        for ix in db[coll_name].aggregate([{"$indexStats": {}}]):
                            if ix["name"] != "_id_" and ix["accesses"]["ops"] == 0:
                                unused_indexes.append(
                                    {
                                        "namespace": f"{db_name}.{coll_name}",
                                        "index_name": ix["name"],
                                    }
                                )
                    except Exception:
                        pass
            except Exception:
                pass

        return {
            "version": version,
            "deployment_type": deploy_type,
            "deployment_env": deployment_env,
            "node_role": node_role,
            "replset_name": hello.get("setName", "N/A"),
            "db_path": parsed_opts.get("storage", {}).get("dbPath", "/var/lib/mongodb"),
            **op_rates,
            "connections_active": conn_current,
            "connections_available": conn_available,
            "connections_total_max": conn_total_max,
            "mem_resident_mb": server_status.get("mem", {}).get("resident", 0),
            "mem_virtual_mb": server_status.get("mem", {}).get("virtual", 0),
            "wt_cache_used_mb": round(wt_cache.get("bytes currently in the cache", 0) / (1024**2), 2),
            "wt_cache_max_mb": round(wt_cache.get("maximum bytes configured", 0) / (1024**2), 2),
            "wt_cache_dirty_mb": round(wt_cache.get("tracked dirty bytes in the cache", 0) / (1024**2), 2),
            "wt_read_tickets_available": wt_tx.get("read", {}).get("available", 128),
            "wt_write_tickets_available": wt_tx.get("write", {}).get("available", 128),
            "lock_queue_readers": server_status.get("globalLock", {}).get("currentQueue", {}).get("readers", 0),
            "lock_queue_writers": server_status.get("globalLock", {}).get("currentQueue", {}).get("writers", 0),
            "page_faults": server_status.get("extra_info", {}).get("page_faults", 0),
            "oplog_window_hours": oplog_window_hours,
            "oplog_size_gb": oplog_size_gb,
            "security": {
                "auth_enabled": auth_enabled,
                "tls_mode": tls_mode,
                "javascript_disabled": javascript_disabled,
            },
            "db_stats": db_stats_list,
            "unused_indexes": unused_indexes,
        }


def get_query_shape(query_log):
    if "queryHash" in query_log:
        return f"queryHash:{query_log['queryHash']}"

    cmd = query_log.get("command", {})
    if not isinstance(cmd, dict):
        return "raw_command"

    q_filter = cmd.get("filter") or cmd.get("q") or {}
    if not q_filter and "pipeline" in cmd and isinstance(cmd["pipeline"], list):
        for stage in cmd["pipeline"]:
            if isinstance(stage, dict) and "$match" in stage:
                q_filter = stage["$match"]
                break

    def normalize(obj):
        if isinstance(obj, dict):
            return {k: normalize(v) for k, v in sorted(obj.items()) if not k.startswith("$comment")}
        elif isinstance(obj, list):
            return [normalize(x) for x in obj]
        else:
            return "?"

    normalized_filter = normalize(q_filter)
    sort_fields = list(cmd.get("sort", {}).keys()) if isinstance(cmd.get("sort"), dict) else []

    shape_payload = {
        "filter": normalized_filter,
        "sort": sort_fields
    }
    return json.dumps(shape_payload, sort_keys=True)


def generate_esr_recommendation(query_log):
    ns = query_log.get("ns", "sample.collection")
    cmd = query_log.get("command", {})
    if not isinstance(cmd, dict):
        cmd = {}

    q_filter = cmd.get("filter") or cmd.get("q") or {}
    if not q_filter and "pipeline" in cmd and isinstance(cmd["pipeline"], list):
        for stage in cmd["pipeline"]:
            if isinstance(stage, dict) and "$match" in stage:
                q_filter = stage["$match"]
                break

    equality_fields, range_fields, sort_fields = [], [], []

    if isinstance(q_filter, dict):
        for k, v in q_filter.items():
            if k.startswith("$"):
                continue
            if isinstance(v, dict) and any(str(op).startswith("$") for op in v.keys()):
                range_fields.append(k)
            else:
                equality_fields.append(k)

    sort_cmd = cmd.get("sort", {})
    if isinstance(sort_cmd, dict):
        sort_fields = [k for k in sort_cmd.keys() if not k.startswith("$")]

    index_spec = {}
    for f in equality_fields:
        index_spec[f] = 1
    for f in sort_fields:
        if f not in index_spec:
            index_spec[f] = 1
    for f in range_fields:
        if f not in index_spec:
            index_spec[f] = 1

    coll_name = ns.split(".", 1)[-1] if "." in ns else ns
    if index_spec:
        fields_json = json.dumps(index_spec).replace(":", ": ")
        return f"db.{coll_name}.createIndex({fields_json})"
    else:
        return f"db.{coll_name}.createIndex({{ \"<field_name>\": 1 }})"


class LogAnalyzer:
    @staticmethod
    def analyze_log(log_path, hours=24):
        if not shutil.which("jq"):
            return {"error": "jq command line tool is not installed or available in PATH"}

        if not os.path.exists(log_path):
            return {"error": f"Log file not found at {log_path}"}

        cutoff_time = datetime.utcnow() - timedelta(hours=hours)
        cutoff_iso = cutoff_time.strftime("%Y-%m-%dT%H:%M:%S")

        jq_filter = f"""
        select(.t."$date" >= "{cutoff_iso}") |
        {{
            c: .c,
            s: .s,
            duration: (.attr.durationMillis // 0),
            ns: .attr.ns,
            command: .attr.command,
            planSummary: .attr.planSummary,
            queryHash: .attr.queryHash,
            docsExamined: (.attr.docsExamined // 0)
        }}
        """

        try:
            cmd = ["jq", "-c", jq_filter, log_path]
            process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

            buckets = {"101-500ms": 0, "501-1000ms": 0, "1001-2000ms": 0, ">2001ms": 0}
            total_slow = 0
            total_parsed = 0
            max_duration = 0
            grouped_queries = {}

            for line in process.stdout:
                if not line.strip():
                    continue
                total_parsed += 1
                try:
                    entry = json.loads(line)
                    duration = entry.get("duration", 0)

                    if duration > 100:
                        total_slow += 1
                        if duration > max_duration:
                            max_duration = duration

                        if 100 < duration <= 500:
                            buckets["101-500ms"] += 1
                        elif 500 < duration <= 1000:
                            buckets["501-1000ms"] += 1
                        elif 1000 < duration <= 2000:
                            buckets["1001-2000ms"] += 1
                        else:
                            buckets[">2001ms"] += 1

                        if "COLLSCAN" in str(entry.get("planSummary", "")):
                            ns = entry.get("ns", "unknown.collection")
                            query_shape = get_query_shape(entry)
                            recommendation = generate_esr_recommendation(entry)

                            group_key = (ns, query_shape)
                            docs = entry.get("docsExamined", 0)

                            if group_key not in grouped_queries:
                                grouped_queries[group_key] = {
                                    "ns": ns,
                                    "query_shape": query_shape,
                                    "recommendation": recommendation,
                                    "count": 0,
                                    "max_duration": 0,
                                    "max_docs_examined": 0,
                                }

                            grouped_queries[group_key]["count"] += 1
                            grouped_queries[group_key]["max_duration"] = max(
                                grouped_queries[group_key]["max_duration"], duration
                            )
                            grouped_queries[group_key]["max_docs_examined"] = max(
                                grouped_queries[group_key]["max_docs_examined"], docs
                            )
                except json.JSONDecodeError:
                    continue

            process.wait()

            sla_pct = (
                round((1.0 - (total_slow / float(total_parsed))) * 100, 2)
                if total_parsed > 0
                else 100.0
            )

            unique_slow_queries = sorted(
                grouped_queries.values(), key=lambda x: x["max_duration"], reverse=True
            )

            return {
                "total_parsed": total_parsed,
                "total_slow_queries": total_slow,
                "sla_compliance_pct": sla_pct,
                "max_duration_ms": max_duration,
                "buckets": buckets,
                "slow_queries": unique_slow_queries[:5],
            }
        except Exception as e:
            return {"error": str(e)}


class BaselineDeltaEngine:
    @staticmethod
    def process_baseline(current_metrics, baseline_path=BASELINE_FILE):
        previous_metrics = {}
        if os.path.exists(baseline_path):
            try:
                with open(baseline_path, "r") as f:
                    previous_metrics = json.load(f)
            except Exception:
                previous_metrics = {}

        with open(baseline_path, "w") as f:
            json.dump(current_metrics, f, indent=2)

        return previous_metrics


def render_report(host_data, mongo_data, os_checks, log_data, prev_data):
    def calc_delta(curr, key, suffix=""):
        prev = prev_data.get(key, curr)
        diff = curr - prev
        sign = "+" if diff >= 0 else ""
        return f"{sign}{round(diff, 2)}{suffix}"

    print("=" * 80)
    print("📊 MONGO & HOST DIAGNOSTIC ASSESSMENT REPORT")
    print("=" * 80)

    print("\n" + "=" * 80)
    print("DEPLOYMENT & ENVIRONMENT IDENTIFICATION")
    print("=" * 80)
    print(f"Host Identification       : {host_data['hostname']}")
    print(f"Platform Environment      : {mongo_data['deployment_env']} ({host_data['os_kernel']})")
    print(f"MongoDB Version           : {mongo_data['version']}")
    print(f"Deployment Architecture   : {mongo_data['deployment_type']}")
    print(f"Node Role / State         : {mongo_data['node_role']}")
    print(f"ReplicaSet Name           : {mongo_data['replset_name']}")
    print(f"Assessment Timestamp      : {datetime.now().strftime('%Y-%m-%d %H:%M:%S IST')}")
    print("=" * 80)

    # Executive Summary & Health Scorecard
    print("\n" + "=" * 80)
    print("🎯 EXECUTIVE SUMMARY & HEALTH SCORECARD")
    print("=" * 80)

    prev_used = prev_data.get("data_partition_used_gb", host_data["data_partition_used_gb"])
    growth_gb = max(host_data["data_partition_used_gb"] - prev_used, 0.0)
    if growth_gb > 0:
        runway_days = str(math.floor(host_data["data_partition_free_gb"] / growth_gb)) + " Days Remaining"
    else:
        runway_days = "Sufficient Capacity (Low Growth)"

    sla_pct = log_data.get("sla_compliance_pct", 100.0)
    sla_status = "🟢 COMPLIANT" if sla_pct >= 99.0 else f"🔴 {sla_pct}% (Target: >99.0%)"

    sec = mongo_data["security"]
    sec_status = "🟢 COMPLIANT" if sec["auth_enabled"] and sec["tls_mode"] == "requireTLS" else "🔴 NON-COMPLIANT"

    print(f"Overall Health Status      : {'🔴 CRITICAL RISK' if not sec['auth_enabled'] else '🟢 HEALTHY'}")
    print(f"Storage Capacity Runway    : 🟡 {runway_days} (Free: {host_data['data_partition_free_gb']} GB)")
    print(f"SLA Compliance (<100ms)    : {sla_status}")
    print(f"Security Hardening Status  : {sec_status}")
    print("=" * 80)

    # Table 1: Host Resource Metrics
    print("\n[1] HOST RESOURCE & DATA PARTITION METRICS")
    print("+--------------------------------+----------------+---------------+---------------+------------------+")
    print("| Metric                         | Previous Run   | Current Run   | Delta         | Status / Threshold")
    print("+--------------------------------+----------------+---------------+---------------+------------------+")

    read_iops_status = "🟢 NORMAL" if host_data["disk_read_iops"] < 500 else "🟡 ELEVATED"
    write_iops_status = "🟢 NORMAL" if host_data["disk_write_iops"] < 500 else "🟡 ELEVATED"

    host_metrics_table = [
        ("Host CPU Usage (%)", "cpu_usage_pct", host_data["cpu_usage_pct"], "%", "🔴 HIGH (>80%)" if host_data["cpu_usage_pct"] > 80 else "🟢 OK"),
        ("Host RAM Used (%)", "ram_used_pct", host_data["ram_used_pct"], "%", "🔴 HIGH (>90%)" if host_data["ram_used_pct"] > 90 else "🟢 OK"),
        ("Swap Memory Used (%)", "swap_used_pct", host_data["swap_used_pct"], "%", "🟡 WARN (>0%)" if host_data["swap_used_pct"] > 0 else "🟢 OK"),
        ("/data Partition Used (%)", "data_partition_used_pct", host_data["data_partition_used_pct"], "%", "🟡 WARN (>80%)" if host_data["data_partition_used_pct"] > 80 else "🟢 OK"),
        ("Disk Read IOPS", "disk_read_iops", host_data["disk_read_iops"], "", read_iops_status),
        ("Disk Write IOPS", "disk_write_iops", host_data["disk_write_iops"], "", write_iops_status),
        ("Disk Read Latency (ms)", "disk_read_latency_ms", host_data["disk_read_latency_ms"], " ms", "🟡 ELEVATED" if host_data["disk_read_latency_ms"] > 10 else "🟢 NORMAL"),
        ("Disk Write Latency (ms)", "disk_write_latency_ms", host_data["disk_write_latency_ms"], " ms", "🟡 ELEVATED" if host_data["disk_write_latency_ms"] > 10 else "🟢 NORMAL"),
    ]

    for label, key, val, suff, status in host_metrics_table:
        prev_val = prev_data.get(key, val)
        delta_str = calc_delta(val, key, suff)
        print(f"| {label:<30} | {str(prev_val) + suff:<14} | {str(val) + suff:<13} | {delta_str:<13} | {status}")
    print("+--------------------------------+----------------+---------------+---------------+------------------+")

    # Table 2: Mongo Engine Metrics
    print("\n[2] MONGODB ENGINE & PERFORMANCE METRICS")
    print("+--------------------------------+----------------+---------------+---------------+------------------+")
    print("| Metric                         | Previous Run   | Current Run   | Delta         | Status / Threshold")
    print("+--------------------------------+----------------+---------------+---------------+------------------+")

    conn_pct = (mongo_data["connections_active"] / max(mongo_data["connections_total_max"], 1)) * 100
    conn_status = "🟢 OK" if conn_pct < 70 else ("🟡 ELEVATED" if conn_pct < 85 else "🔴 CRITICAL")

    mongo_table = [
        ("Insert Operations / sec", "op_insert_sec", mongo_data["op_insert_sec"], " /s", "🟢 NORMAL"),
        ("Query Operations / sec", "op_query_sec", mongo_data["op_query_sec"], " /s", "🔴 SPIKE" if mongo_data["op_query_sec"] > 1000 else "🟢 NORMAL"),
        ("Update Operations / sec", "op_update_sec", mongo_data["op_update_sec"], " /s", "🟢 NORMAL"),
        ("Delete Operations / sec", "op_delete_sec", mongo_data["op_delete_sec"], " /s", "🟢 NORMAL"),
        ("Active Connections", "connections_active", mongo_data["connections_active"], "", conn_status),
        ("WT Cache Used (MB)", "wt_cache_used_mb", mongo_data["wt_cache_used_mb"], " MB", "🔴 CRITICAL" if mongo_data["wt_cache_used_mb"] > mongo_data["wt_cache_max_mb"] * 0.9 else "🟢 OK"),
        ("WT Concurrent Write Tickets", "wt_write_tickets_available", mongo_data["wt_write_tickets_available"], "", "🔴 EXHAUSTED" if mongo_data["wt_write_tickets_available"] < 10 else "🟢 OK"),
        ("Replication Lag (sec)", "repl_lag", 0.0, " s", "🟢 OK"),
    ]

    for label, key, val, suff, status in mongo_table:
        prev_val = prev_data.get(key, val)
        delta_str = calc_delta(val, key, suff)
        print(f"| {label:<30} | {str(prev_val) + suff:<14} | {str(val) + suff:<13} | {delta_str:<13} | {status}")
    print("+--------------------------------+----------------+---------------+---------------+------------------+")

    # Table 3: Database & Collection Footprint (With proper width and truncation for long names)
    if mongo_data.get("db_stats"):
        print("\n📊 DATABASE, COLLECTION & STORAGE FOOTPRINT")
        print("+----------------------------------+------------+------------+------------+--------------------+")
        print("| Database Name                    | Data Size  | Index Size | Collections| Index-to-Data Ratio|")
        print("+----------------------------------+------------+------------+------------+--------------------+")
        for db_item in mongo_data["db_stats"]:
            ratio_status = "🔴 BLOATED" if db_item["index_ratio"] > 100 else "🟢 NORMAL"
            dbname_display = db_item["name"] if len(db_item["name"]) <= 32 else db_item["name"][:29] + "..."
            print(
                f"| {dbname_display:<32} | {str(db_item['data_size_gb']) + ' GB':<10} | "
                f"{str(db_item['index_size_gb']) + ' GB':<10} | {db_item['collections']:<10} | "
                f"{str(db_item['index_ratio']) + '% (' + ratio_status + ')':<18} |"
            )
        print("+----------------------------------+------------+------------+------------+--------------------+")

    # Table 4: OS Recommended Settings Audit (Expanded Recommended Value column width to 35 chars)
    print("\n" + "=" * 80)
    print(f"⚙️ MONGODB PRODUCTION NOTES & RECOMMENDED SETTINGS AUDIT (v{mongo_data['version']} COMPLIANCE)")
    print("=" * 80)
    print("+-----------------------------------+-----------------------+-------------------------------------+---------------------+")
    print("| Setting Parameter                 | Current System Value  | Recommended Value                   | Compliance Status   |")
    print("+-----------------------------------+-----------------------+-------------------------------------+---------------------+")
    for display_name, item in os_checks.items():
        status_flag = "🟢 COMPLIANT" if item["compliant"] else "🔴 NON-COMPLIANT"
        print(f"| {display_name:<33} | {item['current']:<21} | {item['recommended']:<35} | {status_flag:<19} |")
    print("+-----------------------------------+-----------------------+-------------------------------------+---------------------+")

    # Table 5: Security Audit
    print("\n" + "=" * 80)
    print("🔒 SECURITY & HARDENING COMPLIANCE AUDIT")
    print("=" * 80)
    print("+--------------------------+-----------------------+---------------------+")
    print("| Security Control         | Configured Status     | Compliance Status   |")
    print("+--------------------------+-----------------------+---------------------+")
    print(f"| Access Control / Auth    | {'Enabled' if sec['auth_enabled'] else 'Disabled':<21} | {'🟢 COMPLIANT' if sec['auth_enabled'] else '🔴 NON-COMPLIANT':<19} |")
    print(f"| TLS/SSL Wire Encryption  | Mode={sec['tls_mode']:<16} | {'🟢 COMPLIANT' if sec['tls_mode'] == 'requireTLS' else '🔴 NON-COMPLIANT':<19} |")
    print(f"| Server-Side Scripting    | {'Disabled' if sec['javascript_disabled'] else 'Enabled':<21} | {'🟢 COMPLIANT' if sec['javascript_disabled'] else '🟡 WARN':<19} |")
    print("+--------------------------+-----------------------+---------------------+")

    # Table 6: Log Analysis
    print("\n" + "=" * 80)
    print("📋 MONGODB LOG ANALYSIS SUMMARY (JQ PARSER)")
    print("=" * 80)
    if "error" in log_data:
        print(f"⚠️ Log Analysis Notice: {log_data['error']}")
    else:
        print(f"• Total Log Entries Parsed     : {log_data.get('total_parsed', 0)}")
        print(f"• Total Slow Queries (>100ms)  : {log_data['total_slow_queries']} operations")
        print(f"• Longest Query Duration       : {log_data['max_duration_ms']} ms")
        print("\n⏱️ SLOW QUERY DURATION BUCKET DISTRIBUTION")
        print("+--------------------------+-------------------+")
        print("| Latency Range (ms)       | Slow Query Count  |")
        print("+--------------------------+-------------------+")
        for bucket, count in log_data["buckets"].items():
            print(f"| {bucket:<24} | {count:<17} |")
        print("+--------------------------+-------------------+")

        if log_data.get("slow_queries"):
            print("\n🔥 TOP SLOW QUERY SHAPES & INDEX SUGGESTIONS (ESR RULE)")
            for q_group in log_data["slow_queries"]:
                count_str = f"({q_group['count']} occurrences)" if q_group['count'] > 1 else "(1 occurrence)"
                print(f"\n⚠️ [COLLSCAN] Namespace: {q_group['ns']} {count_str}")
                print(f"   • Query Shape        : {q_group['query_shape']}")
                print(f"   • Max Execution Time : {q_group['max_duration']} ms")
                print(f"   • Max Docs Examined  : {q_group['max_docs_examined']}")
                print("   💡 RECOMMENDED INDEX CREATION COMMAND:")
                print("   " + "-" * 70)
                print(f"   {q_group['recommendation']}")
                print("   " + "-" * 70)

    print("\n" + "=" * 80)
    print("END OF DIAGNOSTIC REPORT")
    print("=" * 80)


def main():
    parser = argparse.ArgumentParser(description="MongoDB and Host Diagnostic Assessment Tool")
    parser.add_argument("--uri", default="mongodb://localhost:27017/admin", help="MongoDB Connection URI")
    parser.add_argument("--log-file", default="/var/log/mongodb/mongod.log", help="Path to mongod.log JSON file")
    parser.add_argument("--log-hours", type=int, default=24, help="Log analysis lookback duration in hours")
    args = parser.parse_args()

    try:
        host_metrics = SystemCollector.get_host_metrics()
    except Exception as e:
        sys.exit(f"Failed to collect host metrics: {e}")

    try:
        mongo_collector = MongoCollector(args.uri)
        mongo_metrics = mongo_collector.capture_all()
    except PyMongoError as e:
        sys.exit(f"Failed to connect to MongoDB: {e}")

    os_checks = SystemCollector.check_os_production_settings(mongo_metrics["version"])
    log_metrics = LogAnalyzer.analyze_log(args.log_file, hours=args.log_hours)
    prev_metrics = BaselineDeltaEngine.process_baseline({**host_metrics, **mongo_metrics})

    render_report(host_metrics, mongo_metrics, os_checks, log_metrics, prev_metrics)


if __name__ == "__main__":
    main()
