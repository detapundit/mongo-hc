import os
import psutil
import pandas as pd
from datetime import datetime, timezone
from pymongo import MongoClient
from pymongo.server_api import ServerApi
import json

# Rich Terminal UI Imports
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

console = Console()

HOST_METRICS_FILE = "metrics_history.csv"
MONGO_METRICS_FILE = "mongo_history.csv"


def clean_query_column(val):
    """Converts raw MongoDB command dicts into clean, brief string previews."""
    if pd.isna(val) or not val:
        return "N/A"
    if isinstance(val, dict):
        str_val = json.dumps(val)
    else:
        str_val = str(val)
    return str_val[:57] + "..." if len(str_val) > 60 else str_val


def display_rich_table(df, title, columns, header_styles=None):
    """Generic helper to render Pandas DataFrames as formatted Rich Tables."""
    table = Table(title=title, show_header=True, header_style="bold magenta", show_lines=True)

    for col in columns:
        style = header_styles.get(col, "cyan") if header_styles else "cyan"
        table.add_column(col, style=style)

    for _, row in df.iterrows():
        row_data = [str(row.get(col, "N/A")) for col in columns]
        table.add_row(*row_data)

    console.print(table)


def analyze_json_logs(log_file_path, hours_back=24, use_latest_log_time=False):
    """
    Parses and analyzes MongoDB JSON log files for performance metrics within a target timeframe.
    """
    log_data = []

    # 1. Native line-by-line parsing
    try:
        with open(log_file_path, "r") as f:
            for line in f:
                try:
                    log_data.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
    except FileNotFoundError:
        console.print(f"[bold red]❌ Log file not found at path: {log_file_path}[/bold red]")
        return

    if not log_data:
        console.print(Panel("[yellow]⚠️ Warning: No valid JSON log entries found to parse.[/yellow]", style="yellow"))
        return

    # 2. Flatten JSON tree
    df = pd.json_normalize(log_data, max_level=1)

    # 3. Datetime Parsing & Timeframe Filtering
    if 't.$date' in df.columns:
        df['log_dt'] = pd.to_datetime(df['t.$date'], errors='coerce', utc=True)

        reference_time = df['log_dt'].max() if use_latest_log_time and not df['log_dt'].isna().all() else pd.Timestamp.now(tz='UTC')
        cutoff_time = reference_time - pd.Timedelta(hours=hours_back)

        df = df[df['log_dt'] >= cutoff_time].copy()
    else:
        console.print("[yellow]⚠️ Warning: Could not locate timestamp field 't.$date' in log data.[/yellow]")

    if df.empty:
        console.print(Panel(f"[bold yellow]ℹ️ NO LOG ENTRIES FOUND WITHIN THE LAST {hours_back} HOURS[/bold yellow]", style="yellow"))
        return

    # 4. Dynamic Safe Mapping
    df['timestamp'] = df['log_dt'].dt.strftime('%Y-%m-%d %H:%M:%S') if 'log_dt' in df.columns else "N/A"
    df['component'] = df.get('c', 'UNKNOWN')
    df['duration_ms'] = pd.to_numeric(df.get('attr.durationMillis', 0)).fillna(0).astype(int)
    df['namespace'] = df.get('attr.ns', 'N/A')
    df['operation'] = df.get('attr.type', 'N/A')

    if 'attr.command' in df.columns:
        df['query'] = df['attr.command'].apply(clean_query_column)
    else:
        df['query'] = "N/A"

    console.print("\n")
    console.print(Panel(f"[bold white]📊 MONGO LOG ANALYSIS (TIMEFRAME: LAST {hours_back} HOURS)[/bold white]", style="bold blue", expand=False))

    # Analysis A: Slow Queries
    slow_queries = df[df['duration_ms'] >= 200]
    if not slow_queries.empty:
        display_rich_table(
            slow_queries,
            "🔥 [bold red]SLOW QUERIES OVER 200ms[/bold red]",
            ['timestamp', 'namespace', 'operation', 'duration_ms', 'query'],
            header_styles={'duration_ms': 'bold red', 'query': 'dim'}
        )
    else:
        console.print("[green]  ✓ No performance issues. Zero queries exceeded 200ms in this timeframe.[/green]\n")

    # Analysis B: Collection Scans
    if 'attr.planSummary' in df.columns:
        collscans = df[df['attr.planSummary'] == "COLLSCAN"]
        if not collscans.empty:
            display_rich_table(
                collscans,
                "⚠️ [bold yellow]UNINDEXED RAW COLLECTION SCANS (COLLSCAN)[/bold yellow]",
                ['timestamp', 'namespace', 'duration_ms', 'query'],
                header_styles={'duration_ms': 'yellow', 'query': 'dim'}
            )
        else:
            console.print("[green]  ✓ Excellent! Zero structural collection scans detected.[/green]\n")
    else:
        console.print("[dim]  ✓ Plan summaries not present in this log chunk.[/dim]\n")

    # Analysis C: Component Aggregation
    if 'component' in df.columns:
        counts = df['component'].value_counts().reset_index()
        counts.columns = ['Component Space', 'Log Count']
        display_rich_table(counts, "📊 [bold cyan]DISTRIBUTION BY MONGO COMPONENT[/bold cyan]", ['Component Space', 'Log Count'])


def capture_and_save_host_metrics():
    console.print("\n[bold cyan]Capturing system performance...[/bold cyan]")

    cpu_percent = psutil.cpu_percent(interval=1)
    cpu_stats = psutil.cpu_stats()
    load_1m, load_5m, load_15m = psutil.getloadavg()
    total_memory = psutil.virtual_memory().total / (1024 ** 3)
    used_memory = psutil.virtual_memory().percent
    free_memory = psutil.virtual_memory().free / (1024 ** 3)
    swap_mem = psutil.swap_memory().percent
    target_path = "C:\\" if os.name == 'nt' else "/"

    try:
        disk_info = psutil.disk_usage(target_path)
        disk_used_pct = disk_info.percent
        disk_free_gb = disk_info.free / (1024 ** 3)
    except Exception:
        disk_used_pct, disk_free_gb = 0.0, 0.0

    try:
        io_counters = psutil.disk_io_counters()
        read_mb = io_counters.read_bytes / (1024 ** 2)
        write_mb = io_counters.write_bytes / (1024 ** 2)
    except Exception:
        read_mb, write_mb = 0.0, 0.0

    current_run = {
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "cpu_percent": cpu_percent,
        "cpu_count": psutil.cpu_count(logical=True),
        #"ctx_switches": cpu_stats.ctx_switches,
        #"interrupts": cpu_stats.interrupts,
        "load_1m": load_1m,
        "load_5m": load_5m,
        "load_15m": load_15m,
        "total_memory(GB)": total_memory,
        "used_memory(%)": used_memory,
        "free_memory(GB)": free_memory,
        "swap_memory_used(%)": swap_mem,
        "disk_used_percent": disk_used_pct,
        "disk_free_gb": disk_free_gb,
        "disk_total_read_mb": read_mb,
        "disk_total_write_mb": write_mb
    }

    df = pd.DataFrame([current_run])
    file_exists = os.path.isfile(HOST_METRICS_FILE)
    df.to_csv(HOST_METRICS_FILE, mode='a', index=False, header=not file_exists)

    console.print(f"[green]✓ Metrics archived down to {HOST_METRICS_FILE}[/green]")
    return current_run


def capture_and_save_mongo_metrics():
    console.print("\n[bold cyan]Capturing Mongo performance...[/bold cyan]")
    uri = "mongodb://localhost:27017/"
    EXCLUDED_DATABASES = {"admin", "local", "config"}

    try:
        client = MongoClient(uri, server_api=ServerApi('1'), serverSelectionTimeoutMS=5000)
        admin_db = client.admin

        server_status = admin_db.command("serverStatus")
        hello_status = admin_db.command("hello")

        process_type = server_status.get('process', '')
        is_mongos = (process_type == 'mongos')
        is_replset = 'setName' in server_status or 'setName' in hello_status or 'repl' in server_status

        is_sharded = False
        try:
            list_shards = admin_db.command("listShards")
            if list_shards.get("ok") == 1:
                is_sharded = True
        except Exception:
            is_sharded = False

        if is_mongos or (is_sharded and not is_replset):
            node_type = "mongos"
        elif is_replset:
            node_type = "replica_set"
        else:
            node_type = "standalone"

        repl_lag_sec = 0.0
        repl_members_count = 0
        oplog_used_mb = 0.0
        oplog_max_mb = 0.0
        oplog_window_hours = 0.0

        if is_replset and not is_mongos:
            try:
                repl_status = admin_db.command("replSetGetStatus")
                members = repl_status.get("members", [])
                repl_members_count = len(members)

                primary_optime = None
                my_optime = None

                for member in members:
                    if member.get("stateStr") == "PRIMARY":
                        primary_optime = member.get("optimeDate")
                    if member.get("self"):
                        my_optime = member.get("optimeDate")

                if primary_optime and my_optime:
                    repl_lag_sec = max(0.0, (primary_optime - my_optime).total_seconds())
            except Exception as repl_err:
                console.print(f"[yellow]⚠️ Could not fetch replSetGetStatus: {repl_err}[/yellow]")

            try:
                local_db = client.local
                oplog_stats = local_db.command("collStats", "oplog.rs")
                oplog_used_mb = round(oplog_stats.get('size', 0) / (1024 ** 2), 2)
                oplog_max_mb = round(oplog_stats.get('maxSize', 0) / (1024 ** 2), 2)

                first_doc = local_db["oplog.rs"].find_one(sort=[('$natural', 1)])
                last_doc = local_db["oplog.rs"].find_one(sort=[('$natural', -1)])

                if first_doc and last_doc:
                    t_first = first_doc.get("ts").time if first_doc.get("ts") else 0
                    t_last = last_doc.get("ts").time if last_doc.get("ts") else 0
                    if t_last >= t_first:
                        oplog_window_hours = round((t_last - t_first) / 3600.0, 2)
            except Exception as oplog_err:
                console.print(f"[yellow]⚠️ Could not fetch Oplog stats: {oplog_err}[/yellow]")

        shards_count = 0
        mongos_count = 0
        total_chunks = 0
        balancer_active = False

        if is_sharded or is_mongos:
            try:
                shards_info = admin_db.command("listShards")
                shards_count = len(shards_info.get("shards", []))
            except Exception:
                shards_count = 0

            try:
                config_db = client.config
                mongos_count = config_db["mongos"].count_documents({})
                total_chunks = config_db["chunks"].count_documents({})
            except Exception:
                pass

            try:
                balancer_status = admin_db.command("balancerStatus")
                balancer_active = balancer_status.get("mode") != "off" and balancer_status.get("inBalancerRound", False)
            except Exception:
                balancer_active = False

        all_dbs = client.list_database_names()
        target_dbs = [db_name for db_name in all_dbs if db_name not in EXCLUDED_DATABASES]

        total_data_size_bytes = 0
        total_storage_size_bytes = 0
        total_collections_count = 0

        for db_name in target_dbs:
            try:
                db_stats = client[db_name].command("dbStats")
                total_data_size_bytes += db_stats.get('dataSize', 0)
                total_storage_size_bytes += db_stats.get('storageSize', 0)
                total_collections_count += db_stats.get('collections', 0)
            except Exception as db_err:
                console.print(f"[yellow]⚠️ Warning: Could not read stats for database '{db_name}': {db_err}[/yellow]")

        connections = server_status.get('connections', {})
        opcounters = server_status.get('opcounters', {})
        global_lock = server_status.get('globalLock', {}).get('currentQueue', {})
        wt_tx = server_status.get('wiredTiger', {}).get('concurrentTransactions', {})
        wt_cache = server_status.get('wiredTiger', {}).get('cache', {})
        query_exec = server_status.get('metrics', {}).get('queryExecutor', {})
        ops_metrics = server_status.get('metrics', {}).get('operation', {})

        current_run = {
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "node_type": node_type,
            "is_sharded": is_sharded,
            "conn_current": connections.get('current', 0),
            "conn_available": connections.get('available', 0),
            "uptime_days": round(server_status.get('uptime', 0) / 86400, 2),
            "repl_lag_sec": repl_lag_sec,
            "repl_members_count": repl_members_count,
            "oplog_used_mb": oplog_used_mb,
            "oplog_max_mb": oplog_max_mb,
            "oplog_window_hours": oplog_window_hours,
            "shards_count": shards_count,
            "mongos_count": mongos_count,
            "total_chunks": total_chunks,
            "balancer_active": balancer_active,
            "op_inserts": opcounters.get('insert', 0),
            "op_queries": opcounters.get('query', 0),
            "op_updates": opcounters.get('update', 0),
            "op_deletes": opcounters.get('delete', 0),
            "lock_queue_total": global_lock.get('total', 0),
            "lock_queue_readers": global_lock.get('readers', 0),
            "lock_queue_writers": global_lock.get('writers', 0),
            "wt_tickets_read_out": wt_tx.get('read', {}).get('out', 0),
            "wt_tickets_read_avail": wt_tx.get('read', {}).get('available', 0),
            "wt_tickets_write_out": wt_tx.get('write', {}).get('out', 0),
            "wt_tickets_write_avail": wt_tx.get('write', {}).get('available', 0),
            "wt_cache_used_mb": round(wt_cache.get('bytes currently in the cache', 0) / (1024 ** 2), 2),
            "wt_cache_max_mb": round(wt_cache.get('maximum bytes configured', 0) / (1024 ** 2), 2),
            "wt_cache_dirty_mb": round(wt_cache.get('tracked dirty bytes in the cache', 0) / (1024 ** 2), 2),
            "wt_pages_evicted": wt_cache.get('pages evicted by workers', 0),
            "page_faults": server_status.get('extra_info', {}).get('page_faults', 0),
            "query_scanned_objects": query_exec.get('scannedObjects', 0),
            "query_scanned_keys": query_exec.get('scanned', 0),
            "slow_ops_accumulated": ops_metrics.get('slowOp', 0),
            "db_data_size_mb": round(total_data_size_bytes / (1024 ** 2), 2),
            "db_storage_size_mb": round(total_storage_size_bytes / (1024 ** 2), 2),
            "db_collections": total_collections_count
        }

        df = pd.DataFrame([current_run])
        file_exists = os.path.isfile(MONGO_METRICS_FILE)
        df.to_csv(MONGO_METRICS_FILE, mode='a', index=False, header=not file_exists)

        console.print(f"[green]✓ Mongo metrics archived down to {MONGO_METRICS_FILE}[/green]")
        return current_run

    except Exception as e:
        console.print(f"[bold red]❌ Failed to capture Mongo metrics: {e}[/bold red]")
        return None


def render_comparison_table(df, title_text):
    """Generates styled Rich tables with color-coded numeric differences."""
    previous_run = df.iloc[-2]
    current_run = df.iloc[-1]

    table = Table(
        title=f"[bold green]{title_text}[/bold green]\n[dim]Previous Run: {previous_run['timestamp']}  |  Current Run: {current_run['timestamp']}[/dim]",
        show_header=True,
        header_style="bold magenta",
        show_lines=True
    )

    table.add_column("Metric", style="bold white")
    table.add_column("Previous Run", justify="right", style="cyan")
    table.add_column("Current Run", justify="right", style="cyan")
    table.add_column("Difference", justify="right")

    for metric in df.columns:
        if metric == 'timestamp':
            continue

        prev_val = previous_run[metric]
        curr_val = current_run[metric]

        try:
            prev_num = float(prev_val)
            curr_num = float(curr_val)
            delta = curr_num - prev_num
            diff_str = f"{delta:+.2f}"

            # Highlighting logic based on metrics
            if delta > 0:
                if any(k in metric for k in ['used', 'faults', 'queue', 'slow', 'lag', 'scanned']):
                    diff_formatted = f"[bold red]{diff_str}[/bold red]"
                else:
                    diff_formatted = f"[yellow]{diff_str}[/yellow]"
            elif delta < 0:
                diff_formatted = f"[bold green]{diff_str}[/bold green]"
            else:
                diff_formatted = f"[dim]{diff_str}[/dim]"

            table.add_row(metric, f"{prev_num:.2f}", f"{curr_num:.2f}", diff_formatted)
        except (ValueError, TypeError):
            table.add_row(metric, str(prev_val), str(curr_val), "[dim]N/A (Categorical)[/dim]")

    console.print(table)


def generate_comparison_report():
    if not os.path.isfile(HOST_METRICS_FILE):
        console.print("[yellow]No historical host metrics found to compare.[/yellow]")
        return

    df = pd.read_csv(HOST_METRICS_FILE)
    if len(df) < 2:
        console.print("[yellow]Need at least two recorded runs to calculate performance deltas.[/yellow]")
        return

    render_comparison_table(df, "=== SYSTEM HOST COMPARISON REPORT ===")


def generate_mongo_comparison_report():
    if not os.path.isfile(MONGO_METRICS_FILE):
        console.print("[yellow]No historical Mongo metrics found to compare.[/yellow]")
        return

    df = pd.read_csv(MONGO_METRICS_FILE)
    if len(df) < 2:
        console.print("[yellow]Need at least two recorded runs to calculate Mongo performance deltas.[/yellow]")
        return

    render_comparison_table(df, "=== MONGO DATABASE COMPARISON REPORT ===")


if __name__ == "__main__":
    capture_and_save_host_metrics()
    generate_comparison_report()
    capture_and_save_mongo_metrics()
    generate_mongo_comparison_report()

    my_log_path = "/var/log/mongodb/mongod.log"
    analyze_json_logs(my_log_path)
