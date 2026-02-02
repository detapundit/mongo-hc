def extract_slow_queries(host_payload: dict) -> list:
    """
    Normalize slow queries from different agent payload formats
    """
    # Case 1: direct
    if isinstance(host_payload.get("slow_queries"), list):
        return host_payload["slow_queries"]

    # Case 2: under logs
    logs = host_payload.get("logs", {})
    if isinstance(logs.get("slow_queries"), list):
        return logs["slow_queries"]

    # Case 3: under mongo_logs
    mongo_logs = host_payload.get("mongo_logs", {})
    if isinstance(mongo_logs.get("slow_queries"), list):
        return mongo_logs["slow_queries"]

    return []


from collections import defaultdict

def summarize_slow_queries(hosts: dict) -> list:
    agg = defaultdict(list)

    for h in hosts.values():
        slow_queries = extract_slow_queries(h)

        for q in slow_queries:
            ns = q.get("ns") or q.get("namespace")
            dur = q.get("duration_ms") or q.get("durationMillis")

            if not ns or not dur:
                continue

            agg[ns].append(dur)

    return [
        {
            "ns": ns,
            "count": len(v),
            "avg_ms": round(sum(v) / len(v), 2),
            "max_ms": max(v)
        }
        for ns, v in agg.items()
    ]
