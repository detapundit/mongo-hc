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
