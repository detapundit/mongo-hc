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
