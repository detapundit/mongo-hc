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
