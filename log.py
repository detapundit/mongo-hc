import logging
from logging.handlers import RotatingFileHandler

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


