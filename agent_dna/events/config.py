import os

KAFKA_ENABLED = os.getenv("PV_KAFKA_ENABLED", "false").lower() == "true"
KAFKA_BOOTSTRAP = os.getenv("PV_KAFKA_BOOTSTRAP", "localhost:9092")

REDIS_ENABLED = os.getenv("PV_REDIS_ENABLED", "false").lower() == "true"
REDIS_URL = os.getenv("PV_REDIS_URL", "redis://localhost:6379/0")
