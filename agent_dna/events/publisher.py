import json

from .config import (
    KAFKA_ENABLED,
    KAFKA_BOOTSTRAP,
    REDIS_ENABLED,
    REDIS_URL,
)

try:
    from kafka import KafkaProducer
except Exception:
    KafkaProducer = None

try:
    import redis
except Exception:
    redis = None


class EventPublisher:

    def __init__(self):

        self.kafka = None
        self.redis = None

        if KAFKA_ENABLED and KafkaProducer:

            self.kafka = KafkaProducer(
                bootstrap_servers=KAFKA_BOOTSTRAP,
                value_serializer=lambda v: json.dumps(v).encode("utf-8"),
            )

        if REDIS_ENABLED and redis:

            self.redis = redis.from_url(REDIS_URL)

    def publish(
        self,
        topic,
        event,
    ):

        if self.kafka:

            self.kafka.send(topic, event)

        if self.redis:

            self.redis.publish(topic, json.dumps(event))

    def flush(self):

        if self.kafka:

            self.kafka.flush()
