"""
NIDS — Message broker integration
=================================
Optional RabbitMQ event bus for decoupling detection from event processing.
"""

from __future__ import annotations

import json
import logging
import threading
from typing import Callable, Any

import pika

logger = logging.getLogger("NIDS.Broker")


class RabbitMQBroker:
    """Simple RabbitMQ publisher/consumer wrapper."""

    def __init__(
        self,
        url: str,
        exchange: str,
        queue: str,
        routing_key: str,
        prefetch_count: int = 100,
    ):
        self.url = url
        self.exchange = exchange
        self.queue = queue
        self.routing_key = routing_key
        self.prefetch_count = prefetch_count
        self._publish_connection: pika.BlockingConnection | None = None
        self._publish_channel = None
        self._consumer_connection: pika.BlockingConnection | None = None
        self._consumer_channel = None
        self._consumer_thread: threading.Thread | None = None
        self._consumer_running = False
        self._publish_lock = threading.Lock()

    def _connect_publisher(self) -> None:
        if self._publish_connection and self._publish_connection.is_open:
            return
        params = pika.URLParameters(self.url)
        self._publish_connection = pika.BlockingConnection(params)
        self._publish_channel = self._publish_connection.channel()
        self._publish_channel.exchange_declare(exchange=self.exchange, exchange_type="topic", durable=True)
        self._publish_channel.queue_declare(queue=self.queue, durable=True)
        self._publish_channel.queue_bind(queue=self.queue, exchange=self.exchange, routing_key=self.routing_key)
        logger.info("RabbitMQ publisher connected (%s)", self.url)

    def _connect_consumer(self) -> None:
        if self._consumer_connection and self._consumer_connection.is_open:
            return
        params = pika.URLParameters(self.url)
        self._consumer_connection = pika.BlockingConnection(params)
        self._consumer_channel = self._consumer_connection.channel()
        self._consumer_channel.exchange_declare(exchange=self.exchange, exchange_type="topic", durable=True)
        self._consumer_channel.queue_declare(queue=self.queue, durable=True)
        self._consumer_channel.queue_bind(queue=self.queue, exchange=self.exchange, routing_key=self.routing_key)
        self._consumer_channel.basic_qos(prefetch_count=self.prefetch_count)
        logger.info("RabbitMQ connected (%s)", self.url)

    def close(self) -> None:
        if self._publish_connection and self._publish_connection.is_open:
            self._publish_connection.close()
        self._publish_channel = None
        self._publish_connection = None

        if self._consumer_channel and getattr(self._consumer_channel, "is_open", False):
            try:
                self._consumer_channel.stop_consuming()
            except Exception:
                pass
        if self._consumer_connection and self._consumer_connection.is_open:
            self._consumer_connection.close()
        self._consumer_channel = None
        self._consumer_connection = None

    def publish(self, event: dict[str, Any]) -> None:
        with self._publish_lock:
            if not self._publish_channel or not getattr(self._publish_channel, "is_open", False):
                self._connect_publisher()
            body = json.dumps(event).encode("utf-8")
            self._publish_channel.basic_publish(
                exchange=self.exchange,
                routing_key=self.routing_key,
                body=body,
                properties=pika.BasicProperties(delivery_mode=2, content_type="application/json"),
            )

    def start_consumer(self, on_message: Callable[[dict[str, Any]], None]) -> None:
        if self._consumer_thread and self._consumer_thread.is_alive():
            return

        self._consumer_running = True

        def _run() -> None:
            while self._consumer_running:
                try:
                    self._connect_consumer()

                    def _callback(ch, method, properties, body):
                        try:
                            payload = json.loads(body.decode("utf-8"))
                            on_message(payload)
                            ch.basic_ack(delivery_tag=method.delivery_tag)
                        except Exception as exc:
                            logger.error("Broker consumer message error: %s", exc)
                            ch.basic_nack(delivery_tag=method.delivery_tag, requeue=False)

                    self._consumer_channel.basic_consume(queue=self.queue, on_message_callback=_callback, auto_ack=False)
                    self._consumer_channel.start_consuming()
                except Exception as exc:
                    logger.error("Broker consumer loop error: %s", exc)
                finally:
                    if self._consumer_connection and self._consumer_connection.is_open:
                        self._consumer_connection.close()
                    self._consumer_channel = None
                    self._consumer_connection = None

        self._consumer_thread = threading.Thread(target=_run, name="nids-rabbitmq-consumer", daemon=True)
        self._consumer_thread.start()

    def stop_consumer(self) -> None:
        self._consumer_running = False
        self.close()
