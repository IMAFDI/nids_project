"""
NIDS — Async Packet Processing Pipeline
=======================================
Asynchronous producer/consumer architecture for high-throughput packet processing.

Producer : packet capture → asyncio.Queue
Consumer : signature engine + ML engine (concurrent workers)
"""

from __future__ import annotations

import asyncio
import logging
import time
import threading
from dataclasses import dataclass, field
from typing import Callable, Any
from collections import defaultdict
from datetime import datetime, timezone

logger = logging.getLogger("NIDS.AsyncPipeline")


# ---------------------------------------------------------------------------
# Packet wrapper
# ---------------------------------------------------------------------------

@dataclass
class Packet:
    """Wrapper for a captured packet with metadata."""
    scapy_packet: Any
    captured_at: float = field(default_factory=time.time)
    interface: str = ""


# ---------------------------------------------------------------------------
# Pipeline metrics
# ---------------------------------------------------------------------------

@dataclass
class PipelineMetrics:
    """Thread-safe metrics for the pipeline."""
    packets_received: int = 0
    packets_processed: int = 0
    packets_dropped: int = 0
    queue_depth: int = 0
    avg_processing_time_ms: float = 0.0
    _lock: threading.Lock = field(default_factory=threading.Lock)
    _processing_times: list = field(default_factory=list)

    def record_received(self, n: int = 1) -> None:
        with self._lock:
            self.packets_received += n

    def record_processed(self, n: int = 1, processing_time_ms: float = 0.0) -> None:
        with self._lock:
            self.packets_processed += n
            if processing_time_ms > 0:
                self._processing_times.append(processing_time_ms)
                if len(self._processing_times) > 1000:
                    self._processing_times = self._processing_times[-1000:]
                self.avg_processing_time_ms = sum(self._processing_times) / len(self._processing_times)

    def record_dropped(self, n: int = 1) -> None:
        with self._lock:
            self.packets_dropped += n

    def update_queue_depth(self, depth: int) -> None:
        with self._lock:
            self.queue_depth = depth

    def to_dict(self) -> dict:
        with self._lock:
            return {
                "packets_received": self.packets_received,
                "packets_processed": self.packets_processed,
                "packets_dropped": self.packets_dropped,
                "queue_depth": self.queue_depth,
                "avg_processing_time_ms": round(self.avg_processing_time_ms, 3),
            }


# ---------------------------------------------------------------------------
# Detection pipeline
# ---------------------------------------------------------------------------

class DetectionPipeline:
    """
    Async pipeline that coordinates packet capture, signature detection,
    and ML anomaly detection as concurrent workers.
    """

    def __init__(
        self,
        max_queue_depth: int = 10000,
        num_workers: int = 4,
        signature_detector=None,
        ml_model=None,
        on_event: Callable[[dict], None] | None = None,
    ):
        self.max_queue_depth = max_queue_depth
        self.num_workers = num_workers
        self.signature_detector = signature_detector
        self.ml_model = ml_model
        self.on_event = on_event  # callback for each detection event

        self._queue: asyncio.Queue[Packet] = asyncio.Queue(maxsize=max_queue_depth)
        self._metrics = PipelineMetrics()
        self._running = False
        self._workers: list[asyncio.Task] = []
        self._producer_task: asyncio.Task | None = None
        self._rate_limit: dict[str, list[float]] = defaultdict(list)
        self._rate_lock = threading.Lock()

        # Whitelist for trusted IPs
        self._whitelist: set[str] = set()
        self._whitelist_loaded = False

    # ------------------------------------------------------------------ #
    # Whitelist
    # ------------------------------------------------------------------ #

    def set_whitelist(self, ips: set[str]) -> None:
        self._whitelist = ips
        self._whitelist_loaded = True

    def is_whitelisted(self, ip: str) -> bool:
        return ip in self._whitelist

    # ------------------------------------------------------------------ #
    # Rate limiting per IP
    # ------------------------------------------------------------------ #

    def _check_rate_limit(self, ip: str, limit: int, window: float) -> bool:
        """Return True if IP is within rate limit, False if exceeded."""
        now = time.time()
        with self._rate_lock:
            self._rate_limit[ip] = [t for t in self._rate_limit[ip] if now - t < window]
            if len(self._rate_limit[ip]) >= limit:
                return False
            self._rate_limit[ip].append(now)
            return True

    # ------------------------------------------------------------------ #
    # Producer (packet capture)
    # ------------------------------------------------------------------ #

    async def start_producer(self, capture_fn: Callable) -> None:
        """
        Start the producer loop. `capture_fn` should be an async or sync callable
        that yields scapy packets.
        """
        self._running = True
        logger.info("Packet producer started.")

        while self._running:
            try:
                # Capture a batch of packets
                if asyncio.iscoroutinefunction(capture_fn):
                    packets = await capture_fn()
                else:
                    packets = capture_fn()

                for pkt in packets:
                    if not self._running:
                        break
                    try:
                        self._queue.put_nowait(Packet(scapy_packet=pkt))
                        self._metrics.record_received()
                    except asyncio.QueueFull:
                        self._metrics.record_dropped()
                        logger.warning(f"Queue full — packet dropped (depth={self._queue.qsize()})")

                self._metrics.update_queue_depth(self._queue.qsize())

            except Exception as e:
                logger.error(f"Producer error: {e}")

            await asyncio.sleep(0.01)  # Brief yield

        logger.info("Packet producer stopped.")

    def enqueue_packet(self, pkt: Any) -> bool:
        """
        Enqueue a single packet from a synchronous callback.
        Returns True if enqueued, False if dropped.
        """
        try:
            self._queue.put_nowait(Packet(scapy_packet=pkt))
            self._metrics.record_received()
            self._metrics.update_queue_depth(self._queue.qsize())
            return True
        except asyncio.QueueFull:
            self._metrics.record_dropped()
            return False

    # ------------------------------------------------------------------ #
    # Consumer (worker coroutines)
    # ------------------------------------------------------------------ #

    async def _worker(self, worker_id: int) -> None:
        """Individual worker coroutine that processes packets from the queue."""
        logger.info(f"Worker {worker_id} started.")
        from config.signature_detection import SignatureDetector
        from config.anomaly_detection import perform_anomaly_detection

        while self._running:
            try:
                # Wait for a packet with timeout so we can check _running
                try:
                    packet = await asyncio.wait_for(
                        self._queue.get(),
                        timeout=1.0
                    )
                except asyncio.TimeoutError:
                    continue

                start_time = time.time()

                try:
                    # Run signature detection
                    if self.signature_detector:
                        matches = self.signature_detector.evaluate(packet.scapy_packet)
                        for match in matches:
                            if self.is_whitelisted(match.get("src_ip", "")):
                                continue
                            self._handle_signature_match(match)

                    # Run ML anomaly detection
                    if self.ml_model:
                        anomalies = perform_anomaly_detection(
                            [packet.scapy_packet],
                            self.ml_model
                        )
                        for anomaly in anomalies:
                            if self.is_whitelisted(anomaly.get("src_ip", "")):
                                continue
                            self._handle_anomaly(anomaly)

                except Exception as e:
                    logger.debug(f"Packet processing error: {e}")

                processing_time_ms = (time.time() - start_time) * 1000
                self._metrics.record_processed(processing_time_ms=processing_time_ms)
                self._metrics.update_queue_depth(self._queue.qsize())

            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Worker {worker_id} error: {e}")

        logger.info(f"Worker {worker_id} stopped.")

    # ------------------------------------------------------------------ #
    # Event handlers
    # ------------------------------------------------------------------ #

    def _handle_signature_match(self, match: dict) -> None:
        from config.logging_alerting import log_intrusion, alert_intrusion, SEVERITY_LOW, SEVERITY_MEDIUM, SEVERITY_HIGH, SEVERITY_CRITICAL
        from config.notifications import send_notification

        ratio = match.get("count", 1) / max(match.get("threshold", 1), 1)
        if ratio >= 5:
            severity = SEVERITY_CRITICAL
        elif ratio >= 2:
            severity = SEVERITY_HIGH
        elif ratio >= 1:
            severity = SEVERITY_MEDIUM
        else:
            severity = SEVERITY_LOW

        msg = (f"Signature alert — {match.get('description', '')} | "
               f"src={match['src_ip']} dst={match.get('dst_ip', '')} "
               f"count={match.get('count')}/{match.get('threshold')}")

        log_intrusion(msg, severity=severity)
        alert_intrusion(msg, severity=severity)

        details = {
            "src_ip": match["src_ip"],
            "dst_ip": match.get("dst_ip"),
            "protocol": match.get("protocol"),
            "description": match.get("description"),
            "rule_id": match.get("rule_id"),
            "count": match.get("count"),
            "threshold": match.get("threshold"),
            "event_type": "signature",
            "severity": severity,
        }

        # Persist event
        from config.database_v2 import log_intrusion_event
        event_id = log_intrusion_event("signature", severity, msg, details=details)

        # Notifications
        send_notification(severity, msg, {**details, "event_id": event_id})

        # Dashboard push
        if self.on_event:
            self.on_event({**details, "event_id": event_id, "raw_message": msg})

    def _handle_anomaly(self, anomaly: dict) -> None:
        from config.logging_alerting import log_intrusion, alert_intrusion, SEVERITY_HIGH
        from config.notifications import send_notification

        severity = SEVERITY_HIGH
        msg = (f"Anomaly detected | src={anomaly['src_ip']} "
               f"dst={anomaly.get('dst_ip', '')} "
               f"proto={anomaly.get('protocol')} len={anomaly.get('packet_length')}")

        log_intrusion(msg, severity=severity)
        alert_intrusion(msg, severity=severity)

        details = {
            "src_ip": anomaly["src_ip"],
            "dst_ip": anomaly.get("dst_ip"),
            "protocol": str(anomaly.get("protocol")),
            "packet_length": anomaly.get("packet_length"),
            "tcp_flags": anomaly.get("tcp_flags"),
            "ttl": anomaly.get("ttl"),
            "description": msg,
            "event_type": "anomaly",
            "severity": severity,
        }

        from config.database_v2 import log_intrusion_event
        event_id = log_intrusion_event("anomaly", severity, msg, details=details)

        if self.on_event:
            self.on_event({**details, "event_id": event_id, "raw_message": msg})

    # ------------------------------------------------------------------ #
    # Lifecycle
    # ------------------------------------------------------------------ #

    async def start(self) -> None:
        """Start all workers."""
        if self._running:
            return
        self._running = True
        self._workers = [
            asyncio.create_task(self._worker(i))
            for i in range(self.num_workers)
        ]
        logger.info(f"Pipeline started with {self.num_workers} workers.")

    async def stop(self) -> None:
        """Gracefully stop all workers."""
        self._running = False
        logger.info("Pipeline stopping...")

        # Cancel all workers
        for w in self._workers:
            w.cancel()
        await asyncio.gather(*self._workers, return_exceptions=True)
        self._workers.clear()

        # Drain queue
        drained = 0
        while not self._queue.empty():
            try:
                self._queue.get_nowait()
                drained += 1
            except asyncio.QueueEmpty:
                break
        logger.info(f"Pipeline stopped. Drained {drained} packets from queue.")

    def get_metrics(self) -> dict:
        """Return current pipeline metrics."""
        return self._metrics.to_dict()

    @property
    def is_running(self) -> bool:
        return self._running
