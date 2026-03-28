"""
NIDS — Real-time Detection Engine
=================================
Background service that continuously processes network traffic,
runs signature matching and ML anomaly detection, and logs events.
"""

from __future__ import annotations

import asyncio
import logging
import random
import time
import hashlib
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable
from collections import deque

logger = logging.getLogger("NIDS.DetectionEngine")


@dataclass
class PacketData:
    """Represents a network packet for analysis."""
    timestamp: datetime
    src_ip: str
    dst_ip: str
    protocol: str
    src_port: int
    dst_port: int
    packet_length: int
    tcp_flags: int = 0
    ttl: int = 64
    payload: bytes = b""
    country_code: str | None = None
    
    def to_dict(self) -> dict[str, Any]:
        return {
            "timestamp": self.timestamp.isoformat(),
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "protocol": self.protocol,
            "src_port": self.src_port,
            "dst_port": self.dst_port,
            "packet_length": self.packet_length,
            "tcp_flags": self.tcp_flags,
            "ttl": self.ttl,
            "country_code": self.country_code,
        }


@dataclass
class DetectionResult:
    """Result from detection engine analysis."""
    detected: bool
    event_type: str  # 'signature' | 'anomaly'
    severity: str    # LOW | MEDIUM | HIGH | CRITICAL
    rule_id: int | None
    rule_name: str | None
    description: str
    ml_score: float | None = None
    threat_intel_score: int | None = None
    country_code: str | None = None


@dataclass
class EngineMetrics:
    """Real-time engine metrics."""
    packets_received: int = 0
    packets_processed: int = 0
    packets_dropped: int = 0
    events_detected: int = 0
    queue_depth: int = 0
    avg_processing_time_ms: float = 0.0
    packets_per_second: float = 0.0
    events_per_minute: float = 0.0
    start_time: float = field(default_factory=time.time)
    
    # Rolling windows for rate calculation
    _packet_times: deque = field(default_factory=lambda: deque(maxlen=1000))
    _event_times: deque = field(default_factory=lambda: deque(maxlen=1000))
    _processing_times: deque = field(default_factory=lambda: deque(maxlen=100))
    
    def record_packet(self):
        self.packets_received += 1
        self._packet_times.append(time.time())
        self._update_rates()
    
    def record_processed(self, processing_time_ms: float):
        self.packets_processed += 1
        self._processing_times.append(processing_time_ms)
        if self._processing_times:
            self.avg_processing_time_ms = sum(self._processing_times) / len(self._processing_times)
    
    def record_event(self):
        self.events_detected += 1
        self._event_times.append(time.time())
        self._update_rates()
    
    def record_dropped(self):
        self.packets_dropped += 1
    
    def _update_rates(self):
        now = time.time()
        # Packets per second (last 10 seconds)
        recent_packets = [t for t in self._packet_times if now - t < 10]
        self.packets_per_second = len(recent_packets) / 10.0 if recent_packets else 0.0
        
        # Events per minute (last 60 seconds)
        recent_events = [t for t in self._event_times if now - t < 60]
        self.events_per_minute = len(recent_events)
    
    def to_dict(self) -> dict[str, Any]:
        return {
            "packets_received": self.packets_received,
            "packets_processed": self.packets_processed,
            "packets_dropped": self.packets_dropped,
            "events_detected": self.events_detected,
            "queue_depth": self.queue_depth,
            "avg_processing_time_ms": round(self.avg_processing_time_ms, 2),
            "packets_per_second": round(self.packets_per_second, 2),
            "events_per_minute": self.events_per_minute,
            "uptime_seconds": round(time.time() - self.start_time, 2),
        }


class DetectionEngine:
    """
    Real-time network intrusion detection engine.
    
    Processes packets from a queue, runs signature matching and ML detection,
    and emits events via callbacks.
    """
    
    def __init__(
        self,
        max_queue_size: int = 10000,
        worker_count: int = 4,
    ):
        self.packet_queue: asyncio.Queue[PacketData] = asyncio.Queue(maxsize=max_queue_size)
        self.max_queue_size = max_queue_size
        self.worker_count = worker_count
        self.metrics = EngineMetrics()
        self.running = False
        self._workers: list[asyncio.Task] = []
        self._rules: list[dict] = []
        self._event_callbacks: list[Callable] = []
        self._metrics_callbacks: list[Callable] = []
        
        # Rate limiting tracking per IP
        self._ip_packet_counts: dict[str, deque] = {}
        self._event_publisher: Callable[[dict[str, Any]], None] | None = None
        self._suppression_cache: dict[tuple[int, str], float] = {}
        
    def add_event_callback(self, callback: Callable):
        """Register callback for when events are detected."""
        self._event_callbacks.append(callback)

    def remove_event_callback(self, callback: Callable):
        """Remove a previously registered event callback."""
        self._event_callbacks = [cb for cb in self._event_callbacks if cb is not callback]
    
    def add_metrics_callback(self, callback: Callable):
        """Register callback for metrics updates."""
        self._metrics_callbacks.append(callback)

    def set_event_publisher(self, publisher: Callable[[dict[str, Any]], None] | None):
        """Optional async bus publisher (e.g., RabbitMQ)."""
        self._event_publisher = publisher
    
    def load_rules(self, rules: list[dict]):
        """Load detection rules."""
        self._rules = [
            r for r in rules
            if r.get("enabled", True) and r.get("lifecycle_state", "production") == "production"
        ]
        logger.info(f"Loaded {len(self._rules)} active detection rules")
    
    async def submit_packet(self, packet: PacketData) -> bool:
        """Submit a packet for analysis. Returns False if queue is full."""
        self.metrics.record_packet()
        self.metrics.queue_depth = self.packet_queue.qsize()
        
        try:
            self.packet_queue.put_nowait(packet)
            return True
        except asyncio.QueueFull:
            self.metrics.record_dropped()
            return False
    
    async def start(self):
        """Start the detection engine workers."""
        if self.running:
            return
        
        self.running = True
        logger.info(f"Starting detection engine with {self.worker_count} workers")
        
        for i in range(self.worker_count):
            task = asyncio.create_task(self._worker(i))
            self._workers.append(task)
        
        # Start metrics broadcaster
        asyncio.create_task(self._broadcast_metrics())
    
    async def stop(self):
        """Stop the detection engine."""
        self.running = False
        for task in self._workers:
            task.cancel()
        self._workers.clear()
        logger.info("Detection engine stopped")
    
    async def _worker(self, worker_id: int):
        """Worker coroutine that processes packets from the queue."""
        logger.info(f"Detection worker {worker_id} started")
        
        while self.running:
            try:
                packet = await asyncio.wait_for(
                    self.packet_queue.get(),
                    timeout=1.0
                )
                
                start_time = time.time()
                
                # Run detection
                result = await self._analyze_packet(packet)
                
                processing_time = (time.time() - start_time) * 1000
                self.metrics.record_processed(processing_time)
                self.metrics.queue_depth = self.packet_queue.qsize()
                
                # If threat detected, emit event
                if result and result.detected:
                    self.metrics.record_event()
                    await self._emit_event(packet, result)
                
            except asyncio.TimeoutError:
                continue
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Worker {worker_id} error: {e}")
    
    async def _analyze_packet(self, packet: PacketData) -> DetectionResult | None:
        """Analyze a packet against all detection methods."""
        
        # 1. Signature-based detection
        for rule in self._rules:
            result = self._check_signature_rule(packet, rule)
            if result and result.detected:
                return result
        
        # 2. Rate limit detection
        rate_result = self._check_rate_limit(packet)
        if rate_result and rate_result.detected:
            return rate_result
        
        # 3. ML anomaly detection (simplified)
        ml_result = self._check_ml_anomaly(packet)
        if ml_result and ml_result.detected:
            return ml_result
        
        return None
    
    def _check_signature_rule(self, packet: PacketData, rule: dict) -> DetectionResult | None:
        """Check packet against a signature rule."""
        rule_type = rule.get("rule_type", "")
        criteria = rule.get("criteria", {})
        
        if rule_type == "SIGNATURE":
            # Protocol match
            if "protocol" in criteria:
                if packet.protocol.lower() != criteria["protocol"].lower():
                    return None
            
            # Port match
            if "dst_port" in criteria:
                if packet.dst_port != criteria["dst_port"]:
                    return None
            
            if "src_port" in criteria:
                if packet.src_port != criteria["src_port"]:
                    return None
            
            # If we get here, rule matched
            return DetectionResult(
                detected=True,
                event_type="signature",
                severity=rule.get("priority", "MEDIUM"),
                rule_id=rule.get("id"),
                rule_name=rule.get("name"),
                description=f"Signature match: {rule.get('name')}",
                country_code=packet.country_code,
            )
        
        elif rule_type == "PAYLOAD_MATCH":
            import re
            regex = criteria.get("regex", "")
            if regex and packet.payload:
                flags = re.IGNORECASE if criteria.get("case_insensitive") else 0
                try:
                    payload_str = packet.payload.decode("utf-8", errors="ignore")
                    if re.search(regex, payload_str, flags):
                        return DetectionResult(
                            detected=True,
                            event_type="signature",
                            severity=rule.get("priority", "HIGH"),
                            rule_id=rule.get("id"),
                            rule_name=rule.get("name"),
                            description=f"Payload pattern match: {rule.get('name')}",
                            country_code=packet.country_code,
                        )
                except Exception:
                    pass
        
        return None
    
    def _check_rate_limit(self, packet: PacketData) -> DetectionResult | None:
        """Check for rate limit violations (e.g., port scanning)."""
        src_ip = packet.src_ip
        now = time.time()
        
        # Initialize tracking for this IP
        if src_ip not in self._ip_packet_counts:
            self._ip_packet_counts[src_ip] = deque(maxlen=1000)
        
        self._ip_packet_counts[src_ip].append(now)
        
        # Count packets in last 10 seconds
        recent = [t for t in self._ip_packet_counts[src_ip] if now - t < 10]
        packets_per_second = len(recent) / 10.0
        
        # Check against rate limit rules
        for rule in self._rules:
            if rule.get("rule_type") == "RATE_LIMIT":
                threshold = rule.get("criteria", {}).get("packets_per_second", 100)
                if packets_per_second > threshold:
                    return DetectionResult(
                        detected=True,
                        event_type="signature",
                        severity=rule.get("priority", "HIGH"),
                        rule_id=rule.get("id"),
                        rule_name=rule.get("name"),
                        description=f"Rate limit exceeded: {packets_per_second:.1f} pps from {src_ip}",
                        country_code=packet.country_code,
                    )
        
        return None
    
    def _check_ml_anomaly(self, packet: PacketData) -> DetectionResult | None:
        """Simple ML-based anomaly detection."""
        # Simplified scoring based on packet characteristics
        anomaly_score = 0.0
        
        # Unusual ports
        suspicious_ports = [4444, 5555, 6666, 31337, 12345, 54321]
        if packet.dst_port in suspicious_ports or packet.src_port in suspicious_ports:
            anomaly_score += 0.3
        
        # Large packets
        if packet.packet_length > 1500:
            anomaly_score += 0.2
        
        # Low TTL (possible spoofing)
        if packet.ttl < 32:
            anomaly_score += 0.2
        
        # Unusual TCP flags
        if packet.tcp_flags > 0 and packet.tcp_flags not in [2, 16, 18, 24]:  # SYN, ACK, SYN-ACK, PSH-ACK
            anomaly_score += 0.3
        
        # Random factor for demo (simulates ML model output)
        if random.random() < 0.02:  # 2% random anomaly
            anomaly_score += 0.4
        
        if anomaly_score >= 0.5:
            severity = "CRITICAL" if anomaly_score > 0.8 else "HIGH" if anomaly_score > 0.6 else "MEDIUM"
            return DetectionResult(
                detected=True,
                event_type="anomaly",
                severity=severity,
                rule_id=None,
                rule_name=None,
                description=f"ML anomaly detected (score: {anomaly_score:.2f})",
                ml_score=anomaly_score,
                country_code=packet.country_code,
            )
        
        return None
    
    async def _emit_event(self, packet: PacketData, result: DetectionResult):
        """Emit a detection event to all registered callbacks."""
        rule_fingerprint = None
        if result.rule_id is not None:
            matched_rule = next((r for r in self._rules if r.get("id") == result.rule_id), None)
            if matched_rule and self._is_suppressed(matched_rule, packet):
                return
            if matched_rule:
                rule_fingerprint = self._suppression_fingerprint(int(result.rule_id), packet)

        event_data = {
            "timestamp": packet.timestamp.isoformat(),
            "event_type": result.event_type,
            "severity": result.severity,
            "src_ip": packet.src_ip,
            "dst_ip": packet.dst_ip,
            "protocol": packet.protocol,
            "src_port": packet.src_port,
            "dst_port": packet.dst_port,
            "description": result.description,
            "rule_id": result.rule_id,
            "rule_name": result.rule_name,
            "rule_fingerprint": rule_fingerprint,
            "packet_length": packet.packet_length,
            "ml_score": result.ml_score,
            "threat_intel_score": result.threat_intel_score,
            "country_code": result.country_code,
        }

        # Publish to external broker first if configured
        if self._event_publisher:
            try:
                self._event_publisher(event_data)
            except Exception as e:
                logger.error(f"Event publish error: {e}")

        # Direct callbacks remain as fallback / local mode
        for callback in self._event_callbacks:
            try:
                if asyncio.iscoroutinefunction(callback):
                    await callback(event_data)
                else:
                    callback(event_data)
            except Exception as e:
                logger.error(f"Event callback error: {e}")

    def _suppression_fingerprint(self, rule_id: int, packet: PacketData) -> str:
        raw = f"{rule_id}|{packet.src_ip}|{packet.dst_ip}|{packet.protocol.lower()}"
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()

    def _is_suppressed(self, rule: dict, packet: PacketData) -> bool:
        if not rule.get("suppression_enabled", False):
            return False
        window = int(rule.get("suppression_window_seconds") or 0)
        if window <= 0:
            return False
        rule_id = rule.get("id")
        if rule_id is None:
            return False
        now = time.time()
        fingerprint = self._suppression_fingerprint(int(rule_id), packet)
        key = (int(rule_id), fingerprint)
        last_seen = self._suppression_cache.get(key)
        self._suppression_cache[key] = now
        return last_seen is not None and (now - last_seen) <= window
    
    async def _broadcast_metrics(self):
        """Periodically broadcast metrics to callbacks."""
        while self.running:
            await asyncio.sleep(1.0)
            
            metrics_data = self.metrics.to_dict()
            for callback in self._metrics_callbacks:
                try:
                    if asyncio.iscoroutinefunction(callback):
                        await callback(metrics_data)
                    else:
                        callback(metrics_data)
                except Exception as e:
                    logger.error(f"Metrics callback error: {e}")


# Global engine instance
_engine: DetectionEngine | None = None


def get_detection_engine() -> DetectionEngine:
    """Get the global detection engine instance."""
    global _engine
    if _engine is None:
        _engine = DetectionEngine()
    return _engine
