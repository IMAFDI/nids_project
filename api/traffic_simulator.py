"""
NIDS — Network Traffic Simulator
================================
Generates realistic network traffic for demo and testing purposes.
Simulates both normal traffic and various attack scenarios.
"""

from __future__ import annotations

import asyncio
import logging
import random
from datetime import datetime, timezone
from typing import Any

from api.detection_engine import PacketData, get_detection_engine

logger = logging.getLogger("NIDS.TrafficSimulator")


# Realistic IP ranges for simulation
INTERNAL_IPS = [f"10.0.0.{i}" for i in range(1, 50)]
EXTERNAL_IPS = [
    # Normal traffic sources
    "8.8.8.8", "8.8.4.4",  # Google DNS
    "1.1.1.1", "1.0.0.1",  # Cloudflare DNS
    "208.67.222.222",      # OpenDNS
    "93.184.216.34",       # example.com
    "151.101.1.140",       # Reddit
    "140.82.112.4",        # GitHub
    # Suspicious sources (for attack simulation)
    "185.220.101.45",      # Known Tor exit
    "45.33.32.156",        # Scanners
    "91.121.87.18",        # Suspicious
    "203.0.113.50",        # Test range
    "198.51.100.25",       # Test range
]

ATTACK_IPS = [
    ("192.168.1.100", "CN"),   # Port scanner
    ("45.76.113.90", "RU"),    # Brute forcer
    ("185.220.101.45", "DE"),  # Tor exit node
    ("91.189.95.10", "NL"),    # Botnet C2
    ("104.244.42.1", "US"),    # Scraper
    ("45.33.32.156", "BR"),    # Vulnerability scanner
]

# Common ports and protocols
NORMAL_PORTS = [80, 443, 53, 22, 25, 993, 587, 8080, 3306, 5432]
SUSPICIOUS_PORTS = [4444, 5555, 6666, 31337, 12345, 54321, 1337, 9999]


class AttackScenario:
    """Base class for attack scenarios."""
    
    def __init__(self, name: str, duration_seconds: int = 30):
        self.name = name
        self.duration = duration_seconds
        self.active = False
        self.start_time = 0.0
    
    async def generate_packet(self) -> PacketData | None:
        raise NotImplementedError


class PortScanAttack(AttackScenario):
    """Simulates a port scanning attack from a single IP."""
    
    def __init__(self):
        super().__init__("Port Scan Attack", duration_seconds=20)
        self.attacker_ip, self.country = random.choice(ATTACK_IPS)
        self.target_ip = random.choice(INTERNAL_IPS)
        self.current_port = 1
    
    async def generate_packet(self) -> PacketData:
        packet = PacketData(
            timestamp=datetime.now(timezone.utc),
            src_ip=self.attacker_ip,
            dst_ip=self.target_ip,
            protocol="tcp",
            src_port=random.randint(40000, 65000),
            dst_port=self.current_port,
            packet_length=52,
            tcp_flags=2,  # SYN
            ttl=random.randint(50, 64),
            country_code=self.country,
        )
        self.current_port += 1
        if self.current_port > 1024:
            self.current_port = 1
        return packet


class SSHBruteForceAttack(AttackScenario):
    """Simulates SSH brute force attack."""
    
    def __init__(self):
        super().__init__("SSH Brute Force", duration_seconds=30)
        self.attacker_ip, self.country = random.choice(ATTACK_IPS)
        self.target_ip = random.choice(INTERNAL_IPS)
    
    async def generate_packet(self) -> PacketData:
        return PacketData(
            timestamp=datetime.now(timezone.utc),
            src_ip=self.attacker_ip,
            dst_ip=self.target_ip,
            protocol="tcp",
            src_port=random.randint(40000, 65000),
            dst_port=22,
            packet_length=random.randint(64, 256),
            tcp_flags=24,  # PSH-ACK
            ttl=random.randint(50, 64),
            payload=b"SSH-2.0-OpenSSH_8.0\r\n",
            country_code=self.country,
        )


class SQLInjectionAttack(AttackScenario):
    """Simulates SQL injection attempts."""
    
    PAYLOADS = [
        b"GET /search?q=' OR '1'='1 HTTP/1.1\r\n",
        b"POST /login HTTP/1.1\r\n\r\nusername=admin'--&password=x",
        b"GET /users?id=1 UNION SELECT * FROM users-- HTTP/1.1\r\n",
        b"GET /product?id=1; DROP TABLE users;-- HTTP/1.1\r\n",
    ]
    
    def __init__(self):
        super().__init__("SQL Injection", duration_seconds=15)
        self.attacker_ip, self.country = random.choice(ATTACK_IPS)
        self.target_ip = random.choice(INTERNAL_IPS)
    
    async def generate_packet(self) -> PacketData:
        payload = random.choice(self.PAYLOADS)
        return PacketData(
            timestamp=datetime.now(timezone.utc),
            src_ip=self.attacker_ip,
            dst_ip=self.target_ip,
            protocol="tcp",
            src_port=random.randint(40000, 65000),
            dst_port=random.choice([80, 443, 8080]),
            packet_length=len(payload) + 52,
            tcp_flags=24,  # PSH-ACK
            ttl=random.randint(50, 64),
            payload=payload,
            country_code=self.country,
        )


class DDoSAttack(AttackScenario):
    """Simulates a DDoS flood attack."""
    
    def __init__(self):
        super().__init__("DDoS Flood", duration_seconds=25)
        self.target_ip = random.choice(INTERNAL_IPS)
    
    async def generate_packet(self) -> PacketData:
        # Random source IPs (spoofed) - random countries
        src_ip = f"{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}"
        countries = ["CN", "RU", "US", "BR", "IN", "DE", "FR", "GB", "JP", "KR"]
        return PacketData(
            timestamp=datetime.now(timezone.utc),
            src_ip=src_ip,
            dst_ip=self.target_ip,
            protocol=random.choice(["tcp", "udp"]),
            src_port=random.randint(1024, 65000),
            dst_port=random.choice([80, 443]),
            packet_length=random.randint(64, 1500),
            tcp_flags=2 if random.random() > 0.5 else 0,  # SYN or none
            ttl=random.randint(20, 64),
            country_code=random.choice(countries),
        )


class C2CommunicationAttack(AttackScenario):
    """Simulates Command & Control communication."""
    
    def __init__(self):
        super().__init__("C2 Communication", duration_seconds=40)
        self.infected_ip = random.choice(INTERNAL_IPS)
        self.c2_server, self.c2_country = random.choice(ATTACK_IPS)
    
    async def generate_packet(self) -> PacketData:
        # Beaconing pattern - small packets at regular intervals
        return PacketData(
            timestamp=datetime.now(timezone.utc),
            src_ip=self.infected_ip,
            dst_ip=self.c2_server,
            protocol="tcp",
            src_port=random.randint(40000, 65000),
            dst_port=random.choice([443, 8443, 4444, 8080]),
            packet_length=random.randint(64, 128),
            tcp_flags=24,  # PSH-ACK
            ttl=64,
            payload=b"\x00" * random.randint(16, 64),  # Encrypted beacon
            country_code=self.c2_country,
        )


class TrafficSimulator:
    """
    Network traffic simulator that generates realistic traffic patterns.
    
    Includes both normal traffic and periodic attack simulations.
    """
    
    def __init__(
        self,
        normal_pps: float = 50.0,     # Normal packets per second
        attack_interval: float = 30.0, # Seconds between attacks
    ):
        self.normal_pps = normal_pps
        self.attack_interval = attack_interval
        self.running = False
        self.current_attack: AttackScenario | None = None
        self._tasks: list[asyncio.Task] = []
        
        # Available attack types
        self.attack_types = [
            PortScanAttack,
            SSHBruteForceAttack,
            SQLInjectionAttack,
            DDoSAttack,
            C2CommunicationAttack,
        ]
    
    async def start(self):
        """Start the traffic simulator."""
        if self.running:
            return
        
        self.running = True
        logger.info(f"Starting traffic simulator: {self.normal_pps} pps normal traffic")
        
        # Start normal traffic generator
        self._tasks.append(asyncio.create_task(self._generate_normal_traffic()))
        
        # Start attack scheduler
        self._tasks.append(asyncio.create_task(self._schedule_attacks()))
    
    async def stop(self):
        """Stop the traffic simulator."""
        self.running = False
        for task in self._tasks:
            task.cancel()
        self._tasks.clear()
        logger.info("Traffic simulator stopped")
    
    async def _generate_normal_traffic(self):
        """Generate normal network traffic."""
        engine = get_detection_engine()
        interval = 1.0 / self.normal_pps
        
        while self.running:
            try:
                packet = self._create_normal_packet()
                await engine.submit_packet(packet)
                await asyncio.sleep(interval + random.uniform(-0.01, 0.01))
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Normal traffic error: {e}")
                await asyncio.sleep(0.1)
    
    def _create_normal_packet(self) -> PacketData:
        """Create a normal-looking network packet."""
        # Mostly internal-to-external traffic
        if random.random() < 0.7:
            src_ip = random.choice(INTERNAL_IPS)
            dst_ip = random.choice(EXTERNAL_IPS)
        else:
            src_ip = random.choice(EXTERNAL_IPS)
            dst_ip = random.choice(INTERNAL_IPS)
        
        # Common protocols and ports
        if random.random() < 0.6:
            # HTTPS
            protocol, dst_port = "tcp", 443
        elif random.random() < 0.8:
            # HTTP
            protocol, dst_port = "tcp", 80
        elif random.random() < 0.9:
            # DNS
            protocol, dst_port = "udp", 53
        else:
            # Other
            protocol = random.choice(["tcp", "udp"])
            dst_port = random.choice(NORMAL_PORTS)
        
        # Assign country code based on source IP
        if src_ip in INTERNAL_IPS:
            country_code = "US"  # Internal IPs are US-based
        else:
            # External IPs get random legitimate country codes
            legitimate_countries = ["US", "GB", "DE", "FR", "CA", "AU", "JP", "SG", "NL", "SE"]
            country_code = random.choice(legitimate_countries)
        
        return PacketData(
            timestamp=datetime.now(timezone.utc),
            src_ip=src_ip,
            dst_ip=dst_ip,
            protocol=protocol,
            src_port=random.randint(32768, 65535),
            dst_port=dst_port,
            packet_length=random.randint(64, 1400),
            tcp_flags=18 if protocol == "tcp" else 0,  # SYN-ACK
            ttl=random.randint(50, 64),
            country_code=country_code,
        )
    
    async def _schedule_attacks(self):
        """Schedule periodic attack simulations."""
        engine = get_detection_engine()
        
        # Wait initial delay before first attack
        await asyncio.sleep(10)
        
        while self.running:
            try:
                # Select random attack type
                attack_class = random.choice(self.attack_types)
                self.current_attack = attack_class()
                
                logger.info(f"Starting attack simulation: {self.current_attack.name}")
                
                # Run attack for its duration
                attack_end_time = asyncio.get_event_loop().time() + self.current_attack.duration
                attack_pps = random.uniform(20, 100)  # Attack intensity
                
                while asyncio.get_event_loop().time() < attack_end_time and self.running:
                    packet = await self.current_attack.generate_packet()
                    await engine.submit_packet(packet)
                    await asyncio.sleep(1.0 / attack_pps)
                
                logger.info(f"Attack simulation ended: {self.current_attack.name}")
                self.current_attack = None
                
                # Wait before next attack
                await asyncio.sleep(self.attack_interval + random.uniform(-5, 10))
                
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Attack scheduler error: {e}")
                await asyncio.sleep(5)


# Global simulator instance
_simulator: TrafficSimulator | None = None


def get_traffic_simulator() -> TrafficSimulator:
    """Get the global traffic simulator instance."""
    global _simulator
    if _simulator is None:
        _simulator = TrafficSimulator()
    return _simulator
