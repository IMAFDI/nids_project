#!/usr/bin/env python3
"""Add comprehensive detection rules to NIDS"""

import sys
sys.path.insert(0, '/Users/imafdi/Desktop/Project/my-projects/nids_project')

from config.database_v2 import init_db, get_session
from config.database_v2 import AlertRule
from datetime import datetime, timezone
from config.settings import get_settings

settings = get_settings()
init_db(settings.database.url)

# Additional detection rules
rules = [
    {
        "name": "FTP Brute Force",
        "rule_type": "SIGNATURE",
        "enabled": True,
        "priority": "HIGH",
        "description": "Detects multiple FTP login attempts",
        "criteria": {
            "protocol": "tcp",
            "dst_port": 21,
            "threshold": 5,
            "time_window_seconds": 60
        }
    },
    {
        "name": "RDP Brute Force",
        "rule_type": "SIGNATURE",
        "enabled": True,
        "priority": "CRITICAL",
        "description": "Detects multiple RDP connection attempts",
        "criteria": {
            "protocol": "tcp",
            "dst_port": 3389,
            "threshold": 5,
            "time_window_seconds": 60
        }
    },
    {
        "name": "Telnet Access Attempt",
        "rule_type": "SIGNATURE",
        "enabled": True,
        "priority": "MEDIUM",
        "description": "Detects Telnet access (insecure protocol)",
        "criteria": {
            "protocol": "tcp",
            "dst_port": 23
        }
    },
    {
        "name": "SMB Exploitation Attempt",
        "rule_type": "SIGNATURE",
        "enabled": True,
        "priority": "HIGH",
        "description": "Detects SMB exploitation attempts (EternalBlue, etc.)",
        "criteria": {
            "protocol": "tcp",
            "dst_port": 445,
            "packet_size_min": 500
        }
    },
    {
        "name": "DNS Tunneling",
        "rule_type": "RATE_LIMIT",
        "enabled": True,
        "priority": "HIGH",
        "description": "Detects suspicious DNS query rates",
        "criteria": {
            "protocol": "udp",
            "dst_port": 53,
            "packets_per_second": 20,
            "time_window_seconds": 10
        }
    },
    {
        "name": "ICMP Flood",
        "rule_type": "RATE_LIMIT",
        "enabled": True,
        "priority": "HIGH",
        "description": "Detects ICMP flood attacks",
        "criteria": {
            "protocol": "icmp",
            "packets_per_second": 100,
            "time_window_seconds": 5
        }
    },
    {
        "name": "SYN Flood",
        "rule_type": "SIGNATURE",
        "enabled": True,
        "priority": "CRITICAL",
        "description": "Detects TCP SYN flood attacks",
        "criteria": {
            "protocol": "tcp",
            "tcp_flags": "S",
            "threshold": 100,
            "time_window_seconds": 10
        }
    },
    {
        "name": "MySQL Brute Force",
        "rule_type": "SIGNATURE",
        "enabled": True,
        "priority": "HIGH",
        "description": "Detects MySQL brute force attempts",
        "criteria": {
            "protocol": "tcp",
            "dst_port": 3306,
            "threshold": 5,
            "time_window_seconds": 60
        }
    },
    {
        "name": "PostgreSQL Brute Force",
        "rule_type": "SIGNATURE",
        "enabled": True,
        "priority": "HIGH",
        "description": "Detects PostgreSQL brute force attempts",
        "criteria": {
            "protocol": "tcp",
            "dst_port": 5432,
            "threshold": 5,
            "time_window_seconds": 60
        }
    },
    {
        "name": "Web Admin Panel Access",
        "rule_type": "PAYLOAD_MATCH",
        "enabled": True,
        "priority": "MEDIUM",
        "description": "Detects access to common admin panels",
        "criteria": {
            "regex": "/(admin|phpmyadmin|wp-admin|manager|cpanel)",
            "case_insensitive": True
        }
    },
    {
        "name": "XSS Attack",
        "rule_type": "PAYLOAD_MATCH",
        "enabled": True,
        "priority": "HIGH",
        "description": "Detects Cross-Site Scripting attempts",
        "criteria": {
            "regex": "<script|javascript:|onerror=|onload=",
            "case_insensitive": True
        }
    },
    {
        "name": "Command Injection",
        "rule_type": "PAYLOAD_MATCH",
        "enabled": True,
        "priority": "CRITICAL",
        "description": "Detects command injection attempts",
        "criteria": {
            "regex": "(;|\\||&&)\\s*(cat|ls|whoami|pwd|wget|curl|nc|bash|sh)",
            "case_insensitive": True
        }
    },
    {
        "name": "Large Packet Anomaly",
        "rule_type": "SIGNATURE",
        "enabled": True,
        "priority": "LOW",
        "description": "Detects unusually large packets",
        "criteria": {
            "packet_size_min": 1500
        }
    },
    {
        "name": "Suspicious HTTP Method",
        "rule_type": "PAYLOAD_MATCH",
        "enabled": True,
        "priority": "MEDIUM",
        "description": "Detects unusual HTTP methods",
        "criteria": {
            "regex": "(TRACE|CONNECT|DEBUG|PROPFIND)",
            "case_insensitive": False
        }
    },
    {
        "name": "Directory Traversal",
        "rule_type": "PAYLOAD_MATCH",
        "enabled": True,
        "priority": "HIGH",
        "description": "Detects path traversal attempts",
        "criteria": {
            "regex": "\\.\\./|\\.\\.\\\\",
            "case_insensitive": False
        }
    }
]

with get_session() as session:
    # Check how many rules exist
    existing_count = session.query(AlertRule).count()
    print(f"Existing rules: {existing_count}")
    
    # Add new rules
    added = 0
    for rule_data in rules:
        # Check if rule already exists
        existing = session.query(AlertRule).filter_by(name=rule_data["name"]).first()
        if not existing:
            rule = AlertRule(
                name=rule_data["name"],
                rule_type=rule_data["rule_type"],
                enabled=rule_data["enabled"],
                version=1,
                priority=rule_data["priority"],
                description=rule_data["description"],
                criteria=rule_data["criteria"],
                created_at=datetime.now(timezone.utc),
                updated_at=datetime.now(timezone.utc),
                match_count=0
            )
            session.add(rule)
            added += 1
            print(f"✓ Added: {rule_data['name']}")
        else:
            print(f"- Exists: {rule_data['name']}")
    
    session.commit()
    print(f"\n✅ Added {added} new rules. Total: {existing_count + added}")
