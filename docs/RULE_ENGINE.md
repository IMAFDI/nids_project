# Writing Custom Detection Rules

## Overview

NIDS supports five types of detection rules. Rules can be:
1. **Static** — defined in `config/rules.json`
2. **Dynamic** — created, updated, and deleted via the REST API

---

## Rule Structure

Every rule has these common fields:

| Field | Type | Required | Description |
|-------|------|---------|-------------|
| `id` | int | Yes | Unique rule identifier |
| `name` | string | Yes | Human-readable name |
| `rule_type` | enum | Yes | SIGNATURE, RATE_LIMIT, PAYLOAD_MATCH, GEO_BLOCK, WHITELIST |
| `enabled` | bool | No | Whether rule is active (default: true) |
| `priority` | enum | No | LOW, MEDIUM, HIGH, CRITICAL (default: MEDIUM) |
| `description` | string | No | Human-readable description |
| `criteria` | object | Yes | Rule-type-specific criteria |

---

## Rule Types

### SIGNATURE

Traditional rule-based detection. Matches packets by protocol, IP, port, TCP flags, and threshold/time-window.

```json
{
  "id": 101,
  "name": "SSH Brute Force Detection",
  "rule_type": "SIGNATURE",
  "enabled": true,
  "priority": "HIGH",
  "description": "Detects SSH brute force via repeated SYN packets to port 22",
  "criteria": {
    "protocol": "tcp",
    "src_ip": "any",
    "dst_ip": "any",
    "src_port": "any",
    "dst_port": 22,
    "flags": "SYN",
    "threshold": 10,
    "time_window": 30
  }
}
```

| Criteria Field | Type | Description |
|---------------|------|-------------|
| `protocol` | string | tcp, udp, icmp, any |
| `src_ip` | string | IP address, CIDR, or "any" |
| `dst_ip` | string | IP address, CIDR, or "any" |
| `src_port` | int or "any" | Source port |
| `dst_port` | int or "any" | Destination port |
| `flags` | string | TCP flags: SYN, ACK, FIN, RST, PSH, URG (comma-separated) |
| `type` | string | ICMP type: echo-request, echo-reply |
| `threshold` | int | Packets to trigger alert |
| `time_window` | int | Seconds for threshold window |

---

### RATE_LIMIT

Triggers when traffic rate from a single IP exceeds a threshold.

```json
{
  "id": 102,
  "name": "ICMP Flood Detection",
  "rule_type": "RATE_LIMIT",
  "enabled": true,
  "priority": "HIGH",
  "description": "Detects ICMP flood attack",
  "criteria": {
    "protocol": "icmp",
    "rate_per_second": 50,
    "time_window": 1
  }
}
```

| Criteria Field | Type | Description |
|---------------|------|-------------|
| `protocol` | string | tcp, udp, icmp, any |
| `rate_per_second` | int | Packets per second threshold |
| `time_window` | int | Time window in seconds (default: 1) |

---

### PAYLOAD_MATCH

Triggers when a packet's payload matches a regex pattern. Useful for DPI-style detection.

```json
{
  "id": 103,
  "name": "SQL Injection Detection",
  "rule_type": "PAYLOAD_MATCH",
  "enabled": true,
  "priority": "CRITICAL",
  "description": "Detects SQL injection attempts in HTTP requests",
  "criteria": {
    "protocol": "tcp",
    "payload_regex": "(?i)(SELECT|INSERT|UPDATE|DELETE|DROP).*FROM"
  }
}
```

| Criteria Field | Type | Description |
|---------------|------|-------------|
| `protocol` | string | tcp, udp, any |
| `payload_regex` | string | Python regex pattern (case-insensitive by default) |

**Note**: Requires packet to have a Raw layer (payload data). TCP ACK-only packets with no payload will not match.

---

### GEO_BLOCK

Blocks or alerts on traffic from specific countries. Requires GeoLite2 database.

```json
{
  "id": 104,
  "name": "Block China Traffic",
  "rule_type": "GEO_BLOCK",
  "enabled": false,
  "priority": "HIGH",
  "description": "Block all traffic from China",
  "criteria": {
    "countries": ["CN", "HK"]
  }
}
```

| Criteria Field | Type | Description |
|---------------|------|-------------|
| `countries` | array | ISO 3166-1 alpha-2 country codes |

**Note**: Requires `geoip2` package and GeoLite2-Country.mmdb database installed.

---

### WHITELIST

Marks IPs as trusted — no alerts will be generated for these IPs regardless of other rule matches.

```json
{
  "id": 200,
  "name": "Internal Network Whitelist",
  "rule_type": "WHITELIST",
  "enabled": true,
  "description": "Trusted internal network",
  "criteria": {
    "src_ip": "10.0.0.0/8"
  }
}
```

**Note**: Whitelist rules are evaluated first. Matching IPs bypass all other detection (except logging).

---

## Managing Rules via API

### Create a rule

```bash
curl -X POST http://localhost:8000/api/v1/rules \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "My Custom Rule",
    "rule_type": "PAYLOAD_MATCH",
    "criteria": {
      "protocol": "tcp",
      "payload_regex": "malicious_pattern"
    },
    "priority": "CRITICAL",
    "description": "Custom detection rule"
  }'
```

### Update a rule

```bash
curl -X PUT http://localhost:8000/api/v1/rules/103 \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "enabled": true,
    "threshold": 5
  }'
```

### Toggle a rule

```bash
curl -X POST http://localhost:8000/api/v1/rules/103/toggle \
  -H "Authorization: Bearer $TOKEN"
```

### Delete a rule

```bash
curl -X DELETE http://localhost:8000/api/v1/rules/103 \
  -H "Authorization: Bearer $TOKEN"
```

---

## Best Practices

1. **Use specific thresholds**: Too low = false positives, too high = missed attacks
2. **Set appropriate time windows**: Shorter windows catch burst attacks, longer windows catch slow attacks
3. **Use priority levels**: CRITICAL rules for severe threats, LOW for informational alerts
4. **Whitelist internal networks**: Prevent alerts from trusted internal IPs
5. **Monitor rule hit counts**: Use the Rules Manager dashboard to identify frequently triggered rules
6. **Test new rules**: Use batch mode with a small packet capture before deploying live
