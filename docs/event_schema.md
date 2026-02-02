# Security Event Schema (sec.event.v1)

ARES ingests untrusted security telemetry events and treats them as log data:
authenticate → validate → correlate → policy → alert/audit.

## Event Type: sec.event.v1

### Required fields
- event_type: "sec.event.v1"
- event_id: string (UUID recommended)
- source: string (e.g., "auth", "sysmon", "zeek", "wazuh", "custom-agent")
- host: string (hostname)
- timestamp_utc: ISO8601 string (timezone-aware)

- category: string (e.g., "auth", "process", "network")
- action: string (e.g., "login_failed", "proc_start", "dns_query")
- severity: integer 0..10

### Optional fields
- user: string
- src_ip: string
- dest_ip: string
- process_name: string
- attributes: object (free-form key-values)

### Gateway rules
Reject if:
- missing required fields or bad types
- timestamp outside replay window
- duplicate event_id
- rate limit exceeded
