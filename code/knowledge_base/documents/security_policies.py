"""Security policy documents for ChromaDB ingestion.

Describes the active security policies from the PolicyEngine in natural language,
so the LLM can reason about whether a flow violates site policy even before
calling any tools.
"""

SECURITY_POLICIES: list[dict] = [
    {
        "id": "policy_block_telnet",
        "text": (
            "Security policy BLOCK_TELNET: Block Telnet and common Mirai ports. "
            "Blocked ports: 23 (Telnet standard), 2323 (alternative Telnet), 5555 (ADB - Android Debug Bridge). "
            "Suggested action: block_port. "
            "Rationale: Telnet transmits credentials in cleartext and is the primary vector for "
            "Mirai botnet infection of IoT devices. Port 2323 is used when port 23 is filtered. "
            "Port 5555 (ADB) allows full shell access to Android-based IoT devices with no authentication "
            "if left exposed. "
            "Any flow with destination port 23, 2323, or 5555 should be immediately escalated "
            "regardless of ML prediction. This is an automatic policy violation. "
            "If source IP is external (internet-routable), it is almost certainly a Mirai scanner. "
            "If source IP is internal (192.168.137.x), the device may already be compromised "
            "and participating in the Mirai botnet — quarantine that device."
        ),
        "metadata": {"rule_id": "BLOCK_TELNET", "action": "block_port", "ports": "23,2323,5555"},
    },
    {
        "id": "policy_rate_limit_pps",
        "text": (
            "Security policy RATE_LIMIT_HIGH_PPS: Flag flows exceeding 10,000 packets per second. "
            "Suggested action: rate_limit. "
            "Rationale: Legitimate IoT traffic rarely exceeds 1,000 pkt/s even for high-bandwidth sensors. "
            "A flow rate above 10,000 pkt/s indicates a flood-type attack (DoS, DDoS, or UDP amplification). "
            "This policy is protocol-agnostic and applies to TCP, UDP, and ICMP. "
            "Action: Apply rate limiting at the gateway to cap the offending flow. "
            "If the packet rate is >100,000 pkt/s, escalate to block_ip instead of just rate_limit. "
            "Note: The check_flow_baseline tool uses tighter per-protocol thresholds "
            "(TCP: 500 pkt/s, UDP: 1000 pkt/s, ICMP: 50 pkt/s). A flow exceeding those "
            "is suspicious; one exceeding 10,000 pkt/s is definitely malicious."
        ),
        "metadata": {"rule_id": "RATE_LIMIT_HIGH_PPS", "action": "rate_limit", "threshold_pps": "10000"},
    },
    {
        "id": "policy_rate_limit_bps",
        "text": (
            "Security policy RATE_LIMIT_HIGH_BPS: Flag flows exceeding 100 MB/s (100,000,000 bytes/s). "
            "Suggested action: rate_limit. "
            "Rationale: IoT devices have limited bandwidth and legitimate flows stay well under 10 MB/s. "
            "A byte rate above 100 MB/s indicates volumetric attack traffic (UDP flood, ICMP flood, "
            "or high-bandwidth DDoS). "
            "This threshold is conservative — the real anomaly threshold from check_flow_baseline "
            "is 1 MB/s for UDP and 500 KB/s for TCP. "
            "Flows between 1–100 MB/s are suspicious; above 100 MB/s are policy violations. "
            "Action: rate_limit the offending source IP. "
            "Combined with high PPS: block_ip is more appropriate than rate_limit."
        ),
        "metadata": {"rule_id": "RATE_LIMIT_HIGH_BPS", "action": "rate_limit", "threshold_bps": "100000000"},
    },
    {
        "id": "policy_allowed_protocols",
        "text": (
            "Network protocol policy: Only TCP (protocol 6) and UDP (protocol 17) are allowed "
            "for standard IoT device communication. "
            "ICMP (protocol 1) is permitted for network diagnostics but at strictly limited rates "
            "(< 50 pkt/s per the check_flow_baseline baseline). "
            "Other protocols: Any flow using protocol numbers other than 1, 6, or 17 is unusual "
            "and should be escalated for review. "
            "Common IoT protocols over TCP/UDP: "
            "  MQTT: TCP port 1883 (unencrypted), 8883 (TLS). "
            "  CoAP: UDP port 5683 (standard), 5684 (DTLS). "
            "  HTTP/HTTPS: TCP port 80, 443. "
            "  NTP: UDP port 123. "
            "  DNS: UDP port 53. "
            "Traffic on non-standard ports should be flagged unless the device is known to "
            "use custom ports for its application protocol."
        ),
        "metadata": {"rule_id": "ALLOWED_PROTOCOLS", "allowed": "TCP(6),UDP(17),ICMP(1)"},
    },
    {
        "id": "policy_mitigation_actions",
        "text": (
            "Available mitigation actions for the Incident Manager agent. "
            "These are the only valid actions that can be requested when escalating: "
            "  quarantine_device: Isolate the device from the network entirely. "
            "    Use when: device is confirmed compromised (e.g., sending Mirai scans from IoT subnet). "
            "  rate_limit: Apply traffic shaping to cap the offending flow's bandwidth or packet rate. "
            "    Use when: flow exceeds baselines but attack confirmation is uncertain. "
            "  block_port: Block traffic on a specific destination port (e.g., 23, 2323, 5555). "
            "    Use when: policy-violating port access (BLOCK_TELNET policy). "
            "  block_ip: Drop all traffic from the offending source IP. "
            "    Use when: IP has multiple prior alerts, confirmed attacker, or DoS source. "
            "  alert_only: Generate alert for human operator, no automated blocking. "
            "    Use when: low confidence, first offense, or unclear situation. "
            "  no_action: Flow is benign after investigation. Log and continue. "
            "    Use when: investigation concludes the flow is safe. "
            "Escalation priority: quarantine_device > block_ip > block_port > rate_limit > alert_only > no_action."
        ),
        "metadata": {"rule_id": "MITIGATION_ACTIONS", "type": "escalation_guide"},
    },
]
