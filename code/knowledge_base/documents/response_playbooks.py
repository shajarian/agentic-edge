"""Incident response playbook documents for ChromaDB ingestion.

Per-attack-class decision guides for the monitoring agent LLM.
Each playbook defines: escalation criteria, recommended action,
and key evidence to include in the escalation reason.
"""

RESPONSE_PLAYBOOKS: list[dict] = [
    {
        "id": "playbook_ddos",
        "text": (
            "Incident response playbook for DDoS attacks. "
            "Escalation criteria: ALWAYS escalate DDoS. Never log benign if ML predicts DDoS. "
            "Priority: CRITICAL. "
            "Evidence to include in escalation reason: "
            "  1. Packet rate and how much it exceeds the baseline (pkt_rate_ratio from check_flow_baseline). "
            "  2. Byte rate and ratio. "
            "  3. SYN_FIN_Ratio if high (> 10 = SYN flood). "
            "  4. Number of recent events for the destination IP (victim) from EventStore. "
            "  5. Sub-type: SYN Flood, UDP Flood, HTTP Flood, or SlowLoris based on protocol+port+flags. "
            "Recommended action: rate_limit immediately, escalate to block_ip if multiple sources. "
            "Fast path override: Even if ML confidence is moderate (0.6–0.85), "
            "if packet_rate > 5000 pkt/s AND destination is on IoT subnet, escalate. "
            "SlowLoris exception: low packet rate but very long duration + many concurrent flows = escalate."
        ),
        "metadata": {"attack_class": "DDoS", "priority": "critical", "action": "rate_limit,block_ip"},
    },
    {
        "id": "playbook_dos",
        "text": (
            "Incident response playbook for DoS attacks. "
            "Escalation criteria: ALWAYS escalate DoS. "
            "Priority: CRITICAL. "
            "Evidence to include in escalation reason: "
            "  1. Single source IP confirmed (source IP is the attacker). "
            "  2. Packet or byte rate multiple times over baseline. "
            "  3. Prior events for this source IP in EventStore (repeat attacker?). "
            "  4. Target device subnet (IoT subnet = higher priority). "
            "Recommended action: block_ip for the single attacking source. "
            "This is more decisive than rate_limit for single-source attacks. "
            "If destination is a gateway or critical infrastructure, mark severity as critical."
        ),
        "metadata": {"attack_class": "DoS", "priority": "critical", "action": "block_ip"},
    },
    {
        "id": "playbook_mirai",
        "text": (
            "Incident response playbook for Mirai botnet attacks. "
            "Escalation criteria: ALWAYS escalate. Destination port 23/2323/5555 = automatic escalation. "
            "Priority: HIGH. "
            "Evidence to include in escalation reason: "
            "  1. Destination port (23, 2323, 5555, or 7547). "
            "  2. Policy violation: BLOCK_TELNET policy. "
            "  3. Source IP classification: external (scanner) or internal IoT subnet (compromised device). "
            "  4. SYN_FIN_Ratio (scanning pattern). "
            "  5. Recent events for source IP. "
            "Recommended actions: "
            "  - External source scanning internal IoT devices: block_port + block_ip. "
            "  - Internal IoT device (192.168.137.x) initiating scans: quarantine_device "
            "    (the device is compromised and spreading the botnet). "
            "Always report both source_ip and destination_ip when escalating Mirai."
        ),
        "metadata": {"attack_class": "Mirai", "priority": "high", "action": "block_port,quarantine_device"},
    },
    {
        "id": "playbook_bruteforce",
        "text": (
            "Incident response playbook for BruteForce attacks. "
            "CAUTION: ML F1=0.36. Require stronger evidence before escalating. "
            "Escalation criteria: "
            "  - Source IP has 3+ prior alerts in EventStore for same destination: ESCALATE. "
            "  - Destination port is 22 (SSH) or 23 (Telnet) from external IP: ESCALATE. "
            "  - Flow rate is normal but EventStore shows repeated short flows: ESCALATE. "
            "  - Single flow with no prior history and low confidence: alert_only or log. "
            "Priority: HIGH when confirmed, MEDIUM for first detection. "
            "Evidence to include in escalation reason: "
            "  1. Destination port (22 SSH, 23 Telnet, 21 FTP, 3389 RDP). "
            "  2. EventStore prior alert count for source+destination IP pair. "
            "  3. Flow duration (very short = per-attempt pattern). "
            "  4. PSH+ACK flag count. "
            "Recommended action: alert_only on first detection; block_ip after 3+ alerts. "
            "Destination device criticality matters — IoT device target = escalate sooner."
        ),
        "metadata": {"attack_class": "BruteForce", "priority": "high", "action": "alert_only,block_ip"},
    },
    {
        "id": "playbook_recon",
        "text": (
            "Incident response playbook for Recon (reconnaissance) attacks. "
            "Escalation criteria: "
            "  - First Recon detection: alert_only (attacker mapping the network). "
            "  - Recon followed by other attack type from same IP in EventStore: ESCALATE with high priority. "
            "  - Recon targeting IoT subnet (192.168.137.0/24): ESCALATE (attacker targeting IoT devices). "
            "Priority: MEDIUM for isolated Recon, HIGH if pre-cursor to another attack. "
            "Evidence to include in escalation reason: "
            "  1. RST count (high = port scan). "
            "  2. Flow duration (< 10ms = probe). "
            "  3. Protocol (ICMP = ping sweep, TCP = port scan). "
            "  4. Whether EventStore shows this IP previously doing other attacks. "
            "Recommended action: alert_only initially; block_ip if persistent or followed by attack. "
            "Key insight: Recon alone is not an attack but is a strong indicator that one is coming. "
            "Always include the observation in EventStore for future correlation."
        ),
        "metadata": {"attack_class": "Recon", "priority": "medium", "action": "alert_only,block_ip"},
    },
    {
        "id": "playbook_spoofing",
        "text": (
            "Incident response playbook for Spoofing attacks. "
            "Escalation criteria: "
            "  - Asymmetric fwd_bwd_ratio > 10 with no baseline explanation: ESCALATE. "
            "  - Internal source IP (192.168.137.x) behaving like external attacker: ESCALATE (ARP spoof). "
            "  - UDP to port 53 at high rate: ESCALATE (DNS spoofing). "
            "Priority: HIGH. "
            "Evidence to include in escalation reason: "
            "  1. fwd_bwd_ratio (extreme asymmetry = spoofed source). "
            "  2. RST count (confused hosts resetting spoofed connections). "
            "  3. Source IP classification (internal vs external). "
            "  4. Destination port (53=DNS spoof, broadcast=ARP). "
            "Recommended action: alert_only + block_ip for identified spoof source. "
            "ARP spoofing requires network-level response (VLAN isolation, static ARP entries) "
            "beyond what the agent can do — flag for human operator."
        ),
        "metadata": {"attack_class": "Spoofing", "priority": "high", "action": "alert_only,block_ip"},
    },
    {
        "id": "playbook_web_based",
        "text": (
            "Incident response playbook for Web-Based attacks. "
            "CAUTION: ML F1=0.62. LLM reasoning is important. "
            "Escalation criteria: "
            "  - Destination port 80/443/8080/8443 with ML predicting Web-Based: ESCALATE. "
            "  - Any confidence level for Web-Based prediction warrants investigation. "
            "  - PSH+ACK dominant flow to web port = data-carrying HTTP request (suspicious content). "
            "Priority: HIGH. "
            "Evidence to include in escalation reason: "
            "  1. Destination port (80, 443, 8080, 8443). "
            "  2. PSH flag count (data payloads). "
            "  3. Fwd_bwd_ratio (asymmetric = server returning error responses). "
            "  4. Prior events for source IP. "
            "Recommended action: alert_only first (cannot inspect HTTP payload at flow level); "
            "block_ip if source IP has prior web attack alerts in EventStore. "
            "Note to operator: Deep packet inspection recommended to confirm attack type "
            "(SQL injection vs XSS vs command injection). Flow-level analysis alone is insufficient."
        ),
        "metadata": {"attack_class": "Web-Based", "priority": "high", "action": "alert_only,block_ip"},
    },
    {
        "id": "playbook_benign",
        "text": (
            "Decision guide for flows the LLM determines are benign after investigation. "
            "When to log (not escalate): "
            "  - ML predicts Benign with confidence >= 0.85: fast path (LLM not invoked). "
            "  - ML predicts attack with low confidence (0.5–0.65) AND "
            "    check_flow_baseline shows rates within normal range AND "
            "    EventStore shows no prior alerts for source IP AND "
            "    destination port is a known legitimate IoT port: log the flow. "
            "  - BruteForce prediction with single isolated flow, no EventStore history, "
            "    destination is not an authentication service: log with alert_only note. "
            "Output format for benign decision: say 'Decision: log' as the final response. "
            "Do NOT call escalate_to_incident_manager for benign decisions. "
            "The decision must be explicit — ambiguous responses default to escalate in the agent logic."
        ),
        "metadata": {"attack_class": "Benign", "priority": "none", "action": "log"},
    },
]
