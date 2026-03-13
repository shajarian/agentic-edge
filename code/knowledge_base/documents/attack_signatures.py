"""Attack signature documents for ChromaDB ingestion.

One document per attack class from the CIC IoT-IDAD 2024 dataset:
    Benign, DDoS, DoS, Mirai, BruteForce, Recon, Spoofing, Web-Based

Each document describes the attack's flow-level signatures, helping the LLM
reason from CICFlowMeter features to threat class even when ML confidence is low.
"""

ATTACK_SIGNATURES: list[dict] = [
    {
        "id": "sig_benign",
        "text": (
            "Benign IoT traffic characteristics. "
            "Normal IoT devices produce short, bursty flows with balanced SYN and FIN flags "
            "(SYN_FIN_Ratio close to 1.0, typically 0.8–1.5). "
            "Packet rates are low: ICMP under 50 pkt/s, TCP under 500 pkt/s, UDP under 1000 pkt/s. "
            "Byte rates stay below 500 KB/s for TCP and 1 MB/s for UDP. "
            "Flows are short-lived (milliseconds to a few seconds) for sensor telemetry, "
            "or have long duration with low packet rate for keep-alive connections. "
            "Forward and backward packet counts are roughly balanced (fwd_bwd_ratio near 1.0). "
            "ACK and PSH flags appear together for normal data exchange. "
            "RST flag count is low. "
            "Destination ports are typically application-specific: 80/443 (HTTP/HTTPS), "
            "1883/8883 (MQTT), 5683 (CoAP), 123 (NTP). "
            "If ML predicts Benign with confidence >= 0.85, the flow takes the fast path and is logged without LLM analysis."
        ),
        "metadata": {"class": "Benign", "severity": "none", "ml_f1": "0.99"},
    },
    {
        "id": "sig_ddos",
        "text": (
            "DDoS (Distributed Denial of Service) attack signatures. "
            "Traffic originates from multiple source IPs simultaneously targeting a single victim. "
            "Sub-types observed in the CIC IoT-IDAD 2024 dataset:\n"
            "  SYN Flood: Extremely high SYN flag count, near-zero FIN count. "
            "SYN_FIN_Ratio typically > 100. Packet rate >> 1000 pkt/s per source. "
            "Small payload (few bytes). Protocol TCP. Destination port 80 or 443.\n"
            "  UDP Flood: Very high UDP packet rate (>10,000 pkt/s), large byte rate. "
            "No TCP flags. Random or fixed destination port.\n"
            "  HTTP Flood: High PSH+ACK count on port 80/443. Looks like legitimate HTTP "
            "but at extreme rates. Moderate packet size.\n"
            "  SlowLoris: Many concurrent long-duration TCP flows (>60s), very low packet "
            "rate per flow (<5 pkt/s), targeting port 80. Keeps connections open without completing. "
            "Fwd_bwd_ratio is very high (server never responds fully).\n"
            "Key indicators: exceeds_baseline=true, high pkt_rate_ratio or byte_rate_ratio. "
            "Multiple IPs in EventStore with recent alerts = distributed attack in progress. "
            "Recommended action: rate_limit or block_ip for each attacking source."
        ),
        "metadata": {"class": "DDoS", "severity": "critical", "ml_f1": "0.95"},
    },
    {
        "id": "sig_dos",
        "text": (
            "DoS (Denial of Service) attack signatures — single-source variant. "
            "Same flood techniques as DDoS but all traffic originates from one source IP. "
            "Very high packet rate (>5000 pkt/s) from a single source. "
            "High byte rate exceeding baseline significantly. "
            "SYN Flood variant: SYN_FIN_Ratio > 50, high RST count (server refusing). "
            "ICMP Flood: Protocol=1, packet rate far exceeding 50 pkt/s baseline. "
            "UDP Flood: Protocol=17, packet rate far exceeding 1000 pkt/s baseline. "
            "Flow duration can be short (burst) or sustained (minutes). "
            "Destination IP is typically a critical IoT device or gateway (high-value target). "
            "If source IP has prior alerts in EventStore, this is likely an ongoing attack. "
            "Recommended action: block_ip for the single attacking source."
        ),
        "metadata": {"class": "DoS", "severity": "critical", "ml_f1": "0.97"},
    },
    {
        "id": "sig_mirai",
        "text": (
            "Mirai botnet attack signatures targeting IoT devices. "
            "Mirai is an IoT malware that scans for vulnerable devices using default credentials. "
            "Primary signature: connection attempts to Telnet port 23, "
            "alternative Telnet port 2323, TR-069/CWMP port 7547, and ADB port 5555. "
            "These ports are blocked by policy rule BLOCK_TELNET. "
            "Flow characteristics: TCP protocol, SYN-heavy scanning pattern (SYN_FIN_Ratio > 10), "
            "very short flow duration (<100ms per probe), small payload (Telnet banner exchange). "
            "Scanning behavior: sequential or random IP sweeping — many destination IPs in short time. "
            "After compromise, infected device joins botnet and starts scanning others "
            "(source IP becomes attacker — watch EventStore for IP appearing as both victim and attacker). "
            "RST count is high (most targets reject connection). "
            "Recommended action: block_port (23, 2323, 5555, 7547) and quarantine_device if device is compromised."
        ),
        "metadata": {"class": "Mirai", "severity": "high", "ml_f1": "0.98"},
    },
    {
        "id": "sig_bruteforce",
        "text": (
            "BruteForce attack signatures — automated credential guessing. "
            "WARNING: ML model has low F1=0.36 for BruteForce. LLM reasoning is critical here. "
            "Targets authentication services: SSH port 22, Telnet port 23, FTP port 21, "
            "HTTP Basic Auth port 80, RDP port 3389. "
            "Flow characteristics: many short TCP flows to the same destination IP and port. "
            "Each flow represents one login attempt (SYN→data→FIN or RST). "
            "PSH+ACK flags dominant (sending credentials). "
            "ACK count high relative to other flags. "
            "Individual flows appear normal rate, but high volume of repeated flows to same target "
            "is the distinguishing feature. "
            "Check EventStore for repeated alerts involving same source+destination IP pair. "
            "Flow duration: very short (< 500ms per attempt). "
            "Fwd_bwd_ratio > 2 (attacker sends more than server responds, especially after failed auth). "
            "Recommended action: block_ip for attacker and alert_only initially; "
            "escalate to quarantine_device if target is an IoT sensor."
        ),
        "metadata": {"class": "BruteForce", "severity": "high", "ml_f1": "0.36"},
    },
    {
        "id": "sig_recon",
        "text": (
            "Recon (Reconnaissance) attack signatures — network discovery and port scanning. "
            "Attacker maps the network to find live hosts and open services before launching an attack. "
            "Sub-types:\n"
            "  Port scan: Single source IP, many destination ports, very short flows (SYN then RST/no-reply). "
            "RST count extremely high (closed ports). Very low packet count per flow (1–3 packets). "
            "Flow duration < 10ms.\n"
            "  Ping sweep (ICMP): Protocol=1, many destination IPs, ICMP echo request pattern. "
            "Packet rate moderate but spread across many IPs.\n"
            "  Service scan (e.g., Nmap): TCP SYN to specific ports (22, 23, 80, 443, 8080). "
            "Slight delay between probes.\n"
            "Key indicators: high RST count, very low packet count per flow, "
            "flow_duration_ms < 10, many unique destination ports. "
            "Fwd_bwd_ratio very high (no server response = scan target offline or filtered). "
            "Recon typically precedes other attacks — check EventStore for follow-up attacks from same IP. "
            "Recommended action: alert_only for first detection; block_ip if persistent or followed by attack."
        ),
        "metadata": {"class": "Recon", "severity": "medium", "ml_f1": "0.99"},
    },
    {
        "id": "sig_spoofing",
        "text": (
            "Spoofing attack signatures — IP and ARP spoofing in IoT networks. "
            "Attacker forges source IP or MAC addresses to impersonate legitimate devices. "
            "IP Spoofing: Asymmetric traffic — high fwd_bwd_ratio because real destination host "
            "sends replies to the spoofed source (not the attacker). "
            "Attacker receives no reply, so flow appears one-directional. "
            "RST count may be high from confused hosts. "
            "ARP Spoofing: At the flow level, appears as many short broadcast-like flows. "
            "Characteristic: source IP is on internal subnet (192.168.x.x) but behaves suspiciously. "
            "May see traffic to .255 broadcast or gateway IP. "
            "DNS Spoofing: High UDP traffic to port 53, large number of short flows. "
            "Flow characteristics: very asymmetric fwd/bwd ratio, "
            "short duration, moderate packet rate, SYN without corresponding FIN/ACK completion. "
            "Recommended action: alert_only with escalation to incident manager; "
            "block_ip if spoofing source is identified."
        ),
        "metadata": {"class": "Spoofing", "severity": "high", "ml_f1": "0.93"},
    },
    {
        "id": "sig_web_based",
        "text": (
            "Web-Based attack signatures — HTTP exploitation targeting IoT web interfaces. "
            "WARNING: ML model has moderate F1=0.62 for Web-Based. LLM reasoning is important here. "
            "Targets web management interfaces on IoT devices: port 80 (HTTP), 443 (HTTPS), "
            "8080 (alt HTTP), 8443 (alt HTTPS). "
            "Attack types include SQL injection, XSS, command injection, path traversal, "
            "and exploitation of CVEs in IoT web firmware. "
            "Flow characteristics: TCP protocol, PSH+ACK dominant (HTTP request/response data). "
            "Moderate packet rate (not as extreme as DDoS). "
            "Larger payload sizes (attack payloads embedded in HTTP body). "
            "Flow duration moderate (seconds). "
            "Fwd_bwd_ratio > 3 (attacker sends large requests, small server response for errors). "
            "SYN_FIN_Ratio near 1 (complete TCP connections, unlike floods). "
            "HTTP response codes 4xx/5xx patterns not visible at flow level — rely on payload size asymmetry. "
            "If destination port is 80/443 and ML predicts Web-Based with even moderate confidence, "
            "escalate for human review. "
            "Recommended action: block_ip and alert_only; escalate to quarantine_device "
            "if the targeted device shows signs of compromise."
        ),
        "metadata": {"class": "Web-Based", "severity": "high", "ml_f1": "0.62"},
    },
]
