"""CICFlowMeter feature glossary documents for ChromaDB ingestion.

Translates the 77 numerical CICFlowMeter features into security-meaningful
interpretations. Grouped by feature category so the LLM can retrieve relevant
context when reasoning about specific flow characteristics.
"""

FEATURE_GLOSSARY: list[dict] = [
    {
        "id": "feat_rate_features",
        "text": (
            "Flow rate features and their security interpretation. "
            "'Flow Packets/s' (packet_rate): Number of packets per second in the flow. "
            "Normal IoT baselines: ICMP < 50 pkt/s, TCP < 500 pkt/s, UDP < 1000 pkt/s. "
            "5x–10x over baseline = suspicious. 100x+ over baseline = certain attack. "
            "Very high packet rate (>10,000 pkt/s) = DoS/DDoS flood. "
            "'Flow Bytes/s' (byte_rate): Bytes transmitted per second in the flow. "
            "Normal baselines: TCP < 500 KB/s, UDP < 1 MB/s. "
            "High byte rate with low packet rate = large payload per packet (normal data transfer or exfiltration). "
            "High byte rate with high packet rate = flood attack. "
            "Very low byte rate with moderate packet rate = empty SYN packets (SYN flood, scan). "
            "The monitoring agent computes packet_rate and byte_rate in flow statistics and passes them "
            "to the LLM. Call check_flow_baseline with the Protocol number to get threshold comparison."
        ),
        "metadata": {"category": "rate_features", "features": "Flow Packets/s, Flow Bytes/s"},
    },
    {
        "id": "feat_syn_fin_ratio",
        "text": (
            "SYN_FIN_Ratio: Engineered feature computed as SYN Flag Count / (FIN Flag Count + 1). "
            "Interpretation by value: "
            "  0.5–2.0 = Normal TCP traffic. Connections open and close cleanly. "
            "  2.0–10.0 = Mildly suspicious. Some connections not completing (timeouts, resets). "
            "  10–100 = Strong attack indicator. Many connections opened, few or none closed. "
            "    Consistent with SYN flood, port scanning, or brute force. "
            "  > 100 = Very strong SYN flood signature. Attacker sending SYN-only packets. "
            "Context: In a SYN flood, attacker sends SYN packets to exhaust server connection table "
            "but never completes the three-way handshake (no ACK). "
            "SYN Flag Count will be very high; FIN Flag Count will be near zero. "
            "This is the single most reliable indicator of SYN-based DoS/DDoS and Mirai scanning. "
            "Use this feature alongside RST Flag Count for confirming scan patterns."
        ),
        "metadata": {"category": "engineered_feature", "features": "SYN_FIN_Ratio"},
    },
    {
        "id": "feat_tcp_flags",
        "text": (
            "TCP flag features and their security interpretation. "
            "'SYN Flag Count': Number of packets with SYN bit set. "
            "  High SYN, low FIN = connection flood (SYN flood, Mirai scan, brute force). "
            "'FIN Flag Count': Number of packets with FIN bit set. "
            "  Low FIN relative to SYN = connections not properly terminated. "
            "'RST Flag Count': Number of packets with RST bit set. "
            "  High RST = many connections being rejected (scan hitting closed ports, "
            "  server refusing connections, or spoofed traffic causing resets). "
            "  Very high RST = port scan signature. "
            "'PSH Flag Count': Number of packets with PSH bit set. "
            "  High PSH = data-carrying packets (HTTP requests, credential submission). "
            "  PSH dominant flow to port 80/443 = web traffic or web-based attack. "
            "  PSH dominant flow to port 22/23 = authentication protocol (brute force target). "
            "'ACK Flag Count': Number of packets with ACK bit set. "
            "  Should accompany most data flows. Low ACK relative to PSH = one-directional data push. "
            "  In the flag_summary dict, check ratios: PSH/ACK balance, SYN/FIN balance."
        ),
        "metadata": {"category": "tcp_flags", "features": "SYN,FIN,RST,PSH,ACK Flag Count"},
    },
    {
        "id": "feat_fwd_bwd_ratio",
        "text": (
            "Forward/Backward packet ratio (fwd_bwd_ratio) and its security interpretation. "
            "Computed as: Total Fwd Packet / (Total Bwd packets + 1). "
            "Forward direction = client (source) to server (destination). "
            "Backward direction = server to client (reply traffic). "
            "Value interpretation: "
            "  0.5–3.0 = Normal bidirectional communication (IoT sensor reporting to cloud, HTTP exchange). "
            "  3.0–10.0 = Mildly asymmetric. Could be file upload, large request, or early attack stage. "
            "  > 10 = Strongly asymmetric. "
            "    If source is attacker: server is not responding (target offline, flood overwhelming it, "
            "    or IP spoofing so replies go to spoofed victim). "
            "    If destination port is closed: RST replies bring ratio down; if no reply, ratio is infinite. "
            "  ~1.0 = Symmetric — expected for request-response protocols (HTTP, MQTT, SSH). "
            "SlowLoris exception: ratio may be moderate because the server holds the connection open. "
            "Combine with flow_duration_ms: long duration + high fwd_bwd_ratio + low packet rate = SlowLoris."
        ),
        "metadata": {"category": "direction_features", "features": "Total Fwd Packet, Total Bwd packets"},
    },
    {
        "id": "feat_flow_duration",
        "text": (
            "Flow Duration and its security interpretation. "
            "Stored in raw data as microseconds. Displayed as flow_duration_ms (milliseconds) in flow stats. "
            "Value interpretation: "
            "  < 1 ms = Ultra-short flow. Typical of scan probes (SYN-RST exchange), "
            "    ICMP ping replies, or malformed/incomplete connections. "
            "    High volume of <1ms flows from same source = port scan or Mirai scan. "
            "  1–100 ms = Short transactional flow. Normal for CoAP, DNS, NTP, ICMP. "
            "    Also normal for a single HTTP request-response cycle. "
            "  100ms–10s = Medium duration. Normal for most IoT sensor reporting sessions. "
            "    Brute force attempts are often in this range (login attempt per flow). "
            "  10s–60s = Long flow. Persistent connections: MQTT keep-alive, WebSocket, SSH session. "
            "  > 60s = Very long flow. Suspicious if packet rate is very low: "
            "    SlowLoris maintains long-duration flows with minimal traffic to hold server resources. "
            "    Legitimate long flows exist (MQTT subscriptions, SSH tunnels) but should have "
            "    regular heartbeat packets."
        ),
        "metadata": {"category": "duration_feature", "features": "Flow Duration"},
    },
    {
        "id": "feat_packet_length",
        "text": (
            "Packet length features and their security interpretation. "
            "'Fwd Packet Length Max': Largest packet sent by the source. "
            "  Very small max (< 60 bytes) = SYN-only packets (no payload, flood attack). "
            "  Large max (> 1000 bytes) = data payload present (normal or web attack). "
            "'Fwd Packet Length Mean': Average packet size from source. "
            "  Mean ≈ 40-60 bytes = header-only packets (scan, SYN flood). "
            "  Mean ≈ 200-1000 bytes = normal IoT telemetry or HTTP. "
            "  Mean > 1000 bytes = large payload (video stream, file transfer, or DDoS amplification). "
            "'Fwd Packet Length Min': Smallest packet from source. "
            "  If min ≈ max ≈ mean = fixed-size packets (typical of flood attacks using crafted packets). "
            "  Variable min/max = normal traffic with mixed packet sizes. "
            "Backward (Bwd) equivalents: 'Bwd Packet Length Max/Mean/Min' describe server response sizes. "
            "  Very small bwd packets with large fwd packets = server sending errors (attack being rejected). "
            "  Zero bwd packets (Total Bwd packets = 0) = no server response (target unreachable or spoofed source)."
        ),
        "metadata": {"category": "packet_length", "features": "Fwd/Bwd Packet Length Max/Mean/Min"},
    },
    {
        "id": "feat_iat_features",
        "text": (
            "Inter-Arrival Time (IAT) features and their security interpretation. "
            "IAT = time between consecutive packets in the flow. "
            "'Flow IAT Mean': Average time between all packets (forward + backward). "
            "  Very low IAT mean (< 1ms) = machine-speed packet generation (flood attack). "
            "  Human-like traffic has higher, more variable IAT (10ms+). "
            "'Flow IAT Std': Standard deviation of inter-arrival times. "
            "  Low std with low mean = regular machine-paced flood (attack tool signature). "
            "  High std = variable human traffic or mixed flow. "
            "'Fwd IAT Mean': Average time between forward direction packets. "
            "  Very low Fwd IAT = attacker flooding at machine speed. "
            "'Fwd IAT Std': Variability in forward packet timing. "
            "  Low std + low mean = scripted/automated attack tool. "
            "  High std = human or application-paced traffic. "
            "Security rule of thumb: "
            "  Fwd IAT Mean < 0.1ms + Fwd IAT Std ≈ 0 = almost certainly automated flood/scan tool. "
            "  Fwd IAT Mean > 10ms with high std = likely human or normal application traffic."
        ),
        "metadata": {"category": "iat_features", "features": "Flow IAT Mean/Std, Fwd/Bwd IAT Mean/Std"},
    },
    {
        "id": "feat_protocol_ports",
        "text": (
            "Protocol number and destination port interpretation for IoT security. "
            "Protocol field (IANA numbers): "
            "  1 = ICMP. Used for ping, traceroute, error messages. "
            "    High ICMP rate = ICMP flood or ping sweep reconnaissance. "
            "  6 = TCP. Connection-oriented. Used for HTTP, SSH, Telnet, MQTT over TCP. "
            "    Check SYN/FIN flags and flow duration for attack patterns. "
            "  17 = UDP. Connectionless. Used for DNS, NTP, CoAP, MQTT over WebSocket. "
            "    High UDP rate = UDP flood. "
            "Destination port security context: "
            "  21 = FTP (brute force target). "
            "  22 = SSH (brute force, exfiltration channel). "
            "  23 = Telnet (BLOCK_TELNET policy — Mirai). "
            "  53 = DNS (spoofing, amplification). "
            "  80 = HTTP (web-based attack, DDoS HTTP flood). "
            "  123 = NTP (amplification DDoS). "
            "  443 = HTTPS (web-based attack, encrypted C2 channel). "
            "  1883 = MQTT unencrypted (IoT data interception). "
            "  2323 = Alt Telnet (BLOCK_TELNET policy — Mirai). "
            "  3389 = RDP (brute force). "
            "  5555 = ADB (BLOCK_TELNET policy — device hijack). "
            "  7547 = TR-069/CWMP (Mirai, router exploitation). "
            "  8080/8443 = Alt HTTP/HTTPS (IoT web interface attacks). "
            "Any connection to Telnet ports (23, 2323) or ADB (5555) should always trigger escalation."
        ),
        "metadata": {"category": "protocol_ports", "features": "Protocol, Dst Port"},
    },
]
