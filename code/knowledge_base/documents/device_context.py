"""Device and network context documents for ChromaDB ingestion.

Describes the network topology, subnet roles, and device criticality
used in the CIC IoT-IDAD 2024 testbed. Helps the LLM reason about
whether a targeted or attacking device is high-value and how to
prioritize response.
"""

DEVICE_CONTEXT: list[dict] = [
    {
        "id": "ctx_iot_subnet",
        "text": (
            "IoT device subnet: 192.168.137.0/24. "
            "This is the primary IoT device network in the CIC testbed. "
            "Devices on this subnet are IoT sensors, actuators, smart home devices, "
            "IP cameras, smart thermostats, and industrial IoT controllers. "
            "Criticality: medium to high. These devices have limited computing resources, "
            "run embedded firmware, and typically cannot be patched quickly. "
            "Compromise of a device on this subnet can give the attacker a persistent foothold "
            "inside the network and the ability to pivot to other devices. "
            "A flow targeting a destination IP in 192.168.137.0/24 should be treated as "
            "higher priority than one targeting external hosts. "
            "A flow from a 192.168.137.x source IP that appears malicious may indicate "
            "an already-compromised IoT device (e.g., Mirai botnet member). "
            "Policy: devices on this subnet should only use ports 80, 443, 1883, 8883, 5683, 123. "
            "Any connection attempt to Telnet (23, 2323) from this subnet = Mirai compromise indicator."
        ),
        "metadata": {"subnet": "192.168.137.0/24", "role": "iot_device", "criticality": "medium"},
    },
    {
        "id": "ctx_internal_subnet_192",
        "text": (
            "Internal device subnet: 192.168.0.0/16 (excluding 192.168.137.0/24). "
            "This subnet contains internal infrastructure: servers, workstations, "
            "network management systems, and gateway devices. "
            "Criticality: medium. "
            "Devices here are more capable than IoT devices and can be patched more easily. "
            "Traffic from this subnet to the IoT subnet (192.168.137.0/24) should be "
            "monitored — legitimate management traffic vs. lateral movement. "
            "A gateway or server being targeted by DoS/DDoS from external IPs is high priority. "
            "Anomalous traffic from 192.168.0.x hosts may indicate compromised internal machine."
        ),
        "metadata": {"subnet": "192.168.0.0/16", "role": "internal_device", "criticality": "medium"},
    },
    {
        "id": "ctx_internal_subnet_10",
        "text": (
            "Internal private subnet: 10.0.0.0/8. "
            "Large private address space for internal infrastructure and VMs. "
            "Criticality: low to medium. "
            "In the CIC IoT-IDAD 2024 testbed, this range is used for background "
            "internal traffic and infrastructure nodes. "
            "Flows entirely within 10.0.0.0/8 are typically lower priority unless "
            "they show attack signatures (e.g., lateral movement, Recon scanning). "
            "A 10.x.x.x source IP generating scan patterns (high RST, short flows, many ports) "
            "indicates internal reconnaissance — potential attacker that already breached the perimeter."
        ),
        "metadata": {"subnet": "10.0.0.0/8", "role": "internal_device", "criticality": "low"},
    },
    {
        "id": "ctx_internal_subnet_172",
        "text": (
            "Internal private subnet: 172.16.0.0/12. "
            "Used for containerized services, VMs, and test infrastructure in the CIC testbed. "
            "Criticality: low. "
            "Similar to the 10.0.0.0/8 range — internal background traffic. "
            "Unusual outbound traffic from 172.16.x.x to external IPs may indicate "
            "data exfiltration from a compromised container or service."
        ),
        "metadata": {"subnet": "172.16.0.0/12", "role": "internal_device", "criticality": "low"},
    },
    {
        "id": "ctx_external_host",
        "text": (
            "External hosts: any IP not in 192.168.0.0/16, 10.0.0.0/8, or 172.16.0.0/12. "
            "External IPs in the CIC dataset represent attack sources in the testbed. "
            "In production, external IPs are internet-routable hosts outside the organization. "
            "A flow from an external source IP to an internal IoT device is inherently suspicious "
            "unless the device is intentionally internet-facing (e.g., cloud-connected sensor). "
            "Most IoT devices should NOT receive unsolicited inbound connections from external IPs. "
            "External source IP + connection to Telnet port (23/2323) = almost certain Mirai scan. "
            "External source IP + high packet rate = DoS/DDoS attack. "
            "External source IP + many short flows to port 22 = SSH brute force. "
            "Treat all external-to-internal flows as elevated risk by default."
        ),
        "metadata": {"subnet": "external", "role": "external_host", "criticality": "low"},
    },
    {
        "id": "ctx_device_types",
        "text": (
            "IoT device type context for incident prioritization. "
            "High criticality devices (quarantine immediately if compromised): "
            "  - Industrial IoT controllers (PLCs, SCADA sensors): control physical processes. "
            "  - Medical IoT devices: patient safety critical. "
            "  - Security cameras and access control systems: safety infrastructure. "
            "Medium criticality devices (escalate, investigate): "
            "  - Smart thermostats, HVAC controllers: comfort and energy systems. "
            "  - Network gateways and edge routers: connectivity infrastructure. "
            "  - Smart meters: utility billing. "
            "Low criticality devices (alert, monitor): "
            "  - Consumer smart home devices (lights, locks): limited blast radius. "
            "  - Environmental sensors (temperature, humidity): data collection only. "
            "When source or destination IP maps to a high-criticality device, "
            "always escalate regardless of ML confidence level."
        ),
        "metadata": {"type": "device_classification", "criticality": "varies"},
    },
]
