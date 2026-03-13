"""
Device Registry — maintains metadata about IoT devices in the network.

In a production deployment this would be backed by a persistent store
on the gateway.  For research evaluation we populate it from the dataset's
IP addresses and assign simulated roles.
"""

import ipaddress
import logging
from dataclasses import dataclass, field
from typing import Optional

logger = logging.getLogger(__name__)


@dataclass
class DeviceInfo:
    """Metadata about a single IoT device."""
    ip: str
    role: str = "unknown"          # e.g. sensor, actuator, gateway, camera
    device_type: str = "generic"   # e.g. smart_thermostat, ip_camera
    criticality: str = "medium"    # low | medium | high | critical
    owner: str = "unknown"
    notes: str = ""


class DeviceRegistry:
    """
    In-memory registry of known devices.  Provides fast IP → DeviceInfo
    look-ups for the Incident Manager agent.
    """

    # Default role assignment by subnet (configurable)
    _DEFAULT_SUBNET_ROLES = {
        "192.168.137.0/24": ("iot_device", "medium"),
        "192.168.0.0/16": ("internal_device", "medium"),
        "10.0.0.0/8": ("internal_device", "low"),
        "172.16.0.0/12": ("internal_device", "low"),
    }

    def __init__(self, subnet_roles: dict | None = None):
        self._devices: dict[str, DeviceInfo] = {}
        self._subnet_roles = subnet_roles or self._DEFAULT_SUBNET_ROLES

    # ── Public API ────────────────────────────────────────────────────

    def register(self, ip: str, **kwargs) -> DeviceInfo:
        """Register or update a device entry."""
        if ip in self._devices:
            for k, v in kwargs.items():
                setattr(self._devices[ip], k, v)
        else:
            self._devices[ip] = DeviceInfo(ip=ip, **kwargs)
        return self._devices[ip]

    def lookup(self, ip: str) -> DeviceInfo:
        """
        Look up a device by IP.  If not explicitly registered, infer
        role from subnet and create a default entry.
        """
        if ip in self._devices:
            return self._devices[ip]

        # Infer from subnet
        role, criticality = self._infer_role(ip)
        device = DeviceInfo(ip=ip, role=role, criticality=criticality)
        self._devices[ip] = device
        return device

    def all_devices(self) -> list[DeviceInfo]:
        return list(self._devices.values())

    def summary(self) -> dict:
        """Return a compact summary for the LLM context window."""
        roles = {}
        for d in self._devices.values():
            roles.setdefault(d.role, 0)
            roles[d.role] += 1
        return {
            "total_devices": len(self._devices),
            "role_distribution": roles,
        }

    # ── Bulk loading from dataset ─────────────────────────────────────

    def populate_from_dataframe(self, df, src_col: str = "Src IP", dst_col: str = "Dst IP"):
        """Extract unique IPs from a DataFrame and register them."""
        ips = set()
        if src_col in df.columns:
            ips.update(df[src_col].dropna().unique())
        if dst_col in df.columns:
            ips.update(df[dst_col].dropna().unique())

        for ip in ips:
            if ip not in self._devices:
                self.lookup(ip)  # auto-registers with inferred role

        logger.info("Device registry populated: %d devices", len(self._devices))

    # ── Internal ──────────────────────────────────────────────────────

    def _infer_role(self, ip_str: str) -> tuple[str, str]:
        """Infer (role, criticality) from subnet rules."""
        try:
            addr = ipaddress.ip_address(ip_str)
            for subnet_str, (role, crit) in self._subnet_roles.items():
                if addr in ipaddress.ip_network(subnet_str, strict=False):
                    return role, crit
        except ValueError:
            pass
        return "external_host", "low"
