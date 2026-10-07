"""IP address validation — SSRF defense.

Used by modules to ensure target IPs are public (not RFC 1918, loopback,
link-local, multicast, reserved). Defense-in-depth for SSRF.
"""

from __future__ import annotations

import ipaddress
from typing import Iterable


# Private / reserved / non-routable ranges (matches handoff schema)
PRIVATE_RANGES = [
    "0.0.0.0/8",          # "this network"
    "10.0.0.0/8",         # RFC 1918 private
    "100.64.0.0/10",      # CGN
    "127.0.0.0/8",        # loopback
    "169.254.0.0/16",     # link-local
    "172.16.0.0/12",      # RFC 1918 private
    "192.0.0.0/24",       # IETF assignments
    "192.0.2.0/24",       # TEST-NET-1
    "192.168.0.0/16",    # RFC 1918 private
    "198.18.0.0/15",      # benchmarking
    "198.51.100.0/24",    # TEST-NET-2
    "203.0.113.0/24",     # TEST-NET-3
    "224.0.0.0/4",        # multicast
    "240.0.0.0/4",        # reserved
    "255.255.255.255/32", # broadcast
    "::1/128",            # IPv6 loopback
    "fc00::/7",           # IPv6 ULA
    "fe80::/10",          # IPv6 link-local
    "ff00::/8",           # IPv6 multicast
]

_PRIVATE_NETS = [ipaddress.ip_network(net) for net in PRIVATE_RANGES]


def is_public_ip(ip_str: str) -> bool:
    """Return True if the IP is public (routable on the internet).

    Returns False for:
    - Invalid IP strings
    - Private (RFC 1918) addresses
    - Loopback, link-local, multicast, reserved
    - IPv6 ULA, link-local, multicast
    """
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return False

    # is_global covers most cases; we also explicitly check for reserved
    if not ip.is_global:
        return False

    # Defense in depth: explicit check against known private ranges
    for net in _PRIVATE_NETS:
        if ip in net:
            return False

    return True


def filter_public_ips(ip_strings: Iterable[str]) -> list[str]:
    """Return only the public (routable) IPs from an iterable of strings."""
    return [ip for ip in ip_strings if is_public_ip(ip)]