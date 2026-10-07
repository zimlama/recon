"""Network + filesystem safety helpers — SSRF defense, filename sanitization.

Used by modules to ensure target IPs are public (not RFC 1918, loopback,
link-local, multicast, reserved). Defense-in-depth for SSRF.

Also provides filename helpers to defend against header-injection / CRLF
attacks when constructing Content-Disposition filenames from user-controlled
fields (e.g. job.target).
"""

from __future__ import annotations

import ipaddress
import re
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


# Allow only filename-safe chars: ASCII letters, digits, dot, underscore, dash.
# Anything else (whitespace, CRLF, '/', '\\', ':', ';', quotes, non-ASCII,
# control chars, etc.) is collapsed to '_'. Cap length to keep the final
# filename within typical filesystem limits and avoid header-bloat attacks.
_FILENAME_SAFE_RE = re.compile(r"[^A-Za-z0-9._-]")
_FILENAME_MAX_LEN = 63


def safe_filename_part(s: str) -> str:
    """Return a filename-safe version of ``s``.

    - Replaces any character outside ``[A-Za-z0-9._-]`` with ``_``.
    - Strips leading/trailing whitespace and dots (defense against ``..``,
      leading-dot hidden files, and stray whitespace in Content-Disposition).
    - Caps the result at 63 chars.
    - Returns ``"unknown"`` if the input is empty or fully stripped.

    Use this whenever you embed user-controlled data (e.g. ``job.target``)
    into a ``Content-Disposition`` filename to prevent CRLF / header
    injection and path traversal via crafted inputs.
    """
    if not isinstance(s, str):
        return "unknown"
    cleaned = _FILENAME_SAFE_RE.sub("_", s).strip().strip(".")
    if not cleaned:
        return "unknown"
    return cleaned[:_FILENAME_MAX_LEN]