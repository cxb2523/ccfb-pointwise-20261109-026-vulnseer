"""SSRF (Server-Side Request Forgery) signature detector.

Three-layer detection model, tuned to keep false positives low while still
catching SSRF hidden behind redirects or DNS rebinding:

  Layer 1 (SSRF-001): a request parameter value matches an SSRF-prone pattern
    (e.g. url=, endpoint=, callback= pointing at a loopback/metadata/internal
    address, or a file:// scheme). A hit here alone is only "suspected" --
    plenty of internal tooling legitimately passes internal URLs around.

  Layer 2 (SSRF-002): the parameter's value is followed through a redirect
    chain (or the response it ultimately produced) to see where the request
    actually lands. If the final hop is still inside an internal/metadata
    range, the finding is upgraded to "confirmed" -- this is what catches
    SSRF that uses an allow-listed redirector to reach an internal target.

  Layer 3 (SSRF-003): DNS rebinding. When the host in the parameter is a
    domain name rather than a literal IP, the caller supplies the resolved
    IP(s) (resolved_ips). A domain can look "external" lexically yet resolve
    to an internal/metadata address -- if any resolved IP is internal, this
    is confirmed with bypass_type="dns_rebinding".

All three layers reuse the exact same internal-CIDR classification function
(`is_internal_address`) so a future change to the internal/metadata ranges
only has to happen in one place.
"""

import ipaddress
import re
from typing import Dict, List, Optional
from urllib.parse import urlparse

from detectors import Finding

# Cloud metadata endpoints that are not covered by RFC1918 but are just as
# dangerous as an SSRF target (AWS/GCP/Azure/Alibaba instance metadata, etc).
METADATA_ADDRESSES = {
    "169.254.169.254",
    "fd00:ec2::254",
}

# Keys whose values commonly carry a caller-supplied URL and are therefore
# the classic SSRF injection point.
SSRF_PARAM_KEYS = re.compile(r"(url|endpoint|callback|target|uri|src|path|dest|redirect)$", re.IGNORECASE)

# Matches http(s):// or file:// URLs embedded in a parameter value.
URL_PATTERN = re.compile(r"(https?|file)://([^\s'\"<>]*)", re.IGNORECASE)


def is_internal_address(host: str) -> bool:
    """Single source of truth for "is this host internal/metadata/loopback".

    Used by all three detection layers so the internal CIDR rules never
    drift out of sync between them.
    """
    if not host:
        return False

    if host in METADATA_ADDRESSES:
        return True

    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return False

    return (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_reserved
        or ip.is_multicast
    )


def _extract_host(url: str) -> Optional[str]:
    """Pull the host portion out of a URL, stripping brackets from IPv6 literals."""
    try:
        parsed = urlparse(url)
    except ValueError:
        return None

    host = parsed.hostname
    if host:
        return host

    # file:// URLs with no netloc (file:///etc/passwd) -- treat as internal,
    # since local file access from a server-side fetcher is SSRF-equivalent.
    if parsed.scheme == "file":
        return "127.0.0.1"

    return None


def _is_domain(host: str) -> bool:
    """True if host is a hostname rather than a literal IP address."""
    try:
        ipaddress.ip_address(host)
        return False
    except ValueError:
        return True


class SSRFDetector:
    """Detects SSRF-prone parameters, confirming via redirect-chain and DNS-rebinding checks."""

    def scan(self, request_data: Dict) -> List[Finding]:
        findings: List[Finding] = []

        host = request_data.get("host", "")
        params = request_data.get("params", {}) or {}
        redirect_chain = request_data.get("redirect_chain") or []
        resolved_ips = request_data.get("resolved_ips") or []

        for param_name, param_value in params.items():
            if not isinstance(param_value, str):
                continue

            hit = self._match_ssrf_pattern(param_name, param_value)
            if not hit:
                continue

            candidate_host, candidate_url, layer1_hit = hit

            # Layer 2: follow the (caller-supplied, simulated) redirect
            # chain to see where the request actually lands. Only applies
            # when a redirect chain was actually provided -- absence of a
            # redirect chain is not evidence of anything, and must not be
            # treated as "the target itself is the final hop" or every
            # layer-1 hit would be silently upgraded to confirmed.
            if redirect_chain:
                final_host = self._final_hop_host(redirect_chain)
                if final_host and is_internal_address(final_host):
                    findings.append(Finding(
                        rule_id="SSRF-002",
                        severity="High",
                        status="confirmed",
                        host=host,
                        evidence=f"param '{param_name}'={param_value} redirects to internal host {final_host}",
                        description="Request parameter follows a redirect chain that lands on an internal/metadata address.",
                    ))
                    continue

            # Layer 3: DNS rebinding. The parameter's host is a domain name,
            # not an IP literal -- lexical inspection can't tell us where it
            # really resolves, so trust the caller-supplied resolution.
            if _is_domain(candidate_host) and resolved_ips:
                internal_hits = [ip for ip in resolved_ips if is_internal_address(ip)]
                if internal_hits:
                    findings.append(Finding(
                        rule_id="SSRF-003",
                        severity="High",
                        status="confirmed",
                        host=host,
                        evidence=f"param '{param_name}'={param_value} resolves to internal IP(s) {internal_hits}",
                        description="Domain in request parameter resolves to an internal/metadata address (DNS rebinding).",
                        bypass_type="dns_rebinding",
                    ))
                    continue

            # Layer 1 only: pattern matched but neither redirect-chain nor
            # DNS-rebinding evidence confirmed it lands internally. A
            # lexically-external domain with no follow-up evidence at all
            # is not flagged -- that would just be noise on every ordinary
            # url= parameter.
            if layer1_hit:
                findings.append(Finding(
                    rule_id="SSRF-001",
                    severity="Medium",
                    status="suspected",
                    host=host,
                    evidence=f"param '{param_name}'={param_value} matches SSRF-prone pattern",
                    description="Request parameter value points at an internal/metadata address or uses a dangerous scheme.",
                ))

        return findings

    def _match_ssrf_pattern(self, param_name: str, param_value: str):
        """Layer 1: does this parameter look SSRF-prone?

        Returns (host, url, is_resolved_target) if the value embeds a URL
        whose host is already internal/metadata, or uses file://. A plain
        external-looking domain is NOT flagged by itself -- that would make
        every ordinary url= parameter a false positive. Domains only become
        interesting together with layer 2 (redirect_chain) or layer 3
        (resolved_ips) evidence, which the caller supplies separately.
        Returns None if nothing SSRF-prone is visible in the value alone.
        """
        match = URL_PATTERN.search(param_value)
        if not match:
            return None

        url = match.group(0)
        scheme = match.group(1).lower()
        host = _extract_host(url)

        if scheme == "file":
            return ("127.0.0.1", url, True)

        if not host:
            return None

        if is_internal_address(host):
            # Internal/metadata target -- flag regardless of parameter name,
            # since an internal literal is dangerous no matter what it's
            # called.
            return (host, url, True)

        if _is_domain(host) and SSRF_PARAM_KEYS.search(param_name):
            # Lexically external domain behind a classic SSRF-sink parameter
            # name -- only worth returning as a candidate so layers 2/3 can
            # check follow-up evidence; it is NOT a layer-1 hit by itself.
            # Requiring a sink-shaped name here keeps ordinary third-party
            # domains out of unrelated parameters from being considered at
            # all.
            return (host, url, False)

        return None

    def _final_hop_host(self, redirect_chain: List[str]) -> Optional[str]:
        """Layer 2: resolve the final hop of a (possibly simulated) redirect chain."""
        last_hop = redirect_chain[-1]
        return _extract_host(last_hop) or last_hop
