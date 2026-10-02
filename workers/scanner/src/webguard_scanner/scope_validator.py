"""Target URL and network-scope validation for OpenHuntX WebGuard.

This module prevents the public scanner from being used to access localhost,
private networks, cloud metadata endpoints, reserved networks, or other
prohibited destinations.

DNS and redirect destinations must also be revalidated at connection time.
"""

from __future__ import annotations

import ipaddress
import socket
from dataclasses import dataclass
from enum import Enum
from typing import Callable, FrozenSet, Iterable, Tuple
from urllib.parse import urlsplit, urlunsplit


Resolver = Callable[[str, int], Iterable[str]]


class ValidationMode(str, Enum):
    """Available target-validation policies."""

    COMMERCIAL = "commercial"
    LAB = "lab"


@dataclass(frozen=True)
class ValidationPolicy:
    """Configuration controlling which targets may be accepted."""

    mode: ValidationMode
    allowed_lab_hosts: FrozenSet[str] = frozenset()
    maximum_url_length: int = 2048


@dataclass(frozen=True)
class CanonicalTarget:
    """A target URL parsed and normalised, before any DNS resolution.

    Carries no information about whether the target is reachable or safe to
    connect to -- only validate_target_url's full resolution and address
    classification establishes that. Exists so that checks which only need
    the canonical URL (does this match an authorization's recorded target?
    is the scheme https?) can run before any network activity, without
    duplicating validate_target_url's parsing logic.
    """

    original_url: str
    normalised_url: str
    scheme: str
    hostname: str
    port: int


@dataclass(frozen=True)
class ValidatedTarget:
    """Normalised target returned after successful validation."""

    original_url: str
    normalised_url: str
    scheme: str
    hostname: str
    port: int
    resolved_addresses: Tuple[str, ...]


class TargetValidationError(ValueError):
    """Controlled target-validation failure."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


def resolve_host(hostname: str, port: int) -> Tuple[str, ...]:
    """Resolve a hostname into unique IPv4 and IPv6 addresses."""

    try:
        literal = ipaddress.ip_address(hostname)
        return (literal.compressed,)
    except ValueError:
        pass

    try:
        records = socket.getaddrinfo(
            hostname,
            port,
            family=socket.AF_UNSPEC,
            type=socket.SOCK_STREAM,
        )
    except socket.gaierror as exc:
        raise TargetValidationError(
            "dns_resolution_failed",
            f"DNS resolution failed for {hostname!r}.",
        ) from exc

    addresses = {
        record[4][0].split("%", maxsplit=1)[0]
        for record in records
        if record[4]
    }

    if not addresses:
        raise TargetValidationError(
            "dns_no_addresses",
            f"DNS returned no usable addresses for {hostname!r}.",
        )

    return tuple(sorted(addresses))


def _normalise_hostname(hostname: str) -> str:
    """Return a canonical IP address or IDNA hostname."""

    candidate = hostname.strip().rstrip(".")

    if not candidate:
        raise TargetValidationError(
            "hostname_missing",
            "The target URL does not contain a hostname.",
        )

    if "%" in candidate:
        raise TargetValidationError(
            "ipv6_zone_not_allowed",
            "IPv6 zone identifiers are not allowed.",
        )

    try:
        return ipaddress.ip_address(candidate).compressed
    except ValueError:
        pass

    try:
        ascii_hostname = candidate.encode("idna").decode("ascii").lower()
    except UnicodeError as exc:
        raise TargetValidationError(
            "hostname_invalid",
            "The hostname is not valid.",
        ) from exc

    if len(ascii_hostname) > 253:
        raise TargetValidationError(
            "hostname_too_long",
            "The hostname exceeds 253 characters.",
        )

    for label in ascii_hostname.split("."):
        if not label:
            raise TargetValidationError(
                "hostname_invalid",
                "The hostname contains an empty DNS label.",
            )

        if len(label) > 63:
            raise TargetValidationError(
                "hostname_label_too_long",
                "A hostname label exceeds 63 characters.",
            )

        if label.startswith("-") or label.endswith("-"):
            raise TargetValidationError(
                "hostname_invalid",
                "A hostname label cannot begin or end with a hyphen.",
            )

        if not all(character.isalnum() or character == "-" for character in label):
            raise TargetValidationError(
                "hostname_invalid",
                "The hostname contains invalid characters.",
            )

    return ascii_hostname


def _classification_address(
    address: ipaddress.IPv4Address | ipaddress.IPv6Address,
) -> ipaddress.IPv4Address | ipaddress.IPv6Address:
    """Extract an embedded IPv4 address from IPv4-mapped IPv6."""

    if isinstance(address, ipaddress.IPv6Address):
        if address.ipv4_mapped is not None:
            return address.ipv4_mapped

    return address


def _parse_address(
    address_text: str,
) -> tuple[
    ipaddress.IPv4Address | ipaddress.IPv6Address,
    ipaddress.IPv4Address | ipaddress.IPv6Address,
]:
    """Parse and classify a DNS-provided address."""

    try:
        original = ipaddress.ip_address(address_text)
    except ValueError as exc:
        raise TargetValidationError(
            "dns_invalid_address",
            f"DNS returned an invalid address: {address_text!r}.",
        ) from exc

    return original, _classification_address(original)


def _validate_commercial_address(address_text: str) -> str:
    """Require a globally routable public address."""

    original, classified = _parse_address(address_text)

    if (
        not classified.is_global
        or classified.is_private
        or classified.is_loopback
        or classified.is_link_local
        or classified.is_multicast
        or classified.is_reserved
        or classified.is_unspecified
    ):
        raise TargetValidationError(
            "non_public_address",
            f"Commercial scans cannot target {address_text!r}.",
        )

    return original.compressed


def _validate_lab_address(address_text: str) -> str:
    """Allow only private or loopback addresses in laboratory mode."""

    original, classified = _parse_address(address_text)

    if (
        classified.is_link_local
        or classified.is_multicast
        or classified.is_reserved
        or classified.is_unspecified
    ):
        raise TargetValidationError(
            "unsafe_lab_address",
            f"The laboratory address {address_text!r} is prohibited.",
        )

    if not (classified.is_private or classified.is_loopback):
        raise TargetValidationError(
            "public_lab_address",
            "Laboratory mode cannot target public addresses.",
        )

    return original.compressed


def _format_netloc(hostname: str, port: int, scheme: str) -> str:
    """Build a canonical URL authority without credentials."""

    try:
        address = ipaddress.ip_address(hostname)
        formatted_host = (
            f"[{hostname}]"
            if isinstance(address, ipaddress.IPv6Address)
            else hostname
        )
    except ValueError:
        formatted_host = hostname

    default_port = 443 if scheme == "https" else 80

    if port == default_port:
        return formatted_host

    return f"{formatted_host}:{port}"


def canonicalize_target_url(
    url: str,
    policy: ValidationPolicy,
) -> CanonicalTarget:
    """Parse and normalise a target URL without resolving or connecting to it.

    This performs no DNS lookup and no network activity of any kind. It
    exists so that authorization checks which only need the canonical URL
    string (malformed input, scheme, an authorization's recorded target,
    its host allowlist) can reject a scan before validate_target_url's own
    resolver call ever runs. It does not establish that the target is safe
    to connect to -- validate_target_url's resolution and address
    classification is still the sole gate before any actual connection, and
    still must run and still must pass before that connection is made.
    """

    if not isinstance(url, str):
        raise TargetValidationError(
            "url_type_invalid",
            "The target URL must be a string.",
        )

    candidate = url.strip()

    if not candidate:
        raise TargetValidationError(
            "url_empty",
            "The target URL cannot be empty.",
        )

    if len(candidate) > policy.maximum_url_length:
        raise TargetValidationError(
            "url_too_long",
            "The target URL exceeds the maximum permitted length.",
        )

    if "\\" in candidate:
        raise TargetValidationError(
            "backslash_not_allowed",
            "Backslashes are not allowed in target URLs.",
        )

    if any(ord(character) < 32 or ord(character) == 127 for character in candidate):
        raise TargetValidationError(
            "control_character_not_allowed",
            "Control characters are not allowed in target URLs.",
        )

    try:
        parsed = urlsplit(candidate)
    except ValueError as exc:
        raise TargetValidationError(
            "url_invalid",
            "The target URL is malformed.",
        ) from exc

    scheme = parsed.scheme.lower()

    if scheme not in {"http", "https"}:
        raise TargetValidationError(
            "scheme_not_allowed",
            "Only HTTP and HTTPS targets are supported.",
        )

    if parsed.username is not None or parsed.password is not None:
        raise TargetValidationError(
            "credentials_not_allowed",
            "Credentials cannot be embedded in target URLs.",
        )

    if parsed.query:
        raise TargetValidationError(
            "query_not_allowed",
            "Registered target URLs cannot contain query strings.",
        )

    if parsed.fragment:
        raise TargetValidationError(
            "fragment_not_allowed",
            "Registered target URLs cannot contain fragments.",
        )

    if parsed.hostname is None:
        raise TargetValidationError(
            "hostname_missing",
            "The target URL does not contain a hostname.",
        )

    hostname = _normalise_hostname(parsed.hostname)

    try:
        port = parsed.port
    except ValueError as exc:
        raise TargetValidationError(
            "port_invalid",
            "The target URL contains an invalid port.",
        ) from exc

    if port is None:
        port = 443 if scheme == "https" else 80

    path = parsed.path or "/"

    normalised_url = urlunsplit(
        (
            scheme,
            _format_netloc(hostname, port, scheme),
            path,
            "",
            "",
        )
    )

    return CanonicalTarget(
        original_url=candidate,
        normalised_url=normalised_url,
        scheme=scheme,
        hostname=hostname,
        port=port,
    )


def validate_target_url(
    url: str,
    policy: ValidationPolicy,
    resolver: Resolver = resolve_host,
) -> ValidatedTarget:
    """Validate, resolve and normalise a target URL.

    The resolved addresses must still be enforced when the scanner opens the
    connection. Redirect destinations must be independently revalidated.
    """

    canonical = canonicalize_target_url(url, policy)
    hostname = canonical.hostname
    port = canonical.port

    try:
        raw_addresses = tuple(resolver(hostname, port))
    except TargetValidationError:
        raise
    except OSError as exc:
        raise TargetValidationError(
            "dns_resolution_failed",
            f"DNS resolution failed for {hostname!r}.",
        ) from exc

    if not raw_addresses:
        raise TargetValidationError(
            "dns_no_addresses",
            f"DNS returned no usable addresses for {hostname!r}.",
        )

    if policy.mode is ValidationMode.COMMERCIAL:
        validated_addresses = tuple(
            sorted(
                {
                    _validate_commercial_address(address)
                    for address in raw_addresses
                }
            )
        )

    elif policy.mode is ValidationMode.LAB:
        allowed_hosts = frozenset(
            _normalise_hostname(host)
            for host in policy.allowed_lab_hosts
        )

        if not allowed_hosts:
            raise TargetValidationError(
                "lab_allowlist_empty",
                "Laboratory mode requires an explicit hostname allowlist.",
            )

        if hostname not in allowed_hosts:
            raise TargetValidationError(
                "lab_host_not_allowed",
                f"The laboratory hostname {hostname!r} is not allowlisted.",
            )

        validated_addresses = tuple(
            sorted(
                {
                    _validate_lab_address(address)
                    for address in raw_addresses
                }
            )
        )

    else:
        raise TargetValidationError(
            "validation_mode_invalid",
            "The selected validation mode is unsupported.",
        )

    return ValidatedTarget(
        original_url=canonical.original_url,
        normalised_url=canonical.normalised_url,
        scheme=canonical.scheme,
        hostname=canonical.hostname,
        port=canonical.port,
        resolved_addresses=validated_addresses,
    )
