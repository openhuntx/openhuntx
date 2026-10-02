"""Connection-time HTTP safety controls for OpenHuntX WebGuard."""

from __future__ import annotations

import errno
import hashlib
import http.client
import ipaddress
import re
import socket
import ssl
import threading
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import FrozenSet, Iterable, Tuple
from urllib.parse import quote, urlsplit

from .scope_validator import ValidatedTarget


@dataclass(frozen=True)
class FetchPolicy:
    """Limits applied to one HTTP request."""

    timeout_seconds: float = 10.0
    maximum_body_bytes: int = 1_048_576
    maximum_header_bytes: int = 65_536
    maximum_header_count: int = 100
    allowed_methods: FrozenSet[str] = frozenset({"GET", "HEAD"})
    maximum_request_body_bytes: int = 65_536


@dataclass(frozen=True, slots=True)
class TlsConnectionInfo:
    """Bounded non-secret metadata from one verified TLS connection."""

    protocol: str
    cipher_name: str
    cipher_bits: int
    server_hostname: str
    certificate_not_before: datetime
    certificate_not_after: datetime
    certificate_sha256: str
    subject_alt_names: Tuple[str, ...]
    certificate_verified: bool
    hostname_validated: bool
    verified_chain_length: int | None = None


@dataclass(frozen=True)
class SafeHttpResponse:
    """Bounded HTTP response returned by the safe client."""

    status: int
    reason: str
    headers: Tuple[Tuple[str, str], ...]
    body: bytes
    connected_address: str
    elapsed_milliseconds: int
    tls: TlsConnectionInfo | None = None


_FORBIDDEN_REQUEST_HEADERS = frozenset(
    {
        "host",
        "content-length",
        "transfer-encoding",
        "connection",
        "forwarded",
        "x-forwarded-host",
        "x-forwarded-for",
    }
)


class SafeRequestError(RuntimeError):
    """Controlled failure raised by the safe HTTP client."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message




_MAXIMUM_TLS_NAME_ENTRIES = 256
_MAXIMUM_TLS_NAME_LENGTH = 512
_MAXIMUM_TLS_CHAIN_CERTIFICATES = 32
_MAXIMUM_TLS_TEXT_LENGTH = 256


def _bounded_tls_text(value: object, name: str) -> str:
    if not isinstance(value, str):
        raise SafeRequestError(
            "tls_certificate_metadata_invalid",
            f"TLS {name} metadata is not text.",
        )

    cleaned = value.strip()
    if not cleaned or len(cleaned) > _MAXIMUM_TLS_TEXT_LENGTH:
        raise SafeRequestError(
            "tls_certificate_metadata_invalid",
            f"TLS {name} metadata is missing or too long.",
        )
    return cleaned


def _certificate_time(value: object, name: str) -> datetime:
    text = _bounded_tls_text(value, name)
    try:
        timestamp = ssl.cert_time_to_seconds(text)
    except (TypeError, ValueError) as exc:
        raise SafeRequestError(
            "tls_certificate_metadata_invalid",
            f"TLS certificate {name} is invalid.",
        ) from exc
    return datetime.fromtimestamp(timestamp, timezone.utc)


def _subject_alt_names(certificate: dict[str, object]) -> Tuple[str, ...]:
    raw = certificate.get("subjectAltName", ())
    if not isinstance(raw, (tuple, list)):
        raise SafeRequestError(
            "tls_certificate_metadata_invalid",
            "TLS certificate subjectAltName metadata is invalid.",
        )
    if len(raw) > _MAXIMUM_TLS_NAME_ENTRIES:
        raise SafeRequestError(
            "tls_certificate_metadata_too_large",
            "TLS certificate contains too many subject alternative names.",
        )

    names: list[str] = []
    for item in raw:
        if (
            not isinstance(item, tuple)
            or len(item) != 2
            or not isinstance(item[0], str)
            or not isinstance(item[1], str)
        ):
            raise SafeRequestError(
                "tls_certificate_metadata_invalid",
                "TLS certificate subjectAltName entry is invalid.",
            )
        kind, value = item
        cleaned = value.strip()
        if len(cleaned) > _MAXIMUM_TLS_NAME_LENGTH:
            raise SafeRequestError(
                "tls_certificate_metadata_too_large",
                "TLS certificate subject alternative name is too long.",
            )
        if kind in {"DNS", "IP Address"} and cleaned:
            rendered = f"{kind}:{cleaned}"
            if rendered not in names:
                names.append(rendered)
    return tuple(sorted(names))


def _verified_chain_length(sock: object) -> int | None:
    getter = getattr(sock, "get_verified_chain", None)
    if not callable(getter):
        return None
    try:
        chain = getter()
    except (AttributeError, NotImplementedError, ssl.SSLError):
        return None
    if chain is None:
        return None
    if not isinstance(chain, (tuple, list)):
        raise SafeRequestError(
            "tls_certificate_metadata_invalid",
            "TLS verified-chain metadata is invalid.",
        )
    if len(chain) > _MAXIMUM_TLS_CHAIN_CERTIFICATES:
        raise SafeRequestError(
            "tls_certificate_metadata_too_large",
            "TLS verified chain contains too many certificates.",
        )
    return len(chain)


def _tls_connection_info(
    connection: http.client.HTTPConnection,
    target: ValidatedTarget,
) -> TlsConnectionInfo:
    sock = getattr(connection, "sock", None)
    context = getattr(connection, "_context", None)

    if sock is None or context is None:
        raise SafeRequestError(
            "tls_metadata_unavailable",
            "The verified TLS socket metadata is unavailable.",
        )

    certificate_verified = (
        getattr(context, "verify_mode", None) == ssl.CERT_REQUIRED
    )
    hostname_validated = bool(
        getattr(context, "check_hostname", False)
    )
    if not certificate_verified or not hostname_validated:
        raise SafeRequestError(
            "tls_context_insecure",
            "The HTTPS connection did not enforce certificate and hostname "
            "verification.",
        )

    try:
        certificate = sock.getpeercert(binary_form=False)
        certificate_der = sock.getpeercert(binary_form=True)
        protocol = sock.version()
        cipher = sock.cipher()
    except (AttributeError, OSError, ssl.SSLError) as exc:
        raise SafeRequestError(
            "tls_metadata_unavailable",
            "Unable to read verified TLS connection metadata.",
        ) from exc

    if not isinstance(certificate, dict) or not certificate:
        raise SafeRequestError(
            "tls_certificate_metadata_invalid",
            "The peer certificate metadata is unavailable.",
        )
    if not isinstance(certificate_der, bytes) or not certificate_der:
        raise SafeRequestError(
            "tls_certificate_metadata_invalid",
            "The peer certificate DER data is unavailable.",
        )
    if (
        not isinstance(cipher, tuple)
        or len(cipher) != 3
        or isinstance(cipher[2], bool)
        or not isinstance(cipher[2], int)
        or cipher[2] < 0
    ):
        raise SafeRequestError(
            "tls_certificate_metadata_invalid",
            "The negotiated TLS cipher metadata is invalid.",
        )

    return TlsConnectionInfo(
        protocol=_bounded_tls_text(protocol, "protocol"),
        cipher_name=_bounded_tls_text(cipher[0], "cipher"),
        cipher_bits=cipher[2],
        server_hostname=target.hostname,
        certificate_not_before=_certificate_time(
            certificate.get("notBefore"),
            "notBefore",
        ),
        certificate_not_after=_certificate_time(
            certificate.get("notAfter"),
            "notAfter",
        ),
        certificate_sha256=hashlib.sha256(certificate_der).hexdigest(),
        subject_alt_names=_subject_alt_names(certificate),
        certificate_verified=True,
        hostname_validated=True,
        verified_chain_length=_verified_chain_length(sock),
    )


class _BoundedChunkHTTPResponse(http.client.HTTPResponse):
    """Rejects a negative chunked-transfer chunk size.

    ``http.client``'s own chunk-size parser (``int(line, 16)``) accepts a
    leading ``-``. A malformed or hostile chunk size of ``-1`` (or any
    negative value) then reaches ``_safe_read(chunk_left)``, which calls
    ``fp.read(chunk_left)``: a negative size means "read until EOF" in
    Python's file-read convention. That single internal read bypasses
    every bound this module places on a response: `_read_bounded_body`
    asks for at most 65536 bytes at a time specifically so its own
    running total can be checked against ``maximum_body_bytes`` between
    reads, but a negative chunk size is read in one call regardless of
    the amount requested, before that check ever runs again. Rejecting a
    negative chunk size here, at the one place it is parsed, closes that
    gap without depending on how much any caller asks to read.
    """

    def _read_next_chunk_size(self) -> int:
        size = super()._read_next_chunk_size()
        if size < 0:
            self.close()
            raise http.client.HTTPException(
                "Invalid negative chunk size in chunked response."
            )
        return size


class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    """HTTPS connection pinned to an approved IP address.

    The socket connects directly to connect_address while TLS certificate
    validation and SNI continue to use server_hostname.
    """

    response_class = _BoundedChunkHTTPResponse

    def __init__(
        self,
        connect_address: str,
        server_hostname: str,
        port: int,
        timeout: float,
        context: ssl.SSLContext,
    ) -> None:
        super().__init__(
            host=server_hostname,
            port=port,
            timeout=timeout,
            context=context,
        )

        self._connect_address = connect_address
        self._server_hostname = server_hostname

    def connect(self) -> None:
        if self._tunnel_host is not None:
            raise SafeRequestError(
                "proxy_tunnel_not_allowed",
                "Proxy tunnels are not supported.",
            )

        raw_socket = socket.create_connection(
            (self._connect_address, self.port),
            self.timeout,
            self.source_address,
        )

        try:
            raw_socket.setsockopt(
                socket.IPPROTO_TCP,
                socket.TCP_NODELAY,
                1,
            )
        except OSError:
            pass

        try:
            self.sock = self._context.wrap_socket(
                raw_socket,
                server_hostname=self._server_hostname,
            )
        except BaseException:
            raw_socket.close()
            raise


def _validate_policy(policy: FetchPolicy) -> None:
    if policy.timeout_seconds <= 0:
        raise SafeRequestError(
            "timeout_invalid",
            "The request timeout must be greater than zero.",
        )

    if policy.maximum_body_bytes < 0:
        raise SafeRequestError(
            "body_limit_invalid",
            "The response-body limit cannot be negative.",
        )

    if policy.maximum_header_bytes <= 0:
        raise SafeRequestError(
            "header_limit_invalid",
            "The response-header limit must be greater than zero.",
        )

    if policy.maximum_header_count <= 0:
        raise SafeRequestError(
            "header_count_invalid",
            "The response header-count limit must be greater than zero.",
        )

    if policy.maximum_request_body_bytes < 0:
        raise SafeRequestError(
            "request_body_limit_invalid",
            "The request-body limit cannot be negative.",
        )


def _canonical_addresses(
    addresses: Iterable[str],
) -> Tuple[str, ...]:
    canonical: list[str] = []

    for address_text in addresses:
        try:
            address = ipaddress.ip_address(address_text)
        except ValueError as exc:
            raise SafeRequestError(
                "validated_address_invalid",
                f"Invalid approved address {address_text!r}.",
            ) from exc

        compressed = address.compressed

        if compressed not in canonical:
            canonical.append(compressed)

    if not canonical:
        raise SafeRequestError(
            "validated_addresses_empty",
            "The validated target has no approved addresses.",
        )

    return tuple(canonical)


def _authority(
    hostname: str,
    port: int,
    scheme: str,
) -> str:
    try:
        address = ipaddress.ip_address(hostname)

        formatted_hostname = (
            f"[{hostname}]"
            if isinstance(address, ipaddress.IPv6Address)
            else hostname
        )
    except ValueError:
        formatted_hostname = hostname

    default_port = 443 if scheme == "https" else 80

    if port == default_port:
        return formatted_hostname

    return f"{formatted_hostname}:{port}"


def _request_path(target: ValidatedTarget) -> str:
    parsed = urlsplit(target.normalised_url)

    parsed_port = parsed.port

    if parsed_port is None:
        parsed_port = 443 if parsed.scheme == "https" else 80

    if (
        parsed.scheme != target.scheme
        or parsed.hostname != target.hostname
        or parsed_port != target.port
    ):
        raise SafeRequestError(
            "validated_target_mismatch",
            "The validated fields do not match the normalised URL.",
        )

    if parsed.fragment:
        raise SafeRequestError(
            "fragment_not_allowed",
            "URL fragments cannot be sent in HTTP requests.",
        )

    path = parsed.path or "/"

    if parsed.query:
        path = f"{path}?{parsed.query}"

    # P6-003: a discovered link can carry a literal non-ASCII character
    # (e.g. an unescaped path segment) straight through urlsplit, which
    # does no encoding of its own. http.client's putrequest() encodes
    # the request line as strict ASCII and raises UnicodeEncodeError on
    # anything else -- uncontrolled, and for a crawl resuming from a
    # checkpoint that already queued this exact URL, permanent: every
    # resume attempt hits the same page and crashes identically. `%` is
    # kept safe so an already-percent-encoded sequence is not
    # double-escaped; the rest of the safe set is RFC 3986's own
    # path/query reserved characters, left as-is.
    return quote(path, safe="!#$%&'()*+,/:;=?@[]~._-")


def _make_connection(
    target: ValidatedTarget,
    address: str,
    policy: FetchPolicy,
) -> http.client.HTTPConnection:
    if target.scheme == "http":
        connection = http.client.HTTPConnection(
            host=address,
            port=target.port,
            timeout=policy.timeout_seconds,
        )
        # Instance override, not a subclass: HTTPConnection has no other
        # customisation point needed here, and response_class is exactly
        # the documented per-instance extension http.client provides for
        # this (see _BoundedChunkHTTPResponse's own docstring for why).
        connection.response_class = _BoundedChunkHTTPResponse
        return connection

    if target.scheme == "https":
        return _PinnedHTTPSConnection(
            connect_address=address,
            server_hostname=target.hostname,
            port=target.port,
            timeout=policy.timeout_seconds,
            context=ssl.create_default_context(),
        )

    raise SafeRequestError(
        "scheme_not_allowed",
        "Only HTTP and HTTPS requests are supported.",
    )


def _header_size(
    headers: Tuple[Tuple[str, str], ...],
    reason: str,
) -> int:
    status_line_size = (
        len(reason.encode("latin-1", errors="replace")) + 16
    )

    fields_size = sum(
        len(name.encode("latin-1", errors="replace"))
        + len(value.encode("latin-1", errors="replace"))
        + 4
        for name, value in headers
    )

    return status_line_size + fields_size + 2


_CONTENT_LENGTH_TOKEN = re.compile(r"[0-9]{1,20}")


def _declared_content_length(
    response: http.client.HTTPResponse,
) -> int | None:
    values = response.msg.get_all("Content-Length", [])

    if not values:
        return None

    tokens: list[str] = []

    for value in values:
        tokens.extend(
            part.strip()
            for part in value.split(",")
        )

    # str.isdigit() accepts Unicode decimal-digit characters (e.g. the
    # superscript "\xb2") that int() cannot parse in base 10, and places
    # no bound on length: a long enough all-ASCII-digit token exceeds
    # Python's own integer-string-conversion limit, which int() reports
    # by raising ValueError. Either shape used to reach int() directly
    # below and escape as an uncontrolled exception. A strict, bounded
    # ASCII pattern rejects both before int() is ever called.
    if not tokens or any(
        _CONTENT_LENGTH_TOKEN.fullmatch(token) is None
        for token in tokens
    ):
        raise SafeRequestError(
            "content_length_invalid",
            "The server returned an invalid Content-Length.",
        )

    lengths = {
        int(token)
        for token in tokens
    }

    if len(lengths) != 1:
        raise SafeRequestError(
            "content_length_ambiguous",
            "The server returned conflicting Content-Length values.",
        )

    return lengths.pop()


def _read_bounded_body(
    response: http.client.HTTPResponse,
    maximum_body_bytes: int,
) -> bytes:
    declared_length = _declared_content_length(response)

    if (
        declared_length is not None
        and declared_length > maximum_body_bytes
    ):
        raise SafeRequestError(
            "response_body_too_large",
            "The declared response body exceeds the limit.",
        )

    chunks: list[bytes] = []
    total = 0

    while True:
        remaining_probe = maximum_body_bytes + 1 - total
        if remaining_probe <= 0:
            raise SafeRequestError(
                "response_body_too_large",
                "The response body exceeds the configured limit.",
            )

        chunk = response.read(
            min(65_536, remaining_probe)
        )

        if not chunk:
            break

        total += len(chunk)

        if total > maximum_body_bytes:
            raise SafeRequestError(
                "response_body_too_large",
                "The response body exceeds the configured limit.",
            )

        chunks.append(chunk)

    return b"".join(chunks)


def _perform_request(
    target: ValidatedTarget,
    address: str,
    method: str,
    path: str,
    policy: FetchPolicy,
    *,
    body: bytes = b"",
    content_type: str = "",
    extra_headers: Tuple[Tuple[str, str], ...] = (),
    allow_redirect_status: bool = False,
) -> SafeHttpResponse:
    connection = _make_connection(
        target,
        address,
        policy,
    )

    started = time.monotonic()
    request_sent = False

    # policy.timeout_seconds otherwise only bounds each individual socket
    # operation (connect, one recv). A server that drips a byte just
    # under that timeout -- either in the body, or as an endless stream
    # of 1xx interim responses inside http.client's own internal read
    # loop -- can stall this call far longer than the configured timeout
    # without any single operation ever timing out on its own. This
    # watchdog force-interrupts the connection once the *whole* request
    # has run past the deadline, regardless of which blocking call it is
    # stuck in. shutdown(), not close(): closing the fd from this thread
    # while the main thread may be blocked in a read on it risks the fd
    # number being reused before that read notices; shutdown() safely
    # wakes a blocked read with EOF without invalidating the fd.
    completed = threading.Event()
    deadline_exceeded = threading.Event()

    def _enforce_deadline() -> None:
        if not completed.wait(policy.timeout_seconds):
            deadline_exceeded.set()
            sock = getattr(connection, "sock", None)
            if sock is not None:
                try:
                    sock.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass

    watchdog = threading.Thread(target=_enforce_deadline, daemon=True)
    watchdog.start()

    try:
        connection.putrequest(
            method,
            path,
            skip_host=True,
            skip_accept_encoding=True,
        )

        connection.putheader(
            "Host",
            _authority(
                target.hostname,
                target.port,
                target.scheme,
            ),
        )
        connection.putheader(
            "User-Agent",
            "OpenHuntX-WebGuard/0.1",
        )
        connection.putheader("Accept", "*/*")
        connection.putheader(
            "Accept-Encoding",
            "identity",
        )
        if body:
            connection.putheader(
                "Content-Type",
                content_type or "application/octet-stream",
            )
            connection.putheader("Content-Length", str(len(body)))
        # extra_headers is validated against _FORBIDDEN_REQUEST_HEADERS by
        # fetch_once before this function is ever called -- re-checked
        # here too as defense in depth, since this is the layer that
        # actually writes bytes onto the wire.
        for name, value in extra_headers:
            if name.lower() in _FORBIDDEN_REQUEST_HEADERS:
                raise SafeRequestError(
                    "forbidden_request_header",
                    f"Header {name!r} cannot be set through extra_headers.",
                )
            connection.putheader(name, value)
        connection.putheader(
            "Connection",
            "close",
        )
        # Calling endheaders() with zero arguments when there is no body
        # is deliberately preserved byte-for-byte from before request
        # bodies existed -- every existing fake connection in the test
        # suite implements endheaders(self) with no parameters, and this
        # keeps every GET/HEAD-only code path (the only paths those fakes
        # exercise) calling it exactly as before.
        if body:
            connection.endheaders(body)
        else:
            connection.endheaders()
        # fetch_once's caller invokes its before_request/after_request
        # safety hooks (rate limiting, permit-attempt budget, circuit
        # breaker) exactly once per fetch_once call, regardless of how
        # many resolved addresses it tries below. Once the full request
        # has actually gone out over the wire, any further failure is a
        # failure of *this* accounted attempt, not grounds to silently
        # send a second real request to another address under the same
        # accounting.
        request_sent = True
        tls = (
            _tls_connection_info(connection, target)
            if target.scheme == "https"
            else None
        )

        response = connection.getresponse()
        reason = response.reason or ""
        headers = tuple(response.getheaders())

        if len(headers) > policy.maximum_header_count:
            raise SafeRequestError(
                "response_headers_too_many",
                "The response contains too many headers.",
            )

        if (
            _header_size(headers, reason)
            > policy.maximum_header_bytes
        ):
            raise SafeRequestError(
                "response_headers_too_large",
                "The response headers exceed the limit.",
            )

        if not 100 <= response.status <= 599:
            # http.client parses any digits on the status line into an int
            # with no range check; RequestAttempt's own contract only
            # accepts 100-599, but rejects it after this request has
            # already been sent and counted -- reject it here instead so
            # it never reaches that later, already-committed contract.
            raise SafeRequestError(
                "response_status_invalid",
                "The response has an invalid HTTP status code.",
            )

        if (
            300 <= response.status < 400
            and response.status != 304
            and not allow_redirect_status
        ):
            raise SafeRequestError(
                "redirect_blocked",
                "Automatic redirect following is disabled.",
            )

        body = (
            b""
            if method == "HEAD"
            else _read_bounded_body(
                response,
                policy.maximum_body_bytes,
            )
        )

        if deadline_exceeded.is_set():
            # The watchdog's shutdown() interrupted a blocking read, but
            # for a plain Content-Length response (unlike chunked)
            # http.client's own read() does not raise on a short read at
            # EOF -- it just returns what it already had, so a silently
            # truncated body would otherwise look like a complete,
            # successful response.
            raise SafeRequestError(
                "request_deadline_exceeded",
                "The request exceeded the configured time limit.",
            )

        elapsed = int(
            (time.monotonic() - started) * 1000
        )

        return SafeHttpResponse(
            status=response.status,
            reason=reason,
            headers=headers,
            body=body,
            connected_address=address,
            elapsed_milliseconds=elapsed,
            tls=tls,
        )
    except (OSError, ssl.SSLError, http.client.HTTPException) as exc:
        if deadline_exceeded.is_set():
            raise SafeRequestError(
                "request_deadline_exceeded",
                "The request exceeded the configured time limit.",
            ) from exc
        exc.webguard_request_sent = request_sent
        raise
    finally:
        completed.set()
        try:
            connection.close()
        except (
            OSError,
            ssl.SSLError,
            http.client.HTTPException,
        ):
            # A cleanup-time failure must never replace the try block's
            # outcome (a returned response or an already-raised error).
            # The socket is being discarded either way.
            pass

@dataclass(frozen=True)
class _ConnectionFailure:
    """One bounded failure observed for an approved address."""

    address: str
    code: str
    exception_name: str


_RETRYABLE_CONNECTION_CODES = frozenset(
    {
        "connection_timeout",
        "connection_refused",
        "connection_interrupted",
        "network_unreachable",
        "connection_failed",
    }
)

_INTERRUPTED_ERRNOS = frozenset(
    value
    for name in (
        "ECONNRESET",
        "ECONNABORTED",
        "EPIPE",
    )
    if (value := getattr(errno, name, None)) is not None
)

_UNREACHABLE_ERRNOS = frozenset(
    value
    for name in (
        "ENETUNREACH",
        "EHOSTUNREACH",
        "ENETDOWN",
        "EHOSTDOWN",
    )
    if (value := getattr(errno, name, None)) is not None
)


def _connection_error_code(
    exc: BaseException,
) -> str:
    """Map a transport exception to a stable controlled error code."""

    if isinstance(exc, ssl.SSLCertVerificationError):
        return "tls_certificate_invalid"

    if isinstance(exc, ssl.SSLError):
        return "tls_handshake_failed"

    if isinstance(exc, (socket.timeout, TimeoutError)):
        return "connection_timeout"

    if isinstance(exc, ConnectionRefusedError):
        return "connection_refused"

    if isinstance(
        exc,
        (
            ConnectionResetError,
            ConnectionAbortedError,
            BrokenPipeError,
        ),
    ):
        return "connection_interrupted"

    if isinstance(exc, http.client.HTTPException):
        return "http_protocol_error"

    if isinstance(exc, OSError):
        if exc.errno == errno.ECONNREFUSED:
            return "connection_refused"

        if exc.errno == errno.ETIMEDOUT:
            return "connection_timeout"

        if exc.errno in _INTERRUPTED_ERRNOS:
            return "connection_interrupted"

        if exc.errno in _UNREACHABLE_ERRNOS:
            return "network_unreachable"

        return "connection_failed"

    return "connection_failed_mixed"


def _aggregate_connection_error_code(
    failures: tuple[_ConnectionFailure, ...],
) -> str:
    """Return one conservative code for all approved-address failures."""

    codes = {
        failure.code
        for failure in failures
    }

    if len(codes) == 1:
        return next(iter(codes))

    if codes and codes.issubset(
        _RETRYABLE_CONNECTION_CODES
    ):
        return "connection_failed"

    return "connection_failed_mixed"


def fetch_once(
    target: ValidatedTarget,
    method: str = "GET",
    policy: FetchPolicy = FetchPolicy(),
    *,
    body: bytes = b"",
    content_type: str = "",
    extra_headers: Tuple[Tuple[str, str], ...] = (),
    allow_redirect_status: bool = False,
) -> SafeHttpResponse:
    """Make one bounded request to an already validated target.

    ``body``/``content_type`` are optional and empty by default -- every
    pre-existing GET/HEAD-only caller is unaffected. When ``body`` is
    supplied it is checked against ``policy.maximum_request_body_bytes``
    before any connection is attempted (fail closed on an oversized
    request body, mirroring the existing response-body limit).

    ``extra_headers`` (Slice 7: authentication support) is checked
    against ``_FORBIDDEN_REQUEST_HEADERS`` before any connection is
    attempted -- this is not a general header-injection mechanism, only
    the path ``authentication.apply_authentication`` uses to attach
    ``Authorization``/``Cookie``. Every other caller passes nothing here
    and is unaffected.

    ``allow_redirect_status`` (Slice 7: login workflow) lets a 3xx
    response through instead of raising ``redirect_blocked`` -- this
    never causes a second request to be issued to the redirect's target;
    it only lets the caller read the ``Location`` header value as a
    string (e.g. to check a login-success redirect marker). Every other
    caller leaves this False and is unaffected.
    """

    _validate_policy(policy)

    normalised_method = method.upper()

    if normalised_method not in policy.allowed_methods:
        raise SafeRequestError(
            "method_not_allowed",
            f"HTTP method {normalised_method!r} is prohibited.",
        )

    if body and len(body) > policy.maximum_request_body_bytes:
        raise SafeRequestError(
            "request_body_too_large",
            "The request body exceeds the configured limit.",
        )

    for name, _ in extra_headers:
        if name.lower() in _FORBIDDEN_REQUEST_HEADERS:
            raise SafeRequestError(
                "forbidden_request_header",
                f"Header {name!r} cannot be set through extra_headers.",
            )

    path = _request_path(target)
    addresses = _canonical_addresses(
        target.resolved_addresses
    )

    connection_failures: list[_ConnectionFailure] = []

    for address in addresses:
        try:
            return _perform_request(
                target,
                address,
                normalised_method,
                path,
                policy,
                body=body,
                content_type=content_type,
                extra_headers=extra_headers,
                allow_redirect_status=allow_redirect_status,
            )
        except SafeRequestError:
            raise
        except (
            OSError,
            ssl.SSLError,
            http.client.HTTPException,
        ) as exc:
            if getattr(exc, "webguard_request_sent", False):
                # P6-005: a real request already went out on this address
                # under the caller's single before_request/after_request
                # accounting for this attempt. Falling back to the next
                # address here would send a second real request that
                # accounting never counted.
                raise SafeRequestError(
                    _connection_error_code(exc),
                    "The request failed after it was already sent to "
                    "the target.",
                ) from exc
            connection_failures.append(
                _ConnectionFailure(
                    address=address,
                    code=_connection_error_code(exc),
                    exception_name=exc.__class__.__name__,
                )
            )

    bounded_failures = tuple(connection_failures)
    failure_code = _aggregate_connection_error_code(
        bounded_failures
    )

    raise SafeRequestError(
        failure_code,
        "All approved destination addresses failed: "
        + ", ".join(
            f"{failure.address}: {failure.exception_name}"
            for failure in bounded_failures
        ),
    )
