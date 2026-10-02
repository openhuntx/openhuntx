"""Unit tests for the connection-time HTTP safety layer."""

from __future__ import annotations

import socket
import ssl
import threading
import time
import tracemalloc
import unittest
from dataclasses import replace
from datetime import datetime, timezone
from email.message import Message
from unittest.mock import patch

from webguard_scanner import (
    FetchPolicy,
    SafeRequestError,
    TlsConnectionInfo,
    ValidatedTarget,
    fetch_once,
)
from webguard_scanner import safe_http


class FakeResponse:
    """Minimal HTTPResponse replacement for deterministic tests."""

    def __init__(
        self,
        status: int = 200,
        reason: str = "OK",
        headers: list[tuple[str, str]] | None = None,
        body: bytes = b"response",
    ) -> None:
        self.status = status
        self.reason = reason
        self._headers = (
            headers
            if headers is not None
            else [("Content-Length", str(len(body)))]
        )
        self._body = body
        self._position = 0
        self.msg = Message()

        for name, value in self._headers:
            self.msg.add_header(name, value)

    def getheaders(self) -> list[tuple[str, str]]:
        return list(self._headers)

    def read(self, amount: int = -1) -> bytes:
        if amount < 0:
            amount = len(self._body) - self._position

        chunk = self._body[
            self._position:self._position + amount
        ]
        self._position += len(chunk)

        return chunk


class FakeTlsContext:
    verify_mode = ssl.CERT_REQUIRED
    check_hostname = True


class FakeTlsSocket:
    def __init__(
        self,
        *,
        protocol: str = "TLSv1.3",
        cipher: tuple[str, str, int] = (
            "TLS_AES_256_GCM_SHA384",
            "TLSv1.3",
            256,
        ),
        certificate: dict[str, object] | None = None,
        certificate_der: bytes = b"certificate-der",
        chain_length: int | None = 3,
    ) -> None:
        self._protocol = protocol
        self._cipher = cipher
        self._certificate = certificate or {
            "notBefore": "Mar 15 00:00:00 2026 GMT",
            "notAfter": "Oct  1 00:00:00 2026 GMT",
            "subjectAltName": (("DNS", "example.com"),),
        }
        self._certificate_der = certificate_der
        self._chain_length = chain_length

    def getpeercert(self, binary_form: bool = False):
        if binary_form:
            return self._certificate_der
        return self._certificate

    def version(self) -> str:
        return self._protocol

    def cipher(self) -> tuple[str, str, int]:
        return self._cipher

    def get_verified_chain(self):
        if self._chain_length is None:
            return None
        return [object()] * self._chain_length


class FakeConnection:
    """Minimal HTTPConnection replacement for deterministic tests."""

    def __init__(
        self,
        response: FakeResponse,
        *,
        tls_socket: object | None = None,
        tls_context: object | None = None,
    ) -> None:
        self.response = response
        self.request = None
        self.headers: list[tuple[str, str]] = []
        self.closed = False
        self.sock = tls_socket if tls_socket is not None else FakeTlsSocket()
        self._context = (
            tls_context
            if tls_context is not None
            else FakeTlsContext()
        )

    def putrequest(
        self,
        method: str,
        path: str,
        **kwargs,
    ) -> None:
        self.request = (method, path, kwargs)

    def putheader(
        self,
        name: str,
        value: str,
    ) -> None:
        self.headers.append((name, value))

    def endheaders(self) -> None:
        return None

    def getresponse(self) -> FakeResponse:
        return self.response

    def close(self) -> None:
        self.closed = True


def create_target(
    normalised_url: str = "https://example.com/",
    scheme: str = "https",
    hostname: str = "example.com",
    port: int = 443,
) -> ValidatedTarget:
    return ValidatedTarget(
        original_url=normalised_url,
        normalised_url=normalised_url,
        scheme=scheme,
        hostname=hostname,
        port=port,
        resolved_addresses=("93.184.216.34",),
    )


class SafeHttpTests(unittest.TestCase):
    """Verify request pinning and response limits."""

    def test_connects_to_ip_and_sends_hostname(self) -> None:
        connection = FakeConnection(FakeResponse())

        with patch(
            "webguard_scanner.safe_http._make_connection",
            return_value=connection,
        ) as make_connection:
            response = fetch_once(create_target())

        self.assertEqual(
            make_connection.call_args.args[1],
            "93.184.216.34",
        )
        self.assertIn(
            ("Host", "example.com"),
            connection.headers,
        )
        self.assertEqual(
            response.connected_address,
            "93.184.216.34",
        )
        self.assertIsInstance(response.tls, TlsConnectionInfo)
        self.assertEqual(response.tls.protocol, "TLSv1.3")
        self.assertEqual(response.tls.cipher_bits, 256)
        self.assertEqual(response.tls.verified_chain_length, 3)
        self.assertTrue(response.tls.certificate_verified)
        self.assertTrue(response.tls.hostname_validated)
        self.assertTrue(connection.closed)

    def test_non_default_port_appears_in_host(self) -> None:
        connection = FakeConnection(FakeResponse())

        custom_target = create_target(
            normalised_url="https://example.com:8443/",
            port=8443,
        )

        with patch(
            "webguard_scanner.safe_http._make_connection",
            return_value=connection,
        ):
            fetch_once(custom_target)

        self.assertIn(
            ("Host", "example.com:8443"),
            connection.headers,
        )

    def test_blocks_redirect_response(self) -> None:
        connection = FakeConnection(
            FakeResponse(
                status=302,
                reason="Found",
                headers=[
                    ("Location", "http://127.0.0.1/")
                ],
                body=b"",
            )
        )

        with patch(
            "webguard_scanner.safe_http._make_connection",
            return_value=connection,
        ):
            with self.assertRaises(
                SafeRequestError
            ) as context:
                fetch_once(create_target())

        self.assertEqual(
            context.exception.code,
            "redirect_blocked",
        )
        self.assertTrue(connection.closed)

    def test_rejects_declared_oversized_body(self) -> None:
        connection = FakeConnection(
            FakeResponse(
                headers=[("Content-Length", "100")],
                body=b"",
            )
        )

        with patch(
            "webguard_scanner.safe_http._make_connection",
            return_value=connection,
        ):
            with self.assertRaises(
                SafeRequestError
            ) as context:
                fetch_once(
                    create_target(),
                    policy=FetchPolicy(
                        maximum_body_bytes=10
                    ),
                )

        self.assertEqual(
            context.exception.code,
            "response_body_too_large",
        )

    def test_rejects_undeclared_oversized_body(self) -> None:
        connection = FakeConnection(
            FakeResponse(
                headers=[],
                body=b"01234567890",
            )
        )

        with patch(
            "webguard_scanner.safe_http._make_connection",
            return_value=connection,
        ):
            with self.assertRaises(
                SafeRequestError
            ) as context:
                fetch_once(
                    create_target(),
                    policy=FetchPolicy(
                        maximum_body_bytes=10
                    ),
                )

        self.assertEqual(
            context.exception.code,
            "response_body_too_large",
        )

    def test_rejects_conflicting_content_lengths(self) -> None:
        connection = FakeConnection(
            FakeResponse(
                headers=[
                    ("Content-Length", "5"),
                    ("Content-Length", "7"),
                ],
                body=b"hello",
            )
        )

        with patch(
            "webguard_scanner.safe_http._make_connection",
            return_value=connection,
        ):
            with self.assertRaises(
                SafeRequestError
            ) as context:
                fetch_once(create_target())

        self.assertEqual(
            context.exception.code,
            "content_length_ambiguous",
        )

    def test_rejects_unapproved_method(self) -> None:
        with self.assertRaises(
            SafeRequestError
        ) as context:
            fetch_once(
                create_target(),
                method="POST",
            )

        self.assertEqual(
            context.exception.code,
            "method_not_allowed",
        )


    def test_http_response_does_not_contain_tls_metadata(self) -> None:
        connection = FakeConnection(FakeResponse())
        http_target = create_target(
            normalised_url="http://example.com/",
            scheme="http",
            port=80,
        )
        with patch(
            "webguard_scanner.safe_http._make_connection",
            return_value=connection,
        ):
            response = fetch_once(http_target)
        self.assertIsNone(response.tls)

    def test_tls_metadata_is_captured_before_response_closes_socket(
        self,
    ) -> None:
        connection = FakeConnection(FakeResponse())
        original_getresponse = connection.getresponse

        def getresponse_and_clear_socket():
            result = original_getresponse()
            connection.sock = None
            return result

        connection.getresponse = getresponse_and_clear_socket  # type: ignore[method-assign]

        with patch(
            "webguard_scanner.safe_http._make_connection",
            return_value=connection,
        ):
            response = fetch_once(create_target())

        self.assertIsInstance(response.tls, TlsConnectionInfo)

    def test_tls_metadata_contains_bounded_public_certificate_facts(self) -> None:
        connection = FakeConnection(FakeResponse())
        with patch(
            "webguard_scanner.safe_http._make_connection",
            return_value=connection,
        ):
            response = fetch_once(create_target())
        assert response.tls is not None
        self.assertEqual(
            response.tls.server_hostname,
            "example.com",
        )
        self.assertEqual(
            response.tls.subject_alt_names,
            ("DNS:example.com",),
        )
        self.assertEqual(
            response.tls.certificate_not_before,
            datetime(2026, 3, 15, tzinfo=timezone.utc),
        )
        self.assertEqual(len(response.tls.certificate_sha256), 64)
        self.assertNotIn("certificate-der", repr(response.tls))

    def test_unavailable_verified_chain_method_is_nonfatal(self) -> None:
        socket_without_chain = FakeTlsSocket()
        socket_without_chain.get_verified_chain = None  # type: ignore[method-assign]
        connection = FakeConnection(
            FakeResponse(),
            tls_socket=socket_without_chain,
        )
        with patch(
            "webguard_scanner.safe_http._make_connection",
            return_value=connection,
        ):
            response = fetch_once(create_target())
        assert response.tls is not None
        self.assertIsNone(response.tls.verified_chain_length)

    def test_rejects_https_connection_without_tls_socket(self) -> None:
        connection = FakeConnection(FakeResponse())
        connection.sock = None
        with patch(
            "webguard_scanner.safe_http._make_connection",
            return_value=connection,
        ):
            with self.assertRaises(SafeRequestError) as context:
                fetch_once(create_target())
        self.assertEqual(
            context.exception.code,
            "tls_metadata_unavailable",
        )

    def test_rejects_insecure_tls_context(self) -> None:
        class InsecureContext:
            verify_mode = ssl.CERT_NONE
            check_hostname = False

        connection = FakeConnection(
            FakeResponse(),
            tls_context=InsecureContext(),
        )
        with patch(
            "webguard_scanner.safe_http._make_connection",
            return_value=connection,
        ):
            with self.assertRaises(SafeRequestError) as context:
                fetch_once(create_target())
        self.assertEqual(
            context.exception.code,
            "tls_context_insecure",
        )

    def test_rejects_invalid_certificate_time_metadata(self) -> None:
        socket = FakeTlsSocket(
            certificate={
                "notBefore": "not-a-date",
                "notAfter": "Oct  1 00:00:00 2026 GMT",
                "subjectAltName": (("DNS", "example.com"),),
            }
        )
        connection = FakeConnection(
            FakeResponse(),
            tls_socket=socket,
        )
        with patch(
            "webguard_scanner.safe_http._make_connection",
            return_value=connection,
        ):
            with self.assertRaises(SafeRequestError) as context:
                fetch_once(create_target())
        self.assertEqual(
            context.exception.code,
            "tls_certificate_metadata_invalid",
        )

    def test_rejects_excessive_subject_alternative_names(self) -> None:
        names = tuple(
            ("DNS", f"host-{index}.example.com")
            for index in range(257)
        )
        socket = FakeTlsSocket(
            certificate={
                "notBefore": "Mar 15 00:00:00 2026 GMT",
                "notAfter": "Oct  1 00:00:00 2026 GMT",
                "subjectAltName": names,
            }
        )
        connection = FakeConnection(
            FakeResponse(),
            tls_socket=socket,
        )
        with patch(
            "webguard_scanner.safe_http._make_connection",
            return_value=connection,
        ):
            with self.assertRaises(SafeRequestError) as context:
                fetch_once(create_target())
        self.assertEqual(
            context.exception.code,
            "tls_certificate_metadata_too_large",
        )


class MalformedChunkedResponseTests(unittest.TestCase):
    """Adversarial tests against a real socket, not a mocked connection.

    These reproduce wire-level parsing behaviour inside ``http.client``
    itself, which a mocked response object cannot exercise: the bug this
    class pins (a negative chunk size) lives inside the stdlib's own
    chunk-size parser, not in this module's code around it.
    """

    @staticmethod
    def _serve_once(server: socket.socket, raw_response: bytes) -> None:
        connection, _ = server.accept()
        try:
            connection.recv(65536)
            try:
                connection.sendall(raw_response)
            except (BrokenPipeError, ConnectionResetError, OSError):
                pass
        finally:
            connection.close()

    def _fetch_from_raw_response(
        self,
        raw_response: bytes,
        *,
        maximum_body_bytes: int = 1_048_576,
    ):
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind(("127.0.0.1", 0))
        server.listen(1)
        port = server.getsockname()[1]
        thread = threading.Thread(
            target=self._serve_once,
            args=(server, raw_response),
            daemon=True,
        )
        thread.start()
        self.addCleanup(server.close)
        self.addCleanup(thread.join, timeout=2)

        target = ValidatedTarget(
            original_url=f"http://127.0.0.1:{port}/",
            normalised_url=f"http://127.0.0.1:{port}/",
            scheme="http",
            hostname="127.0.0.1",
            port=port,
            resolved_addresses=("127.0.0.1",),
        )
        return fetch_once(
            target,
            method="GET",
            policy=FetchPolicy(
                maximum_body_bytes=maximum_body_bytes,
                timeout_seconds=5,
            ),
        )

    def test_negative_chunk_size_is_rejected_not_read_to_eof(self) -> None:
        """P6-001: a chunk size of -1 must not bypass maximum_body_bytes.

        ``http.client``'s chunk-size parser accepts a leading '-' and
        passes the negative result to ``fp.read(chunk_left)``, where a
        negative size means "read until EOF" -- unboundedly, regardless
        of what this module's own read loop asked for. Both the fixed and
        unfixed code eventually raise ``SafeRequestError`` here (the
        garbage that follows fails to parse as a chunk header either
        way), so the error code alone cannot distinguish them: without
        the fix this response's full 4MB is read into memory first, then
        discarded when the eventual parse failure occurs. The bound
        below on peak traced memory is the actual regression this test
        pins.
        """

        payload_size = 4 * 1024 * 1024
        raw_response = (
            b"HTTP/1.1 200 OK\r\n"
            b"Transfer-Encoding: chunked\r\n"
            b"\r\n"
            b"-1\r\n"
            + b"A" * payload_size
        )
        tracemalloc.start()
        try:
            with self.assertRaises(SafeRequestError) as context:
                self._fetch_from_raw_response(
                    raw_response, maximum_body_bytes=1
                )
            _current, peak = tracemalloc.get_traced_memory()
        finally:
            tracemalloc.stop()
        self.assertEqual(context.exception.code, "http_protocol_error")
        self.assertLess(
            peak,
            payload_size // 4,
            "the negative chunk size was read toward EOF instead of "
            "being rejected at the chunk-size parser",
        )

    def test_valid_chunked_response_still_reads_normally(self) -> None:
        raw_response = (
            b"HTTP/1.1 200 OK\r\n"
            b"Transfer-Encoding: chunked\r\n"
            b"\r\n"
            b"5\r\nhello\r\n"
            b"0\r\n\r\n"
        )
        response = self._fetch_from_raw_response(raw_response)
        self.assertEqual(response.status, 200)
        self.assertEqual(response.body, b"hello")

    def test_non_ascii_digit_content_length_is_rejected(self) -> None:
        """P6-002: str.isdigit() accepts Unicode decimal digits (e.g. the
        Latin-1 superscript-two byte, which decodes to '\xb2') that
        int() cannot parse in base 10. Before the fix this reached
        int('\xb2') directly and raised an uncontrolled ValueError."""

        raw_response = (
            b"HTTP/1.1 200 OK\r\n"
            b"Content-Length: \xb2\r\n"
            b"\r\n"
            b"hello"
        )
        with self.assertRaises(SafeRequestError) as context:
            self._fetch_from_raw_response(raw_response)
        self.assertEqual(context.exception.code, "content_length_invalid")

    def test_excessively_long_content_length_is_rejected(self) -> None:
        """str.isdigit() places no bound on length; a long enough
        all-digit token exceeds Python's own integer-string-conversion
        limit, and int() raises ValueError rather than returning a
        value. Before the fix that ValueError was uncontrolled."""

        raw_response = (
            b"HTTP/1.1 200 OK\r\n"
            b"Content-Length: " + b"1" * 5000 + b"\r\n"
            b"\r\n"
            b"hello"
        )
        with self.assertRaises(SafeRequestError) as context:
            self._fetch_from_raw_response(raw_response)
        self.assertEqual(context.exception.code, "content_length_invalid")

    def test_out_of_range_status_code_is_rejected(self) -> None:
        """P6-004: http.client only requires a 3-digit status line, so a
        server returning 600-999 previously passed through unchecked and
        only failed later at RequestAttempt's own 100-599 contract check,
        after the request had already been sent and counted."""

        raw_response = b"HTTP/1.1 600 Custom\r\n\r\n"
        with self.assertRaises(SafeRequestError) as context:
            self._fetch_from_raw_response(raw_response)
        self.assertEqual(context.exception.code, "response_status_invalid")

    def test_post_send_failure_does_not_fall_back_to_a_second_address(
        self,
    ) -> None:
        """P6-005: fetch_once's per-address fallback is meant for a
        server it never reached (e.g. connection refused on one of
        several resolved addresses). The caller's before_request/
        after_request safety hooks -- rate limiting, permit-attempt
        budget, circuit breaker -- are invoked exactly once per
        fetch_once call, no matter how many addresses it tries. Before
        this fix, a request that was fully sent to the first address but
        then failed while its response was still being read (here: a
        malformed chunked body) still fell back and sent a second, real
        request to the next address -- unaccounted for by that single
        hook pair. The second server below must never see a connection.
        """

        # The OS only assigns 127.0.0.1 to lo0 without an (unavailable in
        # this test) sudo-added alias, so two distinct *approved
        # addresses* are simulated by patching _make_connection to route
        # each fake address literal to its own real 127.0.0.1 port below
        # -- the fallback decision under test lives entirely in
        # fetch_once's own control flow, not in address resolution.
        bad_server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        bad_server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        bad_server.bind(("127.0.0.1", 0))
        bad_server.listen(1)
        bad_port = bad_server.getsockname()[1]

        good_server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        good_server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        good_server.bind(("127.0.0.1", 0))
        good_server.listen(1)
        good_server.settimeout(0.5)
        good_port = good_server.getsockname()[1]

        real_make_connection = safe_http._make_connection
        address_ports = {"127.0.0.1": bad_port, "127.0.0.9": good_port}

        def fake_make_connection(target, address, policy):
            return real_make_connection(
                replace(target, port=address_ports[address]),
                "127.0.0.1",
                policy,
            )

        good_server_saw_connection = []

        def serve_bad() -> None:
            connection, _ = bad_server.accept()
            try:
                connection.recv(65536)
                try:
                    connection.sendall(
                        b"HTTP/1.1 200 OK\r\n"
                        b"Transfer-Encoding: chunked\r\n"
                        b"\r\n"
                        b"-1\r\n" + b"A" * 4096
                    )
                except (BrokenPipeError, ConnectionResetError, OSError):
                    pass
            finally:
                connection.close()

        def serve_good() -> None:
            try:
                connection, _ = good_server.accept()
                good_server_saw_connection.append(True)
                connection.close()
            except OSError:
                pass

        bad_thread = threading.Thread(target=serve_bad, daemon=True)
        good_thread = threading.Thread(target=serve_good, daemon=True)
        bad_thread.start()
        good_thread.start()
        self.addCleanup(bad_server.close)
        self.addCleanup(good_server.close)
        self.addCleanup(bad_thread.join, timeout=2)
        self.addCleanup(good_thread.join, timeout=2)

        target = ValidatedTarget(
            original_url=f"http://127.0.0.1:{bad_port}/",
            normalised_url=f"http://127.0.0.1:{bad_port}/",
            scheme="http",
            hostname="127.0.0.1",
            port=bad_port,
            resolved_addresses=("127.0.0.1", "127.0.0.9"),
        )
        with patch.object(
            safe_http, "_make_connection", fake_make_connection
        ):
            with self.assertRaises(SafeRequestError) as context:
                fetch_once(
                    target,
                    method="GET",
                    policy=FetchPolicy(
                        maximum_body_bytes=1,
                        timeout_seconds=5,
                    ),
                )
        self.assertEqual(context.exception.code, "http_protocol_error")

        good_thread.join(timeout=2)
        self.assertEqual(
            good_server_saw_connection,
            [],
            "fetch_once sent a second real request to another address "
            "after the first request had already been sent, bypassing "
            "the caller's single before_request/after_request accounting",
        )

    def test_slow_drip_response_is_bounded_by_an_overall_deadline(
        self,
    ) -> None:
        """P6-006: timeout_seconds only bounded each individual socket
        operation, not the request as a whole. A server that drips its
        body one byte at a time, with every gap safely under that
        per-operation timeout, kept the whole call alive far past the
        configured limit -- each individual read succeeds, so nothing
        ever timed out on its own."""

        body = b"A" * 20
        drip_seconds = 0.05

        def serve(server: socket.socket) -> None:
            connection, _ = server.accept()
            try:
                connection.recv(65536)
                connection.sendall(
                    f"HTTP/1.1 200 OK\r\n"
                    f"Content-Length: {len(body)}\r\n\r\n".encode("ascii")
                )
                for byte in body:
                    time.sleep(drip_seconds)
                    try:
                        connection.sendall(bytes([byte]))
                    except (
                        BrokenPipeError,
                        ConnectionResetError,
                        OSError,
                    ):
                        return
            finally:
                connection.close()

        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind(("127.0.0.1", 0))
        server.listen(1)
        port = server.getsockname()[1]
        thread = threading.Thread(
            target=serve, args=(server,), daemon=True
        )
        thread.start()
        self.addCleanup(server.close)
        self.addCleanup(thread.join, timeout=3)

        target = ValidatedTarget(
            original_url=f"http://127.0.0.1:{port}/",
            normalised_url=f"http://127.0.0.1:{port}/",
            scheme="http",
            hostname="127.0.0.1",
            port=port,
            resolved_addresses=("127.0.0.1",),
        )
        started = time.monotonic()
        with self.assertRaises(SafeRequestError) as context:
            fetch_once(
                target,
                method="GET",
                policy=FetchPolicy(timeout_seconds=0.5),
            )
        elapsed = time.monotonic() - started

        self.assertEqual(
            context.exception.code, "request_deadline_exceeded"
        )
        self.assertLess(
            elapsed,
            len(body) * drip_seconds - 0.2,
            "the request was not cut off by the overall deadline",
        )


class NonAsciiPathTests(unittest.TestCase):
    """P6-003: a discovered link can carry a literal non-ASCII path
    segment straight through urlsplit, which does no encoding of its
    own. http.client's putrequest() encodes the request line as strict
    ASCII, so this must be reproduced with a real connection -- a mocked
    one would happily store whatever string it is handed."""

    def test_non_ascii_path_is_percent_encoded_on_the_wire(self) -> None:
        received = {}

        def serve(server: socket.socket) -> None:
            connection, _ = server.accept()
            try:
                request_line = b""
                while not request_line.endswith(b"\r\n"):
                    request_line += connection.recv(1)
                received["request_line"] = request_line
                connection.recv(65536)
                connection.sendall(
                    b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"
                )
            finally:
                connection.close()

        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind(("127.0.0.1", 0))
        server.listen(1)
        port = server.getsockname()[1]
        thread = threading.Thread(
            target=serve, args=(server,), daemon=True
        )
        thread.start()
        self.addCleanup(server.close)
        self.addCleanup(thread.join, timeout=2)

        target = ValidatedTarget(
            original_url=f"http://127.0.0.1:{port}/café",
            normalised_url=f"http://127.0.0.1:{port}/café",
            scheme="http",
            hostname="127.0.0.1",
            port=port,
            resolved_addresses=("127.0.0.1",),
        )
        response = fetch_once(target, method="GET")

        self.assertEqual(response.status, 200)
        self.assertEqual(
            received["request_line"],
            b"GET /caf%C3%A9 HTTP/1.1\r\n",
        )

    def test_already_percent_encoded_path_is_not_double_encoded(
        self,
    ) -> None:
        target = create_target(
            normalised_url="https://example.com/a%20b?x=1%2B1",
        )
        path = safe_http._request_path(target)
        self.assertEqual(path, "/a%20b?x=1%2B1")


if __name__ == "__main__":
    unittest.main()
