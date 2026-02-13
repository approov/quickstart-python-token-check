#!/usr/bin/env python3
"""Single-file Approov quickstart server with token verification and token binding."""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
import logging
import os
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Iterable, Mapping, Optional, Protocol, Sequence, TypeGuard
from urllib.parse import urlsplit

import jwt

APPROOV_HEADER = "Approov-Token"
AUTH_HEADER = "Authorization"
SESSION_ID_HEADER = "SessionId"
PLACEHOLDER_SECRET = "approov_base64url_secret_here"
DEFAULT_PORT = 8080
ERROR_MISSING_APPROOV_TOKEN = "missing_approov_token"
ERROR_MISSING_BINDING_HEADER = "missing_binding_header"
ERROR_BINDING_MISMATCH = "binding_mismatch"
ERROR_TOKEN_VERIFICATION_FAILED = "token_verification_failed"


class HTTPRequest(Protocol):
    """Minimal request contract expected by the Approov middleware."""

    method: str
    path: str
    headers: Mapping[str, str]


@dataclass(frozen=True, slots=True)
class ProtectedRoute:
    """Protected route definition with optional token binding requirements."""

    path: str
    method: str = "GET"
    bound_headers: tuple[str, ...] = ()
    token_check: bool = True

    def __post_init__(self) -> None:
        object.__setattr__(self, "path", _normalize_route_path(self.path))
        object.__setattr__(self, "method", _normalize_route_method(self.method))

        normalized_headers = tuple(
            header.strip() for header in self.bound_headers if _has_text(header)
        )
        object.__setattr__(self, "bound_headers", normalized_headers)


@dataclass(frozen=True, slots=True)
class ApproovDecision:
    """Authorization decision returned by middleware enforcement."""

    status: int
    summary: str
    required_headers: tuple[str, ...] = ()
    claims: Mapping[str, Any] = field(default_factory=dict)
    error: Optional[str] = None

    @property
    def is_authorized(self) -> bool:
        return self.status == 200


@dataclass(slots=True)
class ApproovConfig:
    """Runtime switches and cryptographic material for Approov verification."""

    approov_secret: bytes
    approov_enabled: bool = True
    token_binding_enabled: bool = True
    approov_token_header: str = APPROOV_HEADER


@dataclass(frozen=True, slots=True)
class SimpleRequest:
    """Tiny helper request object used by the HTTP layer."""

    method: str
    path: str
    headers: Mapping[str, str]
    remote_addr: str = "127.0.0.1"
    server_port: int = DEFAULT_PORT


def configure_logging(level: int = logging.INFO) -> None:
    """Set a sane default logging format for services using this module."""
    logging.basicConfig(
        level=level,
        format="[%(asctime)s] %(name)s %(levelname)s %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )


def _has_text(value: Optional[str]) -> TypeGuard[str]:
    return value is not None and value.strip() != ""


def _as_text(value: Any) -> Optional[str]:
    if value is None:
        return None
    normalized = str(value).strip()
    return normalized if normalized else None


def _normalize_route_method(method: str) -> str:
    normalized = method.strip().upper()
    if not normalized:
        raise ValueError("Route method must not be empty")
    return normalized


def _normalize_route_path(path: str) -> str:
    normalized = path.strip()
    if not normalized:
        raise ValueError("Route path must not be empty")
    return normalized


def _decode_base64url(secret: str) -> bytes:
    normalized = secret.strip().replace("+", "-").replace("/", "_")
    padding = "=" * (-len(normalized) % 4)
    return base64.urlsafe_b64decode(normalized + padding)


def _normalize_base64(value: str) -> str:
    return value.strip().replace("-", "+").replace("_", "/").rstrip("=")


def load_approov_secret(
    env_key: str = "APPROOV_BASE64URL_SECRET",
    *,
    logger: Optional[logging.Logger] = None,
) -> bytes:
    """Load and validate the base64url secret from environment variables."""
    active_logger = logger or logging.getLogger("approov")
    raw_secret = os.getenv(env_key)

    if not _has_text(raw_secret):
        active_logger.error("Required secret is not set")
        raise RuntimeError("Required secret is not set")

    normalized_secret = raw_secret.strip()
    if normalized_secret == PLACEHOLDER_SECRET:
        active_logger.error("Required secret is not set")
        raise RuntimeError("Required secret is not set")

    try:
        decoded = _decode_base64url(normalized_secret)
    except (binascii.Error, ValueError):
        active_logger.error("Required secret is invalid")
        raise RuntimeError("Required secret is invalid")

    if len(decoded) < 32:
        active_logger.error("Required secret is invalid")
        raise RuntimeError("Required secret is invalid")

    return decoded


def _headers_mapping(req: Any) -> Mapping[str, Any]:
    headers = getattr(req, "headers", None)
    if isinstance(headers, Mapping):
        return headers
    return {}


def _header_value(req: Any, header_name: str) -> Optional[str]:
    headers = _headers_mapping(req)

    direct = headers.get(header_name)
    if direct is not None:
        return _as_text(direct)

    target = header_name.lower()
    for key, value in headers.items():
        if str(key).lower() != target:
            continue
        return _as_text(value)

    for getter_name in ("get_header", "header"):
        getter = getattr(req, getter_name, None)
        if callable(getter):
            found = getter(header_name)
            if found is not None:
                return _as_text(found)

    return None


def _build_token_binding_string(
    req: Any, bound_headers: Sequence[str]
) -> tuple[Optional[str], Optional[str]]:
    """Build token binding input string by concatenating headers in declared order."""
    if not bound_headers:
        return ERROR_TOKEN_VERIFICATION_FAILED, None

    values: list[str] = []
    for header in bound_headers:
        value = _header_value(req, header)
        if not _has_text(value):
            return ERROR_MISSING_BINDING_HEADER, None
        values.append(value.strip())

    return None, "".join(values)


def _sha256_b64_from_str(value: str) -> str:
    """Base64-encoded SHA256 hash of the provided string (without padding)."""
    digest = hashlib.sha256(value.encode("utf-8")).digest()
    return base64.b64encode(digest).decode("ascii").rstrip("=")


def _binding_matches(pay_claim: str, computed_hash: str) -> bool:
    return hmac.compare_digest(
        _normalize_base64(pay_claim), _normalize_base64(computed_hash)
    )


def _summarize_error(error: str) -> str:
    if error in {
        ERROR_MISSING_APPROOV_TOKEN,
        ERROR_MISSING_BINDING_HEADER,
        ERROR_BINDING_MISMATCH,
        ERROR_TOKEN_VERIFICATION_FAILED,
    }:
        return error
    return ERROR_TOKEN_VERIFICATION_FAILED


def _request_method(req: Any) -> str:
    method = _as_text(getattr(req, "method", None))
    return method.upper() if method is not None else "GET"


def _request_path(req: Any) -> str:
    path = _as_text(getattr(req, "path", None))
    if path is not None:
        return path

    url = _as_text(getattr(req, "url", None))
    if url is not None:
        parsed = urlsplit(url)
        return parsed.path or "/"

    return "/"


def _request_ip(req: Any) -> str:
    for attr in ("remote_addr", "client_ip", "ip"):
        value = _as_text(getattr(req, attr, None))
        if value is not None:
            return value
    return ""


def _request_port(req: Any) -> int:
    for attr in ("server_port", "port"):
        value = _as_text(getattr(req, attr, None))
        if value is None:
            continue
        try:
            return int(value)
        except ValueError:
            continue
    return DEFAULT_PORT


class ApproovApplication:
    """Portable Approov middleware engine."""

    def __init__(
        self,
        *,
        approov_secret: bytes,
        logger: Optional[logging.Logger] = None,
        approov_enabled: bool = True,
        token_binding_enabled: bool = True,
        approov_token_header: str = APPROOV_HEADER,
    ) -> None:
        if not approov_secret:
            raise ValueError("approov_secret must not be empty")

        self.logger = logger or logging.getLogger("approov")
        self.config = ApproovConfig(
            approov_secret=approov_secret,
            approov_enabled=approov_enabled,
            token_binding_enabled=token_binding_enabled,
            approov_token_header=approov_token_header,
        )
        self._protected_routes: dict[tuple[str, str], ProtectedRoute] = {}
        self._route_details: dict[tuple[str, str], str] = {}

    @classmethod
    def from_environment(
        cls,
        *,
        logger: Optional[logging.Logger] = None,
        env_key: str = "APPROOV_BASE64URL_SECRET",
        register_default_routes: bool = True,
    ) -> "ApproovApplication":
        active_logger = logger or logging.getLogger("approov")
        secret = load_approov_secret(env_key=env_key, logger=active_logger)
        application = cls(approov_secret=secret, logger=active_logger)
        if register_default_routes:
            application.register_default_demo_routes()
        return application

    def register_default_demo_routes(self) -> None:
        self.register_public_route(
            "/unprotected",
            details="unprotected endpoint reached",
        )
        self.register_default_protected_routes()

    def register_default_protected_routes(self) -> None:
        self.register_protected_route(
            "/token-check",
            details="token check endpoint reached",
        )
        self.register_protected_route(
            "/token-binding",
            bound_headers=[AUTH_HEADER],
            details="single token binding endpoint reached",
        )
        self.register_protected_route(
            "/token-double-binding",
            bound_headers=[AUTH_HEADER, SESSION_ID_HEADER],
            details="double token binding endpoint reached",
        )

    def register_public_route(
        self,
        path: str,
        *,
        method: str = "GET",
        details: Optional[str] = None,
    ) -> None:
        route = ProtectedRoute(
            path=path,
            method=method,
            token_check=False,
        )
        route_key = (route.method, route.path)
        default_details = f"{route.path} endpoint reached"
        self._route_details[route_key] = _as_text(details) or default_details

    def register_protected_route(
        self,
        path: str,
        *,
        method: str = "GET",
        bound_headers: Optional[Iterable[str]] = None,
        token_check: bool = True,
        details: Optional[str] = None,
    ) -> None:
        route = ProtectedRoute(
            path=path,
            method=method,
            bound_headers=tuple(bound_headers or ()),
            token_check=token_check,
        )
        route_key = (route.method, route.path)
        self._protected_routes[route_key] = route

        default_details = f"{route.path} endpoint reached"
        self._route_details[route_key] = _as_text(details) or default_details

    def route_details_for(self, path: str, *, method: str = "GET") -> Optional[str]:
        route_key = (_normalize_route_method(method), _normalize_route_path(path))
        return self._route_details.get(route_key)

    def has_registered_route(self, path: str, *, method: Optional[str] = None) -> bool:
        route_path = _normalize_route_path(path)
        if method is not None:
            route_key = (_normalize_route_method(method), route_path)
            return route_key in self._route_details

        return any(
            registered_path == route_path for _, registered_path in self._route_details
        )

    def allowed_methods_for_path(self, path: str) -> tuple[str, ...]:
        route_path = _normalize_route_path(path)
        methods = sorted(
            method
            for method, registered_path in self._route_details
            if registered_path == route_path
        )
        return tuple(methods)

    def protected_route_for(self, req: Any) -> Optional[ProtectedRoute]:
        return self._protected_routes.get((_request_method(req), _request_path(req)))

    def enable_approov(self) -> None:
        self.config.approov_enabled = True

    def disable_approov(self) -> None:
        self.config.approov_enabled = False

    def enable_token_binding(self) -> None:
        self.config.token_binding_enabled = True

    def disable_token_binding(self) -> None:
        self.config.token_binding_enabled = False

    def state_payload(self) -> dict[str, bool]:
        return {
            "approovEnabled": bool(self.config.approov_enabled),
            "tokenBindingEnabled": bool(self.config.token_binding_enabled),
        }

    def info_payload(self, details: str) -> dict[str, Any]:
        payload: dict[str, Any] = self.state_payload()
        payload["details"] = details
        return payload

    def _required_headers_for_request(
        self, bound_headers: Sequence[str]
    ) -> tuple[str, ...]:
        if (not self.config.token_binding_enabled) or (not bound_headers):
            return (self.config.approov_token_header,)
        return (self.config.approov_token_header, *bound_headers)

    def approov(
        self,
        req: Any,
        *,
        token_check: bool = True,
        bound_headers: Optional[Sequence[str]] = None,
    ) -> tuple[Mapping[str, Any], Optional[str]]:
        if not token_check or not self.config.approov_enabled:
            self.logger.warning("[approov] endpoint protection is disabled")
            return {}, None

        token = _header_value(req, self.config.approov_token_header)
        if not _has_text(token):
            return {}, ERROR_MISSING_APPROOV_TOKEN

        try:
            claims = jwt.decode(
                token.strip(),
                self.config.approov_secret,
                algorithms=["HS256"],
                options={
                    "require": ["exp"],
                    "verify_signature": True,
                    "verify_exp": True,
                },
            )
        except jwt.ExpiredSignatureError:
            return {}, ERROR_TOKEN_VERIFICATION_FAILED
        except jwt.InvalidSignatureError:
            return {}, ERROR_TOKEN_VERIFICATION_FAILED
        except jwt.InvalidTokenError as error:
            self.logger.warning(
                "[approov] token invalid (%s)", error.__class__.__name__
            )
            return {}, ERROR_TOKEN_VERIFICATION_FAILED

        if bound_headers:
            pay_claim = claims.get("pay")
            if pay_claim is None:
                return {}, ERROR_BINDING_MISMATCH
            if not isinstance(pay_claim, str) or not _has_text(pay_claim):
                return {}, ERROR_BINDING_MISMATCH

            binding_error, binding_string = _build_token_binding_string(
                req, bound_headers
            )
            if binding_error is not None or binding_string is None:
                return {}, binding_error or ERROR_TOKEN_VERIFICATION_FAILED

            computed_hash = _sha256_b64_from_str(binding_string)
            if not _binding_matches(pay_claim, computed_hash):
                return {}, ERROR_BINDING_MISMATCH

            self.logger.debug(
                "[approov] token binding verification successful for %s",
                list(bound_headers),
            )

        self.logger.debug("[approov] token verification successful")
        return claims, None

    def _complete_decision(
        self, req: Any, decision: ApproovDecision
    ) -> ApproovDecision:
        self._log_http_request_completed(req, decision)
        return decision

    def extension(self, req: Any) -> ApproovDecision:
        route = self.protected_route_for(req)
        if route is None:
            return self._complete_decision(
                req,
                ApproovDecision(status=200, summary="unprotected"),
            )

        required_headers = self._required_headers_for_request(route.bound_headers)

        if not route.token_check:
            return self._complete_decision(
                req,
                ApproovDecision(
                    status=200,
                    summary="approov_skipped",
                    required_headers=required_headers,
                ),
            )

        if not self.config.approov_enabled:
            return self._complete_decision(
                req,
                ApproovDecision(
                    status=200,
                    summary="approov_disabled",
                    required_headers=required_headers,
                ),
            )

        active_bound_headers: Sequence[str]
        if self.config.token_binding_enabled:
            active_bound_headers = route.bound_headers
        else:
            active_bound_headers = ()

        claims, error = self.approov(
            req,
            token_check=True,
            bound_headers=active_bound_headers,
        )
        if error is not None:
            error_code = _summarize_error(error)
            return self._complete_decision(
                req,
                ApproovDecision(
                    status=401,
                    summary="approov_failed",
                    required_headers=required_headers,
                    claims={},
                    error=error_code,
                ),
            )

        return self._complete_decision(
            req,
            ApproovDecision(
                status=200,
                summary="approov_ok",
                required_headers=required_headers,
                claims=claims,
            ),
        )

    def _log_http_request_completed(self, req: Any, decision: ApproovDecision) -> None:
        if decision.status not in (200, 401):
            return

        payload: dict[str, Any] = {
            "summary": decision.summary,
            "method": _request_method(req),
            "path": _request_path(req),
            "status": decision.status,
            "ip": _request_ip(req),
            "port": _request_port(req),
            "approovEnabled": bool(self.config.approov_enabled),
            "tokenBindingEnabled": bool(self.config.token_binding_enabled),
            "required_headers": list(decision.required_headers),
        }

        if decision.error:
            payload["error"] = decision.error

        message = "http.request.completed " + json.dumps(
            payload,
            separators=(",", ":"),
        )
        if decision.status == 401:
            self.logger.warning(message)
        else:
            self.logger.info(message)


def _load_port(raw_port: str) -> int:
    value = raw_port.strip()
    port = int(value)
    if port < 1 or port > 65535:
        raise ValueError("HTTP_PORT must be in range 1-65535")
    return port


class ApproovHTTPServer(ThreadingHTTPServer):
    """HTTP server that keeps a shared Approov application instance."""

    def __init__(
        self,
        server_address: tuple[str, int],
        handler_class: type[BaseHTTPRequestHandler],
        application: ApproovApplication,
    ) -> None:
        super().__init__(server_address, handler_class)
        self.application = application


class ApproovRequestHandler(BaseHTTPRequestHandler):
    """Routes incoming requests to quickstart endpoints."""

    server: ApproovHTTPServer

    _CONTROL_ROUTES = {
        "/approov-state": "GET",
        "/approov/enable": "POST",
        "/approov/disable": "POST",
    }

    def do_GET(self) -> None:  # noqa: N802
        self._dispatch()

    def do_POST(self) -> None:  # noqa: N802
        self._dispatch()

    def log_message(self, fmt: str, *args: object) -> None:
        logging.getLogger("approov.server.http").info(
            "%s - %s", self.address_string(), fmt % args
        )

    def _dispatch(self) -> None:
        method = self.command
        path = urlsplit(self.path).path

        expected_method = self._CONTROL_ROUTES.get(path)
        if expected_method is not None:
            if method != expected_method:
                self._send_json(
                    405,
                    {
                        "error": "method_not_allowed",
                        "allowedMethods": [expected_method],
                    },
                    extra_headers={"Allow": expected_method},
                )
                return

            if path == "/approov-state":
                self._send_json(200, self.server.application.state_payload())
                return
            if path == "/approov/enable":
                self._set_approov_enabled(enabled=True)
                return

            self._set_approov_enabled(enabled=False)
            return

        if not self.server.application.has_registered_route(path):
            self._send_json(404, {"error": "not_found", "path": path})
            return

        if not self.server.application.has_registered_route(path, method=method):
            allowed_methods = self.server.application.allowed_methods_for_path(path)
            payload: dict[str, object] = {"error": "method_not_allowed"}
            extra_headers: Optional[dict[str, str]] = None
            if allowed_methods:
                payload["allowedMethods"] = list(allowed_methods)
                extra_headers = {"Allow": ", ".join(allowed_methods)}

            self._send_json(405, payload, extra_headers=extra_headers)
            return

        details = self.server.application.route_details_for(path, method=method)
        decision = self.server.application.extension(self._to_simple_request(path))
        self._send_decision(details or "endpoint reached", decision)

    def _to_simple_request(self, path: str) -> SimpleRequest:
        return SimpleRequest(
            method=self.command,
            path=path,
            headers={key: value for key, value in self.headers.items()},
            remote_addr=self.client_address[0] if self.client_address else "",
            server_port=self.server.server_port,
        )

    def _set_approov_enabled(self, *, enabled: bool) -> None:
        if enabled:
            self.server.application.enable_approov()
            details = "Approov protection enabled"
        else:
            self.server.application.disable_approov()
            details = "Approov protection disabled"
        self._send_json(200, self.server.application.info_payload(details))

    def _send_decision(self, details: str, decision: ApproovDecision) -> None:
        payload = self.server.application.info_payload(details)
        payload["summary"] = decision.summary
        if decision.required_headers:
            payload["requiredHeaders"] = list(decision.required_headers)

        if decision.is_authorized:
            self._send_json(decision.status, payload)
            return

        payload["error"] = "Unauthorized"
        self._send_json(decision.status, payload)

    def _send_json(
        self,
        status: int,
        payload: Mapping[str, object],
        *,
        extra_headers: Optional[Mapping[str, str]] = None,
    ) -> None:
        body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Content-Length", str(len(body)))
        if extra_headers:
            for header_name, header_value in extra_headers.items():
                self.send_header(header_name, header_value)
        self.end_headers()
        self.wfile.write(body)


def main() -> int:
    configure_logging()
    logger = logging.getLogger("approov.server")

    host = os.getenv("SERVER_HOSTNAME", "0.0.0.0").strip() or "0.0.0.0"
    try:
        port = _load_port(os.getenv("HTTP_PORT", "8080"))
    except ValueError as error:
        logger.error("Invalid HTTP_PORT value: %s", error)
        return 1

    try:
        application = ApproovApplication.from_environment(logger=logger)
    except RuntimeError as error:
        logger.error("Failed to initialize Approov application: %s", error)
        return 1

    server = ApproovHTTPServer((host, port), ApproovRequestHandler, application)
    logger.info("Listening on http://%s:%d", host, port)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        logger.info("Shutdown requested")
    finally:
        server.server_close()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
