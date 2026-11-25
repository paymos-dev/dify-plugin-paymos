from __future__ import annotations

import base64
import hashlib
import hmac
import json
import re
import time
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime, timezone
from decimal import Decimal
from email.utils import parsedate_to_datetime
from typing import Any, Literal, Protocol
from urllib.parse import quote, urlparse

DEFAULT_BASE_URL = "https://api.paymos.io"
USER_AGENT = "paymos-dify/0.1.0"
DEFAULT_TIMEOUT_SECONDS = 30.0
DEFAULT_MAX_RETRIES = 2
DEFAULT_BASE_DELAY_SECONDS = 0.150
MAX_RETRY_DELAY_SECONDS = 30.0

PaymosEnvironment = Literal["production", "sandbox"]

VALID_INVOICE_STATUSES = frozenset(
    {
        "awaiting_client",
        "awaiting_payment",
        "confirming",
        "underpaid_waiting",
        "paid",
        "paid_over",
        "underpaid",
        "expired",
        "cancelled",
    }
)
VALID_SIMULATE_STAGES = frozenset({"paid", "overpaid", "underpay", "cancel"})
VALID_REFUND_MODES = frozenset({"full", "overpayment"})

_DECIMAL_AMOUNT_RE = re.compile(r"^\d+(?:\.\d+)?$")


class PaymosError(Exception):
    """Base exception for all Paymos Dify plugin client errors."""


class PaymosConfigurationError(PaymosError):
    """Raised when credentials, URL, environment guard, or request parameters are invalid."""


def parse_problem_details(raw_body: str, status: int | None = None) -> dict[str, Any] | None:
    """Parse RFC 9457 Paymos Problem Details without mutating or promoting nested error codes.

    Preserves top-level ``code``, ``field``, ``detail``, and ``errors[]`` verbatim.
    Never overwrites top-level ``code`` with ``errors[0].code``.
    """
    if not isinstance(raw_body, str) or not raw_body.strip():
        return None
    try:
        parsed = json.loads(raw_body)
    except json.JSONDecodeError:
        return None
    if not isinstance(parsed, dict):
        return None

    parsed_status = parsed.get("status")
    if status is not None and parsed_status is not None:
        if isinstance(parsed_status, bool) or not isinstance(parsed_status, int) or parsed_status != status:
            return None

    has_problem_marker = any(
        isinstance(parsed.get(key), str) for key in ("type", "title", "detail", "code")
    ) or isinstance(parsed.get("errors"), list)
    if not has_problem_marker:
        return None

    raw_errors = parsed.get("errors")
    errors: list[dict[str, Any]] = (
        [dict(item) for item in raw_errors if isinstance(item, dict)] if isinstance(raw_errors, list) else []
    )

    raw_field = parsed.get("field")
    field = str(raw_field) if raw_field is not None else None

    result: dict[str, Any] = {
        "type": str(parsed["type"]) if isinstance(parsed.get("type"), str) else None,
        "title": str(parsed["title"]) if isinstance(parsed.get("title"), str) else None,
        "status": parsed_status if isinstance(parsed_status, int) and not isinstance(parsed_status, bool) else status,
        "detail": str(parsed["detail"]) if isinstance(parsed.get("detail"), str) else None,
        "code": str(parsed["code"]) if isinstance(parsed.get("code"), str) else None,
        "field": field,
        "errors": errors,
    }
    if isinstance(parsed.get("trace_id"), str):
        result["trace_id"] = parsed["trace_id"]
    return result


class PaymosApiError(PaymosError):
    """Represents a non-2xx HTTP response from the Paymos Merchant API."""

    def __init__(self, status: int, body: str, headers: Mapping[str, str] | None = None) -> None:
        self.status = status
        self.body = body
        self.headers = {str(k).lower(): str(v) for k, v in (headers or {}).items()}
        self.problem = parse_problem_details(body, status=status)

        # Preserve exact top-level RFC 9457 attributes without promoting errors[0].code / errors[0].field.
        self.code: str = (self.problem.get("code") or "") if self.problem else ""
        self.field: str | None = self.problem.get("field") if self.problem else None
        self.title: str = (self.problem.get("title") or "") if self.problem else ""
        self.detail: str = (self.problem.get("detail") or "") if self.problem else ""
        self.errors: list[dict[str, Any]] = list(self.problem.get("errors", [])) if self.problem else []

        summary = self.detail or self.code or self.title or body or "Empty response"
        message = f"Paymos API {status}"
        if self.code:
            message += f" ({self.code})"
        message += f": {summary}"
        if self.field:
            message += f" [field={self.field}]"
        elif self.errors:
            formatted = "; ".join(
                f"{item.get('field') or 'body'}: {item.get('code') or 'invalid'} ({item.get('message') or ''})"
                for item in self.errors
            )
            message += f" [{formatted}]"
        super().__init__(message)

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "code": self.code,
            "field": self.field,
            "detail": self.detail,
            "title": self.title,
            "errors": list(self.errors),
        }


@dataclass(frozen=True)
class ValidatedCredentials:
    public_key: str
    secret_key: str
    base_url: str
    environment: PaymosEnvironment


@dataclass(frozen=True)
class HttpResponse:
    status: int
    body: str
    headers: Mapping[str, str]


class HttpTransport(Protocol):
    def __call__(
        self,
        method: str,
        url: str,
        headers: Mapping[str, str],
        body: bytes | None,
        timeout: float,
    ) -> HttpResponse: ...


def sha256_hex(body: str | bytes = "") -> str:
    """Return lowercase hex SHA-256 of body bytes, or empty string when body is empty."""
    if isinstance(body, str):
        if body == "":
            return ""
        raw = body.encode("utf-8")
    else:
        if len(body) == 0:
            return ""
        raw = body
    return hashlib.sha256(raw).hexdigest()


def string_to_sign(
    timestamp: str | int,
    method: str,
    path: str,
    query: str = "",
    body: str | bytes = "",
) -> str:
    """Build Paymos canonical HMAC-SHA256 string to sign."""
    return f"{timestamp}\n{method.upper()}\n{path}\n{query}\n{sha256_hex(body)}"


def sign(secret: str, value: str) -> str:
    """Compute base64-encoded HMAC-SHA256 digest."""
    digest = hmac.new(secret.encode("utf-8"), value.encode("utf-8"), hashlib.sha256).digest()
    return base64.b64encode(digest).decode("ascii")


def authorization_header(
    api_key: str,
    api_secret: str,
    timestamp: str | int,
    method: str,
    path: str,
    query: str = "",
    body: str | bytes = "",
) -> str:
    """Format canonical Paymos Authorization header."""
    signature = sign(api_secret, string_to_sign(timestamp, method, path, query, body))
    return f"HMAC-SHA256 {api_key}:{signature}"


def encode_path_segment(value: str) -> str:
    """RFC 3986 percent-encoding for a single URL path segment."""
    return quote(str(value), safe="-._~")


def build_query(filters: Mapping[str, Any] | None) -> str:
    """Build canonical RFC 3986 query string with sorted keys/values and leading '?'."""
    if not filters:
        return ""
    parts: list[str] = []
    for key in sorted(filters):
        raw = filters[key]
        if raw is None:
            continue
        if isinstance(raw, Sequence) and not isinstance(raw, (str, bytes, bytearray)):
            values = sorted(raw, key=str)
            if not values:
                raise ValueError(f"Paymos query filter cannot be empty: {key}")
        else:
            values = [raw]
        for value in values:
            if isinstance(value, bool) or not isinstance(value, (str, int)) or str(value) == "":
                raise ValueError(f"Invalid Paymos query filter: {key}")
            parts.append(f"{quote(str(key), safe='-._~')}={quote(str(value), safe='-._~')}")
    return "?" + "&".join(parts) if parts else ""


def normalize_base_url(raw_value: str | None) -> str:
    """Validate and normalize Paymos base URL (HTTPS required; HTTP allowed only for loopback)."""
    candidate = (raw_value or DEFAULT_BASE_URL).strip() or DEFAULT_BASE_URL
    parsed = urlparse(candidate)
    host = (parsed.hostname or "").lower()
    if not host:
        raise PaymosConfigurationError("Paymos Base URL is not a valid URL.")
    if parsed.username is not None or parsed.password is not None:
        raise PaymosConfigurationError("Paymos Base URL must not contain embedded credentials.")
    if parsed.query or parsed.fragment:
        raise PaymosConfigurationError("Paymos Base URL must not include query parameters or fragments.")
    is_loopback = host in {"localhost", "127.0.0.1", "::1"}
    if parsed.scheme != "https" and not (parsed.scheme == "http" and is_loopback):
        raise PaymosConfigurationError(
            "Paymos Base URL must use HTTPS (HTTP is allowed only for loopback tests)."
        )
    return candidate.rstrip("/")


def validate_credentials(
    public_key: str | None,
    secret_key: str | None,
    base_url: str | None = None,
) -> ValidatedCredentials:
    """Validate Paymos Payment API credentials prior to any network activity."""
    pk = (public_key or "").strip() if isinstance(public_key, str) else ""
    sk = (secret_key or "").strip() if isinstance(secret_key, str) else ""

    if not pk:
        raise PaymosConfigurationError(
            "Paymos Public Key is required (expected pk_live_... or pk_test_...)."
        )
    if pk.startswith("rk_"):
        raise PaymosConfigurationError(
            "Payout API keys (rk_) are not supported by the Paymos Dify plugin. "
            "Use a Payment API key starting with pk_live_ (Production) or pk_test_ (Sandbox)."
        )

    environment: PaymosEnvironment
    if pk.startswith("pk_live_"):
        environment = "production"
    elif pk.startswith("pk_test_"):
        environment = "sandbox"
    else:
        raise PaymosConfigurationError(
            "Invalid Paymos Public Key prefix. Expected a Payment API key starting with "
            "pk_live_ (Production) or pk_test_ (Sandbox)."
        )

    if not sk:
        raise PaymosConfigurationError("Paymos Secret Key is required.")

    normalized_url = normalize_base_url(base_url)
    return ValidatedCredentials(
        public_key=pk,
        secret_key=sk,
        base_url=normalized_url,
        environment=environment,
    )


def parse_optional_str(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text if text else None


def parse_optional_int(value: Any, field_name: str) -> int | None:
    if value is None or value == "":
        return None
    if isinstance(value, bool):
        raise PaymosConfigurationError(f"Parameter '{field_name}' must be an integer.")
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        if value.is_integer():
            return int(value)
        raise PaymosConfigurationError(f"Parameter '{field_name}' must be an integer.")
    if isinstance(value, str):
        stripped = value.strip()
        if not stripped:
            return None
        try:
            return int(stripped)
        except ValueError as exc:
            raise PaymosConfigurationError(f"Parameter '{field_name}' must be an integer.") from exc
    raise PaymosConfigurationError(f"Parameter '{field_name}' must be an integer.")


def _default_transport(
    method: str,
    url: str,
    headers: Mapping[str, str],
    body: bytes | None,
    timeout: float,
) -> HttpResponse:
    import requests

    try:
        response = requests.request(
            method=method,
            url=url,
            headers=dict(headers),
            data=body,
            timeout=timeout,
            allow_redirects=False,
        )
    except requests.RequestException as exc:
        raise OSError(str(exc)) from exc

    return HttpResponse(
        status=int(response.status_code),
        body=response.text,
        headers=dict(response.headers.items()),
    )


def _parse_retry_after_seconds(headers: Mapping[str, str]) -> float | None:
    value: str | None = None
    for key, raw in headers.items():
        if key.lower() == "retry-after":
            value = str(raw).strip()
            break
    if not value:
        return None
    if value.isdigit():
        return float(value)
    try:
        dt = parsedate_to_datetime(value)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return max(0.0, (dt - datetime.now(timezone.utc)).total_seconds())
    except (TypeError, ValueError, OverflowError):
        return None


def _require_non_empty(value: Any, field_name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise PaymosConfigurationError(f"Parameter '{field_name}' is required and cannot be empty.")
    return value.strip()


class PaymosClient:
    """Canonical HMAC-SHA256 Paymos Payment API client for Dify Tool Plugins."""

    def __init__(
        self,
        public_key: str,
        secret_key: str,
        *,
        base_url: str | None = None,
        timeout: float = DEFAULT_TIMEOUT_SECONDS,
        max_retries: int = DEFAULT_MAX_RETRIES,
        base_delay: float = DEFAULT_BASE_DELAY_SECONDS,
        transport: HttpTransport | None = None,
        clock: Callable[[], float] | None = None,
        sleep: Callable[[float], None] | None = None,
    ) -> None:
        validated = validate_credentials(public_key, secret_key, base_url)
        if timeout <= 0 or max_retries < 0 or base_delay < 0:
            raise PaymosConfigurationError("timeout, max_retries, and base_delay must be valid positive values.")

        self.public_key = validated.public_key
        self.secret_key = validated.secret_key
        self.base_url = validated.base_url
        self.environment = validated.environment
        self.timeout = timeout
        self.max_retries = max_retries
        self.base_delay = base_delay
        self.transport: HttpTransport = transport if transport is not None else _default_transport
        self.clock: Callable[[], float] = clock if clock is not None else time.time
        self.sleep: Callable[[float], None] = sleep if sleep is not None else time.sleep

    @classmethod
    def from_credentials(
        cls,
        credentials: Mapping[str, Any] | None,
        **kwargs: Any,
    ) -> PaymosClient:
        if not isinstance(credentials, Mapping):
            raise PaymosConfigurationError("Paymos credentials are required.")
        return cls(
            public_key=str(credentials.get("public_key") or ""),
            secret_key=str(credentials.get("secret_key") or ""),
            base_url=parse_optional_str(credentials.get("base_url")),
            **kwargs,
        )

    def request(
        self,
        method: str,
        path: str,
        *,
        query: Mapping[str, Any] | None = None,
        payload: Mapping[str, Any] | None = None,
        max_retries: int | None = None,
    ) -> dict[str, Any]:
        upper_method = method.upper()
        if path.startswith("/v1/sandbox/") and self.environment != "sandbox":
            raise PaymosConfigurationError(
                "Sandbox endpoints (/v1/sandbox/*) require a Sandbox Payment API key (pk_test_). "
                "Production keys (pk_live_) cannot call sandbox endpoints."
            )

        query_string = build_query(query)
        body_text = "" if payload is None else json.dumps(payload, separators=(",", ":"), ensure_ascii=False)
        body_bytes = body_text.encode("utf-8") if body_text else None
        url = f"{self.base_url}{path}{query_string}"

        retries = self.max_retries if max_retries is None else max_retries
        is_idempotent_read = upper_method in {"GET", "HEAD", "OPTIONS"}

        for attempt in range(retries + 1):
            timestamp = str(int(self.clock()))
            headers: dict[str, str] = {
                "Authorization": authorization_header(
                    self.public_key,
                    self.secret_key,
                    timestamp,
                    upper_method,
                    path,
                    query_string,
                    body_text,
                ),
                "X-Request-Timestamp": timestamp,
                "Accept": "application/json",
                "User-Agent": USER_AGENT,
            }
            if body_text:
                headers["Content-Type"] = "application/json"

            try:
                response = self.transport(upper_method, url, headers, body_bytes, self.timeout)
            except OSError as exc:
                if attempt < retries and is_idempotent_read:
                    delay = min(self.base_delay * (2**attempt), MAX_RETRY_DELAY_SECONDS)
                    if delay > 0:
                        self.sleep(delay)
                    continue
                raise PaymosError(f"Paymos request failed: {exc}") from exc

            if attempt < retries and (
                response.status == 429 or (500 <= response.status <= 599 and is_idempotent_read)
            ):
                retry_after = _parse_retry_after_seconds(response.headers)
                backoff = self.base_delay * (2**attempt)
                delay = min(max(backoff, retry_after or 0.0), MAX_RETRY_DELAY_SECONDS)
                if delay > 0:
                    self.sleep(delay)
                continue

            if not (200 <= response.status < 300):
                raise PaymosApiError(response.status, response.body, response.headers)

            if not response.body or not response.body.strip():
                return {}
            try:
                parsed = json.loads(response.body)
            except json.JSONDecodeError as exc:
                raise PaymosError("Paymos API returned invalid JSON.") from exc
            return parsed if isinstance(parsed, dict) else {"data": parsed}

        raise AssertionError("unreachable")

    def validate_connection(self) -> dict[str, Any]:
        """Verify Payment API credentials via GET /v1/invoices?limit=1."""
        return self.request("GET", "/v1/invoices", query={"limit": 1}, max_retries=0)

    def create_invoice(
        self,
        *,
        project_id: str,
        amount: str,
        currency: str,
        external_order_id: str,
        network: str | None = None,
        customer_fee_percent: int | None = None,
        client_id: str | None = None,
        **extra: Any,
    ) -> dict[str, Any]:
        if "ttl" in extra:
            raise PaymosConfigurationError(
                "Parameter 'ttl' is not supported by Paymos POST /v1/invoices."
            )
        if extra:
            unexpected = ", ".join(sorted(extra.keys()))
            raise PaymosConfigurationError(
                f"Unsupported create_invoice parameter(s): {unexpected}."
            )

        clean_project_id = _require_non_empty(project_id, "project_id")
        clean_amount = _require_non_empty(amount, "amount")
        if not _DECIMAL_AMOUNT_RE.match(clean_amount) or Decimal(clean_amount) <= 0:
            raise PaymosConfigurationError(
                "Parameter 'amount' must be a positive decimal string (e.g. '50.00')."
            )
        clean_currency = _require_non_empty(currency, "currency").upper()
        clean_order_id = _require_non_empty(external_order_id, "external_order_id")
        if clean_order_id.lower().startswith("wgt_"):
            raise PaymosConfigurationError(
                "Parameter 'external_order_id' must not start with the reserved 'wgt_' prefix."
            )
        if len(clean_order_id) > 128:
            raise PaymosConfigurationError("Parameter 'external_order_id' must be at most 128 characters.")

        payload: dict[str, Any] = {
            "project_id": clean_project_id,
            "amount": clean_amount,
            "currency": clean_currency,
            "external_order_id": clean_order_id,
        }

        clean_network = parse_optional_str(network)
        if clean_network is not None:
            payload["network"] = clean_network.upper()

        if customer_fee_percent is not None:
            fee_pct = parse_optional_int(customer_fee_percent, "customer_fee_percent")
            if fee_pct is not None:
                if fee_pct < 0 or fee_pct > 100:
                    raise PaymosConfigurationError(
                        "Parameter 'customer_fee_percent' must be an integer between 0 and 100."
                    )
                payload["customer_fee_percent"] = fee_pct

        clean_client_id = parse_optional_str(client_id)
        if clean_client_id is not None:
            if len(clean_client_id) > 200:
                raise PaymosConfigurationError("Parameter 'client_id' must be at most 200 characters.")
            payload["client_id"] = clean_client_id

        return self.request("POST", "/v1/invoices", payload=payload)

    def get_invoice(self, invoice_id: str) -> dict[str, Any]:
        clean_id = _require_non_empty(invoice_id, "invoice_id")
        return self.request("GET", f"/v1/invoices/{encode_path_segment(clean_id)}")

    def list_invoices(
        self,
        *,
        project_id: str | None = None,
        status: str | Sequence[str] | None = None,
        external_order_id: str | None = None,
        created_from: int | None = None,
        created_to: int | None = None,
        limit: int | None = None,
        cursor: str | None = None,
    ) -> dict[str, Any]:
        filters: dict[str, Any] = {}

        clean_project_id = parse_optional_str(project_id)
        if clean_project_id is not None:
            filters["project_id"] = clean_project_id

        if status is not None:
            if isinstance(status, str):
                status_items = [item.strip() for item in status.split(",") if item.strip()]
            else:
                status_items = [str(item).strip() for item in status if str(item).strip()]
            if status_items:
                invalid = [s for s in status_items if s not in VALID_INVOICE_STATUSES]
                if invalid:
                    raise PaymosConfigurationError(
                        f"Invalid invoice status filter(s): {', '.join(invalid)}."
                    )
                filters["status"] = status_items[0] if len(status_items) == 1 else status_items

        clean_order_id = parse_optional_str(external_order_id)
        if clean_order_id is not None:
            filters["external_order_id"] = clean_order_id

        clean_from = parse_optional_int(created_from, "created_from")
        if clean_from is not None:
            if clean_from < 0:
                raise PaymosConfigurationError("Parameter 'created_from' must be a non-negative Unix timestamp.")
            filters["created_from"] = clean_from

        clean_to = parse_optional_int(created_to, "created_to")
        if clean_to is not None:
            if clean_to < 0:
                raise PaymosConfigurationError("Parameter 'created_to' must be a non-negative Unix timestamp.")
            filters["created_to"] = clean_to

        clean_limit = parse_optional_int(limit, "limit")
        if clean_limit is not None:
            if clean_limit < 1 or clean_limit > 100:
                raise PaymosConfigurationError("Parameter 'limit' must be an integer between 1 and 100.")
            filters["limit"] = clean_limit

        clean_cursor = parse_optional_str(cursor)
        if clean_cursor is not None:
            filters["cursor"] = clean_cursor

        return self.request("GET", "/v1/invoices", query=filters)

    def cancel_invoice(self, invoice_id: str, reason: str) -> dict[str, Any]:
        clean_id = _require_non_empty(invoice_id, "invoice_id")
        if not isinstance(reason, str) or not reason.strip() or len(reason) > 500:
            raise PaymosConfigurationError(
                "Parameter 'reason' is required and must contain 1 to 500 characters."
            )
        return self.request(
            "POST",
            f"/v1/invoices/{encode_path_segment(clean_id)}/cancel",
            payload={"reason": reason},
        )

    def simulate_sandbox_invoice(self, invoice_id: str, stage: str) -> dict[str, Any]:
        clean_id = _require_non_empty(invoice_id, "invoice_id")
        clean_stage = _require_non_empty(stage, "stage").lower()
        if clean_stage not in VALID_SIMULATE_STAGES:
            raise PaymosConfigurationError(
                "Parameter 'stage' must be one of: paid, overpaid, underpay, cancel."
            )
        return self.request(
            "POST",
            f"/v1/sandbox/invoices/{encode_path_segment(clean_id)}/simulate-payment",
            payload={"stage": clean_stage},
        )

    def create_payment_channel(self, *, project_id: str, external_id: str) -> dict[str, Any]:
        clean_project_id = _require_non_empty(project_id, "project_id")
        clean_external_id = _require_non_empty(external_id, "external_id")
        return self.request(
            "POST",
            "/v1/payment-channels",
            payload={"project_id": clean_project_id, "external_id": clean_external_id},
        )

    def get_payment_channel(self, channel_id: str) -> dict[str, Any]:
        clean_id = _require_non_empty(channel_id, "channel_id")
        return self.request("GET", f"/v1/payment-channels/{encode_path_segment(clean_id)}")

    def create_refund(
        self,
        *,
        invoice_id: str,
        mode: str,
        external_order_id: str,
        **extra: Any,
    ) -> dict[str, Any]:
        """Create a server-calculated refund.

        Paymos CreateRefundRequest enforces strict member validation: only
        ``invoice_id``, ``mode`` (``full`` | ``overpayment``), and ``external_order_id``
        are accepted. Amount, currency, network, and destination address are server-calculated.
        """
        if extra:
            disallowed = ", ".join(sorted(extra.keys()))
            raise PaymosConfigurationError(
                f"Disallowed create_refund parameter(s): {disallowed}. "
                "Paymos refunds strictly accept only invoice_id, mode, and external_order_id "
                "(amount, currency, network, and destination address are server-calculated)."
            )
        clean_invoice_id = _require_non_empty(invoice_id, "invoice_id")
        clean_mode = _require_non_empty(mode, "mode").lower()
        if clean_mode not in VALID_REFUND_MODES:
            raise PaymosConfigurationError(
                "Parameter 'mode' must be 'full' or 'overpayment'."
            )
        clean_order_id = _require_non_empty(external_order_id, "external_order_id")

        return self.request(
            "POST",
            "/v1/refunds",
            payload={
                "invoice_id": clean_invoice_id,
                "mode": clean_mode,
                "external_order_id": clean_order_id,
            },
        )
