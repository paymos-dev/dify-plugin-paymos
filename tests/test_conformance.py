from __future__ import annotations

import ast
import importlib.util
import json
import sys
import types
import unittest
from collections.abc import Mapping
from pathlib import Path
from typing import Any
from unittest.mock import patch

PLUGIN_ROOT = Path(__file__).resolve().parent.parent
CONTRACT_PATH = PLUGIN_ROOT.parent / "sdk-conformance" / "contract.json"

if str(PLUGIN_ROOT) not in sys.path:
    sys.path.insert(0, str(PLUGIN_ROOT))

from client.paymos_client import (  # noqa: E402
    HttpResponse,
    PaymosApiError,
    PaymosClient,
    PaymosConfigurationError,
    authorization_header,
    build_query,
    encode_path_segment,
    normalize_base_url,
    parse_problem_details,
    sha256_hex,
    sign,
    string_to_sign,
    validate_credentials,
)

EXPECTED_TOOL_FILES: dict[str, str] = {
    "create_invoice.py": "CreateInvoiceTool",
    "get_invoice.py": "GetInvoiceTool",
    "list_invoices.py": "ListInvoicesTool",
    "cancel_invoice.py": "CancelInvoiceTool",
    "simulate_sandbox_invoice.py": "SimulateSandboxInvoiceTool",
    "create_payment_channel.py": "CreatePaymentChannelTool",
    "get_payment_channel.py": "GetPaymentChannelTool",
    "create_refund.py": "CreateRefundTool",
}


class RecordingTransport:
    def __init__(self, responses: list[HttpResponse] | None = None) -> None:
        self.calls: list[dict[str, Any]] = []
        self._responses = list(responses) if responses is not None else [HttpResponse(200, "{}", {})]

    def __call__(
        self,
        method: str,
        url: str,
        headers: Mapping[str, str],
        body: bytes | None,
        timeout: float,
    ) -> HttpResponse:
        self.calls.append(
            {
                "method": method,
                "url": url,
                "headers": dict(headers),
                "body": body.decode("utf-8") if body is not None else "",
                "timeout": timeout,
            }
        )
        if len(self._responses) > 1:
            return self._responses.pop(0)
        return self._responses[0]


def _load_contract() -> dict[str, Any]:
    return json.loads(CONTRACT_PATH.read_text(encoding="utf-8"))


def _make_dify_stub_modules() -> dict[str, types.ModuleType]:
    dify_mod = types.ModuleType("dify_plugin")
    entities_mod = types.ModuleType("dify_plugin.entities")
    entities_tool_mod = types.ModuleType("dify_plugin.entities.tool")
    errors_mod = types.ModuleType("dify_plugin.errors")
    errors_tool_mod = types.ModuleType("dify_plugin.errors.tool")

    class ToolProviderCredentialValidationError(Exception):
        pass

    class ToolInvokeMessage:
        def __init__(self, payload: dict[str, Any]) -> None:
            self.payload = payload

    class ToolProvider:
        pass

    class Tool:
        def __init__(self, credentials: dict[str, Any]) -> None:
            self.runtime = types.SimpleNamespace(credentials=credentials)

        def create_json_message(self, payload: dict[str, Any]) -> ToolInvokeMessage:
            return ToolInvokeMessage(payload)

    dify_mod.Tool = Tool
    dify_mod.ToolProvider = ToolProvider
    entities_tool_mod.ToolInvokeMessage = ToolInvokeMessage
    errors_tool_mod.ToolProviderCredentialValidationError = ToolProviderCredentialValidationError
    dify_mod.entities = entities_mod
    entities_mod.tool = entities_tool_mod
    dify_mod.errors = errors_mod
    errors_mod.tool = errors_tool_mod

    return {
        "dify_plugin": dify_mod,
        "dify_plugin.entities": entities_mod,
        "dify_plugin.entities.tool": entities_tool_mod,
        "dify_plugin.errors": errors_mod,
        "dify_plugin.errors.tool": errors_tool_mod,
    }


def _load_module_from_path(module_name: str, file_path: Path) -> types.ModuleType:
    spec = importlib.util.spec_from_file_location(module_name, file_path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class SigningConformanceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.contract = _load_contract()

    def test_post_signing_vector(self) -> None:
        vec = self.contract["vectors"]["post_signing"]
        self.assertEqual(sha256_hex(vec["body"]), vec["body_sha256"])
        canonical = string_to_sign(
            vec["timestamp"], vec["method"], vec["path"], vec["query"], vec["body"]
        )
        self.assertEqual(sign(vec["api_secret"], canonical), vec["signature"])
        self.assertEqual(
            authorization_header(
                vec["api_key"],
                vec["api_secret"],
                vec["timestamp"],
                vec["method"],
                vec["path"],
                vec["query"],
                vec["body"],
            ),
            vec["authorization"],
        )

    def test_post_empty_body_signing_vector(self) -> None:
        vec = self.contract["vectors"]["post_empty_body_signing"]
        self.assertEqual(sha256_hex(vec["body"]), "")
        self.assertNotEqual(
            sha256_hex(""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        )
        canonical = string_to_sign(
            vec["timestamp"], vec["method"], vec["path"], vec["query"], vec["body"]
        )
        self.assertTrue(canonical.endswith("\n"))
        self.assertEqual(sign(vec["api_secret"], canonical), vec["signature"])
        self.assertEqual(
            authorization_header(
                vec["api_key"],
                vec["api_secret"],
                vec["timestamp"],
                vec["method"],
                vec["path"],
                vec["query"],
                vec["body"],
            ),
            vec["authorization"],
        )

    def test_get_query_signing_vector(self) -> None:
        vec = self.contract["vectors"]["get_query_signing"]
        query = build_query(
            {
                "status": ["paid_over", "paid"],
                "project_id": "prj/a",
                "limit": 50,
                "cursor": None,
            }
        )
        self.assertEqual(query, vec["query"])
        canonical = string_to_sign(
            vec["timestamp"], vec["method"], vec["path"], query, vec["body"]
        )
        self.assertEqual(sign(vec["api_secret"], canonical), vec["signature"])

    def test_client_sends_canonical_signed_headers(self) -> None:
        vec = self.contract["vectors"]["post_signing"]
        transport = RecordingTransport([HttpResponse(201, '{"invoice_id":"inv_1"}', {})])
        client = PaymosClient(
            vec["api_key"],
            vec["api_secret"],
            transport=transport,
            clock=lambda: int(vec["timestamp"]),
        )
        result = client.request("POST", "/v1/invoices", payload={"amount": "10.00"})
        self.assertEqual(result, {"invoice_id": "inv_1"})
        self.assertEqual(len(transport.calls), 1)
        call = transport.calls[0]
        self.assertEqual(call["headers"]["Authorization"], vec["authorization"])
        self.assertEqual(call["headers"]["X-Request-Timestamp"], vec["timestamp"])
        self.assertEqual(call["body"], vec["body"])
        self.assertTrue(call["headers"]["User-Agent"].startswith("paymos-"))


class ProblemDetailsConformanceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.contract = _load_contract()

    def test_flat_problem_details_vector(self) -> None:
        vec = self.contract["vectors"]["problem_details"]["flat"]
        raw = json.dumps(vec)
        parsed = parse_problem_details(raw, status=vec["status"])
        self.assertIsNotNone(parsed)
        assert parsed is not None
        self.assertEqual(parsed["code"], "conflict")
        self.assertEqual(parsed["field"], "client_request_id")
        self.assertEqual(parsed["detail"], "Conflict.")
        self.assertEqual(parsed["errors"], [])

        err = PaymosApiError(vec["status"], raw)
        self.assertEqual(err.status, 409)
        self.assertEqual(err.code, "conflict")
        self.assertEqual(err.field, "client_request_id")
        self.assertEqual(err.detail, "Conflict.")
        self.assertEqual(err.errors, [])

    def test_multi_problem_details_preserves_top_level_code_and_errors(self) -> None:
        vec = self.contract["vectors"]["problem_details"]["multi"]
        raw = json.dumps(vec)
        parsed = parse_problem_details(raw, status=vec["status"])
        self.assertIsNotNone(parsed)
        assert parsed is not None
        self.assertEqual(parsed["code"], "validation_failed")
        self.assertNotEqual(parsed["code"], "field_required")
        self.assertIsNone(parsed["field"])
        self.assertEqual(parsed["detail"], "Validation failed.")
        self.assertEqual(parsed["errors"], vec["errors"])

        transport = RecordingTransport(
            [HttpResponse(400, raw, {"Content-Type": "application/problem+json"})]
        )
        client = PaymosClient("pk_test_demo", "unit-secret", transport=transport, max_retries=0)
        with self.assertRaises(PaymosApiError) as ctx:
            client.get_invoice("inv_bad")

        err = ctx.exception
        self.assertEqual(err.status, 400)
        self.assertEqual(err.code, "validation_failed")
        self.assertIsNone(err.field)
        self.assertEqual(err.detail, "Validation failed.")
        self.assertEqual(len(err.errors), 1)
        self.assertEqual(err.errors[0]["code"], "field_required")
        self.assertEqual(err.errors[0]["field"], "address")
        self.assertEqual(err.errors[0]["message"], "Required.")


class CredentialAndSandboxGuardTests(unittest.TestCase):
    def test_rejects_payout_rk_keys_before_network(self) -> None:
        transport = RecordingTransport()
        for bad_key in ("rk_live_test", "rk_test_demo"):
            with self.subTest(bad_key=bad_key):
                with self.assertRaises(PaymosConfigurationError) as ctx:
                    PaymosClient(bad_key, "unit-secret", transport=transport)
                self.assertIn("rk_", str(ctx.exception))
        self.assertEqual(transport.calls, [])

    def test_rejects_unknown_prefixes_and_missing_credentials_before_network(self) -> None:
        transport = RecordingTransport()
        for bad_key, bad_secret in (
            ("", "unit-secret"),
            ("   ", "unit-secret"),
            ("pk_staging_123", "unit-secret"),
            ("unknown_key_123", "unit-secret"),
            ("pk_test_demo", ""),
        ):
            with self.subTest(bad_key=bad_key, bad_secret=bad_secret):
                with self.assertRaises(PaymosConfigurationError):
                    PaymosClient(bad_key, bad_secret, transport=transport)
        self.assertEqual(transport.calls, [])

    def test_accepts_pk_live_and_pk_test_and_enforces_https_base_url(self) -> None:
        prod = validate_credentials("pk_live_demo", "unit-secret", "https://api.paymos.io/")
        self.assertEqual(prod.environment, "production")
        self.assertEqual(prod.base_url, "https://api.paymos.io")

        sandbox = validate_credentials("pk_test_demo", "unit-secret", "http://127.0.0.1:8080/")
        self.assertEqual(sandbox.environment, "sandbox")
        self.assertEqual(sandbox.base_url, "http://127.0.0.1:8080")

        self.assertEqual(normalize_base_url("http://localhost:9000/"), "http://localhost:9000")

        with self.assertRaises(PaymosConfigurationError):
            normalize_base_url("http://api.paymos.io")
        with self.assertRaises(PaymosConfigurationError):
            normalize_base_url("https://user:pass@api.paymos.io")

    def test_rejects_sandbox_endpoint_with_pk_live_before_network(self) -> None:
        transport = RecordingTransport()
        client = PaymosClient("pk_live_demo", "unit-secret", transport=transport)
        with self.assertRaises(PaymosConfigurationError) as ctx:
            client.simulate_sandbox_invoice("inv_123", "paid")
        self.assertIn("pk_test_", str(ctx.exception))
        self.assertEqual(transport.calls, [])

    def test_allows_sandbox_endpoint_with_pk_test(self) -> None:
        transport = RecordingTransport([HttpResponse(200, '{"invoice_id":"inv_123","status":"paid"}', {})])
        client = PaymosClient("pk_test_demo", "unit-secret", transport=transport, clock=lambda: 1700000000)
        result = client.simulate_sandbox_invoice("inv_123", "paid")
        self.assertEqual(result["status"], "paid")
        self.assertEqual(len(transport.calls), 1)
        self.assertEqual(transport.calls[0]["method"], "POST")
        self.assertEqual(
            transport.calls[0]["url"],
            "https://api.paymos.io/v1/sandbox/invoices/inv_123/simulate-payment",
        )
        self.assertEqual(json.loads(transport.calls[0]["body"]), {"stage": "paid"})


class StrictWireDtoTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.contract = _load_contract()

    def test_validate_connection_calls_get_invoices_limit_1(self) -> None:
        transport = RecordingTransport([HttpResponse(200, '{"items":[],"next_cursor":null}', {})])
        client = PaymosClient("pk_test_demo", "unit-secret", transport=transport, clock=lambda: 1700000000)
        client.validate_connection()
        self.assertEqual(len(transport.calls), 1)
        self.assertEqual(transport.calls[0]["method"], "GET")
        self.assertEqual(transport.calls[0]["url"], "https://api.paymos.io/v1/invoices?limit=1")
        self.assertEqual(transport.calls[0]["body"], "")

    def test_create_invoice_strict_guards_and_payload(self) -> None:
        transport = RecordingTransport([HttpResponse(201, '{"invoice_id":"inv_1"}', {})])
        client = PaymosClient("pk_test_demo", "unit-secret", transport=transport, clock=lambda: 1700000000)

        with self.assertRaises(PaymosConfigurationError):
            client.create_invoice(
                project_id="prj_1",
                amount="25.00",
                currency="USD",
                external_order_id="order-1",
                ttl=3600,
            )

        with self.assertRaises(PaymosConfigurationError):
            client.create_invoice(
                project_id="prj_1",
                amount="25.00",
                currency="USD",
                external_order_id="wgt_reserved",
            )

        with self.assertRaises(PaymosConfigurationError):
            client.create_invoice(
                project_id="prj_1",
                amount="25.00",
                currency="USD",
                external_order_id="WGT_reserved",
            )

        self.assertEqual(transport.calls, [])

        client.create_invoice(
            project_id="prj_1",
            amount="25.00",
            currency="usdt",
            external_order_id="order-1",
            network="trc20",
            customer_fee_percent=50,
            client_id="cust-42",
        )
        self.assertEqual(len(transport.calls), 1)
        self.assertEqual(
            json.loads(transport.calls[0]["body"]),
            {
                "project_id": "prj_1",
                "amount": "25.00",
                "currency": "USDT",
                "external_order_id": "order-1",
                "network": "TRC20",
                "customer_fee_percent": 50,
                "client_id": "cust-42",
            },
        )

    def test_cancel_invoice_requires_reason_up_to_500_chars(self) -> None:
        transport = RecordingTransport([HttpResponse(200, '{"invoice_id":"inv_1","status":"cancelled"}', {})])
        client = PaymosClient("pk_test_demo", "unit-secret", transport=transport, clock=lambda: 1700000000)

        for bad_reason in ("", "   ", "x" * 501):
            with self.assertRaises(PaymosConfigurationError):
                client.cancel_invoice("inv_1", bad_reason)
        self.assertEqual(transport.calls, [])

        max_reason = "r" * 500
        client.cancel_invoice("inv/1", max_reason)
        self.assertEqual(len(transport.calls), 1)
        self.assertEqual(
            transport.calls[0]["url"],
            f"https://api.paymos.io/v1/invoices/{encode_path_segment('inv/1')}/cancel",
        )
        self.assertEqual(json.loads(transport.calls[0]["body"]), {"reason": max_reason})

    def test_create_refund_strict_payload_and_rejected_fields(self) -> None:
        refund_create = self.contract["vectors"]["refunds"]["create"]
        refund_over = self.contract["vectors"]["refunds"]["overpayment"]
        transport = RecordingTransport([HttpResponse(201, '{"withdrawal_id":"wdr_1"}', {})])
        client = PaymosClient("pk_test_demo", "unit-secret", transport=transport, clock=lambda: 1700000000)

        for forbidden_field in refund_create["rejected_fields"]:
            with self.subTest(forbidden_field=forbidden_field):
                with self.assertRaises(PaymosConfigurationError):
                    client.create_refund(
                        invoice_id="inv_1",
                        mode="full",
                        external_order_id="ref-1",
                        **{forbidden_field: "forbidden"},
                    )

        with self.assertRaises(PaymosConfigurationError):
            client.create_refund(invoice_id="inv_1", mode="partial", external_order_id="ref-2")

        self.assertEqual(transport.calls, [])

        client.create_refund(**refund_create["body"])
        client.create_refund(**refund_over["body"])
        self.assertEqual(len(transport.calls), 2)
        self.assertEqual(transport.calls[0]["url"], "https://api.paymos.io/v1/refunds")
        self.assertEqual(json.loads(transport.calls[0]["body"]), refund_create["body"])
        self.assertEqual(set(json.loads(transport.calls[0]["body"]).keys()), {"invoice_id", "mode", "external_order_id"})
        self.assertEqual(json.loads(transport.calls[1]["body"]), refund_over["body"])

    def test_payment_channel_and_list_invoices_endpoints(self) -> None:
        transport = RecordingTransport([HttpResponse(200, '{"ok":true}', {})])
        client = PaymosClient("pk_test_demo", "unit-secret", transport=transport, clock=lambda: 1700000000)

        client.create_payment_channel(project_id="prj_1", external_id="cust_99")
        client.get_payment_channel("pch/99")
        client.list_invoices(project_id="prj_1", status="paid_over,paid", limit=10)

        self.assertEqual(len(transport.calls), 3)
        self.assertEqual(transport.calls[0]["url"], "https://api.paymos.io/v1/payment-channels")
        self.assertEqual(
            json.loads(transport.calls[0]["body"]),
            {"project_id": "prj_1", "external_id": "cust_99"},
        )
        self.assertEqual(transport.calls[1]["url"], "https://api.paymos.io/v1/payment-channels/pch%2F99")
        self.assertEqual(
            transport.calls[2]["url"],
            "https://api.paymos.io/v1/invoices?limit=10&project_id=prj_1&status=paid&status=paid_over",
        )


class DifyPluginStructureTests(unittest.TestCase):
    def test_each_tool_file_defines_strictly_one_tool_subclass(self) -> None:
        tools_dir = PLUGIN_ROOT / "tools"
        actual_py_files = sorted(p.name for p in tools_dir.glob("*.py"))
        self.assertEqual(actual_py_files, sorted(EXPECTED_TOOL_FILES.keys()))

        for filename, expected_class_name in EXPECTED_TOOL_FILES.items():
            file_path = tools_dir / filename
            with self.subTest(file=filename):
                tree = ast.parse(file_path.read_text(encoding="utf-8"), filename=str(file_path))
                tool_classes: list[ast.ClassDef] = []
                for node in tree.body:
                    if not isinstance(node, ast.ClassDef):
                        continue
                    for base in node.bases:
                        if (isinstance(base, ast.Name) and base.id == "Tool") or (
                            isinstance(base, ast.Attribute) and base.attr == "Tool"
                        ):
                            tool_classes.append(node)
                            break

                self.assertEqual(
                    len(tool_classes),
                    1,
                    f"{filename} must define strictly 1 Tool subclass for load_single_subclass_from_source",
                )
                self.assertEqual(tool_classes[0].name, expected_class_name)
                method_names = {
                    item.name for item in tool_classes[0].body if isinstance(item, ast.FunctionDef)
                }
                self.assertIn("_invoke", method_names)

    def test_provider_defines_strictly_one_tool_provider_subclass(self) -> None:
        provider_path = PLUGIN_ROOT / "provider" / "paymos.py"
        tree = ast.parse(provider_path.read_text(encoding="utf-8"), filename=str(provider_path))
        provider_classes = [
            node
            for node in tree.body
            if isinstance(node, ast.ClassDef)
            and any(
                (isinstance(base, ast.Name) and base.id == "ToolProvider")
                or (isinstance(base, ast.Attribute) and base.attr == "ToolProvider")
                for base in node.bases
            )
        ]
        self.assertEqual(len(provider_classes), 1)
        self.assertEqual(provider_classes[0].name, "PaymosProvider")

    def test_provider_and_tools_runtime_with_dify_stubs(self) -> None:
        stubs = _make_dify_stub_modules()
        with patch.dict(sys.modules, stubs):
            provider_mod = _load_module_from_path(
                "_test_paymos_provider", PLUGIN_ROOT / "provider" / "paymos.py"
            )
            err_cls = stubs["dify_plugin.errors.tool"].ToolProviderCredentialValidationError
            provider = provider_mod.PaymosProvider()

            with self.assertRaises(err_cls):
                provider._validate_credentials(
                    {"public_key": "rk_live_forbidden", "secret_key": "unit-secret"}
                )

            transport = RecordingTransport([HttpResponse(200, '{"items":[],"next_cursor":null}', {})])
            with patch("client.paymos_client._default_transport", new=transport):
                provider._validate_credentials(
                    {"public_key": "pk_test_demo", "secret_key": "unit-secret"}
                )
                self.assertEqual(len(transport.calls), 1)
                self.assertEqual(transport.calls[0]["url"], "https://api.paymos.io/v1/invoices?limit=1")

                refund_mod = _load_module_from_path(
                    "_test_create_refund_tool", PLUGIN_ROOT / "tools" / "create_refund.py"
                )
                refund_tool = refund_mod.CreateRefundTool(
                    {"public_key": "pk_test_demo", "secret_key": "unit-secret"}
                )
                with self.assertRaises(PaymosConfigurationError):
                    list(
                        refund_tool._invoke(
                            {
                                "invoice_id": "inv_1",
                                "mode": "full",
                                "external_order_id": "ref-1",
                                "amount": "10.00",
                            }
                        )
                    )
                messages = list(
                    refund_tool._invoke(
                        {
                            "invoice_id": "inv_1",
                            "mode": "full",
                            "external_order_id": "ref-1",
                        }
                    )
                )
                self.assertEqual(len(messages), 1)
                self.assertEqual(
                    json.loads(transport.calls[-1]["body"]),
                    {"invoice_id": "inv_1", "mode": "full", "external_order_id": "ref-1"},
                )

    def test_required_manifest_and_assets_present(self) -> None:
        manifest_text = (PLUGIN_ROOT / "manifest.yaml").read_text(encoding="utf-8")
        for needle in (
            "version: 0.1.0",
            "type: plugin",
            "author: paymos-dev",
            "name: paymos",
            "icon: icon.svg",
            "provider/paymos.yaml",
            "privacy: PRIVACY.md",
            'minimum_dify_version: "1.0.0"',
            "- finance",
            "- business",
        ):
            self.assertIn(needle, manifest_text)

        self.assertTrue((PLUGIN_ROOT / "_assets" / "icon.svg").is_file())
        self.assertTrue((PLUGIN_ROOT / "PRIVACY.md").is_file())
        self.assertTrue((PLUGIN_ROOT / "README.md").is_file())

        refund_yaml = (PLUGIN_ROOT / "tools" / "create_refund.yaml").read_text(encoding="utf-8")
        for forbidden_param in ("name: amount", "name: currency", "name: network", "name: destination_address"):
            self.assertNotIn(forbidden_param, refund_yaml)


if __name__ == "__main__":
    unittest.main()
