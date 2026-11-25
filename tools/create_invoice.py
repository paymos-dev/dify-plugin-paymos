from __future__ import annotations

from collections.abc import Generator
from typing import Any

from dify_plugin import Tool
from dify_plugin.entities.tool import ToolInvokeMessage

from client.paymos_client import PaymosClient, parse_optional_int, parse_optional_str

_ALLOWED_PARAMETERS = frozenset(
    {
        "project_id",
        "amount",
        "currency",
        "external_order_id",
        "network",
        "customer_fee_percent",
        "client_id",
    }
)


class CreateInvoiceTool(Tool):
    """Dify tool for creating a Paymos payment invoice (POST /v1/invoices)."""

    def _invoke(self, tool_parameters: dict[str, Any]) -> Generator[ToolInvokeMessage, None, None]:
        extra = {
            key: value
            for key, value in tool_parameters.items()
            if key not in _ALLOWED_PARAMETERS and value not in (None, "")
        }
        client = PaymosClient.from_credentials(self.runtime.credentials)
        result = client.create_invoice(
            project_id=str(tool_parameters.get("project_id") or ""),
            amount=str(tool_parameters.get("amount") or ""),
            currency=str(tool_parameters.get("currency") or ""),
            external_order_id=str(tool_parameters.get("external_order_id") or ""),
            network=parse_optional_str(tool_parameters.get("network")),
            customer_fee_percent=parse_optional_int(
                tool_parameters.get("customer_fee_percent"), "customer_fee_percent"
            ),
            client_id=parse_optional_str(tool_parameters.get("client_id")),
            **extra,
        )
        yield self.create_json_message(result)
