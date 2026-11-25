from __future__ import annotations

from collections.abc import Generator
from typing import Any

from dify_plugin import Tool
from dify_plugin.entities.tool import ToolInvokeMessage

from client.paymos_client import PaymosClient

_ALLOWED_PARAMETERS = frozenset({"invoice_id", "mode", "external_order_id"})


class CreateRefundTool(Tool):
    """Dify tool for creating a server-calculated Paymos invoice refund (POST /v1/refunds)."""

    def _invoke(self, tool_parameters: dict[str, Any]) -> Generator[ToolInvokeMessage, None, None]:
        extra = {
            key: value
            for key, value in tool_parameters.items()
            if key not in _ALLOWED_PARAMETERS and value not in (None, "")
        }
        client = PaymosClient.from_credentials(self.runtime.credentials)
        result = client.create_refund(
            invoice_id=str(tool_parameters.get("invoice_id") or ""),
            mode=str(tool_parameters.get("mode") or ""),
            external_order_id=str(tool_parameters.get("external_order_id") or ""),
            **extra,
        )
        yield self.create_json_message(result)
