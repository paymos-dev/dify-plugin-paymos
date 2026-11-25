from __future__ import annotations

from collections.abc import Generator
from typing import Any

from dify_plugin import Tool
from dify_plugin.entities.tool import ToolInvokeMessage

from client.paymos_client import PaymosClient


class CancelInvoiceTool(Tool):
    """Dify tool for cancelling an open Paymos invoice (POST /v1/invoices/{invoice_id}/cancel)."""

    def _invoke(self, tool_parameters: dict[str, Any]) -> Generator[ToolInvokeMessage, None, None]:
        client = PaymosClient.from_credentials(self.runtime.credentials)
        result = client.cancel_invoice(
            invoice_id=str(tool_parameters.get("invoice_id") or ""),
            reason=str(tool_parameters.get("reason") or ""),
        )
        yield self.create_json_message(result)
