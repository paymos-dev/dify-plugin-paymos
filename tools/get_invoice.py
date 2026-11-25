from __future__ import annotations

from collections.abc import Generator
from typing import Any

from dify_plugin import Tool
from dify_plugin.entities.tool import ToolInvokeMessage

from client.paymos_client import PaymosClient


class GetInvoiceTool(Tool):
    """Dify tool for fetching a Paymos invoice by ID (GET /v1/invoices/{invoice_id})."""

    def _invoke(self, tool_parameters: dict[str, Any]) -> Generator[ToolInvokeMessage, None, None]:
        client = PaymosClient.from_credentials(self.runtime.credentials)
        result = client.get_invoice(str(tool_parameters.get("invoice_id") or ""))
        yield self.create_json_message(result)
