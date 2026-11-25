from __future__ import annotations

from collections.abc import Generator
from typing import Any

from dify_plugin import Tool
from dify_plugin.entities.tool import ToolInvokeMessage

from client.paymos_client import PaymosClient


class SimulateSandboxInvoiceTool(Tool):
    """Dify tool for simulating a Sandbox invoice payment outcome (pk_test_ only)."""

    def _invoke(self, tool_parameters: dict[str, Any]) -> Generator[ToolInvokeMessage, None, None]:
        client = PaymosClient.from_credentials(self.runtime.credentials)
        result = client.simulate_sandbox_invoice(
            invoice_id=str(tool_parameters.get("invoice_id") or ""),
            stage=str(tool_parameters.get("stage") or ""),
        )
        yield self.create_json_message(result)
