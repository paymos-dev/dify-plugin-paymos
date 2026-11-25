from __future__ import annotations

from collections.abc import Generator
from typing import Any

from dify_plugin import Tool
from dify_plugin.entities.tool import ToolInvokeMessage

from client.paymos_client import PaymosClient


class CreatePaymentChannelTool(Tool):
    """Dify tool for idempotently creating or fetching a Paymos Payment Channel."""

    def _invoke(self, tool_parameters: dict[str, Any]) -> Generator[ToolInvokeMessage, None, None]:
        client = PaymosClient.from_credentials(self.runtime.credentials)
        result = client.create_payment_channel(
            project_id=str(tool_parameters.get("project_id") or ""),
            external_id=str(tool_parameters.get("external_id") or ""),
        )
        yield self.create_json_message(result)
