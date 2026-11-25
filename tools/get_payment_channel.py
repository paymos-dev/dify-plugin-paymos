from __future__ import annotations

from collections.abc import Generator
from typing import Any

from dify_plugin import Tool
from dify_plugin.entities.tool import ToolInvokeMessage

from client.paymos_client import PaymosClient


class GetPaymentChannelTool(Tool):
    """Dify tool for retrieving a Paymos Payment Channel by ID."""

    def _invoke(self, tool_parameters: dict[str, Any]) -> Generator[ToolInvokeMessage, None, None]:
        client = PaymosClient.from_credentials(self.runtime.credentials)
        result = client.get_payment_channel(str(tool_parameters.get("channel_id") or ""))
        yield self.create_json_message(result)
