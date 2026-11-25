from __future__ import annotations

from collections.abc import Generator
from typing import Any

from dify_plugin import Tool
from dify_plugin.entities.tool import ToolInvokeMessage

from client.paymos_client import PaymosClient, parse_optional_int, parse_optional_str


class ListInvoicesTool(Tool):
    """Dify tool for listing Paymos invoices (GET /v1/invoices)."""

    def _invoke(self, tool_parameters: dict[str, Any]) -> Generator[ToolInvokeMessage, None, None]:
        client = PaymosClient.from_credentials(self.runtime.credentials)
        raw_status = tool_parameters.get("status")
        status: str | list[str] | None
        if isinstance(raw_status, list):
            status = [str(item) for item in raw_status]
        else:
            status = parse_optional_str(raw_status)

        result = client.list_invoices(
            project_id=parse_optional_str(tool_parameters.get("project_id")),
            status=status,
            external_order_id=parse_optional_str(tool_parameters.get("external_order_id")),
            created_from=parse_optional_int(tool_parameters.get("created_from"), "created_from"),
            created_to=parse_optional_int(tool_parameters.get("created_to"), "created_to"),
            limit=parse_optional_int(tool_parameters.get("limit"), "limit"),
            cursor=parse_optional_str(tool_parameters.get("cursor")),
        )
        yield self.create_json_message(result)
