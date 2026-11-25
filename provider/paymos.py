from __future__ import annotations

from typing import Any

from dify_plugin import ToolProvider
from dify_plugin.errors.tool import ToolProviderCredentialValidationError

from client.paymos_client import PaymosClient, PaymosError


class PaymosProvider(ToolProvider):
    """Dify ToolProvider for the Paymos Payment API."""

    def _validate_credentials(self, credentials: dict[str, Any]) -> None:
        try:
            client = PaymosClient.from_credentials(credentials)
            client.validate_connection()
        except PaymosError as exc:
            raise ToolProviderCredentialValidationError(str(exc)) from exc
        except Exception as exc:
            raise ToolProviderCredentialValidationError(
                f"Failed to validate Paymos credentials: {exc}"
            ) from exc
