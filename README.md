# Paymos Plugin for Dify

Official **Paymos** tool plugin for Dify workflows and AI agents. Connect your Dify applications directly to the Paymos Payment API to create and manage invoices, provision permanent customer Payment Channels, run Sandbox simulations, and issue server-calculated invoice refunds.

## About Paymos

Paymos is a custodial crypto payment processor supporting **5 assets** — 4 stablecoins (**USDT**, **USDC**, **USD1**, **DAI**) and 1 gold-backed asset (**XAUT**) — across **13 deposit networks** (`TRC20`, `ERC20`, `BEP20`, `POLYGON`, `ARBITRUM`, `OPTIMISM`, `BASE`, `TON`, `AVAX`, `SOL`, `NEAR`, `SUI`, `PLASMA`) and **11 withdrawal networks** (NEAR and Sui are deposit-only).

- **Pricing:** 1.0% standard incoming processing fee (configurable 0–100% pass-through to the payer) and 0% Paymos withdrawal commission (only the route's disclosed subsidised network fee applies).
- **Onboarding:** Self-serve sign-up at [app.paymos.io](https://app.paymos.io) with no KYC or KYB documents required at sign-up, plus full Sandbox testing before going live.
- **Settlement:** Balances are settled in the accepted asset per merchant account with no forced conversion and no rolling reserves.

## Authentication & Security

This plugin authenticates every API request using Paymos's canonical **HMAC-SHA256** request signing scheme (`Authorization: HMAC-SHA256 {public_key}:{signature}` and `X-Request-Timestamp`).

- **Payment API Keys Only:** Provide a Payment API key starting with `pk_live_` (Production) or `pk_test_` (Sandbox). Payout API keys (`rk_`) are rejected locally before any network call.
- **Sandbox Guard:** `simulate_sandbox_invoice` requires a `pk_test_` key and is rejected before leaving Dify if a `pk_live_` key is configured.
- **HTTPS Enforcement:** Custom `base_url` values must use `https://` (plain HTTP is allowed only for loopback tests).
- **Connection Verification:** Saving credentials verifies connectivity via `GET /v1/invoices?limit=1`.

## Setup in Dify

1. Sign in to [Paymos Dashboard](https://app.paymos.io) and create or select a project (`prj_...`).
2. Open **Developer → API Keys** and create a **Payment API** key pair (`pk_test_...` for Sandbox or `pk_live_...` for Production).
3. Install the **Paymos** plugin in Dify and configure:
   - **Payment API Public Key:** `pk_live_...` or `pk_test_...`
   - **Payment API Secret Key:** the paired HMAC secret key
   - **API Base URL** *(optional)*: defaults to `https://api.paymos.io`

## Included Tools (8)

| Tool | Endpoint | Description |
| --- | --- | --- |
| `create_invoice` | `POST /v1/invoices` | Create an idempotent payment invoice priced in fiat (45 currencies) or supported crypto assets (`USDT`, `USDC`, `USD1`, `DAI`, `XAUT`). Returns hosted checkout `payment_url`. |
| `get_invoice` | `GET /v1/invoices/{invoice_id}` | Retrieve full status, payment details, and transfer history for an invoice. |
| `list_invoices` | `GET /v1/invoices` | List invoices with filters (`project_id`, `status`, `external_order_id`, `created_from`, `created_to`, `limit`, `cursor`). |
| `cancel_invoice` | `POST /v1/invoices/{invoice_id}/cancel` | Cancel an open invoice with a required reason (`1–500` characters). |
| `simulate_sandbox_invoice` | `POST /v1/sandbox/invoices/{invoice_id}/simulate-payment` | Simulate `paid`, `overpaid`, `underpay`, or `cancel` on a Sandbox invoice (`pk_test_` only). |
| `create_payment_channel` | `POST /v1/payment-channels` | Idempotently create or fetch a customer's permanent Payment Channel with non-expiring deposit addresses per network. |
| `get_payment_channel` | `GET /v1/payment-channels/{channel_id}` | Fetch a Payment Channel's status and provisioned deposit addresses. |
| `create_refund` | `POST /v1/refunds` | Create a server-calculated `full` or `overpayment` refund to the original sender of a paid invoice (accepts strictly `invoice_id`, `mode`, `external_order_id`). |

## Documentation & Support

- Source repository: https://github.com/paymos-dev/dify-plugin-paymos
- Documentation: https://paymos.io/docs
- Website: https://paymos.io
- Privacy Policy: https://paymos.io/privacy
- Support: support@paymos.io
