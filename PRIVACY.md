# Privacy Policy — Paymos Dify Plugin

This privacy policy explains how the **Paymos** Dify tool plugin (`paymos-dev/paymos`) handles credentials and request data when used inside Dify workflows and agents.

## 1. Data Processed by the Plugin

When you configure and invoke the Paymos plugin, it processes only the inputs you explicitly provide:

- **Merchant Credentials:** Your Paymos Payment API Public Key (`pk_live_...` or `pk_test_...`), Secret Key, and optional API Base URL (defaults to `https://api.paymos.io`).
- **Tool Parameters:** Payment workflow fields passed to Paymos tools, including project IDs, invoice amounts and currencies, merchant order IDs (`external_order_id`), optional blockchain network selections, optional customer reference IDs (`client_id`), payment channel `external_id` values, invoice cancellation reasons, sandbox simulation stages, and refund mode parameters.

The plugin accepts **Payment API keys only** (`pk_live_` / `pk_test_`). Payout API keys (`rk_`) are rejected locally before any network request is made.

## 2. Data Transmission and Third Parties

- Every tool call signs the request using HMAC-SHA256 and transmits it directly over HTTPS to the Paymos Merchant API (`https://api.paymos.io`, or the custom HTTPS endpoint you configured).
- The plugin does **not** transmit data to any third-party analytics, telemetry, logging, or tracking services.
- HTTP redirects are disabled so signed `Authorization` headers are never forwarded to unexpected hosts or downgraded to plaintext HTTP.

## 3. Data Storage and Retention

- This plugin is stateless and does not persist credentials, transaction records, or customer identifiers to local files or external databases.
- Your Paymos API credentials are stored solely in Dify's own plugin credential store according to your Dify workspace configuration.
- Invoice, payment channel, and refund records created through the API are stored and processed by Paymos in accordance with the [Paymos Privacy Policy](https://paymos.io/privacy) and [Terms of Service](https://paymos.io/terms).

## 4. Payer Data

Paymos does not collect payer identity or KYC information through these Payment API endpoints. Any optional merchant-defined identifiers you pass (`external_order_id`, `client_id`, `external_id`, `reason`) are under your control as the merchant.

## 5. Contact

For privacy questions or support regarding Paymos and this plugin:

- Email: support@paymos.io
- Website: https://paymos.io
- Privacy Policy: https://paymos.io/privacy
