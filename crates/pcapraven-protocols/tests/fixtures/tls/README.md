# Synthetic TLS 1.2 / TLS 1.3 Test Fixtures

This directory contains synthetic TLS test fixtures used exclusively for unit,
regression, and integration testing of the TLS protocol parser in `pcapraven-protocols`.

## Provenance & Safety
- **Synthetic Origin**: All fixtures were crafted synthetically using standard RFC wire formats.
- **No Production Traffic**: Zero packets or records derived from real organizations or production networks.
- **No Credentials or Secrets**: Contains zero private keys, secret tokens, certificate DER, or decryptable session data.
- **Redistribution**: Freely redistributable under the repository's MIT license.

## Fixture Inventory
- `client_hello_tls13.tls`: Valid TLS 1.3 ClientHello offering TLS 1.3/1.2, SNI, ALPN, KeyShare, Supported Groups.
- `client_hello_tls12.tls`: Valid TLS 1.2 ClientHello with SNI and ALPN.
- `server_hello_tls13.tls`: Valid TLS 1.3 ServerHello selecting TLS 1.3 and KeyShare group.
- `server_hello_tls12.tls`: Valid TLS 1.2 ServerHello selecting TLS 1.2 and cipher suite.
- `hello_retry_request.tls`: Valid TLS 1.3 HelloRetryRequest with SHA-256 HRR sentinel and selected group.
- `sni_example.tls`: ClientHello with custom SNI host_name.
- `alpn_h2_http11.tls`: ClientHello offering `h2` and `http/1.1`.
- `multi_record_handshake.tls`: ClientHello fragmented across two adjacent TLS Handshake records in the same packet.
- `truncated_record.tls`: TLS record truncated before declared record length.
- `truncated_handshake.tls`: TLS handshake message truncated before declared 24-bit length.
- `duplicate_extension.tls`: ClientHello containing duplicate extension type codes.
- `tls10_unsupported.tls`: ServerHello selecting unsupported TLS 1.0.
