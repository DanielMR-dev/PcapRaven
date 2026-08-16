# Synthetic HTTP/1.x Test Fixtures

This directory contains synthetic HTTP/1.x test fixtures used exclusively for
unit, regression, and integration testing of the HTTP protocol parser in
`pcapraven-protocols`.

## Provenance & Safety
- **Synthetic Origin**: All fixtures were hand-crafted synthetically.
- **No Production Traffic**: Zero packets or payloads derived from live or real network captures.
- **No Credentials**: No passwords, API tokens, Authorization secrets, or private cookies.
- **Redistribution**: Freely redistributable under the repository's MIT license.

## Fixture Inventory
- `simple_request_http11.http`: Valid baseline HTTP/1.1 GET request with Host and User-Agent.
- `simple_response_http11.http`: Valid baseline HTTP/1.1 200 OK response with Server, Content-Type, Content-Length.
- `simple_request_http10.http`: Valid baseline HTTP/1.0 GET request without Host header.
- `missing_host.http`: HTTP/1.1 request missing mandatory Host header.
- `duplicate_host.http`: HTTP/1.1 request containing multiple Host headers.
- `obs_fold.http`: HTTP request with unsupported line folding (obs-fold).
- `lf_only.http`: HTTP request using bare LF instead of standard CRLF.
- `truncated_headers.http`: HTTP request truncated before completing the header section.
- `content_length_list_identical.http`: HTTP response with comma-separated identical Content-Length values.
- `content_length_conflict.http`: HTTP response with conflicting Content-Length values.
- `te_and_cl.http`: HTTP request containing both Transfer-Encoding and Content-Length.
- `oversized_selected_header.http`: HTTP request containing a Host header exceeding maximum selected field bytes.
