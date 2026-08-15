# Synthetic DNS Test Fixtures

All binary fixture files in this directory are synthetic test vectors generated
purely from protocol specifications (RFC 1035, RFC 2671, RFC 6891). They contain
no real network capture data, credentials, private domain names, or telemetry.

## Inventory and Purpose

1. `simple_query.bin`: Standard UDP DNS query message for `example.com` (QTYPE=A, QCLASS=IN).
2. `compressed_response.bin`: Standard DNS response containing question for `www.example.com`, CNAME to `example.com`, and A record for `example.com` using backward compression pointers.
3. `pointer_self_loop.bin`: Malformed DNS message where a compression pointer points to itself (`0xC00C` at offset 12).
4. `pointer_forward.bin`: Malformed DNS message where a compression pointer points forward (`target >= current_offset`).
5. `pointer_out_of_bounds.bin`: Malformed DNS message where a compression pointer points beyond the message boundary.
6. `truncated_name.bin`: Malformed DNS message where a label header declares more bytes than remain in the message.
7. `oversized_label.bin`: Malformed DNS message where a label header exceeds the RFC 1035 63-byte limit.
8. `bad_rdlength.bin`: Malformed DNS message where an IPv4 A record declares RDLENGTH != 4.
9. `edns_query.bin`: DNS query message containing a valid EDNS(0) OPT resource record in the Additional section (RFC 6891).
10. `duplicate_opt.bin`: Malformed DNS message containing two OPT resource records in the Additional section.
11. `tcp_truncated_frame.bin`: TCP DNS stream segment where the 2-byte frame length prefix exceeds available payload bytes.
