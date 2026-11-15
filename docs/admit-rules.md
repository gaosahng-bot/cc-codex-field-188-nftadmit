# nftadmit admit rules

## Signing input
`v1|{kid}|{table}|{chain}|{set}|{elem}|{action}|{priority}|{iat}|{nonce}`

## Set membership
If set non-empty: set must exist under table; elem must be listed in sets[table][set] (fixtures use exact string match OR for CIDR entries, elem may be host in that CIDR — implement with ipaddress; fixtures use exact members and one host in 203.0.113.0/24).
Reject elem containing deny substrings. set name `deny4` is never admit-able for accept (fixtures deny).

## Gates
table/chain maps; action allowlist; priority range; HMAC+revoke; time; nonce allow-only.
Empty set/elem only allowed for tables without required set (ip nat prerouting ok).
