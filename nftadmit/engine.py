from __future__ import annotations
import base64
import hashlib
import hmac
import ipaddress
from typing import Any

def inspect_rule(obj: dict) -> dict:
    return {
        "kid": obj.get("kid"),
        "table": obj.get("table"),
        "chain": obj.get("chain"),
        "set": obj.get("set"),
        "elem": obj.get("elem"),
        "action": obj.get("action"),
        "priority": obj.get("priority"),
        "nonce": obj.get("nonce"),
    }

def _b64url(digest: bytes) -> str:
    return base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")

def _signing_input(obj: dict) -> str:
    return "v1|{kid}|{table}|{chain}|{set}|{elem}|{action}|{priority}|{iat}|{nonce}".format(
        kid=obj.get("kid"),
        table=obj.get("table"),
        chain=obj.get("chain"),
        set=obj.get("set"),
        elem=obj.get("elem"),
        action=obj.get("action"),
        priority=obj.get("priority"),
        iat=obj.get("iat"),
        nonce=obj.get("nonce"),
    )

def _elem_in_set(elem: str, members: list) -> bool:
    if elem in members:
        return True
    try:
        host = ipaddress.ip_address(elem)
    except ValueError:
        return False
    for member in members:
        try:
            network = ipaddress.ip_network(member, strict=False)
        except ValueError:
            continue
        if host.version == network.version and host in network:
            return True
    return False

def admit_rule(obj: dict, keys: dict, policy: dict, store: dict, now_unix: int) -> dict:
    reasons: list[str] = []
    chain = obj.get("chain")

    def deny(code: str) -> dict:
        reasons.append(code)
        return {"decision": "deny", "reason_codes": reasons, "chain": chain}

    table = obj.get("table")
    if table not in policy.get("allowed_tables", []):
        return deny("table_not_allowed")

    allowed_chains = policy.get("allowed_chains", {}).get(table, [])
    if chain not in allowed_chains:
        return deny("chain_not_allowed")

    set_name = obj.get("set")
    elem = obj.get("elem")
    table_sets = policy.get("sets", {}).get(table, {})
    if not set_name and not elem:
        if table_sets:
            return deny("set_required")
    else:
        if not set_name or not elem:
            return deny("set_elem_incomplete")
        if "deny" in set_name:
            return deny("set_denied")
        if set_name not in table_sets:
            return deny("set_not_found")
        for needle in policy.get("elem_deny_substrings", []):
            if needle and needle in elem:
                return deny("elem_glob_denied")
        if not _elem_in_set(elem, table_sets[set_name]):
            return deny("elem_not_in_set")

    if obj.get("action") not in policy.get("allowed_actions", []):
        return deny("action_not_allowed")

    priority = obj.get("priority")
    if isinstance(priority, bool) or not isinstance(priority, int) or not (
        policy.get("priority_min", -100) <= priority <= policy.get("priority_max", 100)
    ):
        return deny("priority_out_of_range")

    key_entry = keys.get("keys", {}).get(obj.get("kid"))
    if not key_entry:
        return deny("kid_unknown")
    if key_entry.get("status") != "active":
        return deny("key_revoked")

    secret = key_entry.get("secret", "")
    try:
        secret_bytes = bytes.fromhex(secret)
    except (TypeError, ValueError):
        return deny("key_malformed")
    expected = _b64url(hmac.new(
        secret_bytes, _signing_input(obj).encode("utf-8"), hashlib.sha256
    ).digest())
    if not isinstance(obj.get("sig"), str) or not hmac.compare_digest(expected, obj["sig"]):
        return deny("bad_signature")

    iat = obj.get("iat")
    if isinstance(iat, bool) or not isinstance(iat, int):
        return deny("iat_invalid")
    skew = policy.get("clock_skew_seconds", 60)
    max_age = policy.get("max_age_seconds", 600)
    if iat > now_unix + skew or now_unix - iat > max_age + skew:
        return deny("iat_outside_window")

    nonce = obj.get("nonce")
    if not isinstance(nonce, str) or not nonce:
        return deny("nonce_invalid")
    if nonce in store.get("items", {}):
        return deny("nonce_replay")

    store.setdefault("items", {})[nonce] = {"ts": now_unix}
    return {"decision": "allow", "reason_codes": [], "chain": chain}
