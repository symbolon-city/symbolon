"""Independent check of docs/format-vectors.json, written from docs/FORMAT.md only (no Symbolon code).

Usage: python -I scripts/verify-format-vectors.py [path/to/format-vectors.json]
Needs only the Python standard library; Ed25519 signatures are checked too if the
`cryptography` package is installed.
"""

import hashlib
import json
import sys


def canonical(v):
    """RFC 8785 (JCS) restricted to safe integers: sorted keys (UTF-16 code units), no whitespace."""
    if v is None:
        return "null"
    if v is True:
        return "true"
    if v is False:
        return "false"
    if isinstance(v, int):
        if abs(v) > 2**53 - 1:
            raise ValueError("only safe integers")
        return str(v)
    if isinstance(v, float):
        raise ValueError("only integers; write amounts as strings")
    if isinstance(v, str):
        return json.dumps(v, ensure_ascii=False)
    if isinstance(v, list):
        return "[" + ",".join(canonical(x) for x in v) + "]"
    if isinstance(v, dict):
        keys = sorted(v.keys(), key=lambda k: k.encode("utf-16-be"))
        return "{" + ",".join(json.dumps(k, ensure_ascii=False) + ":" + canonical(v[k]) for k in keys) + "}"
    raise ValueError(f"cannot canonicalise {type(v)}")


def sha256(b):
    return hashlib.sha256(b).digest()


def leaf(data):
    return sha256(b"\x00" + data)


def node(left, right):
    return sha256(b"\x01" + left + right)


def tree_root(leaves):
    n = len(leaves)
    if n == 0:
        return sha256(b"")
    if n == 1:
        return leaves[0]
    k = 1
    while k * 2 < n:
        k *= 2
    return node(tree_root(leaves[:k]), tree_root(leaves[k:]))


def digest(value):
    return sha256(canonical(value).encode("utf-8")).hex()


def main(path):
    v = json.load(open(path, encoding="utf-8"))
    checks = []

    t = v["text_fingerprint"]
    checks.append(("text: exact UTF-8 bytes", t["text"].encode("utf-8").hex() == t["utf8_hex"]))
    checks.append(("text fingerprint", sha256(t["text"].encode("utf-8")).hex() == t["fingerprint"]))

    j = v["json_fingerprint"]
    checks.append(("JSON canonical form", canonical(j["json"]) == j["canonical"]))
    checks.append(("JSON fingerprint", digest(j["json"]) == j["fingerprint"]))

    c = v["clauses"]
    leaves = [leaf(canonical({"n": x["name"], "s": x["salt"], "v": x["value"]}).encode("utf-8")) for x in c["clauses"]]
    checks.append(("clause leaves", [x.hex() for x in leaves] == c["leaves"]))
    checks.append(("clauses root", tree_root(leaves).hex() == c["root"]))

    m = v["mandate"]
    checks.append(("mandate id", digest(m["mandate"]["body"]) == m["id"]))
    a = v["mandate_approval"]
    checks.append(("approval: id", digest(a["mandate"]["body"]) == a["id"]))
    checks.append(("approval: bound to the clauses root", a["mandate"]["body"]["agreement"]["clausesRoot"] == c["root"]))
    checks.append(("approval: under mandate A", a["mandate"]["body"]["agreement"]["under"] == m["id"]))
    rb = v["record"]["record"]["body"]
    checks.append(("approval: bound to the record's nonce", a["mandate"]["body"]["agreement"]["nonce"] == rb["nonce"]))
    checks.append(("approval: bound to agent B's mandate", a["mandate"]["body"]["agreement"]["withMandates"] == [rb["parties"][1]["mandate"]]))
    k = v["mandate_without_domain"]
    checks.append(("mandate without domain: id", digest(k["mandate"]["body"]) == k["id"]))
    checks.append(("mandate without domain: canonical body", canonical(k["mandate"]["body"]) == k["canonical_body"]))
    checks.append(("mandate without domain: owner has the key only", list(k["mandate"]["body"]["owner"].keys()) == ["key"]))

    r = v["record"]
    rec = r["record"]
    sigs = [next(s for s in rec["signatures"] if s["agent"] == p["agent"]) for p in rec["body"]["parties"]]
    checks.append(("record entry (fingerprint sent to the register)", digest({"body": rec["body"], "signatures": sigs}) == r["entry"]))
    checks.append(("record clause root is the clauses root", rec["body"]["clausesRoot"] == c["root"]))

    g = v["register"]
    reg_leaves = [leaf(("accord-entry/1:" + e).encode("utf-8")) for e in g["entries"]]
    checks.append(("register leaves", [x.hex() for x in reg_leaves] == g["leaves"]))
    checks.append(("register roots", all(tree_root(reg_leaves[: int(n)]).hex() == root for n, root in g["roots"].items())))

    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
        s = v["signature"]
        key = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(s["secret_key"]))
        checks.append(("Ed25519 signature over canonical JSON", key.sign(canonical(s["value"]).encode("utf-8")).hex() == s["signature"]))
        def ok(value, sig, pk):
            try:
                Ed25519PublicKey.from_public_bytes(bytes.fromhex(pk.removeprefix("ed25519:"))).verify(bytes.fromhex(sig), canonical(value).encode("utf-8"))
                return True
            except Exception:
                return False
        checks.append(("mandate signature", ok(m["mandate"]["body"], m["mandate"]["signature"], m["mandate"]["body"]["owner"]["key"])))
        checks.append(("approval: signature", ok(a["mandate"]["body"], a["mandate"]["signature"], a["mandate"]["body"]["owner"]["key"])))
        checks.append(("mandate without domain: signature", ok(k["mandate"]["body"], k["mandate"]["signature"], k["mandate"]["body"]["owner"]["key"])))
        checks.append(("record signatures", all(ok(rec["body"], x["signature"], x["agent"]) for x in rec["signatures"])))
    except ImportError:
        print("(cryptography not installed: Ed25519 checks skipped)")

    for name, good in checks:
        print(("OK   " if good else "FAIL ") + name)
    return 0 if all(g for _, g in checks) else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1] if len(sys.argv) > 1 else "docs/format-vectors.json"))
