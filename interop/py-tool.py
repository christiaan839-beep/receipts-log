"""py-tool.py — runs the verifiable-receipts Python package over a JSON job.

Usage:
  python3 -I py-tool.py <checkout> sign <ed25519-private.pem> <count>
      prints <count> receipts signed with sign_v2_receipt, one JSON per line
  python3 -I py-tool.py <checkout> verify < job.json
      job: {"inclusion": [{leafHashHex, leafIndex, treeSize, auditPath, rootHashHex}],
            "receipts": [...], "issuerPublicKeyPem": "..."}
      prints {"inclusion": [bool...], "receipts": [bool...]}
"""

import json
import sys

sys.path.insert(0, sys.argv[1] + "/packages/verifiable-receipts-py")

from cryptography.hazmat.primitives.serialization import load_pem_private_key  # noqa: E402

from sovereign_matrix.verifiable_receipts.sign import sign_v2_receipt  # noqa: E402
from sovereign_matrix.verifiable_receipts.transparency import verify_inclusion_proof  # noqa: E402
from sovereign_matrix.verifiable_receipts.verify import verify_v2_receipt  # noqa: E402


def main() -> None:
    cmd = sys.argv[2]
    if cmd == "sign":
        with open(sys.argv[3], "rb") as f:
            key = load_pem_private_key(f.read(), password=None)
        for i in range(int(sys.argv[4])):
            body = {
                "runId": f"interop_{i:04d}",
                "overall": "pass" if i % 3 else "warn",
                "rules": [{"ruleId": "r1", "verdict": "pass"}],
                "note": "Zürich ✓",
            }
            print(json.dumps(sign_v2_receipt(body, key), ensure_ascii=False))
        return
    job = json.load(sys.stdin)
    out = {
        "inclusion": [
            verify_inclusion_proof(p, p["leafHashHex"], p["rootHashHex"]) for p in job.get("inclusion", [])
        ],
        "receipts": [],
    }
    pem = job.get("issuerPublicKeyPem")
    for r in job.get("receipts", []):
        res = verify_v2_receipt(r, pem.encode())
        out["receipts"].append(bool(getattr(res, "ok", res)))
    print(json.dumps(out))


main()
