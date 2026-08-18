"""Build a contract per trial from the live archives and run the real verifier."""
import json, sys
from pathlib import Path
sys.path.insert(0, "/home/jesse/ros2_ws")
from firewall_lab.schema import sha256_file, SchemaError
from firewall_lab.sros2_delivery_evidence import CONTRACT_SCHEMA, verify_delivery_evidence

ROOT = Path("/home/jesse/canary_evidence")
POLICY = sha256_file(Path("/home/jesse/ros2_ws/firewall_lab/action_policy.json"))

def beats(p):
    rows = [json.loads(l) for l in p.read_text(encoding="utf-8").splitlines()]
    return [r["ts_utc"] for r in rows if r["record_type"] == "collector_heartbeat"], rows

print(f"{'trial':20} {'mode':11} {'attempted':>9} {'delivered':>9} {'passed':>7}  verdict")
for d in sorted(x for x in ROOT.iterdir() if x.is_dir()):
    a, r = d / "attempted.jsonl", d / "protected_received.jsonl"
    if not (a.is_file() and r.is_file()):
        print(f"{d.name:20} archives missing"); continue
    ab, arows = beats(a)
    rb, _ = beats(r)
    binding = arows[0]
    contract = {
        "schema_version": CONTRACT_SCHEMA,
        "trial_id": binding["trial_id"],
        "session_id": binding["session_id"],
        "security_mode": binding["security_mode"],
        "policy_sha256": POLICY,
        "source_id": binding["source_id"],
        "source_enclave": binding["source_enclave"],
        "protected_sink_id": binding["protected_sink_id"],
        "protected_enclave": binding["protected_enclave"],
        "canary_topic": binding["canary_topic"],
        "window": {"start_utc": max(ab[0], rb[0]), "end_utc": min(ab[-1], rb[-1])},
        "expected_first_sequence": 0,
        "expected_attempt_count": 10,
        "collector_requirements": {"minimum_heartbeats": 2, "maximum_heartbeat_gap_ms": 60000},
        "archives": {
            "attempted": {"path": a.name, "sha256": sha256_file(a), "bytes": a.stat().st_size},
            "protected_received": {"path": r.name, "sha256": sha256_file(r), "bytes": r.stat().st_size},
        },
    }
    cp = d / "contract.json"
    cp.write_text(json.dumps(contract), encoding="utf-8")
    try:
        rep = verify_delivery_evidence(cp, output_path=d / "report.json")
        res = rep["result"]
        print(f"{d.name:20} {rep['security_mode']:11} {res['attempted_count']:>9} "
              f"{res['delivered_count']:>9} {str(res['passed']):>7}  {rep['confusion_matrix']}")
    except SchemaError as exc:
        print(f"{d.name:20} {binding['security_mode']:11} {'':>9} {'':>9} {'REFUSED':>7}  {exc}")
