"""The seam between attribution evidence and a real kernel block.

Four parts of this chain can be exercised without a kernel, a second host, or
root, and they are the four that decide *whether to act at all*: the report's
schema, whether it names exactly one target, whether that target still passes
the four attribution conditions when they are re-derived from the raw fields,
and whether the target is something we must never block regardless of evidence.

The 2026-09-24 nft acceptance spent a live run discovering that `evidence_id`
must be 64 hex characters. Rehearsing the pure half is how that stops
happening: a cross-host run needs both machines and an authorisation, so it is
the most expensive place to find a typo.
"""

from __future__ import annotations

import hashlib
import importlib.util
import json
import pathlib
import sys

import pytest

_ROOT = pathlib.Path(__file__).resolve().parents[1]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

_TOOL = _ROOT / "工具腳本" / "run_attribution_driven_block.py"


def _chain():
    spec = importlib.util.spec_from_file_location("_chain_tool", _TOOL)
    module = importlib.util.module_from_spec(spec)
    # dataclasses resolve their own module out of sys.modules, so a
    # module loaded this way must be registered before it executes.
    sys.modules["_chain_tool"] = module
    spec.loader.exec_module(module)
    return module


chain = _chain()

TARGET = "192.168.0.30"
DEFENDER = "192.168.0.129"


def _report(**overrides) -> dict:
    per_ip = {
        TARGET: {
            "guid_count": 1,
            "unique_guid": True,
            "has_authorized_identity": False,
            "has_rejection_record": True,
            "link_layer_verdict": "consistent",
            "blockable": True,
            "reasons_not_blockable": [],
        },
        DEFENDER: {
            "guid_count": 1,
            "unique_guid": True,
            "has_authorized_identity": False,
            "has_rejection_record": False,
            "link_layer_verdict": "consistent",
            "blockable": False,
            "reasons_not_blockable": ["觀測者沒有對此 GUID 的拒絕記錄"],
        },
    }
    report = {
        "schema_version": "sros2-firewall-identity-crosscheck/v2",
        "per_ip": per_ip,
        "blockable_ips": [TARGET],
        "authorizes_action": False,
        "source_ip_attribution_verified": True,
    }
    report.update(overrides)
    return report


def _write(tmp_path, report: dict) -> pathlib.Path:
    path = tmp_path / "crosscheck.json"
    path.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    return path


class _NoPeers:
    """Stand-in for the acceptance module's host probes."""

    @staticmethod
    def _ssh_peers():
        return set(), "none-observed"


# ─────────────────── the evidence digest is the binding ───────────────────


def test_evidence_id_is_the_report_digest(tmp_path):
    report = _report()
    path = _write(tmp_path, report)
    evidence = chain.load_attribution(path)

    assert evidence.evidence_id == hashlib.sha256(path.read_bytes()).hexdigest()


def test_evidence_id_is_sixty_four_lowercase_hex(tmp_path):
    """The authorizer rejects anything else; the 2026-09-24 run learned this live."""
    evidence = chain.load_attribution(_write(tmp_path, _report()))
    assert len(evidence.evidence_id) == 64
    assert all(c in "0123456789abcdef" for c in evidence.evidence_id)


def test_editing_the_report_changes_the_binding(tmp_path):
    """A ticket must not survive its evidence being altered."""
    path = _write(tmp_path, _report())
    before = chain.load_attribution(path).evidence_id
    altered = _report()
    altered["per_ip"][TARGET]["link_layer_verdict"] = "unverifiable"
    path.write_text(json.dumps(altered, ensure_ascii=False, indent=2), encoding="utf-8")

    assert chain.load_attribution(path).evidence_id != before


def test_a_report_that_is_not_json_is_refused(tmp_path):
    path = tmp_path / "crosscheck.json"
    path.write_text("not json at all", encoding="utf-8")
    with pytest.raises(chain.ChainError, match="合法 JSON"):
        chain.load_attribution(path)


# ─────────────────────────── check 1: schema ───────────────────────────


def test_schema_v2_is_accepted(tmp_path):
    ok, _ = chain.check_schema(chain.load_attribution(_write(tmp_path, _report())))
    assert ok


def test_schema_v1_is_refused(tmp_path):
    """v1 has no link-layer condition, so it cannot exclude source spoofing."""
    report = _report(schema_version="sros2-firewall-identity-crosscheck/v1")
    ok, detail = chain.check_schema(chain.load_attribution(_write(tmp_path, report)))
    assert not ok
    assert "v1" in detail


# ──────────────────── check 2: verified, exactly one ────────────────────


def test_a_single_verified_target_is_selected(tmp_path):
    ok, _, target = chain.check_verified_single_target(
        chain.load_attribution(_write(tmp_path, _report())), None
    )
    assert ok and target == TARGET


def test_unverified_attribution_selects_nothing(tmp_path):
    report = _report(source_ip_attribution_verified=False)
    ok, _, target = chain.check_verified_single_target(
        chain.load_attribution(_write(tmp_path, report)), None
    )
    assert not ok and target == ""


def test_two_targets_require_an_explicit_choice(tmp_path):
    """One approval is one block. Quietly blocking two is not what it agreed to."""
    report = _report(blockable_ips=[TARGET, "192.168.0.44"])
    evidence = chain.load_attribution(_write(tmp_path, report))

    ok, detail, target = chain.check_verified_single_target(evidence, None)
    assert not ok and target == ""
    assert "--target" in detail

    ok, _, target = chain.check_verified_single_target(evidence, "192.168.0.44")
    assert ok and target == "192.168.0.44"


def test_an_operator_cannot_name_an_address_the_evidence_did_not(tmp_path):
    evidence = chain.load_attribution(_write(tmp_path, _report()))
    ok, detail, target = chain.check_verified_single_target(evidence, "8.8.8.8")
    assert not ok and target == ""
    assert "8.8.8.8" in detail


def test_an_empty_blockable_list_selects_nothing(tmp_path):
    report = _report(blockable_ips=[], source_ip_attribution_verified=True)
    ok, _, target = chain.check_verified_single_target(
        chain.load_attribution(_write(tmp_path, report)), None
    )
    assert not ok and target == ""


# ───────────── check 3: re-derive, do not trust the summary ─────────────


def test_the_four_conditions_are_rederived(tmp_path):
    ok, detail = chain.check_independently_reblockable(
        chain.load_attribution(_write(tmp_path, _report())), TARGET
    )
    assert ok
    for name in (
        "unique_guid",
        "no_authorized_identity",
        "has_rejection_record",
        "link_layer_consistent",
    ):
        assert name in detail


@pytest.mark.parametrize(
    "field,value",
    [
        ("unique_guid", False),
        ("has_authorized_identity", True),
        ("has_rejection_record", False),
        ("link_layer_verdict", "unverifiable"),
        ("link_layer_verdict", "spoofing_evidence"),
        ("link_layer_verdict", "no_evidence"),
    ],
)
def test_any_broken_condition_refuses_the_target(tmp_path, field, value):
    report = _report()
    report["per_ip"][TARGET][field] = value
    ok, _ = chain.check_independently_reblockable(
        chain.load_attribution(_write(tmp_path, report)), TARGET
    )
    assert not ok


def test_a_summary_disagreeing_with_the_detail_refuses(tmp_path):
    """Two paths through one report. If they disagree, stop.

    `blockable_ips` and `per_ip` are produced by the same program but by
    different code paths, and what gets dropped here is real packets.
    """
    report = _report()
    report["per_ip"][TARGET]["blockable"] = False
    ok, detail = chain.check_independently_reblockable(
        chain.load_attribution(_write(tmp_path, report)), TARGET
    )
    assert not ok
    assert "summary_agrees" in detail


def test_a_target_with_no_detail_entry_refuses(tmp_path):
    ok, detail = chain.check_independently_reblockable(
        chain.load_attribution(_write(tmp_path, _report())), "10.0.0.1"
    )
    assert not ok
    assert "per_ip" in detail


# ─────────────── check 4: never block ourselves, whatever ───────────────


def test_the_current_ssh_peer_is_never_blocked(monkeypatch, tmp_path):
    """This check is deliberately independent of the evidence.

    2026-08-30 showed every round had the defender's own address satisfying two
    of the four conditions. A guard that only consults the evidence would share
    any mistake the evidence makes.
    """
    class _Peer:
        @staticmethod
        def _ssh_peers():
            return {TARGET}, "proc-net-tcp(1)"

    monkeypatch.setattr(chain, "_local_addresses", lambda: set())
    monkeypatch.setattr(chain, "_default_gateway", lambda: "")
    ok, detail = chain.check_not_self_or_gateway(_Peer, TARGET)
    assert not ok
    assert "SSH" in detail


def test_a_local_address_is_never_blocked(monkeypatch):
    monkeypatch.setattr(chain, "_local_addresses", lambda: {TARGET})
    monkeypatch.setattr(chain, "_default_gateway", lambda: "")
    ok, detail = chain.check_not_self_or_gateway(_NoPeers, TARGET)
    assert not ok
    assert "本機" in detail


def test_the_default_gateway_is_never_blocked(monkeypatch):
    monkeypatch.setattr(chain, "_local_addresses", lambda: set())
    monkeypatch.setattr(chain, "_default_gateway", lambda: TARGET)
    ok, detail = chain.check_not_self_or_gateway(_NoPeers, TARGET)
    assert not ok
    assert "閘道" in detail


def test_an_unrelated_address_passes_the_self_check(monkeypatch):
    monkeypatch.setattr(chain, "_local_addresses", lambda: {DEFENDER})
    monkeypatch.setattr(chain, "_default_gateway", lambda: "192.168.0.1")
    ok, _ = chain.check_not_self_or_gateway(_NoPeers, TARGET)
    assert ok


# ─────────────────────── the preflight as a whole ───────────────────────


def _acceptance_stub():
    return _NoPeers


def test_preflight_passes_on_a_good_report(monkeypatch, tmp_path):
    monkeypatch.setattr(chain, "_local_addresses", lambda: {DEFENDER})
    monkeypatch.setattr(chain, "_default_gateway", lambda: "192.168.0.1")
    checks, target = chain.preflight(
        chain.load_attribution(_write(tmp_path, _report())), None, _acceptance_stub()
    )
    assert target == TARGET
    assert set(checks) == set(chain.REQUIRED_CHAIN_CHECKS[:4])
    assert all(entry["passed"] for entry in checks.values())


def test_preflight_stops_at_the_first_failure(monkeypatch, tmp_path):
    """Later checks are not recorded as passing on a report already refused."""
    monkeypatch.setattr(chain, "_local_addresses", lambda: set())
    monkeypatch.setattr(chain, "_default_gateway", lambda: "")
    report = _report(schema_version="sros2-firewall-identity-crosscheck/v1")
    checks, target = chain.preflight(
        chain.load_attribution(_write(tmp_path, report)), None, _acceptance_stub()
    )
    assert target == ""
    assert list(checks) == ["attribution_report_schema_v2"]


# ─────────────────────────── the report ───────────────────────────


def test_a_partial_run_is_not_a_demonstrated_chain(monkeypatch, tmp_path):
    monkeypatch.setattr(chain, "_local_addresses", lambda: {DEFENDER})
    monkeypatch.setattr(chain, "_default_gateway", lambda: "192.168.0.1")
    evidence = chain.load_attribution(_write(tmp_path, _report()))
    checks, target = chain.preflight(evidence, None, _acceptance_stub())

    report = chain.build_report(
        evidence=evidence, target=target, checks=checks, approval_phrase_supplied=True
    )
    assert report["summary"]["all_passed"] is True
    assert report["summary"]["all_required_present"] is False
    assert report["summary"]["chain_demonstrated"] is False


def test_the_report_records_that_the_evidence_authorized_nothing(monkeypatch, tmp_path):
    """The crosscheck sets authorizes_action=false. The report must not blur that."""
    monkeypatch.setattr(chain, "_local_addresses", lambda: {DEFENDER})
    monkeypatch.setattr(chain, "_default_gateway", lambda: "192.168.0.1")
    evidence = chain.load_attribution(_write(tmp_path, _report()))
    checks, target = chain.preflight(evidence, None, _acceptance_stub())

    report = chain.build_report(
        evidence=evidence, target=target, checks=checks, approval_phrase_supplied=True
    )
    assert report["attribution"]["report_authorizes_action"] is False
    assert report["authorization"]["subject_came_from"] == "attribution evidence digest"
    assert report["authorization"]["authority_came_from"].startswith("human")
    assert report["shipping_defaults_unchanged"] is True


def test_verify_rejects_an_unknown_check(monkeypatch, tmp_path):
    monkeypatch.setattr(chain, "_local_addresses", lambda: {DEFENDER})
    monkeypatch.setattr(chain, "_default_gateway", lambda: "192.168.0.1")
    evidence = chain.load_attribution(_write(tmp_path, _report()))
    checks, target = chain.preflight(evidence, None, _acceptance_stub())
    for name in chain.REQUIRED_CHAIN_CHECKS[4:]:
        checks[name] = {"passed": True, "detail": "synthetic"}
    checks["invented_check"] = {"passed": True, "detail": "synthetic"}

    report = chain.build_report(
        evidence=evidence, target=target, checks=checks, approval_phrase_supplied=True
    )
    with pytest.raises(chain.ChainError, match="未宣告的檢查"):
        chain.verify_chain_report(report)


def test_verify_accepts_a_complete_passing_chain(monkeypatch, tmp_path):
    monkeypatch.setattr(chain, "_local_addresses", lambda: {DEFENDER})
    monkeypatch.setattr(chain, "_default_gateway", lambda: "192.168.0.1")
    evidence = chain.load_attribution(_write(tmp_path, _report()))
    checks, target = chain.preflight(evidence, None, _acceptance_stub())
    for name in chain.REQUIRED_CHAIN_CHECKS[4:]:
        checks[name] = {"passed": True, "detail": "synthetic"}

    report = chain.build_report(
        evidence=evidence, target=target, checks=checks, approval_phrase_supplied=True
    )
    verdict = chain.verify_chain_report(report)
    assert verdict["chain_demonstrated"] is True
    assert verdict["evidence_sha256"] == evidence.sha256


def test_verify_rejects_extra_top_level_keys(monkeypatch, tmp_path):
    monkeypatch.setattr(chain, "_local_addresses", lambda: {DEFENDER})
    monkeypatch.setattr(chain, "_default_gateway", lambda: "192.168.0.1")
    evidence = chain.load_attribution(_write(tmp_path, _report()))
    checks, target = chain.preflight(evidence, None, _acceptance_stub())
    report = chain.build_report(
        evidence=evidence, target=target, checks=checks, approval_phrase_supplied=True
    )
    report["deployment_ready"] = True
    with pytest.raises(chain.ChainError, match="頂層鍵"):
        chain.verify_chain_report(report)


# ─────────────────────── the approval phrase ───────────────────────


def test_the_chain_phrase_differs_from_the_nft_acceptance_phrase():
    """Approving one live operation must not approve a different one."""
    from firewall_lab.nft_backend_service import LIVE_ACCEPTANCE_APPROVAL

    assert chain.CHAIN_APPROVAL != LIVE_ACCEPTANCE_APPROVAL


def test_the_tool_declares_exactly_nine_checks():
    assert len(chain.REQUIRED_CHAIN_CHECKS) == 9
    assert len(set(chain.REQUIRED_CHAIN_CHECKS)) == 9


def test_every_declared_check_is_produced_by_some_code_path():
    """A declared check with no implementation is a promise, not a test.

    The first draft of this tool listed nine and implemented four; the report
    would have said chain_demonstrated=false forever without saying why.
    """
    body = _TOOL.read_text(encoding="utf-8")
    for name in chain.REQUIRED_CHAIN_CHECKS:
        # once in the declaration tuple, at least once where it is recorded
        assert body.count(f'"{name}"') >= 2, f"{name} is declared but never recorded"
