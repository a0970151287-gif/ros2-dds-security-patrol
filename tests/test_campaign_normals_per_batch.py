"""`--normals-per-batch` reorders a batch so every stack instance carries a
fixed number of benign reference sessions, without changing the plan.

Why (2026-10-28): one batch = one stack_up = one benign background, and
C2C-116 traced the identification collapse to the background differing between
batches. C2C-127 tried per-batch benign-reference centering and it failed in
both modes -- but the candidate mechanism it left open, untestable on existing
data, was that Enforce batches had a median of one normal session. This switch
makes "k normals per batch" a design rather than a scheduling accident.

These tests pin that it is a reordering only: the entry set, their contents,
and the plan's requested_counts are untouched, so a resumed run still lines up.
"""
from __future__ import annotations

import copy

import pytest

from firewall_lab.campaign import execute_campaign, interleave_normals


def _entry(index: int, klass: str) -> dict:
    return {
        "entry_id": f"run_{index:05d}",
        "scenario_id": "normal_patrol" if klass == "normal" else "cmd_vel",
        "attack_class": klass,
        "security_mode": "enforce",
        "status": "pending",
    }


def _candidates(n_normal: int, n_attack: int) -> list[dict]:
    out = [_entry(i, "attack") for i in range(n_attack)]
    out += [_entry(100 + i, "normal") for i in range(n_normal)]
    return out


def _classes(entries: list[dict]) -> list[str]:
    return [e["attack_class"] for e in entries]


def test_default_zero_is_the_original_order():
    cands = _candidates(5, 35)
    out = interleave_normals(cands, limit=40, normals_per_batch=0)
    assert out == cands


def test_no_limit_means_no_reorder():
    cands = _candidates(5, 35)
    out = interleave_normals(cands, limit=None, normals_per_batch=3)
    assert out == cands


def test_the_batch_gets_exactly_k_normals_spread_out():
    cands = _candidates(20, 80)
    out = interleave_normals(cands, limit=10, normals_per_batch=3)
    head = _classes(out[:10])
    assert head.count("normal") == 3
    # Spread, not clustered at the front: the first position is an attack and
    # the normals are not three in a row.
    assert head[0] == "attack"
    normal_positions = [i for i, c in enumerate(head) if c == "normal"]
    gaps = [b - a for a, b in zip(normal_positions, normal_positions[1:])]
    assert all(g >= 2 for g in gaps), head


def test_it_is_a_reordering_not_a_rewrite():
    cands = _candidates(20, 80)
    frozen = copy.deepcopy(cands)
    out = interleave_normals(cands, limit=10, normals_per_batch=3)
    # Same multiset of entries, same objects, nothing mutated.
    assert sorted(e["entry_id"] for e in out) == sorted(
        e["entry_id"] for e in frozen)
    assert {e["entry_id"]: e for e in out} == {e["entry_id"]: e for e in cands}


def test_a_batch_short_on_attacks_is_padded_with_normals_not_shrunk():
    # Only two attacks left but limit 10: the batch stays 10 long using normals.
    cands = _candidates(20, 2)
    out = interleave_normals(cands, limit=10, normals_per_batch=3)
    head = out[:10]
    assert len(head) == 10
    assert _classes(head).count("attack") == 2
    assert _classes(head).count("normal") == 8


def test_fewer_normals_available_than_requested():
    cands = _candidates(1, 39)
    out = interleave_normals(cands, limit=10, normals_per_batch=3)
    assert _classes(out[:10]).count("normal") == 1


def test_execute_campaign_rejects_normals_without_a_limit(tmp_path):
    with pytest.raises(ValueError, match="requires limit"):
        execute_campaign(
            plan_path=tmp_path / "plan.json",
            dataset_root=tmp_path / "out",
            security_mode="enforce",
            capture_interface="lo",
            limit=None,
            normals_per_batch=3,
            confirm_isolated_lab=True,
        )


def test_execute_campaign_rejects_normals_exceeding_the_limit(tmp_path):
    with pytest.raises(ValueError, match="exceed"):
        execute_campaign(
            plan_path=tmp_path / "plan.json",
            dataset_root=tmp_path / "out",
            security_mode="enforce",
            capture_interface="lo",
            limit=5,
            normals_per_batch=6,
            confirm_isolated_lab=True,
        )
