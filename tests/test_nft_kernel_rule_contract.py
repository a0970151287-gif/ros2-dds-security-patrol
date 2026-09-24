"""The nft rule contract, pinned against a real kernel's own rendering.

Every other test of the nftables backend drives a fake nft runner, and until
2026-09-21 those fakes were built from ``EXPECTED_RULE_EXPRESSION`` -- the same
constant the production code compared against. The constant only ever agreed
with itself, so a contract that no real kernel could satisfy passed offline for
weeks and was found on the first live acceptance run on the Pi.

The fixture below is the verbatim output of::

    nft -j list table inet sros2_ticket_guard

on nftables v1.0.9 (Old Doc Yak #3), Linux 6.8.0-1048-raspi, aarch64, after
loading ``render_bootstrap_ruleset_for_review()``. It is recorded data, not a
restatement of the code, which is the whole point: a fixture derived from the
implementation cannot catch the implementation being wrong about the kernel.
"""

from __future__ import annotations

import copy
import json
import pathlib
import sys

import pytest

_ROOT = pathlib.Path(__file__).resolve().parents[1]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from firewall_lab.nft_backend_service import (  # noqa: E402
    EXPECTED_DROP_EXPRESSION,
    EXPECTED_MATCH_EXPRESSION,
    NFT_CHAIN,
    NFT_CHAIN_COMMENT,
    NFT_CHAIN_PRIORITY,
    NFT_FAMILY,
    NFT_GC_INTERVAL_SEC,
    NFT_RULE_COMMENT,
    NFT_SET,
    NFT_SET_COMMENT,
    NFT_SET_SIZE,
    NFT_TABLE,
    expected_rule_expression,
    rule_expression_matches,
)

# Captured on the Raspberry Pi 5, 2026-09-21. Handles are kernel-assigned and
# increment across the boot, so they are data here, never something to assert.
KERNEL_DUMP = json.loads(r"""
{
    "nftables": [
        {"metainfo": {"version": "1.0.9", "release_name": "Old Doc Yak #3",
                      "json_schema_version": 1}},
        {"table": {"family": "inet", "name": "sros2_ticket_guard", "handle": 4}},
        {"set": {"family": "inet", "name": "blocked_ipv4",
                 "table": "sros2_ticket_guard", "type": "ipv4_addr", "handle": 2,
                 "comment": "sros2-ed25519-ticket-only-timeout-set",
                 "policy": "memory", "size": 1024, "flags": ["timeout"],
                 "timeout": 300, "gc-interval": 5}},
        {"chain": {"family": "inet", "table": "sros2_ticket_guard",
                   "name": "ticket_input", "handle": 1,
                   "comment": "sros2-ed25519-ticket-only-chain", "type": "filter",
                   "hook": "input", "prio": -10, "policy": "accept"}},
        {"rule": {"family": "inet", "table": "sros2_ticket_guard",
                  "chain": "ticket_input", "handle": 3,
                  "comment": "sros2-ed25519-ticket-only-drop",
                  "expr": [
                      {"match": {"op": "==",
                                 "left": {"payload": {"protocol": "ip",
                                                      "field": "saddr"}},
                                 "right": "@blocked_ipv4"}},
                      {"counter": {"packets": 0, "bytes": 0}},
                      {"drop": null}
                  ]}}
    ]
}
""")


def _node(kind: str) -> dict:
    for item in KERNEL_DUMP["nftables"]:
        if kind in item:
            return item[kind]
    raise AssertionError(f"fixture has no {kind} node")


# ── the contract accepts what the kernel actually produces ───────────────────


def test_the_contract_accepts_the_real_kernel_rule():
    assert rule_expression_matches(_node("rule")["expr"])


def test_the_contract_accepts_a_counter_that_has_moved():
    """Counter totals change on every packet; only they are allowed to vary."""
    expression = copy.deepcopy(_node("rule")["expr"])
    expression[1]["counter"] = {"packets": 918, "bytes": 51408}
    assert rule_expression_matches(expression)


def test_the_helper_reproduces_the_kernels_rendering_exactly():
    assert expected_rule_expression() == _node("rule")["expr"]
    assert expected_rule_expression(packets=7, byte_count=392)[1] == {
        "counter": {"packets": 7, "bytes": 392}
    }


# ── the two shapes that were wrong, kept as explicit regressions ─────────────


def test_the_input_syntax_membership_operator_is_rejected():
    """`ip saddr @set` is entered as a membership test; nft renders `==`.

    The old contract asserted "in" and therefore matched nothing on a real
    kernel.
    """
    expression = copy.deepcopy(_node("rule")["expr"])
    expression[0]["match"]["op"] = "in"
    assert not rule_expression_matches(expression)


def test_a_bare_counter_is_rejected():
    """The old contract asserted `{"counter": None}`; the kernel emits a dict."""
    expression = copy.deepcopy(_node("rule")["expr"])
    expression[1] = {"counter": None}
    assert not rule_expression_matches(expression)


def test_the_exact_pair_of_defects_found_on_the_pi_is_rejected():
    """Both wrong fields together: the literal old EXPECTED_RULE_EXPRESSION."""
    old_constant = [
        {
            "match": {
                "op": "in",
                "left": {"payload": {"protocol": "ip", "field": "saddr"}},
                "right": f"@{NFT_SET}",
            }
        },
        {"counter": None},
        {"drop": None},
    ]
    assert not rule_expression_matches(old_constant)


# ── tampering must still be refused: the contract is loose in one place only ──


@pytest.mark.parametrize(
    "mutate,reason",
    [
        (lambda e: e.__setitem__(2, {"accept": None}), "drop turned into accept"),
        (lambda e: e.__setitem__(2, {"drop": None, "log": None}), "extra verdict key"),
        (lambda e: e[0]["match"].__setitem__("right", "@other_set"), "different set"),
        (
            lambda e: e[0]["match"]["left"]["payload"].__setitem__("field", "daddr"),
            "destination instead of source",
        ),
        (lambda e: e.append({"log": None}), "a fourth expression appended"),
        (lambda e: e.pop(1), "counter removed"),
        (lambda e: e[1]["counter"].__setitem__("packets", -1), "negative counter"),
        (lambda e: e[1]["counter"].__setitem__("packets", "7"), "counter as text"),
        (lambda e: e[1]["counter"].__setitem__("packets", True), "counter as bool"),
        (lambda e: e[1]["counter"].__setitem__("drop", 0), "extra counter key"),
        (lambda e: e[1].__setitem__("quota", None), "counter node carries a quota"),
    ],
)
def test_tampering_with_the_rule_is_rejected(mutate, reason):
    expression = copy.deepcopy(_node("rule")["expr"])
    mutate(expression)
    assert not rule_expression_matches(expression), reason


def test_non_lists_and_empty_expressions_are_rejected():
    for value in (None, {}, [], "expr", [EXPECTED_MATCH_EXPRESSION], 3):
        assert not rule_expression_matches(value)


# ── the rest of the fixture still matches the declared namespace ─────────────


def test_the_kernel_agrees_with_the_declared_set_and_chain():
    """Catches drift in the other constants the live run also checks.

    `gc-interval` in particular is a field nft is free to omit when it equals a
    default; the fixture proves this kernel echoes it.
    """
    table = _node("table")
    assert (table["family"], table["name"]) == (NFT_FAMILY, NFT_TABLE)

    nft_set = _node("set")
    assert nft_set["name"] == NFT_SET
    assert nft_set["type"] == "ipv4_addr"
    assert nft_set["size"] == NFT_SET_SIZE
    assert nft_set["gc-interval"] == NFT_GC_INTERVAL_SEC
    assert nft_set["flags"] == ["timeout"]
    assert nft_set["comment"] == NFT_SET_COMMENT
    assert "elem" not in nft_set, "the acceptance run installs an empty set"

    chain = _node("chain")
    assert chain["name"] == NFT_CHAIN
    assert chain["type"] == "filter"
    assert chain["hook"] == "input"
    assert chain["prio"] == NFT_CHAIN_PRIORITY
    assert chain["policy"] == "accept"
    assert chain["comment"] == NFT_CHAIN_COMMENT

    assert _node("rule")["comment"] == NFT_RULE_COMMENT
    assert EXPECTED_DROP_EXPRESSION == {"drop": None}
