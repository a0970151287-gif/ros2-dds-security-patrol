"""Timeout units, pinned against what the kernel actually reports.

Until 2026-09-21 the backend read nftables set and element timeouts as
milliseconds. They are seconds. The error was invisible offline for two
compounding reasons:

1. the mock nft runner multiplied by 1000, so it produced exactly what the
   parser expected -- the fake and the parser shared one wrong assumption and
   agreed with each other;
2. no test asserted an expiry value, so changing the mock's units by a factor
   of 1000 did not move a single assertion.

The second point is the more serious of the two, and it is what this file
fixes. The fixture is the verbatim stdout of::

    nft -j list table inet sros2_ticket_guard

on nftables v1.0.9, Linux 6.8.0-1048-raspi, taken four seconds after adding
``10.99.99.99 timeout 12s``. It is a recording, not a restatement of the code.

Why the direction of the error matters: read as milliseconds, a 12-second block
resolves to an expiry 12,000 seconds away. The kernel releases the source after
12 seconds while this backend goes on reporting it blocked for another three and
a quarter hours -- the failure points at "believes it is still protecting the
host", which is the worst direction for a response system to be wrong in.
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
    MAX_RESPONSE_TTL_SEC,
    NFT_GC_INTERVAL_SEC,
    NFT_JSON_SCHEMA_VERSION,
    BackendApplyError,
    NftablesTimeoutSetAdapter,
)

NOW_NS = 2_000_000_000_000_000_000
SECOND_NS = 1_000_000_000

# Verbatim; only whitespace has been added. Handles are kernel-assigned.
KERNEL_TABLE_WITH_ELEMENT = (
    '{"nftables": ['
    '{"metainfo": {"version": "1.0.9", "release_name": "Old Doc Yak #3", '
    '"json_schema_version": 1}}, '
    '{"table": {"family": "inet", "name": "sros2_ticket_guard", "handle": 6}}, '
    '{"set": {"family": "inet", "name": "blocked_ipv4", "table": "sros2_ticket_guard", '
    '"type": "ipv4_addr", "handle": 2, '
    '"comment": "sros2-ed25519-ticket-only-timeout-set", "policy": "memory", '
    '"size": 1024, "flags": ["timeout"], "timeout": 300, "gc-interval": 5, '
    '"elem": [{"elem": {"val": "10.99.99.99", "timeout": 12, "expires": 7}}]}}, '
    '{"chain": {"family": "inet", "table": "sros2_ticket_guard", "name": "ticket_input", '
    '"handle": 1, "comment": "sros2-ed25519-ticket-only-chain", "type": "filter", '
    '"hook": "input", "prio": -10, "policy": "accept"}}, '
    '{"rule": {"family": "inet", "table": "sros2_ticket_guard", "chain": "ticket_input", '
    '"handle": 3, "comment": "sros2-ed25519-ticket-only-drop", "expr": ['
    '{"match": {"op": "==", "left": {"payload": {"protocol": "ip", "field": "saddr"}}, '
    '"right": "@blocked_ipv4"}}, '
    '{"counter": {"packets": 0, "bytes": 0}}, '
    '{"drop": null}]}}'
    ']}'
)


def _parse(text: str) -> dict[str, int]:
    return NftablesTimeoutSetAdapter._parse_snapshot(text, now_ns=NOW_NS)


def _mutated(mutate) -> str:
    document = json.loads(KERNEL_TABLE_WITH_ELEMENT)
    mutate(document)
    return json.dumps(document)


def _node(document: dict, kind: str) -> dict:
    for item in document["nftables"]:
        if kind in item:
            return item[kind]
    raise AssertionError(f"no {kind} node")


# ── the recorded kernel output parses, and to the right instant ──────────────


def test_the_real_kernel_snapshot_parses():
    assert _parse(KERNEL_TABLE_WITH_ELEMENT) == {
        "10.99.99.99": NOW_NS + 7 * SECOND_NS
    }


def test_the_expiry_is_seconds_not_milliseconds():
    """The assertion the old code base never made anywhere.

    `expires: 7` means seven seconds. Under the old millisecond reading it
    meant seven milliseconds, so the parsed expiry was 1000x too close -- and
    the set-level fields moved the same error the other way.
    """
    expiry = _parse(KERNEL_TABLE_WITH_ELEMENT)["10.99.99.99"]
    assert expiry - NOW_NS == 7 * SECOND_NS
    assert expiry - NOW_NS != 7 * 1_000_000, "this is the millisecond reading"


def test_a_full_length_block_stays_inside_the_signed_bound():
    """300s is the maximum; under the old units it would be 300,000."""
    text = _mutated(lambda d: _node(d, "set")["elem"][0]["elem"].update(
        {"timeout": MAX_RESPONSE_TTL_SEC, "expires": MAX_RESPONSE_TTL_SEC}
    ))
    expiry = _parse(text)["10.99.99.99"]
    assert expiry - NOW_NS == MAX_RESPONSE_TTL_SEC * SECOND_NS


def test_the_set_level_units_are_seconds_too():
    document = json.loads(KERNEL_TABLE_WITH_ELEMENT)
    nft_set = _node(document, "set")
    assert nft_set["timeout"] == MAX_RESPONSE_TTL_SEC
    assert nft_set["gc-interval"] == NFT_GC_INTERVAL_SEC
    assert nft_set["timeout"] != MAX_RESPONSE_TTL_SEC * 1000
    assert nft_set["gc-interval"] != NFT_GC_INTERVAL_SEC * 1000


# ── the old millisecond shape must now be refused ────────────────────────────


@pytest.mark.parametrize(
    "mutate,reason",
    [
        (lambda d: _node(d, "set").__setitem__("timeout", MAX_RESPONSE_TTL_SEC * 1000),
         "set timeout in milliseconds"),
        (lambda d: _node(d, "set").__setitem__("gc-interval", NFT_GC_INTERVAL_SEC * 1000),
         "gc-interval in milliseconds"),
        (lambda d: _node(d, "set")["elem"][0]["elem"].update(
            {"timeout": 12_000, "expires": 7_000}), "element timeout in milliseconds"),
    ],
)
def test_the_old_millisecond_shape_is_refused(mutate, reason):
    with pytest.raises(BackendApplyError):
        _parse(_mutated(mutate))


# ── an element in its final second is normal, not a fault ────────────────────


def test_expires_zero_is_accepted_because_the_countdown_reaches_it():
    """`expires` counts down; 0 appears in the last second before collection.

    The old check demanded >= 1 for both fields. In milliseconds that was
    effectively unreachable, but in seconds it would turn an ordinary read into
    a hard BackendApplyError right when the block is about to lapse.
    """
    text = _mutated(lambda d: _node(d, "set")["elem"][0]["elem"].__setitem__("expires", 0))
    assert _parse(text) == {"10.99.99.99": NOW_NS}


def test_a_zero_timeout_is_still_refused():
    text = _mutated(lambda d: _node(d, "set")["elem"][0]["elem"].update(
        {"timeout": 0, "expires": 0}))
    with pytest.raises(BackendApplyError, match="positive seconds"):
        _parse(text)


def test_expires_beyond_timeout_is_refused():
    text = _mutated(lambda d: _node(d, "set")["elem"][0]["elem"].update(
        {"timeout": 12, "expires": 13}))
    with pytest.raises(BackendApplyError, match="exceeds the signed response bound"):
        _parse(text)


def test_a_timeout_beyond_the_signed_maximum_is_refused():
    text = _mutated(lambda d: _node(d, "set")["elem"][0]["elem"].update(
        {"timeout": MAX_RESPONSE_TTL_SEC + 1, "expires": 1}))
    with pytest.raises(BackendApplyError, match="exceeds the signed response bound"):
        _parse(text)


# ── units are a property of the schema version, so it must be checked ────────


def test_an_unmeasured_schema_version_fails_closed():
    """Silently reading unknown units is the failure this guards against."""
    text = _mutated(
        lambda d: _node(d, "metainfo").__setitem__("json_schema_version", 2)
    )
    with pytest.raises(BackendApplyError, match="schema version"):
        _parse(text)


def test_the_declared_schema_version_is_the_one_that_was_measured():
    assert NFT_JSON_SCHEMA_VERSION == 1


def test_missing_metainfo_fails_closed():
    text = _mutated(
        lambda d: d.__setitem__(
            "nftables", [item for item in d["nftables"] if "metainfo" not in item]
        )
    )
    with pytest.raises(BackendApplyError, match="no metainfo"):
        _parse(text)


def test_metainfo_that_is_not_an_object_fails_closed():
    text = _mutated(lambda d: d["nftables"].__setitem__(0, {"metainfo": "1.0.9"}))
    with pytest.raises(BackendApplyError, match="metainfo is not recognized"):
        _parse(text)


# ── the surrounding contract is unchanged by the unit fix ────────────────────


def test_an_empty_set_still_parses_to_nothing_blocked():
    text = _mutated(lambda d: _node(d, "set").__setitem__("elem", []))
    assert _parse(text) == {}


def test_a_duplicated_source_is_still_refused():
    def duplicate(document):
        elements = _node(document, "set")["elem"]
        elements.append(copy.deepcopy(elements[0]))

    with pytest.raises(BackendApplyError, match="duplicate source"):
        _parse(_mutated(duplicate))
