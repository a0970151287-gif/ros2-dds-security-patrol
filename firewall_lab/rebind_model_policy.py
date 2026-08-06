#!/usr/bin/env python3
"""Rebind a signed model to a new action-policy hash without retraining.

This command deliberately does not evaluate the test split.  It preserves the
estimator objects and copies the metrics byte-for-byte, then proves equivalence
with estimator serialization and non-test canary prediction digests.
"""

from __future__ import annotations

import argparse
import csv
import gc
import hashlib
import json
import math
import shutil
import sys
from pathlib import Path
from typing import Any, Sequence

from .decision import DecisionPolicy
from .schema import atomic_write_json, sha256_file, utc_now
from .train import ML_DIR, MODEL_SCHEMA_VERSION


REPORT_SCHEMA = "sros2-firewall-model-policy-rebind/v1"


def _canonical_sha256(value: Any) -> str:
    encoded = json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _non_policy_metadata_digest(bundle: dict[str, Any]) -> str:
    metadata = {
        key: value
        for key, value in bundle.items()
        if key not in {"classifier", "anomaly_detector"}
    }
    training = dict(metadata.get("training") or {})
    training["action_policy_sha256"] = "<POLICY_SHA256>"
    metadata["training"] = training
    return _canonical_sha256(metadata)


def _semantic_update(digest, value: Any, active: set[int]) -> None:
    """Hash fitted estimator state without pickle framing or array padding."""

    import numpy as np

    if value is None:
        digest.update(b"none;")
        return
    if isinstance(value, bool):
        digest.update(b"bool:1;" if value else b"bool:0;")
        return
    if isinstance(value, int):
        digest.update(f"int:{value};".encode("ascii"))
        return
    if isinstance(value, float):
        digest.update(f"float:{value.hex()};".encode("ascii"))
        return
    if isinstance(value, str):
        encoded = value.encode("utf-8")
        digest.update(f"str:{len(encoded)}:".encode("ascii"))
        digest.update(encoded)
        return
    if isinstance(value, (bytes, bytearray, memoryview)):
        encoded = bytes(value)
        digest.update(f"bytes:{len(encoded)}:".encode("ascii"))
        digest.update(encoded)
        return
    if isinstance(value, np.generic):
        _semantic_update(digest, value.item(), active)
        return
    if isinstance(value, np.dtype):
        _semantic_update(digest, value.descr or value.str, active)
        return

    object_id = id(value)
    if object_id in active:
        raise ValueError("cyclic estimator state is unsupported")
    active.add(object_id)
    try:
        if isinstance(value, np.ndarray):
            digest.update(b"ndarray;")
            _semantic_update(digest, tuple(int(item) for item in value.shape), active)
            if value.dtype.names:
                # sklearn tree nodes use a structured dtype whose padding can
                # change across pickle round-trips.  Hash named fields only.
                for name in value.dtype.names:
                    _semantic_update(digest, name, active)
                    _semantic_update(digest, value[name], active)
            elif value.dtype.kind == "O":
                _semantic_update(digest, value.dtype.str, active)
                for item in value.ravel(order="C"):
                    _semantic_update(digest, item, active)
            else:
                _semantic_update(digest, value.dtype.str, active)
                digest.update(np.ascontiguousarray(value).tobytes(order="C"))
            return
        if isinstance(value, dict):
            digest.update(b"dict;")
            for key in sorted(
                value,
                key=lambda item: (type(item).__qualname__, repr(item)),
            ):
                _semantic_update(digest, key, active)
                _semantic_update(digest, value[key], active)
            return
        if isinstance(value, (list, tuple)):
            digest.update(b"list;" if isinstance(value, list) else b"tuple;")
            for item in value:
                _semantic_update(digest, item, active)
            return
        if isinstance(value, (set, frozenset)):
            digest.update(b"set;")
            item_digests = []
            for item in value:
                item_hash = hashlib.sha256()
                _semantic_update(item_hash, item, set())
                item_digests.append(item_hash.digest())
            for item_digest in sorted(item_digests):
                digest.update(item_digest)
            return
        if isinstance(value, slice):
            digest.update(b"slice;")
            _semantic_update(digest, (value.start, value.stop, value.step), active)
            return
        if isinstance(value, Path):
            _semantic_update(digest, str(value), active)
            return
        if isinstance(value, type) or callable(value) and not hasattr(value, "__getstate__"):
            digest.update(
                (
                    "callable:"
                    + getattr(value, "__module__", "")
                    + "."
                    + getattr(value, "__qualname__", repr(value))
                    + ";"
                ).encode("utf-8")
            )
            return
        state_getter = getattr(value, "__getstate__", None)
        state = state_getter() if callable(state_getter) else None
        if state is None:
            state = getattr(value, "__dict__", None)
        if state is None:
            raise TypeError(f"unsupported estimator state type: {type(value)!r}")
        digest.update(
            (
                "object:"
                + type(value).__module__
                + "."
                + type(value).__qualname__
                + ";"
            ).encode("utf-8")
        )
        _semantic_update(digest, state, active)
    finally:
        active.remove(object_id)


def _estimator_sha256(bundle: dict[str, Any]) -> str:
    digest = hashlib.sha256()
    _semantic_update(digest, bundle["classifier"], set())
    _semantic_update(digest, bundle["anomaly_detector"], set())
    return digest.hexdigest()


def _load_train_canary(
    path: Path,
    feature_names: Sequence[str],
    *,
    rows: int,
) -> tuple[list[list[float]], str]:
    if rows < 1:
        raise ValueError("canary rows must be positive")
    selected: list[list[float]] = []
    identities: list[dict[str, str]] = []
    with path.open(encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle)
        required = set(feature_names) | {"split", "group_id", "window"}
        missing = required - set(reader.fieldnames or ())
        if missing:
            raise ValueError(f"canary CSV is missing {sorted(missing)}")
        for row in reader:
            if row["split"] != "train":
                continue
            values = [float(row[name]) for name in feature_names]
            if any(not math.isfinite(value) for value in values):
                raise ValueError("canary feature is not finite")
            selected.append(values)
            identities.append(
                {"group_id": row["group_id"], "window": row["window"]}
            )
            if len(selected) == rows:
                break
    if len(selected) != rows:
        raise ValueError(f"only found {len(selected)} train canary rows")
    return selected, _canonical_sha256(identities)


def _prediction_sha256(bundle: dict[str, Any], rows: list[list[float]]) -> str:
    classifier = bundle["classifier"]
    anomaly = bundle["anomaly_detector"]
    probabilities = classifier.predict_proba(rows)
    anomaly_values = anomaly.predict(rows)
    payload = {
        "classes": [str(value) for value in bundle["classes"]],
        "probability_hex": [
            [float(value).hex() for value in probability_row]
            for probability_row in probabilities
        ],
        "anomaly": [int(value) for value in anomaly_values],
    }
    return _canonical_sha256(payload)


def rebind_model_policy(
    *,
    source_model: str | Path,
    output_model: str | Path,
    action_policy: str | Path,
    metrics_path: str | Path,
    canary_csv: str | Path,
    report_path: str | Path,
    copy_artifacts: Sequence[str | Path] = (),
    canary_rows: int = 64,
    signing_secret: bytes | None = None,
) -> dict[str, Any]:
    sys.path.insert(0, str(ML_DIR))
    try:
        from ml_utils import atomic_joblib_dump, verified_joblib_load
    finally:
        sys.path.remove(str(ML_DIR))

    source_path = Path(source_model)
    output_path = Path(output_model)
    policy_path = Path(action_policy)
    source_metrics = Path(metrics_path)
    report = Path(report_path)
    canary_path = Path(canary_csv)
    if source_path.resolve() == output_path.resolve():
        raise ValueError("output_model must not overwrite source_model")
    if source_metrics.is_symlink() or not source_metrics.is_file():
        raise ValueError("metrics file is missing or is a symlink")

    load_kwargs = {} if signing_secret is None else {"secret": signing_secret}
    bundle = verified_joblib_load(source_path, **load_kwargs)
    if not isinstance(bundle, dict) or bundle.get("schema_version") != MODEL_SCHEMA_VERSION:
        raise ValueError("unsupported model bundle")
    training = bundle.get("training")
    if not isinstance(training, dict):
        raise ValueError("model training metadata is missing")
    old_policy_sha256 = training.get("action_policy_sha256")
    if not isinstance(old_policy_sha256, str) or len(old_policy_sha256) != 64:
        raise ValueError("old action policy hash is invalid")
    policy = DecisionPolicy.load(policy_path)
    if set(str(value) for value in bundle.get("classes", [])) != set(policy.rules):
        raise ValueError("new action policy does not cover model classes exactly")
    new_policy_sha256 = sha256_file(policy_path)
    if old_policy_sha256 == new_policy_sha256:
        raise ValueError("model is already bound to this action policy")

    output_path.parent.mkdir(parents=True, exist_ok=True)
    report.parent.mkdir(parents=True, exist_ok=True)
    canary, canary_identity_sha256 = _load_train_canary(
        canary_path,
        bundle["features"],
        rows=canary_rows,
    )
    source_model_sha256 = sha256_file(source_path)
    source_metrics_sha256 = sha256_file(source_metrics)
    source_estimator_sha256 = _estimator_sha256(bundle)
    source_prediction_sha256 = _prediction_sha256(bundle, canary)
    source_metadata_sha256 = _non_policy_metadata_digest(bundle)
    source_deployment_eligible = bundle["training"].get(
        "deployment_eligible"
    )
    source_test_prediction_passes = bundle["training"].get(
        "test_prediction_passes"
    )

    # The only in-bundle mutation allowed by this operation.
    bundle["training"]["action_policy_sha256"] = new_policy_sha256
    dump_kwargs = {} if signing_secret is None else {"secret": signing_secret}
    atomic_joblib_dump(bundle, output_path, **dump_kwargs)
    del bundle
    gc.collect()
    rebound = verified_joblib_load(output_path, **load_kwargs)

    rebound_estimator_sha256 = _estimator_sha256(rebound)
    rebound_prediction_sha256 = _prediction_sha256(rebound, canary)
    rebound_metadata_sha256 = _non_policy_metadata_digest(rebound)
    if rebound["training"].get("action_policy_sha256") != new_policy_sha256:
        raise RuntimeError("rebound policy hash was not persisted")
    if source_estimator_sha256 != rebound_estimator_sha256:
        raise RuntimeError("estimator digest changed during policy rebind")
    if source_prediction_sha256 != rebound_prediction_sha256:
        raise RuntimeError("non-test canary prediction digest changed")
    if source_metadata_sha256 != rebound_metadata_sha256:
        raise RuntimeError("non-policy model metadata changed")

    destination_metrics = output_path.parent / source_metrics.name
    shutil.copyfile(source_metrics, destination_metrics)
    if sha256_file(destination_metrics) != source_metrics_sha256:
        raise RuntimeError("test metrics changed during copy")
    copied = []
    for artifact in copy_artifacts:
        source_artifact = Path(artifact)
        if source_artifact.is_symlink() or not source_artifact.is_file():
            raise ValueError(f"copy artifact is invalid: {source_artifact}")
        destination = output_path.parent / source_artifact.name
        shutil.copyfile(source_artifact, destination)
        if sha256_file(destination) != sha256_file(source_artifact):
            raise RuntimeError(f"copied artifact digest changed: {source_artifact}")
        copied.append(
            {
                "name": source_artifact.name,
                "sha256": sha256_file(destination),
            }
        )

    result = {
        "schema_version": REPORT_SCHEMA,
        "created_utc": utc_now(),
        "operation": "policy_hash_only_repackage",
        "source_model": str(source_path),
        "output_model": str(output_path),
        "source_model_sha256": source_model_sha256,
        "output_model_sha256": sha256_file(output_path),
        "old_action_policy_sha256": old_policy_sha256,
        "new_action_policy_sha256": new_policy_sha256,
        "estimator_sha256_before": source_estimator_sha256,
        "estimator_sha256_after": rebound_estimator_sha256,
        "estimator_unchanged": True,
        "non_policy_metadata_sha256_before": source_metadata_sha256,
        "non_policy_metadata_sha256_after": rebound_metadata_sha256,
        "non_policy_metadata_unchanged": True,
        "canary": {
            "split": "train",
            "rows": canary_rows,
            "identity_sha256": canary_identity_sha256,
            "prediction_sha256_before": source_prediction_sha256,
            "prediction_sha256_after": rebound_prediction_sha256,
            "prediction_unchanged": True,
        },
        "test_predictions_recomputed": False,
        "test_metrics_source_sha256": source_metrics_sha256,
        "test_metrics_output_sha256": sha256_file(destination_metrics),
        "test_metrics_unchanged": True,
        "test_prediction_passes": rebound["training"].get(
            "test_prediction_passes"
        ),
        "deployment_eligible_unchanged": (
            source_deployment_eligible
            == rebound["training"].get("deployment_eligible")
        ),
        "deployment_eligible": rebound["training"].get(
            "deployment_eligible"
        ),
        "copied_artifacts": copied,
        "hmac_verified_after_write": True,
    }
    if result["test_prediction_passes"] != source_test_prediction_passes:
        raise RuntimeError("test prediction pass count changed")
    if not result["deployment_eligible_unchanged"]:
        raise RuntimeError("deployment eligibility changed")
    atomic_write_json(report, result)
    return result


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Rebind only a signed model's action-policy hash"
    )
    parser.add_argument("--source-model", type=Path, required=True)
    parser.add_argument("--output-model", type=Path, required=True)
    parser.add_argument("--action-policy", type=Path, required=True)
    parser.add_argument("--metrics", type=Path, required=True)
    parser.add_argument("--canary-csv", type=Path, required=True)
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--copy-artifact", action="append", default=[])
    parser.add_argument("--canary-rows", type=int, default=64)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    result = rebind_model_policy(
        source_model=args.source_model,
        output_model=args.output_model,
        action_policy=args.action_policy,
        metrics_path=args.metrics,
        canary_csv=args.canary_csv,
        report_path=args.report,
        copy_artifacts=args.copy_artifact,
        canary_rows=args.canary_rows,
    )
    print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
