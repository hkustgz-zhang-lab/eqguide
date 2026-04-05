#!/usr/bin/env python3

import argparse
import json
import math
from typing import Any

try:
    from lightgbm import LGBMRegressor
except ImportError as exc:
    raise SystemExit(
        "lightgbm is required. Use the repo venv: ./venv/bin/python -m pip install lightgbm scikit-learn"
    ) from exc


PAIR_FEATURES = [
    "gold_dff_cnt",
    "gate_dff_cnt",
    "has_dff",
    "has_submodule",
    "exact_total",
    "pi_cnt",
    "po_cnt",
    "dff_cnt",
    "dff_po_cnt",
    "subckt_cnt",
    "unmatched_gold",
    "unmatched_gate",
    "retimed",
    "touched_by_multiplier",
    "const_blackbox_inputs_inserted",
]

ACTION_ONEHOT = [
    "act_cec_map",
    "act_cec_nomap",
    "act_dsec_map",
    "act_dsec_nomap",
]

FEATURE_NAMES = PAIR_FEATURES + ACTION_ONEHOT

ACTION_NAMES = [
    "cec_map",
    "cec_nomap",
    "dsec_map",
    "dsec_nomap",
]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Train a shared shallow GBDT scheduler model from sched.jsonl."
    )
    parser.add_argument("input", help="Input sched.jsonl file.")
    parser.add_argument(
        "-o",
        "--output",
        default="sched_model.json",
        help="Output model JSON file.",
    )
    parser.add_argument("--par-ms", type=float, default=60000.0, help="Base timeout cost in milliseconds.")
    parser.add_argument("--par-factor", type=float, default=2.0, help="Penalty multiplier for non-pass actions.")
    parser.add_argument("--n-estimators", type=int, default=96, help="Number of boosting stages.")
    parser.add_argument("--max-depth", type=int, default=4, help="Maximum depth of each tree.")
    parser.add_argument("--learning-rate", type=float, default=0.05, help="Boosting learning rate.")
    parser.add_argument("--min-samples-leaf", type=int, default=20, help="Minimum samples per leaf.")
    parser.add_argument("--num-leaves", type=int, default=15, help="Maximum number of leaves per tree.")
    parser.add_argument("--random-state", type=int, default=7, help="Random seed.")
    return parser.parse_args()


def load_rows(path: str) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    with open(path, "r", encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            rows.append(json.loads(line))
    return rows


def pair_feature_map(row: dict[str, Any]) -> dict[str, float]:
    pair = row["pair"]
    match = row["match"]
    return {
        "gold_dff_cnt": float(pair.get("gold_dff_cnt", 0)),
        "gate_dff_cnt": float(pair.get("gate_dff_cnt", 0)),
        "has_dff": 1.0 if pair.get("gold_dff_cnt", 0) or pair.get("gate_dff_cnt", 0) else 0.0,
        "has_submodule": 1.0 if pair.get("has_submodule", False) else 0.0,
        "exact_total": float(match.get("exact_total", 0)),
        "pi_cnt": float(match.get("pi_cnt", 0)),
        "po_cnt": float(match.get("po_cnt", 0)),
        "dff_cnt": float(match.get("dff_cnt", 0)),
        "dff_po_cnt": float(match.get("dff_po_cnt", 0)),
        "subckt_cnt": float(match.get("subckt_cnt", 0)),
        "unmatched_gold": float(match.get("unmatched_gold", 0)),
        "unmatched_gate": float(match.get("unmatched_gate", 0)),
        "retimed": 1.0 if pair.get("retimed", False) else 0.0,
        "touched_by_multiplier": 1.0 if pair.get("touched_by_multiplier", False) else 0.0,
        "const_blackbox_inputs_inserted": float(pair.get("const_blackbox_inputs_inserted", 0)),
    }


def contextual_feature_vector(row: dict[str, Any], action_name: str) -> list[float]:
    features = pair_feature_map(row)
    for onehot in ACTION_ONEHOT:
        features[onehot] = 0.0
    features[f"act_{action_name}"] = 1.0
    return [features[name] for name in FEATURE_NAMES]


def action_cost(action: dict[str, Any], par_ms: float, par_factor: float) -> float:
    runtime_ms = float(action.get("runtime_ms", 0.0))
    if action.get("result_code") == 1:
        return runtime_ms
    return max(runtime_ms, par_ms) * par_factor


def build_samples(rows: list[dict[str, Any]], par_ms: float, par_factor: float) -> tuple[list[list[float]], list[float]]:
    x_rows: list[list[float]] = []
    y_rows: list[float] = []
    for row in rows:
        for action in row.get("actions", []):
            action_name = action.get("action")
            if action_name not in ACTION_NAMES:
                continue
            x_rows.append(contextual_feature_vector(row, action_name))
            y_rows.append(math.log1p(action_cost(action, par_ms, par_factor)))
    return x_rows, y_rows


def train_model(x_rows: list[list[float]], y_rows: list[float], args: argparse.Namespace) -> LGBMRegressor:
    effective_min_samples_leaf = min(args.min_samples_leaf, max(1, len(x_rows) // 4))
    model = LGBMRegressor(
        objective="regression",
        learning_rate=args.learning_rate,
        n_estimators=args.n_estimators,
        max_depth=args.max_depth,
        num_leaves=args.num_leaves,
        min_samples_leaf=effective_min_samples_leaf,
        random_state=args.random_state,
        verbose=-1,
    )
    model.fit(x_rows, y_rows)
    model.guide_effective_min_samples_leaf = effective_min_samples_leaf
    return model


def flatten_tree(node: dict[str, Any], nodes: list[dict[str, Any]]) -> int:
    index = len(nodes)
    if "leaf_value" in node:
        nodes.append(
            {
                "feature_index": -1,
                "threshold": 0.0,
                "left": -1,
                "right": -1,
                "value": float(node["leaf_value"]),
                "is_leaf": True,
            }
        )
        return index

    nodes.append(
        {
            "feature_index": int(node["split_feature"]),
            "threshold": float(node["threshold"]),
            "left": -1,
            "right": -1,
            "value": 0.0,
            "is_leaf": False,
        }
    )
    left = flatten_tree(node["left_child"], nodes)
    right = flatten_tree(node["right_child"], nodes)
    nodes[index]["left"] = left
    nodes[index]["right"] = right
    return index


def export_tree(tree_info: dict[str, Any]) -> dict[str, Any]:
    nodes: list[dict[str, Any]] = []
    flatten_tree(tree_info["tree_structure"], nodes)
    return {"nodes": nodes}


def main() -> int:
    args = parse_args()
    rows = load_rows(args.input)
    x_rows, y_rows = build_samples(rows, args.par_ms, args.par_factor)
    if not x_rows:
        raise SystemExit("No scheduler samples found in input JSONL.")

    model = train_model(x_rows, y_rows, args)
    booster = model.booster_
    dump = booster.dump_model()

    trees = [
        export_tree(tree_info)
        for tree_info in dump["tree_info"]
    ]

    output = {
        "model_type": "guide_sched_gbdt_v1",
        "feature_names": FEATURE_NAMES,
        "base_score": 0.0,
        "learning_rate": 1.0,
        "par_ms": args.par_ms,
        "par_factor": args.par_factor,
        "n_estimators": args.n_estimators,
        "max_depth": args.max_depth,
        "num_leaves": args.num_leaves,
        "min_samples_leaf": int(model.guide_effective_min_samples_leaf),
        "num_rows": len(x_rows),
        "trees": trees,
    }

    with open(args.output, "w", encoding="utf-8") as handle:
        json.dump(output, handle, indent=2, sort_keys=True)
        handle.write("\n")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
