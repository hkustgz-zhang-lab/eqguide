#!/usr/bin/env python3

import argparse
import json
import math
from typing import Any


ACTION_ORDER = [
    "cec_map",
    "cec_nomap",
    "dsec_map",
    "dsec_nomap",
]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Evaluate heuristic vs model scheduler ordering on sched.jsonl."
    )
    parser.add_argument("input", help="Input sched.jsonl file.")
    parser.add_argument("--model", required=True, help="Model JSON file.")
    parser.add_argument("--par-ms", type=float, default=60000.0, help="Penalty added when no action passes.")
    return parser.parse_args()


def load_jsonl(path: str) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    with open(path, "r", encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if line:
                rows.append(json.loads(line))
    return rows


def load_model(path: str) -> dict[str, Any]:
    with open(path, "r", encoding="utf-8") as handle:
        return json.load(handle)


def pair_features(row: dict[str, Any]) -> dict[str, float]:
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


def contextual_vector(model: dict[str, Any], row: dict[str, Any], action_name: str) -> list[float]:
    features = pair_features(row)
    features["act_cec_map"] = 1.0 if action_name == "cec_map" else 0.0
    features["act_cec_nomap"] = 1.0 if action_name == "cec_nomap" else 0.0
    features["act_dsec_map"] = 1.0 if action_name == "dsec_map" else 0.0
    features["act_dsec_nomap"] = 1.0 if action_name == "dsec_nomap" else 0.0
    return [float(features.get(name, 0.0)) for name in model["feature_names"]]


def tree_predict(tree: dict[str, Any], features: list[float]) -> float:
    nodes = tree["nodes"]
    index = 0
    while True:
        node = nodes[index]
        if node["is_leaf"]:
            return float(node["value"])
        feature_value = features[node["feature_index"]]
        index = node["left"] if feature_value <= node["threshold"] else node["right"]


def predict_cost(model: dict[str, Any], row: dict[str, Any], action_name: str) -> float:
    features = contextual_vector(model, row, action_name)
    score = float(model.get("base_score", 0.0))
    for tree in model.get("trees", []):
        score += tree_predict(tree, features)
    return score


def action_map(row: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {action["action"]: action for action in row.get("actions", [])}


def heuristic_order(row: dict[str, Any]) -> list[str]:
    has_dff = bool(row["pair"].get("gold_dff_cnt", 0) or row["pair"].get("gate_dff_cnt", 0))
    order = ["cec_map", "cec_nomap"]
    if has_dff:
        order += ["dsec_map", "dsec_nomap"]
    return order


def model_order(model: dict[str, Any], row: dict[str, Any]) -> list[str]:
    has_dff = bool(row["pair"].get("gold_dff_cnt", 0) or row["pair"].get("gate_dff_cnt", 0))
    actions = ["cec_map", "cec_nomap"] + (["dsec_map", "dsec_nomap"] if has_dff else [])
    return sorted(actions, key=lambda action: (predict_cost(model, row, action), action))


def rollout_cost(row: dict[str, Any], order: list[str], par_ms: float) -> float:
    actions = action_map(row)
    total = 0.0
    for action_name in order:
        if action_name not in actions:
            continue
        total += float(actions[action_name].get("runtime_ms", 0.0))
        if actions[action_name].get("result_code") == 1:
            return total
    return total + par_ms


def main() -> int:
    args = parse_args()
    rows = load_jsonl(args.input)
    model = load_model(args.model)

    heuristic_total = 0.0
    model_total = 0.0
    heuristic_wins = 0
    model_wins = 0

    for row in rows:
        heuristic_cost = rollout_cost(row, heuristic_order(row), args.par_ms)
        learned_cost = rollout_cost(row, model_order(model, row), args.par_ms)
        heuristic_total += heuristic_cost
        model_total += learned_cost
        if learned_cost < heuristic_cost:
            model_wins += 1
        elif heuristic_cost < learned_cost:
            heuristic_wins += 1

    summary = {
        "num_rows": len(rows),
        "heuristic_total_cost_ms": heuristic_total,
        "model_total_cost_ms": model_total,
        "heuristic_avg_cost_ms": heuristic_total / max(len(rows), 1),
        "model_avg_cost_ms": model_total / max(len(rows), 1),
        "model_wins": model_wins,
        "heuristic_wins": heuristic_wins,
    }

    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
