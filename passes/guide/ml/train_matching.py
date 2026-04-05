#!/usr/bin/env python3

import argparse
import json
import math
from typing import Any

from catboost import CatBoostRanker, Pool

from matching_common import CAT_COLUMNS, FEATURE_COLUMNS, group_numeric_id, training_rows


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Train a CatBoost matching ranker from match.jsonl."
    )
    parser.add_argument("input", help="Input match.jsonl file.")
    parser.add_argument(
        "-o",
        "--output-prefix",
        default="match_ranker",
        help="Output prefix for cbm/json files.",
    )
    parser.add_argument("--iterations", type=int, default=300)
    parser.add_argument("--depth", type=int, default=5)
    parser.add_argument("--learning-rate", type=float, default=0.05)
    parser.add_argument("--l2-leaf-reg", type=float, default=5.0)
    parser.add_argument("--random-state", type=int, default=0)
    return parser.parse_args()


def load_rows(path: str) -> list[dict[str, Any]]:
    import matching_common

    return matching_common.load_rows(path)


def split_rows(rows: list[dict[str, Any]], split_name: str) -> list[dict[str, Any]]:
    return [row for row in rows if row["split"] == split_name]


def cat_feature_indices() -> list[int]:
    return [FEATURE_COLUMNS.index(column) for column in CAT_COLUMNS]


def to_pool(rows: list[dict[str, Any]]) -> Pool:
    data = [[row[column] for column in FEATURE_COLUMNS] for row in rows]
    labels = [float(row.get("label", 0)) for row in rows]
    groups = [group_numeric_id(row["group_id"]) for row in rows]
    return Pool(
        data=data,
        label=labels,
        group_id=groups,
        cat_features=cat_feature_indices(),
        feature_names=FEATURE_COLUMNS,
    )


def percentile(values: list[float], q: float) -> float:
    if not values:
        return -1e18
    values = sorted(values)
    if len(values) == 1:
        return values[0]
    pos = q * (len(values) - 1)
    lo = int(math.floor(pos))
    hi = int(math.ceil(pos))
    if lo == hi:
        return values[lo]
    frac = pos - lo
    return values[lo] * (1.0 - frac) + values[hi] * frac


def recommended_thresholds(model: CatBoostRanker, rows: list[dict[str, Any]]) -> tuple[float, float]:
    if not rows:
        return (-1e18, -1e18)

    pool = to_pool(rows)
    scores = model.predict(pool)
    grouped: dict[str, list[dict[str, Any]]] = {}
    for row, score in zip(rows, scores):
        item = dict(row)
        item["score"] = float(score)
        grouped.setdefault(row["group_id"], []).append(item)

    score_values: list[float] = []
    margin_values: list[float] = []
    for items in grouped.values():
        ranked = sorted(items, key=lambda item: (-item["score"], item.get("gate_name", "")))
        if not ranked or int(ranked[0].get("label", 0)) != 1:
            continue
        score_values.append(float(ranked[0]["score"]))
        margin = float(ranked[0]["score"])
        if len(ranked) > 1:
            margin = float(ranked[0]["score"]) - float(ranked[1]["score"])
        margin_values.append(margin)

    return (percentile(score_values, 0.10), percentile(margin_values, 0.10))


def main() -> int:
    args = parse_args()
    rows = training_rows(load_rows(args.input))
    if not rows:
        raise SystemExit("No useful ranking groups found in input JSONL.")

    train_rows = split_rows(rows, "train")
    valid_rows = split_rows(rows, "valid")
    if not train_rows:
        raise SystemExit("Training split is empty.")
    if not valid_rows:
        valid_rows = train_rows

    train_pool = to_pool(train_rows)
    valid_pool = to_pool(valid_rows)

    model = CatBoostRanker(
        loss_function="PairLogit",
        eval_metric="NDCG:top=5",
        iterations=args.iterations,
        depth=args.depth,
        learning_rate=args.learning_rate,
        l2_leaf_reg=args.l2_leaf_reg,
        random_seed=args.random_state,
        verbose=50,
    )
    model.fit(
        train_pool,
        eval_set=valid_pool,
        use_best_model=True,
        early_stopping_rounds=30,
    )

    min_score, min_margin = recommended_thresholds(model, valid_rows)

    cbm_path = f"{args.output_prefix}.cbm"
    json_path = f"{args.output_prefix}.json"
    meta_path = f"{args.output_prefix}.meta.json"

    model.save_model(cbm_path)
    model.save_model(json_path, format="json", pool=train_pool)

    meta = {
        "model_type": "guide_match_catboost_ranker_v1",
        "feature_columns": FEATURE_COLUMNS,
        "cat_columns": CAT_COLUMNS,
        "iterations": args.iterations,
        "depth": args.depth,
        "learning_rate": args.learning_rate,
        "l2_leaf_reg": args.l2_leaf_reg,
        "num_rows": len(rows),
        "num_train_rows": len(train_rows),
        "num_valid_rows": len(valid_rows),
        "num_groups": len({row["group_id"] for row in rows}),
        "cbm_path": cbm_path,
        "json_path": json_path,
        "suggestion_defaults": {
            "min_score": min_score,
            "min_margin": min_margin,
            "snapshot": "pre_async",
        },
    }
    with open(meta_path, "w", encoding="utf-8") as handle:
        json.dump(meta, handle, indent=2, sort_keys=True)
        handle.write("\n")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
