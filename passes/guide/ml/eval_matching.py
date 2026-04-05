#!/usr/bin/env python3

import argparse
import json

from catboost import CatBoostRanker, Pool

from matching_common import CAT_COLUMNS, FEATURE_COLUMNS, group_numeric_id, training_rows


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Evaluate a CatBoost matching ranker on match.jsonl."
    )
    parser.add_argument("input", help="Input match.jsonl file.")
    parser.add_argument("--model", required=True, help="Input CatBoost .cbm model.")
    parser.add_argument("--split", default="valid", help="Split to evaluate.")
    parser.add_argument("--snapshot", default="pre_async", help="Snapshot to evaluate.")
    return parser.parse_args()


def load_rows(path: str) -> list[dict]:
    import matching_common

    return matching_common.load_rows(path)


def cat_feature_indices() -> list[int]:
    return [FEATURE_COLUMNS.index(column) for column in CAT_COLUMNS]


def filtered_rows(path: str, split: str, snapshot: str) -> list[dict]:
    rows = [
        row for row in training_rows(load_rows(path))
        if row["split"] == split and row["snapshot"] == snapshot
    ]
    grouped = {}
    for row in rows:
        grouped.setdefault(row["group_id"], []).append(row)
    out = []
    for items in grouped.values():
        if len(items) < 2:
            continue
        if max(int(item.get("label", 0)) for item in items) == 0:
            continue
        out.extend(items)
    return out


def main() -> int:
    args = parse_args()
    rows = filtered_rows(args.input, args.split, args.snapshot)
    if not rows:
        raise SystemExit("No rows available for evaluation.")

    model = CatBoostRanker()
    model.load_model(args.model)

    data = [[row[column] for column in FEATURE_COLUMNS] for row in rows]
    group_ids = [group_numeric_id(row["group_id"]) for row in rows]
    pool = Pool(data=data, group_id=group_ids, cat_features=cat_feature_indices(), feature_names=FEATURE_COLUMNS)
    scores = model.predict(pool)

    grouped = {}
    for row, score in zip(rows, scores):
        row = dict(row)
        row["score"] = float(score)
        grouped.setdefault(row["group_id"], []).append(row)

    total_groups = 0
    top1_hits = 0
    top3_hits = 0
    reciprocal_rank_sum = 0.0

    for items in grouped.values():
        total_groups += 1
        ranked = sorted(items, key=lambda item: (-item["score"], item["gate_name"]))
        labels = [int(item.get("label", 0)) for item in ranked]
        if labels and labels[0] == 1:
            top1_hits += 1
        if any(label == 1 for label in labels[:3]):
            top3_hits += 1
        for idx, label in enumerate(labels, start=1):
            if label == 1:
                reciprocal_rank_sum += 1.0 / idx
                break

    result = {
        "num_groups": total_groups,
        "top1": top1_hits / max(total_groups, 1),
        "top3": top3_hits / max(total_groups, 1),
        "mrr": reciprocal_rank_sum / max(total_groups, 1),
        "split": args.split,
        "snapshot": args.snapshot,
    }
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
