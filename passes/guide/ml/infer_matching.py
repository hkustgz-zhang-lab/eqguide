#!/usr/bin/env python3

import argparse
import json
import pathlib
from typing import Any

from catboost import CatBoostRanker, Pool

from matching_common import CAT_COLUMNS, FEATURE_COLUMNS, ranking_rows


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run CatBoost matching reranking on match.jsonl."
    )
    parser.add_argument("input", help="Input match.jsonl file.")
    parser.add_argument("--model", required=True, help="Input CatBoost .cbm model.")
    parser.add_argument(
        "-o",
        "--output",
        default="match_suggestions.model.json",
        help="Output suggestion JSON file.",
    )
    parser.add_argument("--min-score", type=float, default=None)
    parser.add_argument("--min-margin", type=float, default=None)
    parser.add_argument("--snapshot", default="pre_async")
    return parser.parse_args()


def load_rows(path: str) -> list[dict[str, Any]]:
    import matching_common

    return matching_common.load_rows(path)


def cat_feature_indices() -> list[int]:
    return [FEATURE_COLUMNS.index(column) for column in CAT_COLUMNS]


def load_meta_defaults(model_path: str) -> tuple[float, float]:
    path = pathlib.Path(model_path)
    meta_path = path.with_suffix(".meta.json")
    if not meta_path.exists():
        return (-1e18, -1e18)
    with open(meta_path, "r", encoding="utf-8") as handle:
        meta = json.load(handle)
    defaults = meta.get("suggestion_defaults", {})
    return (
        float(defaults.get("min_score", -1e18)),
        float(defaults.get("min_margin", -1e18)),
    )


def score_rows(model: CatBoostRanker, rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    data = [[row[column] for column in FEATURE_COLUMNS] for row in rows]
    pool = Pool(data=data, cat_features=cat_feature_indices(), feature_names=FEATURE_COLUMNS)
    scores = model.predict(pool)
    scored = []
    for row, score in zip(rows, scores):
        item = dict(row)
        item["model_score"] = float(score)
        scored.append(item)
    return scored


def build_suggestions(rows: list[dict[str, Any]], min_score: float, min_margin: float, snapshot: str) -> list[dict[str, Any]]:
    grouped: dict[str, list[dict[str, Any]]] = {}
    for row in rows:
        if row.get("snapshot") != snapshot:
            continue
        grouped.setdefault(row["group_id"], []).append(row)

    suggestions: list[dict[str, Any]] = []
    for items in grouped.values():
        if any(int(item.get("label", 0)) == 1 for item in items):
            continue
        ranked = sorted(items, key=lambda item: (-item["model_score"], item.get("gate_name", "")))
        if not ranked:
            continue
        top = ranked[0]
        margin = top["model_score"]
        if len(ranked) > 1:
            margin = top["model_score"] - ranked[1]["model_score"]
        if top["model_score"] < min_score or margin < min_margin:
            continue
        suggestions.append(
            {
                "pair_id": top["pair_id"],
                "snapshot": top["snapshot"],
                "gold_mod": top["gold_mod"],
                "gate_mod": top["gate_mod"],
                "gold_name": top["gold_name"],
                "gold_wire_name": top["gold_wire_name"],
                "gold_bit_index": top["gold_bit_index"],
                "type": top["type"],
                "suggested_gate_name": top["gate_name"],
                "suggested_gate_wire_name": top["gate_wire_name"],
                "suggested_gate_bit_index": top["gate_bit_index"],
                "score": top["model_score"],
                "score_margin": margin,
            }
        )
    return suggestions


def main() -> int:
    args = parse_args()
    model = CatBoostRanker()
    model.load_model(args.model)
    min_score, min_margin = load_meta_defaults(args.model)
    if args.min_score is not None:
        min_score = args.min_score
    if args.min_margin is not None:
        min_margin = args.min_margin
    rows = ranking_rows(load_rows(args.input))
    scored = score_rows(model, rows)
    suggestions = build_suggestions(scored, min_score, min_margin, args.snapshot)
    with open(args.output, "w", encoding="utf-8") as handle:
        json.dump(suggestions, handle, indent=2, sort_keys=True)
        handle.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
