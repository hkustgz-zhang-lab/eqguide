#!/usr/bin/env python3

import argparse
import json
import math
from typing import Any


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Evaluate guide_check failure_hints.json against curated packet labels."
    )
    parser.add_argument("hints", help="Path to failure_hints.json.")
    parser.add_argument("labels", nargs="?", help="Path to curated label JSON (optional; omit for stats-only mode).")
    parser.add_argument("--batch", action="store_true", help="Accept multiple hint files (hints is a glob or first of many).")
    return parser.parse_args()


def load_json(path: str) -> Any:
    with open(path, "r", encoding="utf-8") as handle:
        return json.load(handle)


def safe_div(num: float, den: float) -> float:
    if den == 0:
        return math.nan
    return num / den


def top3_ids(item: dict[str, Any]) -> set[str]:
    ids: set[str] = set()
    for step in item.get("next_steps", [])[:3]:
        if isinstance(step, dict) and isinstance(step.get("id"), str):
            ids.add(step["id"])
    return ids


def stats_only(hint_items: dict[str, Any]) -> dict[str, Any]:
    items = hint_items.get("items", [])
    total = len(items)
    classes: dict[str, int] = {}
    confidences: dict[str, int] = {}
    engines: dict[str, int] = {}
    scopes: dict[str, int] = {}
    proof_outcomes: dict[str, int] = {}
    fallback = 0

    for item in items:
        tc = item.get("failure_kind", "unknown")
        classes[tc] = classes.get(tc, 0) + 1
        conf = item.get("confidence", "unknown")
        confidences[conf] = confidences.get(conf, 0) + 1
        eng = item.get("engine", "unknown")
        engines[eng] = engines.get(eng, 0) + 1
        sc = item.get("scope", "pair")
        scopes[sc] = scopes.get(sc, 0) + 1
        po = item.get("proof_outcome", "unknown")
        proof_outcomes[po] = proof_outcomes.get(po, 0) + 1
        if "provider_error" in item:
            fallback += 1

    return {
        "packets_total": total,
        "failure_kind_distribution": classes,
        "confidence_distribution": confidences,
        "engine_distribution": engines,
        "scope_distribution": scopes,
        "proof_outcome_distribution": proof_outcomes,
        "fallback_count": fallback,
        "fallback_rate": safe_div(fallback, total),
    }


def evaluate_with_labels(
    hint_items: dict[str, dict[str, Any]], label_items: list[dict[str, Any]]
) -> dict[str, Any]:
    total = 0
    class_hits = 0
    clue_hits = 0
    clue_total = 0
    top3_hits = 0
    fallback = 0
    families: set[str] = set()
    per_class: dict[str, dict[str, int]] = {}

    for label in label_items:
        packet_id = str(label.get("packet_id", ""))
        item = hint_items.get(packet_id)
        if item is None:
            continue
        total += 1

        expected_class = label.get("expected_teacher_class")
        if expected_class:
            got_class = item.get("teacher", {}).get("class", item.get("failure_kind", ""))
            is_hit = got_class == expected_class
            if is_hit:
                class_hits += 1
            if expected_class not in per_class:
                per_class[expected_class] = {"total": 0, "hits": 0}
            per_class[expected_class]["total"] += 1
            if is_hit:
                per_class[expected_class]["hits"] += 1

        expected_clues = set(str(x) for x in label.get("expected_clues", []))
        got_clues = set(str(x) for x in item.get("teacher", {}).get("matched_clues", []))
        clue_total += len(expected_clues)
        clue_hits += len(expected_clues & got_clues)

        acceptable = set(str(x) for x in label.get("acceptable_step_ids", []))
        if acceptable and top3_ids(item) & acceptable:
            top3_hits += 1

        if "provider_error" in item:
            fallback += 1

        family = label.get("family")
        if family:
            families.add(str(family))

    per_class_summary = {}
    for cls_name, counts in per_class.items():
        per_class_summary[cls_name] = {
            "samples": counts["total"],
            "hits": counts["hits"],
            "accuracy": safe_div(counts["hits"], counts["total"]),
        }

    return {
        "packets_scored": total,
        "teacher_class_acc": safe_div(class_hits, total),
        "clue_recall": safe_div(clue_hits, clue_total),
        "top3_step_hit_rate": safe_div(top3_hits, total),
        "fallback_rate": safe_div(fallback, total),
        "family_coverage": len(families),
        "per_class": per_class_summary,
    }


def main() -> int:
    args = parse_args()
    hints = load_json(args.hints)
    hint_items = {str(item["packet_id"]): item for item in hints.get("items", [])}

    if args.labels is None:
        out = stats_only(hints)
    else:
        labels = load_json(args.labels)
        label_items = labels.get("items", [])
        out = evaluate_with_labels(hint_items, label_items)

    print(json.dumps(out, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
