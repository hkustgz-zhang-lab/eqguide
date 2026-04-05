#!/usr/bin/env python3

import copy
import hashlib
import json
import re
from typing import Any


FEATURE_COLUMNS = [
    "match_type",
    "gold_wire_stem",
    "gate_wire_stem",
    "gold_port_family",
    "gate_port_family",
    "gold_instance_family",
    "gate_instance_family",
    "bit_index_absdiff",
    "same_bit_index",
    "full_name_token_jaccard",
    "wire_stem_jaccard",
    "same_last_token",
    "same_instance_stem",
    "same_subckt_dir",
    "heuristic_score",
]

CAT_COLUMNS = [
    "match_type",
    "gold_wire_stem",
    "gate_wire_stem",
    "gold_port_family",
    "gate_port_family",
    "gold_instance_family",
    "gate_instance_family",
]


def load_rows(path: str) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    with open(path, "r", encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if line:
                rows.append(json.loads(line))
    return rows


def normalize_name(name: str) -> str:
    return re.sub(r"[^0-9A-Za-z]+", "_", name)


def stem(name: str) -> str:
    normalized = normalize_name(name)
    normalized = re.sub(r"_?\d+$", "", normalized)
    parts = [part for part in normalized.split("_") if part]
    return parts[-1] if parts else normalized


def tokens(name: str) -> set[str]:
    return {part for part in normalize_name(name).lower().split("_") if part}


def last_token(name: str) -> str:
    tok = list(tokens(name))
    return tok[-1] if tok else ""


def instance_family(name: str) -> str:
    if "." not in name:
        return ""
    return stem(name.split(".", 1)[0])


def port_family(name: str) -> str:
    target = name.split(".")[-1]
    return stem(target)


def jaccard(lhs: set[str], rhs: set[str]) -> float:
    if not lhs and not rhs:
        return 1.0
    union = lhs | rhs
    if not union:
        return 0.0
    return len(lhs & rhs) / len(union)


def group_id(row: dict[str, Any]) -> str:
    return f"{row.get('pair_id','')}|{row.get('snapshot','')}|{row.get('gold_name','')}"


def split_name(group: str) -> str:
    digest = hashlib.sha256(group.encode("utf-8")).hexdigest()
    bucket = int(digest[:8], 16) % 10
    if bucket < 7:
        return "train"
    if bucket < 9:
        return "valid"
    return "test"


def group_numeric_id(group: str) -> int:
    digest = hashlib.sha256(group.encode("utf-8")).hexdigest()
    return int(digest[:15], 16)


def feature_map(row: dict[str, Any]) -> dict[str, Any]:
    gold_name = row.get("gold_name", "")
    gate_name = row.get("gate_name", "")
    gold_wire = row.get("gold_wire_name", "")
    gate_wire = row.get("gate_wire_name", "")
    gold_bit = int(row.get("gold_bit_index", 0))
    gate_bit = int(row.get("gate_bit_index", 0))

    features: dict[str, Any] = {}
    features["match_type"] = row.get("type", "")
    features["gold_wire_stem"] = stem(gold_wire)
    features["gate_wire_stem"] = stem(gate_wire)
    features["gold_port_family"] = port_family(gold_name)
    features["gate_port_family"] = port_family(gate_name)
    features["gold_instance_family"] = instance_family(gold_name)
    features["gate_instance_family"] = instance_family(gate_name)
    features["bit_index_absdiff"] = abs(gold_bit - gate_bit)
    features["same_bit_index"] = 1 if gold_bit == gate_bit else 0
    features["full_name_token_jaccard"] = jaccard(tokens(gold_name), tokens(gate_name))
    features["wire_stem_jaccard"] = jaccard(tokens(gold_wire), tokens(gate_wire))
    features["same_last_token"] = 1 if last_token(gold_wire) == last_token(gate_wire) else 0
    features["same_instance_stem"] = 1 if instance_family(gold_name) == instance_family(gate_name) and instance_family(gold_name) else 0
    features["same_subckt_dir"] = 1 if ("." in gold_name) == ("." in gate_name) else 0
    features["heuristic_score"] = float(row.get("score", 0.0))
    return features


def row_with_features(row: dict[str, Any]) -> dict[str, Any]:
    enriched = dict(row)
    enriched["group_id"] = group_id(row)
    enriched["split"] = row.get("split", split_name(enriched["group_id"]))
    enriched.update(feature_map(row))
    return enriched


def ranking_rows(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [row_with_features(row) for row in rows]


def perturb_variants(name: str) -> list[str]:
    variants = set()
    normalized = normalize_name(name)
    variants.add(normalized)
    variants.add(normalized.lower())
    variants.add(f"inst_{normalized}")
    variants.add(re.sub(r"\[(\d+)\]", r"_\1_", name))
    return [variant for variant in variants if variant and variant != name]


def training_rows(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    enriched = ranking_rows(rows)
    buckets: dict[tuple[str, str, str, int], list[dict[str, Any]]] = {}
    positives = [row for row in enriched if int(row.get("label", 0)) == 1]

    for row in positives:
        key = (
            row.get("pair_id", ""),
            row.get("snapshot", ""),
            row.get("type", ""),
            int(row.get("gold_bit_index", 0)),
        )
        buckets.setdefault(key, []).append(row)

    output: list[dict[str, Any]] = []
    for idx, row in enumerate(positives):
        key = (
            row.get("pair_id", ""),
            row.get("snapshot", ""),
            row.get("type", ""),
            int(row.get("gold_bit_index", 0)),
        )
        group = f"{row.get('pair_id','')}|{row.get('snapshot','')}|synthetic|{row.get('gold_name','')}|{idx}"
        split = split_name(group)

        base = copy.deepcopy(row)
        base["group_id"] = group
        base["split"] = split
        output.append(base)

        for variant in perturb_variants(row.get("gate_name", ""))[:3]:
            synthetic = copy.deepcopy(row)
            synthetic["gate_name"] = variant
            synthetic["gate_wire_name"] = variant
            synthetic["group_id"] = group
            synthetic["split"] = split
            synthetic.update(feature_map(synthetic))
            output.append(synthetic)

        negatives = 0
        for other in buckets.get(key, []):
            if other.get("gate_name") == row.get("gate_name"):
                continue
            negative = copy.deepcopy(other)
            negative["gold_name"] = row.get("gold_name", "")
            negative["gold_wire_name"] = row.get("gold_wire_name", "")
            negative["gold_bit_index"] = row.get("gold_bit_index", 0)
            negative["label"] = 0
            negative["group_id"] = group
            negative["split"] = split
            negative.update(feature_map(negative))
            output.append(negative)
            negatives += 1
            if negatives >= 8:
                break

    return output
