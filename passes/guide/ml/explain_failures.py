#!/usr/bin/env python3

import argparse
import hashlib
import json
import os
import sys
from typing import Any

from openai import OpenAI


SCHEMA_VERSION = 1
DEFAULT_OPENAI_MODEL = "gpt-5-mini"

LEGACY_STEP_IDS = {
    "try -n fallback": "retry_cec_nomap",
    "inspect match density": "inspect_match_density",
    "inspect pi and cutpoint alignment": "inspect_match_density",
    "check trivial boundary mismatches": "inspect_match_density",
    "inspect sat counterexample-bearing signals": "inspect_counterexample",
    "inspect fraiging-sensitive cone differences": "inspect_counterexample",
    "inspect partition boundary assumptions": "inspect_partition_boundary",
    "inspect simulation counterexample": "inspect_counterexample",
    "inspect early mismatch-producing signals": "inspect_counterexample",
    "inspect sequential framing assumptions": "inspect_retime_pair",
    "check reset/init handling": "inspect_upstream_transforms",
    "increase -skip": "increase_bmc_skip",
    "increase -k": "increase_bmc_k",
    "inspect retimed pair": "inspect_retime_pair",
    "check multiplier width/sign": "check_multiplier_sign_width",
    "check blackboxing path": "check_blackboxing_path",
    "inspect counterexample-producing module pair": "inspect_counterexample",
    "check upstream transforms": "inspect_upstream_transforms",
    "inspect command log": "inspect_command_log",
    "replay failing action manually": "replay_failing_action",
}

STEP_REASON = {
    "retry_cec_nomap": "Retry the pair without the current name map to see whether mapping sparsity is blocking the proof path.",
    "retry_dsec_map": "Escalate to the sequential engine on the mapped pair when combinational checks are inconclusive.",
    "inspect_match_density": "Inspect exact and typed match counts before changing the proof flow.",
    "increase_bmc_skip": "Give the BMC warmup more room before concluding the sequential proof path is blocked.",
    "increase_bmc_k": "Increase the search depth so the failing sequential proof has a chance to settle.",
    "inspect_retime_pair": "Inspect retimed structure and warmup alignment on this module pair.",
    "check_multiplier_sign_width": "Check multiplier signedness and width assumptions against the extracted cone.",
    "check_blackboxing_path": "Verify the multiplier blackboxing/substitution path before changing the proof result.",
    "replay_failing_action": "Replay the exact failing action with the captured log to confirm the failure mode.",
    "inspect_counterexample": "Inspect the earliest counterexample-bearing signals before changing transforms or matching.",
    "inspect_upstream_transforms": "Check whether preprocessing or structural rewrites changed the behavior or proof contract.",
    "inspect_partition_boundary": "Inspect partition boundary assumptions before trusting a local mismatch.",
    "inspect_command_log": "Read the captured command log before changing policy or classification.",
}

LIKELY_CAUSES = {
    "abc_miter_failed": [
        "ABC could not build a usable miter for this pair",
        "the current match density may be too sparse or misleading",
        "the mapped fallback path may not fit this pair",
    ],
    "abc_not_equivalent_struct_hash": [
        "a shallow mismatch is already visible before deeper proof phases",
        "boundary naming or cutpoint alignment may be off",
        "the pair may contain a real combinational mismatch",
    ],
    "abc_not_equivalent_sat": [
        "SAT found a concrete mismatch after structural hashing did not settle the pair",
        "the mismatch is likely semantic rather than purely syntactic",
        "the failing cone is often small enough to inspect directly",
    ],
    "abc_not_equivalent_generic": [
        "the proof engines found a concrete mismatch on this pair",
        "upstream transforms or matching may have misaligned the pair",
        "the failing cone should be replayed before changing policy",
    ],
    "bmc_weak_failed": [
        "weak-mode induction did not close with the current warmup",
        "retimed structure may need different skip or depth settings",
        "sequential alignment may still be off on this pair",
    ],
    "bmc_bmc_phase_failed": [
        "the BMC phase did not close within the current warmup/depth budget",
        "retimed structure may still need more skip or depth",
        "the trace should be replayed before changing proof policy",
    ],
    "bmc_induct_phase_failed": [
        "the induction step failed even after the bounded phase ran",
        "the pair may need a different retime or warmup setup",
        "proof depth may still be too small for this pair",
    ],
    "amulet_verify_failed": [
        "the multiplier-specific flow rejected the current candidate",
        "signedness or width assumptions may be wrong",
        "the blackboxing or substitute path may not match the extracted cone",
    ],
    "tool_exit_nonzero": [
        "the external tool exited unsuccessfully before a clear clue was extracted",
        "the command log is needed before changing the classification",
    ],
    "missing_log_or_parse_error": [
        "the packet did not retain enough logging to classify the failure cleanly",
        "the command should be replayed to recover the missing context",
    ],
    "unknown": [
        "the packet does not match a known failure class yet",
        "the command log needs manual inspection",
    ],
}

CONFIDENCE = {
    "abc_miter_failed": "medium",
    "abc_not_equivalent_struct_hash": "high",
    "abc_not_equivalent_sat": "high",
    "abc_not_equivalent_generic": "medium",
    "bmc_weak_failed": "medium",
    "bmc_bmc_phase_failed": "medium",
    "bmc_induct_phase_failed": "medium",
    "amulet_verify_failed": "high",
    "tool_exit_nonzero": "low",
    "missing_log_or_parse_error": "low",
    "unknown": "low",
}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Explain guide_check failure packets into canonical failure_hints.json artifacts."
    )
    parser.add_argument("input", help="Input failure packet JSONL file.")
    parser.add_argument(
        "-o",
        "--output",
        default="failure_hints.json",
        help="Output JSON file.",
    )
    parser.add_argument(
        "--rule",
        action="store_true",
        help="Use rule-only mode without the online OpenAI-compatible API.",
    )
    parser.add_argument(
        "--model",
        default="",
        help="Model to use for the selected provider.",
    )
    parser.add_argument(
        "--max-packets",
        type=int,
        default=0,
        help="Limit the number of packets to explain. 0 means no limit.",
    )
    return parser.parse_args()


def load_packets(path: str) -> list[dict[str, Any]]:
    packets: list[dict[str, Any]] = []
    with open(path, "r", encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            packets.append(json.loads(line))
    return packets


def packet_id(packet: dict[str, Any]) -> str:
    if packet.get("packet_id"):
        return str(packet["packet_id"])
    joined = json.dumps(packet, sort_keys=True, ensure_ascii=True)
    return "fp_" + hashlib.sha256(joined.encode("utf-8")).hexdigest()[:16]


def pair_id(packet: dict[str, Any]) -> str:
    return str(packet.get("pair_id", "unknown_pair"))


def teacher_from_packet(packet: dict[str, Any]) -> dict[str, Any]:
    teacher = packet.get("teacher")
    if isinstance(teacher, dict):
        cls = str(teacher.get("class", packet.get("teacher_class", "unknown")))
        matched_clues = [str(x) for x in teacher.get("matched_clues", packet.get("clues", []))]
        raw_steps = teacher.get("allowed_step_ids", packet.get("next_steps", []))
    else:
        cls = str(packet.get("teacher_class", "unknown"))
        matched_clues = [str(x) for x in packet.get("clues", [])]
        raw_steps = packet.get("next_steps", [])

    allowed_step_ids: list[str] = []
    for step in raw_steps:
        step_id = normalize_step_id(step)
        if step_id and step_id not in allowed_step_ids:
            allowed_step_ids.append(step_id)

    if not allowed_step_ids:
        allowed_step_ids = ["inspect_command_log", "replay_failing_action"]

    return {
        "class": cls or "unknown",
        "matched_clues": matched_clues,
        "allowed_step_ids": allowed_step_ids,
    }


def normalize_step_id(step: Any) -> str:
    if not isinstance(step, str):
        return ""
    if step in STEP_REASON:
        return step
    return LEGACY_STEP_IDS.get(step.lower(), "")


def summarize_packet(packet: dict[str, Any], teacher: dict[str, Any]) -> str:
    teacher_class = teacher["class"]
    action = packet.get("action", "unknown_action")
    stage = packet.get("stage", "UNKNOWN")
    pid = pair_id(packet)
    proof_outcome = packet.get("proof_outcome", "unknown")
    clues = packet.get("clues", [])

    if teacher_class == "abc_miter_failed":
        return f"{stage} blocked on {pid} while running {action}; ABC could not build a usable miter."
    if teacher_class == "abc_not_equivalent_struct_hash":
        return f"{stage} reported a mismatch for {pid} during structural hashing while running {action}."
    if teacher_class == "abc_not_equivalent_sat":
        return f"{stage} reported a mismatch for {pid} after SAT while running {action}."
    if teacher_class == "abc_not_equivalent_generic":
        return f"{stage} reported a mismatch for {pid} while running {action}; replay the failing pair before changing heuristics."
    if teacher_class == "bmc_weak_failed":
        return f"{stage} blocked for {pid} while running {action}; weak-mode induction did not close."
    if teacher_class == "bmc_bmc_phase_failed":
        return f"{stage} blocked for {pid} while running {action}; the bounded phase did not close cleanly."
    if teacher_class == "bmc_induct_phase_failed":
        return f"{stage} blocked for {pid} while running {action}; the induction phase failed."
    if teacher_class == "amulet_verify_failed":
        return f"{stage} blocked for {pid} while running {action}; the multiplier-specific verification path rejected the candidate."
    if teacher_class == "tool_exit_nonzero":
        return f"{stage} hit a tool-side execution error for {pid} while running {action}."
    if teacher_class == "missing_log_or_parse_error":
        return f"{stage} failed for {pid} while running {action}; the packet is missing enough log context for a clean classification."
    if proof_outcome == "timeout":
        return f"{stage} timed out for {pid} while running {action}."
    if clues:
        return f"{stage} failed for {pid} while running {action}; primary clue: {clues[0]}."
    return f"{stage} failed for {pid} while running {action}; inspect the captured log before changing the proof path."


def default_step_objs(step_ids: list[str]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for idx, step_id in enumerate(step_ids, start=1):
        out.append(
            {
                "id": step_id,
                "rank": idx,
                "reason": STEP_REASON.get(step_id, "Inspect the captured failure context before changing the proof path."),
            }
        )
    return out


def build_llm_prompt(packet: dict[str, Any], teacher: dict[str, Any]) -> str:
    prompt_packet = dict(packet)
    prompt_packet["packet_id"] = packet_id(packet)
    prompt_packet["teacher"] = teacher
    packet_json = json.dumps(prompt_packet, indent=2, sort_keys=True)
    allowed_steps = ", ".join(teacher["allowed_step_ids"])
    return (
        "Generate equivalence-check debugging hints from this guide_check failure packet.\n"
        "Use only the packet contents.\n"
        "Do not decide whether the designs are equivalent.\n"
        "The teacher class is authoritative.\n"
        "You may only choose next-step ids from this allowed set:\n"
        f"{allowed_steps}\n"
        "Return strict JSON only with these keys:\n"
        "failure_kind, confidence, hint_summary, likely_causes, next_steps.\n"
        "Set failure_kind to the authoritative teacher class.\n"
        "Set next_steps to a ranked list of objects with keys id and reason.\n"
        "Do not invent new step ids.\n\n"
        f"{packet_json}"
    )


def extract_chat_text(completion: object) -> str:
    choices = getattr(completion, "choices", None) or []
    if not choices:
        raise RuntimeError("OpenAI chat response did not contain choices.")

    message = getattr(choices[0], "message", None)
    content = getattr(message, "content", None)
    if isinstance(content, str) and content:
        return content

    parts: list[str] = []
    for item in content or []:
        text = getattr(item, "text", None)
        if isinstance(text, str) and text:
            parts.append(text)

    if parts:
        return "\n".join(parts)
    finish_reason = getattr(choices[0], "finish_reason", None)
    raise RuntimeError(
        "OpenAI chat response did not contain text content; "
        f"finish_reason={finish_reason}"
    )


def parse_llm_json(text: str) -> dict[str, Any]:
    text = text.strip()
    if text.startswith("```"):
        lines = text.splitlines()
        if lines and lines[0].startswith("```"):
            lines = lines[1:]
        if lines and lines[-1].strip() == "```":
            lines = lines[:-1]
        text = "\n".join(lines).strip()
        if text.startswith("json"):
            text = text[4:].strip()
    return json.loads(text)


def validate_next_steps(raw_steps: Any, teacher: dict[str, Any]) -> list[dict[str, Any]]:
    allowed = teacher["allowed_step_ids"]
    out: list[dict[str, Any]] = []
    seen: set[str] = set()

    if isinstance(raw_steps, list):
        for item in raw_steps:
            if isinstance(item, dict):
                step_id = normalize_step_id(item.get("id"))
                reason = str(item.get("reason", "")).strip()
            else:
                step_id = normalize_step_id(item)
                reason = ""
            if not step_id or step_id not in allowed or step_id in seen:
                continue
            seen.add(step_id)
            out.append(
                {
                    "id": step_id,
                    "rank": len(out) + 1,
                    "reason": reason or STEP_REASON.get(step_id, "Inspect the failure context before changing the proof path."),
                }
            )

    if out:
        return out
    return default_step_objs(allowed)


def normalize_explanation(parsed: dict[str, Any], packet: dict[str, Any], teacher: dict[str, Any], kind: str) -> dict[str, Any]:
    teacher_class = teacher["class"]
    confidence = str(parsed.get("confidence", CONFIDENCE.get(teacher_class, "low"))).lower()
    if confidence not in {"low", "medium", "high"}:
        confidence = CONFIDENCE.get(teacher_class, "low")

    likely_causes = parsed.get("likely_causes", LIKELY_CAUSES.get(teacher_class, LIKELY_CAUSES["unknown"]))
    if not isinstance(likely_causes, list) or not likely_causes:
        likely_causes = LIKELY_CAUSES.get(teacher_class, LIKELY_CAUSES["unknown"])
    likely_causes = [str(x) for x in likely_causes]

    summary = str(parsed.get("hint_summary", "")).strip() or summarize_packet(packet, teacher)
    next_steps = validate_next_steps(parsed.get("next_steps"), teacher)

    return {
        "provider_kind": kind,
        "failure_kind": teacher_class,
        "confidence": confidence,
        "hint_summary": summary,
        "likely_causes": likely_causes,
        "next_steps": next_steps,
    }


def rule_explanation(packet: dict[str, Any], teacher: dict[str, Any]) -> dict[str, Any]:
    teacher_class = teacher["class"]
    return {
        "provider_kind": "rule",
        "failure_kind": teacher_class,
        "confidence": CONFIDENCE.get(teacher_class, "low"),
        "hint_summary": summarize_packet(packet, teacher),
        "likely_causes": LIKELY_CAUSES.get(teacher_class, LIKELY_CAUSES["unknown"]),
        "next_steps": default_step_objs(teacher["allowed_step_ids"]),
    }


def openai_api_key() -> str:
    return os.environ.get("EQGUIDE_OPENAI_API_KEY", "")


def openai_base_url() -> str:
    return os.environ.get("EQGUIDE_OPENAI_BASE_URL", "https://api.openai.com/v1")


def openai_explanation(
    packet: dict[str, Any],
    teacher: dict[str, Any],
    model: str,
) -> dict[str, Any]:
    api_key = openai_api_key()
    base_url = openai_base_url()
    if not api_key:
        raise RuntimeError("OpenAI-compatible API key is not set.")

    client = OpenAI(api_key=api_key, base_url=base_url, timeout=60.0)
    completion = client.chat.completions.create(
        model=model,
        messages=[
            {
                "role": "system",
                "content": (
                    "Return strict JSON only. "
                    "Use the authoritative teacher class and only the allowed step ids."
                ),
            },
            {"role": "user", "content": build_llm_prompt(packet, teacher)},
        ],
    )
    parsed = parse_llm_json(extract_chat_text(completion))
    return normalize_explanation(parsed, packet, teacher, "openai")


def explain_packet(
    packet: dict[str, Any],
    use_rule: bool,
    model: str,
) -> dict[str, Any]:
    teacher = teacher_from_packet(packet)
    explanation = rule_explanation(packet, teacher)
    provider_error = ""

    try:
        if not use_rule:
            explanation = openai_explanation(packet, teacher, model)
    except Exception as exc:
        provider_error = str(exc)

    item = {
        "packet_id": packet_id(packet),
        "pair_id": pair_id(packet),
        "scope": str(packet.get("scope", "pair")),
        "engine": str(packet.get("engine", "unknown")),
        "stage": str(packet.get("stage", "UNKNOWN")),
        "action": str(packet.get("action", "unknown_action")),
        "proof_outcome": str(packet.get("proof_outcome", "unknown")),
        "failure_kind": explanation["failure_kind"],
        "confidence": explanation["confidence"],
        "hint_summary": explanation["hint_summary"],
        "likely_causes": explanation["likely_causes"],
        "next_steps": explanation["next_steps"],
        "teacher": teacher,
    }
    if provider_error:
        item["provider_error"] = provider_error
    return item


def provider_kind(args: argparse.Namespace) -> str:
    return "rule" if args.rule else "openai"


def provider_model(args: argparse.Namespace) -> str | None:
    if args.rule:
        return None
    if args.model:
        return args.model
    return os.environ.get("EQGUIDE_OPENAI_MODEL", DEFAULT_OPENAI_MODEL)


def main() -> int:
    args = parse_args()
    model = provider_model(args)
    packets = load_packets(args.input)
    if args.max_packets > 0:
        packets = packets[: args.max_packets]

    items = [
        explain_packet(
            packet,
            args.rule,
            model or "",
        )
        for packet in packets
    ]

    output = {
        "schema_version": SCHEMA_VERSION,
        "source_fail_jsonl": os.path.abspath(args.input),
        "provider": {
            "kind": provider_kind(args),
            "model": model,
        },
        "items": items,
    }

    with open(args.output, "w", encoding="utf-8") as handle:
        json.dump(output, handle, indent=2, sort_keys=True)
        handle.write("\n")

    return 0


if __name__ == "__main__":
    sys.exit(main())
