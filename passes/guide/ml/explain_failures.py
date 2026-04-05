#!/usr/bin/env python3

import argparse
import json
import os
import sys
from typing import Any

from openai import OpenAI


DEFAULT_MODEL = "GLM-4.7"


def env_first(*names: str, default: str = "") -> str:
    for name in names:
        value = os.environ.get(name)
        if value:
            return value
    return default


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Explain guide_check failure packets with rules or OpenAI."
    )
    parser.add_argument("input", help="Input failure packet JSONL file.")
    parser.add_argument(
        "-o",
        "--output",
        default="failure_explained.json",
        help="Output JSON file.",
    )
    parser.add_argument(
        "--use-openai",
        action="store_true",
        help="Use the OpenAI Responses API to explain packets.",
    )
    parser.add_argument(
        "--model",
        default=env_first("EQGUIDE_OPENAI_MODEL", "OPENAI_MODEL", default=DEFAULT_MODEL),
        help=f"Model to use for OpenAI mode. Default: {DEFAULT_MODEL}",
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


def summarize_packet(packet: dict[str, Any]) -> str:
    teacher_class = packet.get("teacher_class", "unknown_failure")
    action = packet.get("action", "unknown_action")
    stage = packet.get("stage", "UNKNOWN")
    pair_id = packet.get("pair_id", "unknown_pair")
    clues = packet.get("clues", [])

    if teacher_class == "abc_miter_failed":
        return f"{stage} failed for {pair_id} while running {action}; ABC could not build a usable miter."
    if teacher_class == "retime_or_warmup_issue":
        return f"{stage} failed for {pair_id} while running {action}; the packet looks consistent with a retime or warmup issue."
    if teacher_class == "multiplier_annotation_or_sca_issue":
        return f"{stage} failed for {pair_id} while running {action}; the multiplier-specific flow rejected the candidate module."
    if teacher_class == "not_equivalent_counterexample":
        return f"{stage} reported a non-equivalence result for {pair_id} while running {action}."
    if clues:
        return f"{stage} failed for {pair_id} while running {action}; primary clue: {clues[0]}."
    return f"{stage} failed for {pair_id} while running {action}; inspect the command log for the root cause."


def rule_explanation(packet: dict[str, Any]) -> dict[str, Any]:
    return {
        "mode": "rule",
        "summary": summarize_packet(packet),
        "teacher_class": packet.get("teacher_class", "unknown_failure"),
        "next_steps": packet.get(
            "next_steps",
            ["inspect command log", "replay failing action manually"],
        ),
    }


def openai_api_key() -> str:
    return env_first("EQGUIDE_OPENAI_API_KEY", "OPENAI_API_KEY", "OPENAI_AI_KEY")


def openai_base_url() -> str:
    return env_first("EQGUIDE_OPENAI_BASE_URL", "OPENAI_BASE_URL", default="https://api.openai.com/v1")


def build_llm_prompt(packet: dict[str, Any]) -> str:
    packet_json = json.dumps(packet, indent=2, sort_keys=True)
    return (
        "Explain this guide_check failure packet.\n"
        "Use only the packet contents.\n"
        "Do not decide whether the designs are equivalent.\n"
        "Produce a concise explanation and rank the next steps.\n\n"
        f"{packet_json}"
    )


def extract_response_text(response: object) -> str:
    output_text = getattr(response, "output_text", None)
    if isinstance(output_text, str) and output_text:
        return output_text

    output = getattr(response, "output", None) or []
    for item in output:
        content = getattr(item, "content", None) or []
        for entry in content:
            text = getattr(entry, "text", None)
            if isinstance(text, str) and text:
                return text

    raise RuntimeError("OpenAI response did not contain text output.")


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
    raise RuntimeError("OpenAI chat response did not contain text content.")


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


def openai_explanation(packet: dict[str, Any], model: str) -> dict[str, Any]:
    api_key = openai_api_key()
    if not api_key:
        raise RuntimeError("EQGUIDE_OPENAI_API_KEY, OPENAI_API_KEY, or OPENAI_AI_KEY is not set.")
    base_url = openai_base_url()

    schema = {
        "type": "object",
        "properties": {
            "summary": {"type": "string"},
            "next_steps": {
                "type": "array",
                "items": {"type": "string"},
                "minItems": 1,
                "maxItems": 3,
            },
        },
        "required": ["summary", "next_steps"],
        "additionalProperties": False,
    }

    client = OpenAI(api_key=api_key, base_url=base_url, timeout=60.0)
    prompt = build_llm_prompt(packet)
    format_instruction = (
        "Return strict JSON with this shape only: "
        '{"summary": "<string>", "next_steps": ["<string>", "<string>"]}.'
    )
    response_text = ""

    try:
        completion = client.chat.completions.create(
            model=model,
            messages=[
                {"role": "system", "content": format_instruction},
                {"role": "user", "content": prompt},
            ],
            max_completion_tokens=1024,
        )
        response_text = extract_chat_text(completion)
    except Exception:
        response = client.responses.create(
            model=model,
            input=prompt,
            text={
                "format": {
                    "type": "json_schema",
                    "name": "guide_check_failure_explainer",
                    "schema": schema,
                    "strict": True,
                }
            },
            max_output_tokens=1024,
        )
        response_text = extract_response_text(response)

    parsed = parse_llm_json(response_text)
    return {
        "mode": "openai",
        "summary": parsed["summary"],
        "teacher_class": packet.get("teacher_class", "unknown_failure"),
        "next_steps": parsed["next_steps"],
    }


def explain_packet(packet: dict[str, Any], use_openai: bool, model: str) -> dict[str, Any]:
    explanation = rule_explanation(packet)
    if use_openai:
        try:
            explanation = openai_explanation(packet, model)
        except Exception as exc:
            explanation["mode"] = "rule_with_openai_error"
            explanation["llm_error"] = str(exc)

    return {
        "packet": packet,
        "explanation": explanation,
    }


def main() -> int:
    args = parse_args()
    packets = load_packets(args.input)
    if args.max_packets > 0:
        packets = packets[: args.max_packets]

    explained = [
        explain_packet(packet, args.use_openai, args.model)
        for packet in packets
    ]

    output = {
        "input": args.input,
        "mode": "openai" if args.use_openai else "rule",
        "model": args.model if args.use_openai else None,
        "items": explained,
    }

    with open(args.output, "w", encoding="utf-8") as handle:
        json.dump(output, handle, indent=2, sort_keys=True)
        handle.write("\n")

    return 0


if __name__ == "__main__":
    sys.exit(main())
