#!/usr/bin/env python3

import argparse
import json
import os
import sys
import urllib.error
import urllib.request
from typing import Any

import dashscope
from dashscope import Generation
from openai import OpenAI


DEFAULT_MODEL = "GLM-4.7"
DEFAULT_GEMINI_MODEL = "gemini-2.5-flash"
DEFAULT_QWEN_MODEL = "qwen-max"


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
        help="Use the OpenAI-compatible API to explain packets.",
    )
    parser.add_argument(
        "--use-gemini",
        action="store_true",
        help="Use the Gemini API to explain packets.",
    )
    parser.add_argument(
        "--use-qwen",
        action="store_true",
        help="Use the Qwen API to explain packets.",
    )
    parser.add_argument(
        "--online",
        action="store_true",
        help="Use the default online provider (Qwen).",
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
    teacher_class = packet.get("teacher_class", "unknown_failure")
    likely_causes = {
        "abc_miter_failed": [
            "miter construction failed before proof completed",
            "signal name mapping may be too sparse or misleading",
            "the current action ordering may not fit this module pair",
        ],
        "retime_or_warmup_issue": [
            "sequential proof depth may be too small",
            "warmup or retime handling may be mismatched",
            "retimed structure may need a different proof order",
        ],
        "multiplier_annotation_or_sca_issue": [
            "multiplier annotation may not match the extracted logic",
            "signedness or width assumptions may be wrong",
            "blackboxing or multiplier preprocessing may have changed module shape",
        ],
        "not_equivalent_counterexample": [
            "the engines reported a concrete non-equivalence condition",
            "matching may have aligned the wrong signals",
            "an upstream transform may have changed behavior",
        ],
        "unknown_failure": [
            "the proof flow failed without a recognized clue",
            "the tool log needs manual inspection",
        ],
    }
    confidence = {
        "abc_miter_failed": "medium",
        "retime_or_warmup_issue": "medium",
        "multiplier_annotation_or_sca_issue": "high",
        "not_equivalent_counterexample": "medium",
        "unknown_failure": "low",
    }
    failure_kind = {
        "abc_miter_failed": "proof_path_blocked",
        "retime_or_warmup_issue": "sequential_proof_blocked",
        "multiplier_annotation_or_sca_issue": "multiplier_verification_blocked",
        "not_equivalent_counterexample": "possible_real_mismatch",
        "unknown_failure": "unknown_failure",
    }
    return {
        "mode": "rule",
        "failure_kind": failure_kind.get(teacher_class, "unknown_failure"),
        "confidence": confidence.get(teacher_class, "low"),
        "hint_summary": summarize_packet(packet),
        "likely_causes": likely_causes.get(teacher_class, likely_causes["unknown_failure"]),
        "next_steps": packet.get(
            "next_steps",
            ["inspect command log", "replay failing action manually"],
        ),
    }


def openai_api_key() -> str:
    return env_first("EQGUIDE_OPENAI_API_KEY", "OPENAI_API_KEY", "OPENAI_AI_KEY")


def openai_base_url() -> str:
    return env_first("EQGUIDE_OPENAI_BASE_URL", "OPENAI_BASE_URL", default="https://api.openai.com/v1")


def gemini_api_key() -> str:
    return env_first("EQGUIDE_GEMINI_API_KEY", "GEMINI_API_KEY")


def gemini_base_url() -> str:
    return env_first("EQGUIDE_GEMINI_BASE_URL", default="https://generativelanguage.googleapis.com/v1beta")


def qwen_api_key() -> str:
    return env_first("EQGUIDE_QWEN_API_KEY", "DASHSCOPE_API_KEY")


def build_llm_prompt(packet: dict[str, Any]) -> str:
    packet_json = json.dumps(packet, indent=2, sort_keys=True)
    return (
        "Generate equivalence-check debugging hints from this guide_check failure packet.\n"
        "Use only the packet contents.\n"
        "Do not decide whether the designs are equivalent.\n"
        "Focus on why the equivalence-check did not complete cleanly and what to inspect next.\n"
        "Do not claim structural or functional non-equivalence unless the packet explicitly states it.\n"
        "Produce a concise hint summary, likely causes, and ranked next steps.\n\n"
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
    finish_reason = getattr(choices[0], "finish_reason", None)
    reasoning_content = getattr(message, "reasoning_content", None)
    if isinstance(reasoning_content, str) and reasoning_content:
        raise RuntimeError(
            "Provider returned empty completion content; "
            f"finish_reason={finish_reason}, reasoning_content_present=yes"
        )
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


def gemini_explanation(packet: dict[str, Any], model: str) -> dict[str, Any]:
    api_key = gemini_api_key()
    if not api_key:
        raise RuntimeError("EQGUIDE_GEMINI_API_KEY or GEMINI_API_KEY is not set.")

    payload = {
        "contents": [
            {
                "role": "user",
                "parts": [
                    {
                        "text": (
                            "Return strict JSON only.\n"
                            "Use exactly these keys: failure_kind, confidence, hint_summary, likely_causes, next_steps.\n"
                            "Do not wrap the JSON in markdown fences.\n\n"
                            + build_llm_prompt(packet)
                        )
                    }
                ],
            }
        ],
        "generationConfig": {
            "responseMimeType": "application/json",
            "temperature": 0.1,
        },
    }

    url = f"{gemini_base_url().rstrip('/')}/models/{model}:generateContent"
    request = urllib.request.Request(
        url,
        data=json.dumps(payload).encode("utf-8"),
        headers={
            "Content-Type": "application/json",
            "x-goog-api-key": api_key,
        },
        method="POST",
    )

    try:
        with urllib.request.urlopen(request, timeout=60) as response:
            response_json = json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", errors="replace")
        raise RuntimeError(f"Gemini HTTP {exc.code}: {body}") from exc

    candidates = response_json.get("candidates", [])
    if not candidates:
        raise RuntimeError("Gemini response did not contain candidates.")
    parts = candidates[0].get("content", {}).get("parts", [])
    text = "\n".join(part.get("text", "") for part in parts if part.get("text"))
    if not text:
        raise RuntimeError("Gemini response did not contain text content.")

    parsed = parse_llm_json(text)
    return {
        "mode": "gemini",
        "failure_kind": parsed["failure_kind"],
        "confidence": parsed["confidence"],
        "hint_summary": parsed["hint_summary"],
        "likely_causes": parsed["likely_causes"],
        "next_steps": parsed["next_steps"],
    }


def qwen_explanation(packet: dict[str, Any], model: str) -> dict[str, Any]:
    api_key = qwen_api_key()
    if not api_key:
        raise RuntimeError("EQGUIDE_QWEN_API_KEY or DASHSCOPE_API_KEY is not set.")

    dashscope.api_key = api_key
    prompt = build_llm_prompt(packet)
    system_prompt = (
        "Return strict JSON with this shape only: "
        '{"failure_kind":"<string>","confidence":"<string>","hint_summary":"<string>",'
        '"likely_causes":["<string>"],"next_steps":["<string>"]}.'
    )
    response = Generation.call(
        model=model,
        messages=[
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": prompt},
        ],
        result_format="message",
    )
    if getattr(response, "status_code", None) != 200:
        raise RuntimeError(
            "Qwen request failed: "
            f"status={getattr(response, 'status_code', None)} "
            f"code={getattr(response, 'code', None)} "
            f"message={getattr(response, 'message', None)}"
        )

    content = response.output.choices[0]["message"]["content"]
    parsed = parse_llm_json(content)
    return {
        "mode": "qwen",
        "failure_kind": parsed["failure_kind"],
        "confidence": parsed["confidence"],
        "hint_summary": parsed["hint_summary"],
        "likely_causes": parsed["likely_causes"],
        "next_steps": parsed["next_steps"],
    }


def openai_explanation(packet: dict[str, Any], model: str) -> dict[str, Any]:
    api_key = openai_api_key()
    if not api_key:
        raise RuntimeError("EQGUIDE_OPENAI_API_KEY, OPENAI_API_KEY, or OPENAI_AI_KEY is not set.")
    base_url = openai_base_url()

    client = OpenAI(api_key=api_key, base_url=base_url, timeout=60.0)
    prompt = build_llm_prompt(packet)
    format_instruction = (
        "Return strict JSON with this shape only: "
        '{"failure_kind":"<string>","confidence":"<string>","hint_summary":"<string>",'
        '"likely_causes":["<string>"],"next_steps":["<string>"]}.'
    )
    completion = client.chat.completions.create(
        model=model,
        messages=[
            {"role": "system", "content": format_instruction},
            {"role": "user", "content": prompt},
        ],
    )
    response_text = extract_chat_text(completion)

    parsed = parse_llm_json(response_text)
    return {
        "mode": "openai",
        "failure_kind": parsed["failure_kind"],
        "confidence": parsed["confidence"],
        "hint_summary": parsed["hint_summary"],
        "likely_causes": parsed["likely_causes"],
        "next_steps": parsed["next_steps"],
    }


def explain_packet(packet: dict[str, Any], use_openai: bool, use_gemini: bool, use_qwen: bool, model: str) -> dict[str, Any]:
    explanation = rule_explanation(packet)
    if use_qwen:
        try:
            explanation = qwen_explanation(packet, model)
        except Exception as exc:
            explanation["mode"] = "rule_with_qwen_error"
            explanation["llm_error"] = str(exc)
    elif use_gemini:
        try:
            explanation = gemini_explanation(packet, model)
        except Exception as exc:
            explanation["mode"] = "rule_with_gemini_error"
            explanation["llm_error"] = str(exc)
    elif use_openai:
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
    if args.online:
        args.use_qwen = True

    if sum([1 if args.use_openai else 0, 1 if args.use_gemini else 0, 1 if args.use_qwen else 0]) > 1:
        raise SystemExit("Use only one of --use-openai, --use-gemini, --use-qwen, or --online.")

    model = args.model
    if not model:
        if args.use_qwen:
            model = env_first("EQGUIDE_QWEN_MODEL", default=DEFAULT_QWEN_MODEL)
        elif args.use_gemini:
            model = env_first("EQGUIDE_GEMINI_MODEL", default=DEFAULT_GEMINI_MODEL)
        elif args.use_openai:
            model = env_first("EQGUIDE_OPENAI_MODEL", "OPENAI_MODEL", default=DEFAULT_MODEL)

    packets = load_packets(args.input)
    if args.max_packets > 0:
        packets = packets[: args.max_packets]

    explained = [
        explain_packet(packet, args.use_openai, args.use_gemini, args.use_qwen, model)
        for packet in packets
    ]

    output = {
        "input": args.input,
        "mode": "qwen" if args.use_qwen else ("gemini" if args.use_gemini else ("openai" if args.use_openai else "rule")),
        "model": model if (args.use_openai or args.use_gemini or args.use_qwen) else None,
        "items": explained,
    }

    with open(args.output, "w", encoding="utf-8") as handle:
        json.dump(output, handle, indent=2, sort_keys=True)
        handle.write("\n")

    return 0


if __name__ == "__main__":
    sys.exit(main())
