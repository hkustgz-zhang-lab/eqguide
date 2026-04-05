#!/usr/bin/env python3

import argparse
import pathlib
import subprocess
import sys


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run the guide_check failure explainer on a fail.jsonl file or testcase directory."
    )
    parser.add_argument(
        "input",
        help="Path to fail.jsonl or a testcase directory containing fail.jsonl.",
    )
    parser.add_argument(
        "-o",
        "--output",
        default="failure_explained.json",
        help="Output JSON file. If a testcase directory is given, this is relative to that directory.",
    )
    parser.add_argument(
        "--use-openai",
        action="store_true",
        help="Use the OpenAI-backed explainer path.",
    )
    parser.add_argument(
        "--use-gemini",
        action="store_true",
        help="Use the Gemini-backed explainer path.",
    )
    parser.add_argument(
        "--use-qwen",
        action="store_true",
        help="Use the Qwen-backed explainer path.",
    )
    parser.add_argument(
        "--online",
        action="store_true",
        help="Use the default online provider (Qwen).",
    )
    parser.add_argument(
        "--max-packets",
        type=int,
        default=0,
        help="Limit the number of packets to explain. 0 means no limit.",
    )
    return parser.parse_args()


def resolve_input(path_str: str) -> tuple[pathlib.Path, pathlib.Path]:
    path = pathlib.Path(path_str)
    if path.is_dir():
        return path.resolve() / "fail.jsonl", path.resolve()
    return path.resolve(), path.resolve().parent


def main() -> int:
    args = parse_args()
    input_path, workdir = resolve_input(args.input)
    script = pathlib.Path(__file__).with_name("explain_failures.py")

    cmd = [
        sys.executable,
        str(script),
        str(input_path),
        "-o",
        args.output,
    ]
    if args.use_openai:
        cmd.append("--use-openai")
    if args.use_gemini:
        cmd.append("--use-gemini")
    if args.use_qwen:
        cmd.append("--use-qwen")
    if args.online:
        cmd.append("--online")
    if args.max_packets > 0:
        cmd.extend(["--max-packets", str(args.max_packets)])

    proc = subprocess.run(cmd, cwd=workdir, text=True, capture_output=True)
    if proc.returncode != 0:
        raise SystemExit(proc.stderr.strip() or proc.stdout.strip() or "failure explainer failed")

    print(f"Wrote {workdir / args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
