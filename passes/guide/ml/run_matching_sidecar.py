#!/usr/bin/env python3

import argparse
import json
import os
import pathlib
import subprocess
import sys


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run guide_check with match dump enabled, then run CatBoost matching inference."
    )
    parser.add_argument("case_dir", help="Case directory under yosys-guide-test or an explicit path.")
    parser.add_argument("--model", required=True, help="CatBoost .cbm model path.")
    parser.add_argument("--yosys", default="../../yosys/yosys")
    parser.add_argument("--datdir", default="../../yosys/share")
    parser.add_argument("--snapshot", default="pre_async")
    parser.add_argument("--output", default="match_suggestions.json")
    parser.add_argument("--min-score", type=float, default=None)
    parser.add_argument("--min-margin", type=float, default=None)
    return parser.parse_args()


def case_path(name: str) -> pathlib.Path:
    path = pathlib.Path(name)
    if path.exists():
        return path.resolve()
    root = pathlib.Path(__file__).resolve().parents[4] / "yosys-guide-test"
    return (root / name).resolve()


def inject_dump(verific_path: pathlib.Path) -> str:
    lines = verific_path.read_text(encoding="utf-8").splitlines()
    out_lines = []
    found = False
    for line in lines:
        stripped = line.strip()
        if stripped.startswith("guide_check "):
            found = True
            if "-guide-dump-match" not in stripped:
                line = line.replace("guide_check ", "guide_check -guide-dump-match match.jsonl ", 1)
        out_lines.append(line)
    if not found:
        raise RuntimeError(f"No plain guide_check line found in {verific_path}")
    return "\n".join(out_lines) + "\n"


def run_case(case_dir: pathlib.Path, yosys_rel: str, datdir_rel: str) -> None:
    verific = case_dir / "verific.ys"
    temp_verific = case_dir / "verific_match_sidecar_tmp.ys"
    temp_verific.write_text(inject_dump(verific), encoding="utf-8")
    try:
        env = dict(os.environ)
        env["YOSYS_DATDIR"] = datdir_rel
        proc = subprocess.run(
            [yosys_rel, "-q", "-s", temp_verific.name],
            cwd=case_dir,
            env=env,
            text=True,
            capture_output=True,
        )
        if proc.returncode != 0:
            raise RuntimeError(proc.stderr.strip() or proc.stdout.strip() or "guide_check failed")
    finally:
        if temp_verific.exists():
            temp_verific.unlink()


def main() -> int:
    args = parse_args()
    case_dir = case_path(args.case_dir)
    model_path = pathlib.Path(args.model).resolve()
    run_case(case_dir, args.yosys, args.datdir)
    infer_script = pathlib.Path(__file__).with_name("infer_matching.py")
    cmd = [
        sys.executable,
        str(infer_script),
        "match.jsonl",
        "--model",
        str(model_path),
        "--snapshot",
        args.snapshot,
        "-o",
        args.output,
    ]
    if args.min_score is not None:
        cmd.extend(["--min-score", str(args.min_score)])
    if args.min_margin is not None:
        cmd.extend(["--min-margin", str(args.min_margin)])
    proc = subprocess.run(cmd, cwd=case_dir, text=True, capture_output=True)
    if proc.returncode != 0:
        raise SystemExit(proc.stderr.strip() or proc.stdout.strip() or "matching inference failed")
    output_path = case_dir / args.output
    suggestions = json.loads(output_path.read_text(encoding="utf-8"))
    print(f"Wrote {output_path}")
    print(f"Suggestions: {len(suggestions)}")
    if not suggestions:
        print("No suggestions passed the default thresholds.")
        print("Retry with --min-score -1e18 --min-margin -1e18 to inspect all top-ranked candidates.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
