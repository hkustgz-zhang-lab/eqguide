#!/usr/bin/env python3

import argparse
import os
import pathlib
import subprocess


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run guide_check testcases and collect match.jsonl files."
    )
    parser.add_argument(
        "cases",
        nargs="+",
        help="Case directories under yosys-guide-test or absolute/relative paths.",
    )
    parser.add_argument(
        "--yosys",
        default="../../yosys/yosys",
        help="Relative yosys path from testcase directories.",
    )
    parser.add_argument(
        "--datdir",
        default="../../yosys/share",
        help="Relative YOSYS_DATDIR path from testcase directories.",
    )
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
    injected = False
    for line in lines:
        stripped = line.strip()
        if stripped.startswith("guide_check ") and "-guide-dump-match" not in stripped:
            line = line.replace("guide_check ", "guide_check -guide-dump-match match.jsonl ", 1)
            injected = True
        out_lines.append(line)
    if not injected:
        raise RuntimeError(f"No plain guide_check line found in {verific_path}")
    return "\n".join(out_lines) + "\n"


def run_case(case_dir: pathlib.Path, yosys_rel: str, datdir_rel: str) -> tuple[bool, str]:
    verific = case_dir / "verific.ys"
    if not verific.exists():
        return False, f"missing {verific.name}"

    temp_verific = case_dir / "verific_match_tmp.ys"
    temp_verific.write_text(inject_dump(verific), encoding="utf-8")
    try:
        match = case_dir / "match.jsonl"
        if match.exists():
            match.unlink()
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
            return False, proc.stderr.strip() or proc.stdout.strip() or "guide_check failed"
        if not match.exists():
            return False, "match.jsonl not produced"
        return True, "ok"
    finally:
        if temp_verific.exists():
            temp_verific.unlink()


def main() -> int:
    args = parse_args()
    failed = False
    for case in args.cases:
        case_dir = case_path(case)
        ok, msg = run_case(case_dir, args.yosys, args.datdir)
        print(f"{case_dir.name}: {msg}")
        failed = failed or not ok
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
