#!/usr/bin/env python3

import argparse
import shutil
import json
import os
import pathlib
import re
import subprocess
import sys
import time
from typing import Dict, List


GUIDE_CHECK_RE = re.compile(r"^\s*guide_check\s+")
FINAL_RESULT_RE = re.compile(r"GUIDE_CHECK\s+(PASSED|FAILED):")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Replay baseline, local-validate-shadow, and validated-matching runs for guide_check."
    )
    parser.add_argument("case_dir", help="Case directory under yosys-guide-test or an explicit path.")
    parser.add_argument("--model", help="CatBoost .cbm model path for matching sidecar inference.")
    parser.add_argument("--yosys", default="../../yosys/yosys")
    parser.add_argument("--datdir", default="../../yosys/share")
    parser.add_argument("--snapshot", default="pre_async")
    parser.add_argument("--output", default="local_validate_replay.json")
    parser.add_argument("--min-score", type=float, default=None)
    parser.add_argument("--min-margin", type=float, default=None)
    parser.add_argument("--suggestions-file", help="Use an explicit suggestions JSON file instead of rerunning sidecar inference.")
    parser.add_argument("--support-slice", action="store_true", help="Enable support-sliced local validation for DFF suggestions.")
    return parser.parse_args()


def case_path(name: str) -> pathlib.Path:
    path = pathlib.Path(name)
    if path.exists():
        return path.resolve()
    root = pathlib.Path(__file__).resolve().parents[4] / "yosys-guide-test"
    return (root / name).resolve()


def rewrite_guide_check(verific_path: pathlib.Path, extra_flags: List[str], strip_flags: List[str] | None = None) -> str:
    lines = verific_path.read_text(encoding="utf-8").splitlines()
    out_lines = []
    found = False
    strip_flags = strip_flags or []
    for line in lines:
        stripped = line.strip()
        if GUIDE_CHECK_RE.match(stripped):
            found = True
            prefix = line[:line.find("guide_check")] if "guide_check" in line else ""
            parts = stripped.split()
            filtered = []
            i = 1
            while i < len(parts):
                tok = parts[i]
                if tok in strip_flags:
                    if i + 1 < len(parts) and not parts[i + 1].startswith("-"):
                        i += 2
                    else:
                        i += 1
                    continue
                filtered.append(tok)
                i += 1
            line = prefix + "guide_check " + " ".join(extra_flags + filtered)
        out_lines.append(line)
    if not found:
        raise RuntimeError(f"No guide_check line found in {verific_path}")
    return "\n".join(out_lines) + "\n"


def run_script(case_dir: pathlib.Path, script_text: str, yosys_rel: str, datdir_rel: str) -> Dict[str, object]:
    temp_script = case_dir / "verific_local_validate_replay_tmp.ys"
    temp_script.write_text(script_text, encoding="utf-8")
    env = dict(os.environ)
    env["YOSYS_DATDIR"] = datdir_rel
    start = time.time()
    try:
        proc = subprocess.run(
            [yosys_rel, "-s", temp_script.name],
            cwd=case_dir,
            env=env,
            text=True,
            capture_output=True,
        )
    finally:
        if temp_script.exists():
            temp_script.unlink()
    wall_ms = (time.time() - start) * 1000.0
    output = (proc.stdout or "") + (proc.stderr or "")
    final = "unknown"
    match = FINAL_RESULT_RE.search(output)
    if match:
        final = match.group(1).lower()
    return {
        "returncode": proc.returncode,
        "wall_time_ms": wall_ms,
        "final_result": final,
        "output": output,
    }


def count_raw_dff_suggestions(path: pathlib.Path) -> int:
    if not path.exists():
        return 0
    data = json.loads(path.read_text(encoding="utf-8"))
    return sum(1 for item in data if item.get("type") in {"DFF", "DFF_PO"})


def read_jsonl(path: pathlib.Path) -> List[dict]:
    rows = []
    if not path.exists():
        return rows
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        rows.append(json.loads(line))
    return rows


def remove_old_artifacts(case_dir: pathlib.Path) -> None:
    for pattern in (
        "match_exact_*.txt",
        "match_validated_*.txt",
        "match_suggestions_*.jsonl",
        "local_validate_*.jsonl",
    ):
        for path in case_dir.glob(pattern):
            if path.is_file():
                path.unlink()


def main() -> int:
    args = parse_args()
    case_dir = case_path(args.case_dir)
    verific = case_dir / "verific.ys"
    if not verific.exists():
        raise SystemExit(f"Missing {verific}")

    remove_old_artifacts(case_dir)

    baseline = run_script(case_dir, verific.read_text(encoding="utf-8"), args.yosys, args.datdir)
    shadow = run_script(
        case_dir,
        rewrite_guide_check(verific, ["-local-validate-shadow"]),
        args.yosys,
        args.datdir,
    )

    accepted = None
    raw_dff_suggestions = 0
    skipped_dff_suggestions = 0
    validated_dff_suggestions = 0
    rejected_dff_suggestions = 0
    local_validator_runs = 0
    local_validator_runtime_ms = 0.0
    local_bmc_fallback_runs = 0
    shadow_validator_runs = 0
    shadow_validator_runtime_ms = 0.0
    shadow_bmc_fallback_runs = 0
    selected_cutpoints = []
    local_exact_totals = []

    if args.model or args.suggestions_file:
        suggestions_path = case_dir / "match_suggestions_replay.json"
        if args.suggestions_file:
            shutil.copyfile(pathlib.Path(args.suggestions_file).resolve(), suggestions_path)
        else:
            model_path = pathlib.Path(args.model).resolve()
            sidecar = pathlib.Path(__file__).with_name("run_matching_sidecar.py")
            cmd = [
                sys.executable,
                str(sidecar),
                str(case_dir),
                "--model",
                str(model_path),
                "--snapshot",
                args.snapshot,
                "--output",
                suggestions_path.name,
            ]
            if args.min_score is not None:
                cmd.extend(["--min-score", str(args.min_score)])
            if args.min_margin is not None:
                cmd.extend(["--min-margin", str(args.min_margin)])
            proc = subprocess.run(cmd, cwd=case_dir, text=True, capture_output=True)
            if proc.returncode != 0:
                raise SystemExit(proc.stderr.strip() or proc.stdout.strip() or "matching sidecar failed")

        raw_dff_suggestions = count_raw_dff_suggestions(suggestions_path)

        accepted = run_script(
            case_dir,
            rewrite_guide_check(
                verific,
                (["-local-validate-support-slice"] if args.support_slice else []) +
                ["-guide-accept-match-suggestions", suggestions_path.name],
                ["-guide-dump-match", "-guide-dump-sched", "-guide-dump-fail"],
            ),
            args.yosys,
            args.datdir,
        )

        for path in sorted(case_dir.glob("local_validate_*.jsonl")):
            for row in read_jsonl(path):
                source = row.get("source")
                if source == "shadow_dff_set":
                    if row.get("validator_result") in {"pass", "fail"}:
                        shadow_validator_runs += 1
                        shadow_validator_runtime_ms += float(row.get("runtime_ms", 0.0))
                        if row.get("used_bmc_fallback"):
                            shadow_bmc_fallback_runs += 1
                    continue
                if source != "ml_raw":
                    continue
                if row.get("validator_result") == "skip":
                    skipped_dff_suggestions += 1
                elif row.get("accepted"):
                    validated_dff_suggestions += 1
                else:
                    rejected_dff_suggestions += 1
                if row.get("validator_result") in {"pass", "fail"}:
                    local_validator_runs += 1
                    local_validator_runtime_ms += float(row.get("runtime_ms", 0.0))
                    if row.get("used_bmc_fallback"):
                        local_bmc_fallback_runs += 1
                    if "selected_cutpoints" in row:
                        selected_cutpoints.append(float(row["selected_cutpoints"]))
                    if "local_exact_total" in row:
                        local_exact_totals.append(float(row["local_exact_total"]))

    def avg(values: list[float]) -> float:
        if not values:
            return 0.0
        return sum(values) / len(values)

    def median(values: list[float]) -> float:
        if not values:
            return 0.0
        ordered = sorted(values)
        n = len(ordered)
        mid = n // 2
        if n % 2:
            return ordered[mid]
        return (ordered[mid - 1] + ordered[mid]) / 2.0

    report = {
        "case": case_dir.name,
        "baseline_pass_fail": baseline["final_result"],
        "shadow_pass_fail": shadow["final_result"],
        "raw_dff_suggestions": raw_dff_suggestions,
        "validated_dff_suggestions": validated_dff_suggestions,
        "rejected_dff_suggestions": rejected_dff_suggestions,
        "skipped_dff_suggestions": skipped_dff_suggestions,
        "local_validator_runs": local_validator_runs,
        "local_validator_runtime_ms": local_validator_runtime_ms,
        "local_bmc_fallback_runs": local_bmc_fallback_runs,
        "avg_selected_cutpoints": avg(selected_cutpoints),
        "median_selected_cutpoints": median(selected_cutpoints),
        "avg_local_exact_total": avg(local_exact_totals),
        "slice_mode": "support_slice" if args.support_slice else "all_dff",
        "shadow_validator_runs": shadow_validator_runs,
        "shadow_validator_runtime_ms": shadow_validator_runtime_ms,
        "shadow_bmc_fallback_runs": shadow_bmc_fallback_runs,
        "final_pass_fail": accepted["final_result"] if accepted is not None else shadow["final_result"],
        "baseline_wall_time_ms": baseline["wall_time_ms"],
        "shadow_wall_time_ms": shadow["wall_time_ms"],
        "accepted_wall_time_ms": accepted["wall_time_ms"] if accepted is not None else None,
    }

    output_path = case_dir / args.output
    output_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(report, indent=2, sort_keys=True))
    print(f"Wrote {output_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
