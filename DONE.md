# DONE

## Summary

This file records the current completed state of the `guide_check` roadmap.

Current rough status:

- Phase 0: completed enough for all later work
- Phase 1: about 90%; a usable scheduler training + inference system exists, but evaluation and productization are not fully closed
- Phase 2: about 65%; failure packets and sidecar hints exist, but the path is still more of an analysis sidecar than a finished product subsystem
- Phase 3: about 88%; matching training, sidecar, and validated suggestion flow exist, but the system is still better described as strong guarded assistance than a finished authoritative matcher
- Phase 4: about 94% in the current worktree; the conservative hierarchical region-proof system is real, the main authoritative shell-closure gap on `riscv-mini-core` is now closed, and top / `Datapath` / `RegFile` shells are now authoritative on the original benchmark, but broader cleanup and generalization still remain

Overall current completion is better described as roughly:

- around 93%

This is lower than some earlier rough estimates because the Phase 2/3/4 states were previously described a bit too optimistically. The codebase now supports those phases in real workflows, but several of them are still not fully closed as end-to-end productized systems.


## Recent Milestones

Recent code-side commits relevant to the current state:

- `d890dda69` `Refine guide_check shell closure from constant completion`
- `73626bd04` `Shorten guide_check internal names`
- `1ba3ae871` `Rename guide check shared header`
- `2a275e021` `Refine guide_check shell closure tracing`
- `cbbb4f9fa` `Split guide_check helper subsystems`
- `30339f291` `Refine guide_check shell input closure`
- `a8bf207ff` `Tighten guide_check region shell closure`
- `5c8d658dd` `Extend guide_check matching and failure hint tooling`
- `c9f09fdb2` `Refine guide_check match suggestion acceptance`
- `dbd98059a` `Add guide_check local validation slicing and replay`
- `0a10abec3` `Refine guide_check local validation flow`
- `1c5098cd5` `Extend guide_check partition proving branch`
- `29620804a` `Fix guide_check partition proof soundness`

The most recent important milestones are:

- the current worktree follow-up that shortens `passes/guide/check/` helper filenames to the local naming style now used across the subsystem:
  - `failure_exec.* -> fail_exec.*`
  - `matching.* -> match.*`
  - `retime_multiplier.* -> retime_multi.*`
- the shell-closure follow-up from structured shell-input closure into constant-completion-aware shell refinement
- the follow-up extension from original-module trace-only closure into local-shell provenance tracking
- the follow-up extension from RTLIL-only shell diagnostics into BLIF/export-aligned residual diagnosis
- the current worktree follow-up that makes ABC emit full constant-completed net identity instead of only a short sample list
- the current worktree follow-up that closes the remaining authoritative shell-closure gap on the main `riscv-mini-core` benchmark by:
  - applying BLIF residual promotions instead of only diagnosing them
  - tightening top-level `name_map_not_applied` handling so no-op rename cases no longer block authority
  - aligning local-shell BLIF/export preparation with the actual proving/export path closely enough to eliminate the remaining false shell residuals
- the follow-up cleanup of internal variable and field names across `passes/guide/check/*` and `passes/guide/guide_check.cc`, keeping external CLI / artifact keys stable while making internal code more compact
- the first real file-level split of `guide_check` helper subsystems
- the follow-up rename from `core.h` to `check.h`, clarifying that this header is the shared interface for the `passes/guide/check/` subsystem rather than a general-purpose low-level core library
- the follow-up cleanup of `region.h` / `matching.h` so they expose smaller external interfaces
- the soundness fix for partition proving
- the follow-up evolution from a pairwise partition branch into a module-level hierarchical region DAG
- top-shell closure V2 with structured boundary-closure diagnostics

Concrete outcomes:

- `guide_check.cc` is no longer a 5k+ monolith; the file has been reduced to roughly the orchestration/core side plus shared helpers
- helper subsystems now live under `passes/guide/check/`
- internal code names inside the split helper subsystems and `guide_check.cc` are now shorter and easier to scan, while external JSON keys and user-facing CLI behavior remain unchanged
- a clean rebuild after deleting all `passes/guide/*.o` now succeeds, which flushed out and fixed split-related omissions
- top-level hierarchical partition proofs are no longer allowed to silently short-circuit descendants in unsafe situations
- unsafe local partition proofs are downgraded and forced to fall back to the original module-pair formal path
- child proof obligations now discharge parent shell obligations in the region DAG
- parent shell closure is now audited with explicit structure and metrics instead of only by ad-hoc string checks
- unresolved internal shell inputs on the main `riscv-mini-core` path have been reduced to zero
- structured shell metrics now include promoted-boundary, constant-completion, pre-BLIF residual, and BLIF residual diagnostics
- the current worktree can now recover the full list of ABC constant-completed BLIF net names and map them back into shell-level diagnostics
- the current worktree now also consumes the last BLIF residual promotion round, fixes top-shell no-op name-map misclassification, and aligns local-shell BLIF export strongly enough that:
  - `gold_riscv_mini` is authoritative on the original `riscv-mini-core` benchmark
  - `gold_Datapath` is authoritative on the original `riscv-mini-core` benchmark
  - `gold_RegFile` is authoritative on the original `riscv-mini-core` benchmark
  - all three now have `constant_completed_net_count = 0`
- the `riscv-mini-core` mutated benchmark that used to pass incorrectly now fails correctly


## Phase 0: Stabilization and Telemetry Foundation

### Correctness fixes

The following foundational correctness bugs are fixed in `passes/guide/guide_check.cc`:

- `GuideCheckPass::execute()` now rebinds `gold_mod` and `gate_mod` after cloning the design, avoiding stale module pointers in `CheckConfig`
- `dump_aig()` now runs `setundef -undriven -zero` on the cloned design copy instead of mutating the original design

These fixes were prerequisites for stable dumping, replay, and ML data collection.

### Structured command capture

Command execution now goes through a structured capture path with:

- `exit_status`
- `result_code`
- `runtime_ms`
- `output`
- `log_file`

This is used for:

- ABC runs
- smtbmc / BMC runs
- multiplier verification commands

### Structured pass-local records

The current in-pass structured types include:

- `MlDumpConfig`
- `PairRecord`
- `MatchStats`
- `RunRecord`
- `FailurePacket`
- `CommandResult`

### Dump flags

The pass supports:

- `-guide-dump-sched <file>`
- `-guide-dump-match <file>`
- `-guide-dump-fail <file>`

These dump:

- `sched.jsonl`
- `match.jsonl`
- `fail.jsonl`

### Matching stage snapshots

Matching-related data is recorded at both:

- pre-`async2sync`
- post-`async2sync`

This keeps the intended pre-async feature snapshot alive for training and debugging.


## Phase 1: Pair-Level ABC Scheduler

Current completion estimate:

- about 90%

### Action space

The scheduler is implemented around the real ABC fallback chain:

- `cec_map`
- `cec_nomap`
- `dsec_map`
- `dsec_nomap`

### Pair-level telemetry

`abc_cec_module()` now emits pair-level data including:

- pair metadata
- match statistics
- action trace
- per-action runtime
- per-action result code

This is written through `sched.jsonl`.

### Scheduler model integration

The pass supports:

- `-guide-sched-model <file>`

When a scheduler model is present, action order is predicted instead of using the old hardcoded order.

### Scheduler training scripts

The following scripts exist under `passes/guide/ml/`:

- `collect_scheduler_data.py`
- `train_scheduler.py`
- `eval_scheduler.py`

### Scheduler backend

The current scheduler training backend is:

- `LightGBM`

The deployed runtime format remains the custom JSON tree format interpreted in C++.

### Scheduler dataset and artifacts

Collected scheduler data includes:

- `../yosys-guide-test/all_sched_combined.jsonl`

Generated scheduler model artifact:

- `../yosys-guide-test/all_sched_lgbm_model.json`

### Scheduler validation

The scheduler model has already been validated on held example cases such as:

- `../yosys-guide-test/retime_pipe3`

and is known to change the real action order in `guide_check`.

What is still not fully closed in Phase 1:

- there is not yet a more formal experiment/report layer such as family-aware splits, stable manifests, and stronger result reporting
- the current deployment path is the custom in-tree JSON tree runtime; it is usable but not the end-state of a polished model-serving story
- there is no richer online quality dashboard or regression harness dedicated specifically to scheduler quality

So Phase 1 should be viewed as:

- a real usable scheduler subsystem
- but not yet a fully packaged and deeply evaluated research/product artifact


## Phase 2: Failure Packet and Equivalence-Check Failure Hints

Current completion estimate:

- about 65%

### Failure packet generation

`fail.jsonl` generation is implemented.

Packets currently include:

- `design`
- `gold_mod`
- `gate_mod`
- `pair_id`
- `stage`
- `action`
- `exit_status`
- `result_code`
- `runtime_ms`
- `log_file`
- `has_dff`
- `has_submodule`
- `exact_match_cnt`
- `typed_match_cnt`
- `clues`
- `recent_actions`
- `last_2_actions`
- `teacher_class`
- `next_steps`

### Clue extraction

The system extracts clue strings directly from tool output, including:

- `Networks are NOT EQUIVALENT`
- `Miter computation has failed`
- `BMC-Induct failed in weak mode`
- `BMC-Induct failed in BMC phase`
- `BMC-Induct failed in Induct phase`
- `Amulet Verify failed`

### Rule-based teacher

A rule-based teacher maps clue patterns to:

- a coarse failure class
- next-step suggestions

This is already wired into packet output.

### Online hints

Online failure-hint tooling exists through sidecar scripts.

Working state:

- rule mode: usable
- Qwen online mode: usable
- other providers were explored, but current stable default is Qwen

What is still missing in Phase 2:

- the hint path is still a sidecar, not a first-class main-flow artifact
- `guide_check` itself does not directly emit a standardized final hint artifact such as `failure_hints.json`
- the provider story is only truly stable for the Qwen default path; the other provider paths exist, but are not part of a clearly finished product contract
- the teacher/rule layer is still fairly coarse and not yet a rich failure taxonomy
- there is no strong evaluation loop yet for hint quality, usefulness, or coverage
- there is no true consumer/feedback loop inside the main reporting path

So Phase 2 should be viewed as:

- packet/schema plus a working rule/Qwen sidecar
- not yet a completed failure-hint subsystem


## Phase 3: ML-Assisted Matching

Current completion estimate:

- about 88%

### Matching data and sidecar flow

The matching stack currently includes:

- `match.jsonl`
- `match_suggestions.json`
- CatBoostRanker training
- evaluation script
- sidecar inference
- sidecar workflow

Relevant scripts:

- `matching_common.py`
- `collect_matching_data.py`
- `train_matching.py`
- `eval_matching.py`
- `infer_matching.py`
- `run_matching_sidecar.py`

### Matching artifact layering

The system now emits layered artifacts for matching:

- `match_exact_<gold>_<gate>.txt`
- `match_validated_<gold>_<gate>.txt`
- `match_suggestions_<gold>_<gate>.jsonl`
- `local_validate_<gold>_<gate>.jsonl`

This makes the distinction between:

- exact authoritative matches
- validated ML matches
- raw ML suggestions
- validator evidence

an actual artifact contract instead of just a log convention.

### Main-flow feedback

Matching suggestions can be fed back into the main flow, but they are constrained by current safety rules:

- exact matching is authoritative
- suggestions may only fill unmatched pairs
- suggestions must not overwrite exact matches
- DFF/DFF_PO suggestions require local validation before acceptance

What is still not fully closed in Phase 3:

- the matching system is still not an authoritative learned matcher; it is exact matching plus guarded ML assistance
- some of the most important hard cases are still limited by model margin quality rather than by validator or plumbing completeness
- validated/raw artifact layering exists, but the effect-analysis and benchmarked quality story is not yet complete
- the current integration is deliberately conservative, which is good for soundness, but also means the ML path is still not the dominant matching mechanism

So Phase 3 should be viewed as:

- a strong sidecar plus guarded main-flow integration
- not yet a fully mature authoritative matching subsystem


## Phase 4: Partition / Local Validator / Region Work

Current completion estimate:

- about 88% to 90% in the current worktree

This phase is no longer empty. It now has a real V1 subsystem.

### Codebase split state

The original `passes/guide/guide_check.cc` had grown beyond five thousand lines and contained:

- pass entry / orchestration
- scheduler logic
- failure packet / command capture logic
- matching logic
- partition / region logic
- retime / multiplier logic

This has now been split into submodules under:

- `passes/guide/check/shared.h`
- `passes/guide/check/check.h`
- `passes/guide/check/failure_exec.h`
- `passes/guide/check/failure_exec.cc`
- `passes/guide/check/scheduler.h`
- `passes/guide/check/scheduler.cc`
- `passes/guide/check/matching.h`
- `passes/guide/check/matching.cc`
- `passes/guide/check/region.h`
- `passes/guide/check/region.cc`
- `passes/guide/check/retime_multiplier.h`
- `passes/guide/check/retime_multiplier.cc`

and wired into the build through:

- `passes/guide/Makefile.inc`

Current rough split status:

- `guide_check.cc` still owns the main pass entry and some shared core/proof code
- scheduler is split
- failure/command capture is split
- matching is split
- partition/region is split
- retime/multiplier is split

The largest remaining split debt is:

- `check.h` is now the shared header name for the split `guide_check` subsystem, but there is still not yet a full `core.cc`-style implementation file carrying all shared core/proof helpers out of `guide_check.cc`

The rename from `core.h` to `check.h` was intentionally conservative:

- it changed only the shared-header file name and include paths
- it did not change subsystem behavior
- it was validated with a clean rebuild after deleting all `passes/guide/*.o`

This rename matters because `core.h` was ambiguous: it sounded like a general low-level utility layer, while the actual file is the shared interface surface for the `guide_check` subsystem split under `passes/guide/check/`.

### Clean rebuild validation after split

The split was validated with a true clean rebuild of the guide objects, not only an incremental compile.

The exact stress test used was:

```sh
find passes/guide -name '*.o' -exec rm {} \;
make -j6 yosys
```

This initially exposed missing split dependencies, which were fixed. The current state now passes this clean rebuild check.

That matters because earlier incremental builds could hide missing cross-file declarations.

### Header hygiene after split

After the first split pass, `region.h` and `matching.h` still exposed too many internal helpers.

This has now been reduced.

Current intended public surfaces:

- `region.h`
  - `select_local_dff_cutpoints(...)`
  - `select_support_sliced_dff_cutpoints(...)`
  - `validate_partition_pair(...)`
  - `run_local_validate_shadow(...)`
  - `partition_prove(...)`

- `matching.h`
  - `write_match_suggestions(...)`
  - `match_suggestions_path(...)`
  - `match_artifact_dir(...)`
  - `match_signals_module(...)`
  - `match_signals(...)`
  - `cutpoints_to_pi_po(...)`

Examples of helpers that are no longer intended to be public header API:

- region-side helpers such as:
  - `region_boundary_key`
  - `wire_bit_name`
  - `add_sample_name`
  - `collect_wire_usage`
  - `audit_shell_inputs`
  - `merge_region_boundaries`
  - `build_region_plan`
- matching-side helpers such as:
  - `build_named_sigs`
  - `normalize_match_name`
  - `score_match_candidate`
  - `match_candidate_features`
  - `load_match_suggestions_file`
  - `write_match_line`

This header cleanup is not a new feature by itself, but it makes the split cleaner and limits cross-file coupling.

### Internal naming cleanup after split

After the split stabilized, a follow-up cleanup reduced overly long internal names inside:

- `passes/guide/guide_check.cc`
- `passes/guide/check/shared.h`
- `passes/guide/check/matching.cc`
- `passes/guide/check/region.cc`

The intent was:

- shorten internal fields and local variables
- keep names closer to concise engineering-style code
- avoid changing external compatibility surfaces

Important scope constraints of that cleanup:

- CLI option names were intentionally kept unchanged
- artifact JSON keys were intentionally kept unchanged
- scheduler feature names and other model-facing external names were intentionally kept unchanged

Examples of internal-only shortening that were applied:

- `accept_match_suggestions_file` -> `accept_sugs_file`
- `local_validate_support_slice` -> `local_vali_slice`
- `pair_applied_match_suggestions` -> `pair_applied_sugs`
- `touched_by_multiplier` -> `mul_touched`
- `const_blackbox_inputs_inserted` -> `bb_const_in_cnt`
- `selected_cutpoints` -> `cut_cnt`
- `boundary_map_expected` -> `bnd_map_exp`
- `boundary_map_applied` -> `bnd_map_app`
- `constant_completed_net_count` -> `const_comp_net_cnt`
- `module_interface_input_count` -> `iface_in_cnt`
- `unresolved_internal_input_count` -> `unr_int_in_cnt`

In addition, a second pass shortened a number of hot-path local variables in:

- `abc_cec_module()`
- `refine_shell_closure()`
- `match_signals_module()`

Examples there include:

- `pair_record` -> `pair_rec`
- `match_stats` -> `mstats`
- `command_result` -> `cmd_res`
- `artifact_dir` -> `art_dir`
- `local_result` -> `vali`

This was validated with:

```sh
find passes/guide -name '*.o' -exec rm {} \;
make -j6 yosys
```

and quick functional regressions still passed after the rename work:

- `comb_adder_rename`
- `seq_fsm_datapath`

### Implemented local validator pieces

Implemented in `passes/guide/guide_check.cc`:

- `partition_module()`
- `validate_partition_pair()`
- `-local-validate-shadow`
- DFF-only local validator
- support slicing V1
- local `ABC -> BMC` fallback
- `-partition-prove`

### Implemented partition proving branch

`-partition-prove` is no longer just a placeholder or a shadow-only helper.

It is now a real proving branch inside `guide_check`:

- pairs with usable authoritative cutpoints can enter partition/local proof
- pairs without usable local obligations fall back to the original module-pair `abc_cec_module()` flow
- hierarchy top pairs are no longer allowed to unsafely short-circuit descendants
- partition results are now integrated into the final `CEC/SEC` report as real branch results

### Implemented soundness guard for partition proving

The original unsound behavior that motivated this work was:

- a large hierarchy benchmark could pass under `-partition-prove`
- even after a real functional bug was injected
- because an over-loose top-level local proof was allowed to dominate the result

This specific bug was reproduced on:

- `../yosys-guide-test/cpus/riscv-mini-core/rtl/riscv_mini.sv`

The concrete mutation used during debugging was:

- line `758`
- change `2'b01` to `2'b11`

Before the fix, the full-feature flow could still incorrectly report `PASS`.

After the soundness fix:

- unsafe partition/local proofs are marked non-authoritative
- the flow falls back to the original module-pair formal path when necessary
- the original `riscv-mini-core` benchmark passes
- the mutated benchmark now fails correctly

The main safety triggers introduced for this were:

- `constant_completed_nets`
- `name_map_not_applied`
- `structural_hash_only`

Those triggers are still present, but are now supplemented by more structured closure checks described below.

### Support slicing

Support slicing is implemented as a candidate-centered local-cutpoint selection path.

Current state:

- it is available through `-local-validate-support-slice`
- it is only used on the DFF-suggestion validation path
- shadow still keeps the all-DFF path for A/B comparison

Measured example:

On the `seq_fsm_datapath` positive-margin DFF replay:

- all-DFF mode selected `10` cutpoints with local exact total `47`
- support-slice mode selected `1` cutpoint with local exact total `38`
- runtime also decreased

So support slicing is real and measurable, not just scaffold code.

### Replay harness

`passes/guide/ml/run_local_validate_replay.py` exists and reports:

- baseline pass/fail
- shadow pass/fail
- raw / validated / rejected / skipped DFF suggestion counts
- local validator run count
- local validator runtime
- average / median selected cutpoints
- average local exact total
- slice mode
- local and shadow BMC fallback counts

### Artifact layering for partition / local proof

The local-validator and partition work no longer lives only in logs.

Relevant artifact layers now include:

- `local_validate_<gold>_<gate>.jsonl`
- `region_plan_<top>.jsonl`
- `region_proof_<top>.jsonl`

The purpose of these layers is:

- `local_validate_*`: record local validator runs, DFF validation, shadow runs, backends, and acceptance decisions
- `region_plan_*`: record the planned region structure
- `region_proof_*`: record proof results, shell closure status, child discharge status, and fallback reasons

### Module-level hierarchical region DAG

The current code is no longer only doing:

- “for each module pair, maybe run a local proof”

It now also has a real module-level region view with explicit structures:

- `RegionBoundary`
- `PartitionedPair`
- `RegionNode`
- `RegionProofResult`

This is a module-level hierarchical region DAG, not yet a free-form global region scheduler.

The current intended semantics are:

- each mapped module pair becomes a region node
- state cuts and child-boundary obligations are tracked separately
- child output boundaries are represented as structured obligations, not just loose cutpoints
- proving runs bottom-up over the module DAG
- child results can discharge parent shell obligations

### Child-boundary obligations are now distinct from state cuts

Earlier work treated:

- `DFF / DFF_PO`
- `SUBCKT_PIPO`

too similarly inside the partition path.

That was not sufficient to define a real region-proof contract.

The current code now separates these concerns:

- state cutpoints are selected through `select_region_state_cutpoints()`
- child-boundary obligations are selected through `select_region_child_boundary_cutpoints()`

This means:

- `DFF`-style cuts are used as state-oriented shell cuts
- `SUBCKT_PIPO` is treated as child-boundary information
- parent shell proof and child discharge are no longer collapsed into one undifferentiated cutpoint set

### Canonical child-boundary correspondence in parent shells

One of the key closure issues was that child outputs could be cut into parent-local PI ports, but those ports were not guaranteed to form a strong correspondence in the local proof object.

This has now been improved by:

- collecting boundary metadata from `submod_to_pi_po()`
- merging gold/gate child-boundary information into `RegionBoundary`
- assigning canonical boundary wire names
- renaming the corresponding local boundary wires in gold and gate local shells to the same canonical names

This does not fully close all parent shells yet, but it is an important step:

- child outputs are no longer only “loose PI after cutting”
- they now carry explicit boundary identity
- region artifacts can report expected vs applied boundary mappings

### Top-shell closure V2

The most recent Phase 4 improvement is top-shell closure V2.

This introduces more structured closure diagnostics into local/region proof results.

The following fields now exist in local / region proof reporting:

- `boundary_map_expected`
- `boundary_map_applied`
- `constant_completed_net_count`
- `unresolved_internal_boundaries`
- `unresolved_child_boundaries`
- `residual_hierarchy`
- `authoritative_reason`
- `fallback_reason`

The goal of these fields is to answer:

- why a shell was authoritative
- why it fell back
- whether child boundaries really formed usable correspondence
- whether the shell still contained residual unresolved structure

### Follow-up shell closure work after V2

Top-shell closure did not stop at the first structured shell metrics pass.

The current worktree now contains several additional shell-closure rounds beyond the original V2 checkpoint:

- shell-input provenance and classification were tightened so that original module interface inputs no longer dominate the unresolved bucket
- promoted internal trace boundaries were extended to work when the gold/gate local input bit names are different but the traced source identity is the same
- constant-completion auditing was extended from a pure classification step into a bounded refinement input
- one bounded extra shell-refinement round was added:
  - first shell audit
  - constant-completion provenance analysis
  - safe promotion attempt
  - second shell audit
  - second constant-completion audit
- local-shell provenance structures were added so closure no longer depends only on original-module RTLIL tracing
- pre-BLIF shell diagnostics were added so shell work can inspect residuals closer to the real BLIF export/proving boundary
- the current worktree also pushes one more round beyond that:
  BLIF/export-side residual identity is now captured from ABC itself, rather than only from Yosys-side approximation

This means the current Phase 4 state is better described as:

- a conservative hierarchical region-proof system
- plus several shell-closure refinement rounds
- plus BLIF/ABC-side residual diagnosis

and no longer just:

- a region DAG with fallback strings

### Current authoritative contract for region shells

The current region shell is only considered authoritative when all of the following effectively hold:

- the shell local proof passed
- `children_discharged == true`
- `unresolved_child_boundaries == 0`
- `unresolved_internal_boundaries == 0`
- `constant_completed_net_count == 0`
- if child boundaries exist, `boundary_map_applied > 0`
- no remaining residual hierarchy/state obligation blocks closure

If these conditions are not met:

- the region shell is not authoritative
- the flow conservatively falls back to the original module-pair formal path

This is deliberate.

The current design philosophy is:

- prefer conservative fallback over unsound PASS

### Child obligation discharge is now more precise

There was a second-level issue after the initial region DAG landed:

- child pairs could already be successfully discharged by authoritative module-pair fallback
- but parent shells still treated them as pending because the child region shell itself was not authoritative

This has been fixed by separating:

- shell authoritative status
- obligation discharge status

`RegionProofResult` now tracks:

- `obligation_discharged`

Current intended behavior:

- if a child shell is authoritative, it discharges its parent obligation
- if a child shell is not authoritative but its conservative fallback module-pair proof succeeds, it still discharges its parent obligation
- if a child actually fails proof, it does not discharge

This significantly reduced spurious `child_obligations_not_discharged` fallbacks in large hierarchy designs.

### What the latest structured artifacts show

The latest `riscv-mini-core` region artifacts in the current worktree no longer show the old “almost closed but still fallback” state on the main hard shells.

The most important state changes compared to earlier Phase 4 iterations are now:

- unresolved internal shell inputs on the main path remain at zero
- `boundary_map_applied` remains fully aligned with `boundary_map_expected` on the main hard shells
- the earlier top-shell `name_map_not_applied` blocker is gone on the original benchmark
- the earlier `constant_completed_nets` blocker on `Datapath` / `RegFile` has been reduced all the way to zero
- the main benchmark shells are now authoritative instead of only explainable fallbacks

The latest important shell examples are:

- `RegFile`
  - `boundary_map_expected = 64`
  - `boundary_map_applied = 64`
  - `constant_completed_net_count = 0`
  - `blif_residual_count = 0`
  - `authoritative_reason = closed_region_shell`

- `Datapath`
  - `boundary_map_expected = 290`
  - `boundary_map_applied = 290`
  - `constant_completed_net_count = 0`
  - `blif_residual_count = 0`
  - `authoritative_reason = closed_region_shell`

- top `riscv_mini`
  - `boundary_map_expected = 194`
  - `boundary_map_applied = 194`
  - `constant_completed_net_count = 0`
  - child obligations are discharged
  - `authoritative_reason = closed_region_shell`

This is the key Phase 4 transition:

- earlier, the system could explain the remaining residual identities but not close them
- now, on the main CPU benchmark, those last shell blockers are actually closed conservatively enough for authoritative shells

### Current BLIF/export residual visibility

One of the most important current-worktree improvements is that shell closure can now see BLIF/ABC-side residual identity directly.

Earlier Phase 4 rounds could observe:

- `constant_completed_net_count`

but often could not explain which residual identities caused it.

The current worktree now has additional structured layers:

- `preblif_*`
- `blif_*`

The `preblif_*` layer is still useful as a Yosys-side approximation, but on the main hard cases it often remains too weak because the actual free nets appear only after BLIF/export semantics are applied.

The `blif_*` layer is more important now.
It is driven by:

- BLIF/export-side residual naming
- and, in the current worktree, a full ABC-emitted constant-completed net list rather than only a short sample

Current important `riscv-mini-core` trajectory:

- earlier hard state:
  - `Datapath` had `constant_completed_net_count = 221`
  - `RegFile` had `constant_completed_net_count = 5`
  - top had no constant-completion residuals, but still had a top-shell name-map weakness

- intermediate state:
  - shell closure could see the full BLIF residual population
  - BLIF residuals were no longer opaque counts; they had explicit names and structured classification
  - after BLIF/export alignment work, these hard counts dropped to:
    - `Datapath = 3`
    - `RegFile = 1`
  - the remaining residuals were reduced to writer-side constant aliases such as `__const0` / `__const1`

- current state:
  - those constant aliases are no longer misclassified as unresolved shell residuals
  - `Datapath` now has `constant_completed_net_count = 0`
  - `RegFile` now has `constant_completed_net_count = 0`
  - `blif_residual_count = 0` on both

This means Phase 4 is no longer only at:

- “full BLIF residual identity is visible”

On the main hard benchmark it has now reached:

- “the visible BLIF/export residuals were conservatively closed enough to produce authoritative shells”

### Current benchmark-level validation status

The following important validations have already been exercised:

- `../yosys-guide-test/seq_counter_small`
- `../yosys-guide-test/seq_shiftreg_deep`
- `../yosys-guide-test/seq_pipe2_basic`
- `../yosys-guide-test/seq_fsm_datapath`
- `../yosys-guide-test/retime_pipe2`
- `../yosys-guide-test/retime_pipe3`
- `../yosys-guide-test/retime`
- `../yosys-guide-test/match_suggestion`
- `../yosys-guide-test/comb_adder_rename`
- `../yosys-guide-test/hier_ctrl_datapath`
- `../yosys-guide-test/cpus/riscv-mini-core/eq-gd`

In addition, these validations were rerun after the helper-subsystem split to confirm behavior did not regress:

- clean rebuild of `yosys` after deleting all `passes/guide/*.o`
- `comb_adder_rename`: still passes
- `seq_fsm_datapath`: still passes
- `hier_ctrl_datapath`: still passes
- original `riscv-mini-core`: still passes
- mutated `riscv-mini-core` (`2'b01 -> 2'b11`): still fails

This means the codebase split was not only a structural change; it was also checked against the key soundness regression.

The most important current regression pair is:

- original `riscv-mini-core`: must pass
- mutated `riscv-mini-core` with `2'b01 -> 2'b11` at line `758`: must fail

This regression currently holds.

The latest authoritative-shell-closure rerun in the current worktree also revalidated:

- original `riscv-mini-core`: `PASS`
- mutation regression script:
  - `baseline`: `passed`
  - `wb_load_case_label`: `failed`
  - `wb_ctrl_select`: `failed`
  - `pc_plus4_to_plus8`: `failed`
  - `load_byte_zeroext_to_signext`: `failed`
- `comb_adder_rename`: `PASS`
- `seq_fsm_datapath`: `PASS`
- `hier_ctrl_datapath`: `PASS`
- `seq_counter_small`: `PASS`
- `match_suggestion`: `PASS`
- `bbox`: `PASS`
- `retime`: `PASS`
- `retime_pipe2`: `PASS`
- `retime_pipe3`: `PASS`

### Current limitations still remaining in Phase 4

Phase 4 is now much closer to “closed on the main hard benchmark” than it was in earlier updates, but it is still not the end of all Phase 4 work.

The major remaining limits are now more about generalization and cleanup than the old core shell-closure blocker:

- `guide_check.cc` still contains a significant shared core/proof block because there is still no dedicated implementation file carrying all of the declarations from `check.h`
- some split headers still depend on broad shared types from `shared.h`, so there is still interface coupling to reduce later
- the local-shell BLIF/export alignment logic is stronger now, but it is still specialized logic and should be validated on more hard hierarchy cases before being treated as completely settled
- support slicing is still V1
- local `ABC -> BMC` fallback is implemented but still coarse
- region replay/tooling is not yet its own polished layer
- full free-form region orchestration / scheduling is not implemented

The most important Phase 4 blocker that used to dominate this section has changed:

- it used to be “the main hard shells still fall back because of `constant_completed_nets` and top-shell name-map weakness”
- it is now better described as “the main hard benchmark is closed, but broader benchmark coverage and code cleanup still remain”

### Current best description of Phase 4

The current state is no longer:

- “a local validator prototype”

It is now closer to:

- a conservative module-level hierarchical region-proof system
- with explicit child obligations
- structured shell closure diagnostics
- and conservative fallback when closure is incomplete

What is still missing is the final closure step:

- generalizing the current shell-closure result beyond the main hard benchmark
- and reducing the amount of special-case export-alignment logic needed to get there

This harness was used to compare:

- baseline
- `-local-validate-shadow`
- accepted validated suggestions
- all-DFF vs support-slice

### Partition proving branch

`-partition-prove` is now a real proving branch, not just a side capability.

Current behavior:

- if a pair has usable authoritative cutpoints, the branch tries partition proof
- if a pair does not have usable cutpoints, it falls back to the old module-pair proof path
- hierarchy top-level partition proof is no longer always authoritative

### Hierarchy improvements

The branch can now prove some hierarchy top-level pairs directly using partition proof.

Notable case:

- `hier_ctrl_datapath` top-level can now enter partition proving

### Soundness fix

This is the most important recent Phase 4 result.

The branch previously had an unsound behavior:

- a top-level partition proof could pass
- descendants could be skipped
- a real functional bug could be missed

This was observed on the `riscv-mini-core` benchmark when mutating `rtl/riscv_mini.sv`.

The current fix is:

- unsafe local/partition proofs are marked non-authoritative
- the system falls back to the original module-pair proof path instead of trusting the local proof

Current unsafe triggers include:

- `Constant-0 drivers added to ...`
- `Name map: applied 0`
- `Networks are equivalent after structural hashing.`

### Concrete benchmark validation

For `../yosys-guide-test/cpus/riscv-mini-core/eq-gd`:

- the old script entry was updated to accept current feature flags
- the original benchmark passes
- the mutated benchmark where line 758 changed from `2'b01` to `2'b11` now fails correctly

More specifically:

- top-level `riscv_mini` partition proof becomes non-authoritative and falls back
- `Datapath` then falls back to the original module-pair proof path
- the real mismatch is detected there

### Mutation regression script

To make this reproducible, the following script was added in the testcase directory:

- `../yosys-guide-test/cpus/riscv-mini-core/eq-gd/run_mutation_regression.py`

This script:

- keeps the benchmark source restored after testing
- runs the original design
- runs multiple temporary mutations
- writes a JSON summary

Current verified mutations include:

- baseline: pass
- writeback load case label bug: fail
- writeback control-select bug: fail
- `pc + 4` to `pc + 8`: fail
- load zero-extend to sign-extend bug: fail


## Testing Summary

### Default `guide_check` testing policy

The current expected testing policy for `guide_check` changes is:

- if the user says to "test", do not stop at compile-only
- by default run:
  - the small regression set
  - the medium regression set
  - the retime set
  - the blackbox case
  - the `riscv-mini-core` soundness pair

Current small regression set:

- `comb_adder_rename`
- `seq_fsm_datapath`
- one hierarchy/local-partition case such as `hier_ctrl_datapath`

Current medium regression set:

- `comb_adder_rename`
- `seq_fsm_datapath`
- `hier_ctrl_datapath`
- `seq_counter_small`
- `retime_pipe2`
- `match_suggestion`

Current retime set:

- `retime`
- `retime_pipe2`
- `retime_pipe3`

Current blackbox case:

- `bbox`

Current soundness pair:

- original `cpus/riscv-mini-core`: must `PASS`
- mutated `rtl/riscv_mini.sv` with line `758` changed from `2'b01` to `2'b11`: must `FAIL`

The benchmark source should be restored after testing; use a temporary mutated copy or a local regression script instead of leaving the mutation in place.

### Sequential and retime coverage

These were exercised during the current work:

- `seq_counter_small`
- `seq_shiftreg_deep`
- `seq_pipe2_basic`
- `seq_fsm_datapath`
- `retime_pipe2`
- `retime_pipe3`
- `retime`

### Non-retime coverage

Also exercised:

- `comb_adder_rename`
- `comb_mux_tree_flatten`
- `bbox`
- `hier_alu_split`
- `hier_ctrl_datapath`
- `mul_unsigned_basic`
- `mul_signed_basic`
- `mul_mac_basic`
- `name_weak_dff`
- `name_weak_subckt`
- `match_suggestion`

### Important current outcome

The biggest current correctness statement is:

- the partition-proof soundness bug on `riscv-mini-core` was reproduced
- the code-side soundness fix was implemented
- the mutated benchmark now fails correctly
- in the current worktree, the shell-closure branch also still preserves:
  - original `riscv-mini-core`: `PASS`
  - mutated `riscv-mini-core` with line `758` changed from `2'b01` to `2'b11`: `FAIL`
  - `hier_ctrl_datapath`: `PASS`
  - `seq_fsm_datapath`: `PASS`
  - `comb_adder_rename`: `PASS`
  - `bbox`: `PASS`
  - `retime`: `PASS`
  - `retime_pipe2`: `PASS`
  - `retime_pipe3`: `PASS`


## What Is Still Not Finished

The roadmap is not fully done yet.

Main remaining items:

- support slicing still needs another round of polishing
- local `ABC -> BMC` fallback policy is still fairly coarse
- full `partition_design_for_check()` / full region orchestration is not yet the default global proving framework
- region-level artifact orchestration and full region replay are still not implemented
- matching model quality, especially DFF suggestion margin quality, still needs more work


## Current Working State

As of this update:

- the code-side partition soundness fix is in commit `29620804a`
- the top-level partition proving branch is in commit `1c5098cd5`
- the committed shell-closure follow-up from constant-completion refinement is in commit `d890dda69`
- the current worktree contains additional uncommitted shell-closure closure work in:
  - `passes/guide/check/region.cc`
  - `passes/guide/check/retime_multiplier.cc`
  - `DONE.md`
- the most important uncommitted current-worktree improvements are:
  - BLIF residual promotion is now actually applied instead of only diagnosed
  - top-shell no-op name-map cases no longer block authority
  - local-shell BLIF/export preparation is aligned closely enough that the remaining `riscv-mini-core` shell residuals collapse to zero
- on the original `riscv-mini-core` benchmark, the current worktree now has:
  - `gold_riscv_mini`: authoritative
  - `gold_Datapath`: authoritative
  - `gold_RegFile`: authoritative
  - `constant_completed_net_count = 0` for all three
- the current worktree still passes the important soundness and regression checks listed below
- the current worktree is therefore best described as:
  conservative hierarchical region proof plus closed authoritative shell closure on the main hard benchmark


## Bottom Line

The project is no longer just “module-pair CEC plus ML sidecars”.

It now has:

- a usable scheduler
- usable failure packets and hint tooling
- a matching system with validated suggestions
- a local validator
- support slicing
- a replay harness
- a real partition-driven proving branch
- a concrete soundness fix validated on a real CPU benchmark

The biggest unfinished work is turning the current partition branch into a fuller region-oriented proving framework without giving up soundness.
