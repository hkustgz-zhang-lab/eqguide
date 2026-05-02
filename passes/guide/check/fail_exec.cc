#include "passes/guide/check/fail_exec.h"

YOSYS_NAMESPACE_BEGIN
namespace guide_check {

static void add_unique_clue(std::vector<string> &clues, const string &clue)
{
    for (const auto &it : clues)
        if (it == clue)
            return;
    clues.push_back(clue);
}

void append_jsonl(const string &path, const Json &json)
{
    if (path.empty())
        return;

    FILE *f = fopen(path.c_str(), "a");
    if (f == nullptr)
        log_error("Cannot open JSONL file %s for append.\n", path.c_str());

    fprintf(f, "%s\n", json.dump().c_str());
    fclose(f);
}

string make_command_log_file(const string &tempdir_name, const string &tag)
{
    string dir_name = tempdir_name.empty() ? get_base_tmpdir() : tempdir_name;
    string log_file = dir_name + "/" + sanitize_filename(tag) + "-XXXXXX.log";
    return make_temp_file(log_file);
}

string failure_log_dir(const MlDumpConfig &dump_cfg)
{
    if (!dump_cfg.dump_fail || dump_cfg.fail_jsonl.empty())
        return "";
    string dir_name = path_dirname(dump_cfg.fail_jsonl) + "/failure_logs";
    if (!create_directory(dir_name))
        log_error("Cannot create failure log directory %s.\n", dir_name.c_str());
    return dir_name;
}

string resolve_yosys_smtbmc_executable()
{
    string local = proc_self_dirname() + proc_program_prefix() + "yosys-smtbmc";
    if (access(local.c_str(), X_OK) == 0)
        return local;
    return "yosys-smtbmc";
}

std::vector<string> extract_failure_clues(const string &output)
{
    std::vector<string> clues;
    const std::vector<string> known_clues = {
        "Networks are NOT EQUIVALENT after structural hashing",
        "Networks are NOT EQUIVALENT after SAT",
        "Networks are NOT EQUIVALENT after fraiging",
        "Networks are NOT EQUIVALENT after partitioning",
        "Networks are NOT EQUIVALENT after framing",
        "Networks are NOT EQUIVALENT after simulation",
        "Networks are NOT EQUIVALENT. Output",
        "Networks are NOT EQUIVALENT",
        "Miter computation has failed",
        "BMC-Induct failed in weak mode",
        "BMC-Induct failed in BMC phase",
        "BMC-Induct failed in Induct phase",
        "Amulet Verify failed"
    };

    for (auto &clue : known_clues)
        if (output.find(clue) != string::npos)
            add_unique_clue(clues, clue);

    return clues;
}

string partition_unsafe_why(const CommandResult &command_result)
{
    const string &output = command_result.output;
    if (output.find("Constant-0 drivers added to") != string::npos)
        return "constant_completed_nets";
    if (output.find("Name map: applied 0") != string::npos)
        return "name_map_not_applied";
    if (output.find("Networks are equivalent after structural hashing.") != string::npos)
        return "structural_hash_only";
    return "";
}

static string infer_proof_outcome(const CommandResult &result, const std::vector<string> &clues)
{
    for (const auto &clue : clues)
        if (clue.find("Networks are NOT EQUIVALENT") != string::npos)
            return "not_equivalent";

    if (result.output.find("Networks are equivalent") != string::npos)
        return "equivalent";

    for (const auto &clue : clues)
        if (clue == "Miter computation has failed" ||
            clue == "BMC-Induct failed in weak mode" ||
            clue == "BMC-Induct failed in BMC phase" ||
            clue == "BMC-Induct failed in Induct phase" ||
            clue == "Amulet Verify failed")
            return "blocked";

    string out_lc = result.output;
    std::transform(out_lc.begin(), out_lc.end(), out_lc.begin(),
                   [](unsigned char ch) { return std::tolower(ch); });
    if (result.exit_status == 124 || out_lc.find("timeout") != string::npos)
        return "timeout";
    if (result.exit_status != 0)
        return "tool_error";
    return "unknown";
}

static string packet_key(const string &pair_id, const string &stage, const string &action,
                         const string &proof_outcome, int raw_result_code,
                         const std::vector<string> &clues)
{
    string joined = pair_id + "|" + stage + "|" + action + "|" + proof_outcome + "|" +
        std::to_string(raw_result_code);
    for (const auto &clue : clues)
        joined += "|" + clue;
    return joined;
}

static string packet_id_from_key(const string &key)
{
    return stringf("fp_%016llx", (long long unsigned int)run_hash(key));
}

static string packet_fingerprint(const string &packet_id, const string &log_file)
{
    return packet_id + "|" + log_file;
}

static string packet_engine(const string &stage)
{
    if (stage == "ABC")
        return "abc";
    if (stage == "BMC")
        return "bmc";
    if (stage == "AMULET")
        return "amulet";
    if (stage == "REGION")
        return "abc";
    return "unknown";
}

static string packet_scope(const string &stage)
{
    if (stage == "BMC")
        return "bmc";
    if (stage == "AMULET")
        return "multiplier_subcheck";
    if (stage == "REGION")
        return "region_local";
    return "pair";
}

static PairRecord packet_pair_record(const CheckConfig &conf)
{
    string pair_id = get_pair_id(conf.gold_mod->name, conf.gate_mod->name);
    if (conf.telemetry != nullptr) {
        auto it = conf.telemetry->pair_records.find(pair_id);
        if (it != conf.telemetry->pair_records.end())
            return it->second;
    }

    PairRecord pair;
    pair.pair_id = pair_id;
    pair.gold_mod = strip_backslash(conf.gold_mod->name);
    pair.gate_mod = strip_backslash(conf.gate_mod->name);
    pair.has_submodule = module_has_submodule(conf.design, conf.gold_mod);
    pair.retimed = conf.telemetry != nullptr &&
        (conf.telemetry->retimed_mods.count(conf.gold_mod->name) ||
         conf.telemetry->retimed_mods.count(conf.gate_mod->name));
    pair.mul_touched = conf.telemetry != nullptr &&
        (conf.telemetry->multiplier_mods.count(conf.gold_mod->name) ||
         conf.telemetry->multiplier_mods.count(conf.gate_mod->name));

    for (auto cell : conf.gold_mod->cells())
        if (cell->type == ID($ff) || cell->type == ID($dff) || cell->type == ID($dffe) ||
            cell->type == ID($_DFF_P_) || cell->type == ID($_DFF_N_) || cell->type == ID($_DFFE_PN) ||
            cell->type == ID($_DFFE_PP))
            pair.gold_dff_cnt++;

    for (auto cell : conf.gate_mod->cells())
        if (cell->type == ID($ff) || cell->type == ID($dff) || cell->type == ID($dffe) ||
            cell->type == ID($_DFF_P_) || cell->type == ID($_DFF_N_) || cell->type == ID($_DFFE_PN) ||
            cell->type == ID($_DFFE_PP) || cell->type.contains("DFF"))
            pair.gate_dff_cnt++;

    return pair;
}

static PairRecord packet_pair_record(const string &pair_id, const string &gold_mod, const string &gate_mod)
{
    PairRecord pair;
    pair.pair_id = pair_id;
    pair.gold_mod = gold_mod;
    pair.gate_mod = gate_mod;
    return pair;
}

static Json trace_to_json(const std::vector<RunRecord> &trace)
{
    Json::array out;
    for (const auto &item : trace)
        out.push_back(Json::object {
            {"pair_id", item.pair_id},
            {"action", item.action},
            {"exit_status", item.exit_status},
            {"result_code", item.result_code},
            {"proof_outcome", item.proof_outcome},
            {"runtime_ms", item.runtime_ms},
            {"log_file", item.log_file}
        });
    return out;
}

CommandResult exec_capture(const string &cmd, const string &tempdir_name, const string &tag,
                           const string &log_dir)
{
    CommandResult result;
    string cmd_with_stderr = cmd + " 2>&1";
    string log_file;
    if (!log_dir.empty()) {
        if (!create_directory(log_dir))
            log_error("Cannot create command log directory %s.\n", log_dir.c_str());
        log_file = make_temp_file(log_dir + "/" + sanitize_filename(tag) + "-XXXXXX.log");
    } else {
        log_file = make_command_log_file(tempdir_name, tag);
    }
    FILE *log_f = fopen(log_file.c_str(), "w");

    char buffer[1024];
    auto t_start = std::chrono::steady_clock::now();
    FILE *pipe = popen(cmd_with_stderr.c_str(), "r");
    if (!pipe) {
        if (log_f != nullptr)
            fclose(log_f);
        log_error("Error executing command: %s\n", cmd.c_str());
        return result;
    }

    while (fgets(buffer, sizeof(buffer), pipe) != nullptr) {
        result.output += buffer;
        log("%s", buffer);
        if (log_f != nullptr)
            fputs(buffer, log_f);
    }

    int status = pclose(pipe);
    auto t_end = std::chrono::steady_clock::now();
    result.runtime_ms = std::chrono::duration_cast<std::chrono::milliseconds>(t_end - t_start).count();
    result.log_file = log_file;

    if (log_f != nullptr)
        fclose(log_f);

    if (WIFEXITED(status))
        result.exit_status = WEXITSTATUS(status);
    else
        result.exit_status = -1;

    return result;
}

MatchStats get_match_stats(const CheckConfig &conf)
{
    if (conf.telemetry == nullptr)
        return MatchStats();

    string pair_id = get_pair_id(conf.gold_mod->name, conf.gate_mod->name);
    auto it = conf.telemetry->pair_match_stats.find(pair_id);
    if (it == conf.telemetry->pair_match_stats.end())
        return MatchStats();
    return it->second;
}

int typed_match_total(const MatchStats &stats)
{
    return stats.pi_cnt + stats.po_cnt + stats.dff_cnt + stats.dff_po_cnt + stats.subckt_cnt;
}

bool module_has_submodule(RTLIL::Design *design, RTLIL::Module *mod)
{
    for (auto cell : mod->cells()) {
        RTLIL::Module *submod = design->module(cell->type);
        if (submod != nullptr && !submod->get_bool_attribute(ID(blackbox)))
            return true;
    }
    return false;
}

bool module_has_dff(RTLIL::Module *mod, bool gate_side)
{
    for (auto cell : mod->cells())
        if (cell->type == ID($ff) || cell->type == ID($dff) || cell->type == ID($dffe) ||
            cell->type == ID($_DFF_P_) || cell->type == ID($_DFF_N_) || cell->type == ID($_DFFE_PN) ||
            cell->type == ID($_DFFE_PP) || (gate_side && cell->type.contains("DFF")))
            return true;
    return false;
}

FailureTeacher failure_teacher(const CommandResult &result, const std::vector<string> &clues)
{
    for (auto &clue : clues) {
        if (clue == "Miter computation has failed")
            return {"abc_miter_failed", {clue},
                    {"retry_cec_nomap", "inspect_match_density", "replay_failing_action"}};
        if (clue == "Networks are NOT EQUIVALENT after structural hashing")
            return {"abc_not_equivalent_struct_hash", {clue},
                    {"inspect_match_density", "inspect_counterexample", "replay_failing_action"}};
        if (clue == "Networks are NOT EQUIVALENT after SAT")
            return {"abc_not_equivalent_sat", {clue},
                    {"inspect_counterexample", "inspect_upstream_transforms", "replay_failing_action"}};
        if (clue == "Networks are NOT EQUIVALENT after fraiging" ||
            clue == "Networks are NOT EQUIVALENT after partitioning" ||
            clue == "Networks are NOT EQUIVALENT after framing" ||
            clue == "Networks are NOT EQUIVALENT after simulation" ||
            clue == "Networks are NOT EQUIVALENT. Output" ||
            clue == "Networks are NOT EQUIVALENT")
            return {"abc_not_equivalent_generic", {clue},
                    {"inspect_counterexample", "inspect_upstream_transforms", "replay_failing_action"}};
        if (clue == "BMC-Induct failed in weak mode")
            return {"bmc_weak_failed", {clue},
                    {"increase_bmc_skip", "increase_bmc_k", "inspect_retime_pair"}};
        if (clue == "BMC-Induct failed in BMC phase")
            return {"bmc_bmc_phase_failed", {clue},
                    {"increase_bmc_skip", "increase_bmc_k", "inspect_retime_pair"}};
        if (clue == "BMC-Induct failed in Induct phase")
            return {"bmc_induct_phase_failed", {clue},
                    {"increase_bmc_k", "inspect_retime_pair", "replay_failing_action"}};
        if (clue == "Amulet Verify failed")
            return {"amulet_verify_failed", {clue},
                    {"check_multiplier_sign_width", "check_blackboxing_path", "replay_failing_action"}};
    }

    if (result.log_file.empty())
        return {"missing_log_or_parse_error", {}, {"inspect_command_log", "replay_failing_action"}};
    if (result.exit_status != 0)
        return {"tool_exit_nonzero", {}, {"inspect_command_log", "replay_failing_action"}};
    return {"unknown", {}, {"inspect_command_log", "replay_failing_action"}};
}

Json string_array_to_json(const std::vector<string> &values)
{
    Json::array out;
    for (auto &value : values)
        out.push_back(value);
    return out;
}

static bool should_emit_failure_packet(const string &jsonl_path, const string &fp)
{
    static dict<string, pool<string>> seen;
    if (jsonl_path.empty())
        return true;
    if (seen[jsonl_path].count(fp))
        return false;
    seen[jsonl_path].insert(fp);
    return true;
}

void emit_failure_packet(const CheckConfig &conf, const string &stage, const string &action,
                                const CommandResult &command_result, const std::vector<RunRecord> &trace)
{
    if (!conf.dump_cfg.dump_fail || conf.dump_cfg.fail_jsonl.empty())
        return;

    FailurePacket packet;
    packet.design = strip_backslash(conf.gold_mod->name);
    packet.pair = packet_pair_record(conf);
    packet.pair_id = packet.pair.pair_id;
    packet.engine = packet_engine(stage);
    packet.scope = packet_scope(stage);
    packet.stage = stage;
    packet.action = action;
    packet.clues = extract_failure_clues(command_result.output);
    packet.match = get_match_stats(conf);
    packet.exit_status = command_result.exit_status;
    packet.raw_result_code = command_result.raw_result_code;
    packet.result_code = command_result.result_code;
    packet.proof_outcome = command_result.proof_outcome.empty() ?
        infer_proof_outcome(command_result, packet.clues) : command_result.proof_outcome;
    packet.runtime_ms = command_result.runtime_ms;
    packet.log_file = command_result.log_file;

    for (auto &item : trace) {
        packet.recent_actions.push_back(item.action);
        packet.trace.push_back(item);
    }

    std::vector<string> last_2_actions;
    int start = std::max(0, GetSize(packet.recent_actions) - 2);
    for (int i = start; i < GetSize(packet.recent_actions); i++)
        last_2_actions.push_back(packet.recent_actions[i]);

    auto teacher = failure_teacher(command_result, packet.clues);
    string key = packet_key(packet.pair_id, packet.stage, packet.action,
                            packet.proof_outcome, packet.raw_result_code, packet.clues);
    packet.packet_id = packet_id_from_key(key);
    packet.fingerprint = packet_fingerprint(packet.packet_id, packet.log_file);
    if (!should_emit_failure_packet(conf.dump_cfg.fail_jsonl, packet.fingerprint))
        return;

    append_jsonl(conf.dump_cfg.fail_jsonl, Json::object {
        {"schema_version", packet.schema_version},
        {"packet_id", packet.packet_id},
        {"design", packet.design},
        {"gold_mod", packet.pair.gold_mod},
        {"gate_mod", packet.pair.gate_mod},
        {"pair_id", packet.pair_id},
        {"engine", packet.engine},
        {"scope", packet.scope},
        {"pair", pair_record_to_json(packet.pair)},
        {"stage", packet.stage},
        {"action", packet.action},
        {"clues", string_array_to_json(packet.clues)},
        {"match", match_stats_to_json(packet.match)},
        {"has_dff", packet.pair.gold_dff_cnt != 0 || packet.pair.gate_dff_cnt != 0},
        {"has_submodule", packet.pair.has_submodule},
        {"exact_match_cnt", packet.match.exact_total},
        {"typed_match_cnt", typed_match_total(packet.match)},
        {"exit_status", packet.exit_status},
        {"raw_result_code", packet.raw_result_code},
        {"result_code", packet.result_code},
        {"proof_outcome", packet.proof_outcome},
        {"runtime_ms", packet.runtime_ms},
        {"log_file", packet.log_file},
        {"fingerprint", packet.fingerprint},
        {"trace", trace_to_json(packet.trace)},
        {"recent_actions", string_array_to_json(packet.recent_actions)},
        {"last_2_actions", string_array_to_json(last_2_actions)},
        {"teacher_class", teacher.cls},
        {"next_steps", string_array_to_json(teacher.step_ids)},
        {"teacher", Json::object {
            {"class", teacher.cls},
            {"matched_clues", string_array_to_json(teacher.matched_clues)},
            {"allowed_step_ids", string_array_to_json(teacher.step_ids)}
        }}
    });
}

void emit_failure_packet(const MlDumpConfig &dump_cfg, const string &pair_id, const string &stage,
                                const string &action, const string &gold_mod, const string &gate_mod,
                                const CommandResult &command_result)
{
    if (!dump_cfg.dump_fail || dump_cfg.fail_jsonl.empty())
        return;

    std::vector<string> clues = extract_failure_clues(command_result.output);
    auto teacher = failure_teacher(command_result, clues);
    string proof_outcome = command_result.proof_outcome.empty() ?
        infer_proof_outcome(command_result, clues) : command_result.proof_outcome;
    string key = packet_key(pair_id, stage, action, proof_outcome,
                            command_result.raw_result_code, clues);
    string packet_id = packet_id_from_key(key);
    string fp = packet_fingerprint(packet_id, command_result.log_file);
    if (!should_emit_failure_packet(dump_cfg.fail_jsonl, fp))
        return;

    PairRecord pair = packet_pair_record(pair_id, gold_mod, gate_mod);
    append_jsonl(dump_cfg.fail_jsonl, Json::object {
        {"schema_version", 1},
        {"packet_id", packet_id},
        {"design", gold_mod},
        {"gold_mod", gold_mod},
        {"gate_mod", gate_mod},
        {"pair_id", pair_id},
        {"engine", packet_engine(stage)},
        {"scope", packet_scope(stage)},
        {"pair", pair_record_to_json(pair)},
        {"stage", stage},
        {"action", action},
        {"clues", string_array_to_json(clues)},
        {"match", match_stats_to_json(MatchStats())},
        {"has_dff", false},
        {"has_submodule", false},
        {"exact_match_cnt", 0},
        {"typed_match_cnt", 0},
        {"exit_status", command_result.exit_status},
        {"raw_result_code", command_result.raw_result_code},
        {"result_code", command_result.result_code},
        {"proof_outcome", proof_outcome},
        {"runtime_ms", command_result.runtime_ms},
        {"log_file", command_result.log_file},
        {"fingerprint", fp},
        {"trace", Json::array()},
        {"recent_actions", Json::array()},
        {"last_2_actions", Json::array()},
        {"teacher_class", teacher.cls},
        {"next_steps", string_array_to_json(teacher.step_ids)},
        {"teacher", Json::object {
            {"class", teacher.cls},
            {"matched_clues", string_array_to_json(teacher.matched_clues)},
            {"allowed_step_ids", string_array_to_json(teacher.step_ids)}
        }}
    });
}
int exectue_and_check(const std::string & cmd, bool & correct,
                      const std::string & target_output,
                      const string &tempdir_name,
                    const string &tag,
                    const string &log_dir,
                    CommandResult *capture) {
    correct = false;
    CommandResult result = exec_capture(cmd, tempdir_name, tag, log_dir);
    correct = result.output.find(target_output) != std::string::npos;
    result.raw_result_code = correct ? 1 : 0;
    result.result_code = correct ? 1 : 0;
    result.proof_outcome = correct ? "equivalent" : infer_proof_outcome(result, extract_failure_clues(result.output));
    if (capture != nullptr)
        *capture = result;
    return result.exit_status;
}


int exectue_and_check(const std::string & cmd, int & result,
                    const std::vector<std::pair<std::string, int>>& target_result,
                    const string &tempdir_name,
                    const string &tag,
                    const string &log_dir,
                    CommandResult *capture) {
    CommandResult exec_result = exec_capture(cmd, tempdir_name, tag, log_dir);
    result = 0;

    for(auto it: target_result) {
        if (exec_result.output.find(it.first) != std::string::npos) {
            result = it.second;
            break;
        }
    }

    exec_result.raw_result_code = result;
    exec_result.result_code = result;
    exec_result.proof_outcome = infer_proof_outcome(exec_result, extract_failure_clues(exec_result.output));
    if (capture != nullptr)
        *capture = exec_result;
    return exec_result.exit_status;
}
int exec_cmd(const string &cmd, const string &tempdir_name, const string &tag,
             const string &log_dir, CommandResult *capture){
    CommandResult result = exec_capture(cmd, tempdir_name, tag, log_dir);
    result.raw_result_code = result.exit_status;
    result.result_code = result.exit_status;
    result.proof_outcome = infer_proof_outcome(result, extract_failure_clues(result.output));
    if (capture != nullptr)
        *capture = result;
    return result.exit_status;
}

} // namespace guide_check
YOSYS_NAMESPACE_END

// Rule-based failure hint tables and helpers
YOSYS_NAMESPACE_BEGIN
namespace guide_check {

static dict<string, string> HINT_CONFIDENCE = {
    {"abc_miter_failed", "medium"},
    {"abc_not_equivalent_struct_hash", "high"},
    {"abc_not_equivalent_sat", "high"},
    {"abc_not_equivalent_generic", "medium"},
    {"bmc_weak_failed", "medium"},
    {"bmc_bmc_phase_failed", "medium"},
    {"bmc_induct_phase_failed", "medium"},
    {"amulet_verify_failed", "high"},
    {"tool_exit_nonzero", "low"},
    {"missing_log_or_parse_error", "low"},
    {"unknown", "low"},
};

static dict<string, std::vector<string>> HINT_LIKELY_CAUSES = {
    {"abc_miter_failed", {
        "ABC could not build a usable miter for this pair",
        "the current match density may be too sparse or misleading",
        "the mapped fallback path may not fit this pair",
    }},
    {"abc_not_equivalent_struct_hash", {
        "a shallow mismatch is already visible before deeper proof phases",
        "boundary naming or cutpoint alignment may be off",
        "the pair may contain a real combinational mismatch",
    }},
    {"abc_not_equivalent_sat", {
        "SAT found a concrete mismatch after structural hashing did not settle the pair",
        "the mismatch is likely semantic rather than purely syntactic",
        "the failing cone is often small enough to inspect directly",
    }},
    {"abc_not_equivalent_generic", {
        "the proof engines found a concrete mismatch on this pair",
        "upstream transforms or matching may have misaligned the pair",
        "the failing cone should be replayed before changing policy",
    }},
    {"bmc_weak_failed", {
        "weak-mode induction did not close with the current warmup",
        "retimed structure may need different skip or depth settings",
        "sequential alignment may still be off on this pair",
    }},
    {"bmc_bmc_phase_failed", {
        "the BMC phase did not close within the current warmup/depth budget",
        "retimed structure may still need more skip or depth",
        "the trace should be replayed before changing proof policy",
    }},
    {"bmc_induct_phase_failed", {
        "the induction step failed even after the bounded phase ran",
        "the pair may need a different retime or warmup setup",
        "proof depth may still be too small for this pair",
    }},
    {"amulet_verify_failed", {
        "the multiplier-specific flow rejected the current candidate",
        "signedness or width assumptions may be wrong",
        "the blackboxing or substitute path may not match the extracted cone",
    }},
    {"tool_exit_nonzero", {
        "the external tool exited unsuccessfully before a clear clue was extracted",
        "the command log is needed before changing the classification",
    }},
    {"missing_log_or_parse_error", {
        "the packet did not retain enough logging to classify the failure cleanly",
        "the command should be replayed to recover the missing context",
    }},
    {"unknown", {
        "the packet does not match a known failure class yet",
        "the command log needs manual inspection",
    }},
};

static dict<string, string> HINT_STEP_REASON = {
    {"retry_cec_nomap", "Retry the pair without the current name map to see whether mapping sparsity is blocking the proof path."},
    {"retry_dsec_map", "Escalate to the sequential engine on the mapped pair when combinational checks are inconclusive."},
    {"inspect_match_density", "Inspect exact and typed match counts before changing the proof flow."},
    {"increase_bmc_skip", "Give the BMC warmup more room before concluding the sequential proof path is blocked."},
    {"increase_bmc_k", "Increase the search depth so the failing sequential proof has a chance to settle."},
    {"inspect_retime_pair", "Inspect retimed structure and warmup alignment on this module pair."},
    {"check_multiplier_sign_width", "Check multiplier signedness and width assumptions against the extracted cone."},
    {"check_blackboxing_path", "Verify the multiplier blackboxing/substitution path before changing the proof result."},
    {"replay_failing_action", "Replay the exact failing action with the captured log to confirm the failure mode."},
    {"inspect_counterexample", "Inspect the earliest counterexample-bearing signals before changing transforms or matching."},
    {"inspect_upstream_transforms", "Check whether preprocessing or structural rewrites changed the behavior or proof contract."},
    {"inspect_partition_boundary", "Inspect partition boundary assumptions before trusting a local mismatch."},
    {"inspect_command_log", "Read the captured command log before changing policy or classification."},
};

static string json_string_val(const Json &obj, const string &key, const string &fallback = "")
{
    auto it = obj.object_items().find(key);
    if (it != obj.object_items().end() && it->second.is_string())
        return it->second.string_value();
    return fallback;
}

static Json json_val(const Json &obj, const string &key)
{
    auto it = obj.object_items().find(key);
    if (it != obj.object_items().end())
        return it->second;
    return Json();
}

static string hint_summarize(const Json &packet)
{
    string tc = json_string_val(packet, "teacher_class", "unknown");
    string action = json_string_val(packet, "action", "unknown_action");
    string stage = json_string_val(packet, "stage", "UNKNOWN");
    string pid = json_string_val(packet, "pair_id", "unknown_pair");
    string proof_outcome = json_string_val(packet, "proof_outcome", "unknown");

    if (tc == "abc_miter_failed")
        return stringf("%s blocked on %s while running %s; ABC could not build a usable miter.", stage.c_str(), pid.c_str(), action.c_str());
    if (tc == "abc_not_equivalent_struct_hash")
        return stringf("%s reported a mismatch for %s during structural hashing while running %s.", stage.c_str(), pid.c_str(), action.c_str());
    if (tc == "abc_not_equivalent_sat")
        return stringf("%s reported a mismatch for %s after SAT while running %s.", stage.c_str(), pid.c_str(), action.c_str());
    if (tc == "abc_not_equivalent_generic")
        return stringf("%s reported a mismatch for %s while running %s; replay the failing pair before changing heuristics.", stage.c_str(), pid.c_str(), action.c_str());
    if (tc == "bmc_weak_failed")
        return stringf("%s blocked for %s while running %s; weak-mode induction did not close.", stage.c_str(), pid.c_str(), action.c_str());
    if (tc == "bmc_bmc_phase_failed")
        return stringf("%s blocked for %s while running %s; the bounded phase did not close cleanly.", stage.c_str(), pid.c_str(), action.c_str());
    if (tc == "bmc_induct_phase_failed")
        return stringf("%s blocked for %s while running %s; the induction phase failed.", stage.c_str(), pid.c_str(), action.c_str());
    if (tc == "amulet_verify_failed")
        return stringf("%s blocked for %s while running %s; the multiplier-specific verification path rejected the candidate.", stage.c_str(), pid.c_str(), action.c_str());
    if (tc == "tool_exit_nonzero")
        return stringf("%s hit a tool-side execution error for %s while running %s.", stage.c_str(), pid.c_str(), action.c_str());
    if (tc == "missing_log_or_parse_error")
        return stringf("%s failed for %s while running %s; the packet is missing enough log context for a clean classification.", stage.c_str(), pid.c_str(), action.c_str());
    if (proof_outcome == "timeout")
        return stringf("%s timed out for %s while running %s.", stage.c_str(), pid.c_str(), action.c_str());

    Json clues = json_val(packet, "clues");
    if (clues.is_array() && !clues.array_items().empty())
        return stringf("%s failed for %s while running %s; primary clue: %s.", stage.c_str(), pid.c_str(), action.c_str(), clues[0].string_value().c_str());
    return stringf("%s failed for %s while running %s; inspect the captured log before changing the proof path.", stage.c_str(), pid.c_str(), action.c_str());
}

static Json hint_step_objs(const std::vector<string> &step_ids)
{
    Json::array out;
    int rank = 1;
    for (const auto &sid : step_ids) {
        string reason = HINT_STEP_REASON.count(sid) ? HINT_STEP_REASON.at(sid) :
            "Inspect the captured failure context before changing the proof path.";
        Json::object obj;
        obj["id"] = Json(sid);
        obj["rank"] = Json(rank++);
        obj["reason"] = Json(reason);
        out.push_back(Json(obj));
    }
    return Json(out);
}

Json failure_hint_from_packet(const Json &packet)
{
    string tc = json_string_val(packet, "teacher_class", "unknown");
    Json teacher = json_val(packet, "teacher");
    Json clues = json_val(packet, "clues");

    std::vector<string> step_ids;
    if (teacher.is_object() && json_val(teacher, "allowed_step_ids").is_array()) {
        for (const auto &s : json_val(teacher, "allowed_step_ids").array_items())
            step_ids.push_back(s.string_value());
    } else {
        Json ns = json_val(packet, "next_steps");
        if (ns.is_array())
            for (const auto &s : ns.array_items())
                step_ids.push_back(s.string_value());
    }
    if (step_ids.empty())
        step_ids = {"inspect_command_log", "replay_failing_action"};

    string confidence = HINT_CONFIDENCE.count(tc) ? HINT_CONFIDENCE.at(tc) : "low";

    std::vector<string> causes;
    if (HINT_LIKELY_CAUSES.count(tc))
        causes = HINT_LIKELY_CAUSES.at(tc);
    else
        causes = HINT_LIKELY_CAUSES.at("unknown");

    Json::array causes_json;
    for (const auto &c : causes)
        causes_json.push_back(Json(c));

    Json::object hint_obj;
    hint_obj["packet_id"] = json_val(packet, "packet_id");
    hint_obj["pair_id"] = json_val(packet, "pair_id");
    hint_obj["scope"] = json_val(packet, "scope");
    hint_obj["engine"] = json_val(packet, "engine");
    hint_obj["stage"] = json_val(packet, "stage");
    hint_obj["action"] = json_val(packet, "action");
    hint_obj["proof_outcome"] = json_val(packet, "proof_outcome");
    hint_obj["failure_kind"] = Json(tc);
    hint_obj["confidence"] = Json(confidence);
    hint_obj["hint_summary"] = Json(hint_summarize(packet));
    hint_obj["likely_causes"] = Json(causes_json);
    hint_obj["next_steps"] = hint_step_objs(step_ids);
    hint_obj["teacher"] = teacher;
    return Json(hint_obj);
}

void write_failure_hints(const string &fail_jsonl, const string &hints_jsonl)
{
    if (fail_jsonl.empty() || hints_jsonl.empty())
        return;

    FILE *fin = fopen(fail_jsonl.c_str(), "r");
    if (fin == nullptr)
        return;

    Json::array items;
    char buf[262144];
    while (fgets(buf, sizeof(buf), fin) != nullptr) {
        string line = buf;
        while (!line.empty() && (line.back() == '\n' || line.back() == '\r'))
            line.pop_back();
        if (line.empty())
            continue;
        try {
            string err;
            Json packet = Json::parse(line, err);
            items.push_back(failure_hint_from_packet(packet));
        } catch (std::exception &e) {
            log_warning("Skipping unparseable fail.jsonl line: %s\n", e.what());
        }
    }
    fclose(fin);

    Json::object output_obj;
    output_obj["schema_version"] = Json(1);
    output_obj["source_fail_jsonl"] = Json(fail_jsonl);
    Json::object provider_obj;
    provider_obj["kind"] = Json("rule");
    provider_obj["model"] = Json();
    output_obj["provider"] = Json(provider_obj);
    output_obj["items"] = items;
    Json output = Json(output_obj);

    FILE *fout = fopen(hints_jsonl.c_str(), "w");
    if (fout == nullptr)
        log_error("Cannot open %s for writing.\n", hints_jsonl.c_str());
    fprintf(fout, "%s\n", output.dump().c_str());
    fclose(fout);
}

} // namespace guide_check
YOSYS_NAMESPACE_END