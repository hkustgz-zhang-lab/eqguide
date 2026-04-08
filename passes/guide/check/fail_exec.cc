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

static string packet_fingerprint(const string &pair_id, const string &stage, const string &action,
                                 const string &proof_outcome, int raw_result_code,
                                 const std::vector<string> &clues, const string &log_file)
{
    string joined = pair_id + "|" + stage + "|" + action + "|" + proof_outcome + "|" +
        std::to_string(raw_result_code) + "|" + log_file;
    for (const auto &clue : clues)
        joined += "|" + clue;
    return joined;
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

std::pair<string, std::vector<string>> failure_teacher(const std::vector<string> &clues)
{
    for (auto &clue : clues) {
        if (clue == "Miter computation has failed")
            return {"abc_miter_failed", {"try -n fallback", "inspect match density"}};
        if (clue == "Networks are NOT EQUIVALENT after structural hashing")
            return {"not_equivalent_after_structural_hashing", {"inspect PI and cutpoint alignment", "check trivial boundary mismatches"}};
        if (clue == "Networks are NOT EQUIVALENT after SAT")
            return {"not_equivalent_after_sat", {"inspect SAT counterexample-bearing signals", "check upstream transforms"}};
        if (clue == "Networks are NOT EQUIVALENT after fraiging")
            return {"not_equivalent_after_fraiging", {"inspect fraiging-sensitive cone differences", "check structural normalization assumptions"}};
        if (clue == "Networks are NOT EQUIVALENT after partitioning")
            return {"not_equivalent_after_partitioning", {"inspect partition boundary assumptions", "check boundary map density"}};
        if (clue == "Networks are NOT EQUIVALENT after framing")
            return {"not_equivalent_after_framing", {"inspect sequential framing assumptions", "check reset/init handling"}};
        if (clue == "Networks are NOT EQUIVALENT after simulation")
            return {"not_equivalent_after_simulation", {"inspect simulation counterexample", "check early mismatch-producing signals"}};
        if (clue == "BMC-Induct failed in weak mode" || clue == "BMC-Induct failed in BMC phase" ||
            clue == "BMC-Induct failed in Induct phase")
            return {"retime_or_warmup_issue", {"increase -skip", "increase -k", "inspect retimed pair"}};
        if (clue == "Amulet Verify failed")
            return {"multiplier_annotation_or_sca_issue", {"check multiplier width/sign", "check blackboxing path"}};
        if (clue == "Networks are NOT EQUIVALENT")
            return {"not_equivalent_counterexample", {"inspect counterexample-producing module pair", "check upstream transforms"}};
    }

    return {"unknown_failure", {"inspect command log", "replay failing action manually"}};
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
    packet.pair_id = get_pair_id(conf.gold_mod->name, conf.gate_mod->name);
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

    for (auto &item : trace)
        packet.recent_actions.push_back(item.action);

    std::vector<string> last_2_actions;
    int start = std::max(0, GetSize(packet.recent_actions) - 2);
    for (int i = start; i < GetSize(packet.recent_actions); i++)
        last_2_actions.push_back(packet.recent_actions[i]);

    auto teacher = failure_teacher(packet.clues);
    packet.fingerprint = packet_fingerprint(packet.pair_id, packet.stage, packet.action,
                                           packet.proof_outcome, packet.raw_result_code,
                                           packet.clues, packet.log_file);
    if (!should_emit_failure_packet(conf.dump_cfg.fail_jsonl, packet.fingerprint))
        return;

    append_jsonl(conf.dump_cfg.fail_jsonl, Json::object {
        {"design", strip_backslash(conf.gold_mod->name)},
        {"gold_mod", strip_backslash(conf.gold_mod->name)},
        {"gate_mod", strip_backslash(conf.gate_mod->name)},
        {"pair_id", packet.pair_id},
        {"stage", packet.stage},
        {"action", packet.action},
        {"clues", string_array_to_json(packet.clues)},
        {"match", match_stats_to_json(packet.match)},
        {"has_dff", module_has_dff(conf.gold_mod, false) || module_has_dff(conf.gate_mod, true)},
        {"has_submodule", module_has_submodule(conf.design, conf.gold_mod)},
        {"exact_match_cnt", packet.match.exact_total},
        {"typed_match_cnt", typed_match_total(packet.match)},
        {"exit_status", packet.exit_status},
        {"raw_result_code", packet.raw_result_code},
        {"result_code", packet.result_code},
        {"proof_outcome", packet.proof_outcome},
        {"runtime_ms", packet.runtime_ms},
        {"log_file", packet.log_file},
        {"fingerprint", packet.fingerprint},
        {"recent_actions", string_array_to_json(packet.recent_actions)},
        {"last_2_actions", string_array_to_json(last_2_actions)},
        {"teacher_class", teacher.first},
        {"next_steps", string_array_to_json(teacher.second)}
    });
}

void emit_failure_packet(const MlDumpConfig &dump_cfg, const string &pair_id, const string &stage,
                                const string &action, const string &gold_mod, const string &gate_mod,
                                const CommandResult &command_result)
{
    if (!dump_cfg.dump_fail || dump_cfg.fail_jsonl.empty())
        return;

    std::vector<string> clues = extract_failure_clues(command_result.output);
    auto teacher = failure_teacher(clues);
    string proof_outcome = command_result.proof_outcome.empty() ?
        infer_proof_outcome(command_result, clues) : command_result.proof_outcome;
    string fp = packet_fingerprint(pair_id, stage, action, proof_outcome,
                                   command_result.raw_result_code, clues, command_result.log_file);
    if (!should_emit_failure_packet(dump_cfg.fail_jsonl, fp))
        return;

    append_jsonl(dump_cfg.fail_jsonl, Json::object {
        {"design", gold_mod},
        {"gold_mod", gold_mod},
        {"gate_mod", gate_mod},
        {"pair_id", pair_id},
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
        {"recent_actions", Json::array()},
        {"last_2_actions", Json::array()},
        {"teacher_class", teacher.first},
        {"next_steps", string_array_to_json(teacher.second)}
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
