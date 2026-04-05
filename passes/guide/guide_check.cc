/*
 *  yosys -- Yosys Open SYnthesis Suite
 *
 *  Copyright (C) 2025  Bingjin Han <bhan729@connect.hkust-gz.edu.cn>
 *
 *  Permission to use, copy, modify, and/or distribute this software for any
 *  purpose with or without fee is hereby granted, provided that the above
 *  copyright notice and this permission notice appear in all copies.
 *
 *  THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 *  WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 *  MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 *  ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 *  WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 *  ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 *  OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 *
 */

#include "kernel/celltypes.h"
#include "kernel/drivertools.h"
#include "kernel/hashlib.h"
#include "kernel/mem.h"
#include "kernel/register.h"
#include "kernel/rtlil.h"
#include "kernel/log.h"
#include "kernel/ff.h"
#include "libs/json11/json11.hpp"
#include "kernel/sigtools.h"
#include "kernel/yosys.h"
#include <algorithm>
#include <cassert>
#include <cctype>
#include <cstddef>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <map>
#include <sstream>
#include <set>
#include <string>
#include <tuple>
#include <chrono>
#include "kernel/modtools.h"
#include <unordered_map>
#include <utility>
#include <vector>

USING_YOSYS_NAMESPACE
PRIVATE_NAMESPACE_BEGIN

using json11::Json;

/*

TODO: async2sync: still has bugs.
TODO: support latch? 

*/


#define TIMINGSTAT_FIELDS(X)            \
    X(abc_cec_ms)                       \
    X(prep_ms)                          \
    X(dump_blif_ms)                     \
    X(read_lib_ms)                      \
    X(hier_mod_map_ms)                  \
    X(signal_map_ms)                    \
    X(check_mul_ms)                     \
    X(mul_map_ms)                       \
    X(check_retime_ms)                  

struct TimingStat {
#define DECL_FIELD(name) std::uint64_t name = 0;
    TIMINGSTAT_FIELDS(DECL_FIELD)
#undef DECL_FIELD

    TimingStat() {}
};

TimingStat timing_stat;

using Results = std::vector<std::pair<RTLIL::IdString, bool>>;

struct SeqCheckConfig
{
    int k_induct = 20;
    int step_skip = 0;
    bool weak_mode = false;
    bool no_init = false;
};

struct MlDumpConfig
{
    bool dump_sched = false;
    bool dump_match = false;
    bool dump_fail = false;
    string sched_jsonl;
    string match_jsonl;
    string fail_jsonl;
};

struct PairRecord
{
    string pair_id;
    string gold_mod;
    string gate_mod;
    int gold_dff_cnt = 0;
    int gate_dff_cnt = 0;
    bool has_submodule = false;
    bool retimed = false;
    bool touched_by_multiplier = false;
    int const_blackbox_inputs_inserted = 0;
};

struct MatchStats
{
    int exact_total = 0;
    int pi_cnt = 0;
    int po_cnt = 0;
    int dff_cnt = 0;
    int dff_po_cnt = 0;
    int subckt_cnt = 0;
    int unmatched_gold = 0;
    int unmatched_gate = 0;
    string match_file;
};

struct RunRecord
{
    string pair_id;
    string action;
    int exit_status = -1;
    int result_code = 0;
    double runtime_ms = 0;
    string log_file;
};

struct GuideSchedLinearAction
{
    double bias = 0;
    dict<string, double> weights;
};

struct GuideSchedTreeNode
{
    int feature_index = -1;
    double threshold = 0;
    int left = -1;
    int right = -1;
    double value = 0;
    bool is_leaf = false;
};

struct GuideSchedTree
{
    std::vector<GuideSchedTreeNode> nodes;
};

struct GuideSchedModel
{
    bool loaded = false;
    string path;
    string model_type;
    std::vector<string> feature_names;
    double base_score = 0;
    double learning_rate = 1.0;
    dict<string, GuideSchedLinearAction> linear_actions;
    std::vector<GuideSchedTree> trees;
};

struct FailurePacket
{
    string pair_id;
    string stage;
    string action;
    std::vector<string> clues;
    MatchStats match;
    int exit_status = -1;
    int result_code = 0;
    double runtime_ms = 0;
    string log_file;
    std::vector<string> recent_actions;
};

struct CommandResult
{
    int exit_status = -1;
    int result_code = 0;
    double runtime_ms = 0;
    string output;
    string log_file;
};

struct GuideTelemetry
{
    std::map<string, MatchStats> pair_match_stats;
    pool<RTLIL::IdString> retimed_mods;
    pool<RTLIL::IdString> multiplier_mods;
    Json::array match_suggestions;
};

struct CheckConfig
{
    bool nocleanup = false;
    std::string abc_exe_file;
    std::string tempdir_name;
    RTLIL::Design *design = nullptr;
    RTLIL::Module *gold_mod = nullptr;
    RTLIL::Module *gate_mod = nullptr;
    string gold_prefix;
    string gate_prefix;
    string lib_file;
    string sched_model_file;
    SeqCheckConfig seq_check_cfg;
    MlDumpConfig dump_cfg;
    GuideSchedModel *sched_model = nullptr;
    GuideTelemetry *telemetry = nullptr;
    RTLIL::Design *lib_design = nullptr;
};

struct ModMap{
    dict<RTLIL::IdString, RTLIL::IdString> mod_map_gold; // gold -> gate
    dict<RTLIL::IdString, RTLIL::IdString> mod_map_gate; // gate -> gold
    pool<RTLIL::IdString> mapped_mods_gold;
    pool<RTLIL::IdString> mapped_mods_gate;
    pool<RTLIL::IdString> unmapped_mods_gate;
    pool<RTLIL::IdString> unmapped_mods_gold;
};

// the xx_cell under xx_mod. 
struct MultiMapEntry{
    RTLIL::IdString gold_mod;
    RTLIL::IdString gate_mod;
    RTLIL::IdString gold_cell; 
    RTLIL::IdString gate_cell; 
    bool is_multi_mod;  // means that the whole module is a multiplier
};

using MultiMap = std::vector<MultiMapEntry>;

#define MATCHTYPE_FIELDS(X)       \
    X(NONE)                       \
    X(PO)                         \
    X(PI)                         \
    X(DFF)                        \
    X(DFF_PO)                     \
    X(SUBCKT_PIPO)

enum class MatchType {
#define DECL_FIELD(name) name,
    MATCHTYPE_FIELDS(DECL_FIELD)
#undef DECL_FIELD
};

enum class ActionKind {
    CEC_MAP,
    CEC_NOMAP,
    DSEC_MAP,
    DSEC_NOMAP
};

struct CutPoint{
    RTLIL::IdString name;
    RTLIL::SigBit gold_sig;
    RTLIL::SigBit gate_sig;
    MatchType type = MatchType::NONE;
    RTLIL::Cell* gold_ff_cell = nullptr;
    RTLIL::Cell* gate_ff_cell = nullptr;
    RTLIL::IdString gold_wire_name;
    int gold_bit_index = 0;
    RTLIL::IdString gate_wire_name;
    int gate_bit_index = 0;
};

struct MatchResult
{
    std::vector<CutPoint> cut_points;
    MatchStats stats;
};

struct NamedSig {
    RTLIL::SigBit sig;
    MatchType type = MatchType::NONE;
    RTLIL::IdString wire_name;
    int bit_index = 0;
};

static inline void print_timing_stat(const TimingStat& s) {
    std::uint64_t t_total = 0;
    log("Timing Statistics:\n");
#define PRINT_FIELD(name) if(s.name) log("    %s: %.3lf s.\n", #name, s.name/1000.0);
    TIMINGSTAT_FIELDS(PRINT_FIELD)
#undef PRINT_FIELD
#define ACC_FIELD(name) t_total += s.name;
    TIMINGSTAT_FIELDS(ACC_FIELD)
#undef ACC_FIELD
    log("    Total accounting time: %.3lf s.\n",t_total/1000.0);
}

static inline string get_match_type_str(const MatchType& t) {
    switch (t) {
#define CASE(name) case MatchType::name: return #name;
        MATCHTYPE_FIELDS(CASE)
#undef CASE
    }
    assert(0);
    return "UNKNOWN";
}

static inline string get_action_name(ActionKind action)
{
    switch (action) {
    case ActionKind::CEC_MAP:
        return "cec_map";
    case ActionKind::CEC_NOMAP:
        return "cec_nomap";
    case ActionKind::DSEC_MAP:
        return "dsec_map";
    case ActionKind::DSEC_NOMAP:
        return "dsec_nomap";
    }
    assert(0);
    return "unknown";
}

static void print_MultiMap(const MultiMap &mm)
{
    log("MultiMap entries: %zu\n", mm.size());
    for (size_t i = 0; i < mm.size(); ++i) {
        const auto &e = mm[i];
        if(!e.is_multi_mod){
            log("  [%zu] gold_mod=%s gate_mod=%s gold_cell=%s gate_cell=%s is_multi_mod=%d\n",
                i,
                log_id(e.gold_mod),
                log_id(e.gate_mod),
                log_id(e.gold_cell),
                log_id(e.gate_cell),
                int(e.is_multi_mod));
        }
        else { 
            log("  [%zu] gold_mod=%s gate_mod=%s is_multi_mod=%d\n",
                i,
                log_id(e.gold_mod),
                log_id(e.gate_mod),
                int(e.is_multi_mod));
        }
    }
    
}

static std::string strip_backslash(const RTLIL::IdString &id)
{
    std::string s = id.str();
    if (!s.empty() && s[0] == '\\') s = s.substr(1);
    return s;
}
static RTLIL::Design *empty_design()
{
    auto *design = new RTLIL::Design;
    design->push_full_selection();
    return design;
}

static string sanitize_filename(const string &s)
{
    string out = s;
    for (char &ch : out)
        if (!std::isalnum(static_cast<unsigned char>(ch)) && ch != '_' && ch != '-' && ch != '.')
            ch = '_';
    return out;
}

static string get_pair_id(const RTLIL::IdString &gold_mod, const RTLIL::IdString &gate_mod)
{
    return strip_backslash(gold_mod) + "__vs__" + strip_backslash(gate_mod);
}

static Json match_stats_to_json(const MatchStats &stats)
{
    return Json::object {
        {"exact_total", stats.exact_total},
        {"pi_cnt", stats.pi_cnt},
        {"po_cnt", stats.po_cnt},
        {"dff_cnt", stats.dff_cnt},
        {"dff_po_cnt", stats.dff_po_cnt},
        {"subckt_cnt", stats.subckt_cnt},
        {"unmatched_gold", stats.unmatched_gold},
        {"unmatched_gate", stats.unmatched_gate},
        {"match_file", stats.match_file}
    };
}

static Json pair_record_to_json(const PairRecord &record)
{
    return Json::object {
        {"pair_id", record.pair_id},
        {"gold_mod", record.gold_mod},
        {"gate_mod", record.gate_mod},
        {"gold_dff_cnt", record.gold_dff_cnt},
        {"gate_dff_cnt", record.gate_dff_cnt},
        {"has_submodule", record.has_submodule},
        {"retimed", record.retimed},
        {"touched_by_multiplier", record.touched_by_multiplier},
        {"const_blackbox_inputs_inserted", record.const_blackbox_inputs_inserted}
    };
}

static Json run_record_to_json(const RunRecord &record)
{
    return Json::object {
        {"pair_id", record.pair_id},
        {"action", record.action},
        {"exit_status", record.exit_status},
        {"result_code", record.result_code},
        {"runtime_ms", record.runtime_ms},
        {"log_file", record.log_file}
    };
}

static void append_jsonl(const string &path, const Json &json)
{
    if (path.empty())
        return;

    FILE *f = fopen(path.c_str(), "a");
    if (f == nullptr)
        log_error("Cannot open JSONL file %s for append.\n", path.c_str());

    fprintf(f, "%s\n", json.dump().c_str());
    fclose(f);
}

static string make_command_log_file(const string &tempdir_name, const string &tag)
{
    string dir_name = tempdir_name.empty() ? get_base_tmpdir() : tempdir_name;
    string log_file = dir_name + "/" + sanitize_filename(tag) + "-XXXXXX.log";
    return make_temp_file(log_file);
}

static std::vector<string> extract_failure_clues(const string &output)
{
    std::vector<string> clues;
    const std::vector<string> known_clues = {
        "Networks are NOT EQUIVALENT",
        "Miter computation has failed",
        "BMC-Induct failed in weak mode",
        "BMC-Induct failed in BMC phase",
        "BMC-Induct failed in Induct phase",
        "Amulet Verify failed"
    };

    for (auto &clue : known_clues)
        if (output.find(clue) != string::npos)
            clues.push_back(clue);

    return clues;
}

static CommandResult exec_capture(const string &cmd, const string &tempdir_name, const string &tag)
{
    CommandResult result;
    string cmd_with_stderr = cmd + " 2>&1";
    string log_file = make_command_log_file(tempdir_name, tag);
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

static MatchStats get_match_stats(const CheckConfig &conf)
{
    if (conf.telemetry == nullptr)
        return MatchStats();

    string pair_id = get_pair_id(conf.gold_mod->name, conf.gate_mod->name);
    auto it = conf.telemetry->pair_match_stats.find(pair_id);
    if (it == conf.telemetry->pair_match_stats.end())
        return MatchStats();
    return it->second;
}

static int typed_match_total(const MatchStats &stats)
{
    return stats.pi_cnt + stats.po_cnt + stats.dff_cnt + stats.dff_po_cnt + stats.subckt_cnt;
}

static bool module_has_submodule(RTLIL::Design *design, RTLIL::Module *mod)
{
    for (auto cell : mod->cells()) {
        RTLIL::Module *submod = design->module(cell->type);
        if (submod != nullptr && !submod->get_bool_attribute(ID(blackbox)))
            return true;
    }
    return false;
}

static bool module_has_dff(RTLIL::Module *mod, bool gate_side)
{
    for (auto cell : mod->cells())
        if (cell->type == ID($ff) || cell->type == ID($dff) || cell->type == ID($dffe) ||
            cell->type == ID($_DFF_P_) || cell->type == ID($_DFF_N_) || cell->type == ID($_DFFE_PN) ||
            cell->type == ID($_DFFE_PP) || (gate_side && cell->type.contains("DFF")))
            return true;
    return false;
}

static std::pair<string, std::vector<string>> failure_teacher(const std::vector<string> &clues)
{
    for (auto &clue : clues) {
        if (clue == "Miter computation has failed")
            return {"abc_miter_failed", {"try -n fallback", "inspect match density"}};
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

static Json string_array_to_json(const std::vector<string> &values)
{
    Json::array out;
    for (auto &value : values)
        out.push_back(value);
    return out;
}

static dict<string, double> scheduler_pair_features(const PairRecord &pair_record, const MatchStats &match_stats)
{
    dict<string, double> features;
    features["has_dff"] = (pair_record.gold_dff_cnt != 0 || pair_record.gate_dff_cnt != 0) ? 1.0 : 0.0;
    features["gold_dff_cnt"] = pair_record.gold_dff_cnt;
    features["gate_dff_cnt"] = pair_record.gate_dff_cnt;
    features["has_submodule"] = pair_record.has_submodule ? 1.0 : 0.0;
    features["exact_total"] = match_stats.exact_total;
    features["pi_cnt"] = match_stats.pi_cnt;
    features["po_cnt"] = match_stats.po_cnt;
    features["dff_cnt"] = match_stats.dff_cnt;
    features["dff_po_cnt"] = match_stats.dff_po_cnt;
    features["subckt_cnt"] = match_stats.subckt_cnt;
    features["unmatched_gold"] = match_stats.unmatched_gold;
    features["unmatched_gate"] = match_stats.unmatched_gate;
    features["retimed"] = pair_record.retimed ? 1.0 : 0.0;
    features["touched_by_multiplier"] = pair_record.touched_by_multiplier ? 1.0 : 0.0;
    features["const_blackbox_inputs_inserted"] = pair_record.const_blackbox_inputs_inserted;
    return features;
}

static dict<string, double> scheduler_context_features(const string &action,
                                                       const PairRecord &pair_record,
                                                       const MatchStats &match_stats)
{
    dict<string, double> features = scheduler_pair_features(pair_record, match_stats);
    features["act_cec_map"] = action == "cec_map" ? 1.0 : 0.0;
    features["act_cec_nomap"] = action == "cec_nomap" ? 1.0 : 0.0;
    features["act_dsec_map"] = action == "dsec_map" ? 1.0 : 0.0;
    features["act_dsec_nomap"] = action == "dsec_nomap" ? 1.0 : 0.0;
    features["is_dsec"] = (action == "dsec_map" || action == "dsec_nomap") ? 1.0 : 0.0;
    features["use_map"] = (action == "cec_map" || action == "dsec_map") ? 1.0 : 0.0;
    return features;
}

static double tree_predict(const GuideSchedTree &tree, const std::vector<double> &features)
{
    int node_index = 0;
    while (node_index >= 0 && node_index < GetSize(tree.nodes)) {
        const auto &node = tree.nodes[node_index];
        if (node.is_leaf)
            return node.value;

        double feature_value = 0;
        if (node.feature_index >= 0 && node.feature_index < GetSize(features))
            feature_value = features[node.feature_index];
        node_index = feature_value <= node.threshold ? node.left : node.right;
    }
    return 0;
}

static bool load_sched_model(const string &path, GuideSchedModel &model)
{
    if (path.empty())
        return false;
    if (model.loaded && model.path == path)
        return true;

    std::ifstream handle(path);
    if (!handle.is_open())
        log_error("Cannot open scheduler model file %s.\n", path.c_str());

    std::stringstream buffer;
    buffer << handle.rdbuf();
    string error;
    Json json = Json::parse(buffer.str(), error);
    if (!error.empty())
        log_error("Cannot parse scheduler model file %s: %s\n", path.c_str(), error.c_str());

    model = GuideSchedModel();
    model.path = path;
    model.model_type = json["model_type"].string_value();
    model.base_score = json["base_score"].number_value();
    model.learning_rate = json["learning_rate"].number_value();

    auto feature_names = json["feature_names"].array_items();
    for (auto &item : feature_names)
        if (item.is_string())
            model.feature_names.push_back(item.string_value());

    if (model.model_type == "guide_sched_linear_v1") {
        for (auto &it : json["actions"].object_items()) {
            GuideSchedLinearAction action_model;
            action_model.bias = it.second["bias"].number_value();
            for (auto &weight : it.second["weights"].object_items())
                action_model.weights[weight.first] = weight.second.number_value();
            model.linear_actions[it.first] = action_model;
        }
    } else
    if (model.model_type == "guide_sched_gbdt_v1") {
        for (auto &tree_json : json["trees"].array_items()) {
            GuideSchedTree tree;
            for (auto &node_json : tree_json["nodes"].array_items()) {
                GuideSchedTreeNode node;
                node.feature_index = node_json["feature_index"].int_value();
                node.threshold = node_json["threshold"].number_value();
                node.left = node_json["left"].int_value();
                node.right = node_json["right"].int_value();
                node.value = node_json["value"].number_value();
                node.is_leaf = node_json["is_leaf"].bool_value();
                tree.nodes.push_back(node);
            }
            model.trees.push_back(tree);
        }
    } else
        log_error("Unsupported scheduler model type in %s: %s\n", path.c_str(), model.model_type.c_str());

    if (model.model_type == "guide_sched_gbdt_v1" && model.feature_names.empty())
        log_error("Scheduler model %s has no feature names.\n", path.c_str());
    if (model.model_type == "guide_sched_gbdt_v1" && model.trees.empty())
        log_error("Scheduler model %s has no trees.\n", path.c_str());

    if (model.model_type == "guide_sched_linear_v1" && model.linear_actions.empty())
        log_error("Scheduler model %s has no action weights.\n", path.c_str());

    if (model.learning_rate == 0)
        model.learning_rate = 1.0;
    if (model.model_type == "guide_sched_linear_v1" && model.base_score == 0)
        model.base_score = 0;

    if (model.model_type == "guide_sched_gbdt_v1") {
        for (auto &tree : model.trees)
            if (tree.nodes.empty())
                log_error("Scheduler model %s contains an empty tree.\n", path.c_str());
    }

    model.loaded = true;
    return true;
}

static double predict_sched_cost(const GuideSchedModel &model, const string &action,
                                 const PairRecord &pair_record, const MatchStats &match_stats)
{
    if (!model.loaded)
        return 0;

    if (model.model_type == "guide_sched_linear_v1") {
        if (!model.linear_actions.count(action))
            return 0;
        dict<string, double> features = scheduler_context_features(action, pair_record, match_stats);
        double cost = model.linear_actions.at(action).bias;
        for (auto &weight : model.linear_actions.at(action).weights)
            cost += weight.second * (features.count(weight.first) ? features.at(weight.first) : 0.0);
        return cost;
    }

    dict<string, double> features_by_name = scheduler_context_features(action, pair_record, match_stats);
    std::vector<double> features(GetSize(model.feature_names), 0.0);
    for (int i = 0; i < GetSize(model.feature_names); i++)
        if (features_by_name.count(model.feature_names[i]))
            features[i] = features_by_name.at(model.feature_names[i]);

    double cost = model.base_score;
    for (auto &tree : model.trees)
        cost += tree_predict(tree, features);
    return cost;
}

static void emit_failure_packet(const CheckConfig &conf, const string &stage, const string &action,
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
    packet.result_code = command_result.result_code;
    packet.runtime_ms = command_result.runtime_ms;
    packet.log_file = command_result.log_file;

    for (auto &item : trace)
        packet.recent_actions.push_back(item.action);

    std::vector<string> last_2_actions;
    int start = std::max(0, GetSize(packet.recent_actions) - 2);
    for (int i = start; i < GetSize(packet.recent_actions); i++)
        last_2_actions.push_back(packet.recent_actions[i]);

    auto teacher = failure_teacher(packet.clues);

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
        {"result_code", packet.result_code},
        {"runtime_ms", packet.runtime_ms},
        {"log_file", packet.log_file},
        {"recent_actions", string_array_to_json(packet.recent_actions)},
        {"last_2_actions", string_array_to_json(last_2_actions)},
        {"teacher_class", teacher.first},
        {"next_steps", string_array_to_json(teacher.second)}
    });
}

static void emit_failure_packet(const MlDumpConfig &dump_cfg, const string &pair_id, const string &stage,
                                const string &action, const string &gold_mod, const string &gate_mod,
                                const CommandResult &command_result)
{
    if (!dump_cfg.dump_fail || dump_cfg.fail_jsonl.empty())
        return;

    std::vector<string> clues = extract_failure_clues(command_result.output);
    auto teacher = failure_teacher(clues);

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
        {"result_code", command_result.result_code},
        {"runtime_ms", command_result.runtime_ms},
        {"log_file", command_result.log_file},
        {"recent_actions", Json::array()},
        {"last_2_actions", Json::array()},
        {"teacher_class", teacher.first},
        {"next_steps", string_array_to_json(teacher.second)}
    });
}

static RTLIL::SigSpec resize_u0(RTLIL::SigSpec src, int width);

static void flatten_std_cells(RTLIL::Design *design, RTLIL::Design *lib_design)
{
    assert(design);
    assert(lib_design);
    pool<RTLIL::IdString> std_cells;
    for (auto mod : lib_design->modules())
    {
        std_cells.insert(mod->name);
    }

    // Real Modules. Exclude standard cells.
    std::vector<RTLIL::Module*> modules;
    for (auto mod : design->modules())
    {
        if(std_cells.count(mod->name) != 0)
            continue;
        modules.push_back(mod);
    }

    std::vector<bool> keep_hierarchy_flags(modules.size(), false);
    for(size_t i = 0; i < modules.size(); i++){
        RTLIL::Module *mod = modules[i];
        if(mod->get_bool_attribute(ID(keep_hierarchy))){
            keep_hierarchy_flags[i] = true;
        }
    }

    for(auto mod : modules)
    {
        mod->set_bool_attribute(ID(keep_hierarchy), true);
    }

    for (auto mod : modules)
    {
        if(mod->get_bool_attribute(ID(blackbox)))
            continue;
        run_pass(stringf("flatten %s", mod->name.str()), design);
    }

    for(size_t i = 0; i < modules.size(); i++){
        RTLIL::Module *mod = modules[i];
        mod->set_bool_attribute(ID(keep_hierarchy), keep_hierarchy_flags[i]);
    }
}

static RTLIL::Design *clone_design_for_passes(RTLIL::Design *design)
{
    auto *copy = new RTLIL::Design;
    for (auto mod : design->modules())
        copy->add(mod->clone());
    copy->scratchpad = design->scratchpad;
    copy->selection_stack.clear();
    copy->selection_vars.clear();
    copy->selected_active_module.clear();
    copy->push_full_selection();
    return copy;
}

static void lib_import_to_design(RTLIL::Design *design, RTLIL::Design *lib_design)
{
    assert(design);
    assert(lib_design);
    for (auto mod : lib_design->modules())
    {
        if(design->module(mod->name) != nullptr){
            design->remove(design->module(mod->name));
        }
        RTLIL::Module *t = mod->clone();
        t->design = design;
        design->add(t);
    }
}

RTLIL::IdString get_orignal_mod_name(const RTLIL::IdString &mod_name,const RTLIL::IdString root_mod_name, const string& prefix)
{

    if (mod_name == root_mod_name) {
        return root_mod_name;
    }
    else if (mod_name.begins_with(RTLIL::escape_id(prefix))) {
        return RTLIL::escape_id(strip_backslash(mod_name).substr(prefix.size()));
    }
    else {
        return RTLIL::IdString();
    }
}

ModMap hier_mod_map(RTLIL::Design *design, CheckConfig& conf)
{
    assert(design);
    ModMap mod_map;
    
    auto t_start = std::chrono::steady_clock::now();
    

    auto gold2gate = &mod_map.mod_map_gold;
    auto gate2gold = &mod_map.mod_map_gate;
    
    for( auto mod : design->modules()){
        if (mod->name.begins_with(RTLIL::escape_id(conf.gold_prefix)) ||
            mod->name == conf.gold_mod->name ) {
            RTLIL::IdString original_name = get_orignal_mod_name(
                mod->name, conf.gold_mod->name, conf.gold_prefix);
                
            RTLIL::IdString gate_name = mod->name == conf.gold_mod->name ?
                conf.gate_mod->name :
                RTLIL::escape_id(conf.gate_prefix + strip_backslash(original_name));
            if (design->module(gate_name) != nullptr) {
                (*gold2gate)[mod->name] = gate_name;
                mod_map.mapped_mods_gold.insert(mod->name);
                mod_map.mapped_mods_gate.insert(gate_name);
            }
            else {
                mod_map.unmapped_mods_gold.insert(mod->name);
            }
        }
            
    }

    for( auto mod : design->modules()){
        if (mod->name.begins_with(RTLIL::escape_id(conf.gate_prefix)) ||
            mod->name == conf.gate_mod->name ) {
            RTLIL::IdString original_name = get_orignal_mod_name(
                mod->name, conf.gate_mod->name, conf.gate_prefix);

            RTLIL::IdString gold_name = mod->name == conf.gate_mod->name ?
                conf.gold_mod->name :
                RTLIL::escape_id(conf.gold_prefix + strip_backslash(original_name));
            if (design->module(gold_name) != nullptr) {
                (*gate2gold)[gold_name] = mod->name;
                mod_map.mapped_mods_gold.insert(gold_name);
                mod_map.mapped_mods_gate.insert(mod->name);
            }
            else {
                mod_map.unmapped_mods_gate.insert(mod->name);
            }
        }
            
    }

    log("Found %zu equivalence module pairs for LEC.\n", mod_map.mapped_mods_gold.size());
    for(auto const &mod_name : mod_map.mapped_mods_gold){
        log("  Gold module %s  <=>  Gate module %s\n", 
            log_id(mod_name), log_id((*gold2gate)[mod_name]));
    }
    
    for(const auto &mod_name : mod_map.unmapped_mods_gold){
        log_warning("Gold module %s has no matching gate module.\n", log_id(mod_name));
    }
    for(const auto &mod_name : mod_map.unmapped_mods_gate){
        log_warning("Gate module %s has no matching gold module.\n", log_id(mod_name));
    }

    auto t_end = std::chrono::steady_clock::now();
    timing_stat.hier_mod_map_ms += std::chrono::duration_cast<std::chrono::milliseconds>(t_end-t_start).count();

    return mod_map;
}

/*
static void remove_sub_mods(RTLIL::Design *design, const CheckConfig& confp)
{
    assert(design);
    pool<RTLIL::IdString> std_cells;
    if (confp.lib_design) {
        for (auto mod : confp.lib_design->modules())
        {
            std_cells.insert(mod->name);
        }
    }

    pool<RTLIL::Module*> modules;
    for (auto mod : design->modules())
    {
        if(std_cells.count(mod->name) != 0)
            continue;
        modules.insert(mod);
    }

    pool<RTLIL::IdString> submods;
    for (auto mod : modules)
    {
        for (auto cell : mod->cells())
        {
            RTLIL::Module *child = design->module(cell->type);
            if (!child)
                continue;
            if (std_cells.count(child->name) != 0)
                continue;
            if (child->get_blackbox_attribute())
                continue;
            submods.insert(child->name);
        }
    }

    // PO/PO of sub modules -> PO/PO of parent module
    // Remove sub modules
    for (auto mod : modules)
    {
        if (mod->get_blackbox_attribute())
            continue;

        std::vector<RTLIL::Cell*> cells = mod->cells();
        for (auto cell : cells)
        {
            RTLIL::Module *child = design->module(cell->type);
            if (!child)
                continue;
            if (std_cells.count(child->name) != 0)
                continue;
            if (child->get_blackbox_attribute())
                continue;

            std::vector<RTLIL::Wire*> child_ports;
            for (auto *w : child->wires())
                if (w->port_id > 0 && (w->port_input || w->port_output))
                    child_ports.push_back(w);

            std::sort(child_ports.begin(), child_ports.end(),
                      [](RTLIL::Wire *a, RTLIL::Wire *b){ return a->port_id < b->port_id; });

            for (auto *port : child_ports)
            {
                if (!cell->hasPort(port->name))
                    continue;

                RTLIL::SigSpec port_sig = cell->getPort(port->name);
                port_sig = resize_u0(port_sig, GetSize(port));

                if (port->port_input) {
                    std::string base = stringf("%s__%s__to_sub",
                        strip_backslash(cell->name).c_str(),
                        strip_backslash(port->name).c_str());
                    RTLIL::IdString wire_name = mod->uniquify(RTLIL::escape_id(base));
                    RTLIL::Wire *w = mod->addWire(wire_name, GetSize(port));
                    w->is_signed = port->is_signed;
                    w->upto = port->upto;
                    w->start_offset = port->start_offset;
                    w->port_output = true;
                    mod->connect(RTLIL::SigSpec(w), port_sig);
                }

                if (port->port_output) {
                    std::string base = stringf("%s__%s__from_sub",
                        strip_backslash(cell->name).c_str(),
                        strip_backslash(port->name).c_str());
                    RTLIL::IdString wire_name = mod->uniquify(RTLIL::escape_id(base));
                    RTLIL::Wire *w = mod->addWire(wire_name, GetSize(port));
                    w->is_signed = port->is_signed;
                    w->upto = port->upto;
                    w->start_offset = port->start_offset;
                    w->port_input = true;
                    mod->connect(port_sig, RTLIL::SigSpec(w));
                }
            }

            mod->remove(cell);
        }
        mod->fixup_ports();
    }

    for (auto mod : design->modules().to_vector())
    {
        if (std_cells.count(mod->name) != 0)
            continue;
        if (submods.count(mod->name) == 0)
            continue;
        if (mod->get_bool_attribute(ID::top))
            continue;
        if (mod == confp.gold_mod || mod == confp.gate_mod)
            continue;
        design->remove(mod);
    }
    
}
*/


static dict<RTLIL::IdString, NamedSig> build_named_sigs(RTLIL::Design* design, RTLIL::Module *m, dict<RTLIL::SigBit, RTLIL::Cell*>& ff_q_map)
{
    // have't use yet.
    (void) design;


    SigMap sigmap(m);
    dict<RTLIL::IdString, NamedSig> out;
    pool<RTLIL::Cell*> subckts;
    dict<RTLIL::SigBit, RTLIL::Cell*> ff_q_bits_map;

    for (auto cell : m->cells()) {
        // subckt
        if (!yosys_celltypes.cell_known(cell->type)){
            subckts.insert(cell);
            continue;
        }

        if (!cell->is_builtin_ff() && cell->type != ID($anyinit))
            continue;

        FfData ff(nullptr, cell);
        if (!ff.has_clk && !ff.has_gclk){
            assert(0);
            continue;
        }
            

        RTLIL::SigSpec q = ff.sig_q;
        q = sigmap(q);

        for (int i = 0; i < GetSize(q); i++) {
            RTLIL::SigBit qb = q[i];
            ff_q_bits_map[qb] = cell;
            ff_q_bits_map[sigmap(qb)] = cell;
            // log("Found FF Q bit: %s\n", log_signal(sigmap(qb)));
        }
    }

    dict<RTLIL::SigBit, RTLIL::Cell*> ff_conn_bits = ff_q_bits_map;
    bool changed = true;
    while (changed) {
        changed = false;
        for (auto &conn : m->connections()) {
            RTLIL::SigSpec lhs = sigmap(conn.first);
            RTLIL::SigSpec rhs = sigmap(conn.second);
            int width = GetSize(lhs);
            for (int i = 0; i < width; i++) {
                RTLIL::SigBit rb = rhs[i];
                RTLIL::SigBit lb = lhs[i];
                if (rb.is_wire() && ff_conn_bits.count(rb) && !ff_conn_bits.count(lb)) {
                    ff_conn_bits[lb] = ff_conn_bits[rb];
                    changed = true;
                }
            }
        }
    }


    for (auto *w : m->wires()) {
        // if (!w->port_input && !w->port_output) continue;
        // if(w->port_input) continue;
        RTLIL::SigSpec sig = sigmap(RTLIL::SigSpec(w));
        int width = GetSize(sig);
                
        MatchType type = MatchType::NONE;

        for (int i = 0; i < width; i++) {
            RTLIL::SigBit b = sig[i];
            RTLIL::SigBit bm = sigmap(b);

            RTLIL::IdString bit_name;
            if(width == 1){
                bit_name = w->name;
            }
            else{
                bit_name = RTLIL::IdString(stringf("%s[%d]", w->name, i));
            }
            
            bool is_ff = ff_conn_bits.count(bm);

            bool is_output = w->port_output;

            bool is_input = w->port_input;
            // log("Wire %s is input: %s, output: %s\n", bit_name, is_input ? "true" : "false", is_output ? "true" : "false");
            // log("Wire %s is FF Q: %s\n", bit_name, is_ff ? "true" : "false");
            // Can not process `inout`
            assert(!(is_output && is_input));

            type = is_ff && is_output ? MatchType::DFF_PO :
                is_ff ? MatchType::DFF :
                is_output ? MatchType::PO :
                MatchType::NONE;

            type = is_input ? MatchType::PI : type;

            NamedSig entry;
            entry.sig = bm;
            entry.type = type;
            entry.wire_name = w->name;
            entry.bit_index = i;
            out[bit_name] = entry;
            if(is_ff){
                ff_q_map[bm] = ff_conn_bits[bm];
            }
        }
    }

    for(auto subckt: subckts) { 
        for(auto conn: subckt->connections()){
            auto name = conn.first;
            auto sig = conn.second;
            if(!subckt->hasPort(name)){
                continue;
            }

            sig = sigmap(sig);
            
            int width = GetSize(sig);

            for (int i = 0; i < width; i++) {
                RTLIL::SigBit b = sig[i];
                RTLIL::SigBit bm = sigmap(b);

                RTLIL::IdString bit_name;
                if(width == 1){
                    bit_name = RTLIL::IdString(stringf("%s.%s", subckt->name, name));
                }
                else{
                    bit_name = RTLIL::IdString(stringf("%s.%s[%d]", subckt->name, name, i));
                }
                
                bool is_ff = ff_conn_bits.count(bm);

                NamedSig entry;
                entry.sig = bm;
                entry.type = MatchType::SUBCKT_PIPO;
                entry.wire_name = name;
                entry.bit_index = i;
                out[bit_name] = entry;
                if(is_ff){
                    ff_q_map[bm] = ff_conn_bits[bm];
                }
            }
        }
    }
    

    return out;

}


static void update_match_stats(MatchStats &stats, MatchType type)
{
    switch (type) {
    case MatchType::PI:
        stats.pi_cnt++;
        break;
    case MatchType::PO:
        stats.po_cnt++;
        break;
    case MatchType::DFF:
        stats.dff_cnt++;
        break;
    case MatchType::DFF_PO:
        stats.dff_po_cnt++;
        break;
    case MatchType::SUBCKT_PIPO:
        stats.subckt_cnt++;
        break;
    case MatchType::NONE:
        break;
    }
}

static string normalize_match_name(const RTLIL::IdString &id)
{
    string name = strip_backslash(id);
    for (char &ch : name)
        if (!std::isalnum(static_cast<unsigned char>(ch)))
            ch = '_';
    return name;
}

static string last_match_token(const RTLIL::IdString &id)
{
    string name = normalize_match_name(id);
    size_t pos = name.find_last_of('_');
    if (pos == string::npos)
        return name;
    return name.substr(pos + 1);
}

static int score_match_candidate(const NamedSig &gold_sig, const NamedSig &gate_sig)
{
    int score = 0;

    if (gold_sig.type != gate_sig.type)
        return score;
    if (gold_sig.bit_index == gate_sig.bit_index)
        score += 10;
    if (gold_sig.wire_name == gate_sig.wire_name)
        score += 100;
    if (normalize_match_name(gold_sig.wire_name) == normalize_match_name(gate_sig.wire_name))
        score += 40;
    if (last_match_token(gold_sig.wire_name) == last_match_token(gate_sig.wire_name))
        score += 20;

    return score;
}

static void write_match_suggestions(const string &path, const Json::array &suggestions)
{
    FILE *f = fopen(path.c_str(), "w");
    if (f == nullptr)
        log_error("Cannot open match suggestions file %s.\n", path.c_str());
    fprintf(f, "%s\n", Json(suggestions).dump().c_str());
    fclose(f);
}

static string match_suggestions_path(const string &match_jsonl)
{
    if (match_jsonl.empty())
        return "match_suggestions.json";

    size_t pos = match_jsonl.find_last_of('/');
    if (pos == string::npos)
        return "match_suggestions.json";

    return match_jsonl.substr(0, pos + 1) + "match_suggestions.json";
}

static MatchResult match_signals_module(RTLIL::Design *design, RTLIL::Module *gold_mod, RTLIL::Module *gate_mod,
                                        const CheckConfig &conf, bool emit_match_file, const string &snapshot_name)
{
    assert(design && gold_mod && gate_mod);

    MatchResult result;
    dict<RTLIL::SigBit, RTLIL::Cell*> gold_ff_q_map;
    dict<RTLIL::SigBit, RTLIL::Cell*> gate_ff_q_map;

    auto gold = build_named_sigs(design, gold_mod, gold_ff_q_map);
    auto gate = build_named_sigs(design, gate_mod, gate_ff_q_map);
    string pair_id = get_pair_id(gold_mod->name, gate_mod->name);
    string match_file = conf.tempdir_name + "/match_" + RTLIL::unescape_id(gold_mod->name) + "_" + RTLIL::unescape_id(gate_mod->name) + ".txt";
    result.stats.match_file = match_file;

    FILE *f = nullptr;
    if (emit_match_file)
        f = fopen(match_file.c_str(), "w");

    pool<RTLIL::IdString> matched_gold;
    pool<RTLIL::IdString> matched_gate;

    for (auto &it : gold) {
        auto name = it.first;
        if (!gate.count(name))
            continue;

        const auto &gentry = it.second;
        const auto &kentry = gate.at(name);
        RTLIL::SigBit gsig = gentry.sig;
        RTLIL::SigBit ksig = kentry.sig;
        

        // log("Matched signal %s: gold %s gate %s, Type %s\n",
        //     name.c_str(), log_signal(gsig), log_signal(ksig), get_match_type_str(gentry.type));

        // Don't dump NONE type
        // ! Warning: NONE type gentry may has the same signal name with DFF/other type's.
        // This will lead to overwriting in name mapping in ABC. If didn't solve this in 
        // ABC. Please DO NOT dump NONE type entries!
        if(gentry.type != MatchType::NONE && f != nullptr){
            fprintf(f, "Matched signal %s: gold %s gate %s, Type %s\n",
                name.c_str(), log_signal(gsig).c_str(), log_signal(ksig).c_str(), 
                get_match_type_str(gentry.type).c_str());
        }
        matched_gold.insert(name);
        matched_gate.insert(name);
        result.stats.exact_total++;
        update_match_stats(result.stats, gentry.type);
        result.cut_points.push_back(CutPoint{name, gsig, ksig, gentry.type,
                gold_ff_q_map.count(gsig) ? gold_ff_q_map[gsig] : nullptr,
                gate_ff_q_map.count(ksig) ? gate_ff_q_map[ksig] : nullptr,
                gentry.wire_name, gentry.bit_index,
                kentry.wire_name, kentry.bit_index});
    }

    if (f != nullptr)
        fclose(f);

    result.stats.unmatched_gold = GetSize(gold) - GetSize(matched_gold);
    result.stats.unmatched_gate = GetSize(gate) - GetSize(matched_gate);

    if (conf.dump_cfg.dump_match) {
        Json::array suggestions;
        for (auto &it : gold) {
            auto gold_name = it.first;
            const auto &gentry = it.second;
            if (gentry.type == MatchType::NONE)
                continue;

            if (matched_gold.count(gold_name)) {
                append_jsonl(conf.dump_cfg.match_jsonl, Json::object {
                    {"pair_id", pair_id},
                    {"snapshot", snapshot_name},
                    {"gold_mod", strip_backslash(gold_mod->name)},
                    {"gate_mod", strip_backslash(gate_mod->name)},
                    {"gold_name", strip_backslash(gold_name)},
                    {"gate_name", strip_backslash(gold_name)},
                    {"type", get_match_type_str(gentry.type)},
                    {"gold_wire_name", strip_backslash(gentry.wire_name)},
                    {"gate_wire_name", strip_backslash(gate.at(gold_name).wire_name)},
                    {"gold_bit_index", gentry.bit_index},
                    {"gate_bit_index", gate.at(gold_name).bit_index},
                    {"score", 1000},
                    {"label", gentry.type == MatchType::NONE ? 0 : 1}
                });
                continue;
            }

            std::vector<std::pair<int, RTLIL::IdString>> candidates;
            for (auto &gt : gate) {
                auto gate_name = gt.first;
                const auto &kentry = gt.second;
                if (matched_gate.count(gate_name))
                    continue;
                if (kentry.type == MatchType::NONE)
                    continue;
                if (gentry.type != kentry.type)
                    continue;
                if (gentry.bit_index != kentry.bit_index)
                    continue;
                int score = score_match_candidate(gentry, kentry);
                candidates.push_back({score, gate_name});
                append_jsonl(conf.dump_cfg.match_jsonl, Json::object {
                    {"pair_id", pair_id},
                    {"snapshot", snapshot_name},
                    {"gold_mod", strip_backslash(gold_mod->name)},
                    {"gate_mod", strip_backslash(gate_mod->name)},
                    {"gold_name", strip_backslash(gold_name)},
                    {"gate_name", strip_backslash(gate_name)},
                    {"type", get_match_type_str(gentry.type)},
                    {"gold_wire_name", strip_backslash(gentry.wire_name)},
                    {"gate_wire_name", strip_backslash(kentry.wire_name)},
                    {"gold_bit_index", gentry.bit_index},
                    {"gate_bit_index", kentry.bit_index},
                    {"score", score},
                    {"label", 0}
                });
            }

            std::sort(candidates.begin(), candidates.end(),
                [](const std::pair<int, RTLIL::IdString> &lhs, const std::pair<int, RTLIL::IdString> &rhs) {
                    if (lhs.first != rhs.first)
                        return lhs.first > rhs.first;
                    return lhs.second.str() < rhs.second.str();
                });

            if (!candidates.empty() && candidates.front().first > 0) {
                auto top_name = candidates.front().second;
                const auto &top_entry = gate.at(top_name);
                int score_margin = candidates.front().first;
                if (GetSize(candidates) > 1)
                    score_margin = candidates.front().first - candidates[1].first;

                Json suggestion = Json::object {
                    {"pair_id", pair_id},
                    {"snapshot", snapshot_name},
                    {"gold_mod", strip_backslash(gold_mod->name)},
                    {"gate_mod", strip_backslash(gate_mod->name)},
                    {"gold_name", strip_backslash(gold_name)},
                    {"gold_wire_name", strip_backslash(gentry.wire_name)},
                    {"gold_bit_index", gentry.bit_index},
                    {"type", get_match_type_str(gentry.type)},
                    {"suggested_gate_name", strip_backslash(top_name)},
                    {"suggested_gate_wire_name", strip_backslash(top_entry.wire_name)},
                    {"suggested_gate_bit_index", top_entry.bit_index},
                    {"score", candidates.front().first},
                    {"score_margin", score_margin}
                };
                suggestions.push_back(suggestion);
                if (conf.telemetry != nullptr && snapshot_name == "pre_async")
                    conf.telemetry->match_suggestions.push_back(suggestion);
            }
        }

        if (!suggestions.empty()) {
            string suggestions_file = conf.tempdir_name + "/match_suggestions_" +
                snapshot_name + "_" + sanitize_filename(pair_id) + ".json";
            write_match_suggestions(suggestions_file, suggestions);
        }
    }

    return result;
}

static dict<RTLIL::Module*, std::vector<CutPoint>> match_signals(RTLIL::Design *design, const CheckConfig& conf,
                                                                 ModMap& mod_map, bool emit_match_file,
                                                                 const string &snapshot_name)
{
    assert(design);
    auto gold2gate = mod_map.mod_map_gold;

    dict<RTLIL::Module*, std::vector<CutPoint>> gold2cutpoints;

    for(auto const &[gold, gate] : gold2gate){
        auto gold_mod = design->module(gold);
        auto gate_mod = design->module(gate);
        MatchResult match_result =
            match_signals_module(design, gold_mod, gate_mod, conf, emit_match_file, snapshot_name);
        gold2cutpoints[gold_mod] = match_result.cut_points;
        if (emit_match_file && conf.telemetry != nullptr)
            conf.telemetry->pair_match_stats[get_pair_id(gold, gate)] = match_result.stats;
    }
    return gold2cutpoints;
}

static void cutpoints_to_pi_po(RTLIL::Module *mod,
                               const std::vector<CutPoint> &cutpoints,
                               bool use_gold)
{
    SigMap sigmap(mod);
    pool<RTLIL::Cell*> cut_cells;
    pool<RTLIL::SigBit> cut_q_bits;
    std::vector<RTLIL::SigSig> pending_q_conns;

    auto make_port_wire = [&](const RTLIL::IdString &base, const char *suffix, int width,
                              bool is_input, bool is_output) -> RTLIL::Wire* {
        std::string base_name = strip_backslash(base);
        RTLIL::IdString name = mod->uniquify(RTLIL::escape_id(base_name + suffix));
        RTLIL::Wire *w = mod->addWire(name, width);
        w->port_input = is_input;
        w->port_output = is_output;
        return w;
    };

    auto find_ff_by_qbit = [&](RTLIL::SigBit qbit) -> RTLIL::Cell* {
        if (!qbit.is_wire())
            return nullptr;
        for (auto cell : mod->cells()) {
            if (!cell->is_builtin_ff() && cell->type != ID($anyinit))
                continue;
            RTLIL::SigSpec qsig = sigmap(cell->getPort(ID::Q));
            for (int i = 0; i < GetSize(qsig); i++) {
                if (qsig[i] == qbit)
                    return cell;
            }
        }
        return nullptr;
    };

    for (const auto &cp : cutpoints)
    {
        if (cp.type != MatchType::DFF && cp.type != MatchType::DFF_PO)
            continue;

        RTLIL::Cell *ff = use_gold ? cp.gold_ff_cell : cp.gate_ff_cell;
        if (ff != nullptr)
            ff = mod->cell(ff->name);

        RTLIL::IdString qwire_name = use_gold ? cp.gold_wire_name : cp.gate_wire_name;
        int qbit_index = use_gold ? cp.gold_bit_index : cp.gate_bit_index;
        if (qwire_name.empty()) {
            log_warning("Missing cutpoint wire name for %s in module %s.\n",
                log_id(cp.name), log_id(mod->name));
            continue;
        }
        RTLIL::Wire *qwire = mod->wire(qwire_name);
        if (qwire == nullptr) {
            log_warning("Missing cutpoint wire %s in module %s.\n",
                log_id(cp.name), log_id(mod->name));
            continue;
        }
        if (qbit_index < 0 || qbit_index >= GetSize(qwire)) {
            log_warning("Cutpoint index out of range for %s in module %s.\n",
                log_id(cp.name), log_id(mod->name));
            continue;
        }
        RTLIL::SigBit qbit_port(qwire, qbit_index);
        RTLIL::SigBit qbit_mapped = sigmap(qbit_port);

        if (ff == nullptr)
            ff = find_ff_by_qbit(qbit_mapped);

        if (ff == nullptr) {
            log_warning("Missing FF cell for cutpoint %s in module %s.\n",
                log_id(cp.name), log_id(mod->name));
            continue;
        }

        if (!qbit_port.is_wire()) {
            log_warning("Cutpoint %s has non-wire Q bit in module %s.\n",
                log_id(cp.name), log_id(mod->name));
            continue;
        }

        bool is_dff_po = (cp.type == MatchType::DFF_PO);
        cut_q_bits.insert(qbit_mapped);
        cut_cells.insert(ff);

        RTLIL::SigBit pi_bit = qbit_port;
        if (!is_dff_po) {
            if (qbit_port.wire->port_output) {
                RTLIL::Wire *pi_wire = make_port_wire(cp.name, "_pi", 1, true, false);
                pi_bit = RTLIL::SigBit(pi_wire);
                pending_q_conns.emplace_back(RTLIL::SigSpec(qbit_port), RTLIL::SigSpec(pi_wire));
            } else {
                qbit_port.wire->port_input = true;
            }
            if (qbit_mapped != pi_bit)
                pending_q_conns.emplace_back(RTLIL::SigSpec(qbit_mapped), RTLIL::SigSpec(pi_bit));
        }

        RTLIL::SigSpec qsig = sigmap(ff->getPort(ID::Q));
        RTLIL::SigSpec dsig = sigmap(ff->getPort(ID::D));

        int qidx = -1;
        for (int i = 0; i < GetSize(qsig); i++) {
            if (qsig[i] == qbit_mapped) {
                qidx = i;
                break;
            }
        }
        if (qidx < 0) {
            if (GetSize(qsig) > 1) {
                if (qbit_index < 0 || qbit_index >= GetSize(qsig)) {
                    log_warning("Cannot map Q bit for cutpoint %s in module %s.\n",
                        log_id(cp.name), log_id(mod->name));
                    continue;
                }
                qidx = qbit_index;
            } else {
                qidx = 0;
            }
        }

        if (qidx < 0 || qidx >= GetSize(dsig)) {
            log_warning("Cutpoint %s has invalid D index in module %s.\n",
                log_id(cp.name), log_id(mod->name));
            continue;
        }
        RTLIL::SigBit dbit = dsig[qidx];
        if (is_dff_po) {
            pending_q_conns.emplace_back(RTLIL::SigSpec(qbit_mapped), RTLIL::SigSpec(dbit));
            if (qbit_port != qbit_mapped)
                pending_q_conns.emplace_back(RTLIL::SigSpec(qbit_port), RTLIL::SigSpec(qbit_mapped));
        } else {
            RTLIL::Wire *w_out = make_port_wire(cp.name, "_po", 1, false, true);
            mod->connect(RTLIL::SigSpec(w_out), RTLIL::SigSpec(dbit));
        }
    }

    if (!cut_q_bits.empty()) {
        std::vector<RTLIL::SigSig> new_conns;
        new_conns.reserve(mod->connections().size());
        for (auto &ss : mod->connections()) {
            RTLIL::SigSpec lhs, rhs;
            RTLIL::SigSpec lhs_sig = ss.first;
            RTLIL::SigSpec rhs_sig = ss.second;
            int width = GetSize(lhs_sig);
            for (int i = 0; i < width; i++) {
                RTLIL::SigBit lb = sigmap(lhs_sig[i]);
                if (cut_q_bits.count(lb))
                    continue;
                lhs.append(lhs_sig[i]);
                rhs.append(rhs_sig[i]);
            }
            if (GetSize(lhs))
                new_conns.emplace_back(lhs, rhs);
        }
        mod->connections_.swap(new_conns);
    }

    for (auto &conn : pending_q_conns)
        mod->connect(conn.first, conn.second);

    for (auto *ff : cut_cells)
        mod->remove(ff);

    mod->fixup_ports();
}


static void submod_to_pi_po(RTLIL::Design *design, RTLIL::Module *mod)
{
    assert(design);
    assert(mod);

    SigMap sigmap(mod);
    pool<RTLIL::SigBit> cut_bits;
    std::vector<RTLIL::SigSig> pending_conns;
    std::vector<RTLIL::Cell*> remove_cells;

    for (auto *cell : mod->cells()) {

        if(yosys_celltypes.cell_known(cell->type))
            continue;

        RTLIL::Module *child = design->module(cell->type);
        if (!child) {
            log_error("Missing module %s for cell %s in module %s.\n",
                    log_id(cell->type), log_id(cell->name), log_id(mod->name));
            continue;
        }

        

        std::vector<RTLIL::Wire*> child_ports;
        for (auto *w : child->wires())
            if (w->port_id > 0 && (w->port_input || w->port_output))
                child_ports.push_back(w);

        std::sort(child_ports.begin(), child_ports.end(),
                  [](RTLIL::Wire *a, RTLIL::Wire *b){ return a->port_id < b->port_id; });

        for (auto *port : child_ports) {
            if (!cell->hasPort(port->name))
                continue;

            RTLIL::SigSpec port_sig = cell->getPort(port->name);
            port_sig = resize_u0(port_sig, GetSize(port));
            RTLIL::SigSpec mapped_sig = sigmap(port_sig);

            std::string base = stringf("%s_%s",
                strip_backslash(cell->name).c_str(),
                strip_backslash(port->name).c_str());

            auto add_port_wire = [&](const char *suffix, bool is_input, bool is_output) -> RTLIL::Wire* {
                RTLIL::IdString name = mod->uniquify(RTLIL::escape_id(base + suffix));
                RTLIL::Wire *w = mod->addWire(name, GetSize(port));
                w->is_signed = port->is_signed;
                w->upto = port->upto;
                w->start_offset = port->start_offset;
                w->port_input = is_input;
                w->port_output = is_output;
                return w;
            };

            if (port->port_output) {
                RTLIL::Wire *w_pi = add_port_wire("_pi", true, false);
                pending_conns.emplace_back(mapped_sig, RTLIL::SigSpec(w_pi));

                int width = GetSize(port_sig);
                for (int i = 0; i < width; i++) {
                    RTLIL::SigBit pb = port_sig[i];
                    RTLIL::SigBit mb = mapped_sig[i];
                    if (mb.is_wire())
                        cut_bits.insert(mb);
                    if (pb.is_wire() && mb.is_wire() && pb != mb)
                        pending_conns.emplace_back(RTLIL::SigSpec(pb), RTLIL::SigSpec(mb));
                }
            }
        }

        remove_cells.push_back(cell);
    }

    if (!cut_bits.empty()) {
        std::vector<RTLIL::SigSig> new_conns;
        new_conns.reserve(mod->connections().size());
        for (auto &ss : mod->connections()) {
            RTLIL::SigSpec lhs, rhs;
            RTLIL::SigSpec lhs_sig = ss.first;
            RTLIL::SigSpec rhs_sig = ss.second;
            int width = GetSize(lhs_sig);
            for (int i = 0; i < width; i++) {
                RTLIL::SigBit lb = sigmap(lhs_sig[i]);
                if (cut_bits.count(lb))
                    continue;
                lhs.append(lhs_sig[i]);
                rhs.append(rhs_sig[i]);
            }
            if (GetSize(lhs))
                new_conns.emplace_back(lhs, rhs);
        }
        mod->connections_.swap(new_conns);
    }

    for (auto &conn : pending_conns)
        mod->connect(conn.first, conn.second);

    for (auto *cell : remove_cells)
        mod->remove(cell);

    mod->fixup_ports();
}

static std::vector<RTLIL::Module*> topo_sort_modules(RTLIL::Design *design, const RTLIL::IdString& root);

// The function still has bug
[[maybe_unused]]static void remove_subclk(RTLIL::Design* design, CheckConfig& conf) {

    // haven't use now.
    (void) design;

    auto gold_topo = topo_sort_modules(design, conf.gold_mod->name);
    auto gate_topo = topo_sort_modules(design, conf.gate_mod->name);

    for(auto m: gold_topo){
        submod_to_pi_po(design, m);
    }
    for(auto m: gate_topo) {
        submod_to_pi_po(design, m);
    }
}

// RetVal: <gold_submodule, gate_submodule> , pointer in design_check
static std::pair<RTLIL::Module*, RTLIL::Module*> partition_module(RTLIL::Design *design, RTLIL::Design *design_check, 
    RTLIL::Module *gold_mod, RTLIL::Module *gate_mod,  //pointer in design
    const std::vector<CutPoint>& cutpoints, const CheckConfig& conf)
{
    // Maybe implement further.
    assert(0);
    (void) design;
    (void) design_check;
    (void) conf;

    RTLIL::Module *gold_clone = gold_mod->clone();
    RTLIL::Module *gate_clone = gate_mod->clone();

    // convert_ff_to_fine(gold_clone);
    // convert_ff_to_fine(gate_clone);


    cutpoints_to_pi_po(gold_clone, cutpoints, true);
    cutpoints_to_pi_po(gate_clone, cutpoints, false);

    // blackbox_to_pi_po(design, gold_clone);
    // blackbox_to_pi_po(design, gate_clone);

    return {gold_clone, gate_clone};
}

// Maybe implement further.
[[maybe_unused]]static void partition_design_for_check(RTLIL::Design *design, RTLIL::Design *design_check, 
    const CheckConfig& conf, ModMap& mod_map,
    const dict<RTLIL::Module*, std::vector<CutPoint>>& gold2cutpoints)
{
    for(const auto &[gold_mod, cutpoints] : gold2cutpoints){
        RTLIL::IdString gold_mod_name = gold_mod->name;
        RTLIL::IdString gate_mod_name = mod_map.mod_map_gold.at(gold_mod_name);
        RTLIL::Module *gate_mod = design->module(gate_mod_name);

        auto module_partition = 
            partition_module(design, design_check, gold_mod, gate_mod, cutpoints, conf);
        design_check->add(module_partition.first);
        design_check->add(module_partition.second);
    }
}

static int exectue_and_check(const std::string & cmd, bool & correct,
                      const std::string & target_output,
                      const string &tempdir_name = "",
                      const string &tag = "command",
                      CommandResult *capture = nullptr) {
    correct = false;
    CommandResult result = exec_capture(cmd, tempdir_name, tag);
    correct = result.output.find(target_output) != std::string::npos;
    result.result_code = correct ? 1 : 0;
    if (capture != nullptr)
        *capture = result;
    return result.exit_status;
}


static int exectue_and_check(const std::string & cmd, int & result,
                    const std::vector<std::pair<std::string, int>>& target_result,
                    const string &tempdir_name = "",
                    const string &tag = "command",
                    CommandResult *capture = nullptr) {
    CommandResult exec_result = exec_capture(cmd, tempdir_name, tag);
    result = 0;

    for(auto it: target_result) {
        if (exec_result.output.find(it.first) != std::string::npos) {
            result = it.second;
            break;
        }
    }

    exec_result.result_code = result;
    if (capture != nullptr)
        *capture = exec_result;
    return exec_result.exit_status;
}

static bool valid_internal_multiplier_cell(RTLIL::Cell *cell)
{
    if(cell->type != ID($mul))
        return false;

    RTLIL::SigSpec origA = cell->getPort(ID::A);
    RTLIL::SigSpec origB = cell->getPort(ID::B);
    RTLIL::SigSpec origY = cell->getPort(ID::Y);
    dict<RTLIL::IdString, RTLIL::Const> orig_params = cell->parameters;

    if(orig_params[ID::A_SIGNED].as_bool() != orig_params[ID::B_SIGNED].as_bool()){
        return false;
    }

    if(origA.size()!=origB.size()){
        return false;
    }
    return true;
}


static bool is_multiplier_cell(RTLIL::Design *design, RTLIL::Cell *cell)
{
    if (valid_internal_multiplier_cell(cell))
        return true;

    if (cell->get_bool_attribute(ID(multiplier)))
        return true;

    RTLIL::Module *sub = design->module(cell->type);
    if (sub && sub->get_bool_attribute(ID(multiplier)))
        return true;

    return false;
}

static RTLIL::SigSpec resize_u0(RTLIL::SigSpec src, int width)
{
    if (src.size() < width) {
        while (src.size() < width)
            src.append(RTLIL::SigBit(RTLIL::State::S0));
        return src;
    }
    if (src.size() > width)
        return src.extract(0, width);
    return src;
}

static RTLIL::IdString unique_cell_name(RTLIL::Module *m, const std::string &base)
{
    for (int i = 0;; i++) {
        std::string cand = (i == 0) ? base : stringf("%s$%d", base.c_str(), i);
        RTLIL::IdString id = RTLIL::escape_id(cand);
        if (m->cell(id) == nullptr) return id;
    }
}


// Select two "operand" signals: $mul uses A/B; submodules take the first two input ports
static void pick_operands(RTLIL::Design *design, RTLIL::Cell *cell,
                          RTLIL::SigSpec &op1, RTLIL::SigSpec &op2)
{
    op1 = RTLIL::SigSpec();
    op2 = RTLIL::SigSpec();

    if (cell->type == ID($mul)) {
        op1 = cell->getPort(ID::A);
        op2 = cell->getPort(ID::B);
        return;
    }

    if (auto *sub = design->module(cell->type)) {
        std::vector<RTLIL::Wire*> ins;
        for (auto *w : sub->wires())
            if (w->port_id > 0 && w->port_input)
                ins.push_back(w);
        std::sort(ins.begin(), ins.end(),
                  [](RTLIL::Wire *a, RTLIL::Wire *b){ return a->port_id < b->port_id; });

        if (ins.size() >= 1 && cell->hasPort(ins[0]->name)) op1 = cell->getPort(ins[0]->name);
        if (ins.size() >= 2 && cell->hasPort(ins[1]->name)) op2 = cell->getPort(ins[1]->name);
    }

    if (!op1.size() && cell->hasPort(ID::A)) op1 = cell->getPort(ID::A);
    if (!op2.size() && cell->hasPort(ID::B)) op2 = cell->getPort(ID::B);

    if (!op1.size() && !op2.size()) {
        op1 = RTLIL::SigSpec(RTLIL::State::S0);
        op2 = RTLIL::SigSpec(RTLIL::State::S0);
    } else if (!op2.size()) {
        op2 = op1;
    } else if (!op1.size()) {
        op1 = op2;
    }
}

static void replace_mul_with_commutative_stub(RTLIL::Design *design, RTLIL::Module *mod, RTLIL::Cell *cell)
{
    RTLIL::SigSpec a, b;
    pick_operands(design, cell, a, b);

    auto add_xor_driver = [&](RTLIL::SigSpec out_sig, const std::string &tag) {
        int w = out_sig.size();

        RTLIL::Cell *x = mod->addCell(unique_cell_name(mod, "__mul_comm_xor_" + tag), ID($xor));


        x->parameters[ID::A_SIGNED] = RTLIL::Const(0);
        x->parameters[ID::B_SIGNED] = RTLIL::Const(0);
        x->parameters[ID::A_WIDTH]  = RTLIL::Const(w);
        x->parameters[ID::B_WIDTH]  = RTLIL::Const(w);
        x->parameters[ID::Y_WIDTH]  = RTLIL::Const(w);

        x->setPort(ID::A, resize_u0(a, w));
        x->setPort(ID::B, resize_u0(b, w));
        x->setPort(ID::Y, out_sig);

    };

    if (cell->type == ID($mul)) {
        if (cell->hasPort(ID::Y))
            add_xor_driver(cell->getPort(ID::Y), "Y");
    } else {
        
        if (auto *sub = design->module(cell->type)) {
            std::vector<RTLIL::Wire*> outs;
            for (auto *w : sub->wires())
                if (w->port_id > 0 && w->port_output)
                    outs.push_back(w);
            std::sort(outs.begin(), outs.end(),
                      [](RTLIL::Wire *a, RTLIL::Wire *b){ return a->port_id < b->port_id; });

            for (auto *w : outs) {
                if (!cell->hasPort(w->name)) continue;
                add_xor_driver(cell->getPort(w->name), strip_backslash(w->name));
            }
        } else {
            // fallback
            if (cell->hasPort(ID::Y))
                add_xor_driver(cell->getPort(ID::Y), "Y");
        }
    }

    mod->remove(cell);
}


// Must ensure the cell is a multiplier.
static std::pair<int,bool> get_multiplier_width_sign(RTLIL::Design *design, RTLIL::Cell *cell) 
{   
    bool sign;
    int width;
    RTLIL::SigSpec op1, op2;
    pick_operands(design, cell, op1, op2);
    assert(op1.size() == op2.size());
    
    width = op1.size();

    if(cell->type == ID($mul)) {
        sign = cell->parameters[ID::A_SIGNED].as_bool();
    }
    else {
        auto mod = design->module(cell->type);
        assert(mod);
        sign = mod->get_bool_attribute(ID(is_signed));
    }
    
    return {width, sign};
}


static void extract_multi(RTLIL::Design *design, RTLIL::Module *mod)
{
    std::vector<RTLIL::Cell*> cells = mod->cells();
    for (auto *cell : cells) {
        if (!is_multiplier_cell(design, cell))
            continue;
        replace_mul_with_commutative_stub(design, mod, cell);
    }
    mod->fixup_ports();
}

int exec_cmd(const string &cmd, const string &tempdir_name = "", const string &tag = "command", CommandResult *capture = nullptr){
    CommandResult result = exec_capture(cmd, tempdir_name, tag);
    if (capture != nullptr)
        *capture = result;
    return result.exit_status;
}


// static void v2aig(const string& v_file, const string& aig_file, const string& mod_name, const string& lib_file){
//     auto yosys_exe_file = proc_self_dirname() + "yosys";
//     // string cmd = stringf("%s -p 'read_verilog %s; hierarchy -top %s; synth -flatten; aigmap; write_aiger %s'", 
//     //                     yosys_exe_file, v_file, mod_name, aig_file);
    
//     string cmd; 
//     cmd = stringf("%s -p '", yosys_exe_file);
//     if(!lib_file.empty()){
//         cmd += stringf("read_verilog %s; ", lib_file);
//     }
//     cmd += stringf("read_verilog %s; hierarchy -top %s; prep -flatten; proc; techmap; aigmap; write_aiger %s'", 
//                         v_file, mod_name, aig_file);

//     // system(cmd.c_str());

//     exec_cmd(cmd);
// }

// static void v2aig(const string& v_file, const string& aig_file, const string& mod_name){
//     v2aig(v_file, aig_file, mod_name, "");
// }

// static void v2blif(const vector<string>& v_files, const string& blif_file, const string& mod_name){
//     string read_verilog_cmd = "";
//     for(const auto& v_file : v_files){
//         read_verilog_cmd += stringf("read_verilog %s; ", v_file);
//     }
//     auto yosys_exe_file = proc_self_dirname() + "yosys";
//     string cmd = stringf("%s -p '%s hierarchy -top %s; synth -flatten; dffunmap; write_blif -blackbox -top %s %s'", 
//                         yosys_exe_file, read_verilog_cmd, mod_name, mod_name, blif_file);
//     // system(cmd.c_str());
//     exec_cmd(cmd);
// }


static string dump_aig(RTLIL::Design* design, const string &dir_name, RTLIL::Module *mod,
                        const string& lib_file){
    string aig_file = dir_name + "/" 
        + strip_backslash(mod->name)
        + ".aig";
    
    string mod_name = strip_backslash(mod->name);
    log("Dumping module %s to AIG file %s.\n", mod->name.str(), aig_file);
    
    auto log_files_backup = log_files;
    auto log_streams_backup = log_streams;

    // log_files.clear(); // TODO: Maybe it's not a good ieda... 
	// log_streams.clear(); // TODO: We can not see any log...
    RTLIL::Design *design_copy = clone_design_for_passes(design);
    if(!lib_file.empty())
        run_pass(stringf("read_verilog -overwrite %s", lib_file), design_copy);
    run_pass("hierarchy -top " + mod->name.str(), design_copy);
    run_pass(stringf("flatten %s", mod->name.str()), design_copy);
    run_pass(stringf("opt"), design_copy);
    // run_pass(stringf("proc"), design_copy);
    run_pass("setundef -undriven -zero", design_copy);
    run_pass(stringf("opt_expr"), design_copy);
    run_pass(stringf("techmap"), design_copy);
    run_pass(stringf("opt_expr"), design_copy);
    run_pass(stringf("aigmap"), design_copy);
    run_pass(stringf("write_aiger %s", aig_file), design_copy);
    
    delete design_copy;
    log_files = log_files_backup;
    log_streams = log_streams_backup;
    return aig_file;
}

static string dump_aig(RTLIL::Design* design, const string &dir_name, RTLIL::Module *mod){
    return dump_aig(design, dir_name, mod, "");
}

static string dump_blif(RTLIL::Design* design, const string &dir_name, RTLIL::Module *mod, const string& lib_file){
    string blif_file = dir_name + "/" 
        + strip_backslash(mod->name)
        + ".blif";
    string mod_name = strip_backslash(mod->name);
    log("Dumping module %s to BLIF file %s.\n", mod->name.str(), blif_file);
    
    auto log_files_backup = log_files;
    auto log_streams_backup = log_streams;

    // log_files.clear(); // TODO: Maybe it's not a good ieda... 
    // log_streams.clear(); // TODO: We can not see any log...
    RTLIL::Design *design_copy = clone_design_for_passes(design);
    if(!lib_file.empty())
        run_pass(stringf("read_verilog -overwrite -noblackbox %s", lib_file), design_copy);
    run_pass(stringf("hierarchy -top %s", mod->name.str()), design_copy);
    run_pass(stringf("flatten"), design_copy);
    run_pass(stringf("proc"), design_copy);
    run_pass(stringf("opt"), design_copy);
    run_pass(stringf("memory_map"), design_copy);
    run_pass(stringf("techmap"), design_copy);
    run_pass(stringf("dffunmap"), design_copy);
    run_pass(stringf("write_blif -impltf -blackbox -top %s %s", mod_name, blif_file), design_copy);
    delete design_copy;
    log_files = log_files_backup;
    log_streams = log_streams_backup;
    return blif_file;
}

static int materialize_blackbox_input_consts(RTLIL::Design *design, RTLIL::Module *mod)
{
    if (design == nullptr || mod == nullptr)
        return 0;

    int inserted = 0;

    for (auto *cell : mod->cells()) {
        RTLIL::Module *submod = design->module(cell->type);
        if (submod == nullptr || !submod->get_bool_attribute(ID(blackbox)))
            continue;

        std::vector<std::pair<RTLIL::IdString, RTLIL::SigSpec>> updates;

        for (auto &conn : cell->connections()) {
            RTLIL::IdString port = conn.first;
            RTLIL::Wire *port_wire = submod->wire(port);
            if (port_wire == nullptr || !port_wire->port_input || port_wire->port_output)
                continue;

            RTLIL::SigSpec sig = conn.second;
            bool changed = false;

            for (int i = 0; i < GetSize(sig); i++) {
                RTLIL::SigBit bit = sig[i];
                if (bit.wire != nullptr)
                    continue;

                std::string cell_name = RTLIL::unescape_id(cell->name);
                std::string port_name = RTLIL::unescape_id(port);
                std::string wire_name = stringf("$bbconst$%s$%s$%d",
                    cell_name.c_str(), port_name.c_str(), i);

                RTLIL::IdString wire_id = RTLIL::escape_id(wire_name);
                RTLIL::Wire *w = mod->wire(wire_id);
                if (w == nullptr)
                    w = mod->addWire(wire_id, 1);

                mod->connect(RTLIL::SigSpec(w), RTLIL::SigSpec(bit));
                sig[i] = RTLIL::SigBit(w, 0);
                changed = true;
                inserted++;
            }

            if (changed)
                updates.emplace_back(port, sig);
        }

        for (const auto &update : updates)
            cell->setPort(update.first, update.second);
    }

    if (inserted > 0)
        log("Inserted %d constant nets on blackbox inputs in module %s.\n",
            inserted, log_id(mod->name));

    return inserted;
}

static string dump_blif_module(RTLIL::Design* design, const string &dir_name, RTLIL::Module *mod, const string& lib_file,
                               int *inserted_bbconsts = nullptr){

    auto t_start = std::chrono::steady_clock::now();

    string blif_file = dir_name + "/" 
        + strip_backslash(mod->name)
        + ".blif";
    string mod_name = strip_backslash(mod->name);
    log("Dumping module %s to BLIF file %s.\n", mod->name.str(), blif_file);
    
    auto log_files_backup = log_files;
    auto log_streams_backup = log_streams;

    // log_files.clear(); // TODO: Maybe it's not a good ieda... 
    // log_streams.clear(); // TODO: We can not see any log...
    RTLIL::Design *design_copy = clone_design_for_passes(design);
    // (void)lib_file;
    // if(!lib_file.empty())
    //     run_pass(stringf("read_verilog -overwrite %s", lib_file), design_copy);
    
    // run_pass(stringf("flatten"), design_copy);
    // run_pass(stringf("hierarchy -top %s", mod->name.str()), design_copy);
    // run_pass(stringf("proc"), design_copy);
    // run_pass(stringf("opt"), design_copy);
    // run_pass(stringf("memory_map"), design_copy);

    for(auto mod_: design_copy->modules()){
        if(mod_->name != mod->name){
            mod_->set_bool_attribute(ID(blackbox), true);
            // log("Current Module: %s, Set Module `%s` to blackbox.\n", mod->name.str(), mod_->name.str());
        }
    }
    RTLIL::Module *target_mod = design_copy->module(mod->name);
    if (target_mod != nullptr) {
        int inserted = materialize_blackbox_input_consts(design_copy, target_mod);
        if (inserted_bbconsts != nullptr)
            *inserted_bbconsts = inserted;
    }
    (void)lib_file;
    // if(!lib_file.empty())
    //     run_pass(stringf("read_verilog -overwrite %s", lib_file), design_copy);
    // run_pass(stringf("hierarchy -top %s", mod->name.str()), design_copy);
    // run_pass(stringf("flatten"), design_copy);
    // run_pass(stringf("proc"), design_copy);
    // run_pass(stringf("techmap"), design_copy);
    // run_pass(stringf("dffunmap"), design_copy);
    // run_pass(stringf("write_blif -impltf -blackbox -top %s %s", mod_name, blif_file), design_copy);
    run_pass(stringf(
        "write_blif -blackbox -top %s -false + __const0 -true + __const1 -undef + __constx %s",
        mod_name, blif_file),
        design_copy);

    log_files = log_files_backup;
    log_streams = log_streams_backup;

    auto t_end = std::chrono::steady_clock::now();
    timing_stat.dump_blif_ms += std::chrono::duration_cast<std::chrono::milliseconds>(t_end-t_start).count();

    return blif_file;
}


static string dump_smt2(RTLIL::Design* design, const string &dir_name, std::pair<RTLIL::Module*, RTLIL::Module*> mod_pair,
                        const string& lib_file){
    auto gold_mod = mod_pair.first;
    auto gate_mod = mod_pair.second;

    string mod_name = strip_backslash(gold_mod->name) + "_vs_" + strip_backslash(gate_mod->name);
    string smt2_file = dir_name + "/" + mod_name + ".smt2";
    
    log("Dumping module pair %s vs %s to SMT2 file %s.\n", 
        gold_mod->name.str(), gate_mod->name.str(), smt2_file);
    
    auto log_files_backup = log_files;
    auto log_streams_backup = log_streams;

    // log_files.clear(); // TODO: Maybe it's not a good ieda... 
    // log_streams.clear(); // TODO: We can not see any log...

    RTLIL::Design *design_copy = clone_design_for_passes(design);
    if(!lib_file.empty())
        run_pass(stringf("read_verilog -overwrite %s", lib_file), design_copy);
    run_pass(stringf("flatten %s", gold_mod->name.str()), design_copy);
    run_pass(stringf("flatten %s", gate_mod->name.str()), design_copy);
    // run_pass(stringf("proc %s", gold_mod->name.str()), design_copy);
    // run_pass(stringf("proc %s", gate_mod->name.str()), design_copy);
    run_pass(stringf("miter -equiv -make_assert -flatten %s %s %s",
                    gold_mod->name.str(), gate_mod->name.str(), mod_name), design_copy);
    run_pass(stringf("hierarchy -top %s", mod_name), design_copy);
    // run_pass(stringf("techmap"), design_copy);
    run_pass(stringf("prep -top %s", mod_name), design_copy);
    run_pass(stringf("write_smt2 -wires %s", smt2_file), design_copy);
    delete design_copy;
    log_files = log_files_backup;
    log_streams = log_streams_backup;
    return smt2_file;
}


static bool check_multi(RTLIL::Design* design, RTLIL::Module* mod, const string& tempdir_name, const string& lib_file,
    const MlDumpConfig &dump_cfg, const string &pair_id, const string &gold_mod_name,
    const string &gate_mod_name, bool amulet = true){
    log_assert(mod->get_bool_attribute(ID(multiplier)));
    bool is_signed = mod->get_bool_attribute(ID(is_signed));    
    auto aig_file = dump_aig(design, tempdir_name, mod, lib_file);

    amulet = true; // Uses Amulet now.
    if(amulet){
        log("Using amulet to verify the multiplier.\n");
        auto miter_tmp_file = tempdir_name + "/"
            + strip_backslash(mod->name)
            + ".miter.cnf";
        auto rewritten_tmp_file = tempdir_name + "/"
            + strip_backslash(mod->name)
            + ".rewritten.aig";

        auto amulet_sub_cmd = "amulet -substitute " + aig_file + " " + miter_tmp_file  + " " + rewritten_tmp_file + (is_signed? " -signed" : "");
        std::cout << "Running amulet: " << amulet_sub_cmd << std::endl;
        CommandResult substitute_capture;
        exec_cmd(amulet_sub_cmd, tempdir_name, "amulet-substitute-" + sanitize_filename(strip_backslash(mod->name)), &substitute_capture);
        auto amulet_veri_cmd = "amulet -verify " + rewritten_tmp_file + (is_signed ? " -signed" : "");
        std::cout << "Running amulet: " << amulet_veri_cmd << std::endl;
        CommandResult verify_capture;
        auto ret = exec_cmd(amulet_veri_cmd, tempdir_name, "amulet-verify-" + sanitize_filename(strip_backslash(mod->name)), &verify_capture);
        if(ret != 1){
            log("Amulet Verify failed.\n");
            verify_capture.output += "Amulet Verify failed.\n";
            verify_capture.result_code = ret;
            emit_failure_packet(dump_cfg, pair_id, "AMULET", "amulet_verify", gold_mod_name, gate_mod_name, verify_capture);
            return false;
        }
        return true;
    } else {
        bool correct = false; 
        log("Using dynphaseorderopt to verify the multiplier.\n");
        auto cmd = "dynphaseorderopt " + aig_file;
        CommandResult capture;
        exectue_and_check(cmd, correct, "CIRCUIT IS CORRECT", tempdir_name,
                          "dynphaseorderopt-" + sanitize_filename(strip_backslash(mod->name)),
                          &capture);
        if (!correct) {
            capture.result_code = capture.exit_status;
            emit_failure_packet(dump_cfg, pair_id, "AMULET", "dynphaseorderopt", gold_mod_name, gate_mod_name, capture);
        }
        return correct;
    }
}

static std::vector<std::pair<RTLIL::IdString, bool>> check_extract_multi(RTLIL::Design* design, MultiMap& mm,
                                                                         const string& tempdir_name,
                                                                         const MlDumpConfig &dump_cfg,
                                                                         pool<RTLIL::IdString> *touched_mods = nullptr){

    auto t_start = std::chrono::steady_clock::now();
    
    pool<Module*> mod_to_check;
    dict<RTLIL::Module*, string> mod_to_pair_id;
    dict<RTLIL::Module*, string> mod_to_gold_name;
    dict<RTLIL::Module*, string> mod_to_gate_name;
    
    pool<Module*> mod_to_extract;
    pool<Module*> mod_to_blackbox;

    std::vector<std::pair<RTLIL::IdString, bool>> results;
    
    for(auto &e : mm) {
        if(e.is_multi_mod){
            auto goldm = design->module(e.gold_mod);
            auto gatem = design->module(e.gate_mod);
            if (touched_mods != nullptr) {
                touched_mods->insert(e.gold_mod);
                touched_mods->insert(e.gate_mod);
            }
            mod_to_check.insert(goldm);
            mod_to_check.insert(gatem);
            mod_to_pair_id[goldm] = get_pair_id(e.gold_mod, e.gate_mod);
            mod_to_pair_id[gatem] = get_pair_id(e.gold_mod, e.gate_mod);
            mod_to_gold_name[goldm] = strip_backslash(e.gold_mod);
            mod_to_gold_name[gatem] = strip_backslash(e.gold_mod);
            mod_to_gate_name[goldm] = strip_backslash(e.gate_mod);
            mod_to_gate_name[gatem] = strip_backslash(e.gate_mod);
            mod_to_blackbox.insert(goldm);
            mod_to_blackbox.insert(gatem);
        }
        else { 
            auto goldm = design->module(e.gold_mod);
            auto gatem = design->module(e.gate_mod);
            if (touched_mods != nullptr) {
                touched_mods->insert(e.gold_mod);
                touched_mods->insert(e.gate_mod);
            }
            assert(goldm); assert(gatem);
            auto goldc = goldm->cell(e.gold_cell);
            auto gatec = gatem->cell(e.gate_cell);
            assert(goldc); assert(gatec);
            auto gold_mul = design->module(goldc->type);
            auto gate_mul = design->module(gatec->type);
            if(goldc->type.isPublic() || goldc->type.begins_with("$paramod")) {
                mod_to_check.insert(gold_mul);
                mod_to_pair_id[gold_mul] = get_pair_id(e.gold_mod, e.gate_mod);
                mod_to_gold_name[gold_mul] = strip_backslash(e.gold_mod);
                mod_to_gate_name[gold_mul] = strip_backslash(e.gate_mod);
            }
            if(gatec->type.isPublic() || gatec->type.begins_with("$paramod")) {
                mod_to_check.insert(gate_mul);
                mod_to_pair_id[gate_mul] = get_pair_id(e.gold_mod, e.gate_mod);
                mod_to_gold_name[gate_mul] = strip_backslash(e.gold_mod);
                mod_to_gate_name[gate_mul] = strip_backslash(e.gate_mod);
            }
            mod_to_extract.insert(goldm);
            mod_to_extract.insert(gatem);
        }
    }

    for(auto mod: mod_to_check){
        bool result = check_multi(design, mod, tempdir_name, "", dump_cfg, mod_to_pair_id[mod],
                                  mod_to_gold_name[mod], mod_to_gate_name[mod]);
        results.push_back({mod->name,result});
    }

    for(auto mod: mod_to_extract) {
        extract_multi(design, mod);
    }

    for(auto mod: mod_to_blackbox) {
        mod->set_bool_attribute(ID(blackbox), true);
    }
    auto t_end = std::chrono::steady_clock::now();
    timing_stat.check_mul_ms += std::chrono::duration_cast<std::chrono::milliseconds>(t_end-t_start).count();
    return results;
}


static MultiMap get_multi_map(RTLIL::Design* design, const ModMap &mod_map) {
    
    auto t_start = std::chrono::steady_clock::now();
    
    auto mmap = mod_map.mod_map_gold;

    struct Multi {
        int width;
        bool sign;
        RTLIL::IdString type;
        Cell* cell;
        bool operator<(const Multi& other) const {
            if(sign != other.sign) return sign < other.sign; 
            return width < other.width;
        }

        bool param_equal(const Multi& other) const {
            return (width == other.width) && (sign == other.sign);
        }
    };

    vector<Multi> gold_multi;
    vector<Multi> gate_multi;

    MultiMap map;
    

    for(const auto& [gold_mod_name, gate_mod_name]: mmap) {
        auto gold_mod = design->module(gold_mod_name);
        auto gate_mod = design->module(gate_mod_name);
        assert(gold_mod);
        assert(gate_mod);

        // Module map
        bool gold_is_mulmod = gold_mod->get_bool_attribute(ID(multiplier));
        bool gate_is_mulmod = gate_mod->get_bool_attribute(ID(multiplier));

        if (gold_is_mulmod || gate_is_mulmod) {
            if (gold_is_mulmod && gate_is_mulmod) {
                MultiMapEntry e;
                e.gold_mod = gold_mod_name;
                e.gate_mod = gate_mod_name;
                e.gold_cell = "";
                e.gate_cell = "";
                e.is_multi_mod = true;
                map.push_back(e);
            } else {
                log_warning("Can not map multiplier %s and %s: One of them is not multiplier!\n",
                            log_id(gold_mod_name), log_id(gate_mod_name));
            }
            continue;
        }



        // Cell map;
        gold_multi.clear();
        gate_multi.clear();    
        for(auto cell: gold_mod->cells()) { 
            if(is_multiplier_cell(design,cell)) {
                auto w_s = get_multiplier_width_sign(design, cell);
                gold_multi.push_back({w_s.first,w_s.second,cell->type,cell});
            }
        }
        for(auto cell: gate_mod->cells()){
            if(is_multiplier_cell(design,cell)) {
                auto w_s = get_multiplier_width_sign(design, cell);
                gate_multi.push_back({w_s.first,w_s.second,cell->type,cell});
            }
        }

        if(gold_multi.size() != gate_multi.size()) { 
            log_warning("Module %s and %s have different number of multipliers! Skip...\n", 
                gold_mod->name, gate_mod->name);
            continue;
        }
        if(gold_multi.empty() || gate_multi.empty()) {
            continue;
        }
        std::sort(gold_multi.begin(),gold_multi.end());
        std::sort(gate_multi.begin(),gate_multi.end());
        bool map_failed = false;
        MultiMap map_tmp;
        for(size_t i=0; i<gold_multi.size(); i++) {
            auto &mul_gold = gold_multi[i];
            auto &mul_gate = gate_multi[i];
            if(!mul_gold.param_equal(mul_gate)){
                log_warning("Cell %s in Module %s has different parameter with Cell %s in Module %s! Skip this two module!\n",
                    mul_gold.cell->name, gold_mod_name, mul_gate.cell->name, gate_mod_name);
                map_failed = true;
                break;
            }
            MultiMapEntry entry;
            entry.gold_mod  = gold_mod_name;
            entry.gate_mod  = gate_mod_name;
            entry.gold_cell = mul_gold.cell->name;
            entry.gate_cell = mul_gate.cell->name;
            entry.is_multi_mod = false;
            map_tmp.push_back(entry);
        }
        if(!map_failed) {
            map.insert(map.end(), map_tmp.begin(), map_tmp.end());
        }
        
    }

    auto t_end = std::chrono::steady_clock::now();
    timing_stat.mul_map_ms += std::chrono::duration_cast<std::chrono::milliseconds>(t_end-t_start).count();


    print_MultiMap(map);
    return map;
}

static bool abc_check(const CheckConfig &conf, bool use_blif=false, string check_cmd="cec"){
    auto gold_mod = conf.gold_mod;
    auto gate_mod = conf.gate_mod;


    string gold_file;
    
    string gate_file;

    if(use_blif)
    {
        gold_file = dump_blif(conf.design, conf.tempdir_name, gold_mod, conf.lib_file);
        gate_file = dump_blif(conf.design, conf.tempdir_name, gate_mod, conf.lib_file);
    }
    else
    {
        log_error("AIG based check is not supported currently.\n");
        gold_file = dump_aig(conf.design, conf.tempdir_name, gold_mod);
        gate_file = dump_aig(conf.design, conf.tempdir_name, gate_mod);
    }
    
    string abc_cmd = stringf("%s %s %s", check_cmd, gold_file, gate_file);
    string cmd = stringf("%s -c '%s'", conf.abc_exe_file, abc_cmd);
    bool correct = false;

    log("Executing ABC command: '%s'\n", abc_cmd);
    bool abc_ret = exectue_and_check(cmd, correct, "Networks are equivalent");
    if (abc_ret != 0) {
        log_error("Error executing ABC command: %s\n", cmd);
    }
    
    return correct;
}


[[maybe_unused]]static bool abc_cec_full(const CheckConfig &conf){
    // TODO: We use desc here!!!!
    //return abc_check(conf, true, "cec");
    bool has_dff = false;
    bool has_submodule = false;
    for(auto cells: conf.gold_mod->cells()){
        if(cells->type == ID($ff) || cells->type == ID($dff) || cells->type == ID($dffe)|| 
           cells->type == ID($_DFF_P_) || cells->type == ID($_DFF_N_) || cells->type == ID($_DFFE_PN) ||
           cells->type == ID($_DFFE_PP)){
            has_dff = true;
        } 
        auto submod = conf.design->module(cells->type);
        if (submod != nullptr && !(submod->attributes.count(ID::blackbox))) {
            has_submodule = true;
        }
        if(has_dff && has_submodule){
            break;
        }
    }
    if (has_dff || has_submodule) {
	    return abc_check(conf, true, "dsec");
    } else {
	    return abc_check(conf, true, "cec");
    }
}



static bool abc_cec_module(const CheckConfig &conf){
    auto count_module_dffs = [](RTLIL::Module *mod, bool gate_side) {
        int count = 0;
        for (auto cell : mod->cells()) {
            if (cell->type == ID($ff) || cell->type == ID($dff) || cell->type == ID($dffe) ||
                cell->type == ID($_DFF_P_) || cell->type == ID($_DFF_N_) || cell->type == ID($_DFFE_PN) ||
                cell->type == ID($_DFFE_PP) || (gate_side && cell->type.contains("DFF")))
                count++;
        }
        return count;
    };

    auto collect_pair_record = [&](int inserted_bbconsts) {
        PairRecord record;
        record.pair_id = get_pair_id(conf.gold_mod->name, conf.gate_mod->name);
        record.gold_mod = strip_backslash(conf.gold_mod->name);
        record.gate_mod = strip_backslash(conf.gate_mod->name);
        record.gold_dff_cnt = count_module_dffs(conf.gold_mod, false);
        record.gate_dff_cnt = count_module_dffs(conf.gate_mod, true);
        record.const_blackbox_inputs_inserted = inserted_bbconsts;

        for (auto cell : conf.gold_mod->cells()) {
            RTLIL::Module *submod = conf.design->module(cell->type);
            if (submod != nullptr && !submod->get_bool_attribute(ID(blackbox))) {
                record.has_submodule = true;
                break;
            }
        }

        if (conf.telemetry != nullptr) {
            record.retimed = conf.telemetry->retimed_mods.count(conf.gold_mod->name) ||
                             conf.telemetry->retimed_mods.count(conf.gate_mod->name);
            record.touched_by_multiplier = conf.telemetry->multiplier_mods.count(conf.gold_mod->name) ||
                                           conf.telemetry->multiplier_mods.count(conf.gate_mod->name);
        }

        return record;
    };

    auto heuristic_abc_plan = [&](const PairRecord&, const MatchStats&) {
        return std::vector<ActionKind> {
            ActionKind::CEC_MAP,
            ActionKind::CEC_NOMAP,
            ActionKind::DSEC_MAP,
            ActionKind::DSEC_NOMAP
        };
    };

    auto learned_abc_plan = [&](const PairRecord &pair_record, const MatchStats &match_stats) {
        if (conf.sched_model == nullptr || !conf.sched_model->loaded)
            return heuristic_abc_plan(pair_record, match_stats);

        std::vector<std::pair<double, ActionKind>> ranked_actions;
        for (auto action : heuristic_abc_plan(pair_record, match_stats))
            ranked_actions.push_back({predict_sched_cost(*conf.sched_model, get_action_name(action), pair_record, match_stats), action});

        std::sort(ranked_actions.begin(), ranked_actions.end(),
            [](const std::pair<double, ActionKind> &lhs, const std::pair<double, ActionKind> &rhs) {
                if (lhs.first != rhs.first)
                    return lhs.first < rhs.first;
                return get_action_name(lhs.second) < get_action_name(rhs.second);
            });

        std::vector<ActionKind> plan;
        for (auto &entry : ranked_actions)
            plan.push_back(entry.second);
        return plan;
    };

    auto run_abc_action = [&](ActionKind action, const string &match_file, const string &gold_file,
                              const string &gate_file, RunRecord &run_record) {
        string abc_cmd;
        switch (action) {
        case ActionKind::CEC_MAP:
            abc_cmd = stringf("cec -M %s %s %s", match_file, gate_file, gold_file);
            break;
        case ActionKind::CEC_NOMAP:
            abc_cmd = stringf("cec -n %s %s", gate_file, gold_file);
            break;
        case ActionKind::DSEC_MAP:
            abc_cmd = stringf("dsec -M %s %s %s", match_file, gate_file, gold_file);
            break;
        case ActionKind::DSEC_NOMAP:
            abc_cmd = stringf("dsec -n %s %s", gate_file, gold_file);
            break;
        }

        vector<std::pair<std::string, int>> out2result = {
            {"Networks are equivalent", 1},
            {"Networks are NOT EQUIVALENT", 2},
            {"Miter computation has failed", 3}
        };
        string cmd = stringf("%s -c '%s'", conf.abc_exe_file, abc_cmd);
        CommandResult command_result;
        int result_code = 0;
        string action_name = get_action_name(action);
        log("Executing ABC command: '%s'\n", abc_cmd.c_str());
        int exit_status = exectue_and_check(cmd, result_code, out2result, conf.tempdir_name,
                                            "abc-" + sanitize_filename(get_pair_id(conf.gold_mod->name, conf.gate_mod->name)) +
                                            "-" + action_name,
                                            &command_result);
        if (exit_status != 0 || result_code == 0) {
            command_result.result_code = result_code;
            emit_failure_packet(conf, "ABC", action_name, command_result, {});
            log_error("Error executing ABC command: %s\n", cmd.c_str());
        }

        run_record.pair_id = get_pair_id(conf.gold_mod->name, conf.gate_mod->name);
        run_record.action = action_name;
        run_record.exit_status = command_result.exit_status;
        run_record.result_code = result_code;
        run_record.runtime_ms = command_result.runtime_ms;
        run_record.log_file = command_result.log_file;
        command_result.result_code = result_code;
        return command_result;
    };

    auto run_abc_plan = [&](const PairRecord &pair_record, const std::vector<ActionKind> &plan,
                            const string &match_file, const string &gold_file, const string &gate_file,
                            std::vector<RunRecord> *trace, CommandResult *last_result, string *last_action) {
        bool has_dff = pair_record.gold_dff_cnt != 0 || pair_record.gate_dff_cnt != 0;
        bool exhaustive = conf.dump_cfg.dump_sched;
        bool strict_order = conf.sched_model != nullptr && conf.sched_model->loaded;
        bool ran_dsec_map = false;
        int prev_result = 0;
        bool solved = false;
        CommandResult last_command;
        string last_action_name;

        for (auto action : plan) {
            if (!has_dff && (action == ActionKind::DSEC_MAP || action == ActionKind::DSEC_NOMAP))
                continue;

            if (!exhaustive && !strict_order) {
                if (action == ActionKind::CEC_NOMAP && prev_result != 3)
                    continue;
                if (action == ActionKind::DSEC_MAP && !(prev_result == 2 || prev_result == 3))
                    continue;
                if (action == ActionKind::DSEC_NOMAP && (!ran_dsec_map || prev_result != 3))
                    continue;
            }

            RunRecord run_record;
            CommandResult command_result = run_abc_action(action, match_file, gold_file, gate_file, run_record);
            if (trace != nullptr)
                trace->push_back(run_record);

            prev_result = run_record.result_code;
            last_command = command_result;
            last_action_name = run_record.action;
            if (action == ActionKind::DSEC_MAP)
                ran_dsec_map = true;

            if (run_record.result_code == 1) {
                solved = true;
                if (!exhaustive)
                    break;
            }
        }

        if (last_result != nullptr)
            *last_result = last_command;
        if (last_action != nullptr)
            *last_action = last_action_name;
        return solved;
    };

    auto dump_sched_sample = [&](const PairRecord &pair_record, const MatchStats &match_stats,
                                 const std::vector<RunRecord> &trace) {
        if (!conf.dump_cfg.dump_sched || conf.dump_cfg.sched_jsonl.empty())
            return;

        Json::array action_json;
        string best_action;
        double best_runtime = 0;
        bool best_set = false;
        for (auto &run_record : trace) {
            action_json.push_back(run_record_to_json(run_record));
            if (run_record.result_code == 1 && (!best_set || run_record.runtime_ms < best_runtime)) {
                best_runtime = run_record.runtime_ms;
                best_action = run_record.action;
                best_set = true;
            }
        }

        append_jsonl(conf.dump_cfg.sched_jsonl, Json::object {
            {"pair", pair_record_to_json(pair_record)},
            {"match", match_stats_to_json(match_stats)},
            {"actions", action_json},
            {"label_best_action", best_action}
        });
    };

    using clock = std::chrono::steady_clock;
    auto t0 = clock::now();

    int gold_inserted = 0;
    int gate_inserted = 0;
    string gold_file = dump_blif_module(conf.design, conf.tempdir_name, conf.gold_mod, conf.lib_file, &gold_inserted);
    string gate_file = dump_blif_module(conf.design, conf.tempdir_name, conf.gate_mod, conf.lib_file, &gate_inserted);
    string match_file = conf.tempdir_name + "/match_" + RTLIL::unescape_id(conf.gold_mod->name) + "_" +
        RTLIL::unescape_id(conf.gate_mod->name) + ".txt";

    PairRecord pair_record = collect_pair_record(gold_inserted + gate_inserted);
    MatchStats match_stats = get_match_stats(conf);
    log("Gold DFF count: %d, Gate DFF count: %d\n", pair_record.gold_dff_cnt, pair_record.gate_dff_cnt);

    std::vector<ActionKind> plan = learned_abc_plan(pair_record, match_stats);
    std::vector<RunRecord> trace;
    CommandResult last_result;
    string last_action;

    log("Running ABC.\n");
    fflush(stdout);

    bool solved = run_abc_plan(pair_record, plan, match_file, gold_file, gate_file, &trace, &last_result, &last_action);
    dump_sched_sample(pair_record, match_stats, trace);
    if (!solved && !last_action.empty())
        emit_failure_packet(conf, "ABC", last_action, last_result, trace);

    auto t1 = clock::now();
    timing_stat.abc_cec_ms += std::chrono::duration_cast<std::chrono::milliseconds>(t1-t0).count();

    return solved;
}
    

static std::vector<std::pair<RTLIL::IdString, bool>> abc_cec(const CheckConfig &conf){
    // find equivalence-checking pair
    auto design = conf.design;

    vector<std::pair<RTLIL::IdString, RTLIL::IdString>> equiv_mods;

    for( auto mod : design->modules()){
        if(mod->get_blackbox_attribute())
            continue;
        if (mod->name.begins_with(RTLIL::escape_id(conf.gold_prefix)) ||
            mod->name == conf.gold_mod->name ) {
            RTLIL::IdString original_name = get_orignal_mod_name(
                mod->name, conf.gold_mod->name, conf.gold_prefix);
            RTLIL::IdString gate_name = mod->name == conf.gold_mod->name ?
                conf.gate_mod->name :
                RTLIL::escape_id(conf.gate_prefix + strip_backslash(original_name));
            if (design->module(gate_name) != nullptr) {
                equiv_mods.push_back({mod->name, gate_name});
            }
        }
            
    }

    log("Found %zu equivalence module pairs for CEC.\n", equiv_mods.size());
    for(const auto &mod_pair : equiv_mods){
        log("  gold=%s  gate=%s\n", 
            log_id(mod_pair.first), log_id(mod_pair.second));
    }

    CheckConfig conf_ = {
        .nocleanup = conf.nocleanup,
        .abc_exe_file = conf.abc_exe_file,
        .tempdir_name = conf.tempdir_name,
        .design = nullptr,
        .gold_mod = nullptr,
        .gate_mod = nullptr,
        .gold_prefix = conf.gold_prefix,
        .gate_prefix = conf.gate_prefix,
        .lib_file = conf.lib_file,
        .sched_model_file = conf.sched_model_file,
        .seq_check_cfg = conf.seq_check_cfg,
        .dump_cfg = conf.dump_cfg,
        .sched_model = conf.sched_model,
        .telemetry = conf.telemetry,
        .lib_design = conf.lib_design
    };

    std::vector<std::pair<RTLIL::IdString, bool>> results;

    for(auto mod_pair : equiv_mods){
        auto gold_name = mod_pair.first;
        auto gate_name = mod_pair.second;

        auto design_ = clone_design_for_passes(design); 

        auto gold_m = design_->module(gold_name);
        auto gate_m = design_->module(gate_name);
        
        // Have checked the existence before, should not append
        assert(gold_m && gate_m);

        conf_.gold_mod = gold_m;
        conf_.gate_mod = gate_m;
        conf_.design = design_;

        bool cec_result = abc_cec_module(conf_);

        delete design_;
        results.push_back({get_orignal_mod_name(gold_name, gate_name, conf.gold_prefix), cec_result});

        // if(!cec_result){
        //     log("\nGUIDE_CHECK failed for module pair: gold=%s vs gate=%s\n", 
        //         log_id(gold_name), log_id(gate_name));
        // }
        // else 
        // {
        //     log("\nGUIDE_CHECK passed for module pair: gold=%s vs gate=%s\n", 
        //         log_id(gold_name), log_id(gate_name));
        // }


    }
    return results;
    //return true;    
}
// static bool abc_dsec(const CheckConfig &conf){
//     return abc_check(conf, true, "dsec");
// }

static bool bmcinduct_check(const CheckConfig &conf){
    std::string gold_name = strip_backslash(conf.gold_mod->name);
    std::string gate_name = strip_backslash(conf.gate_mod->name);

    auto smt2_file = dump_smt2(conf.design, conf.tempdir_name, {conf.gold_mod, conf.gate_mod}, "");

    string cmd = proc_self_dirname() + proc_program_prefix() + "yosys-smtbmc ";

    if(conf.seq_check_cfg.no_init){
        cmd += "-noinit ";
    }
    cmd += "-m " + gold_name + "_vs_" + gate_name + " ";
    
    if(conf.seq_check_cfg.weak_mode){
        cmd += "-i -t ";
        cmd += std::to_string(conf.seq_check_cfg.step_skip) + ":" + std::to_string(conf.seq_check_cfg.k_induct) + " ";

        CommandResult weak_capture;
        int ret = exec_cmd(cmd + smt2_file, conf.tempdir_name,
                           "smtbmc-weak-" + sanitize_filename(get_pair_id(conf.gold_mod->name, conf.gate_mod->name)),
                           &weak_capture);
        if(ret != 0){
            log("BMC-Induct failed in weak mode.\n");
            weak_capture.output += "BMC-Induct failed in weak mode.\n";
            emit_failure_packet(conf, "BMC", "weak", weak_capture, {});
            return false;
        }
        return true;
    }

    // BMC + K-Induct
    string cmd_bmc = cmd;

    cmd_bmc += " -t " + std::to_string(conf.seq_check_cfg.step_skip) + ":" + std::to_string(conf.seq_check_cfg.k_induct) + " ";
    CommandResult bmc_capture;
    int ret = exec_cmd(cmd_bmc + smt2_file, conf.tempdir_name,
                       "smtbmc-bmc-" + sanitize_filename(get_pair_id(conf.gold_mod->name, conf.gate_mod->name)),
                       &bmc_capture);
    if(ret != 0){
        log("BMC-Induct failed in BMC phase.\n");
        bmc_capture.output += "BMC-Induct failed in BMC phase.\n";
        emit_failure_packet(conf, "BMC", "bmc", bmc_capture, {});
        return false;
    }
    string cmd_induct = cmd;
    cmd_induct += " -i -t "  + std::to_string(conf.seq_check_cfg.k_induct) + " "; 
    CommandResult induct_capture;
    ret = exec_cmd(cmd_induct + smt2_file, conf.tempdir_name,
                   "smtbmc-induct-" + sanitize_filename(get_pair_id(conf.gold_mod->name, conf.gate_mod->name)),
                   &induct_capture);
    if(ret != 0){
        log("BMC-Induct failed in Induct phase.\n");
        induct_capture.output += "BMC-Induct failed in Induct phase.\n";
        emit_failure_packet(conf, "BMC", "induct", induct_capture, {});
        return false;
    }
    return true;
}

static std::vector<RTLIL::Module*> topo_sort_modules(RTLIL::Design *design)
{
    TopoSort<RTLIL::Module*> ts;
    ts.analyze_loops = true;

    for (auto m : design->modules()) {
        ts.node(m);
    }

    for (auto parent : design->modules()) {
        for (auto cell : parent->cells()) {
            RTLIL::Module *child = design->module(cell->type);
            if (!child) continue;
            ts.edge(child, parent);
        }
    }

    bool ok = ts.sort();
    if (!ok) {
        for (const auto &loop : ts.loops) {
            std::string s;
            for (auto id : loop) s += " " + id->name.str();
            log_warning("Module instantiation loop:%s\n", s.c_str());
        }
    }

    return ts.sorted;
}

static std::vector<RTLIL::Module*> topo_sort_modules(RTLIL::Design *design, const RTLIL::IdString& root){
    TopoSort<RTLIL::Module*,RTLIL::IdString::compare_ptr_by_name<RTLIL::Module>> ts;
    ts.analyze_loops = true;


    // get related modules
    std::set<RTLIL::Module*,RTLIL::IdString::compare_ptr_by_name<RTLIL::Module>> related_mods;
    std::function<void(RTLIL::Module*)> dfs = [&](RTLIL::Module* mod){
        if(related_mods.count(mod)){
            return;
        }
        related_mods.insert(mod);
        for(auto cell : mod->cells()){
            RTLIL::Module *child = design->module(cell->type);
            if (!child) continue;
            dfs(child);
        }
    };
    RTLIL::Module* root_mod = design->module(root);
    if(!root_mod){
        log_error("Root Module %s not found in the design.\n", log_id(root));
    }
    dfs(root_mod);

    log("Related modules count: %zu\n", related_mods.size());
    for(auto mod : related_mods){
        log("  Related module: %s\n", log_id(mod->name));
    }

    for (auto m : related_mods) {
        ts.node(m);
    }

    for (auto parent : related_mods) {
        for (auto cell : parent->cells()) {
            RTLIL::Module *child = design->module(cell->type);
            if (!child) continue;
            if(related_mods.count(child) ==0){
                continue;
            }
            ts.edge(child, parent);
        }
    }

    bool ok = ts.sort();
    if (!ok) {
        for (const auto &loop : ts.loops) {
            std::string s;
            for (auto id : loop) s += " " + id->name.str();
            log_warning("Module instantiation loop:%s\n", s.c_str());
        }
    }

    return ts.sorted;
}

// maybe we should reconstruct  the check_retime.
Results check_retime(const CheckConfig &conf,
                  std::set<std::pair<RTLIL::IdString, RTLIL::IdString>>&retimed_mods)
{
    Results results;
    auto sorted_mods = topo_sort_modules(conf.design);
    std::vector<RTLIL::Module*> gate_mods;
    std::map<RTLIL::IdString, RTLIL::Module*> gold_mods;

    for(auto mod : sorted_mods)
    {
        if((mod->name.begins_with(RTLIL::escape_id(conf.gate_prefix)) || mod->name == conf.gate_mod->name )
            && mod->get_bool_attribute(ID(retime)))
        {
            gate_mods.push_back(mod);
        }
        else 
        if((mod->name.begins_with(RTLIL::escape_id(conf.gold_prefix)) || mod->name == conf.gold_mod->name ))
        {
            gold_mods[mod->name] = mod;
        }
    }

    for(auto gate_m : gate_mods)
    {
        string original_name = gate_m ->name == conf.gate_mod->name ? 
            RTLIL::unescape_id(conf.gold_mod->name) :
            RTLIL::unescape_id(gate_m->name).substr(conf.gate_prefix.size()
        );
        
        auto gold_m_it = gold_mods.find(
            original_name == conf.gold_mod->name.str() ?
            conf.gold_mod->name :
            RTLIL::escape_id(conf.gold_prefix + original_name)
        );
        if(gold_m_it == gold_mods.end())
        {
            
            for(auto gm_pair : gold_mods)
            {
                log("Available gold module: %s\n", log_id(gm_pair.first));
            }
            for(auto gm : gate_mods)
            {
                log("Available gate module: %s\n", log_id(gm->name));
            }
            log_error("Can't find the corresponding gold module for gate module %s.\n", log_id(gate_m->name));
            continue;
        }
        auto gold_m = gold_m_it->second;

        retimed_mods.insert({gold_m->name, gate_m->name});
    }


    for (auto mod_pair : retimed_mods)
    {
        auto gold_name = mod_pair.first;
        auto gate_name = mod_pair.second;
        auto gold_m = conf.design->module(gold_name);
        auto gate_m = conf.design->module(gate_name);
        if (!gold_m || !gate_m) {
            log_warning("Skipping retime check for missing module pair: gold=%s vs gate=%s\n",
                log_id(gold_name), log_id(gate_name));
            continue;
        }
        log("Checking retimed module pair: gold=%s vs gate=%s\n", log_id(gold_name), log_id(gate_name));
        CheckConfig conf_ = {
            .nocleanup = conf.nocleanup,
            .abc_exe_file = conf.abc_exe_file,
            .tempdir_name = conf.tempdir_name,
            .design = conf.design,
            .gold_mod = gold_m,
            .gate_mod = gate_m,
            .gold_prefix = conf.gold_prefix,
            .gate_prefix = conf.gate_prefix,
            .lib_file = conf.lib_file,
            .sched_model_file = conf.sched_model_file,
            .seq_check_cfg = conf.seq_check_cfg,
            .dump_cfg = conf.dump_cfg,
            .sched_model = conf.sched_model,
            .telemetry = conf.telemetry,
            .lib_design = conf.lib_design
        };

        //bool dsec_result = abc_dsec(conf_);
        bool result = bmcinduct_check(conf_);

        
        results.push_back({get_orignal_mod_name(gold_m->name, conf.gold_mod->name, conf.gold_prefix),
                        result});
        
    }

    return results;
}


Results check_extract_retime(const ModMap& mmap, const CheckConfig &conf)
{

    std::set<std::pair<RTLIL::IdString, RTLIL::IdString>> retimed_mods;
    auto t_start = std::chrono::steady_clock::now();
    
        
    // TODO: Maybe we should reconstruct the check_retime.
    // In check_retime(), the function construct the module-mapping relations
    // however, we already have this relationship.
    // It is caused by historical reason.
    (void)mmap;
    Results results = check_retime(conf, retimed_mods);
    
    std::set<RTLIL::IdString> blackbox_mods;


    for (auto mod_pair : retimed_mods)
    {
        for (auto mod_name : {mod_pair.first, mod_pair.second})
        {
            if (conf.telemetry != nullptr)
                conf.telemetry->retimed_mods.insert(mod_name);
            auto mod = conf.design->module(mod_name);
            if (!mod) {
                log_warning("Skipping missing module %s when marking as (* blackbox *).\n", log_id(mod_name));
                continue;
            }
            log("Marking module %s as (* blackbox *)\n", log_id(mod_name));
            mod->set_bool_attribute(ID(blackbox), true);
            blackbox_mods.insert(mod_name);
        }
    }

    for(auto mod : conf.design->modules())
    {
        for(auto cell : mod->cells())
        {
            if(blackbox_mods.find(cell->type) != blackbox_mods.end())
            {
                log("Marking cell %s in module %s as (* blackbox *)\n", 
                    log_id(cell->name), log_id(mod->name));
                cell->set_bool_attribute(ID(blackbox), true);
            }
        }
    }
    auto t_end = std::chrono::steady_clock::now();
    timing_stat.check_retime_ms += std::chrono::duration_cast<std::chrono::milliseconds>(t_end-t_start).count();
    return results;
}

struct GuideCheckMultiPass : public Pass {
    GuideCheckMultiPass() : Pass("guide_check_multi", "check and extract multiplier using verfication guide information.") { }
    void help() override
	{
		//   |---v---|---v---|---v---|---v---|---v---|---v---|---v---|---v---|---v---|---v---|
        log("\n");
        log("    guide_check_multi [options] [selection]\n");
        log("\n");
        log("This pass checks and extracts multiplier cells/modules using the verification guide information.\n");
        log("\n");
        log("    -lib <sim_lib.v>\n");
        log("        Simulation library.\n");
        log("\n");
    }
    void execute(std::vector<std::string> args, RTLIL::Design *design) override
    {
        log_header(design, "Executing GUIDE_CHECK_MULTI pass.\n");
        log_push();
        string mod_name;
        string lib_file;
        size_t argidx;
        for (argidx = 1; argidx < args.size(); argidx++)
        {
            if (args[argidx] == "-lib" && argidx + 1 < args.size()) {
                lib_file = args[++argidx];
                continue;
            }
            break;
        }

        extra_args(args, argidx, design);
        
        auto modules = design->all_selected_modules();
    
        if (modules.size() == 0){
            log_warning("No module selected for GUIDE_CHECK_MULTI.\n");
            log_pop();
            return;
        }
        
    
        string tempdir_name;
        tempdir_name = "_tmp_";
        tempdir_name += proc_program_prefix() + "yosys-guide-check-XXXXXX";
        tempdir_name = make_temp_dir(tempdir_name);
        std::vector<RTLIL::Module*> multi_mods;

        log_error("This command has been deprecated!\n");
        // for(auto mod : modules)
        // {
        //     log("Checking module %s for multiplier extraction.\n", mod->name.str());
        //     bool multi_result = false;
        //     multi_result = check_extract_multi(design, mod, tempdir_name, multi_mods, lib_file);
        //     if(!multi_result)
        //     {
        //         log("\nGUIDE_CHECK_MULTI failed for module %s.\n", log_id(mod->name));
        //     }
        //     else 
        //     {
        //         log("\nGUIDE_CHECK_MULTI passed for module %s.\n", log_id(mod->name));
        //     }
        // }

        // (void)multi_mods;
        // for(auto mod : multi_mods)
        // {
        //     if(design->top_module() != mod)
        //         design->remove(mod);
        // }
        log_pop();
    }

} GuideCheckMultiPass;


struct GuideCheckRetimePass : public Pass {
    GuideCheckRetimePass() : Pass("guide_check_retime", "check retimed design using verfication guide information.") { }
    void help() override
    {
        //   |---v---|---v---|---v---|---v---|---v---|---v---|---v---|---v---|---v---|---v---|
        log("\n");
        log("    guide_check_retime [options] gold_top_module gold_prefix gate_top_module gate_prefix\n");
        log("\n");
        log("This pass checks the retimed design using the verification guide information.\n");
        log("\n");
        log("    -nocleanup\n");
        log("        when this option is used, the temporary files created by this pass\n");
        log("        are not removed. this is useful for debugging.\n");
        log("\n");
        log("    -exe <command>\n");
#ifdef ABCEXTERNAL
		log("        use the specified command instead of \"" ABCEXTERNAL "\" to execute ABC.\n");
#else
		log("        use the specified command instead of \"<yosys-bindir>/%syosys-abc\" to execute ABC.\n", proc_program_prefix());
#endif	
        log("\n");
        log("    -assert\n");
		log("        produce an error if any unproven structure is found\n");
		log("\n");
        log("    -weak\n");
        log("        use weak sequential equivalence suitable for retiming:\n");
        log("        allow mismatch in early cycles; prove that once outputs are equal\n");
        log("        for K cycles they will never diverge (k-induction).\n");
        log("\n");
        log("    -skip <N>\n");
        log("        ignore equivalence checks in the first N cycles (warmup/pipeline fill).\n");
        log("\n");
        log("    -k <K>\n");
        log("        set BMC/induction depth (default: 20).\n");
        log("\n");
        log("    -noinit\n");
        log("        do not assume initial conditions at time 0 (treat init as unconstrained).\n");
        log("\n");
        log("    -lib <sim_lib.v>\n");
        log("        Simulation library.\n");
        log("\n");
    }
    void execute(std::vector<std::string> args, RTLIL::Design *design) override 
    {
        log_header(design, "Executing GUIDE_CHECK_RETIME pass.\n");
        log_push();
        string gold_top_mod_name, gate_top_mod_name;
        string gate_prefix, gold_prefix;
        bool nocleanup = false;
        bool assert_mode = false;
        string abc_exe_file = design->scratchpad_get_string("abc.exe", yosys_abc_executable);
        int step_skip = 0;
        bool weak_mode = false;
        int k_induct = 20;
        bool no_init = false;
        string lib_file;


        size_t argidx;
        for (argidx = 1; argidx < args.size(); argidx++)
        {
            if (args[argidx] == "-nocleanup") {
                nocleanup = true;
                continue;
            }
            if (args[argidx] == "-exe" && argidx+1 < args.size()) {
                abc_exe_file = args[++argidx];
                continue;
            }
            if (args[argidx] == "-assert") {
                assert_mode = true;
                continue;
            }
            if (args[argidx] == "-weak") {
                weak_mode = true;
                continue;
            }
            if (args[argidx] == "-skip" && argidx + 1 < args.size()) {
                step_skip = atoi(args[++argidx].c_str());
                continue;
            }
            if (args[argidx] == "-k" && argidx + 1 < args.size()) {
                k_induct = atoi(args[++argidx].c_str());
                continue;
            }
            if (args[argidx] == "-noinit") {
                no_init = true;
                log_error("-noinit option is not supported yet.\n");
                continue;
            }
            if (args[argidx] == "-lib" && argidx + 1 < args.size()) {
                lib_file = args[++argidx];
                continue;
            }
            break;
        }
        if (argidx + 4 != args.size())
            log_cmd_error("Wrong number of arguments for guide_check_retime pass.\n");

        gold_top_mod_name = args[argidx++];
        gold_prefix = args[argidx++];
        gate_top_mod_name = args[argidx++];
        gate_prefix = args[argidx++];
        RTLIL::Module *gold_mod = design->module(RTLIL::escape_id(gold_top_mod_name));
        RTLIL::Module *gate_mod = design->module(RTLIL::escape_id(gate_top_mod_name));
        for(auto mod : {gold_mod, gate_mod}) 
        {
            if (mod == nullptr)
                log_cmd_error("Can't find module %s.\n", mod == gold_mod ? gold_top_mod_name : gate_top_mod_name);
        }
        
        string tempdir_name;
        if(nocleanup)
            tempdir_name = "_tmp_";
        else
            tempdir_name = get_base_tmpdir() + "/";
        
        tempdir_name += proc_program_prefix() + "yosys-guide-check-XXXXXX";
        tempdir_name = make_temp_dir(tempdir_name);
        log("Creating temporary directory %s for GUIDE_CHECK pass.\n", tempdir_name);
        
    
        log_error("This command has been deprecated!\n");

        ModMap map;
        bool result =false;
        auto results = check_extract_retime(map,CheckConfig{
            .nocleanup = nocleanup,
            .abc_exe_file = abc_exe_file,
            .tempdir_name = tempdir_name,
            .design = design,
            .gold_mod = gold_mod,
            .gate_mod = gate_mod,
            .gold_prefix = gold_prefix,
            .gate_prefix = gate_prefix,
            .lib_file = lib_file,
            .sched_model_file = "",
            .seq_check_cfg = SeqCheckConfig{
                .k_induct = k_induct,
                .step_skip = step_skip,
                .weak_mode = weak_mode,
                .no_init = no_init
            },
            .dump_cfg = MlDumpConfig(),
            .sched_model = nullptr,
            .telemetry = nullptr,
            .lib_design = nullptr
        });

        // if(!nocleanup){
        //     remove_directory(tempdir_name);
        // }

        if(result){
            log("\nGUIDE_CHECK_RETIME PASSED: Retimed design is equivalent to the gold design.\n");
        }
        else {
            if(assert_mode)
                log_cmd_error("\nGUIDE_CHECK_RETIME FAILED: Retimed design is NOT equivalent to the gold design.\n");
            else
                log("\nGUIDE_CHECK_RETIME FAILED: Retimed design is NOT equivalent to the gold design.\n");
        }

        log_pop();
    }
} GuideCheckRetimePass;

struct GuideCheckPass : public Pass {
	GuideCheckPass() : Pass("guide_check", "equivalence checking using verfication guide information.") { }
	void help() override
	{
		//   |---v---|---v---|---v---|---v---|---v---|---v---|---v---|---v---|---v---|---v---|
        log("\n");
        log("    guide_check [options] <[gold_top_module gold_prefix gate_top_module gate_prefix]/[gold_top_module gate_top_module]>\n");
        log("\n");
        log("This pass compares two modules using the verification guide information.\n");
        log("\n");
        log("    -lib <sim_lib.v>\n");
        log("        Simulation library.\n");
        log("\n");
        log("    -nocleanup\n");
		log("        when this option is used, the temporary files created by this pass\n");
		log("        are not removed. this is useful for debugging.\n");
        log("\n");
        log("    -exe <command>\n");
#ifdef ABCEXTERNAL
		log("        use the specified command instead of \"" ABCEXTERNAL "\" to execute ABC.\n");
#else
		log("        use the specified command instead of \"<yosys-bindir>/%syosys-abc\" to execute ABC.\n", proc_program_prefix());
#endif	
        log("\n");
        log("    -assert\n");
		log("        produce an error if any unproven structure is found\n");
		log("\n");
        log("    -weak\n");
        log("        use weak sequential equivalence suitable for retiming:\n");
        log("        allow mismatch in early cycles; prove that once outputs are equal\n");
        log("        for K cycles they will never diverge (k-induction).\n");
        log("\n");
        log("    -skip <N>\n");
        log("        ignore equivalence checks in the first N cycles (warmup/pipeline fill).\n");
        log("\n");
        log("    -k <K>\n");
        log("        set BMC/induction depth (default: 20).\n");
        log("\n");
        log("    -noinit\n");
        log("        do not assume initial conditions at time 0 (treat init as unconstrained).\n");
        log("\n");
        log("    -guide-dump-sched <file>\n");
        log("        append pair-level ABC scheduler samples to the JSONL file.\n");
        log("\n");
        log("    -guide-dump-match <file>\n");
        log("        append signal-matching samples to the JSONL file.\n");
        log("\n");
        log("    -guide-dump-fail <file>\n");
        log("        append structured failure packets to the JSONL file.\n");
        log("\n");
        log("    -guide-sched-model <file>\n");
        log("        load a scheduler model JSON file and use it to rank ABC actions.\n");
        log("\n");
	}
	void execute(std::vector<std::string> args, RTLIL::Design *design) override
	{
        log_header(design, "Executing GUIDE_CHECK pass.\n");
        log_push();
        string gold_top_mod_name, gate_top_mod_name;
        string gate_prefix, gold_prefix;
        bool nocleanup = false;
        bool assert_mode = false;
        string abc_exe_file = design->scratchpad_get_string("abc.exe", yosys_abc_executable);
        string lib_file;
        bool weak_mode = false;
        int k_induct = 20;
        int step_skip = 0;
        bool no_init = false;
        string sched_model_file;
        MlDumpConfig dump_cfg;
        
        size_t argidx;
        for (argidx = 1; argidx < args.size(); argidx++)
        {
            if (args[argidx] == "-nocleanup") {
                nocleanup = true;
                continue;
            }
            if (args[argidx] == "-exe" && argidx+1 < args.size()) {
                abc_exe_file = args[++argidx];
                continue;
            }
            if (args[argidx] == "-assert") {
                assert_mode = true;
                continue;
            }
            if (args[argidx] == "-lib" && argidx + 1 < args.size()) {
                lib_file = args[++argidx];
                continue;
            }
            if (args[argidx] == "-weak") {
                weak_mode = true;
                continue;
            }
            if (args[argidx] == "-skip" && argidx + 1 < args.size()) {
                step_skip = atoi(args[++argidx].c_str());
                continue;
            }
            if (args[argidx] == "-k" && argidx + 1 < args.size()) {
                k_induct = atoi(args[++argidx].c_str());
                continue;
            }
            if (args[argidx] == "-noinit") {
                log_error("-noinit option is not supported yet.\n");
                no_init = true;
                continue;
            }
            if (args[argidx] == "-guide-dump-sched" && argidx + 1 < args.size()) {
                dump_cfg.dump_sched = true;
                dump_cfg.sched_jsonl = args[++argidx];
                continue;
            }
            if (args[argidx] == "-guide-dump-match" && argidx + 1 < args.size()) {
                dump_cfg.dump_match = true;
                dump_cfg.match_jsonl = args[++argidx];
                continue;
            }
            if (args[argidx] == "-guide-dump-fail" && argidx + 1 < args.size()) {
                dump_cfg.dump_fail = true;
                dump_cfg.fail_jsonl = args[++argidx];
                continue;
            }
            if (args[argidx] == "-guide-sched-model" && argidx + 1 < args.size()) {
                sched_model_file = args[++argidx];
                continue;
            }
            break;
        }

        timing_stat = TimingStat();

        if (argidx + 2 == args.size()) {
            gold_top_mod_name = args[argidx++];
            gate_top_mod_name = args[argidx++];
            gold_prefix = gold_top_mod_name + ".";
            gate_prefix = gate_top_mod_name + ".";
        } 
        else if (argidx + 4 == args.size()) {
            gold_top_mod_name = args[argidx++];
            gold_prefix = args[argidx++];
            gate_top_mod_name = args[argidx++];
            gate_prefix = args[argidx++];
        }
        else { 
            log_cmd_error("Wrong number of arguments for guide_check pass.\n");
        }

        RTLIL::Module *gold_mod = design->module(RTLIL::escape_id(gold_top_mod_name));
        RTLIL::Module *gate_mod = design->module(RTLIL::escape_id(gate_top_mod_name));
        if (gold_mod == nullptr)
            log_cmd_error("Can't find gold module %s.\n", gold_top_mod_name);
        if (gate_mod == nullptr)
            log_cmd_error("Can't find gate module %s.\n", gate_top_mod_name);
        const RTLIL::IdString gold_mod_name_id = gold_mod->name;
        const RTLIL::IdString gate_mod_name_id = gate_mod->name;

        string tempdir_name;
        if(nocleanup)
            tempdir_name = "_tmp_";
        else
            tempdir_name = get_base_tmpdir() + "/";
        
        tempdir_name += proc_program_prefix() + "yosys-guide-check-XXXXXX";
        tempdir_name = make_temp_dir(tempdir_name);
        log("Creating temporary directory %s for GUIDE_CHECK pass.\n", tempdir_name);



        auto design_backup = design; 
        design = clone_design_for_passes(design);
        gold_mod = design->module(gold_mod_name_id);
        gate_mod = design->module(gate_mod_name_id);
        log_assert(gold_mod && gate_mod);


        auto t_lib_start = std::chrono::steady_clock::now();

        // Load library if specified
        RTLIL::Design *lib_design = nullptr;
        if(!lib_file.empty()){
            lib_design = empty_design();

            if(lib_file.size() > 4 && lib_file.substr(lib_file.size() - 4) == ".lib"){
                run_pass("read_liberty -overwrite " + lib_file, lib_design);
            }
            else if (lib_file.size() > 2 && lib_file.substr(lib_file.size() - 2) == ".v"){
                run_pass("read_verilog -overwrite " + lib_file, lib_design);
                run_pass("proc", lib_design);
                run_pass("techmap", lib_design);
            }
            else {
                design = design_backup;
                log_error("Unsupported library file format: %s\n", lib_file);
            }
            
        }
        
        SeqCheckConfig seq_conf = {
            .k_induct = k_induct,
            .step_skip = step_skip,
            .weak_mode = weak_mode,        
            .no_init = no_init,
        };

        GuideTelemetry telemetry;
        GuideSchedModel sched_model;
        if (!sched_model_file.empty())
            load_sched_model(sched_model_file, sched_model);

        CheckConfig conf = {
            .nocleanup = nocleanup,
            .abc_exe_file = abc_exe_file,
            .tempdir_name = tempdir_name,
            .design = design,
            .gold_mod = gold_mod,
            .gate_mod = gate_mod,
            .gold_prefix = gold_prefix,
            .gate_prefix = gate_prefix,
            .lib_file = lib_file,
            .sched_model_file = sched_model_file,
            .seq_check_cfg = seq_conf,
            .dump_cfg = dump_cfg,
            .sched_model = &sched_model,
            .telemetry = &telemetry,
            .lib_design = lib_design,
        };

        vector<std::pair<RTLIL::IdString,bool>> cec_result_mod;
        bool multi_result = true, cec_result = true, retime_result = true;

        if(lib_design){
            lib_import_to_design(design, lib_design);
            flatten_std_cells(design, lib_design);
            for(auto mod : lib_design->modules()){
                auto mod_ = design->module(mod->name);
                if(mod_) {
                    design->remove(mod_);
                }
            }
        }
        
        auto t_lib_end = std::chrono::steady_clock::now();

        timing_stat.read_lib_ms += std::chrono::duration_cast<std::chrono::milliseconds>(t_lib_end-t_lib_start).count();

        auto t_prep_start1 = std::chrono::steady_clock::now();
        run_pass("proc", design);
        run_pass("memory_map", design);
        run_pass("opt_expr", design);
        run_pass("wreduce", design);
        auto t_prep_end1 = std::chrono::steady_clock::now();
        timing_stat.prep_ms += std::chrono::duration_cast<std::chrono::milliseconds>(t_prep_end1-t_prep_start1).count();


        ModMap mod_map = hier_mod_map(design, conf);
        MultiMap multi_map = get_multi_map(design, mod_map);
        auto multi_results = check_extract_multi(design, multi_map, tempdir_name, dump_cfg, &telemetry.multiplier_mods);
        for(auto r: multi_results){
            log("GUIDE_CHECK for multiplier module : %s : %s\n",
                log_id(r.first),
                r.second ? "\033[1;32mPASSED\033[0m" : "\033[1;31mFAILED\033[0m");
            if (!r.second) {
                multi_result = false;
                break;
            }
        }
        if(!multi_result) { 
            log("GUIDE_CHECK multiplier check failed.\n");
        }
        if (dump_cfg.dump_match)
            (void)match_signals(design, conf, mod_map, false, "pre_async");
        auto t_prep_start2 = std::chrono::steady_clock::now();
        run_pass("techmap", design);
        run_pass("async2sync", design); // ! Warning: May cause side effects. Maybe we can move match_signals before this.
        run_pass("dffunmap", design);
        auto t_prep_end2 = std::chrono::steady_clock::now();
        timing_stat.prep_ms += std::chrono::duration_cast<std::chrono::milliseconds>(t_prep_end2-t_prep_start2).count();
        

        // remove_subclk(design, conf);

        run_pass("opt_clean", design);


        // run_pass("opt_clean", design_check);
        // run_pass("check", design_check);
        // run_pass("write_verilog 1.v", design_check );
        // system("yosys -q -p 'read_verilog 1.v; proc; opt_expr; techmap; show -colors 1 -prefix gold gold_bbox'");
        // system("yosys -q -p 'read_verilog bbox.v; proc; opt_expr; techmap; show -colors 1 -prefix test bbox'");
        // return;


        // (void)multi_mods;

        auto retime_results = check_extract_retime(mod_map, conf);

        retime_result = true;
        for(auto &r: retime_results) {
            if(!r.second) {
                retime_result = false;
                break;
            }
        }


        

        auto gold2cutpoints = match_signals(design, conf, mod_map, true, "post_async");
        (void)gold2cutpoints;

        // remove_subclk(design,conf);
        // RTLIL::Design *design_check = empty_design();

        // run_pass("write_verilog 1.v", design_check );
        // partition_design_for_check(design, design_check, conf, mod_map, gold2cutpoints);

        // propagate_child_ports(design_check);

        // conf.design = design_check;
        cec_result_mod = abc_cec(conf);

        cec_result = true; 
        for(auto r: cec_result_mod){
            if(!r.second){
                cec_result = false;
                break;
            }
        }

        report(gold_mod_name_id, gate_mod_name_id,
                multi_results,retime_results, cec_result_mod);

        if (dump_cfg.dump_match)
            write_match_suggestions(match_suggestions_path(dump_cfg.match_jsonl), telemetry.match_suggestions);

        print_timing_stat(timing_stat);

        
    
        if (!conf.nocleanup) {
			log("Removing temp directory.\n");
			remove_directory(conf.tempdir_name);
		}

        bool succ = cec_result && multi_result && retime_result;
        if(assert_mode && !succ){
            log_error("GUIDE_CHECK Assertion Failed!\n");
        }

        delete design;
        design = design_backup;
        log_pop();
	}

    bool report(RTLIL::IdString gold_mod_name_id, RTLIL::IdString gate_mod_name_id,
                    Results &mul_results,
                    Results &retime_results,
                    Results &cec_results)
    {
        auto ok_str = [](bool ok) {
            return ok ? "\033[1;32mPASSED\033[0m" : "\033[1;31mFAILED\033[0m";
        };

        auto print_sep = [](int w1, int w2, int w3) {
            log("+-%.*s-+-%.*s-+-%.*s-+\n",
                w1, "------------------------------------------------------------",
                w2, "------------------------------------------------------------",
                w3, "------------------------------------------------------------");
        };

        auto print_row = [](int w1, int w2, int w3,
                            const char *c1, const char *c2, const char *c3) {
            log("| %-*s | %-*s | %-*s |\n", w1, c1, w2, c2, w3, c3);
        };

        const int W_CAT = 12;
        const int W_MOD = 35;
        const int W_RES = 6;

        bool mul_ok = true;
        bool cec_ok = true;
        bool retime_ok = true;

        log("\n================== Equivalence Checking Report ================\n");

        print_sep(W_CAT, W_MOD, W_RES);
        print_row(W_CAT, W_MOD, W_RES, "Category", "Module", "Result");
        print_sep(W_CAT, W_MOD, W_RES);

        for (const auto &r : mul_results) {
            print_row(W_CAT, W_MOD, W_RES, "MULTIPLIER", log_id(r.first), ok_str(r.second));
            if (!r.second) mul_ok = false;
        }

        for (const auto &r : retime_results) {
            print_row(W_CAT, W_MOD, W_RES, "RETIMING", log_id(r.first), ok_str(r.second));
            if (!r.second) retime_ok = false;
        }

        for (const auto &r : cec_results) {
            print_row(W_CAT, W_MOD, W_RES, "CEC/SEC", log_id(r.first), ok_str(r.second));
            if (!r.second) cec_ok = false;
        }

        print_sep(W_CAT, W_MOD, W_RES);

        bool succ = mul_ok && cec_ok && retime_ok;

        if (!succ) {
            log("\nGUIDE_CHECK FAILED: Modules %s and %s are NOT equivalent.\n",
                log_id(gold_mod_name_id), log_id(gate_mod_name_id));
        } else {
            log("\nGUIDE_CHECK PASSED: Modules %s and %s are equivalent.\n",
                log_id(gold_mod_name_id), log_id(gate_mod_name_id));
        }

        log("===============================================================\n");
        return succ;
    }
} GuideCheckPass;


PRIVATE_NAMESPACE_END
