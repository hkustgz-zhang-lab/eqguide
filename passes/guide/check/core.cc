#include "passes/guide/check/check.h"
#include "passes/guide/check/fail_exec.h"
#include "passes/guide/check/scheduler.h"
#include "kernel/celltypes.h"
#include "kernel/ff.h"
#include "kernel/log.h"
#include "kernel/register.h"
#include "kernel/rtlil.h"
#include "kernel/yosys.h"
#include "libs/json11/json11.hpp"
#include <fstream>
#include <chrono>

YOSYS_NAMESPACE_BEGIN
namespace guide_check {

TimingStat timing_stat;

void print_MultiMap(const MultiMap &mm)
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

std::string strip_backslash(const RTLIL::IdString &id)
{
    std::string s = id.str();
    if (!s.empty() && s[0] == '\\') s = s.substr(1);
    return s;
}
RTLIL::Design *empty_design()
{
    auto *design = new RTLIL::Design;
    design->push_full_selection();
    return design;
}

string sanitize_filename(const string &s)
{
    string out = s;
    for (char &ch : out)
        if (!std::isalnum(static_cast<unsigned char>(ch)) && ch != '_' && ch != '-' && ch != '.')
            ch = '_';
    return out;
}

string path_dirname(const string &path)
{
    size_t pos = path.find_last_of('/');
    if (pos == string::npos)
        return ".";
    return path.substr(0, pos);
}

string pair_artifact_path(const string &dir_name, const string &prefix,
                                 RTLIL::Module *gold_mod, RTLIL::Module *gate_mod,
                                 const string &ext)
{
    return dir_name + "/" + prefix + "_" +
        sanitize_filename(strip_backslash(gold_mod->name)) + "_" +
        sanitize_filename(strip_backslash(gate_mod->name)) + ext;
}

string get_pair_id(const RTLIL::IdString &gold_mod, const RTLIL::IdString &gate_mod)
{
    return strip_backslash(gold_mod) + "__vs__" + strip_backslash(gate_mod);
}

Json match_stats_to_json(const MatchStats &stats)
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

Json pair_record_to_json(const PairRecord &record)
{
    return Json::object {
        {"pair_id", record.pair_id},
        {"gold_mod", record.gold_mod},
        {"gate_mod", record.gate_mod},
        {"gold_dff_cnt", record.gold_dff_cnt},
        {"gate_dff_cnt", record.gate_dff_cnt},
        {"has_submodule", record.has_submodule},
        {"retimed", record.retimed},
        {"mul_touched", record.mul_touched},
        {"bb_const_in_cnt", record.bb_const_in_cnt}
    };
}

Json run_record_to_json(const RunRecord &record)
{
    return Json::object {
        {"pair_id", record.pair_id},
        {"action", record.action},
        {"exit_status", record.exit_status},
        {"result_code", record.result_code},
        {"proof_outcome", record.proof_outcome},
        {"runtime_ms", record.runtime_ms},
        {"log_file", record.log_file}
    };
}

void flatten_std_cells(RTLIL::Design *design, RTLIL::Design *lib_design)
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

RTLIL::Design *clone_design_for_passes(RTLIL::Design *design)
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

void lib_import_to_design(RTLIL::Design *design, RTLIL::Design *lib_design)
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

    // Structural fallback: for unmapped modules, try to match by port signature
    if (!mod_map.unmapped_mods_gold.empty() && !mod_map.unmapped_mods_gate.empty()) {
        // Build port signatures for unmapped modules: "in_w0_w1_...|out_w0_w1_..."
        auto make_sig = [&](RTLIL::Module *m) -> string {
            std::vector<int> in_w, out_w;
            for (auto w : m->wires()) {
                if (w->port_id == 0) continue;
                if (w->port_input) in_w.push_back(w->width);
                if (w->port_output) out_w.push_back(w->width);
            }
            std::sort(in_w.begin(), in_w.end());
            std::sort(out_w.begin(), out_w.end());
            string sig = "in";
            for (int w : in_w) sig += "_" + std::to_string(w);
            sig += "|out";
            for (int w : out_w) sig += "_" + std::to_string(w);
            return sig;
        };

        dict<string, std::vector<RTLIL::IdString>> gate_sigs;
        for (auto &gn : mod_map.unmapped_mods_gate) {
            auto *gm = design->module(gn);
            if (gm != nullptr) gate_sigs[make_sig(gm)].push_back(gn);
        }

        std::vector<RTLIL::IdString> matched_gold, matched_gate;
        for (auto &gld : mod_map.unmapped_mods_gold) {
            auto *gm = design->module(gld);
            if (gm == nullptr) continue;
            string sig = make_sig(gm);
            auto it = gate_sigs.find(sig);
            if (it == gate_sigs.end() || it->second.empty()) continue;
            // Use first available match (greedy); unambiguous when size==1
            auto gname = it->second[0];
            (*gold2gate)[gld] = gname;
            mod_map.mapped_mods_gold.insert(gld);
            mod_map.mapped_mods_gate.insert(gname);
            matched_gold.push_back(gld);
            matched_gate.push_back(gname);
            it->second.erase(it->second.begin());
            log("  Structurally matched: Gold %s <=> Gate %s (sig=%s)\n",
                log_id(gld), log_id(gname), sig.c_str());
        }
        for (auto &n : matched_gold) mod_map.unmapped_mods_gold.erase(n);
        for (auto &n : matched_gate) mod_map.unmapped_mods_gate.erase(n);
    }

    auto t_end = std::chrono::steady_clock::now();
    timing_stat.hier_mod_map_ms += std::chrono::duration_cast<std::chrono::milliseconds>(t_end-t_start).count();

    return mod_map;
}

bool abc_cec_module(const CheckConfig &conf, bool fatal, CommandResult *deciding_result){
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

    auto collect_pair_record = [&](int bbconsts) {
        PairRecord rec;
        rec.pair_id = get_pair_id(conf.gold_mod->name, conf.gate_mod->name);
        rec.gold_mod = strip_backslash(conf.gold_mod->name);
        rec.gate_mod = strip_backslash(conf.gate_mod->name);
        rec.gold_dff_cnt = count_module_dffs(conf.gold_mod, false);
        rec.gate_dff_cnt = count_module_dffs(conf.gate_mod, true);
        rec.bb_const_in_cnt = bbconsts;

        for (auto cell : conf.gold_mod->cells()) {
            RTLIL::Module *submod = conf.design->module(cell->type);
            if (submod != nullptr && !submod->get_bool_attribute(ID(blackbox))) {
                rec.has_submodule = true;
                break;
            }
        }

        if (conf.telemetry != nullptr) {
            rec.retimed = conf.telemetry->retimed_mods.count(conf.gold_mod->name) ||
                          conf.telemetry->retimed_mods.count(conf.gate_mod->name);
            rec.mul_touched = conf.telemetry->multiplier_mods.count(conf.gold_mod->name) ||
                              conf.telemetry->multiplier_mods.count(conf.gate_mod->name);
        }

        return rec;
    };

    auto heuristic_abc_plan = [&](const PairRecord&, const MatchStats&) {
        return std::vector<ActionKind> {
            ActionKind::CEC_MAP,
            ActionKind::CEC_NOMAP,
            ActionKind::DSEC_MAP,
            ActionKind::DSEC_NOMAP
        };
    };

    auto learned_abc_plan = [&](const PairRecord &pair_rec, const MatchStats &mstats) {
        if (conf.sched_model == nullptr || !conf.sched_model->loaded)
            return heuristic_abc_plan(pair_rec, mstats);

        std::vector<std::pair<double, ActionKind>> ranked;
        for (auto action : heuristic_abc_plan(pair_rec, mstats))
            ranked.push_back({predict_sched_cost(*conf.sched_model, get_action_name(action), pair_rec, mstats), action});

        std::sort(ranked.begin(), ranked.end(),
            [](const std::pair<double, ActionKind> &lhs, const std::pair<double, ActionKind> &rhs) {
                if (lhs.first != rhs.first)
                    return lhs.first < rhs.first;
                return get_action_name(lhs.second) < get_action_name(rhs.second);
            });

        std::vector<ActionKind> plan;
        for (auto &entry : ranked)
            plan.push_back(entry.second);
        return plan;
    };

    auto run_abc_action = [&](ActionKind action, const string &match_file, const string &gold_file,
                              const string &gate_file, RunRecord &rec) {
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
        CommandResult cmd_res;
        int rc = 0;
        string act = get_action_name(action);
        string log_dir = failure_log_dir(conf.dump_cfg);
        log("Executing ABC command: '%s'\n", abc_cmd.c_str());
        int status = exectue_and_check(cmd, rc, out2result, conf.tempdir_name,
                                            "abc-" + sanitize_filename(get_pair_id(conf.gold_mod->name, conf.gate_mod->name)) +
                                            "-" + act,
                                            log_dir,
                                            &cmd_res);
        cmd_res.raw_result_code = rc;
        if (rc == 1)
            cmd_res.proof_outcome = "equivalent";
        else if (rc == 2)
            cmd_res.proof_outcome = "not_equivalent";
        else if (rc == 3)
            cmd_res.proof_outcome = "blocked";
        else if (rc == 0)
            cmd_res.proof_outcome = "blocked";
        else if (status != 0)
            cmd_res.proof_outcome = "tool_error";
        if (status != 0 || rc == 0) {
            cmd_res.result_code = rc;
            emit_failure_packet(conf, "ABC", act, cmd_res, {});
            if (fatal)
                log_error("Error executing ABC command: %s\n", cmd.c_str());
            log_warning("Error executing ABC command: %s\n", cmd.c_str());
        }

        rec.pair_id = get_pair_id(conf.gold_mod->name, conf.gate_mod->name);
        rec.action = act;
        rec.exit_status = cmd_res.exit_status;
        rec.result_code = rc;
        rec.proof_outcome = cmd_res.proof_outcome;
        rec.runtime_ms = cmd_res.runtime_ms;
        rec.log_file = cmd_res.log_file;
        cmd_res.result_code = rc;
        return cmd_res;
    };

    auto run_abc_plan = [&](const PairRecord &pair_rec, const std::vector<ActionKind> &plan,
                            const string &match_file, const string &gold_file, const string &gate_file,
                            std::vector<RunRecord> *trace, CommandResult *last_result, string *last_action) {
        bool has_dff = pair_rec.gold_dff_cnt != 0 || pair_rec.gate_dff_cnt != 0;
        bool exhaustive = conf.dump_cfg.dump_sched;
        bool strict_order = conf.sched_model != nullptr && conf.sched_model->loaded;
        bool ran_dsec_map = false;
        int prev_result = 0;
        bool solved = false;
        CommandResult last_cmd;
        string last_act;

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

            RunRecord rec;
            CommandResult cmd_res = run_abc_action(action, match_file, gold_file, gate_file, rec);
            if (trace != nullptr)
                trace->push_back(rec);

            prev_result = rec.result_code;
            last_cmd = cmd_res;
            last_act = rec.action;
            if (action == ActionKind::DSEC_MAP)
                ran_dsec_map = true;

            if (rec.result_code == 1) {
                solved = true;
                if (!exhaustive)
                    break;
            }
        }

        if (last_result != nullptr)
            *last_result = last_cmd;
        if (last_action != nullptr)
            *last_action = last_act;
        return solved;
    };

    auto dump_sched_sample = [&](const PairRecord &pair_rec, const MatchStats &mstats,
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
            {"pair", pair_record_to_json(pair_rec)},
            {"match", match_stats_to_json(mstats)},
            {"actions", action_json},
            {"label_best_action", best_action}
        });
    };

    using clock = std::chrono::steady_clock;
    auto t0 = clock::now();

    int gold_ins = 0;
    int gate_ins = 0;
    string gold_file = dump_blif_module(conf.design, conf.tempdir_name, conf.gold_mod, conf.lib_file, &gold_ins);
    string gate_file = dump_blif_module(conf.design, conf.tempdir_name, conf.gate_mod, conf.lib_file, &gate_ins);
    string match_file = conf.tempdir_name + "/match_" + RTLIL::unescape_id(conf.gold_mod->name) + "_" +
        RTLIL::unescape_id(conf.gate_mod->name) + ".txt";

    PairRecord pair_rec = collect_pair_record(gold_ins + gate_ins);
    if (conf.telemetry != nullptr)
        conf.telemetry->pair_records[pair_rec.pair_id] = pair_rec;
    MatchStats mstats = get_match_stats(conf);
    log("Gold DFF count: %d, Gate DFF count: %d\n", pair_rec.gold_dff_cnt, pair_rec.gate_dff_cnt);

    std::vector<ActionKind> plan = learned_abc_plan(pair_rec, mstats);
    std::vector<RunRecord> trace;
    CommandResult last_result;
    string last_action;

    log("Running ABC.\n");
    fflush(stdout);

    bool solved = run_abc_plan(pair_rec, plan, match_file, gold_file, gate_file, &trace, &last_result, &last_action);
    dump_sched_sample(pair_rec, mstats, trace);
    if (!solved && !last_action.empty())
        emit_failure_packet(conf, "ABC", last_action, last_result, trace);
    if (deciding_result != nullptr)
        *deciding_result = last_result;

    auto t1 = clock::now();
    timing_stat.abc_cec_ms += std::chrono::duration_cast<std::chrono::milliseconds>(t1-t0).count();

    return solved;
}

bool bmcinduct_check(const CheckConfig &conf){
    std::string gold_name = strip_backslash(conf.gold_mod->name);
    std::string gate_name = strip_backslash(conf.gate_mod->name);

    auto smt2_file = dump_smt2(conf.design, conf.tempdir_name, {conf.gold_mod, conf.gate_mod}, "");

    string cmd = resolve_yosys_smtbmc_executable() + " ";

    if(conf.seq_check_cfg.no_init){
        cmd += "-noinit ";
    }
    cmd += "-m " + gold_name + "_vs_" + gate_name + " ";
    
    if(conf.seq_check_cfg.weak_mode){
        cmd += "-i -t ";
        cmd += std::to_string(conf.seq_check_cfg.step_skip) + ":" + std::to_string(conf.seq_check_cfg.k_induct) + " ";

        CommandResult weak_capture;
        string log_dir = failure_log_dir(conf.dump_cfg);
        int ret = exec_cmd(cmd + smt2_file, conf.tempdir_name,
                           "smtbmc-weak-" + sanitize_filename(get_pair_id(conf.gold_mod->name, conf.gate_mod->name)),
                           log_dir,
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
    string log_dir = failure_log_dir(conf.dump_cfg);
    int ret = exec_cmd(cmd_bmc + smt2_file, conf.tempdir_name,
                       "smtbmc-bmc-" + sanitize_filename(get_pair_id(conf.gold_mod->name, conf.gate_mod->name)),
                       log_dir,
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
                   log_dir,
                   &induct_capture);
    if(ret != 0){
        log("BMC-Induct failed in Induct phase.\n");
        induct_capture.output += "BMC-Induct failed in Induct phase.\n";
        emit_failure_packet(conf, "BMC", "induct", induct_capture, {});
        return false;
    }
    return true;
}

string dump_aig(RTLIL::Design* design, const string &dir_name, RTLIL::Module *mod,
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

string dump_aig(RTLIL::Design* design, const string &dir_name, RTLIL::Module *mod){
    return dump_aig(design, dir_name, mod, "");
}

string dump_blif(RTLIL::Design* design, const string &dir_name, RTLIL::Module *mod, const string& lib_file){
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

int materialize_blackbox_input_consts(RTLIL::Design *design, RTLIL::Module *mod)
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

RTLIL::Design *prepare_blif_module_design(RTLIL::Design *design, RTLIL::Module *mod,
                                                 const string &lib_file,
                                                 int *inserted_bbconsts)
{
    RTLIL::Design *design_copy = clone_design_for_passes(design);
    string mod_name = strip_backslash(mod->name);
    bool local_shell = mod_name.size() >= 7 && mod_name.substr(mod_name.size() - 7) == "__local";
    pool<RTLIL::IdString> lib_mods;

    if (!lib_file.empty() && lib_file.size() >= 2 && lib_file.substr(lib_file.size() - 2) == ".v") {
        pool<RTLIL::IdString> mod_names_before;
        for (auto mod_ : design_copy->modules())
            mod_names_before.insert(mod_->name);
        run_pass(stringf("read_verilog -overwrite -noblackbox %s", lib_file), design_copy);
        run_pass("proc", design_copy);
        for (auto mod_ : design_copy->modules())
            if (!mod_names_before.count(mod_->name))
                lib_mods.insert(mod_->name);
    }

    if (!local_shell) {
        for (auto mod_ : design_copy->modules())
            if (mod_->name != mod->name)
                mod_->set_bool_attribute(ID(blackbox), true);

        RTLIL::Module *target_mod = design_copy->module(mod->name);
        if (target_mod != nullptr) {
            int inserted = materialize_blackbox_input_consts(design_copy, target_mod);
            if (inserted_bbconsts != nullptr)
                *inserted_bbconsts = inserted;
        }
        return design_copy;
    }

    run_pass(stringf("hierarchy -top %s", mod->name.str()), design_copy);

    for (auto mod_ : design_copy->modules())
        if (mod_->name != mod->name && !lib_mods.count(mod_->name))
            mod_->set_bool_attribute(ID(blackbox), true);

    RTLIL::Module *target_mod = design_copy->module(mod->name);
    if (target_mod != nullptr) {
        int inserted = materialize_blackbox_input_consts(design_copy, target_mod);
        if (inserted_bbconsts != nullptr)
            *inserted_bbconsts = inserted;
    }

    run_pass(stringf("flatten %s", mod->name.str()), design_copy);
    pool<RTLIL::IdString> keep_mods;
    std::vector<RTLIL::IdString> worklist;
    keep_mods.insert(mod->name);
    worklist.push_back(mod->name);
    while (!worklist.empty()) {
        RTLIL::IdString mod_name = worklist.back();
        worklist.pop_back();
        RTLIL::Module *cur = design_copy->module(mod_name);
        if (cur == nullptr)
            continue;
        for (auto *cell : cur->cells()) {
            RTLIL::Module *sub = design_copy->module(cell->type);
            if (sub == nullptr || keep_mods.count(sub->name))
                continue;
            keep_mods.insert(sub->name);
            worklist.push_back(sub->name);
        }
    }
    std::vector<RTLIL::Module*> rm_mods;
    for (auto mod_ : design_copy->modules())
        if (!keep_mods.count(mod_->name))
            rm_mods.push_back(mod_);
    for (auto mod_ : rm_mods)
        design_copy->remove(mod_);
    run_pass("opt", design_copy);
    run_pass("memory_map", design_copy);
    run_pass("techmap", design_copy);
    run_pass("dffunmap", design_copy);
    run_pass("opt_clean", design_copy);

    return design_copy;
}

// Fast native BLIF writer: dumps techmapped module as .subckt cells.
// Uses fprintf (not iostream) for maximum speed.
// Assumes cells are already library cells (post-techmap or post-synthesis).
static void write_blif_native(RTLIL::Module *mod, FILE *f)
{
    string name = strip_backslash(mod->name);
    fprintf(f, ".model %s\n", name.c_str());

    // Collect ports with multi-bit expansion
    pool<RTLIL::IdString> port_set;
    std::vector<pair<RTLIL::IdString, int>> in_bits, out_bits;
    for (auto w : mod->wires()) {
        if (w->port_id == 0) continue;
        port_set.insert(w->name);
        int ww = w->width;
        if (w->port_input)
            for (int i = 0; i < ww; i++)
                in_bits.push_back({w->name, i});
        if (w->port_output)
            for (int i = 0; i < ww; i++)
                out_bits.push_back({w->name, i});
    }

    fprintf(f, ".inputs");
    for (auto &p : in_bits) {
        string n = strip_backslash(p.first);
        if (p.second > 0 || p.first.str()[0] == '\\')
            fprintf(f, " %s[%d]", n.c_str(), p.second);
        else
            fprintf(f, " %s", n.c_str());
    }
    fprintf(f, "\n");

    fprintf(f, ".outputs");
    for (auto &p : out_bits) {
        string n = strip_backslash(p.first);
        if (p.second > 0 || p.first.str()[0] == '\\')
            fprintf(f, " %s[%d]", n.c_str(), p.second);
        else
            fprintf(f, " %s", n.c_str());
    }
    fprintf(f, "\n");

    // Constant wire declarations needed by ABC
    fprintf(f, ".names __const0\n");
    fprintf(f, ".names __const1\n1\n");
    fprintf(f, ".names __constx\n");

    // Write cells as .subckt
    for (auto cell : mod->cells()) {
        string type = strip_backslash(cell->type);
        fprintf(f, ".subckt %s", type.c_str());

        for (auto &conn : cell->connections()) {
            RTLIL::SigSpec sig = conn.second;
            string pname = strip_backslash(conn.first);
            int sz = GetSize(sig);

            for (int i = 0; i < sz; i++) {
                RTLIL::SigBit bit = sig[i];
                string val;
                if (bit.wire == nullptr) {
                    val = (bit.data == State::S1) ? "__const1" : "__const0";
                } else {
                    val = strip_backslash(bit.wire->name);
                    if (bit.wire->width > 1)
                        val += stringf("[%d]", bit.offset);
                }
                if (sz == 1)
                    fprintf(f, " %s=%s", pname.c_str(), val.c_str());
                else
                    fprintf(f, " %s[%d]=%s", pname.c_str(), i, val.c_str());
            }
        }
        fprintf(f, "\n");
    }

    fprintf(f, ".end\n");
}

string dump_blif_module(RTLIL::Design* design, const string &dir_name, RTLIL::Module *mod, const string& lib_file,
                               int *inserted_bbconsts){

    auto t_start = std::chrono::steady_clock::now();

    string blif_file = dir_name + "/"
        + strip_backslash(mod->name)
        + ".blif";
    string mod_name = strip_backslash(mod->name);
    log("Dumping module %s to BLIF file %s.\n", mod->name.str(), blif_file);

    auto log_files_backup = log_files;
    auto log_streams_backup = log_streams;

    // Fast path: clone only the target module, no library read
    auto t_prep_start = std::chrono::steady_clock::now();

    RTLIL::Design *design_copy = new RTLIL::Design;
    design_copy->add(mod->clone());
    design_copy->push_full_selection();

    // Add blackbox stubs for any submodule cell types referenced by target module
    // Add blackbox stubs for submodule cells: clone from original design
    for (auto cell : mod->cells()) {
        if (!design_copy->module(cell->type)) {
            auto *orig_mod = design->module(cell->type);
            if (orig_mod != nullptr) {
                auto *clone = orig_mod->clone();
                clone->set_bool_attribute(ID(blackbox), true);
                design_copy->add(clone);
            }
        }
    }

    int inserted = materialize_blackbox_input_consts(design_copy,
        design_copy->module(mod->name));
    if (inserted_bbconsts != nullptr)
        *inserted_bbconsts = inserted;

    timing_stat.dump_blif_prep_ms += std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - t_prep_start).count();

    auto t_write_start = std::chrono::steady_clock::now();
    create_directory(dir_name);
    run_pass(stringf(
        "write_blif -blackbox -top %s -false + __const0 -true + __const1 -undef + __constx %s",
        mod_name.c_str(), blif_file.c_str()),
        design_copy);
    timing_stat.dump_blif_write_ms += std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - t_write_start).count();

    delete design_copy;

    log_files = log_files_backup;
    log_streams = log_streams_backup;

    auto t_end = std::chrono::steady_clock::now();
    timing_stat.dump_blif_ms += std::chrono::duration_cast<std::chrono::milliseconds>(t_end-t_start).count();

    return blif_file;
}


string dump_smt2(RTLIL::Design* design, const string &dir_name, std::pair<RTLIL::Module*, RTLIL::Module*> mod_pair,
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

} // namespace guide_check
YOSYS_NAMESPACE_END
