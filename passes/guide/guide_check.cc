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
#include <unistd.h>
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

#include "passes/guide/check/shared.h"
#include "passes/guide/check/check.h"
#include "passes/guide/check/fail_exec.h"
#include "passes/guide/check/scheduler.h"
#include "passes/guide/check/match.h"
#include "passes/guide/check/region.h"
#include "passes/guide/check/retime_multi.h"

using namespace Yosys::guide_check;

YOSYS_NAMESPACE_BEGIN
namespace guide_check {



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
        .match_model_file = conf.match_model_file,
        .accept_sugs_file = conf.accept_sugs_file,
        .seq_check_cfg = conf.seq_check_cfg,
        .dump_cfg = conf.dump_cfg,
        .sched_model = conf.sched_model,
        .match_model = conf.match_model,
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
            .match_model_file = "",
            .accept_sugs_file = "",
            .seq_check_cfg = SeqCheckConfig{
                .k_induct = k_induct,
                .step_skip = step_skip,
                .weak_mode = weak_mode,
                .no_init = no_init
            },
            .dump_cfg = MlDumpConfig(),
            .sched_model = nullptr,
            .match_model = nullptr,
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
        log("    -guide-match-model <file>\n");
        log("        load a matching model JSON file and use it to score match suggestions.\n");
        log("\n");
        log("    -guide-accept-match-suggestions <file>\n");
        log("    -guide-external-match <file>\n");
        log("        append accepted suggestions from the JSON file into match_file.\n");
        log("\n");
        log("\n");
        log("\n");
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
        string match_model_file;
        string accept_sugs_file;
        string external_match_file;
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
            if (args[argidx] == "-guide-match-model" && argidx + 1 < args.size()) {
                match_model_file = args[++argidx];
                continue;
            }
            if (args[argidx] == "-guide-accept-match-suggestions" && argidx + 1 < args.size()) {
                accept_sugs_file = args[++argidx];
                continue;
            }
            if (args[argidx] == "-guide-external-match" && argidx + 1 < args.size()) {
                external_match_file = args[++argidx];
                continue;
            }
                continue;
            }
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
        GuideMatchModel match_model;
        if (!match_model_file.empty())
            load_match_model(match_model_file, match_model);

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
            .match_model_file = match_model_file,
            .accept_sugs_file = accept_sugs_file,
            .external_match_file = external_match_file,
            .seq_check_cfg = seq_conf,
            .dump_cfg = dump_cfg,
            .sched_model = &sched_model,
            .match_model = &match_model,
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


        

        auto t_match_start = std::chrono::steady_clock::now();
        auto gold2cutpoints = match_signals(design, conf, mod_map, true, "post_async");
        timing_stat.match_ms += std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - t_match_start).count();
        int total_applied_sugs = 0;
        for (auto &it : telemetry.pair_applied_sugs)
            total_applied_sugs += it.second;
        if (total_applied_sugs > 0)
            log("Applied %d match suggestions into match_file(s).\n",
                total_applied_sugs);

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

        if (dump_cfg.dump_match) {
            write_match_suggestions(match_suggestions_path(dump_cfg.match_jsonl), telemetry.match_suggestions);
            log("Matching sidecar hint:\n");
            log("  python3 passes/guide/ml/infer_matching.py %s --model <match_ranker.cbm> -o %s\n",
                dump_cfg.match_jsonl.c_str(),
                match_suggestions_path(dump_cfg.match_jsonl).c_str());
            log("Suggestion accept hint:\n");
            log("  guide_check ... -guide-accept-match-suggestions %s\n",
                match_suggestions_path(dump_cfg.match_jsonl).c_str());
        }
        if (dump_cfg.dump_fail) {
            string hints_path = path_dirname(dump_cfg.fail_jsonl) + "/failure_hints.json";
            write_failure_hints(dump_cfg.fail_jsonl, hints_path);
            log("Failure explainer hint:\n");
            log("  python3 passes/guide/ml/run_failure_explainer.py %s\n",
                dump_cfg.fail_jsonl.c_str());
        }

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


} // namespace guide_check
YOSYS_NAMESPACE_END
