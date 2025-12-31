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

#include "kernel/mem.h"
#include "kernel/register.h"
#include "kernel/rtlil.h"
#include "kernel/log.h"
#include "kernel/yosys.h"
#include <cassert>
#include <cstddef>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

USING_YOSYS_NAMESPACE
PRIVATE_NAMESPACE_BEGIN

struct SeqCheckConfig
{
    int k_induct = 20;
    int step_skip = 0;
    bool weak_mode = false;
    bool no_init = false;
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
    SeqCheckConfig seq_check_cfg;
};

static std::string strip_backslash(const RTLIL::IdString &id)
{
    std::string s = id.str();
    if (!s.empty() && s[0] == '\\') s = s.substr(1);
    return s;
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

static int exectue_and_check(const std::string & cmd, bool & correct, 
                      const std::string & target_output) {
    correct = false;
    char buffer[1024];
    std::string output;

    FILE *pipe = popen(cmd.c_str(), "r");
    if (!pipe) {
        log_error("Error executing command: ");
        return -1;
    }

    while (fgets(buffer, sizeof(buffer), pipe) != nullptr) {
        output += buffer;
        log("%s", buffer);
        if (output.find(target_output) != std::string::npos) {
            correct = true;
        }
    }

    int status = pclose(pipe);
    if (WIFEXITED(status)) {
        status = WEXITSTATUS(status);
    } else {
        status = -1; 
    }

    return status;
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

int exec_cmd(const string &cmd){
    char buffer[1024];

    FILE *pipe = popen(cmd.c_str(), "r");
    if (!pipe) {
        log_error("Error executing command: %s", cmd);
        return -1;
    }

    while (fgets(buffer, sizeof(buffer), pipe) != nullptr) {
        log("%s", buffer);
    }

    int status = pclose(pipe);
    if (WIFEXITED(status)) {
        status = WEXITSTATUS(status);
    } else {
        status = -1; 
    }

    if(status != 0){
        log_error("Error executing command: %s", cmd);
    }
    return status;
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
    run_pass(stringf("proc"), design_copy);
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
        run_pass(stringf("read_verilog -overwrite %s", lib_file), design_copy);
    run_pass(stringf("hierarchy -top %s", mod->name.str()), design_copy);
    run_pass(stringf("flatten"), design_copy);
    run_pass(stringf("proc"), design_copy);
    run_pass(stringf("opt"), design_copy);
    run_pass(stringf("memory_map"), design_copy);
    run_pass(stringf("techmap"), design_copy);
    run_pass(stringf("dffunmap"), design_copy);
    run_pass(stringf("write_blif -blackbox -top %s %s", mod_name, blif_file), design_copy);
    delete design_copy;
    log_files = log_files_backup;
    log_streams = log_streams_backup;
    return blif_file;
}

static string dump_blif_module(RTLIL::Design* design, const string &dir_name, RTLIL::Module *mod, const string& lib_file){
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
        run_pass(stringf("read_verilog -overwrite %s", lib_file), design_copy);
    run_pass(stringf("hierarchy -top %s", mod->name.str()), design_copy);
    run_pass(stringf("flatten"), design_copy);
    run_pass(stringf("hierarchy -top %s", mod->name.str()), design_copy);
    run_pass(stringf("proc"), design_copy);
    run_pass(stringf("opt"), design_copy);
    run_pass(stringf("memory_map"), design_copy);

    for(auto mod_: design_copy->modules()){
        if(mod_!= mod){
            mod_->set_bool_attribute(ID(blackbox), true);
        }
    }
    run_pass(stringf("techmap"), design_copy);
    run_pass(stringf("dffunmap"), design_copy);
    run_pass(stringf("write_blif -blackbox -top %s %s", mod_name, blif_file), design_copy);
    delete design_copy;
    log_files = log_files_backup;
    log_streams = log_streams_backup;
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
    run_pass(stringf("proc %s", gold_mod->name.str()), design_copy);
    run_pass(stringf("proc %s", gate_mod->name.str()), design_copy);
    run_pass(stringf("miter -equiv -make_assert -flatten %s %s %s",
                    gold_mod->name.str(), gate_mod->name.str(), mod_name), design_copy);
    run_pass(stringf("hierarchy -top %s", mod_name), design_copy);
    run_pass(stringf("techmap"), design_copy);
    run_pass(stringf("write_verilog 1.v"), design_copy);
    run_pass(stringf("prep -top %s", mod_name), design_copy);
    run_pass(stringf("write_smt2 -wires %s", smt2_file), design_copy);
    delete design_copy;
    log_files = log_files_backup;
    log_streams = log_streams_backup;
    return smt2_file;
}


static bool check_multi(RTLIL::Design* design, RTLIL::Module* mod, string& tempdir_name, const string& lib_file){
    log_assert(mod->get_bool_attribute(ID(multiplier)));
    bool is_signed = mod->get_bool_attribute(ID(is_signed));    
    auto aig_file = dump_aig(design, tempdir_name, mod, lib_file);

    log("Using amulet to verify the multiplier.\n");
        auto miter_tmp_file = tempdir_name + "/" 
            + strip_backslash(mod->name)
            + ".miter.cnf";
        auto rewritten_tmp_file = tempdir_name + "/" 
            + strip_backslash(mod->name)
            + ".rewritten.aig";

        auto amulet_sub_cmd = "amulet -substitute " + aig_file + " " + miter_tmp_file  + " " + rewritten_tmp_file + (is_signed? " -signed" : "");
        std::cout << "Running amulet: " << amulet_sub_cmd << std::endl;
        auto ret = system(amulet_sub_cmd.c_str());
        auto amulet_veri_cmd = "amulet -verify " + rewritten_tmp_file + (is_signed ? " -signed" : "");
        std::cout << "Running amulet: " << amulet_veri_cmd << std::endl;
        ret = system(amulet_veri_cmd.c_str());
         if(WEXITSTATUS(ret) != 1){
            log("Amulet Verify failed.\n");
            return false;
        }
        return true;
}

static bool check_extract_multi(RTLIL::Design* design, RTLIL::Module* mod, string& tempdir_name, std::vector<RTLIL::Module*> &multi_mods,
                                const string& lib_file){
    if(mod->get_bool_attribute(ID(multiplier))){
        multi_mods.push_back(mod);
        return check_multi(design, mod, tempdir_name, lib_file);
    }
    else 
    {
        auto log_files_backup = log_files;
        auto log_streams_backup = log_streams;
        log_files.clear();
	    log_streams.clear();
        run_pass(string("wreduce ") + mod->name.str(), design);
        extract_multi(design, mod);
        log_files = log_files_backup;
        log_streams = log_streams_backup;
    }
    return true;
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
    
    auto gold_mod = conf.gold_mod;
    auto gate_mod = conf.gate_mod;
    auto design = conf.design;

    // for(auto mod: design->modules()){
    //     if(mod!= gold_mod && mod != gate_mod){
    //         mod->set_bool_attribute(ID(blackbox), true);
    //     }
    // }
    auto gold_file = dump_blif_module(design, conf.tempdir_name, gold_mod, conf.lib_file);
    auto gate_file = dump_blif_module(design, conf.tempdir_name, gate_mod, conf.lib_file);

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


    string abc_cmd = //(has_dff) ? stringf("dsec %s %s", gold_file, gate_file) :
                                                stringf("cec %s %s", gold_file, gate_file);
    string cmd = stringf("%s -c '%s'", conf.abc_exe_file, abc_cmd);
    bool correct = false;
    log("Executing ABC command: '%s'\n", abc_cmd);
    bool abc_ret = exectue_and_check(cmd, correct, "Networks are equivalent");
    if (abc_ret != 0) {
        log_error("Error executing ABC command: %s\n", cmd);
    }
    return correct;
}
    

static bool abc_cec(const CheckConfig &conf){
    // find equivalence-checking pair
    auto design = conf.design;

    vector<std::pair<RTLIL::IdString, RTLIL::IdString>> equiv_mods;

    for( auto mod : design->modules()){
        if (mod->name.begins_with(RTLIL::escape_id(conf.gold_prefix)) ||
            mod->name == conf.gold_mod->name ) {
            RTLIL::IdString original_name = 
                mod->name == conf.gold_mod->name ? 
                conf.gold_mod->name :
                RTLIL::escape_id(strip_backslash(mod->name).substr(conf.gold_prefix.size()));
            
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
        .seq_check_cfg = conf.seq_check_cfg
    };

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
        
        if(!cec_result){
            log("\nGUIDE_CHECK failed for module pair: gold=%s vs gate=%s\n", 
                log_id(gold_name), log_id(gate_name));
            return false;
        }
        else 
        {
            log("\nGUIDE_CHECK passed for module pair: gold=%s vs gate=%s\n", 
                log_id(gold_name), log_id(gate_name));
        }


    }
    
    return true;    
}
// static bool abc_dsec(const CheckConfig &conf){
//     return abc_check(conf, true, "dsec");
// }

static bool bmcinduct_check(const CheckConfig &conf){
    std::string gold_name = strip_backslash(conf.gold_mod->name);
    std::string gate_name = strip_backslash(conf.gate_mod->name);

    auto smt2_file = dump_smt2(conf.design, conf.tempdir_name, {conf.gold_mod, conf.gate_mod},  conf.lib_file);

    string cmd = proc_self_dirname() + proc_program_prefix() + "yosys-smtbmc ";

    if(conf.seq_check_cfg.no_init){
        cmd += "-noinit ";
    }
    cmd += "-m " + gold_name + "_vs_" + gate_name + " ";
    
    if(conf.seq_check_cfg.weak_mode){
        cmd += "-i -t ";
        cmd += std::to_string(conf.seq_check_cfg.step_skip) + ":" + std::to_string(conf.seq_check_cfg.k_induct) + " ";
        
        int ret = exec_cmd(cmd + smt2_file);
        if(ret != 0){
            log("BMC-Induct failed in weak mode.\n");
            return false;
        }
        return true;
    }

    // BMC + K-Induct
    string cmd_bmc = cmd;

    cmd_bmc += " -t " + std::to_string(conf.seq_check_cfg.step_skip) + ":" + std::to_string(conf.seq_check_cfg.k_induct) + " ";
    int ret = exec_cmd(cmd_bmc + smt2_file);
    if(ret != 0){
        log("BMC-Induct failed in BMC phase.\n");
        return false;
    }
    string cmd_induct = cmd;
    cmd_induct += " -i -t "  + std::to_string(conf.seq_check_cfg.k_induct) + " "; 
    ret = exec_cmd(cmd_induct + smt2_file);
    if(ret != 0){
        log("BMC-Induct failed in Induct phase.\n");
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



bool check_retime(const CheckConfig &conf,
                  std::set<std::pair<RTLIL::IdString, RTLIL::IdString>>&retimed_mods)
{
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

        bool final_result = true;

        for (auto mod_pair : retimed_mods)
        {
            auto gold_name = mod_pair.first;
            auto gate_name = mod_pair.second;
            auto gold_m = conf.design->module(gold_name);
            auto gate_m = conf.design->module(gate_name);
            if (!gold_m || !gate_m) {
                log_warning("Skipping retime check for missing module pair: gold=%s vs gate=%s\n",
                    log_id(gold_name), log_id(gate_name));
                final_result = false;
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
                .seq_check_cfg = conf.seq_check_cfg
            };

            //bool dsec_result = abc_dsec(conf_);
            bool dsec_result = bmcinduct_check(conf_);

            if(!dsec_result)
            {
                log("\nGUIDE_CHECK_RETIME failed for module pair: gold=%s vs gate=%s\n", 
                    log_id(gold_name), log_id(gate_name));
                final_result = false;
                break;
            }
            else 
            {
                log("\nGUIDE_CHECK_RETIME passed for module pair: gold=%s vs gate=%s\n", 
                    log_id(gold_name), log_id(gate_name));
            }
            
            
        }

        return final_result;
}


bool check_extract_retime(const CheckConfig &conf)
{

    std::set<std::pair<RTLIL::IdString, RTLIL::IdString>> retimed_mods;

    bool check_result = check_retime(conf, retimed_mods);
    
    std::set<RTLIL::IdString> blackbox_mods;


    for (auto mod_pair : retimed_mods)
    {
        for (auto mod_name : {mod_pair.first, mod_pair.second})
        {
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

    return check_result;
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
        for(auto mod : modules)
        {
            log("Checking module %s for multiplier extraction.\n", mod->name.str());
            bool multi_result = false;
            multi_result = check_extract_multi(design, mod, tempdir_name, multi_mods, lib_file);
            if(!multi_result)
            {
                log("\nGUIDE_CHECK_MULTI failed for module %s.\n", log_id(mod->name));
            }
            else 
            {
                log("\nGUIDE_CHECK_MULTI passed for module %s.\n", log_id(mod->name));
            }
        }

        (void)multi_mods;
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
        
        bool result = check_extract_retime(CheckConfig{
            nocleanup,
            abc_exe_file,
            tempdir_name,
            design,
            gold_mod,
            gate_mod,
            gold_prefix,
            gate_prefix,
            lib_file,
            SeqCheckConfig{
                k_induct,
                step_skip,
                weak_mode,
                no_init
            }
        });

        if(!nocleanup){
            remove_directory(tempdir_name);
        }

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
            break;
        }

        auto design_backup = design; 
        
        design = clone_design_for_passes(design_backup);

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

        string tempdir_name;
        if(nocleanup)
            tempdir_name = "_tmp_";
        else
            tempdir_name = get_base_tmpdir() + "/";
        
        tempdir_name += proc_program_prefix() + "yosys-guide-check-XXXXXX";
        tempdir_name = make_temp_dir(tempdir_name);
        log("Creating temporary directory %s for GUIDE_CHECK pass.\n", tempdir_name);

        SeqCheckConfig seq_conf = {
            .k_induct = k_induct,
            .step_skip = step_skip,
            .weak_mode = weak_mode,        
            .no_init = no_init,
        };

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
            .seq_check_cfg = seq_conf,
        };

        bool multi_result = false, cec_result = false, retime_result;
        
        run_pass("proc", design);

        std::vector<RTLIL::Module*> multi_mods;
        auto all_mods = design->all_selected_modules();
        for(auto mod : all_mods)
        {
            multi_result = check_extract_multi(design, mod, tempdir_name, multi_mods, lib_file);
            if(!multi_result)
            {
                log("GUIDE_CHECK multi-module check failed.\n");
                goto check_failed;
            }
        }
        log("GUIDE_CHECK multi-module check passed.\n");

        (void)multi_mods;

        retime_result = check_extract_retime(conf);

        if(!retime_result)
        {
            log("GUIDE_CHECK retime check failed.\n");
            goto check_failed;
        }
        log("GUIDE_CHECK retime check passed.\n");


        cec_result = abc_cec(conf);
        if(!cec_result)
        {
            log("GUIDE_CHECK cec check failed.\n");
            goto check_failed;
        }

        log("\nGUIDE_CHECK PASSED: Modules %s and %s are equivalent.\n", 
            log_id(gold_mod->name), log_id(gate_mod->name));
        
        goto end_pass;

check_failed:
        if(assert_mode)
        {
            log_cmd_error("\nGUIDE_CHECK FAILED: Modules %s and %s are NOT equivalent.\n", 
                log_id(gold_mod->name), log_id(gate_mod->name));
        }
        else
        {
            log("\nGUIDE_CHECK FAILED: Modules %s and %s are NOT equivalent.\n", 
                log_id(gold_mod->name), log_id(gate_mod->name));
        }
end_pass:
        if (!conf.nocleanup) {
			log("Removing temp directory.\n");
			remove_directory(conf.tempdir_name);
		}

        delete design;
        design = design_backup;
        log_pop();
	}
} GuideCheckPass;


PRIVATE_NAMESPACE_END
