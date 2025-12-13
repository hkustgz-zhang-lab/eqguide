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

#include "kernel/register.h"
#include "kernel/rtlil.h"
#include "kernel/log.h"
#include "kernel/yosys.h"
#include <cassert>
#include <cmath>
#include <cstdlib>
#include <string>
#include <vector>

USING_YOSYS_NAMESPACE
PRIVATE_NAMESPACE_BEGIN


struct CheckConfig
{
    bool nocleanup = false;
    std::string abc_exe_file;
    std::string tempdir_name;
    RTLIL::Design *design = nullptr;
    RTLIL::Module *gold_mod = nullptr;
    RTLIL::Module *gate_mod = nullptr;
};

static std::string strip_backslash(const RTLIL::IdString &id)
{
    std::string s = id.str();
    if (!s.empty() && s[0] == '\\') s = s.substr(1);
    return s;
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
        // std::cout<< buffer;
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


static bool is_multiplier_cell(RTLIL::Design *design, RTLIL::Cell *cell)
{
    if (cell->type == ID($mul))
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


// 选两个“操作数”信号：$mul 用 A/B；子模块就取前两个 input port
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
        // 按 port_id 找 input ports
        std::vector<RTLIL::Wire*> ins;
        for (auto *w : sub->wires())
            if (w->port_id > 0 && w->port_input)
                ins.push_back(w);
        std::sort(ins.begin(), ins.end(),
                  [](RTLIL::Wire *a, RTLIL::Wire *b){ return a->port_id < b->port_id; });

        if (ins.size() >= 1 && cell->hasPort(ins[0]->name)) op1 = cell->getPort(ins[0]->name);
        if (ins.size() >= 2 && cell->hasPort(ins[1]->name)) op2 = cell->getPort(ins[1]->name);
    }

    // 兜底：没找到就尽量用 A/B/Y
    if (!op1.size() && cell->hasPort(ID::A)) op1 = cell->getPort(ID::A);
    if (!op2.size() && cell->hasPort(ID::B)) op2 = cell->getPort(ID::B);

    // 再兜底：只有一个操作数就 op2=op1；都没有就用常 0
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
        // 子模块：把每个 output port 都驱动成同一个交换律 stub
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
            // fallback：常见 Y
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




static void v2aig(const string& v_file, const string& aig_file, const string& mod_name){
    auto yosys_exe_file = proc_self_dirname() + "yosys";
    string cmd = stringf("%s -p 'read_verilog %s; hierarchy -top %s; synth -flatten -flatten; aigmap; write_aiger %s'", 
                        yosys_exe_file, v_file, mod_name, aig_file);
    system(cmd.c_str());
}


static string dump_aig(RTLIL::Design* design, const string &dir_name, RTLIL::Module *mod){
    string aig_file = dir_name + "/" 
        + strip_backslash(mod->name)
        + ".aig";
    string v_file = dir_name + "/" 
        + strip_backslash(mod->name)
        + ".v";
    log("Dumping module %s to AIG file %s.\n", mod->name.str(), aig_file);
    
    auto log_files_backup = log_files;
    auto log_streams_backup = log_streams;

    // log_files.clear(); // TODO: Maybe it's not a good ieda... 
	// log_streams.clear(); // TODO: We can not see any log...

    run_pass(stringf("flatten %s", mod->name.str()), design); // TODO: flatten all dependencies?
    run_pass(stringf("select %s", mod->name.str()), design);  // TODO: select all dependencies?
    run_pass(stringf("write_verilog -selected %s", v_file), design);
    run_pass(stringf("select -clear"), design);
    v2aig(v_file, aig_file, strip_backslash(mod->name));
    log_files = log_files_backup;
    log_streams = log_streams_backup;
    return aig_file;
}


static bool check_multi(RTLIL::Design* design, RTLIL::Module* mod, string& tempdir_name){
    log_assert(mod->get_bool_attribute(ID(multiplier)));
    bool is_signed = mod->get_bool_attribute(ID(is_signed));    
    auto aig_file = dump_aig(design, tempdir_name, mod);

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
                // return;
            return false;
        }
        return true;
}

static bool check_extract_multi(RTLIL::Design* design, RTLIL::Module* mod, string& tempdir_name, std::vector<RTLIL::Module*> &multi_mods){
    if(mod->get_bool_attribute(ID(multiplier))){
        multi_mods.push_back(mod);
        return check_multi(design, mod, tempdir_name);
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


bool abc_cec(CheckConfig &conf){
    auto gold_mod = conf.gold_mod;
    auto gate_mod = conf.gate_mod;


    string gold_aig = dump_aig(conf.design, conf.tempdir_name, gold_mod);
    string gate_aig = dump_aig(conf.design, conf.tempdir_name, gate_mod);

    string abc_cmd = stringf("cec %s %s", gold_aig, gate_aig);
    string cmd = stringf("%s -c '%s'", conf.abc_exe_file, abc_cmd);
    bool correct = false;

    log("Executing ABC command: '%s'\n", abc_cmd);
    bool abc_ret = exectue_and_check(cmd, correct, "Networks are equivalent");
    if (abc_ret != 0) {
        log_error("Error executing ABC command: %s\n", cmd);
    }
    
    return correct;
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
    }
    void execute(std::vector<std::string> args, RTLIL::Design *design) override
    {
        log_header(design, "Executing GUIDE_CHECK_MULTI pass.\n");
        log_push();
        string mod_name;

        size_t argidx;
        for (argidx = 1; argidx < args.size(); argidx++)
        {
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
            multi_result = check_extract_multi(design, mod, tempdir_name, multi_mods);
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

struct GuideCheckPass : public Pass {
	GuideCheckPass() : Pass("guide_check", "equivalence checking using verfication guide information.") { }
	void help() override
	{
		//   |---v---|---v---|---v---|---v---|---v---|---v---|---v---|---v---|---v---|---v---|
        log("\n");
        log("    guide_check [options] gold_module gate_module\n");
        log("\n");
        log("This pass compares two modules using the verification guide information.\n");
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
	}
	void execute(std::vector<std::string> args, RTLIL::Design *design) override
	{
        log_header(design, "Executing GUIDE_CHECK pass.\n");
        log_push();
        string gold_mod_name, gate_mod_name;
        bool nocleanup = false;
        bool assert_mode = false;
        string abc_exe_file = design->scratchpad_get_string("abc.exe", yosys_abc_executable);

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
            break;
        }

        if (argidx + 2 != args.size())
            log_cmd_error("Wrong number of arguments for guide_check pass.\n");
        
        gold_mod_name = args[argidx];
        gate_mod_name = args[argidx+1];

        RTLIL::Module *gold_mod = design->module(RTLIL::escape_id(gold_mod_name));
        RTLIL::Module *gate_mod = design->module(RTLIL::escape_id(gate_mod_name));
        if (gold_mod == nullptr)
            log_cmd_error("Can't find gold module %s.\n", gold_mod_name);
        if (gate_mod == nullptr)
            log_cmd_error("Can't find gate module %s.\n", gate_mod_name);

        string tempdir_name;
        if(nocleanup)
            tempdir_name = "_tmp_";
        else
            tempdir_name = get_base_tmpdir() + "/";
        
        tempdir_name += proc_program_prefix() + "yosys-guide-check-XXXXXX";
        tempdir_name = make_temp_dir(tempdir_name);
        log("Creating temporary directory %s for GUIDE_CHECK pass.\n", tempdir_name);

        CheckConfig conf = {
            .nocleanup = nocleanup,
            .abc_exe_file = abc_exe_file,
            .tempdir_name = tempdir_name,
            .design = design,
            .gold_mod = gold_mod,
            .gate_mod = gate_mod,
        };

        bool multi_result = false, cec_result = false;
        
        // multi_result = check_multi(conf);
        // if(!multi_result)
        // {
        //     log("GUIDE_CHECK multi-module check failed.\n");
        //     goto check_failed;
        // }

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
            log_error("\nGUIDE_CHECK FAILED: Modules %s and %s are NOT equivalent.\n", 
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
        log_pop();
	}
} GuideCheckPass;


PRIVATE_NAMESPACE_END
