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
#include <cmath>
#include <string>
#include <vector>

USING_YOSYS_NAMESPACE
PRIVATE_NAMESPACE_BEGIN


struct CecConfig
{
    bool nocleanup = false;
    std::string exe_file;
    RTLIL::Design *design = nullptr;
    RTLIL::Module *gold_mod = nullptr;
    RTLIL::Module *gate_mod = nullptr;
};

bool check_multi(){
    return true;
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


static string dump_aig(RTLIL::Design* design, string &dir_name, RTLIL::Module *mod){
    string filename = dir_name + "/" 
        + (mod->name.str()[0] == '\\' ? mod->name.str().substr(1): mod->name.str())
        + ".aig";
    log("Dumping module %s to AIG file %s.\n", mod->name.str(), filename);
    
    auto log_files_backup = log_files;
    auto log_streams_backup = log_streams;
    log_files.clear();
	log_streams.clear();
    run_pass(stringf("flatten %s", mod->name.str()), design);
    run_pass(stringf("proc %s", mod->name.str()), design);
    run_pass(stringf("techmap %s", mod->name.str()), design);
    run_pass(stringf("aigmap %s", mod->name.str()), design);
    run_pass(stringf("select %s", mod->name.str()), design);
    run_pass(stringf("write_aiger %s", filename), design);
    run_pass(stringf("select -clear"), design);
    log_files = log_files_backup;
    log_streams = log_streams_backup;
    return filename;
}

bool abc_cec(const CecConfig &conf){
    auto gold_mod = conf.gold_mod;
    auto gate_mod = conf.gate_mod;
    string tempdir_name;

    if(conf.nocleanup)
        tempdir_name = "_tmp_";
    else
        tempdir_name = get_base_tmpdir() + "/";
    
    tempdir_name += proc_program_prefix() + "yosys-guide-check-XXXXXX";
    tempdir_name = make_temp_dir(tempdir_name);
    log("Creating temporary directory %s for GUIDE_CHECK pass.\n", tempdir_name);

    string gold_aig = dump_aig(conf.design, tempdir_name, gold_mod);
    string gate_aig = dump_aig(conf.design, tempdir_name, gate_mod);

    string abc_cmd = stringf("cec %s %s", gold_aig, gate_aig);
    string cmd = stringf("%s -c '%s'", conf.exe_file, abc_cmd);
    bool correct = false;

    log("Executing ABC command: '%s'\n", abc_cmd);
    bool abc_ret = exectue_and_check(cmd, correct, "Networks are equivalent");
    if (abc_ret != 0) {
        log_error("Error executing ABC command: %s\n", cmd);
    }
    
    return correct;
}

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
        string exe_file = design->scratchpad_get_string("abc.exe", yosys_abc_executable);

        size_t argidx;
        for (argidx = 1; argidx < args.size(); argidx++)
        {
            if (args[argidx] == "-nocleanup") {
                nocleanup = true;
                continue;
            }
            if (args[argidx] == "-exe" && argidx+1 < args.size()) {
                exe_file = args[++argidx];
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

        CecConfig conf = {
            .nocleanup = nocleanup,
            .exe_file = exe_file,
            .design = design,
            .gold_mod = gold_mod,
            .gate_mod = gate_mod,
        };

        auto cec_result = abc_cec(conf);
        log("\n");
        if (cec_result) {
            log("GUIDE_CHECK PASSED: Modules %s and %s are equivalent.\n", 
                log_id(gold_mod->name), log_id(gate_mod->name));
        } else {
            if(assert_mode)
            {
                log_error("GUIDE_CHECK FAILED: Modules %s and %s are NOT equivalent.\n", 
                    log_id(gold_mod->name), log_id(gate_mod->name));
            }
            else
            {
                log("GUIDE_CHECK FAILED: Modules %s and %s are NOT equivalent.\n", 
                    log_id(gold_mod->name), log_id(gate_mod->name));
            }
        }

        log_pop();
	}
} GuideCheckPass;


PRIVATE_NAMESPACE_END
