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
#include <vector>


extern std::vector<std::string> designs;

USING_YOSYS_NAMESPACE
PRIVATE_NAMESPACE_BEGIN

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

struct GuideRetimePass : public Pass {
	GuideRetimePass() : Pass("guide_design_check", "Check the saved designs.") { }
	void help() override
	{
		//   |---v---|---v---|---v---|---v---|---v---|---v---|---v---|---v---|---v---|---v---|
        log("\n");
        log("    guide_design_check [options] [selection]\n");
        log("\n");
        log("This pass checks the saved design states for equivalence.\n");
        log("\n");
        log("    -lib <sim_lib.v>\n");
        log("        Simulation library.\n");
        log("\n");
        log("    -weak\n");
        log("        use weak sequential equivalence suitable for retiming:\n");
        log("        allow mismatch in early cycles; prove that once outputs are equal\n");
        log("        for K cycles they will never diverge (k-induction).\n");
        log("\n");
        log("    -nocleanup\n");
        log("        when this option is used, the temporary files created by this pass\n");
        log("        are not removed. this is useful for debugging.\n");
        log("\n");
	}
	void execute(std::vector<std::string> args, RTLIL::Design *design) override
	{
        log_header(design, "Executing GUIDE_DESIGN pass.\n");
        log_push();
		size_t argidx;
        string lib_file;
        bool weak_mode = false;
        bool nocleanup = false;
		for (argidx = 1; argidx < args.size(); argidx++)
		{
            if (args[argidx] == "-lib" && argidx + 1 < args.size()) {
                lib_file = args[++argidx];
                continue;
            }
            if (args[argidx] == "-weak") {
                weak_mode = true;
                continue;
            }
            if (args[argidx] == "-nocleanup") {
                nocleanup = true;
                continue;
            }
            break;
		}
		extra_args(args, argidx, design);
        
        auto design_backup = design;
        design = clone_design_for_passes(design_backup);

        for(size_t i = 0; i < designs.size() - 1; i ++)
        {
            string gold_name = designs[i];
            string gate_name = designs[i + 1];
            log("Checking design saved as %s against design saved as %s.\n", gold_name.c_str(), gate_name.c_str());
            run_pass("design -reset",design);
            run_pass("design -import " + gold_name, design);
            run_pass("design -import " + gate_name, design);
            string guide_check_cmd = "guide_check -assert";
            if(nocleanup)
                guide_check_cmd += " -nocleanup";
            if(!lib_file.empty())
                guide_check_cmd += " -lib " + lib_file;
            if(weak_mode)
                guide_check_cmd += " -weak";
            guide_check_cmd += " " + gold_name + " " + gate_name;
            run_pass(guide_check_cmd, design);
        }


        delete design;
        design = design_backup;
        log_pop();
	}
} GuideRetimePass;


PRIVATE_NAMESPACE_END
