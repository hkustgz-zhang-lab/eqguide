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

USING_YOSYS_NAMESPACE
PRIVATE_NAMESPACE_BEGIN


struct GuideRetimePass : public Pass {
	GuideRetimePass() : Pass("guide_retime", "mark selected modules with the `retime` attribute.") { }
	void help() override
	{
		//   |---v---|---v---|---v---|---v---|---v---|---v---|---v---|---v---|---v---|---v---|
        log("\n");
        log("    guide_retime [options] [selection]\n");
        log("\n");
        log("This pass marks the selected modules by setting the `retime` attribute.\n");
        log("\n");
        log("    -unmark\n");
		log("        Unmark selected modules with the `retime` attribute.\n");

	}
	void execute(std::vector<std::string> args, RTLIL::Design *design) override
	{
        log_header(design, "Executing GUIDE_RETIME pass.\n");
        log_push();
        bool unmark = false;
		size_t argidx;
		for (argidx = 1; argidx < args.size(); argidx++)
		{
            if (args[argidx] == "-unmark") 
            {
                unmark = true;
                continue;
            }
            break;
		}
		extra_args(args, argidx, design);

        for (auto module : design->all_selected_modules()){
            if(unmark)
            {
                log("Module %s: remove attribute retime\n", module->name);
                module->attributes.erase(ID(retime));
                continue;
            }
            else 
            {
                log("Module %s: set attribute retime=1\n", module->name);
                module->attributes[ID(retime)] = RTLIL::Const(1);
            }
            
        }

        log_pop();
	}
} GuideRetimePass;


PRIVATE_NAMESPACE_END
