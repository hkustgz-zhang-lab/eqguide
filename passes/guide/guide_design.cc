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

std::vector<std::string> designs;

USING_YOSYS_NAMESPACE
PRIVATE_NAMESPACE_BEGIN

struct GuideRetimePass : public Pass {
	GuideRetimePass() : Pass("guide_design", "Save the design.") { }
	void help() override
	{
		//   |---v---|---v---|---v---|---v---|---v---|---v---|---v---|---v---|---v---|---v---|
        log("\n");
        log("    guide_design [options] [selection]\n");
        log("\n");
        log("This pass saves the current design state. Prepare for further equivalence checking.\n");
        log("\n");
	}
	void execute(std::vector<std::string> args, RTLIL::Design *design) override
	{
        log_header(design, "Executing GUIDE_DESIGN pass.\n");
        log_push();
		size_t argidx;
		for (argidx = 1; argidx < args.size(); argidx++)
		{
            break;
		}
		extra_args(args, argidx, design);
        static int count = 0;
        
        string name = "guide_design_save_" + std::to_string(count);
        count ++;
        run_pass("design -save " + name);;
        designs.push_back(name);

        log_pop();
	}
} GuideRetimePass;


PRIVATE_NAMESPACE_END
