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


struct PrintModulesPass : public Pass {
	PrintModulesPass() : Pass("print_modules", "print modules.") { }
	void help() override
	{
		//   |---v---|---v---|---v---|---v---|---v---|---v---|---v---|---v---|---v---|---v---|
        log("\n");
        log("    print_modules\n");
        log("\n");

	}
	void execute(std::vector<std::string> args, RTLIL::Design *design) override
	{
        log_header(design, "Executing PRINT_MODULES pass.\n");
        log_push();
		size_t argidx;
		for (argidx = 1; argidx < args.size(); argidx++)
		{
            break;
		}
		extra_args(args, argidx, design);

        for (auto module : design->modules())
        {
            log("Module name: %s, blackbox: %s\n", module->name, 
                    module->get_bool_attribute(ID(blackbox)) ? "true" : "false");
        }

        log_pop();
	}
} PrintModulesPass;


PRIVATE_NAMESPACE_END
