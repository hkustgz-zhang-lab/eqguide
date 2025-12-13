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
#include <vector>

USING_YOSYS_NAMESPACE
PRIVATE_NAMESPACE_BEGIN

static inline string uniq_mul_module_name(RTLIL::Module *module, int idx)
{
    return stringf("mul_%s_%d", RTLIL::unescape_id(module->name), idx);
}

static int wrap_mul_in_module(RTLIL::Module *module)
{
    int cnt = 0;
    RTLIL::Design *design = module->design;

    std::vector<RTLIL::Cell*> mul_cells;
    for (auto cell : module->selected_cells()) {
        if (cell->type == ID($mul))
            mul_cells.push_back(cell);
    }

    for (auto cell : mul_cells)
    {
        RTLIL::IdString inst_name = cell->name;
        RTLIL::SigSpec origA = cell->getPort(ID::A);
        RTLIL::SigSpec origB = cell->getPort(ID::B);
        RTLIL::SigSpec origY = cell->getPort(ID::Y);
        dict<RTLIL::IdString, RTLIL::Const> orig_params = cell->parameters;
        dict<RTLIL::IdString, RTLIL::Const> orig_attrs  = cell->attributes;

        int aw = origA.size();
        int bw = origB.size();
        int yw = origY.size();

        // int aw = orig_params.count(ID::A_WIDTH) ? orig_params.at(ID::A_WIDTH).as_int() : origA.size();
        // int bw = orig_params.count(ID::B_WIDTH) ? orig_params.at(ID::B_WIDTH).as_int() : origB.size();
        // int yw = orig_params.count(ID::Y_WIDTH) ? orig_params.at(ID::Y_WIDTH).as_int() : origY.size();

        string base = uniq_mul_module_name(module, cnt);
        RTLIL::IdString new_mod_id = RTLIL::escape_id(base);

        int suffix = 0;
        while (design->module(new_mod_id) != nullptr) {
            new_mod_id = RTLIL::escape_id(base + stringf("_%d", ++suffix));
        }

        log("Wrapping $mul cell %s in module %s\n",
            log_id(inst_name), log_id(new_mod_id));

        RTLIL::Module *new_mod = new RTLIL::Module;
        new_mod->name = new_mod_id;

        new_mod->attributes[ID(multiplier)] = RTLIL::Const(1);
        new_mod->attributes[ID(keep_hierarchy)]    = RTLIL::Const(1);

        RTLIL::Wire *in_a  = new_mod->addWire(ID::A, aw);
        RTLIL::Wire *in_b  = new_mod->addWire(ID::B, bw);
        RTLIL::Wire *out_y = new_mod->addWire(ID::Y, yw);

        in_a->port_id = 1;  in_a->port_input  = true;
        in_b->port_id = 2;  in_b->port_input  = true;
        out_y->port_id = 3; out_y->port_output = true;


        RTLIL::Cell *inner = new_mod->addCell(ID(mul_inst), ID($mul));
        inner->parameters = orig_params;
        inner->attributes = orig_attrs;

        inner->setPort(ID::A, RTLIL::SigSpec(in_a));
        inner->setPort(ID::B, RTLIL::SigSpec(in_b));
        inner->setPort(ID::Y, RTLIL::SigSpec(out_y));

        new_mod->fixup_ports();

        design->add(new_mod);

        module->remove(cell);

        RTLIL::Cell *mod_inst = module->addCell(inst_name, new_mod->name);
        mod_inst->setPort(ID::A, origA);
        mod_inst->setPort(ID::B, origB);
        mod_inst->setPort(ID::Y, origY);

        mod_inst->attributes = orig_attrs;
        mod_inst->attributes[ID(keep_hierarchy)] = RTLIL::Const(1);

        cnt++;
    }

    return cnt;
}
struct GuideMultiPass : public Pass {
	GuideMultiPass() : Pass("guide_multi", "wrap $mul cells to a modules") { }
	void help() override
	{
		//   |---v---|---v---|---v---|---v---|---v---|---v---|---v---|---v---|---v---|---v---|
		log("\n");
		log("    guide_multi [selection]\n");
		log("\n");
		log("Warp $mul cells to modules\n");
		log("\n");
	}
	void execute(std::vector<std::string> args, RTLIL::Design *design) override
	{
        log_header(design, "Executing GUIDE_MULTI pass (wrap $mul cells to modules).\n");
        log_push();
		size_t argidx;
		for (argidx = 1; argidx < args.size(); argidx++)
		{
			break;
		}
		extra_args(args, argidx, design);


		for (auto module : design->all_selected_modules())
		{
            if(module->get_bool_attribute(ID(multiplier)))
            {
                log("Module %s is marked as multiplier module, skip wrapping $mul cells inside.\n", module->name);
                continue;
            }
            
            int cnt = wrap_mul_in_module(module);
            log("Module %s: wrapped %d $mul cells\n", module->name, cnt);
		}
        log_pop();
	}
} GuideMultiPass;


PRIVATE_NAMESPACE_END
