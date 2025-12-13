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

        if(orig_params[ID::A_SIGNED].as_bool() != orig_params[ID::B_SIGNED].as_bool()){
            log_warning("$mul cell %s has mismatched signedness between A and B ports. Skipping wrapping.\n", log_id(inst_name));
            log_assert(0); // TODO: 
            continue;
        }

        bool is_signed = orig_params[ID::A_SIGNED].as_bool();

        if(origA.size()!=origB.size()){
            log_warning("$mul cell %s has mismatched widths between A and B ports. Skipping wrapping.\n", log_id(inst_name));
            log_assert(0); // TODO:
            continue;
        }

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
        new_mod->attributes[ID(is_signed)]     = RTLIL::Const(is_signed ? 1 : 0);
        // new_mod->attributes[ID(keep_hierarchy)]    = RTLIL::Const(1);

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
        // mod_inst->attributes[ID(keep_hierarchy)] = RTLIL::Const(1);

        cnt++;
    }

    return cnt;
}
struct GuideMultiPass : public Pass {
	GuideMultiPass() : Pass("guide_multi", "wrap $mul cells; mark/unmark multiplier modules.") { }
	void help() override
	{
		//   |---v---|---v---|---v---|---v---|---v---|---v---|---v---|---v---|---v---|---v---|
        log("\n");
        log("    guide_multi [options] [selection]\n");
        log("\n");
        log("Description:\n");
        log("    Wrap each selected $mul cell into its own wrapper module, and replace the\n");
        log("    original $mul cell with an instance of that wrapper module.\n");
        log("\n");
        log("    Modules marked with (* multiplier=1 *) are treated as \"multiplier modules\"\n");
        log("    and will be skipped during wrapping.\n");
        log("\n");
        log("Behavior:\n");
        log("    - With no options, wrap $mul cells in the selected modules.\n");
        log("    - With -mark/-unmark, only set/unset the attribute on selected modules.\n");
        log("    - With -mark-mod/-unmark-mod, only set/unset the attribute on named modules.\n");
        log("\n");
        log("Options:\n");
        log("    -mark\n");
        log("        Set (* multiplier=1 *) on the selected modules, then exit.\n");
        log("\n");
        log("    -unmark\n");
        log("        Remove (* multiplier *) from the selected modules, then exit.\n");
        log("\n");
        log("    -mark-mod <modname>\n");
        log("        Set (* multiplier=1 *) on the named module.\n");
        log("\n");
        log("    -unmark-mod <modname>\n");
        log("        Remove (* multiplier *) from the named module.\n");
        log("\n");
        log("Examples:\n");
        log("    # Wrap $mul in top (and its selected submodules, if any)\n");
        log("    guide_multi top\n");
        log("\n");
        log("    # Mark mul_core as a multiplier module (skip wrapping inside it)\n");
        log("    guide_multi -mark-mod mul_core\n");
        log("\n");
        log("    # Mark selected modules as multiplier modules\n");
        log("    select -module mul_core; guide_multi -mark\n");
        log("\n");

	}
	void execute(std::vector<std::string> args, RTLIL::Design *design) override
	{
        log_header(design, "Executing GUIDE_MULTI pass (wrap $mul cells to modules).\n");
        log_push();

        bool do_mark = false;
        bool do_unmark = false;
        std::vector<RTLIL::IdString> mark_mods, unmark_mods;

		size_t argidx;
		for (argidx = 1; argidx < args.size(); argidx++)
		{
			if( args[argidx] == "-mark" ) {
                do_mark = true;
                continue;
            }
            if( args[argidx] == "-unmark" ) {
                do_unmark = true;
                continue;
            }
            if( args[argidx] == "-mark-mod" && argidx+1 < args.size() ) {
                mark_mods.push_back(RTLIL::escape_id(args[++argidx]));
                continue;
            }
            if( args[argidx] == "-unmark-mod" && argidx+1 < args.size() ) {
                unmark_mods.push_back(RTLIL::escape_id(args[++argidx]));
                continue;
            }
            break;
		}
		extra_args(args, argidx, design);

        for (auto id : mark_mods) {
            if (auto m = design->module(id)) {
                m->attributes[ID(multiplier)] = RTLIL::Const(1);
                log("Marked module %s as (* multiplier=1 *).\n", log_id(m->name));
            } else {
                log_warning("No such module: %s\n", log_id(id));
            }
        }
        for (auto id : unmark_mods) {
            if (auto m = design->module(id)) {
                m->attributes.erase(ID(multiplier));
                log("Unmarked module %s (removed (* multiplier *)).\n", log_id(m->name));
            } else {
                log_warning("No such module: %s\n", log_id(id));
            }
        }

        if(do_mark || do_unmark) 
        {
            for (auto module : design->all_selected_modules())
            {
                if(do_mark) {
                    log("Module %s: set attribute multiplier=1\n", module->name);
                    module->attributes[ID(multiplier)] = RTLIL::Const(1);
                }
                if(do_unmark) {
                    log("Module %s: remove attribute multiplier\n", module->name);
                    module->attributes.erase(ID(multiplier));
                }
            }
            log_pop();
            return;
        }

        if(mark_mods.size() > 0 || unmark_mods.size() > 0) {
            log_pop();
            return;
        }

		for (auto module : design->all_selected_modules())
		{
            if(module->get_bool_attribute(ID(multiplier)))
            {
                log("Module %s is marked as multiplier module, skip wrapping $mul cells inside.\n", module->name);
                continue;
            }

            run_pass(string("wreduce ") + log_id(module->name), design);

            int cnt = wrap_mul_in_module(module);
            log("Module %s: wrapped %d $mul cells\n", module->name, cnt);
		}
        log_pop();
	}
} GuideMultiPass;


PRIVATE_NAMESPACE_END
