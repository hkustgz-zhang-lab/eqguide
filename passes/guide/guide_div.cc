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

static inline string uniq_div_module_name(RTLIL::Module *module, int idx)
{
    return stringf("div_%s_%d", RTLIL::unescape_id(module->name), idx);
}

static int wrap_div_in_module(RTLIL::Module *module)
{
    int cnt = 0;
    RTLIL::Design *design = module->design;

    std::vector<RTLIL::Cell*> div_cells;
    for (auto cell : module->selected_cells()) {
        if (cell->type == ID($div))
            div_cells.push_back(cell);
    }

    for (auto cell : div_cells)
    {
        RTLIL::IdString inst_name = cell->name;
        RTLIL::SigSpec origA = cell->getPort(ID::A);
        RTLIL::SigSpec origB = cell->getPort(ID::B);
        RTLIL::SigSpec origY = cell->getPort(ID::Y);
        dict<RTLIL::IdString, RTLIL::Const> orig_params = cell->parameters;
        dict<RTLIL::IdString, RTLIL::Const> orig_attrs  = cell->attributes;

        if(orig_params[ID::A_SIGNED].as_bool() != orig_params[ID::B_SIGNED].as_bool()){
            log_warning("$div cell %s has mismatched signedness between A and B ports. Skipping wrapping.\n", log_id(inst_name));
            continue;
        }

        bool is_signed = orig_params[ID::A_SIGNED].as_bool();

        if(origA.size()!=origB.size()){
            log_warning("$div cell %s has mismatched widths between A and B ports. Skipping wrapping.\n", log_id(inst_name));
            continue;
        }

        int aw = origA.size();
        int bw = origB.size();
        int yw = origY.size();

        string base = uniq_div_module_name(module, cnt);
        RTLIL::IdString new_mod_id = RTLIL::escape_id(base);

        int suffix = 0;
        while (design->module(new_mod_id) != nullptr) {
            new_mod_id = RTLIL::escape_id(base + stringf("_%d", ++suffix));
        }

        log("Wrapping $div cell %s in module %s\n",
            log_id(inst_name), log_id(new_mod_id));

        RTLIL::Module *new_mod = new RTLIL::Module;
        new_mod->name = new_mod_id;

        new_mod->attributes[ID(divider)] = RTLIL::Const(1);
        new_mod->attributes[ID(is_signed)]     = RTLIL::Const(is_signed ? 1 : 0);

        RTLIL::Wire *in_a  = new_mod->addWire(ID::A, aw);
        RTLIL::Wire *in_b  = new_mod->addWire(ID::B, bw);
        RTLIL::Wire *out_y = new_mod->addWire(ID::Y, yw);
        RTLIL::Wire *out_r = new_mod->addWire(ID::R, bw);

        in_a->port_id = 1;  in_a->port_input  = true;
        in_b->port_id = 2;  in_b->port_input  = true;
        out_y->port_id = 3; out_y->port_output = true;
        out_r->port_id = 4; out_r->port_output = true;

        RTLIL::Cell *inner = new_mod->addCell(ID(div_inst), ID($div));
        inner->parameters = orig_params;
        inner->attributes = orig_attrs;

        inner->setPort(ID::A, RTLIL::SigSpec(in_a));
        inner->setPort(ID::B, RTLIL::SigSpec(in_b));
        inner->setPort(ID::Y, RTLIL::SigSpec(out_y));

        RTLIL::Cell *mod_cell = new_mod->addCell(ID(mod_inst), ID($mod));
        mod_cell->parameters = orig_params;
        mod_cell->setPort(ID::A, RTLIL::SigSpec(in_a));
        mod_cell->setPort(ID::B, RTLIL::SigSpec(in_b));
        mod_cell->setPort(ID::Y, RTLIL::SigSpec(out_r));

        new_mod->fixup_ports();

        design->add(new_mod);

        module->remove(cell);

        RTLIL::SigSpec origR;
        origR.extend_u0(bw, false);
        RTLIL::Wire *r_wire = module->addWire(module->uniquify(stringf("%s_R", RTLIL::unescape_id(inst_name))), bw);
        origR = RTLIL::SigSpec(r_wire);

        RTLIL::Cell *mod_inst = module->addCell(inst_name, new_mod->name);
        mod_inst->setPort(ID::A, origA);
        mod_inst->setPort(ID::B, origB);
        mod_inst->setPort(ID::Y, origY);
        mod_inst->setPort(ID::R, origR);

        mod_inst->attributes = orig_attrs;

        cnt++;
    }

    return cnt;
}

struct GuideDivPass : public Pass {
    GuideDivPass() : Pass("guide_div", "wrap $div cells; mark/unmark divider modules.") { }
    void help() override
    {
        //   |---v---|---v---|---v---|---v---|---v---|---v---|---v---|---v---|---v---|---v---|
        log("\n");
        log("    guide_div [options] [selection]\n");
        log("\n");
        log("Description:\n");
        log("    Wrap each selected $div cell into its own wrapper module, and replace the\n");
        log("    original $div cell with an instance of that wrapper module.\n");
        log("\n");
        log("    Modules marked with (* divider=1 *) are treated as \"divider modules\"\n");
        log("    and will be skipped during wrapping.\n");
        log("\n");
        log("Options:\n");
        log("    -mark\n");
        log("        Set (* divider=1 *) on the selected modules, then exit.\n");
        log("\n");
        log("    -unmark\n");
        log("        Remove (* divider *) from the selected modules, then exit.\n");
        log("\n");
        log("    -mark-mod <modname>\n");
        log("        Set (* divider=1 *) on the named module.\n");
        log("\n");
        log("    -unmark-mod <modname>\n");
        log("        Remove (* divider *) from the named module.\n");
        log("\n");
    }
    void execute(std::vector<std::string> args, RTLIL::Design *design) override
    {
        log_header(design, "Executing GUIDE_DIV pass (wrap $div cells to modules).\n");
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
                m->attributes[ID(divider)] = RTLIL::Const(1);
                log("Marked module %s as (* divider=1 *).\n", log_id(m->name));
            } else {
                log_warning("No such module: %s\n", log_id(id));
            }
        }
        for (auto id : unmark_mods) {
            if (auto m = design->module(id)) {
                m->attributes.erase(ID(divider));
                log("Unmarked module %s (removed (* divider *)).\n", log_id(m->name));
            } else {
                log_warning("No such module: %s\n", log_id(id));
            }
        }

        if(do_mark || do_unmark)
        {
            for (auto module : design->all_selected_modules())
            {
                if(do_mark) {
                    log("Module %s: set attribute divider=1\n", module->name);
                    module->attributes[ID(divider)] = RTLIL::Const(1);
                }
                if(do_unmark) {
                    log("Module %s: remove attribute divider\n", module->name);
                    module->attributes.erase(ID(divider));
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
            if(module->get_bool_attribute(ID(divider)))
            {
                log("Module %s is marked as divider module, skip wrapping $div cells inside.\n", module->name);
                continue;
            }

            run_pass(stringf("wreduce %s", RTLIL::unescape_id(module->name)), design);

            int cnt = wrap_div_in_module(module);
            log("Module %s: wrapped %d $div cells\n", module->name, cnt);
        }
        log_pop();
    }
} GuideDivPass;

PRIVATE_NAMESPACE_END
