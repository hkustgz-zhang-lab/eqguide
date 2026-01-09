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

#include "kernel/celltypes.h"
#include "kernel/drivertools.h"
#include "kernel/mem.h"
#include "kernel/register.h"
#include "kernel/rtlil.h"
#include "kernel/log.h"
#include "kernel/ff.h"
#include "kernel/sigtools.h"
#include "kernel/yosys.h"
#include <cassert>
#include <cstddef>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <tuple>
#include <chrono>
#include "kernel/modtools.h"
#include <unordered_map>
#include <utility>
#include <vector>

USING_YOSYS_NAMESPACE
PRIVATE_NAMESPACE_BEGIN


#define TIMINGSTAT_FIELDS(X)            \
    X(abc_cec_ms)                       \
    X(prep_ms)                          \
    X(dump_blif_ms)                     \
    X(read_lib_ms)

struct TimingStat {
#define DECL_FIELD(name) std::uint64_t name = 0;
    TIMINGSTAT_FIELDS(DECL_FIELD)
#undef DECL_FIELD

    TimingStat() {}
};

TimingStat timing_stat;

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
    RTLIL::Design *lib_design = nullptr;
};

struct ModMap{
    dict<RTLIL::IdString, RTLIL::IdString> mod_map_gold; // gold -> gate
    dict<RTLIL::IdString, RTLIL::IdString> mod_map_gate; // gate -> gold
    pool<RTLIL::IdString> mapped_mods_gold;
    pool<RTLIL::IdString> mapped_mods_gate;
    pool<RTLIL::IdString> unmapped_mods_gate;
    pool<RTLIL::IdString> unmapped_mods_gold;
};


#define MATCHTYPE_FIELDS(X)       \
    X(NONE)                       \
    X(PO)                         \
    X(PI)                         \
    X(DFF)                        \
    X(DFF_PO)                     \
    X(SUBCKT_PIPO)

enum class MatchType {
#define DECL_FIELD(name) name,
    MATCHTYPE_FIELDS(DECL_FIELD)
#undef DECL_FIELD
};

struct CutPoint{
    RTLIL::IdString name;
    RTLIL::SigBit gold_sig;
    RTLIL::SigBit gate_sig;
    MatchType type = MatchType::NONE;
    RTLIL::Cell* gold_ff_cell = nullptr;
    RTLIL::Cell* gate_ff_cell = nullptr;
    RTLIL::IdString gold_wire_name;
    int gold_bit_index = 0;
    RTLIL::IdString gate_wire_name;
    int gate_bit_index = 0;
};

struct NamedSig {
    RTLIL::SigBit sig;
    MatchType type = MatchType::NONE;
    RTLIL::IdString wire_name;
    int bit_index = 0;
};

static inline void print_timing_stat(const TimingStat& s) {
    std::uint64_t t_total = 0;
    log("Timing Stastics:\n");
#define PRINT_FIELD(name) if(s.name) log("    %s: %.3lf s.\n", #name, s.name/1000.0);
    TIMINGSTAT_FIELDS(PRINT_FIELD)
#undef PRINT_FIELD
#define ACC_FIELD(name) t_total += s.name;
    TIMINGSTAT_FIELDS(ACC_FIELD)
#undef ACC_FIELD
    log("    Total accounting time: %.3lf s.\n",t_total/1000.0);
}

static inline string get_match_type_str(const MatchType& t) {
    switch (t) {
#define CASE(name) case MatchType::name: return #name;
        MATCHTYPE_FIELDS(CASE)
#undef CASE
    }
    assert(0);
    return "UNKNOWN";
}

static std::string strip_backslash(const RTLIL::IdString &id)
{
    std::string s = id.str();
    if (!s.empty() && s[0] == '\\') s = s.substr(1);
    return s;
}
static RTLIL::Design *empty_design()
{
    auto *design = new RTLIL::Design;
    design->push_full_selection();
    return design;
}

static RTLIL::SigSpec resize_u0(RTLIL::SigSpec src, int width);

static void flatten_std_cells(RTLIL::Design *design, RTLIL::Design *lib_design)
{
    assert(design);
    assert(lib_design);
    pool<RTLIL::IdString> std_cells;
    for (auto mod : lib_design->modules())
    {
        std_cells.insert(mod->name);
    }

    // Real Modules. Exclude standard cells.
    std::vector<RTLIL::Module*> modules;
    for (auto mod : design->modules())
    {
        if(std_cells.count(mod->name) != 0)
            continue;
        modules.push_back(mod);
    }

    std::vector<bool> keep_hierarchy_flags(modules.size(), false);
    for(size_t i = 0; i < modules.size(); i++){
        RTLIL::Module *mod = modules[i];
        if(mod->get_bool_attribute(ID(keep_hierarchy))){
            keep_hierarchy_flags[i] = true;
        }
    }

    for(auto mod : modules)
    {
        mod->set_bool_attribute(ID(keep_hierarchy), true);
    }

    for (auto mod : modules)
    {
        if(mod->get_bool_attribute(ID(blackbox)))
            continue;
        run_pass(stringf("flatten %s", mod->name.str()), design);
    }

    for(size_t i = 0; i < modules.size(); i++){
        RTLIL::Module *mod = modules[i];
        mod->set_bool_attribute(ID(keep_hierarchy), keep_hierarchy_flags[i]);
    }
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

static void lib_import_to_design(RTLIL::Design *design, RTLIL::Design *lib_design)
{
    assert(design);
    assert(lib_design);
    for (auto mod : lib_design->modules())
    {
        if(design->module(mod->name) != nullptr){
            design->remove(design->module(mod->name));
        }
        RTLIL::Module *t = mod->clone();
        t->design = design;
        design->add(t);
    }
}

RTLIL::IdString get_orignal_mod_name(const RTLIL::IdString &mod_name,const RTLIL::IdString root_mod_name, const string& prefix)
{

    if (mod_name == root_mod_name) {
        return root_mod_name;
    }
    else if (mod_name.begins_with(RTLIL::escape_id(prefix))) {
        return RTLIL::escape_id(strip_backslash(mod_name).substr(prefix.size()));
    }
    else {
        return RTLIL::IdString();
    }
}

ModMap hier_mod_map(RTLIL::Design *design, CheckConfig& conf)
{
    assert(design);
    ModMap mod_map;
    
    auto gold2gate = &mod_map.mod_map_gold;
    auto gate2gold = &mod_map.mod_map_gate;
    
    for( auto mod : design->modules()){
        if (mod->name.begins_with(RTLIL::escape_id(conf.gold_prefix)) ||
            mod->name == conf.gold_mod->name ) {
            RTLIL::IdString original_name = get_orignal_mod_name(
                mod->name, conf.gold_mod->name, conf.gold_prefix);
                
            RTLIL::IdString gate_name = mod->name == conf.gold_mod->name ?
                conf.gate_mod->name :
                RTLIL::escape_id(conf.gate_prefix + strip_backslash(original_name));
            if (design->module(gate_name) != nullptr) {
                (*gold2gate)[mod->name] = gate_name;
                mod_map.mapped_mods_gold.insert(mod->name);
                mod_map.mapped_mods_gate.insert(gate_name);
            }
            else {
                mod_map.unmapped_mods_gold.insert(mod->name);
            }
        }
            
    }

    for( auto mod : design->modules()){
        if (mod->name.begins_with(RTLIL::escape_id(conf.gate_prefix)) ||
            mod->name == conf.gate_mod->name ) {
            RTLIL::IdString original_name = get_orignal_mod_name(
                mod->name, conf.gate_mod->name, conf.gate_prefix);

            RTLIL::IdString gold_name = mod->name == conf.gate_mod->name ?
                conf.gold_mod->name :
                RTLIL::escape_id(conf.gold_prefix + strip_backslash(original_name));
            if (design->module(gold_name) != nullptr) {
                (*gate2gold)[gold_name] = mod->name;
                mod_map.mapped_mods_gold.insert(gold_name);
                mod_map.mapped_mods_gate.insert(mod->name);
            }
            else {
                mod_map.unmapped_mods_gate.insert(mod->name);
            }
        }
            
    }

    log("Found %zu equivalence module pairs for LEC.\n", mod_map.mapped_mods_gold.size());
    for(auto const &mod_name : mod_map.mapped_mods_gold){
        log("  Gold module %s  <=>  Gate module %s\n", 
            log_id(mod_name), log_id((*gold2gate)[mod_name]));
    }
    
    for(const auto &mod_name : mod_map.unmapped_mods_gold){
        log_warning("Gold module %s has no matching gate module.\n", log_id(mod_name));
    }
    for(const auto &mod_name : mod_map.unmapped_mods_gate){
        log_warning("Gate module %s has no matching gold module.\n", log_id(mod_name));
    }
    return mod_map;
}

/*
static void remove_sub_mods(RTLIL::Design *design, const CheckConfig& confp)
{
    assert(design);
    pool<RTLIL::IdString> std_cells;
    if (confp.lib_design) {
        for (auto mod : confp.lib_design->modules())
        {
            std_cells.insert(mod->name);
        }
    }

    pool<RTLIL::Module*> modules;
    for (auto mod : design->modules())
    {
        if(std_cells.count(mod->name) != 0)
            continue;
        modules.insert(mod);
    }

    pool<RTLIL::IdString> submods;
    for (auto mod : modules)
    {
        for (auto cell : mod->cells())
        {
            RTLIL::Module *child = design->module(cell->type);
            if (!child)
                continue;
            if (std_cells.count(child->name) != 0)
                continue;
            if (child->get_blackbox_attribute())
                continue;
            submods.insert(child->name);
        }
    }

    // PO/PO of sub modules -> PO/PO of parent module
    // Remove sub modules
    for (auto mod : modules)
    {
        if (mod->get_blackbox_attribute())
            continue;

        std::vector<RTLIL::Cell*> cells = mod->cells();
        for (auto cell : cells)
        {
            RTLIL::Module *child = design->module(cell->type);
            if (!child)
                continue;
            if (std_cells.count(child->name) != 0)
                continue;
            if (child->get_blackbox_attribute())
                continue;

            std::vector<RTLIL::Wire*> child_ports;
            for (auto *w : child->wires())
                if (w->port_id > 0 && (w->port_input || w->port_output))
                    child_ports.push_back(w);

            std::sort(child_ports.begin(), child_ports.end(),
                      [](RTLIL::Wire *a, RTLIL::Wire *b){ return a->port_id < b->port_id; });

            for (auto *port : child_ports)
            {
                if (!cell->hasPort(port->name))
                    continue;

                RTLIL::SigSpec port_sig = cell->getPort(port->name);
                port_sig = resize_u0(port_sig, GetSize(port));

                if (port->port_input) {
                    std::string base = stringf("%s__%s__to_sub",
                        strip_backslash(cell->name).c_str(),
                        strip_backslash(port->name).c_str());
                    RTLIL::IdString wire_name = mod->uniquify(RTLIL::escape_id(base));
                    RTLIL::Wire *w = mod->addWire(wire_name, GetSize(port));
                    w->is_signed = port->is_signed;
                    w->upto = port->upto;
                    w->start_offset = port->start_offset;
                    w->port_output = true;
                    mod->connect(RTLIL::SigSpec(w), port_sig);
                }

                if (port->port_output) {
                    std::string base = stringf("%s__%s__from_sub",
                        strip_backslash(cell->name).c_str(),
                        strip_backslash(port->name).c_str());
                    RTLIL::IdString wire_name = mod->uniquify(RTLIL::escape_id(base));
                    RTLIL::Wire *w = mod->addWire(wire_name, GetSize(port));
                    w->is_signed = port->is_signed;
                    w->upto = port->upto;
                    w->start_offset = port->start_offset;
                    w->port_input = true;
                    mod->connect(port_sig, RTLIL::SigSpec(w));
                }
            }

            mod->remove(cell);
        }
        mod->fixup_ports();
    }

    for (auto mod : design->modules().to_vector())
    {
        if (std_cells.count(mod->name) != 0)
            continue;
        if (submods.count(mod->name) == 0)
            continue;
        if (mod->get_bool_attribute(ID::top))
            continue;
        if (mod == confp.gold_mod || mod == confp.gate_mod)
            continue;
        design->remove(mod);
    }
    
}
*/


static dict<RTLIL::IdString, NamedSig> build_named_sigs(RTLIL::Design* design, RTLIL::Module *m, dict<RTLIL::SigBit, RTLIL::Cell*>& ff_q_map)
{
    // have't use yet.
    (void) design;


    SigMap sigmap(m);
    dict<RTLIL::IdString, NamedSig> out;
    pool<RTLIL::Cell*> subckts;
    dict<RTLIL::SigBit, RTLIL::Cell*> ff_q_bits_map;

    for (auto cell : m->cells()) {
        // subckt
        if (!yosys_celltypes.cell_known(cell->type)){
            subckts.insert(cell);
            continue;
        }

        if (!cell->is_builtin_ff() && cell->type != ID($anyinit))
            continue;

        FfData ff(nullptr, cell);
        if (!ff.has_clk && !ff.has_gclk){
            assert(0);
            continue;
        }
            

        RTLIL::SigSpec q = ff.sig_q;
        q = sigmap(q);

        for (int i = 0; i < GetSize(q); i++) {
            RTLIL::SigBit qb = q[i];
            ff_q_bits_map[qb] = cell;
            ff_q_bits_map[sigmap(qb)] = cell;
            // log("Found FF Q bit: %s\n", log_signal(sigmap(qb)));
        }
    }

    dict<RTLIL::SigBit, RTLIL::Cell*> ff_conn_bits = ff_q_bits_map;
    bool changed = true;
    while (changed) {
        changed = false;
        for (auto &conn : m->connections()) {
            RTLIL::SigSpec lhs = sigmap(conn.first);
            RTLIL::SigSpec rhs = sigmap(conn.second);
            int width = GetSize(lhs);
            for (int i = 0; i < width; i++) {
                RTLIL::SigBit rb = rhs[i];
                RTLIL::SigBit lb = lhs[i];
                if (rb.is_wire() && ff_conn_bits.count(rb) && !ff_conn_bits.count(lb)) {
                    ff_conn_bits[lb] = ff_conn_bits[rb];
                    changed = true;
                }
            }
        }
    }


    for (auto *w : m->wires()) {
        // if (!w->port_input && !w->port_output) continue;
        // if(w->port_input) continue;
        RTLIL::SigSpec sig = sigmap(RTLIL::SigSpec(w));
        int width = GetSize(sig);
                
        MatchType type = MatchType::NONE;

        for (int i = 0; i < width; i++) {
            RTLIL::SigBit b = sig[i];
            RTLIL::SigBit bm = sigmap(b);

            RTLIL::IdString bit_name;
            if(width == 1){
                bit_name = w->name;
            }
            else{
                bit_name = RTLIL::IdString(stringf("%s[%d]", w->name, i));
            }
            
            bool is_ff = ff_conn_bits.count(bm);

            bool is_output = w->port_output;

            bool is_input = w->port_input;
            // log("Wire %s is input: %s, output: %s\n", bit_name, is_input ? "true" : "false", is_output ? "true" : "false");
            // log("Wire %s is FF Q: %s\n", bit_name, is_ff ? "true" : "false");
            // Can not process `inout`
            assert(!(is_output && is_input));

            type = is_ff && is_output ? MatchType::DFF_PO :
                is_ff ? MatchType::DFF :
                is_output ? MatchType::PO :
                MatchType::NONE;

            type = is_input ? MatchType::PI : type;

            NamedSig entry;
            entry.sig = bm;
            entry.type = type;
            entry.wire_name = w->name;
            entry.bit_index = i;
            out[bit_name] = entry;
            if(is_ff){
                ff_q_map[bm] = ff_conn_bits[bm];
            }
        }
    }

    for(auto subckt: subckts) { 
        for(auto conn: subckt->connections()){
            auto name = conn.first;
            auto sig = conn.second;
            if(!subckt->hasPort(name)){
                continue;
            }

            sig = sigmap(sig);
            log("%s -- %s\n", name, log_signal(sig));
            
            int width = GetSize(sig);

            for (int i = 0; i < width; i++) {
                RTLIL::SigBit b = sig[i];
                RTLIL::SigBit bm = sigmap(b);

                RTLIL::IdString bit_name;
                if(width == 1){
                    bit_name = RTLIL::IdString(stringf("%s.%s", subckt->name, name));
                }
                else{
                    bit_name = RTLIL::IdString(stringf("%s.%s[%d]", subckt->name, name, i));
                }
                
                bool is_ff = ff_conn_bits.count(bm);

                NamedSig entry;
                entry.sig = bm;
                entry.type = MatchType::SUBCKT_PIPO;
                entry.wire_name = name;
                entry.bit_index = i;
                out[bit_name] = entry;
                if(is_ff){
                    ff_q_map[bm] = ff_conn_bits[bm];
                }
            }
        }
    }
    

    return out;

}


static std::vector<CutPoint> match_signals_module(RTLIL::Design *design, RTLIL::Module *gold_mod, RTLIL::Module *gate_mod, const string& tempdir)
{
    assert(design && gold_mod && gate_mod);

    SigMap sigmap_gate(gate_mod);
    SigMap sigmap_gold(gold_mod);

    std::vector<CutPoint> cut_points;
    dict<RTLIL::SigBit, RTLIL::Cell*> gold_ff_q_map;
    dict<RTLIL::SigBit, RTLIL::Cell*> gate_ff_q_map;

    auto gold = build_named_sigs(design, gold_mod, gold_ff_q_map);
    auto gate = build_named_sigs(design, gate_mod, gate_ff_q_map);
    log("---------------------------------------------\n");
    log("Matching signals between Gold module %s and Gate module %s\n",
        log_id(gold_mod), log_id(gate_mod));

    string match_file = tempdir + "/match_" + RTLIL::unescape_id(gold_mod->name) + "_" + RTLIL::unescape_id(gate_mod->name) + ".txt";
    FILE *f = fopen(match_file.c_str(), "w");

    for (auto &it : gold) {
        auto name = it.first;
        if (!gate.count(name))
            continue;

        const auto &gentry = it.second;
        const auto &kentry = gate.at(name);
        RTLIL::SigBit gsig = gentry.sig;
        RTLIL::SigBit ksig = kentry.sig;
        

        // log("Matched signal %s: gold %s gate %s, Type %s\n",
        //     name.c_str(), log_signal(gsig), log_signal(ksig), get_match_type_str(gentry.type));

        // Don't dump NONE type
        // TODO: Warning: NONE type gentry may has the same signal name with DFF/other type's.
        // This will lead to overwriting in name mapping in ABC. If didn't solve this in 
        // ABC. Please DO NOT dump NONE type entries!
        if(gentry.type != MatchType::NONE){
            fprintf(f, "Matched signal %s: gold %s gate %s, Type %s\n",
                name.c_str(), log_signal(gsig).c_str(), log_signal(ksig).c_str(), 
                get_match_type_str(gentry.type).c_str());
        }
        cut_points.push_back(CutPoint{name, gsig, ksig, gentry.type,
                gold_ff_q_map.count(gsig) ? gold_ff_q_map[gsig] : nullptr,
                gate_ff_q_map.count(ksig) ? gate_ff_q_map[ksig] : nullptr,
                gentry.wire_name, gentry.bit_index,
                kentry.wire_name, kentry.bit_index});
    }
    fclose(f);
    return cut_points;
}

static dict<RTLIL::Module*, std::vector<CutPoint>> match_signals(RTLIL::Design *design, const CheckConfig& conf, ModMap& mod_map)
{
    assert(design);
    auto gold2gate = mod_map.mod_map_gold;
    auto gate2gold = mod_map.mod_map_gate;

    dict<RTLIL::Module*, std::vector<CutPoint>> gold2cutpoints;

    for(auto const &[gold, gate] : gold2gate){
        gold2cutpoints[design->module(gold)] = 
            match_signals_module(design, design->module(gold), design->module(gate), conf.tempdir_name);
    }
    return gold2cutpoints;
}

static void cutpoints_to_pi_po(RTLIL::Module *mod,
                               const std::vector<CutPoint> &cutpoints,
                               bool use_gold)
{
    SigMap sigmap(mod);
    pool<RTLIL::Cell*> cut_cells;
    pool<RTLIL::SigBit> cut_q_bits;
    std::vector<RTLIL::SigSig> pending_q_conns;

    auto make_port_wire = [&](const RTLIL::IdString &base, const char *suffix, int width,
                              bool is_input, bool is_output) -> RTLIL::Wire* {
        std::string base_name = strip_backslash(base);
        RTLIL::IdString name = mod->uniquify(RTLIL::escape_id(base_name + suffix));
        RTLIL::Wire *w = mod->addWire(name, width);
        w->port_input = is_input;
        w->port_output = is_output;
        return w;
    };

    auto find_ff_by_qbit = [&](RTLIL::SigBit qbit) -> RTLIL::Cell* {
        if (!qbit.is_wire())
            return nullptr;
        for (auto cell : mod->cells()) {
            if (!cell->is_builtin_ff() && cell->type != ID($anyinit))
                continue;
            RTLIL::SigSpec qsig = sigmap(cell->getPort(ID::Q));
            for (int i = 0; i < GetSize(qsig); i++) {
                if (qsig[i] == qbit)
                    return cell;
            }
        }
        return nullptr;
    };

    for (const auto &cp : cutpoints)
    {
        if (cp.type != MatchType::DFF && cp.type != MatchType::DFF_PO)
            continue;

        RTLIL::Cell *ff = use_gold ? cp.gold_ff_cell : cp.gate_ff_cell;
        if (ff != nullptr)
            ff = mod->cell(ff->name);

        RTLIL::IdString qwire_name = use_gold ? cp.gold_wire_name : cp.gate_wire_name;
        int qbit_index = use_gold ? cp.gold_bit_index : cp.gate_bit_index;
        if (qwire_name.empty()) {
            log_warning("Missing cutpoint wire name for %s in module %s.\n",
                log_id(cp.name), log_id(mod->name));
            continue;
        }
        RTLIL::Wire *qwire = mod->wire(qwire_name);
        if (qwire == nullptr) {
            log_warning("Missing cutpoint wire %s in module %s.\n",
                log_id(cp.name), log_id(mod->name));
            continue;
        }
        if (qbit_index < 0 || qbit_index >= GetSize(qwire)) {
            log_warning("Cutpoint index out of range for %s in module %s.\n",
                log_id(cp.name), log_id(mod->name));
            continue;
        }
        RTLIL::SigBit qbit_port(qwire, qbit_index);
        RTLIL::SigBit qbit_mapped = sigmap(qbit_port);

        if (ff == nullptr)
            ff = find_ff_by_qbit(qbit_mapped);

        if (ff == nullptr) {
            log_warning("Missing FF cell for cutpoint %s in module %s.\n",
                log_id(cp.name), log_id(mod->name));
            continue;
        }

        if (!qbit_port.is_wire()) {
            log_warning("Cutpoint %s has non-wire Q bit in module %s.\n",
                log_id(cp.name), log_id(mod->name));
            continue;
        }

        bool is_dff_po = (cp.type == MatchType::DFF_PO);
        cut_q_bits.insert(qbit_mapped);
        cut_cells.insert(ff);

        RTLIL::SigBit pi_bit = qbit_port;
        if (!is_dff_po) {
            if (qbit_port.wire->port_output) {
                RTLIL::Wire *pi_wire = make_port_wire(cp.name, "_pi", 1, true, false);
                pi_bit = RTLIL::SigBit(pi_wire);
                pending_q_conns.emplace_back(RTLIL::SigSpec(qbit_port), RTLIL::SigSpec(pi_wire));
            } else {
                qbit_port.wire->port_input = true;
            }
            if (qbit_mapped != pi_bit)
                pending_q_conns.emplace_back(RTLIL::SigSpec(qbit_mapped), RTLIL::SigSpec(pi_bit));
        }

        RTLIL::SigSpec qsig = sigmap(ff->getPort(ID::Q));
        RTLIL::SigSpec dsig = sigmap(ff->getPort(ID::D));

        int qidx = -1;
        for (int i = 0; i < GetSize(qsig); i++) {
            if (qsig[i] == qbit_mapped) {
                qidx = i;
                break;
            }
        }
        if (qidx < 0) {
            if (GetSize(qsig) > 1) {
                if (qbit_index < 0 || qbit_index >= GetSize(qsig)) {
                    log_warning("Cannot map Q bit for cutpoint %s in module %s.\n",
                        log_id(cp.name), log_id(mod->name));
                    continue;
                }
                qidx = qbit_index;
            } else {
                qidx = 0;
            }
        }

        if (qidx < 0 || qidx >= GetSize(dsig)) {
            log_warning("Cutpoint %s has invalid D index in module %s.\n",
                log_id(cp.name), log_id(mod->name));
            continue;
        }
        RTLIL::SigBit dbit = dsig[qidx];
        if (is_dff_po) {
            pending_q_conns.emplace_back(RTLIL::SigSpec(qbit_mapped), RTLIL::SigSpec(dbit));
            if (qbit_port != qbit_mapped)
                pending_q_conns.emplace_back(RTLIL::SigSpec(qbit_port), RTLIL::SigSpec(qbit_mapped));
        } else {
            RTLIL::Wire *w_out = make_port_wire(cp.name, "_po", 1, false, true);
            mod->connect(RTLIL::SigSpec(w_out), RTLIL::SigSpec(dbit));
        }
    }

    if (!cut_q_bits.empty()) {
        std::vector<RTLIL::SigSig> new_conns;
        new_conns.reserve(mod->connections().size());
        for (auto &ss : mod->connections()) {
            RTLIL::SigSpec lhs, rhs;
            RTLIL::SigSpec lhs_sig = ss.first;
            RTLIL::SigSpec rhs_sig = ss.second;
            int width = GetSize(lhs_sig);
            for (int i = 0; i < width; i++) {
                RTLIL::SigBit lb = sigmap(lhs_sig[i]);
                if (cut_q_bits.count(lb))
                    continue;
                lhs.append(lhs_sig[i]);
                rhs.append(rhs_sig[i]);
            }
            if (GetSize(lhs))
                new_conns.emplace_back(lhs, rhs);
        }
        mod->connections_.swap(new_conns);
    }

    for (auto &conn : pending_q_conns)
        mod->connect(conn.first, conn.second);

    for (auto *ff : cut_cells)
        mod->remove(ff);

    mod->fixup_ports();
}


static void submod_to_pi_po(RTLIL::Design *design, RTLIL::Module *mod)
{
    assert(design);
    assert(mod);

    SigMap sigmap(mod);
    pool<RTLIL::SigBit> cut_bits;
    std::vector<RTLIL::SigSig> pending_conns;
    std::vector<RTLIL::Cell*> remove_cells;

    for (auto *cell : mod->cells()) {

        if(yosys_celltypes.cell_known(cell->type))
            continue;

        RTLIL::Module *child = design->module(cell->type);
        if (!child) {
            log_error("Missing module %s for cell %s in module %s.\n",
                    log_id(cell->type), log_id(cell->name), log_id(mod->name));
            continue;
        }

        

        std::vector<RTLIL::Wire*> child_ports;
        for (auto *w : child->wires())
            if (w->port_id > 0 && (w->port_input || w->port_output))
                child_ports.push_back(w);

        std::sort(child_ports.begin(), child_ports.end(),
                  [](RTLIL::Wire *a, RTLIL::Wire *b){ return a->port_id < b->port_id; });

        for (auto *port : child_ports) {
            if (!cell->hasPort(port->name))
                continue;

            RTLIL::SigSpec port_sig = cell->getPort(port->name);
            port_sig = resize_u0(port_sig, GetSize(port));
            RTLIL::SigSpec mapped_sig = sigmap(port_sig);

            std::string base = stringf("%s_%s",
                strip_backslash(cell->name).c_str(),
                strip_backslash(port->name).c_str());

            auto add_port_wire = [&](const char *suffix, bool is_input, bool is_output) -> RTLIL::Wire* {
                RTLIL::IdString name = mod->uniquify(RTLIL::escape_id(base + suffix));
                RTLIL::Wire *w = mod->addWire(name, GetSize(port));
                w->is_signed = port->is_signed;
                w->upto = port->upto;
                w->start_offset = port->start_offset;
                w->port_input = is_input;
                w->port_output = is_output;
                return w;
            };

            if (port->port_output) {
                RTLIL::Wire *w_pi = add_port_wire("_pi", true, false);
                pending_conns.emplace_back(mapped_sig, RTLIL::SigSpec(w_pi));

                int width = GetSize(port_sig);
                for (int i = 0; i < width; i++) {
                    RTLIL::SigBit pb = port_sig[i];
                    RTLIL::SigBit mb = mapped_sig[i];
                    if (mb.is_wire())
                        cut_bits.insert(mb);
                    if (pb.is_wire() && mb.is_wire() && pb != mb)
                        pending_conns.emplace_back(RTLIL::SigSpec(pb), RTLIL::SigSpec(mb));
                }
            }
        }

        remove_cells.push_back(cell);
    }

    if (!cut_bits.empty()) {
        std::vector<RTLIL::SigSig> new_conns;
        new_conns.reserve(mod->connections().size());
        for (auto &ss : mod->connections()) {
            RTLIL::SigSpec lhs, rhs;
            RTLIL::SigSpec lhs_sig = ss.first;
            RTLIL::SigSpec rhs_sig = ss.second;
            int width = GetSize(lhs_sig);
            for (int i = 0; i < width; i++) {
                RTLIL::SigBit lb = sigmap(lhs_sig[i]);
                if (cut_bits.count(lb))
                    continue;
                lhs.append(lhs_sig[i]);
                rhs.append(rhs_sig[i]);
            }
            if (GetSize(lhs))
                new_conns.emplace_back(lhs, rhs);
        }
        mod->connections_.swap(new_conns);
    }

    for (auto &conn : pending_conns)
        mod->connect(conn.first, conn.second);

    for (auto *cell : remove_cells)
        mod->remove(cell);

    mod->fixup_ports();
}

static std::vector<RTLIL::Module*> topo_sort_modules(RTLIL::Design *design, const RTLIL::IdString& root);

// The function still has bug
[[maybe_unused]]static void remove_subclk(RTLIL::Design* design, CheckConfig& conf) {

    // haven't use now.
    (void) design;

    auto gold_topo = topo_sort_modules(design, conf.gold_mod->name);
    auto gate_topo = topo_sort_modules(design, conf.gate_mod->name);

    for(auto m: gold_topo){
        submod_to_pi_po(design, m);
    }
    for(auto m: gate_topo) {
        submod_to_pi_po(design, m);
    }
}

// RetVal: <gold_submodule, gate_submodule> , pointer in design_check
static std::pair<RTLIL::Module*, RTLIL::Module*> partition_module(RTLIL::Design *design, RTLIL::Design *design_check, 
    RTLIL::Module *gold_mod, RTLIL::Module *gate_mod,  //pointer in design
    const std::vector<CutPoint>& cutpoints, const CheckConfig& conf)
{
    // Maybe implement further.
    assert(0);
    (void) design;
    (void) design_check;
    (void) conf;

    RTLIL::Module *gold_clone = gold_mod->clone();
    RTLIL::Module *gate_clone = gate_mod->clone();

    // convert_ff_to_fine(gold_clone);
    // convert_ff_to_fine(gate_clone);


    cutpoints_to_pi_po(gold_clone, cutpoints, true);
    cutpoints_to_pi_po(gate_clone, cutpoints, false);

    // blackbox_to_pi_po(design, gold_clone);
    // blackbox_to_pi_po(design, gate_clone);

    return {gold_clone, gate_clone};
}

// Maybe implement further.
[[maybe_unused]]static void partition_design_for_check(RTLIL::Design *design, RTLIL::Design *design_check, 
    const CheckConfig& conf, ModMap& mod_map,
    const dict<RTLIL::Module*, std::vector<CutPoint>>& gold2cutpoints)
{
    for(const auto &[gold_mod, cutpoints] : gold2cutpoints){
        RTLIL::IdString gold_mod_name = gold_mod->name;
        RTLIL::IdString gate_mod_name = mod_map.mod_map_gold.at(gold_mod_name);
        RTLIL::Module *gate_mod = design->module(gate_mod_name);

        auto module_partition = 
            partition_module(design, design_check, gold_mod, gate_mod, cutpoints, conf);
        design_check->add(module_partition.first);
        design_check->add(module_partition.second);
    }
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


static int exectue_and_check(const std::string & cmd, int & result, 
                    const std::vector<std::pair<std::string, int>>& target_result) {
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
    }

    for(auto it: target_result) {
        if (output.find(it.first) != std::string::npos) {
            result = it.second;
            break;
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
        run_pass(stringf("read_verilog -overwrite -noblackbox %s", lib_file), design_copy);
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

    auto t_start = std::chrono::steady_clock::now();

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
    // (void)lib_file;
    // if(!lib_file.empty())
    //     run_pass(stringf("read_verilog -overwrite %s", lib_file), design_copy);
    
    // run_pass(stringf("flatten"), design_copy);
    // run_pass(stringf("hierarchy -top %s", mod->name.str()), design_copy);
    // run_pass(stringf("proc"), design_copy);
    // run_pass(stringf("opt"), design_copy);
    // run_pass(stringf("memory_map"), design_copy);

    for(auto mod_: design_copy->modules()){
        if(mod_->name != mod->name){
            mod_->set_bool_attribute(ID(blackbox), true);
            // log("Current Module: %s, Set Module `%s` to blackbox.\n", mod->name.str(), mod_->name.str());
        }
    }
    (void)lib_file;
    // if(!lib_file.empty())
    //     run_pass(stringf("read_verilog -overwrite %s", lib_file), design_copy);
    // run_pass(stringf("hierarchy -top %s", mod->name.str()), design_copy);
    // run_pass(stringf("flatten"), design_copy);
    // run_pass(stringf("proc"), design_copy);
    // run_pass(stringf("techmap"), design_copy);
    // run_pass(stringf("dffunmap"), design_copy);
    run_pass(stringf("write_blif -blackbox -top %s %s", mod_name, blif_file), design_copy);
    delete design_copy;
    log_files = log_files_backup;
    log_streams = log_streams_backup;

    auto t_end = std::chrono::steady_clock::now();
    timing_stat.dump_blif_ms += std::chrono::duration_cast<std::chrono::milliseconds>(t_end-t_start).count();

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
    // run_pass(stringf("write_verilog 1.v"), design_copy);
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
    int gate_dff_cnt = 0;
    int gold_dff_cnt = 0;
    bool has_submodule = false;
    for(auto cells: conf.gold_mod->cells()){
        if(cells->type == ID($ff) || cells->type == ID($dff) || cells->type == ID($dffe)|| 
           cells->type == ID($_DFF_P_) || cells->type == ID($_DFF_N_) || cells->type == ID($_DFFE_PN) ||
           cells->type == ID($_DFFE_PP)){
            
            gold_dff_cnt++;
        } 
        auto submod = conf.design->module(cells->type);
        if (submod != nullptr && !(submod->attributes.count(ID::blackbox))) {
            has_submodule = true;
        }
        if(has_dff && has_submodule){
            break;
        }
    }

    for(auto cells: conf.gate_mod->cells()){
        if(cells->type.contains("DFF") || cells->type == ID($ff) || cells->type == ID($dff) || cells->type == ID($dffe)|| 
           cells->type == ID($_DFF_P_) || cells->type == ID($_DFF_N_) || cells->type == ID($_DFFE_PN) ||
           cells->type == ID($_DFFE_PP)){
            has_dff = true;
            gate_dff_cnt++;
        } 
    }

    log("Gold DFF count: %d, Gate DFF count: %d\n", gold_dff_cnt, gate_dff_cnt);

    has_dff = (gate_dff_cnt !=0 || gold_dff_cnt !=0);

    using clock = std::chrono::steady_clock;

    auto t0 = clock::now();

    string match_file = conf.tempdir_name + "/match_" + RTLIL::unescape_id(gold_mod->name) + "_" + RTLIL::unescape_id(gate_mod->name) + ".txt";
    // string abc_cmd = (has_dff) ? stringf("dsec -n %s %s", gold_file, gate_file) :
    //                                             stringf("cec -M %s -n %s %s", match_file, gold_file, gate_file);
    string abc_cmd = stringf("cec -M %s %s %s", match_file, gate_file, gold_file);
    string cmd = stringf("%s -c '%s'", conf.abc_exe_file, abc_cmd);
    int result = 0;
    vector<std::pair<std::string , int>> out2result = 
            {{"Networks are equivalent", 1},
             {"Networks are NOT EQUIVALENT", 2},
             {"Miter computation has failed", 3}};

    log("Executing ABC command: '%s'\n", abc_cmd);
    bool abc_ret = exectue_and_check(cmd, result, out2result);
    if (abc_ret != 0 || result == 0) {
        log_error("Error executing ABC command: %s\n", cmd);
    }

    // it's not a good idea
    if (result != 1 && result != 2) {
        abc_cmd = stringf("cec -n %s %s", gate_file, gold_file);
        cmd = stringf("%s -c '%s'", conf.abc_exe_file, abc_cmd);
        log("Executing ABC command: '%s'\n", abc_cmd);
        bool abc_ret = exectue_and_check(cmd, result, out2result);
        if(abc_ret != 0) {
            log_error("Error executing ABC command: %s\n", cmd);
        }
    }
    if (result != 1 && result != 2) {
        abc_cmd = stringf("dsec -M %s %s %s", match_file, gate_file, gold_file);
        cmd = stringf("%s -c '%s'", conf.abc_exe_file, abc_cmd);
        log("Executing ABC command: '%s'\n", abc_cmd);
        bool abc_ret = exectue_and_check(cmd, result, out2result);
        if(abc_ret != 0) {
            log_error("Error executing ABC command: %s\n", cmd);
        }
    }

    // it's not a good idea
    if (result != 1 && result != 2) {
        abc_cmd = stringf("dsec -n %s %s", gate_file, gold_file);
        cmd = stringf("%s -c '%s'", conf.abc_exe_file, abc_cmd);
        log("Executing ABC command: '%s'\n", abc_cmd);
        bool abc_ret = exectue_and_check(cmd, result, out2result);
        if(abc_ret != 0) {
            log_error("Error executing ABC command: %s\n", cmd);
        }
    }
    auto t1 = clock::now();
    timing_stat.abc_cec_ms += std::chrono::duration_cast<std::chrono::milliseconds>(t1-t0).count();

    return result == 1;
}
    

static std::vector<std::pair<RTLIL::IdString, bool>> abc_cec(const CheckConfig &conf){
    // find equivalence-checking pair
    auto design = conf.design;

    vector<std::pair<RTLIL::IdString, RTLIL::IdString>> equiv_mods;

    for( auto mod : design->modules()){
        if(mod->get_blackbox_attribute())
            continue;
        if (mod->name.begins_with(RTLIL::escape_id(conf.gold_prefix)) ||
            mod->name == conf.gold_mod->name ) {
            RTLIL::IdString original_name = get_orignal_mod_name(
                mod->name, conf.gold_mod->name, conf.gold_prefix);
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

    std::vector<std::pair<RTLIL::IdString, bool>> results;

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
        results.push_back({get_orignal_mod_name(gold_name, gate_name, conf.gold_prefix), cec_result});

        // if(!cec_result){
        //     log("\nGUIDE_CHECK failed for module pair: gold=%s vs gate=%s\n", 
        //         log_id(gold_name), log_id(gate_name));
        // }
        // else 
        // {
        //     log("\nGUIDE_CHECK passed for module pair: gold=%s vs gate=%s\n", 
        //         log_id(gold_name), log_id(gate_name));
        // }


    }
    return results;
    //return true;    
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

static std::vector<RTLIL::Module*> topo_sort_modules(RTLIL::Design *design, const RTLIL::IdString& root){
    TopoSort<RTLIL::Module*,RTLIL::IdString::compare_ptr_by_name<RTLIL::Module>> ts;
    ts.analyze_loops = true;


    // get related modules
    std::set<RTLIL::Module*,RTLIL::IdString::compare_ptr_by_name<RTLIL::Module>> related_mods;
    std::function<void(RTLIL::Module*)> dfs = [&](RTLIL::Module* mod){
        if(related_mods.count(mod)){
            return;
        }
        related_mods.insert(mod);
        for(auto cell : mod->cells()){
            RTLIL::Module *child = design->module(cell->type);
            if (!child) continue;
            dfs(child);
        }
    };
    RTLIL::Module* root_mod = design->module(root);
    if(!root_mod){
        log_error("Root Module %s not found in the design.\n", log_id(root));
    }
    dfs(root_mod);

    log("Related modules count: %zu\n", related_mods.size());
    for(auto mod : related_mods){
        log("  Related module: %s\n", log_id(mod->name));
    }

    for (auto m : related_mods) {
        ts.node(m);
    }

    for (auto parent : related_mods) {
        for (auto cell : parent->cells()) {
            RTLIL::Module *child = design->module(cell->type);
            if (!child) continue;
            if(related_mods.count(child) ==0){
                continue;
            }
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

        timing_stat = TimingStat();

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
        const RTLIL::IdString gold_mod_name_id = gold_mod->name;
        const RTLIL::IdString gate_mod_name_id = gate_mod->name;

        string tempdir_name;
        if(nocleanup)
            tempdir_name = "_tmp_";
        else
            tempdir_name = get_base_tmpdir() + "/";
        
        tempdir_name += proc_program_prefix() + "yosys-guide-check-XXXXXX";
        tempdir_name = make_temp_dir(tempdir_name);
        log("Creating temporary directory %s for GUIDE_CHECK pass.\n", tempdir_name);



        auto design_backup = design; 
        design = clone_design_for_passes(design);


        auto t_lib_start = std::chrono::steady_clock::now();

        // Load library if specified
        RTLIL::Design *lib_design = nullptr;
        if(!lib_file.empty()){
            lib_design = empty_design();

            if(lib_file.size() > 4 && lib_file.substr(lib_file.size() - 4) == ".lib"){
                run_pass("read_liberty -overwrite " + lib_file, lib_design);
            }
            else if (lib_file.size() > 2 && lib_file.substr(lib_file.size() - 2) == ".v"){
                run_pass("read_verilog -overwrite " + lib_file, lib_design);
                run_pass("proc", lib_design);
                run_pass("techmap", lib_design);
            }
            else {
                design = design_backup;
                log_error("Unsupported library file format: %s\n", lib_file);
            }
            
        }
        
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
            .lib_design = lib_design,
        };

        vector<std::pair<RTLIL::IdString,bool>> cec_result_mod;
        bool multi_result = false, cec_result = false, retime_result;

        if(lib_design){
            lib_import_to_design(design, lib_design);
            flatten_std_cells(design, lib_design);
            for(auto mod : lib_design->modules()){
                auto mod_ = design->module(mod->name);
                if(mod_) {
                    design->remove(mod_);
                }
            }
        }
        
        auto t_lib_end = std::chrono::steady_clock::now();

        timing_stat.read_lib_ms += std::chrono::duration_cast<std::chrono::milliseconds>(t_lib_end-t_lib_start).count();

        auto t_prep_start = std::chrono::steady_clock::now();
        run_pass("proc", design);
        run_pass("memory_map", design);
        run_pass("opt_expr", design);
        run_pass("techmap", design);
        run_pass("dffunmap", design);

        
        auto mod_map = hier_mod_map(design, conf);
    

        // remove_subclk(design, conf);


        // formalff -clk2ff -ff2anyinit gate

        // for(auto mod: design-> modules()){
        //     run_pass(stringf("async2sync %s", mod->name), design);
        //     run_pass(stringf("formalff -clk2ff %s", (mod->name)), design);
        // }

        run_pass("opt_clean", design);

        auto t_prep_end = std::chrono::steady_clock::now();
        timing_stat.prep_ms += std::chrono::duration_cast<std::chrono::milliseconds>(t_prep_end-t_prep_start).count();

        auto gold2cutpoints = match_signals(design, conf, mod_map);

        // remove_subclk(design,conf);
        // RTLIL::Design *design_check = empty_design();

        // run_pass("write_verilog 1.v", design_check );
        // partition_design_for_check(design, design_check, conf, mod_map, gold2cutpoints);

        // propagate_child_ports(design_check);

        // conf.design = design_check;
        cec_result_mod = abc_cec(conf);

        cec_result = true; 
        for(auto r: cec_result_mod){

    
            log("GUIDE_CHECK result for module : %s : %s\n",
                log_id(r.first),
                r.second ? "\033[1;32mPASSED\033[0m" : "\033[1;31mFAILED\033[0m");

            if(!r.second){
                cec_result = false;
            }
        }

        print_timing_stat(timing_stat);

        // run_pass("opt_clean", design_check);
        // run_pass("check", design_check);
        // run_pass("write_verilog 1.v", design_check );
        // system("yosys -q -p 'read_verilog 1.v; proc; opt_expr; techmap; show -colors 1 -prefix gold gold_bbox'");
        // system("yosys -q -p 'read_verilog bbox.v; proc; opt_expr; techmap; show -colors 1 -prefix test bbox'");
        // return;
        // std::vector<RTLIL::Module*> multi_mods;

        (void) multi_result;

        // auto all_mods = design->all_selected_modules();
        // for(auto mod : all_mods)
        // {
        //     multi_result = check_extract_multi(design, mod, tempdir_name, multi_mods, lib_file);
        //     if(!multi_result)
        //     {
        //         log("GUIDE_CHECK multi-module check failed.\n");
        //         goto check_failed;
        //     }
        // }
        // log("GUIDE_CHECK multi-module check passed.\n");

        // (void)multi_mods;

        (void) retime_result;
        // retime_result = check_extract_retime(conf);

        // if(!retime_result)
        // {
        //     log("GUIDE_CHECK retime check failed.\n");
        //     goto check_failed;
        // }
        // log("GUIDE_CHECK retime check passed.\n");


        
        if(!cec_result)
        {
            log("GUIDE_CHECK cec check failed.\n");
            goto check_failed;
        }

        log("\nGUIDE_CHECK PASSED: Modules %s and %s are equivalent.\n",
            log_id(gold_mod_name_id), log_id(gate_mod_name_id));
        
        goto end_pass;

check_failed:
        if(assert_mode)
        {
            log_cmd_error("\nGUIDE_CHECK FAILED: Modules %s and %s are NOT equivalent.\n",
                log_id(gold_mod_name_id), log_id(gate_mod_name_id));
        }
        else
        {
            log("\nGUIDE_CHECK FAILED: Modules %s and %s are NOT equivalent.\n",
                log_id(gold_mod_name_id), log_id(gate_mod_name_id));
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
