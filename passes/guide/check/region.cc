#include "passes/guide/check/region.h"
#include "passes/guide/check/failure_exec.h"
#include "passes/guide/check/matching.h"
#include "passes/guide/check/retime_multiplier.h"

YOSYS_NAMESPACE_BEGIN
namespace guide_check {

static std::vector<CutPoint> dedup_local_dff_cutpoints(const std::vector<CutPoint> &cutpoints);
static RTLIL::SigBit get_cutpoint_d_bit(RTLIL::Module *mod, const CutPoint &cp, bool use_gold, bool &ok);
static Json json_array_from_ints(const std::vector<int> &values);
static Json json_array_from_strings(const std::vector<string> &values);
static string wire_bit_name(const RTLIL::IdString &wire_name, int width, int index);
static void add_sample_name(std::vector<string> &samples, const string &name, size_t limit = 8);
static string canonical_region_boundary_wire(const CheckConfig &conf, const RegionBoundary &boundary);
static std::vector<RegionBoundary> merge_region_boundaries(const CheckConfig &conf,
                                                           RTLIL::Module *gold_mod,
                                                           RTLIL::Module *gate_mod,
                                                           const std::vector<ChildBoundaryPort> &gold_boundaries,
                                                           const std::vector<ChildBoundaryPort> &gate_boundaries);
static void apply_region_boundary_canonical_names(RTLIL::Module *gold_mod,
                                                  RTLIL::Module *gate_mod,
                                                  std::vector<RegionBoundary> &boundaries);
static pool<string> region_boundary_bit_names(const std::vector<RegionBoundary> &boundaries);
static pool<string> collect_module_interface_input_bit_names(RTLIL::Module *mod);
static pool<string> collect_state_cut_input_bit_names(const std::vector<CutPoint> &cutpoints);
static void collect_wire_usage(RTLIL::Module *mod, pool<string> &driven_bits, pool<string> &used_bits);
static pool<string> promote_traceable_internal_boundaries(RTLIL::Module *gold_mod, RTLIL::Module *gate_mod);
static void audit_shell_inputs(PartitionedPair &pair, RTLIL::Module *gold_orig,
                               const std::vector<CutPoint> &cutpoints);
static std::vector<ChildBoundaryPort> submod_to_pi_po(RTLIL::Design *design, RTLIL::Module *mod);
static void restrict_local_output_ports(RTLIL::Module *mod);
static PartitionedPair partition_module(RTLIL::Design *design, RTLIL::Design *design_check,
                                        RTLIL::Module *gold_mod, RTLIL::Module *gate_mod,
                                        const std::vector<CutPoint> &cutpoints, const CheckConfig &conf);
static bool valid_region_child_module(RTLIL::Design *design, RTLIL::Cell *cell, RTLIL::Module *&child);
static std::vector<RegionBoundary> collect_region_child_boundaries(const CheckConfig &conf,
                                                                   const ModMap &mod_map,
                                                                   RTLIL::Module *gold_mod,
                                                                   RTLIL::Module *gate_mod);
static std::vector<RegionNode> build_region_plan(const CheckConfig &conf,
                                                 const ModMap &mod_map,
                                                 const dict<RTLIL::Module*, std::vector<CutPoint>> &gold2cutpoints);

std::vector<CutPoint> select_local_dff_cutpoints(const std::vector<CutPoint> &all_cps,
                                                        const CutPoint *extra_cand)
{
    std::vector<CutPoint> out;
    auto is_dff_cp = [](const CutPoint &cp) {
        return cp.type == MatchType::DFF || cp.type == MatchType::DFF_PO;
    };

    for (auto &cp : all_cps)
        if (is_dff_cp(cp))
            out.push_back(cp);

    if (extra_cand != nullptr && is_dff_cp(*extra_cand)) {
        bool found = false;
        for (auto &cp : out)
            if (cp.name == extra_cand->name && cp.type == extra_cand->type) {
                found = true;
                break;
            }
        if (!found)
            out.push_back(*extra_cand);
    }

    return dedup_local_dff_cutpoints(out);
}

std::vector<CutPoint> select_region_state_cutpoints(const std::vector<CutPoint> &all_cps)
{
    std::vector<CutPoint> out;
    for (const auto &cp : all_cps)
        if (cp.type == MatchType::DFF)
            out.push_back(cp);
    return dedup_local_dff_cutpoints(out);
}

std::vector<CutPoint> select_region_child_boundary_cutpoints(const std::vector<CutPoint> &all_cps)
{
    std::vector<CutPoint> out;
    for (const auto &cp : all_cps)
        if (cp.type == MatchType::SUBCKT_PIPO)
            out.push_back(cp);
    return out;
}

std::vector<CutPoint> dedup_local_dff_cutpoints(const std::vector<CutPoint> &cutpoints)
{
    dict<string, CutPoint> selected;

    auto key_of = [](const CutPoint &cp) {
        if (cp.gold_ff_cell != nullptr && cp.gate_ff_cell != nullptr)
            return string("ff:") + cp.gold_ff_cell->name.str() + "||" + cp.gate_ff_cell->name.str();
        return string("sig:") + log_signal(cp.gold_sig) + "||" + log_signal(cp.gate_sig);
    };

    auto prefer = [](const CutPoint &candidate, const CutPoint &current) {
        if (candidate.type == current.type)
            return false;
        if (candidate.type == MatchType::DFF && current.type == MatchType::DFF_PO)
            return true;
        return false;
    };

    for (const auto &cp : cutpoints) {
        string key = key_of(cp);
        if (!selected.count(key) || prefer(cp, selected.at(key)))
            selected[key] = cp;
    }

    std::vector<CutPoint> out;
    for (const auto &cp : cutpoints) {
        string key = key_of(cp);
        if (!selected.count(key))
            continue;
        if (selected.at(key).name != cp.name || selected.at(key).type != cp.type)
            continue;
        out.push_back(cp);
        selected.erase(key);
    }
    return out;
}

RTLIL::SigBit get_cutpoint_d_bit(RTLIL::Module *mod, const CutPoint &cp, bool use_gold, bool &ok)
{
    ok = false;
    SigMap sigmap(mod);

    RTLIL::Cell *ff = use_gold ? cp.gold_ff_cell : cp.gate_ff_cell;
    if (ff != nullptr)
        ff = mod->cell(ff->name);

    RTLIL::IdString qwire_name = use_gold ? cp.gold_wire_name : cp.gate_wire_name;
    int qbit_index = use_gold ? cp.gold_bit_index : cp.gate_bit_index;
    if (ff == nullptr || qwire_name.empty())
        return RTLIL::SigBit();

    RTLIL::Wire *qwire = mod->wire(qwire_name);
    if (qwire == nullptr || qbit_index < 0 || qbit_index >= GetSize(qwire))
        return RTLIL::SigBit();

    RTLIL::SigBit qbit_port(qwire, qbit_index);
    RTLIL::SigBit qbit_mapped = sigmap(qbit_port);
    RTLIL::SigSpec qsig = sigmap(ff->getPort(ID::Q));
    RTLIL::SigSpec dsig = sigmap(ff->getPort(ID::D));

    int qidx = -1;
    for (int i = 0; i < GetSize(qsig); i++)
        if (qsig[i] == qbit_mapped) {
            qidx = i;
            break;
        }

    if (qidx < 0) {
        if (GetSize(qsig) > 1) {
            if (qbit_index < 0 || qbit_index >= GetSize(qsig))
                return RTLIL::SigBit();
            qidx = qbit_index;
        } else {
            qidx = 0;
        }
    }

    if (qidx < 0 || qidx >= GetSize(dsig))
        return RTLIL::SigBit();

    ok = true;
    return dsig[qidx];
}

bool can_materialize_cutpoint(RTLIL::Module *mod, const CutPoint &cp, bool use_gold)
{
    if (cp.type == MatchType::SUBCKT_PIPO)
        return false;
    bool ok = false;
    RTLIL::SigBit dbit = get_cutpoint_d_bit(mod, cp, use_gold, ok);
    return ok && dbit.is_wire();
}

std::vector<CutPoint> filter_materializable_cutpoints(RTLIL::Module *gold_mod,
                                                             RTLIL::Module *gate_mod,
                                                             const std::vector<CutPoint> &cutpoints)
{
    std::vector<CutPoint> out;
    for (const auto &cp : cutpoints) {
        if (!can_materialize_cutpoint(gold_mod, cp, true))
            continue;
        if (!can_materialize_cutpoint(gate_mod, cp, false))
            continue;
        out.push_back(cp);
    }
    return out;
}

std::vector<CutPoint> select_support_sliced_dff_cutpoints(RTLIL::Module *gold_mod,
                                                                 RTLIL::Module *gate_mod,
                                                                 const std::vector<CutPoint> &all_cps,
                                                                 const CutPoint &candidate)
{
    auto is_dff_cp = [](const CutPoint &cp) {
        return cp.type == MatchType::DFF || cp.type == MatchType::DFF_PO;
    };

    auto collect_slice = [&](RTLIL::Module *mod, bool use_gold, pool<RTLIL::IdString> &selected) {
        SigMap sigmap(mod);
        dict<RTLIL::SigBit, const CutPoint*> qbit_to_cp;
        dict<RTLIL::SigBit, pool<RTLIL::SigBit>> deps;

        for (const auto &cp : all_cps) {
            if (!is_dff_cp(cp))
                continue;
            RTLIL::SigBit qbit = sigmap(use_gold ? cp.gold_sig : cp.gate_sig);
            if (qbit.is_wire())
                qbit_to_cp[qbit] = &cp;
        }

        for (auto &conn : mod->connections()) {
            RTLIL::SigSpec lhs = sigmap(conn.first);
            RTLIL::SigSpec rhs = sigmap(conn.second);
            int width = std::min(GetSize(lhs), GetSize(rhs));
            for (int i = 0; i < width; i++)
                if (lhs[i].is_wire() && rhs[i].is_wire() && lhs[i] != rhs[i])
                    deps[lhs[i]].insert(rhs[i]);
        }

        for (auto cell : mod->cells()) {
            pool<RTLIL::SigBit> input_bits;
            pool<RTLIL::SigBit> output_bits;
            bool is_ff = cell->is_builtin_ff() || cell->type == ID($anyinit) || cell->type.contains("DFF");

            for (auto &conn : cell->connections()) {
                RTLIL::IdString port = conn.first;
                RTLIL::SigSpec sig = sigmap(conn.second);
                bool is_output = yosys_celltypes.cell_output(cell->type, port);
                bool is_input = yosys_celltypes.cell_input(cell->type, port);

                if (is_output)
                    for (auto bit : sig)
                        if (bit.is_wire())
                            output_bits.insert(bit);
                if (!is_output && is_input)
                    for (auto bit : sig)
                        if (bit.is_wire())
                            input_bits.insert(bit);
            }

            if (is_ff)
                continue;

            for (auto out_bit : output_bits)
                for (auto in_bit : input_bits)
                    if (out_bit != in_bit)
                        deps[out_bit].insert(in_bit);
        }

        pool<RTLIL::SigBit> visited;
        std::vector<RTLIL::SigBit> stack;
        bool ok = false;
        RTLIL::SigBit seed = sigmap(get_cutpoint_d_bit(mod, candidate, use_gold, ok));
        if (!ok || !seed.is_wire())
            return;
        stack.push_back(seed);

        while (!stack.empty()) {
            RTLIL::SigBit bit = stack.back();
            stack.pop_back();
            if (!bit.is_wire() || visited.count(bit))
                continue;
            visited.insert(bit);

            if (qbit_to_cp.count(bit)) {
                selected.insert(qbit_to_cp.at(bit)->name);
                continue;
            }

            if (bit.wire->port_input)
                continue;
            if (!deps.count(bit))
                continue;
            for (auto dep_bit : deps.at(bit))
                if (dep_bit.is_wire() && !visited.count(dep_bit))
                    stack.push_back(dep_bit);
        }
    };

    pool<RTLIL::IdString> selected_names;
    collect_slice(gold_mod, true, selected_names);
    collect_slice(gate_mod, false, selected_names);
    selected_names.insert(candidate.name);

    std::vector<CutPoint> out;
    for (const auto &cp : all_cps)
        if (is_dff_cp(cp) && selected_names.count(cp.name))
            out.push_back(cp);
    if (is_dff_cp(candidate)) {
        bool found = false;
        for (const auto &cp : out)
            if (cp.name == candidate.name && cp.type == candidate.type) {
                found = true;
                break;
            }
        if (!found)
            out.push_back(candidate);
    }
    return dedup_local_dff_cutpoints(out);
}

string region_boundary_key(const string &child_mod_orig,
                                  const RTLIL::IdString &child_cell,
                                  const RTLIL::IdString &port,
                                  int bit_index)
{
    return child_mod_orig + "||" + strip_backslash(child_cell) + "||" +
        strip_backslash(port) + "||" + std::to_string(bit_index);
}

string region_artifact_path(const string &dir_name, const string &prefix,
                                   const RTLIL::IdString &top_mod)
{
    return dir_name + "/" + prefix + "_" + sanitize_filename(strip_backslash(top_mod)) + ".jsonl";
}

Json json_array_from_ints(const std::vector<int> &values)
{
    Json::array out;
    for (int value : values)
        out.push_back(value);
    return out;
}

Json json_array_from_strings(const std::vector<string> &values)
{
    Json::array out;
    for (const auto &value : values)
        out.push_back(value);
    return out;
}

string wire_bit_name(const RTLIL::IdString &wire_name, int width, int index)
{
    string base = strip_backslash(wire_name);
    if (width <= 1)
        return base;
    return stringf("%s[%d]", base.c_str(), index);
}

void add_sample_name(std::vector<string> &samples, const string &name, size_t limit)
{
    if (samples.size() >= limit)
        return;
    for (const auto &existing : samples)
        if (existing == name)
            return;
    samples.push_back(name);
}

int parse_name_map_applied(const string &output)
{
    size_t pos = output.find("Name map: applied ");
    if (pos == string::npos)
        return 0;
    pos += strlen("Name map: applied ");
    return atoi(output.c_str() + pos);
}

int parse_constant_completed_net_count(const string &output)
{
    int total = 0;
    const string pattern = "Constant-0 drivers added to ";
    size_t pos = 0;
    while ((pos = output.find(pattern, pos)) != string::npos) {
        pos += pattern.size();
        total += atoi(output.c_str() + pos);
    }
    return total;
}

string canonical_region_boundary_wire(const CheckConfig &conf,
                                             const RegionBoundary &boundary)
{
    RTLIL::IdString child_orig = get_orignal_mod_name(boundary.gold_child_mod, conf.gold_mod->name, conf.gold_prefix);
    string base = stringf("__region__%s__%s__%s",
        sanitize_filename(strip_backslash(child_orig)).c_str(),
        sanitize_filename(strip_backslash(boundary.gold_child_cell)).c_str(),
        sanitize_filename(strip_backslash(boundary.gold_port)).c_str());
    return base;
}


std::vector<RegionBoundary> merge_region_boundaries(const CheckConfig &conf,
                                                           RTLIL::Module *gold_mod,
                                                           RTLIL::Module *gate_mod,
                                                           const std::vector<ChildBoundaryPort> &gold_boundaries,
                                                           const std::vector<ChildBoundaryPort> &gate_boundaries)
{
    dict<string, ChildBoundaryPort> gate_by_key;
    for (const auto &boundary : gate_boundaries) {
        RTLIL::IdString gate_child_orig = get_orignal_mod_name(boundary.child_mod, conf.gate_mod->name, conf.gate_prefix);
        string key = region_boundary_key(strip_backslash(gate_child_orig), boundary.child_cell, boundary.port, boundary.bit_index);
        gate_by_key[key] = boundary;
    }

    std::vector<RegionBoundary> out;
    for (const auto &gold_boundary : gold_boundaries) {
        RTLIL::IdString gold_child_orig = get_orignal_mod_name(gold_boundary.child_mod, conf.gold_mod->name, conf.gold_prefix);
        string key = region_boundary_key(strip_backslash(gold_child_orig), gold_boundary.child_cell, gold_boundary.port, gold_boundary.bit_index);
        if (!gate_by_key.count(key))
            continue;

        const auto &gate_boundary = gate_by_key.at(key);
        RegionBoundary boundary;
        boundary.parent_gold_mod = gold_mod->name;
        boundary.parent_gate_mod = gate_mod->name;
        boundary.gold_child_cell = gold_boundary.child_cell;
        boundary.gate_child_cell = gate_boundary.child_cell;
        boundary.gold_child_mod = gold_boundary.child_mod;
        boundary.gate_child_mod = gate_boundary.child_mod;
        boundary.gold_port = gold_boundary.port;
        boundary.gate_port = gate_boundary.port;
        boundary.gold_local_wire = gold_boundary.local_wire;
        boundary.gate_local_wire = gate_boundary.local_wire;
        boundary.bit_index = gold_boundary.bit_index;
        boundary.boundary_kind = "child_output";
        boundary.canonical_wire = RTLIL::escape_id(canonical_region_boundary_wire(conf, boundary));
        out.push_back(boundary);
    }

    return out;
}

void apply_region_boundary_canonical_names(RTLIL::Module *gold_mod,
                                                  RTLIL::Module *gate_mod,
                                                  std::vector<RegionBoundary> &boundaries)
{
    dict<RTLIL::IdString, RTLIL::IdString> gold_renames;
    dict<RTLIL::IdString, RTLIL::IdString> gate_renames;
    for (const auto &boundary : boundaries) {
        gold_renames[boundary.gold_local_wire] = boundary.canonical_wire;
        gate_renames[boundary.gate_local_wire] = boundary.canonical_wire;
    }

    auto apply_renames = [](RTLIL::Module *mod, const dict<RTLIL::IdString, RTLIL::IdString> &renames) {
        for (const auto &it : renames) {
            RTLIL::Wire *wire = mod->wire(it.first);
            if (wire == nullptr || wire->name == it.second)
                continue;
            if (mod->wire(it.second) != nullptr && mod->wire(it.second) != wire)
                continue;
            mod->rename(wire, it.second);
        }
        mod->fixup_ports();
    };

    apply_renames(gold_mod, gold_renames);
    apply_renames(gate_mod, gate_renames);

    for (auto &boundary : boundaries) {
        boundary.gold_local_wire = boundary.canonical_wire;
        boundary.gate_local_wire = boundary.canonical_wire;
    }
}

pool<string> region_boundary_bit_names(const std::vector<RegionBoundary> &boundaries)
{
    pool<string> out;
    for (const auto &boundary : boundaries) {
        out.insert(wire_bit_name(boundary.canonical_wire, boundary.bit_index + 1, boundary.bit_index));
    }
    return out;
}

pool<string> collect_module_interface_input_bit_names(RTLIL::Module *mod)
{
    pool<string> out;
    for (auto *w : mod->wires()) {
        if (!w->port_input)
            continue;
        int width = std::max(1, GetSize(w));
        for (int i = 0; i < width; i++)
            out.insert(wire_bit_name(w->name, width, i));
    }
    return out;
}

pool<string> collect_state_cut_input_bit_names(const std::vector<CutPoint> &cutpoints)
{
    pool<string> out;
    for (const auto &cp : cutpoints)
        out.insert(wire_bit_name(RTLIL::escape_id(strip_backslash(cp.name) + "_pi"), 1, 0));
    return out;
}

void collect_wire_usage(RTLIL::Module *mod,
                               pool<string> &driven_bits,
                               pool<string> &used_bits)
{
    SigMap sigmap(mod);
    auto add_sig = [&](const RTLIL::SigSpec &sig, pool<string> &dst) {
        RTLIL::SigSpec mapped = sigmap(sig);
        for (auto bit : mapped) {
            if (!bit.is_wire())
                continue;
            RTLIL::Wire *w = bit.wire;
            int width = std::max(1, GetSize(w));
            int index = bit.offset;
            dst.insert(wire_bit_name(w->name, width, index));
        }
    };

    for (auto &conn : mod->connections()) {
        add_sig(conn.first, driven_bits);
        add_sig(conn.second, used_bits);
    }

    for (auto *cell : mod->cells()) {
        for (auto &conn : cell->connections()) {
            RTLIL::IdString port = conn.first;
            if (yosys_celltypes.cell_output(cell->type, port))
                add_sig(conn.second, driven_bits);
            if (yosys_celltypes.cell_input(cell->type, port))
                add_sig(conn.second, used_bits);
        }
    }
}

pool<string> promote_traceable_internal_boundaries(RTLIL::Module *gold_mod,
                                                          RTLIL::Module *gate_mod)
{
    pool<string> gold_driven, gold_used, gate_driven, gate_used;
    collect_wire_usage(gold_mod, gold_driven, gold_used);
    collect_wire_usage(gate_mod, gate_driven, gate_used);

    pool<string> promoted_bits;
    for (auto *gold_wire : gold_mod->wires()) {
        if (gold_wire->port_input || gold_wire->port_output)
            continue;
        RTLIL::Wire *gate_wire = gate_mod->wire(gold_wire->name);
        if (gate_wire == nullptr)
            continue;
        if (gate_wire->port_input || gate_wire->port_output)
            continue;
        if (GetSize(gold_wire) != GetSize(gate_wire))
            continue;

        int width = std::max(1, GetSize(gold_wire));
        bool promote_wire = width > 0;
        for (int i = 0; i < width; i++) {
            string bit_name = wire_bit_name(gold_wire->name, width, i);
            bool gold_candidate = !gold_driven.count(bit_name) && gold_used.count(bit_name);
            bool gate_candidate = !gate_driven.count(bit_name) && gate_used.count(bit_name);
            if (!(gold_candidate && gate_candidate)) {
                promote_wire = false;
                break;
            }
        }
        if (!promote_wire)
            continue;

        gold_wire->port_input = true;
        gate_wire->port_input = true;
        for (int i = 0; i < width; i++)
            promoted_bits.insert(wire_bit_name(gold_wire->name, width, i));
    }

    gold_mod->fixup_ports();
    gate_mod->fixup_ports();
    return promoted_bits;
}

void audit_shell_inputs(PartitionedPair &pair,
                               RTLIL::Module *gold_orig,
                               const std::vector<CutPoint> &cutpoints)
{
    pool<string> module_interface_inputs = collect_module_interface_input_bit_names(gold_orig);
    pool<string> state_cut_inputs = collect_state_cut_input_bit_names(cutpoints);

    pair.allowed_shell_input_bit_names = module_interface_inputs;
    for (const auto &bit_name : state_cut_inputs)
        pair.allowed_shell_input_bit_names.insert(bit_name);
    for (const auto &bit_name : pair.boundary_bit_names)
        pair.allowed_shell_input_bit_names.insert(bit_name);
    for (const auto &bit_name : pair.promoted_internal_boundary_bit_names)
        pair.allowed_shell_input_bit_names.insert(bit_name);

    pool<string> seen_input_bits;
    for (auto *w : pair.gold_local->wires()) {
        if (!w->port_input)
            continue;
        int width = std::max(1, GetSize(w));
        for (int i = 0; i < width; i++) {
            string bit_name = wire_bit_name(w->name, width, i);
            if (seen_input_bits.count(bit_name))
                continue;
            seen_input_bits.insert(bit_name);

            if (module_interface_inputs.count(bit_name)) {
                pair.module_interface_input_count++;
                continue;
            }
            if (state_cut_inputs.count(bit_name)) {
                pair.state_cut_input_count++;
                continue;
            }
            if (pair.boundary_bit_names.count(bit_name)) {
                pair.child_boundary_input_count++;
                continue;
            }
            if (pair.promoted_internal_boundary_bit_names.count(bit_name)) {
                pair.promoted_internal_boundary_count++;
                add_sample_name(pair.promoted_internal_boundary_samples, bit_name, 8);
                continue;
            }

            pair.unresolved_internal_input_count++;
            add_sample_name(pair.unresolved_internal_input_samples, bit_name, 8);
        }
    }

    pair.unresolved_internal_boundaries = pair.unresolved_internal_input_count;
}

std::vector<ChildBoundaryPort> submod_to_pi_po(RTLIL::Design *design, RTLIL::Module *mod)
{
    assert(design);
    assert(mod);

    SigMap sigmap(mod);
    pool<RTLIL::SigBit> cut_bits;
    std::vector<RTLIL::SigSig> pending_conns;
    std::vector<RTLIL::Cell*> remove_cells;
    std::vector<ChildBoundaryPort> boundaries;

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
                    boundaries.push_back(ChildBoundaryPort{
                        mod->name,
                        cell->name,
                        child->name,
                        port->name,
                        w_pi->name,
                        i
                    });
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
    return boundaries;
}

void restrict_local_output_ports(RTLIL::Module *mod)
{
    for (auto *w : mod->wires()) {
        if (!w->port_output)
            continue;
        string name = strip_backslash(w->name);
        if (name.size() >= 3 && name.substr(name.size() - 3) == "_po")
            continue;
        w->port_output = false;
    }
    mod->fixup_ports();
}

bool abc_cec_module(const CheckConfig &conf, bool fatal, CommandResult *deciding_result);

std::vector<RTLIL::Module*> topo_sort_modules(RTLIL::Design *design, const RTLIL::IdString& root);

// The function still has bug
[[maybe_unused]] void remove_subclk(RTLIL::Design* design, CheckConfig& conf) {

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

PartitionedPair partition_module(RTLIL::Design *design, RTLIL::Design *design_check,
    RTLIL::Module *gold_mod, RTLIL::Module *gate_mod,  //pointer in design
    const std::vector<CutPoint>& cutpoints, const CheckConfig& conf)
{
    log_assert(design);
    log_assert(design_check);
    log_assert(gold_mod);
    log_assert(gate_mod);
    (void) conf;

    RTLIL::Module *gold_clone = gold_mod->clone();
    RTLIL::Module *gate_clone = gate_mod->clone();

    gold_clone->name = RTLIL::escape_id(strip_backslash(gold_mod->name) + "__local");
    gate_clone->name = RTLIL::escape_id(strip_backslash(gate_mod->name) + "__local");

    // convert_ff_to_fine(gold_clone);
    // convert_ff_to_fine(gate_clone);

    cutpoints_to_pi_po(gold_clone, cutpoints, true);
    cutpoints_to_pi_po(gate_clone, cutpoints, false);

    std::vector<ChildBoundaryPort> gold_boundaries = submod_to_pi_po(design, gold_clone);
    std::vector<ChildBoundaryPort> gate_boundaries = submod_to_pi_po(design, gate_clone);
    std::vector<RegionBoundary> boundaries =
        merge_region_boundaries(conf, gold_mod, gate_mod, gold_boundaries, gate_boundaries);
    apply_region_boundary_canonical_names(gold_clone, gate_clone, boundaries);
    pool<string> promoted_internal_boundary_bit_names =
        promote_traceable_internal_boundaries(gold_clone, gate_clone);
    restrict_local_output_ports(gold_clone);
    restrict_local_output_ports(gate_clone);

    design_check->add(gold_clone);
    design_check->add(gate_clone);
    run_pass("opt_clean", design_check);
    run_pass("check", design_check);

    PartitionedPair result;
    result.gold_local = design_check->module(gold_clone->name);
    result.gate_local = design_check->module(gate_clone->name);
    result.boundaries = boundaries;
    result.boundary_bit_names = region_boundary_bit_names(boundaries);
    result.promoted_internal_boundary_bit_names = promoted_internal_boundary_bit_names;
    result.residual_hierarchy = !result.boundaries.empty();
    audit_shell_inputs(result, gold_mod, cutpoints);
    return result;
}

// Maybe implement further.
[[maybe_unused]] void partition_design_for_check(RTLIL::Design *design, RTLIL::Design *design_check, 
    const CheckConfig& conf, ModMap& mod_map,
    const dict<RTLIL::Module*, std::vector<CutPoint>>& gold2cutpoints)
{
    for(const auto &[gold_mod, cutpoints] : gold2cutpoints){
        RTLIL::IdString gold_mod_name = gold_mod->name;
        RTLIL::IdString gate_mod_name = mod_map.mod_map_gold.at(gold_mod_name);
        RTLIL::Module *gate_mod = design->module(gate_mod_name);

        auto module_partition =
            partition_module(design, design_check, gold_mod, gate_mod, cutpoints, conf);
        (void)module_partition;
    }
}

LocalValidateResult validate_partition_pair(const CheckConfig &conf,
                                                   RTLIL::Module *gold_mod,
                                                   RTLIL::Module *gate_mod,
                                                   const std::vector<CutPoint> &cutpoints,
                                                   bool allow_bmc_fallback)
{
    auto t_start = std::chrono::steady_clock::now();
    LocalValidateResult result;
    result.pair_id = get_pair_id(gold_mod->name, gate_mod->name);
    result.selected_cutpoints = GetSize(cutpoints);

    RTLIL::Design *design_check = empty_design();
    auto local_pair = partition_module(conf.design, design_check, gold_mod, gate_mod, cutpoints, conf);
    result.child_boundary_count = GetSize(local_pair.boundaries);
    result.boundary_map_expected =
        GetSize(local_pair.boundary_bit_names) + GetSize(local_pair.promoted_internal_boundary_bit_names);
    result.unresolved_internal_boundaries = local_pair.unresolved_internal_boundaries;
    result.module_interface_input_count = local_pair.module_interface_input_count;
    result.state_cut_input_count = local_pair.state_cut_input_count;
    result.child_boundary_input_count = local_pair.child_boundary_input_count;
    result.promoted_internal_boundary_count = local_pair.promoted_internal_boundary_count;
    result.unresolved_internal_input_count = local_pair.unresolved_internal_input_count;
    result.promoted_internal_boundary_samples = local_pair.promoted_internal_boundary_samples;
    result.unresolved_internal_input_samples = local_pair.unresolved_internal_input_samples;
    result.residual_hierarchy = local_pair.residual_hierarchy;

    GuideTelemetry local_telemetry;
    CheckConfig local_conf = conf;
    local_conf.design = design_check;
    local_conf.gold_mod = local_pair.gold_local;
    local_conf.gate_mod = local_pair.gate_local;
    local_conf.sched_model_file = "";
    local_conf.match_model_file = "";
    local_conf.accept_match_suggestions_file = "";
    local_conf.dump_cfg = MlDumpConfig();
    local_conf.sched_model = nullptr;
    local_conf.match_model = nullptr;
    local_conf.telemetry = &local_telemetry;

    MatchResult local_match =
        match_signals_module(design_check, local_conf.gold_mod, local_conf.gate_mod,
                             local_conf, true, "local_partition");
    local_telemetry.pair_match_stats[get_pair_id(local_conf.gold_mod->name, local_conf.gate_mod->name)] =
        local_match.stats;

    result.local_exact_total = local_match.stats.exact_total;
    for (const auto &cp : local_match.cut_points)
        if (local_pair.boundary_bit_names.count(strip_backslash(cp.name)) ||
            local_pair.promoted_internal_boundary_bit_names.count(strip_backslash(cp.name)))
            result.boundary_map_applied++;

    result.ran = true;
    CommandResult local_abc_result;
    result.proved = abc_cec_module(local_conf, false, &local_abc_result);
    result.validator_backend = "local_abc";
    int abc_name_map_applied = parse_name_map_applied(local_abc_result.output);
    if (result.boundary_map_applied == 0 && abc_name_map_applied > 0)
        result.boundary_map_applied = std::min(result.boundary_map_expected, abc_name_map_applied);
    result.constant_completed_net_count = parse_constant_completed_net_count(local_abc_result.output);
    result.unsafe_reason = partition_unsafe_reason(local_abc_result);
    if (!result.unsafe_reason.empty())
        result.authoritative_ok = false;
    if (result.unresolved_internal_boundaries > 0) {
        result.authoritative_ok = false;
        if (result.fallback_reason.empty())
            result.fallback_reason = "unresolved_internal_boundaries";
    }
    if (result.constant_completed_net_count > 0) {
        result.authoritative_ok = false;
        if (result.fallback_reason.empty())
            result.fallback_reason = "constant_completed_nets";
    }
    if (result.boundary_map_expected > 0 && result.boundary_map_applied == 0) {
        result.authoritative_ok = false;
        if (result.fallback_reason.empty())
            result.fallback_reason = "boundary_map_not_applied";
    }
    if (result.proved && result.authoritative_ok)
        result.authoritative_reason = "closed_shell";

    if (!result.proved && allow_bmc_fallback) {
        bool residual_state = module_has_dff(local_conf.gold_mod, false) || module_has_dff(local_conf.gate_mod, true);
        bool residual_hierarchy = module_has_submodule(design_check, local_conf.gold_mod) || module_has_submodule(design_check, local_conf.gate_mod);
        if (residual_state || residual_hierarchy) {
            result.used_bmc_fallback = true;
            bool bmc_ok = bmcinduct_check(local_conf);
            result.validator_backend = "local_abc_bmc";
            if (bmc_ok)
                result.proved = true;
        }
    }
    auto t_end = std::chrono::steady_clock::now();
    result.runtime_ms = std::chrono::duration_cast<std::chrono::milliseconds>(t_end - t_start).count();

    delete design_check;
    return result;
}

void run_local_validate_shadow(const CheckConfig &conf, ModMap &mod_map,
                                      const dict<RTLIL::Module*, std::vector<CutPoint>> &gold2cutpoints)
{
    int ran_pairs = 0;
    int skipped_pairs = 0;
    int passed_pairs = 0;
    int failed_pairs = 0;

    log("Running local DFF shadow validation.\n");
    string artifact_dir = match_artifact_dir(conf);
    for (const auto &[gold_name, gate_name] : mod_map.mod_map_gold) {
        RTLIL::Module *gold_mod = conf.design->module(gold_name);
        RTLIL::Module *gate_mod = conf.design->module(gate_name);
        if (gold_mod == nullptr || gate_mod == nullptr)
            continue;
        if (!gold2cutpoints.count(gold_mod))
            continue;

        std::vector<CutPoint> local_cutpoints =
            filter_materializable_cutpoints(gold_mod, gate_mod,
                select_local_dff_cutpoints(gold2cutpoints.at(gold_mod)));
        if (local_cutpoints.empty()) {
            skipped_pairs++;
            log("LOCAL_VALIDATE shadow skipped for %s: no DFF cutpoints.\n",
                get_pair_id(gold_name, gate_name).c_str());
            continue;
        }

        LocalValidateResult result = validate_partition_pair(conf, gold_mod, gate_mod, local_cutpoints, false);
        append_jsonl(pair_artifact_path(artifact_dir, "local_validate", gold_mod, gate_mod, ".jsonl"), Json::object {
            {"design", strip_backslash(conf.gold_mod->name)},
            {"gold_mod", strip_backslash(gold_mod->name)},
            {"gate_mod", strip_backslash(gate_mod->name)},
            {"pair_id", result.pair_id},
            {"signal_name", ""},
            {"match_type", "DFF_SET"},
            {"source", "shadow_dff_set"},
            {"score", 0},
            {"margin", 0},
            {"validator_result", result.proved ? "pass" : "fail"},
            {"validator_backend", result.validator_backend},
            {"used_bmc_fallback", result.used_bmc_fallback},
            {"authoritative_ok", result.authoritative_ok},
            {"authoritative_reason", result.authoritative_reason},
            {"unsafe_reason", result.unsafe_reason},
            {"fallback_reason", result.fallback_reason},
            {"runtime_ms", result.runtime_ms},
            {"accepted", false},
            {"selected_cutpoints", result.selected_cutpoints},
            {"local_exact_total", result.local_exact_total},
            {"boundary_map_expected", result.boundary_map_expected},
            {"boundary_map_applied", result.boundary_map_applied},
            {"constant_completed_net_count", result.constant_completed_net_count},
            {"module_interface_input_count", result.module_interface_input_count},
            {"state_cut_input_count", result.state_cut_input_count},
            {"child_boundary_input_count", result.child_boundary_input_count},
            {"promoted_internal_boundary_count", result.promoted_internal_boundary_count},
            {"unresolved_internal_input_count", result.unresolved_internal_input_count},
            {"promoted_internal_boundary_samples", json_array_from_strings(result.promoted_internal_boundary_samples)},
            {"unresolved_internal_input_samples", json_array_from_strings(result.unresolved_internal_input_samples)},
            {"unresolved_internal_boundaries", result.unresolved_internal_boundaries},
            {"child_boundary_count", result.child_boundary_count},
            {"unresolved_child_boundaries", result.unresolved_child_boundaries}
        });
        ran_pairs++;
        if (result.proved)
            passed_pairs++;
        else
            failed_pairs++;

        log("LOCAL_VALIDATE shadow for %s: %s (%d DFF cutpoints, local exact=%d).\n",
            result.pair_id.c_str(),
            result.proved ? "\033[1;32mPASSED\033[0m" : "\033[1;31mFAILED\033[0m",
            result.selected_cutpoints,
            result.local_exact_total);
    }

    log("LOCAL_VALIDATE shadow summary: ran %d pair(s), passed %d, failed %d, skipped %d.\n",
        ran_pairs, passed_pairs, failed_pairs, skipped_pairs);
}

bool valid_region_child_module(RTLIL::Design *design, RTLIL::Cell *cell, RTLIL::Module *&child)
{
    child = design->module(cell->type);
    if (child == nullptr)
        return false;
    if (yosys_celltypes.cell_known(cell->type))
        return false;
    if (child->get_blackbox_attribute())
        return false;
    return true;
}

std::vector<RegionBoundary> collect_region_child_boundaries(const CheckConfig &conf,
                                                                   const ModMap &mod_map,
                                                                   RTLIL::Module *gold_mod,
                                                                   RTLIL::Module *gate_mod)
{
    std::vector<RegionBoundary> out;
    for (auto *gold_cell : gold_mod->cells()) {
        RTLIL::Module *gold_child = nullptr;
        if (!valid_region_child_module(conf.design, gold_cell, gold_child))
            continue;
        RTLIL::Cell *gate_cell = gate_mod->cell(gold_cell->name);
        if (gate_cell == nullptr)
            continue;
        RTLIL::Module *gate_child = nullptr;
        if (!valid_region_child_module(conf.design, gate_cell, gate_child))
            continue;
        if (!mod_map.mod_map_gold.count(gold_child->name))
            continue;
        if (mod_map.mod_map_gold.at(gold_child->name) != gate_child->name)
            continue;

        std::vector<RTLIL::Wire*> gold_ports;
        for (auto *w : gold_child->wires())
            if (w->port_id > 0 && w->port_output)
                gold_ports.push_back(w);
        std::sort(gold_ports.begin(), gold_ports.end(),
                  [](RTLIL::Wire *a, RTLIL::Wire *b){ return a->port_id < b->port_id; });

        for (auto *gold_port : gold_ports) {
            RTLIL::Wire *gate_port = gate_child->wire(gold_port->name);
            if (gate_port == nullptr || !gate_port->port_output)
                continue;
            int width = std::min(GetSize(gold_port), GetSize(gate_port));
            for (int i = 0; i < width; i++) {
                RegionBoundary boundary;
                boundary.parent_gold_mod = gold_mod->name;
                boundary.parent_gate_mod = gate_mod->name;
                boundary.gold_child_cell = gold_cell->name;
                boundary.gate_child_cell = gate_cell->name;
                boundary.gold_child_mod = gold_child->name;
                boundary.gate_child_mod = gate_child->name;
                boundary.gold_port = gold_port->name;
                boundary.gate_port = gate_port->name;
                boundary.bit_index = i;
                boundary.boundary_kind = "child_output";
                out.push_back(boundary);
            }
        }
    }
    return out;
}

std::vector<RegionNode> build_region_plan(const CheckConfig &conf,
                                                 const ModMap &mod_map,
                                                 const dict<RTLIL::Module*, std::vector<CutPoint>> &gold2cutpoints)
{
    std::vector<RegionNode> nodes;
    dict<RTLIL::IdString, int> region_by_gold;
    auto sorted_mods = topo_sort_modules(conf.design, conf.gold_mod->name);

    for (auto *gold_mod : sorted_mods) {
        if (!mod_map.mod_map_gold.count(gold_mod->name))
            continue;
        RTLIL::Module *gate_mod = conf.design->module(mod_map.mod_map_gold.at(gold_mod->name));
        if (gate_mod == nullptr)
            continue;
        if (gold_mod->get_blackbox_attribute() || gate_mod->get_blackbox_attribute())
            continue;

        RegionNode node;
        node.region_id = GetSize(nodes);
        node.gold_mod = gold_mod;
        node.gate_mod = gate_mod;
        node.is_top = gold_mod->name == conf.gold_mod->name;
        if (gold2cutpoints.count(gold_mod)) {
            node.state_cutpoints = select_region_state_cutpoints(gold2cutpoints.at(gold_mod));
            node.child_boundary_cps = select_region_child_boundary_cutpoints(gold2cutpoints.at(gold_mod));
        }
        node.child_boundaries = collect_region_child_boundaries(conf, mod_map, gold_mod, gate_mod);
        nodes.push_back(node);
        region_by_gold[gold_mod->name] = node.region_id;
    }

    for (auto &node : nodes) {
        pool<int> child_ids;
        for (const auto &boundary : node.child_boundaries) {
            if (!region_by_gold.count(boundary.gold_child_mod)) {
                node.unresolved_child_boundary_count++;
                continue;
            }
            int child_id = region_by_gold.at(boundary.gold_child_mod);
            child_ids.insert(child_id);
            nodes[child_id].parent_region_ids.push_back(node.region_id);
        }
        for (int child_id : child_ids)
            node.child_region_ids.push_back(child_id);
        node.is_leaf = node.child_region_ids.empty();
    }

    return nodes;
}

Results partition_prove(const CheckConfig &conf, ModMap &mod_map,
                               const dict<RTLIL::Module*, std::vector<CutPoint>> &gold2cutpoints)
{
    Results results;
    string artifact_dir = match_artifact_dir(conf);
    string region_plan_jsonl = region_artifact_path(artifact_dir, "region_plan", conf.gold_mod->name);
    string region_proof_jsonl = region_artifact_path(artifact_dir, "region_proof", conf.gold_mod->name);
    remove(region_plan_jsonl.c_str());
    remove(region_proof_jsonl.c_str());

    log("Running region-driven proving branch.\n");

    std::vector<RegionNode> nodes = build_region_plan(conf, mod_map, gold2cutpoints);
    std::vector<RegionProofResult> proof_results(GetSize(nodes));

    for (const auto &node : nodes) {
        Json::array child_ids;
        for (int child_id : node.child_region_ids)
            child_ids.push_back(child_id);
        Json::array parent_ids;
        for (int parent_id : node.parent_region_ids)
            parent_ids.push_back(parent_id);
        append_jsonl(region_plan_jsonl, Json::object {
            {"region_id", node.region_id},
            {"gold_mod", strip_backslash(node.gold_mod->name)},
            {"gate_mod", strip_backslash(node.gate_mod->name)},
            {"is_top", node.is_top},
            {"is_leaf", node.is_leaf},
            {"parent_region_ids", parent_ids},
            {"child_region_ids", child_ids},
            {"state_cutpoint_count", int(node.state_cutpoints.size())},
            {"child_boundary_count", int(node.child_boundaries.size())},
            {"subckt_cutpoint_count", int(node.child_boundary_cps.size())},
            {"unresolved_child_boundary_count", node.unresolved_child_boundary_count},
            {"residual_hierarchy", !node.child_boundaries.empty()}
        });
    }

    for (const auto &node : nodes) {
        RegionProofResult region_result;
        region_result.region_id = node.region_id;
        region_result.child_boundary_count = GetSize(node.child_boundaries);
        region_result.unresolved_child_boundaries = node.unresolved_child_boundary_count;

        bool children_discharged = true;
        for (int child_id : node.child_region_ids) {
            const auto &child_result = proof_results.at(child_id);
            if (!child_result.obligation_discharged) {
                children_discharged = false;
                break;
            }
        }
        region_result.children_discharged = children_discharged;

        std::vector<CutPoint> local_cutpoints =
            filter_materializable_cutpoints(node.gold_mod, node.gate_mod, node.state_cutpoints);
        bool shell_attempted = !local_cutpoints.empty() || !node.child_boundaries.empty();
        if (shell_attempted) {
            LocalValidateResult shell_result =
                validate_partition_pair(conf, node.gold_mod, node.gate_mod, local_cutpoints, true);
            region_result.shell_proved = shell_result.proved;
            region_result.selected_cutpoints = shell_result.selected_cutpoints;
            region_result.local_exact_total = shell_result.local_exact_total;
            region_result.child_boundary_count = shell_result.child_boundary_count;
            region_result.unresolved_child_boundaries = shell_result.unresolved_child_boundaries;
            region_result.boundary_map_expected = shell_result.boundary_map_expected;
            region_result.boundary_map_applied = shell_result.boundary_map_applied;
            region_result.constant_completed_net_count = shell_result.constant_completed_net_count;
            region_result.unresolved_internal_boundaries = shell_result.unresolved_internal_boundaries;
            region_result.module_interface_input_count = shell_result.module_interface_input_count;
            region_result.state_cut_input_count = shell_result.state_cut_input_count;
            region_result.child_boundary_input_count = shell_result.child_boundary_input_count;
            region_result.promoted_internal_boundary_count = shell_result.promoted_internal_boundary_count;
            region_result.unresolved_internal_input_count = shell_result.unresolved_internal_input_count;
            region_result.promoted_internal_boundary_samples = shell_result.promoted_internal_boundary_samples;
            region_result.unresolved_internal_input_samples = shell_result.unresolved_internal_input_samples;
            region_result.residual_hierarchy = shell_result.residual_hierarchy;
            region_result.runtime_ms = shell_result.runtime_ms;
            region_result.backend = shell_result.validator_backend;
            region_result.unsafe_reason = shell_result.unsafe_reason;
            region_result.authoritative_ok =
                shell_result.authoritative_ok &&
                region_result.unresolved_child_boundaries == 0 &&
                region_result.unresolved_internal_boundaries == 0 &&
                region_result.constant_completed_net_count == 0 &&
                (region_result.boundary_map_expected == 0 || region_result.boundary_map_applied > 0) &&
                children_discharged;
            if (!children_discharged && region_result.fallback_reason.empty())
                region_result.fallback_reason = "child_obligations_not_discharged";
            if (region_result.unresolved_child_boundaries > 0 && region_result.fallback_reason.empty())
                region_result.fallback_reason = "unresolved_child_boundaries";
            if (region_result.unresolved_internal_boundaries > 0 && region_result.fallback_reason.empty())
                region_result.fallback_reason = "unresolved_internal_boundaries";
            if (region_result.constant_completed_net_count > 0 && region_result.fallback_reason.empty())
                region_result.fallback_reason = "constant_completed_nets";
            if (region_result.boundary_map_expected > 0 && region_result.boundary_map_applied == 0 && region_result.fallback_reason.empty())
                region_result.fallback_reason = "boundary_map_not_applied";
            if (!shell_result.authoritative_ok && region_result.fallback_reason.empty())
                region_result.fallback_reason = !shell_result.fallback_reason.empty() ? shell_result.fallback_reason : shell_result.unsafe_reason;
            region_result.proved = region_result.shell_proved && children_discharged;
            region_result.obligation_discharged = region_result.proved && region_result.authoritative_ok;
            if (region_result.authoritative_ok)
                region_result.authoritative_reason = "closed_region_shell";

            append_jsonl(pair_artifact_path(artifact_dir, "local_validate", node.gold_mod, node.gate_mod, ".jsonl"), Json::object {
                {"design", strip_backslash(conf.gold_mod->name)},
                {"gold_mod", strip_backslash(node.gold_mod->name)},
                {"gate_mod", strip_backslash(node.gate_mod->name)},
                {"pair_id", get_pair_id(node.gold_mod->name, node.gate_mod->name)},
                {"signal_name", ""},
                {"match_type", "REGION_SHELL"},
                {"source", "region_shell"},
                {"score", 0},
                {"margin", 0},
                {"validator_result", shell_result.proved ? "pass" : "fail"},
                {"validator_backend", shell_result.validator_backend},
                {"used_bmc_fallback", shell_result.used_bmc_fallback},
                {"authoritative_ok", region_result.authoritative_ok},
                {"authoritative_reason", region_result.authoritative_reason},
                {"unsafe_reason", shell_result.unsafe_reason},
                {"fallback_reason", region_result.fallback_reason},
                {"runtime_ms", shell_result.runtime_ms},
                {"accepted", false},
                {"selected_cutpoints", shell_result.selected_cutpoints},
                {"local_exact_total", shell_result.local_exact_total},
                {"boundary_map_expected", shell_result.boundary_map_expected},
                {"boundary_map_applied", shell_result.boundary_map_applied},
                {"constant_completed_net_count", shell_result.constant_completed_net_count},
                {"module_interface_input_count", shell_result.module_interface_input_count},
                {"state_cut_input_count", shell_result.state_cut_input_count},
                {"child_boundary_input_count", shell_result.child_boundary_input_count},
                {"promoted_internal_boundary_count", shell_result.promoted_internal_boundary_count},
                {"unresolved_internal_input_count", shell_result.unresolved_internal_input_count},
                {"promoted_internal_boundary_samples", json_array_from_strings(shell_result.promoted_internal_boundary_samples)},
                {"unresolved_internal_input_samples", json_array_from_strings(shell_result.unresolved_internal_input_samples)},
                {"unresolved_internal_boundaries", shell_result.unresolved_internal_boundaries},
                {"child_boundary_count", shell_result.child_boundary_count},
                {"unresolved_child_boundaries", shell_result.unresolved_child_boundaries}
            });
        } else {
            region_result.fallback_reason = "no_shell_obligation";
            region_result.authoritative_ok = false;
            region_result.obligation_discharged = false;
        }

        if (!region_result.proved || !region_result.authoritative_ok) {
            CheckConfig conf_ = conf;
            conf_.gold_mod = node.gold_mod;
            conf_.gate_mod = node.gate_mod;
            bool fallback_ok = abc_cec_module(conf_);
            if (region_result.fallback_reason.empty())
                region_result.fallback_reason = region_result.proved ? "non_authoritative_region" : "shell_failed";
            log("REGION proof for %s falling back to module-pair proof (%s).\n",
                get_pair_id(node.gold_mod->name, node.gate_mod->name).c_str(),
                region_result.fallback_reason.c_str());
            region_result.proved = fallback_ok;
            region_result.authoritative_ok = false;
            region_result.obligation_discharged = fallback_ok;
            if (region_result.backend.empty())
                region_result.backend = "module_pair_fallback";
            else
                region_result.backend += "+module_pair_fallback";
        }

        append_jsonl(region_proof_jsonl, Json::object {
            {"region_id", node.region_id},
            {"gold_mod", strip_backslash(node.gold_mod->name)},
            {"gate_mod", strip_backslash(node.gate_mod->name)},
            {"parent_region_ids", json_array_from_ints(node.parent_region_ids)},
            {"child_region_ids", json_array_from_ints(node.child_region_ids)},
            {"state_cutpoint_count", int(node.state_cutpoints.size())},
            {"child_boundary_count", region_result.child_boundary_count},
            {"shell_proved", region_result.shell_proved},
            {"children_discharged", region_result.children_discharged},
            {"obligation_discharged", region_result.obligation_discharged},
            {"authoritative_ok", region_result.authoritative_ok},
            {"authoritative_reason", region_result.authoritative_reason},
            {"proved", region_result.proved},
            {"unsafe_reason", region_result.unsafe_reason},
            {"fallback_reason", region_result.fallback_reason},
            {"backend", region_result.backend},
            {"runtime_ms", region_result.runtime_ms},
            {"selected_cutpoints", region_result.selected_cutpoints},
            {"local_exact_total", region_result.local_exact_total},
            {"boundary_map_expected", region_result.boundary_map_expected},
            {"boundary_map_applied", region_result.boundary_map_applied},
            {"constant_completed_net_count", region_result.constant_completed_net_count},
            {"module_interface_input_count", region_result.module_interface_input_count},
            {"state_cut_input_count", region_result.state_cut_input_count},
            {"child_boundary_input_count", region_result.child_boundary_input_count},
            {"promoted_internal_boundary_count", region_result.promoted_internal_boundary_count},
            {"unresolved_internal_input_count", region_result.unresolved_internal_input_count},
            {"promoted_internal_boundary_samples", json_array_from_strings(region_result.promoted_internal_boundary_samples)},
            {"unresolved_internal_input_samples", json_array_from_strings(region_result.unresolved_internal_input_samples)},
            {"unresolved_internal_boundaries", region_result.unresolved_internal_boundaries},
            {"unresolved_child_boundaries", region_result.unresolved_child_boundaries},
            {"residual_hierarchy", region_result.residual_hierarchy}
        });

        log("REGION proof for %s: %s (state cuts=%d, child boundaries=%d, children=%s).\n",
            get_pair_id(node.gold_mod->name, node.gate_mod->name).c_str(),
            region_result.proved ? "\033[1;32mPASSED\033[0m" : "\033[1;31mFAILED\033[0m",
            region_result.selected_cutpoints,
            region_result.child_boundary_count,
            region_result.children_discharged ? "discharged" : "pending");

        proof_results.at(node.region_id) = region_result;
        results.push_back({
            get_orignal_mod_name(node.gold_mod->name, conf.gold_mod->name, conf.gold_prefix),
            region_result.proved
        });
    }

    return results;
}

} // namespace guide_check
YOSYS_NAMESPACE_END
