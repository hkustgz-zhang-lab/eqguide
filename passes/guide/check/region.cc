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
static void refine_shell_closure(PartitionedPair &pair, RTLIL::Module *gold_orig, RTLIL::Module *gate_orig,
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

namespace {

struct BitTraceDB
{
    pool<string> module_input_bits;
    pool<string> used_bits;
    pool<string> driven_bits;
    pool<string> const_driven_bits;
    dict<string, std::pair<string, string>> assign_source;
    dict<string, string> cell_output_driver;
};

struct BitTraceInfo
{
    string kind = "other_unresolved";
    string source_id;
    bool traceable = false;
    bool promotable = false;
};

struct ShellAuditInfo
{
    int iface_in_cnt = 0;
    int state_in_cnt = 0;
    int child_in_cnt = 0;
    int alias_in_cnt = 0;
    int slice_res_cnt = 0;
    int trace_res_in_cnt = 0;
    int trace_prom_cnt = 0;
    int prom_int_bnd_cnt = 0;
    int unr_int_in_cnt = 0;
    int unr_untrace_in_cnt = 0;
    int unr_int_bnd_cnt = 0;
    std::vector<string> prom_int_bnd_samps;
    std::vector<string> unr_int_in_samps;
};

struct ConstantCompletionAudit
{
    int traceable_count = 0;
    int untraceable_count = 0;
    std::vector<string> samples;
};

} // namespace

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

int parse_const_comp_net_cnt(const string &output)
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
        boundary.width = std::min(gold_boundary.width, gate_boundary.width);
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
        out.insert(wire_bit_name(boundary.canonical_wire, std::max(1, boundary.width), boundary.bit_index));
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

static BitTraceDB build_bit_trace_db(RTLIL::Module *mod)
{
    BitTraceDB db;
    SigMap sigmap(mod);

    for (auto *w : mod->wires()) {
        int width = std::max(1, GetSize(w));
        for (int i = 0; i < width; i++) {
            string bit_name = wire_bit_name(w->name, width, i);
            if (w->port_input)
                db.module_input_bits.insert(bit_name);
        }
    }

    for (auto &conn : mod->connections()) {
        RTLIL::SigSpec lhs_sig = conn.first;
        RTLIL::SigSpec rhs_sig = conn.second;
        int width = std::min(GetSize(lhs_sig), GetSize(rhs_sig));
        for (int i = 0; i < width; i++) {
            RTLIL::SigBit lhs = sigmap(lhs_sig[i]);
            RTLIL::SigBit rhs = sigmap(rhs_sig[i]);
            if (!lhs.is_wire())
                continue;
            string lhs_name = wire_bit_name(lhs.wire->name, std::max(1, GetSize(lhs.wire)), lhs.offset);
            db.driven_bits.insert(lhs_name);
            if (rhs.is_wire()) {
                string rhs_name = wire_bit_name(rhs.wire->name, std::max(1, GetSize(rhs.wire)), rhs.offset);
                string edge_kind =
                    (GetSize(lhs.wire) == GetSize(rhs.wire) && lhs.offset == rhs.offset) ?
                    "alias" : "slice_or_concat";
                if (!db.assign_source.count(lhs_name))
                    db.assign_source[lhs_name] = std::make_pair(rhs_name, edge_kind);
                else
                    db.assign_source[lhs_name] = std::make_pair(string(), "multi_driver");
                db.used_bits.insert(rhs_name);
            } else {
                db.const_driven_bits.insert(lhs_name);
                if (!db.assign_source.count(lhs_name))
                    db.assign_source[lhs_name] = std::make_pair(string(), "const");
                else
                    db.assign_source[lhs_name] = std::make_pair(string(), "multi_driver");
            }
        }
    }

    for (auto *cell : mod->cells()) {
        for (auto &conn : cell->connections()) {
            RTLIL::IdString port = conn.first;
            RTLIL::SigSpec sig = sigmap(conn.second);
            bool is_output = yosys_celltypes.cell_output(cell->type, port);
            bool is_input = yosys_celltypes.cell_input(cell->type, port);

            for (auto bit : sig) {
                if (!bit.is_wire())
                    continue;
                string bit_name = wire_bit_name(bit.wire->name, std::max(1, GetSize(bit.wire)), bit.offset);
                if (is_output) {
                    db.driven_bits.insert(bit_name);
                    if (!db.cell_output_driver.count(bit_name))
                        db.cell_output_driver[bit_name] = strip_backslash(cell->type);
                }
                if (is_input)
                    db.used_bits.insert(bit_name);
            }
        }
    }

    return db;
}

static BitTraceInfo trace_residual_source(const BitTraceDB &db, const string &bit_name)
{
    BitTraceInfo info;
    string current = bit_name;
    pool<string> seen;
    bool saw_alias = false;
    bool saw_slice_or_concat = false;
    int depth = 0;

    while (depth++ < 64) {
        if (seen.count(current)) {
            info.kind = "other_unresolved";
            return info;
        }
        seen.insert(current);

        if (db.module_input_bits.count(current)) {
            info.kind = saw_slice_or_concat ? "slice_or_concat_residual" :
                        (saw_alias ? "passthrough_alias_input" : "module_interface_input");
            info.source_id = "if:" + current;
            info.traceable = true;
            info.promotable = false;
            return info;
        }

        if (db.cell_output_driver.count(current)) {
            info.kind = "cell_output_residual";
            info.source_id = "cell:" + db.cell_output_driver.at(current) + ":" + current;
            return info;
        }

        if (db.assign_source.count(current)) {
            auto edge = db.assign_source.at(current);
            if (edge.second == "multi_driver") {
                info.kind = "other_unresolved";
                return info;
            }
            if (edge.second == "const") {
                info.kind = "other_unresolved";
                info.source_id = "const:" + current;
                return info;
            }
            if (edge.first.empty()) {
                info.kind = "other_unresolved";
                return info;
            }
            saw_alias = true;
            if (edge.second == "slice_or_concat")
                saw_slice_or_concat = true;
            current = edge.first;
            continue;
        }

        if (!db.driven_bits.count(current) && db.used_bits.count(current)) {
            info.kind = "undriven_unknown";
            info.source_id = "undriven:" + current;
            return info;
        }

        if (saw_alias || saw_slice_or_concat) {
            info.kind = saw_slice_or_concat ? "slice_or_concat_residual" : "passthrough_alias_input";
            info.source_id = "wire:" + current;
            info.traceable = true;
            info.promotable = saw_slice_or_concat;
            return info;
        }

        info.kind = "other_unresolved";
        info.source_id = "wire:" + current;
        return info;
    }

    info.kind = "other_unresolved";
    return info;
}

static std::vector<string> collect_port_input_bit_names(RTLIL::Module *mod)
{
    std::vector<string> bits;
    pool<string> seen;
    for (auto *w : mod->wires()) {
        if (!w->port_input)
            continue;
        int width = std::max(1, GetSize(w));
        for (int i = 0; i < width; i++) {
            string bit_name = wire_bit_name(w->name, width, i);
            if (!seen.count(bit_name)) {
                seen.insert(bit_name);
                bits.push_back(bit_name);
            }
        }
    }
    return bits;
}

static RTLIL::Wire *find_single_bit_input_wire(RTLIL::Module *mod, const string &bit_name)
{
    for (auto *w : mod->wires()) {
        if (!w->port_input)
            continue;
        if (GetSize(w) != 1)
            continue;
        if (wire_bit_name(w->name, 1, 0) == bit_name)
            return w;
    }
    return nullptr;
}

static string canonical_trace_boundary_wire(const string &source_id)
{
    return "__region__trace__" + sanitize_filename(source_id);
}

static void apply_trace_boundary_canonical_names(RTLIL::Module *gold_mod, RTLIL::Module *gate_mod,
                                                 const dict<string, string> &bit_to_source)
{
    dict<RTLIL::IdString, RTLIL::IdString> gold_renames;
    dict<RTLIL::IdString, RTLIL::IdString> gate_renames;

    for (const auto &it : bit_to_source) {
        const string &bit_name = it.first;
        RTLIL::Wire *gold_wire = find_single_bit_input_wire(gold_mod, bit_name);
        RTLIL::Wire *gate_wire = find_single_bit_input_wire(gate_mod, bit_name);
        if (gold_wire == nullptr || gate_wire == nullptr)
            continue;
        RTLIL::IdString canonical = RTLIL::escape_id(canonical_trace_boundary_wire(it.second));
        if ((gold_mod->wire(canonical) != nullptr && gold_mod->wire(canonical) != gold_wire) ||
            (gate_mod->wire(canonical) != nullptr && gate_mod->wire(canonical) != gate_wire))
            continue;
        gold_renames[gold_wire->name] = canonical;
        gate_renames[gate_wire->name] = canonical;
    }

    auto apply_renames = [](RTLIL::Module *mod, const dict<RTLIL::IdString, RTLIL::IdString> &renames) {
        for (const auto &it : renames) {
            RTLIL::Wire *wire = mod->wire(it.first);
            if (wire == nullptr || wire->name == it.second)
                continue;
            mod->rename(wire, it.second);
        }
        mod->fixup_ports();
    };

    apply_renames(gold_mod, gold_renames);
    apply_renames(gate_mod, gate_renames);
}

static ShellAuditInfo audit_shell_inputs(RTLIL::Module *gold_local,
                                         const pool<string> &iface_in,
                                         const pool<string> &state_in,
                                         const pool<string> &child_in,
                                         const pool<string> &alias_in,
                                         const pool<string> &prom_in,
                                         const dict<string, BitTraceInfo> &trace_by_bit)
{
    ShellAuditInfo info;
    pool<string> seen_input_bits;
    for (auto *w : gold_local->wires()) {
        if (!w->port_input)
            continue;
        int width = std::max(1, GetSize(w));
        for (int i = 0; i < width; i++) {
            string bit_name = wire_bit_name(w->name, width, i);
            if (seen_input_bits.count(bit_name))
                continue;
            seen_input_bits.insert(bit_name);

            if (iface_in.count(bit_name)) {
                info.iface_in_cnt++;
                continue;
            }
            if (state_in.count(bit_name)) {
                info.state_in_cnt++;
                continue;
            }
            if (child_in.count(bit_name)) {
                info.child_in_cnt++;
                continue;
            }
            if (alias_in.count(bit_name)) {
                info.alias_in_cnt++;
                continue;
            }
            if (prom_in.count(bit_name)) {
                info.prom_int_bnd_cnt++;
                info.trace_prom_cnt++;
                add_sample_name(info.prom_int_bnd_samps, bit_name, 8);
                continue;
            }

            if (trace_by_bit.count(bit_name)) {
                const auto &trace = trace_by_bit.at(bit_name);
                if (trace.traceable)
                    info.trace_res_in_cnt++;
                if (trace.kind == "slice_or_concat_residual")
                    info.slice_res_cnt++;
            }

            info.unr_int_in_cnt++;
            if (!trace_by_bit.count(bit_name) || !trace_by_bit.at(bit_name).traceable)
                info.unr_untrace_in_cnt++;
            add_sample_name(info.unr_int_in_samps, bit_name, 8);
        }
    }

    info.unr_int_bnd_cnt = info.unr_int_in_cnt;
    return info;
}

static ConstantCompletionAudit audit_constant_completed_nets(RTLIL::Module *gold_local,
                                                            RTLIL::Module *gate_local,
                                                            const BitTraceDB &gold_db,
                                                            const BitTraceDB &gate_db)
{
    ConstantCompletionAudit audit;
    auto collect_undriven_used_internal = [](RTLIL::Module *mod) {
        pool<string> driven_bits, used_bits;
        collect_wire_usage(mod, driven_bits, used_bits);
        pool<string> out;
        for (const auto &bit_name : used_bits) {
            if (driven_bits.count(bit_name))
                continue;
            for (auto *w : mod->wires()) {
                int width = std::max(1, GetSize(w));
                for (int i = 0; i < width; i++) {
                    if (wire_bit_name(w->name, width, i) != bit_name)
                        continue;
                    if (!w->port_input)
                        out.insert(bit_name);
                }
            }
        }
        return out;
    };

    pool<string> local_bits = collect_undriven_used_internal(gold_local);
    pool<string> gate_bits = collect_undriven_used_internal(gate_local);
    for (const auto &bit_name : gate_bits)
        local_bits.insert(bit_name);

    for (const auto &bit_name : local_bits) {
        BitTraceInfo gold_trace = trace_residual_source(gold_db, bit_name);
        BitTraceInfo gate_trace = trace_residual_source(gate_db, bit_name);
        bool traceable =
            gold_trace.traceable || gate_trace.traceable ||
            gold_trace.kind == "passthrough_alias_input" || gate_trace.kind == "passthrough_alias_input" ||
            gold_trace.kind == "slice_or_concat_residual" || gate_trace.kind == "slice_or_concat_residual";
        if (traceable)
            audit.traceable_count++;
        else
            audit.untraceable_count++;
        add_sample_name(audit.samples,
                        bit_name + ":" + (traceable ? "traceable" : "untraceable") +
                        ":" + (gold_trace.kind != "other_unresolved" ? gold_trace.kind : gate_trace.kind),
                        8);
    }
    return audit;
}

void refine_shell_closure(PartitionedPair &pair, RTLIL::Module *gold_orig, RTLIL::Module *gate_orig,
                          const std::vector<CutPoint> &cutpoints)
{
    pool<string> iface_in = collect_module_interface_input_bit_names(gold_orig);
    pool<string> state_in = collect_state_cut_input_bit_names(cutpoints);
    BitTraceDB gold_db = build_bit_trace_db(gold_orig);
    BitTraceDB gate_db = build_bit_trace_db(gate_orig);

    auto base_allowed = [&]() {
        pool<string> allowed = iface_in;
        for (const auto &bit_name : state_in)
            allowed.insert(bit_name);
        for (const auto &bit_name : pair.boundary_bit_names)
            allowed.insert(bit_name);
        for (const auto &bit_name : pair.promoted_internal_boundary_bit_names)
            allowed.insert(bit_name);
        return allowed;
    };

    pool<string> alias_in;
    dict<string, BitTraceInfo> trace_by_bit;

    auto classify_residual_inputs = [&](RTLIL::Module *mod, const BitTraceDB &db,
                                        const pool<string> &allowed, dict<string, BitTraceInfo> &out) {
        for (const auto &bit_name : collect_port_input_bit_names(mod)) {
            if (allowed.count(bit_name))
                continue;
            out[bit_name] = trace_residual_source(db, bit_name);
        }
    };

    pool<string> allowed = base_allowed();
    dict<string, BitTraceInfo> gold_trace_info, gate_trace_info;
    classify_residual_inputs(pair.gold_local, gold_db, allowed, gold_trace_info);
    classify_residual_inputs(pair.gate_local, gate_db, allowed, gate_trace_info);

    dict<string, std::vector<string>> gold_promotable_by_source, gate_promotable_by_source;
    for (const auto &it : gold_trace_info) {
        const string &bit_name = it.first;
        const auto &trace = it.second;
        trace_by_bit[bit_name] = trace;
        if (trace.kind == "passthrough_alias_input" || trace.kind == "module_interface_input")
            alias_in.insert(bit_name);
        if (trace.traceable && trace.promotable && !trace.source_id.empty())
            gold_promotable_by_source[trace.source_id].push_back(bit_name);
    }
    for (const auto &it : gate_trace_info) {
        const auto &trace = it.second;
        if (trace.traceable && trace.promotable && !trace.source_id.empty())
            gate_promotable_by_source[trace.source_id].push_back(it.first);
    }

    dict<string, string> canonical_promotions;
    for (const auto &it : gold_promotable_by_source) {
        const string &source_id = it.first;
        if (!gate_promotable_by_source.count(source_id))
            continue;
        const auto &gold_bits = it.second;
        const auto &gate_bits = gate_promotable_by_source.at(source_id);
        if (GetSize(gold_bits) != 1 || GetSize(gate_bits) != 1)
            continue;
        pair.promoted_internal_boundary_bit_names.insert(gold_bits.front());
        canonical_promotions[gold_bits.front()] = source_id;
    }

    if (!canonical_promotions.empty()) {
        apply_trace_boundary_canonical_names(pair.gold_local, pair.gate_local, canonical_promotions);
        pool<string> renamed_promoted_bits;
        for (const auto &bit_name : pair.promoted_internal_boundary_bit_names) {
            if (canonical_promotions.count(bit_name))
                renamed_promoted_bits.insert(canonical_trace_boundary_wire(canonical_promotions.at(bit_name)));
            else
                renamed_promoted_bits.insert(bit_name);
        }
        pair.promoted_internal_boundary_bit_names = renamed_promoted_bits;
    }

    allowed = base_allowed();
    for (const auto &bit_name : alias_in)
        allowed.insert(bit_name);

    gold_trace_info.clear();
    trace_by_bit.clear();
    classify_residual_inputs(pair.gold_local, gold_db, allowed, gold_trace_info);
    for (const auto &it : gold_trace_info)
        trace_by_bit[it.first] = it.second;

    pair.allowed_shell_input_bit_names = allowed;
    for (const auto &bit_name : alias_in)
        pair.allowed_shell_input_bit_names.insert(bit_name);

    ShellAuditInfo audit = audit_shell_inputs(pair.gold_local, iface_in, state_in,
                                              pair.boundary_bit_names, alias_in,
                                              pair.promoted_internal_boundary_bit_names, trace_by_bit);
    pair.iface_in_cnt = audit.iface_in_cnt;
    pair.state_in_cnt = audit.state_in_cnt;
    pair.child_in_cnt = audit.child_in_cnt;
    pair.alias_in_cnt = audit.alias_in_cnt;
    pair.slice_res_cnt = audit.slice_res_cnt;
    pair.trace_res_in_cnt = audit.trace_res_in_cnt;
    pair.trace_prom_cnt = audit.trace_prom_cnt;
    pair.prom_int_bnd_cnt = audit.prom_int_bnd_cnt;
    pair.unr_int_in_cnt = audit.unr_int_in_cnt;
    pair.unr_untrace_in_cnt = audit.unr_untrace_in_cnt;
    pair.prom_int_bnd_samps = audit.prom_int_bnd_samps;
    pair.unr_int_in_samps = audit.unr_int_in_samps;
    pair.unr_int_bnd_cnt = audit.unr_int_bnd_cnt;

    ConstantCompletionAudit cc_audit =
        audit_constant_completed_nets(pair.gold_local, pair.gate_local, gold_db, gate_db);
    pair.const_comp_trace_cnt = cc_audit.traceable_count;
    pair.const_comp_untrace_cnt = cc_audit.untraceable_count;
    pair.const_comp_samps = cc_audit.samples;
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
                        width,
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
    result.resid_hier = !result.boundaries.empty();
    refine_shell_closure(result, gold_mod, gate_mod, cutpoints);
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
    result.cut_cnt = GetSize(cutpoints);

    RTLIL::Design *design_check = empty_design();
    auto local_pair = partition_module(conf.design, design_check, gold_mod, gate_mod, cutpoints, conf);
    result.child_bnd_cnt = GetSize(local_pair.boundaries);
    result.bnd_map_exp =
        GetSize(local_pair.boundary_bit_names) + GetSize(local_pair.promoted_internal_boundary_bit_names);
    result.unr_int_bnd_cnt = local_pair.unr_int_bnd_cnt;
    result.iface_in_cnt = local_pair.iface_in_cnt;
    result.state_in_cnt = local_pair.state_in_cnt;
    result.child_in_cnt = local_pair.child_in_cnt;
    result.alias_in_cnt = local_pair.alias_in_cnt;
    result.slice_res_cnt = local_pair.slice_res_cnt;
    result.trace_res_in_cnt = local_pair.trace_res_in_cnt;
    result.trace_prom_cnt = local_pair.trace_prom_cnt;
    result.prom_int_bnd_cnt = local_pair.prom_int_bnd_cnt;
    result.unr_int_in_cnt = local_pair.unr_int_in_cnt;
    result.unr_untrace_in_cnt = local_pair.unr_untrace_in_cnt;
    result.prom_int_bnd_samps = local_pair.prom_int_bnd_samps;
    result.unr_int_in_samps = local_pair.unr_int_in_samps;
    result.const_comp_trace_cnt = local_pair.const_comp_trace_cnt;
    result.const_comp_untrace_cnt = local_pair.const_comp_untrace_cnt;
    result.const_comp_samps = local_pair.const_comp_samps;
    result.resid_hier = local_pair.resid_hier;

    GuideTelemetry local_telemetry;
    CheckConfig local_conf = conf;
    local_conf.design = design_check;
    local_conf.gold_mod = local_pair.gold_local;
    local_conf.gate_mod = local_pair.gate_local;
    local_conf.sched_model_file = "";
    local_conf.match_model_file = "";
    local_conf.accept_sugs_file = "";
    local_conf.dump_cfg = MlDumpConfig();
    local_conf.sched_model = nullptr;
    local_conf.match_model = nullptr;
    local_conf.telemetry = &local_telemetry;

    MatchResult local_match =
        match_signals_module(design_check, local_conf.gold_mod, local_conf.gate_mod,
                             local_conf, true, "local_partition");
    local_telemetry.pair_match_stats[get_pair_id(local_conf.gold_mod->name, local_conf.gate_mod->name)] =
        local_match.stats;

    result.exact_cnt = local_match.stats.exact_total;
    for (const auto &cp : local_match.cut_points)
        if (local_pair.boundary_bit_names.count(strip_backslash(cp.name)) ||
            local_pair.promoted_internal_boundary_bit_names.count(strip_backslash(cp.name)))
            result.bnd_map_app++;

    result.ran = true;
    CommandResult local_abc_result;
    result.proved = abc_cec_module(local_conf, false, &local_abc_result);
    result.vali_backend = "local_abc";
    int abc_name_map_applied = parse_name_map_applied(local_abc_result.output);
    if (result.bnd_map_app == 0 && abc_name_map_applied > 0)
        result.bnd_map_app = std::min(result.bnd_map_exp, abc_name_map_applied);
    result.const_comp_net_cnt = parse_const_comp_net_cnt(local_abc_result.output);
    int classified_constant_completed =
        result.const_comp_trace_cnt + result.const_comp_untrace_cnt;
    if (result.const_comp_net_cnt > classified_constant_completed) {
        result.const_comp_untrace_cnt +=
            result.const_comp_net_cnt - classified_constant_completed;
        add_sample_name(result.const_comp_samps, "abc_constant_completed_unclassified", 8);
    }
    result.unsafe_why = partition_unsafe_why(local_abc_result);
    if (!result.unsafe_why.empty())
        result.auth_ok = false;
    if (result.unr_int_bnd_cnt > 0) {
        result.auth_ok = false;
        if (result.fb_why.empty())
            result.fb_why = "unresolved_internal_boundaries";
    }
    if (result.const_comp_net_cnt > 0) {
        result.auth_ok = false;
        if (result.fb_why.empty())
            result.fb_why = "constant_completed_nets";
    }
    if (result.bnd_map_exp > 0 && result.bnd_map_app == 0) {
        result.auth_ok = false;
        if (result.fb_why.empty())
            result.fb_why = "boundary_map_not_applied";
    }
    if (result.proved && result.auth_ok)
        result.auth_why = "closed_shell";

    if (!result.proved && allow_bmc_fallback) {
        bool residual_state = module_has_dff(local_conf.gold_mod, false) || module_has_dff(local_conf.gate_mod, true);
        bool resid_hier = module_has_submodule(design_check, local_conf.gold_mod) || module_has_submodule(design_check, local_conf.gate_mod);
        if (residual_state || resid_hier) {
            result.used_bmc_fb = true;
            bool bmc_ok = bmcinduct_check(local_conf);
            result.vali_backend = "local_abc_bmc";
            if (bmc_ok)
                result.proved = true;
        }
    }
    auto t_end = std::chrono::steady_clock::now();
    result.runtime_ms = std::chrono::duration_cast<std::chrono::milliseconds>(t_end - t_start).count();

    delete design_check;
    return result;
}

void run_local_vali_shadow(const CheckConfig &conf, ModMap &mod_map,
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
            {"validator_backend", result.vali_backend},
            {"used_bmc_fallback", result.used_bmc_fb},
            {"authoritative_ok", result.auth_ok},
            {"authoritative_reason", result.auth_why},
            {"unsafe_reason", result.unsafe_why},
            {"fallback_reason", result.fb_why},
            {"runtime_ms", result.runtime_ms},
            {"accepted", false},
            {"selected_cutpoints", result.cut_cnt},
            {"local_exact_total", result.exact_cnt},
            {"boundary_map_expected", result.bnd_map_exp},
            {"boundary_map_applied", result.bnd_map_app},
            {"constant_completed_net_count", result.const_comp_net_cnt},
            {"module_interface_input_count", result.iface_in_cnt},
            {"state_cut_input_count", result.state_in_cnt},
            {"child_boundary_input_count", result.child_in_cnt},
            {"passthrough_alias_input_count", result.alias_in_cnt},
            {"slice_or_concat_residual_count", result.slice_res_cnt},
            {"traceable_residual_input_count", result.trace_res_in_cnt},
            {"promoted_from_trace_count", result.trace_prom_cnt},
            {"promoted_internal_boundary_count", result.prom_int_bnd_cnt},
            {"unresolved_internal_input_count", result.unr_int_in_cnt},
            {"unresolved_untraceable_input_count", result.unr_untrace_in_cnt},
            {"constant_completed_traceable_count", result.const_comp_trace_cnt},
            {"constant_completed_untraceable_count", result.const_comp_untrace_cnt},
            {"promoted_internal_boundary_samples", json_array_from_strings(result.prom_int_bnd_samps)},
            {"unresolved_internal_input_samples", json_array_from_strings(result.unr_int_in_samps)},
            {"constant_completed_samples", json_array_from_strings(result.const_comp_samps)},
            {"unresolved_internal_boundaries", result.unr_int_bnd_cnt},
            {"child_boundary_count", result.child_bnd_cnt},
            {"unresolved_child_boundaries", result.unr_child_bnd_cnt}
        });
        ran_pairs++;
        if (result.proved)
            passed_pairs++;
        else
            failed_pairs++;

        log("LOCAL_VALIDATE shadow for %s: %s (%d DFF cutpoints, local exact=%d).\n",
            result.pair_id.c_str(),
            result.proved ? "\033[1;32mPASSED\033[0m" : "\033[1;31mFAILED\033[0m",
            result.cut_cnt,
            result.exact_cnt);
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
                boundary.width = width;
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
                node.unresolved_child_bnd_cnt++;
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
            {"unresolved_child_bnd_cnt", node.unresolved_child_bnd_cnt},
            {"residual_hierarchy", !node.child_boundaries.empty()}
        });
    }

    for (const auto &node : nodes) {
        RegionProofResult region_result;
        region_result.region_id = node.region_id;
        region_result.child_bnd_cnt = GetSize(node.child_boundaries);
        region_result.unr_child_bnd_cnt = node.unresolved_child_bnd_cnt;

        bool child_done = true;
        for (int child_id : node.child_region_ids) {
            const auto &child_result = proof_results.at(child_id);
            if (!child_result.oblig_done) {
                child_done = false;
                break;
            }
        }
        region_result.child_done = child_done;

        std::vector<CutPoint> local_cutpoints =
            filter_materializable_cutpoints(node.gold_mod, node.gate_mod, node.state_cutpoints);
        bool shell_attempted = !local_cutpoints.empty() || !node.child_boundaries.empty();
        if (shell_attempted) {
            LocalValidateResult shell_result =
                validate_partition_pair(conf, node.gold_mod, node.gate_mod, local_cutpoints, true);
            region_result.shell_proved = shell_result.proved;
            region_result.cut_cnt = shell_result.cut_cnt;
            region_result.exact_cnt = shell_result.exact_cnt;
            region_result.child_bnd_cnt = shell_result.child_bnd_cnt;
            region_result.unr_child_bnd_cnt = shell_result.unr_child_bnd_cnt;
            region_result.bnd_map_exp = shell_result.bnd_map_exp;
            region_result.bnd_map_app = shell_result.bnd_map_app;
            region_result.const_comp_net_cnt = shell_result.const_comp_net_cnt;
            region_result.unr_int_bnd_cnt = shell_result.unr_int_bnd_cnt;
            region_result.iface_in_cnt = shell_result.iface_in_cnt;
            region_result.state_in_cnt = shell_result.state_in_cnt;
            region_result.child_in_cnt = shell_result.child_in_cnt;
            region_result.alias_in_cnt = shell_result.alias_in_cnt;
            region_result.slice_res_cnt = shell_result.slice_res_cnt;
            region_result.trace_res_in_cnt = shell_result.trace_res_in_cnt;
            region_result.trace_prom_cnt = shell_result.trace_prom_cnt;
            region_result.prom_int_bnd_cnt = shell_result.prom_int_bnd_cnt;
            region_result.unr_int_in_cnt = shell_result.unr_int_in_cnt;
            region_result.unr_untrace_in_cnt = shell_result.unr_untrace_in_cnt;
            region_result.prom_int_bnd_samps = shell_result.prom_int_bnd_samps;
            region_result.unr_int_in_samps = shell_result.unr_int_in_samps;
            region_result.const_comp_trace_cnt = shell_result.const_comp_trace_cnt;
            region_result.const_comp_untrace_cnt = shell_result.const_comp_untrace_cnt;
            region_result.const_comp_samps = shell_result.const_comp_samps;
            region_result.resid_hier = shell_result.resid_hier;
            region_result.runtime_ms = shell_result.runtime_ms;
            region_result.backend = shell_result.vali_backend;
            region_result.unsafe_why = shell_result.unsafe_why;
            region_result.auth_ok =
                shell_result.auth_ok &&
                region_result.unr_child_bnd_cnt == 0 &&
                region_result.unr_int_bnd_cnt == 0 &&
                region_result.const_comp_net_cnt == 0 &&
                (region_result.bnd_map_exp == 0 || region_result.bnd_map_app > 0) &&
                child_done;
            if (!child_done && region_result.fb_why.empty())
                region_result.fb_why = "child_obligations_not_discharged";
            if (region_result.unr_child_bnd_cnt > 0 && region_result.fb_why.empty())
                region_result.fb_why = "unresolved_child_boundaries";
            if (region_result.unr_int_bnd_cnt > 0 && region_result.fb_why.empty())
                region_result.fb_why = "unresolved_internal_boundaries";
            if (region_result.const_comp_net_cnt > 0 && region_result.fb_why.empty())
                region_result.fb_why = "constant_completed_nets";
            if (region_result.bnd_map_exp > 0 && region_result.bnd_map_app == 0 && region_result.fb_why.empty())
                region_result.fb_why = "boundary_map_not_applied";
            if (!shell_result.auth_ok && region_result.fb_why.empty())
                region_result.fb_why = !shell_result.fb_why.empty() ? shell_result.fb_why : shell_result.unsafe_why;
            region_result.proved = region_result.shell_proved && child_done;
            region_result.oblig_done = region_result.proved && region_result.auth_ok;
            if (region_result.auth_ok)
                region_result.auth_why = "closed_region_shell";

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
                {"validator_backend", shell_result.vali_backend},
                {"used_bmc_fallback", shell_result.used_bmc_fb},
                {"authoritative_ok", region_result.auth_ok},
                {"authoritative_reason", region_result.auth_why},
                {"unsafe_reason", shell_result.unsafe_why},
                {"fallback_reason", region_result.fb_why},
                {"runtime_ms", shell_result.runtime_ms},
                {"accepted", false},
                {"selected_cutpoints", shell_result.cut_cnt},
                {"local_exact_total", shell_result.exact_cnt},
                {"boundary_map_expected", shell_result.bnd_map_exp},
                {"boundary_map_applied", shell_result.bnd_map_app},
                {"constant_completed_net_count", shell_result.const_comp_net_cnt},
                {"module_interface_input_count", shell_result.iface_in_cnt},
                {"state_cut_input_count", shell_result.state_in_cnt},
                {"child_boundary_input_count", shell_result.child_in_cnt},
                {"passthrough_alias_input_count", shell_result.alias_in_cnt},
                {"slice_or_concat_residual_count", shell_result.slice_res_cnt},
                {"traceable_residual_input_count", shell_result.trace_res_in_cnt},
                {"promoted_from_trace_count", shell_result.trace_prom_cnt},
                {"promoted_internal_boundary_count", shell_result.prom_int_bnd_cnt},
                {"unresolved_internal_input_count", shell_result.unr_int_in_cnt},
                {"unresolved_untraceable_input_count", shell_result.unr_untrace_in_cnt},
                {"constant_completed_traceable_count", shell_result.const_comp_trace_cnt},
                {"constant_completed_untraceable_count", shell_result.const_comp_untrace_cnt},
                {"promoted_internal_boundary_samples", json_array_from_strings(shell_result.prom_int_bnd_samps)},
                {"unresolved_internal_input_samples", json_array_from_strings(shell_result.unr_int_in_samps)},
                {"constant_completed_samples", json_array_from_strings(shell_result.const_comp_samps)},
                {"unresolved_internal_boundaries", shell_result.unr_int_bnd_cnt},
                {"child_boundary_count", shell_result.child_bnd_cnt},
                {"unresolved_child_boundaries", shell_result.unr_child_bnd_cnt}
            });
        } else {
            region_result.fb_why = "no_shell_obligation";
            region_result.auth_ok = false;
            region_result.oblig_done = false;
        }

        if (!region_result.proved || !region_result.auth_ok) {
            CheckConfig conf_ = conf;
            conf_.gold_mod = node.gold_mod;
            conf_.gate_mod = node.gate_mod;
            bool fallback_ok = abc_cec_module(conf_);
            if (region_result.fb_why.empty())
                region_result.fb_why = region_result.proved ? "non_authoritative_region" : "shell_failed";
            log("REGION proof for %s falling back to module-pair proof (%s).\n",
                get_pair_id(node.gold_mod->name, node.gate_mod->name).c_str(),
                region_result.fb_why.c_str());
            region_result.proved = fallback_ok;
            region_result.auth_ok = false;
            region_result.oblig_done = fallback_ok;
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
            {"child_boundary_count", region_result.child_bnd_cnt},
            {"shell_proved", region_result.shell_proved},
            {"children_discharged", region_result.child_done},
            {"obligation_discharged", region_result.oblig_done},
            {"authoritative_ok", region_result.auth_ok},
            {"authoritative_reason", region_result.auth_why},
            {"proved", region_result.proved},
            {"unsafe_reason", region_result.unsafe_why},
            {"fallback_reason", region_result.fb_why},
            {"backend", region_result.backend},
            {"runtime_ms", region_result.runtime_ms},
            {"selected_cutpoints", region_result.cut_cnt},
            {"local_exact_total", region_result.exact_cnt},
            {"boundary_map_expected", region_result.bnd_map_exp},
            {"boundary_map_applied", region_result.bnd_map_app},
            {"constant_completed_net_count", region_result.const_comp_net_cnt},
            {"module_interface_input_count", region_result.iface_in_cnt},
            {"state_cut_input_count", region_result.state_in_cnt},
            {"child_boundary_input_count", region_result.child_in_cnt},
            {"passthrough_alias_input_count", region_result.alias_in_cnt},
            {"slice_or_concat_residual_count", region_result.slice_res_cnt},
            {"traceable_residual_input_count", region_result.trace_res_in_cnt},
            {"promoted_from_trace_count", region_result.trace_prom_cnt},
            {"promoted_internal_boundary_count", region_result.prom_int_bnd_cnt},
            {"unresolved_internal_input_count", region_result.unr_int_in_cnt},
            {"unresolved_untraceable_input_count", region_result.unr_untrace_in_cnt},
            {"constant_completed_traceable_count", region_result.const_comp_trace_cnt},
            {"constant_completed_untraceable_count", region_result.const_comp_untrace_cnt},
            {"promoted_internal_boundary_samples", json_array_from_strings(region_result.prom_int_bnd_samps)},
            {"unresolved_internal_input_samples", json_array_from_strings(region_result.unr_int_in_samps)},
            {"constant_completed_samples", json_array_from_strings(region_result.const_comp_samps)},
            {"unresolved_internal_boundaries", region_result.unr_int_bnd_cnt},
            {"unresolved_child_boundaries", region_result.unr_child_bnd_cnt},
            {"residual_hierarchy", region_result.resid_hier}
        });

        log("REGION proof for %s: %s (state cuts=%d, child boundaries=%d, children=%s).\n",
            get_pair_id(node.gold_mod->name, node.gate_mod->name).c_str(),
            region_result.proved ? "\033[1;32mPASSED\033[0m" : "\033[1;31mFAILED\033[0m",
            region_result.cut_cnt,
            region_result.child_bnd_cnt,
            region_result.child_done ? "discharged" : "pending");

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
