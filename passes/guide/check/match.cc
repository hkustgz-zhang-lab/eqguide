#include "passes/guide/check/match.h"
#include "passes/guide/check/fail_exec.h"
#include "passes/guide/check/scheduler.h"
#include "passes/guide/check/region.h"
#include <sstream>

YOSYS_NAMESPACE_BEGIN
namespace guide_check {

dict<RTLIL::IdString, NamedSig> build_named_sigs(RTLIL::Design* design, RTLIL::Module *m, dict<RTLIL::SigBit, RTLIL::Cell*>& ff_q_map)
{
    // have't use yet.
    (void) design;


    SigMap sigmap(m);
    dict<RTLIL::IdString, NamedSig> out;
    pool<RTLIL::Cell*> subckts;
    dict<RTLIL::SigBit, RTLIL::Cell*> ff_q_bits_map;

    auto cell_has_ff_ports = [&](RTLIL::Cell *cell) {
        return cell->hasPort(ID::Q) && cell->hasPort(ID::D) &&
               (cell->is_builtin_ff() || cell->type == ID($anyinit) || cell->type.contains("DFF"));
    };

    for (auto cell : m->cells()) {
        // subckt
        if (!yosys_celltypes.cell_known(cell->type)){
            subckts.insert(cell);
            continue;
        }

        if (!cell_has_ff_ports(cell))
            continue;

        RTLIL::SigSpec q = cell->getPort(ID::Q);
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


void update_match_stats(MatchStats &stats, MatchType type)
{
    switch (type) {
    case MatchType::PI:
        stats.pi_cnt++;
        break;
    case MatchType::PO:
        stats.po_cnt++;
        break;
    case MatchType::DFF:
        stats.dff_cnt++;
        break;
    case MatchType::DFF_PO:
        stats.dff_po_cnt++;
        break;
    case MatchType::SUBCKT_PIPO:
        stats.subckt_cnt++;
        break;
    case MatchType::NONE:
        break;
    }
}

string normalize_match_name(const RTLIL::IdString &id)
{
    string name = strip_backslash(id);
    for (char &ch : name)
        if (!std::isalnum(static_cast<unsigned char>(ch)))
            ch = '_';
    return name;
}

string last_match_token(const RTLIL::IdString &id)
{
    string name = normalize_match_name(id);
    size_t pos = name.find_last_of('_');
    if (pos == string::npos)
        return name;
    return name.substr(pos + 1);
}

int score_match_candidate(const NamedSig &gold_sig, const NamedSig &gate_sig)
{
    int score = 0;

    if (gold_sig.type != gate_sig.type)
        return score;
    if (gold_sig.bit_index == gate_sig.bit_index)
        score += 10;
    if (gold_sig.wire_name == gate_sig.wire_name)
        score += 100;
    if (normalize_match_name(gold_sig.wire_name) == normalize_match_name(gate_sig.wire_name))
        score += 40;
    if (last_match_token(gold_sig.wire_name) == last_match_token(gate_sig.wire_name))
        score += 20;

    return score;
}

dict<string, double> match_candidate_features(const NamedSig &gold_sig, const NamedSig &gate_sig)
{
    dict<string, double> features;
    features["bit_index_equal"] = gold_sig.bit_index == gate_sig.bit_index ? 1.0 : 0.0;
    features["bit_index_absdiff"] = std::abs(gold_sig.bit_index - gate_sig.bit_index);
    features["wire_name_exact"] = gold_sig.wire_name == gate_sig.wire_name ? 1.0 : 0.0;
    features["wire_name_norm_exact"] =
        normalize_match_name(gold_sig.wire_name) == normalize_match_name(gate_sig.wire_name) ? 1.0 : 0.0;
    features["same_last_token"] = last_match_token(gold_sig.wire_name) == last_match_token(gate_sig.wire_name) ? 1.0 : 0.0;
    features["heuristic_score"] = score_match_candidate(gold_sig, gate_sig);
    features["gold_name_len"] = strip_backslash(gold_sig.wire_name).size();
    features["gate_name_len"] = strip_backslash(gate_sig.wire_name).size();
    features["name_len_absdiff"] = std::abs(int(strip_backslash(gold_sig.wire_name).size()) - int(strip_backslash(gate_sig.wire_name).size()));
    features["type_pi"] = gold_sig.type == MatchType::PI ? 1.0 : 0.0;
    features["type_po"] = gold_sig.type == MatchType::PO ? 1.0 : 0.0;
    features["type_dff"] = gold_sig.type == MatchType::DFF ? 1.0 : 0.0;
    features["type_dff_po"] = gold_sig.type == MatchType::DFF_PO ? 1.0 : 0.0;
    features["type_subckt_pipo"] = gold_sig.type == MatchType::SUBCKT_PIPO ? 1.0 : 0.0;
    return features;
}

double predict_match_score(const GuideMatchModel &model, const NamedSig &gold_sig, const NamedSig &gate_sig)
{
    if (!model.loaded)
        return score_match_candidate(gold_sig, gate_sig);

    dict<string, double> features_by_name = match_candidate_features(gold_sig, gate_sig);
    std::vector<double> features(GetSize(model.feature_names), 0.0);
    for (int i = 0; i < GetSize(model.feature_names); i++)
        if (features_by_name.count(model.feature_names[i]))
            features[i] = features_by_name.at(model.feature_names[i]);

    double score = model.base_score;
    for (auto &tree : model.trees)
        score += tree_predict(tree, features);
    return score;
}

void write_match_suggestions(const string &path, const Json::array &suggestions)
{
    FILE *f = fopen(path.c_str(), "w");
    if (f == nullptr)
        log_error("Cannot open match suggestions file %s.\n", path.c_str());
    fprintf(f, "%s\n", Json(suggestions).dump().c_str());
    fclose(f);
}

string match_suggestions_path(const string &match_jsonl)
{
    if (match_jsonl.empty())
        return "match_suggestions.json";

    size_t pos = match_jsonl.find_last_of('/');
    if (pos == string::npos)
        return "match_suggestions.json";

    return match_jsonl.substr(0, pos + 1) + "match_suggestions.json";
}

string match_artifact_dir(const CheckConfig &conf)
{
    if (conf.dump_cfg.dump_match && !conf.dump_cfg.match_jsonl.empty())
        return path_dirname(conf.dump_cfg.match_jsonl);
    if (!conf.accept_sugs_file.empty())
        return path_dirname(conf.accept_sugs_file);
    return conf.tempdir_name;
}

Json::array load_match_suggestions_file(const string &path)
{
    if (path.empty())
        return Json::array();

    std::ifstream handle(path);
    if (!handle.is_open())
        log_error("Cannot open match suggestions file %s.\n", path.c_str());

    std::stringstream buffer;
    buffer << handle.rdbuf();
    string error;
    Json json = Json::parse(buffer.str(), error);
    if (!error.empty())
        log_error("Cannot parse match suggestions file %s: %s\n", path.c_str(), error.c_str());
    if (!json.is_array())
        log_error("Match suggestions file %s must contain a JSON array.\n", path.c_str());
    return json.array_items();
}

void write_match_line(FILE *f, const RTLIL::IdString &name,
                             RTLIL::SigBit gsig, RTLIL::SigBit ksig, MatchType type)
{
    if (f == nullptr)
        return;
    fprintf(f, "Matched signal %s: gold %s gate %s, Type %s\n",
        name.c_str(), log_signal(gsig).c_str(), log_signal(ksig).c_str(),
        get_match_type_str(type).c_str());
}

MatchResult match_signals_module(RTLIL::Design *design, RTLIL::Module *gold_mod, RTLIL::Module *gate_mod,
                                        const CheckConfig &conf, bool emit_match_file, const string &snapshot_name)
{
    assert(design && gold_mod && gate_mod);

    MatchResult result;
    dict<RTLIL::SigBit, RTLIL::Cell*> gold_ff_q_map;
    dict<RTLIL::SigBit, RTLIL::Cell*> gate_ff_q_map;

    auto gold = build_named_sigs(design, gold_mod, gold_ff_q_map);
    auto gate = build_named_sigs(design, gate_mod, gate_ff_q_map);
    string pair_id = get_pair_id(gold_mod->name, gate_mod->name);
    string match_file = conf.tempdir_name + "/match_" + RTLIL::unescape_id(gold_mod->name) + "_" + RTLIL::unescape_id(gate_mod->name) + ".txt";
    result.stats.match_file = match_file;
    string art_dir = match_artifact_dir(conf);
    string exact_file = pair_artifact_path(art_dir, "match_exact", gold_mod, gate_mod, ".txt");
    string vali_file = pair_artifact_path(art_dir, "match_validated", gold_mod, gate_mod, ".txt");
    string sugs_jsonl = pair_artifact_path(art_dir, "match_suggestions", gold_mod, gate_mod, ".jsonl");
    string vali_jsonl = pair_artifact_path(art_dir, "local_validate", gold_mod, gate_mod, ".jsonl");

    FILE *f = nullptr;
    FILE *f_exact = nullptr;
    FILE *f_validated = nullptr;
    if (emit_match_file)
        f = fopen(match_file.c_str(), "w");
    if (emit_match_file)
        f_exact = fopen(exact_file.c_str(), "w");
    if (emit_match_file)
        f_validated = fopen(vali_file.c_str(), "w");

    pool<RTLIL::IdString> matched_gold;
    pool<RTLIL::IdString> matched_gate;

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
        // ! Warning: NONE type gentry may has the same signal name with DFF/other type's.
        // This will lead to overwriting in name mapping in ABC. If didn't solve this in 
        // ABC. Please DO NOT dump NONE type entries!
        if (gentry.type != MatchType::NONE) {
            write_match_line(f, name, gsig, ksig, gentry.type);
            write_match_line(f_exact, name, gsig, ksig, gentry.type);
            write_match_line(f_validated, name, gsig, ksig, gentry.type);
        }
        matched_gold.insert(name);
        matched_gate.insert(name);
        result.stats.exact_total++;
        update_match_stats(result.stats, gentry.type);
        result.cut_points.push_back(CutPoint{name, gsig, ksig, gentry.type,
                gold_ff_q_map.count(gsig) ? gold_ff_q_map[gsig] : nullptr,
                gate_ff_q_map.count(ksig) ? gate_ff_q_map[ksig] : nullptr,
                gentry.wire_name, gentry.bit_index,
                kentry.wire_name, kentry.bit_index});
    }

    result.stats.unmatched_gold = GetSize(gold) - GetSize(matched_gold);
    result.stats.unmatched_gate = GetSize(gate) - GetSize(matched_gate);

    // External verification guidance: user-provided signal map
    if (!conf.external_match_file.empty()) {
        FILE *fext = fopen(conf.external_match_file.c_str(), "r");
        if (fext != nullptr) {
            char buf[4096];
            string active_section;
            while (fgets(buf, sizeof(buf), fext) != nullptr) {
                string line = buf;
                while (!line.empty() && (line.back() == '\n' || line.back() == '\r'))
                    line.pop_back();
                if (line.empty() || line[0] == '#') continue;
                // Section header: [gold:gate]
                if (line[0] == '[' && line.back() == ']') {
                    active_section = line.substr(1, line.size() - 2);
                    continue;
                }
                // Signal lines: gold_name gate_name [TYPE]
                std::istringstream iss(line);
                string gname, kname, tstr;
                if (!(iss >> gname >> kname)) continue;
                iss >> tstr;
                // Section filter
                if (!active_section.empty()) {
                    string pid = strip_backslash(gold_mod->name) + ":" + strip_backslash(gate_mod->name);
                    if (active_section != pid) continue;
                }
                // Try literal + auto-expand multi-bit
                auto try_pair = [&](const string &gn, const string &kn) -> bool {
                    for (auto &ge : gold) {
                        if (strip_backslash(ge.first) != gn) continue;
                        if (matched_gold.count(ge.first)) continue;
                        for (auto &ke : gate) {
                            if (strip_backslash(ke.first) != kn) continue;
                            if (matched_gate.count(ke.first)) continue;
                            MatchType t = ge.second.type;
                            if (tstr == "PI") t = MatchType::PI;
                            else if (tstr == "PO") t = MatchType::PO;
                            else if (tstr == "DFF") t = MatchType::DFF;
                            else if (tstr == "DFF_PO") t = MatchType::DFF_PO;
                            else if (tstr == "SUBCKT_PIPO") t = MatchType::SUBCKT_PIPO;
                            result.cut_points.push_back(CutPoint{ge.first, ge.second.sig, ke.second.sig, t,
                                nullptr, nullptr, ge.second.wire_name, ge.second.bit_index,
                                ke.second.wire_name, ke.second.bit_index});
                            matched_gold.insert(ge.first);
                            matched_gate.insert(ke.first);
                            result.stats.exact_total++;
                            if (f) write_match_line(f, ge.first, ge.second.sig, ke.second.sig, t);
                            if (f_exact) write_match_line(f_exact, ge.first, ge.second.sig, ke.second.sig, t);
                            return true;
                        }
                    }
                    return false;
                };
                try_pair(gname, kname);
                string gb = gname, kb = kname;
                size_t gp = gname.rfind('[');
                if (gp != string::npos) gb = gname.substr(0, gp);
                size_t kp = kname.rfind('[');
                if (kp != string::npos) kb = kname.substr(0, kp);
                for (int bi = 0; bi < 2048; bi++)
                    try_pair(gb + "[" + std::to_string(bi) + "]", kb + "[" + std::to_string(bi) + "]");
            }
            fclose(fext);
            result.stats.unmatched_gold = GetSize(gold) - GetSize(matched_gold);
            result.stats.unmatched_gate = GetSize(gate) - GetSize(matched_gate);
        }
    }

    int applied_suggestions = 0;
    int validated_dff_suggestions = 0;
    int rejected_dff_suggestions = 0;
    if (emit_match_file && !conf.accept_sugs_file.empty()) {
        Json::array accepted = load_match_suggestions_file(conf.accept_sugs_file);
        for (auto &item : accepted) {
            if (!item.is_object())
                continue;
            if (item["pair_id"].string_value() != pair_id)
                continue;
            if (item["snapshot"].string_value() != "pre_async")
                continue;

            RTLIL::IdString gold_name = RTLIL::escape_id(item["gold_name"].string_value());
            RTLIL::IdString gate_name = RTLIL::escape_id(item["suggested_gate_name"].string_value());
            if (item["score_margin"].number_value() <= 0) {
                append_jsonl(vali_jsonl, Json::object {
                    {"design", strip_backslash(conf.gold_mod->name)},
                    {"gold_mod", strip_backslash(gold_mod->name)},
                    {"gate_mod", strip_backslash(gate_mod->name)},
                    {"pair_id", pair_id},
                    {"signal_name", strip_backslash(gold_name)},
                    {"match_type", item["type"].string_value()},
                    {"source", "ml_raw"},
                    {"score", item["score"].number_value()},
                    {"margin", item["score_margin"].number_value()},
                    {"validator_result", "skip"},
                    {"skip_reason", "margin_gate"},
                    {"validator_backend", ""},
                    {"runtime_ms", 0.0},
                    {"accepted", false},
                    {"boundary_map_expected", 0},
                    {"boundary_map_applied", 0},
                    {"constant_completed_net_count", 0},
                    {"module_interface_input_count", 0},
                    {"state_cut_input_count", 0},
                    {"child_boundary_input_count", 0},
                    {"passthrough_alias_input_count", 0},
                    {"slice_or_concat_residual_count", 0},
                    {"traceable_residual_input_count", 0},
                    {"promoted_from_trace_count", 0},
                    {"constant_completed_promotable_count", 0},
                    {"promoted_from_constant_completion_count", 0},
                    {"promoted_internal_boundary_count", 0},
                    {"unresolved_internal_input_count", 0},
                    {"unresolved_untraceable_input_count", 0},
                    {"constant_completed_traceable_remaining_count", 0},
                    {"constant_completed_traceable_count", 0},
                    {"constant_completed_untraceable_count", 0},
                    {"preblif_residual_count", 0},
                    {"preblif_traceable_residual_count", 0},
                    {"preblif_promotable_residual_count", 0},
                    {"preblif_untraceable_residual_count", 0},
                    {"promoted_from_preblif_residual_count", 0},
                    {"blif_residual_count", 0},
                    {"blif_residual_traceable_count", 0},
                    {"blif_residual_promotable_count", 0},
                    {"blif_residual_opaque_cell_output_count", 0},
                    {"blif_residual_library_resolved_count", 0},
                    {"blif_residual_untraceable_count", 0},
                    {"promoted_from_blif_residual_count", 0},
                    {"shell_refinement_iterations", 0},
                    {"promoted_internal_boundary_samples", Json::array()},
                    {"promoted_from_constant_completion_samples", Json::array()},
                    {"unresolved_internal_input_samples", Json::array()},
                    {"constant_completed_remaining_samples", Json::array()},
                    {"constant_completed_samples", Json::array()},
                    {"preblif_residual_samples", Json::array()},
                    {"preblif_promoted_samples", Json::array()},
                    {"preblif_remaining_samples", Json::array()},
                    {"blif_residual_samples", Json::array()},
                    {"blif_promoted_samples", Json::array()},
                    {"blif_remaining_samples", Json::array()},
                    {"unresolved_internal_boundaries", 0},
                    {"child_boundary_count", 0},
                    {"unresolved_child_boundaries", 0}
                });
                continue;
            }
            if (!gold.count(gold_name) || !gate.count(gate_name))
                continue;
            if (matched_gold.count(gold_name) || matched_gate.count(gate_name))
                continue;

            const auto &gentry = gold.at(gold_name);
            const auto &kentry = gate.at(gate_name);
            if (gentry.type != kentry.type)
                continue;
            if (gentry.type == MatchType::NONE)
                continue;

            RTLIL::SigBit gsig = gentry.sig;
            RTLIL::SigBit ksig = kentry.sig;
            CutPoint candidate_cutpoint{gold_name, gsig, ksig, gentry.type,
                    gold_ff_q_map.count(gsig) ? gold_ff_q_map[gsig] : nullptr,
                    gate_ff_q_map.count(ksig) ? gate_ff_q_map[ksig] : nullptr,
                    gentry.wire_name, gentry.bit_index,
                    kentry.wire_name, kentry.bit_index};

            if (gentry.type == MatchType::DFF || gentry.type == MatchType::DFF_PO) {
                std::vector<CutPoint> local_cps =
                    false ?
                    select_support_sliced_dff_cutpoints(gold_mod, gate_mod, result.cut_points, candidate_cutpoint) :
                    select_local_dff_cutpoints(result.cut_points, &candidate_cutpoint);
                LocalValidateResult vali =
                    validate_partition_pair(conf, gold_mod, gate_mod, local_cps, true);
                append_jsonl(vali_jsonl, Json::object {
                    {"design", strip_backslash(conf.gold_mod->name)},
                    {"gold_mod", strip_backslash(gold_mod->name)},
                    {"gate_mod", strip_backslash(gate_mod->name)},
                    {"pair_id", pair_id},
                    {"signal_name", strip_backslash(gold_name)},
                    {"match_type", get_match_type_str(gentry.type)},
                    {"source", "ml_raw"},
                    {"score", item["score"].number_value()},
                    {"margin", item["score_margin"].number_value()},
                    {"validator_result", vali.proved ? "pass" : "fail"},
                    {"validator_backend", vali.vali_backend},
                    {"used_bmc_fallback", vali.used_bmc_fb},
                    {"authoritative_ok", vali.auth_ok},
                    {"authoritative_reason", vali.auth_why},
                    {"unsafe_reason", vali.unsafe_why},
                    {"fallback_reason", vali.fb_why},
                    {"runtime_ms", vali.runtime_ms},
                    {"accepted", vali.proved},
                    {"selected_cutpoints", vali.cut_cnt},
                    {"local_exact_total", vali.exact_cnt},
                    {"boundary_map_expected", vali.bnd_map_exp},
                    {"boundary_map_applied", vali.bnd_map_app},
                    {"constant_completed_net_count", vali.const_comp_net_cnt},
                    {"module_interface_input_count", vali.iface_in_cnt},
                    {"state_cut_input_count", vali.state_in_cnt},
                    {"child_boundary_input_count", vali.child_in_cnt},
                    {"passthrough_alias_input_count", vali.alias_in_cnt},
                    {"slice_or_concat_residual_count", vali.slice_res_cnt},
                    {"traceable_residual_input_count", vali.trace_res_in_cnt},
                    {"promoted_from_trace_count", vali.trace_prom_cnt},
                    {"constant_completed_promotable_count", vali.const_comp_prom_cnt},
                    {"promoted_from_constant_completion_count", vali.const_comp_promoted_cnt},
                    {"promoted_internal_boundary_count", vali.prom_int_bnd_cnt},
                    {"unresolved_internal_input_count", vali.unr_int_in_cnt},
                    {"unresolved_untraceable_input_count", vali.unr_untrace_in_cnt},
                    {"constant_completed_traceable_remaining_count", vali.const_comp_trace_rem_cnt},
                    {"constant_completed_traceable_count", vali.const_comp_trace_cnt},
                    {"constant_completed_untraceable_count", vali.const_comp_untrace_cnt},
                    {"preblif_residual_count", vali.preblif_res_cnt},
                    {"preblif_traceable_residual_count", vali.preblif_trace_cnt},
                    {"preblif_promotable_residual_count", vali.preblif_prom_cnt},
                    {"preblif_untraceable_residual_count", vali.preblif_untrace_cnt},
                    {"promoted_from_preblif_residual_count", vali.preblif_promoted_cnt},
                    {"blif_residual_count", vali.blif_res_cnt},
                    {"blif_residual_traceable_count", vali.blif_trace_cnt},
                    {"blif_residual_promotable_count", vali.blif_prom_cnt},
                    {"blif_residual_opaque_cell_output_count", vali.blif_opaque_out_cnt},
                    {"blif_residual_library_resolved_count", vali.blif_lib_resolved_cnt},
                    {"blif_residual_untraceable_count", vali.blif_untrace_cnt},
                    {"promoted_from_blif_residual_count", vali.blif_promoted_cnt},
                    {"shell_refinement_iterations", vali.shell_refine_iter_cnt},
                    {"promoted_internal_boundary_samples", string_array_to_json(vali.prom_int_bnd_samps)},
                    {"promoted_from_constant_completion_samples", string_array_to_json(vali.const_comp_prom_samps)},
                    {"unresolved_internal_input_samples", string_array_to_json(vali.unr_int_in_samps)},
                    {"constant_completed_remaining_samples", string_array_to_json(vali.const_comp_rem_samps)},
                    {"constant_completed_samples", string_array_to_json(vali.const_comp_samps)},
                    {"preblif_residual_samples", string_array_to_json(vali.preblif_res_samps)},
                    {"preblif_promoted_samples", string_array_to_json(vali.preblif_prom_samps)},
                    {"preblif_remaining_samples", string_array_to_json(vali.preblif_rem_samps)},
                    {"blif_residual_samples", string_array_to_json(vali.blif_res_samps)},
                    {"blif_promoted_samples", string_array_to_json(vali.blif_prom_samps)},
                    {"blif_remaining_samples", string_array_to_json(vali.blif_rem_samps)},
                    {"unresolved_internal_boundaries", vali.unr_int_bnd_cnt},
                    {"child_boundary_count", vali.child_bnd_cnt},
                    {"unresolved_child_boundaries", vali.unr_child_bnd_cnt},
                    {"slice_mode", "all_dff"}
                });
                if (!vali.proved) {
                    rejected_dff_suggestions++;
                    log("Rejected DFF suggestion %s -> %s for pair %s: local validation failed.\n",
                        gold_name.c_str(), gate_name.c_str(), pair_id.c_str());
                    continue;
                }
                validated_dff_suggestions++;
                log("Validated DFF suggestion %s -> %s for pair %s.\n",
                    gold_name.c_str(), gate_name.c_str(), pair_id.c_str());
            }

            write_match_line(f, gold_name, gsig, ksig, gentry.type);
            write_match_line(f_validated, gold_name, gsig, ksig, gentry.type);

            matched_gold.insert(gold_name);
            matched_gate.insert(gate_name);
            result.stats.exact_total++;
            update_match_stats(result.stats, gentry.type);
            result.cut_points.push_back(CutPoint{gold_name, gsig, ksig, gentry.type,
                    gold_ff_q_map.count(gsig) ? gold_ff_q_map[gsig] : nullptr,
                    gate_ff_q_map.count(ksig) ? gate_ff_q_map[ksig] : nullptr,
                    gentry.wire_name, gentry.bit_index,
                    kentry.wire_name, kentry.bit_index});
            applied_suggestions++;
        }

        result.stats.unmatched_gold = GetSize(gold) - GetSize(matched_gold);
        result.stats.unmatched_gate = GetSize(gate) - GetSize(matched_gate);
        if (conf.telemetry != nullptr && applied_suggestions > 0)
            conf.telemetry->pair_applied_sugs[pair_id] = applied_suggestions;
        if (applied_suggestions > 0 || validated_dff_suggestions > 0 || rejected_dff_suggestions > 0)
            log("Applied %d match suggestions for pair %s (%d DFF validated, %d DFF rejected).\n",
                applied_suggestions, pair_id.c_str(),
                validated_dff_suggestions, rejected_dff_suggestions);
    }

    if (f != nullptr)
        fclose(f);
    if (f_exact != nullptr)
        fclose(f_exact);
    if (f_validated != nullptr)
        fclose(f_validated);

    if (conf.dump_cfg.dump_match) {
        Json::array suggestions;
        for (auto &it : gold) {
            auto gold_name = it.first;
            const auto &gentry = it.second;
            if (gentry.type == MatchType::NONE)
                continue;

            if (matched_gold.count(gold_name)) {
                append_jsonl(conf.dump_cfg.match_jsonl, Json::object {
                    {"pair_id", pair_id},
                    {"snapshot", snapshot_name},
                    {"gold_mod", strip_backslash(gold_mod->name)},
                    {"gate_mod", strip_backslash(gate_mod->name)},
                    {"gold_name", strip_backslash(gold_name)},
                    {"gate_name", strip_backslash(gold_name)},
                    {"type", get_match_type_str(gentry.type)},
                    {"gold_wire_name", strip_backslash(gentry.wire_name)},
                    {"gate_wire_name", strip_backslash(gate.at(gold_name).wire_name)},
                    {"gold_bit_index", gentry.bit_index},
                    {"gate_bit_index", gate.at(gold_name).bit_index},
                    {"score", 1000},
                    {"label", gentry.type == MatchType::NONE ? 0 : 1}
                });
                continue;
            }

            std::vector<std::pair<double, RTLIL::IdString>> candidates;
            for (auto &gt : gate) {
                auto gate_name = gt.first;
                const auto &kentry = gt.second;
                if (matched_gate.count(gate_name))
                    continue;
                if (kentry.type == MatchType::NONE)
                    continue;
                if (gentry.type != kentry.type)
                    continue;
                if (gentry.bit_index != kentry.bit_index)
                    continue;
                double score = conf.match_model != nullptr && conf.match_model->loaded ?
                    predict_match_score(*conf.match_model, gentry, kentry) :
                    score_match_candidate(gentry, kentry);
                candidates.push_back({score, gate_name});
                append_jsonl(conf.dump_cfg.match_jsonl, Json::object {
                    {"pair_id", pair_id},
                    {"snapshot", snapshot_name},
                    {"gold_mod", strip_backslash(gold_mod->name)},
                    {"gate_mod", strip_backslash(gate_mod->name)},
                    {"gold_name", strip_backslash(gold_name)},
                    {"gate_name", strip_backslash(gate_name)},
                    {"type", get_match_type_str(gentry.type)},
                    {"gold_wire_name", strip_backslash(gentry.wire_name)},
                    {"gate_wire_name", strip_backslash(kentry.wire_name)},
                    {"gold_bit_index", gentry.bit_index},
                    {"gate_bit_index", kentry.bit_index},
                    {"score", score},
                    {"label", 0}
                });
            }

            std::sort(candidates.begin(), candidates.end(),
                [](const std::pair<double, RTLIL::IdString> &lhs, const std::pair<double, RTLIL::IdString> &rhs) {
                    if (lhs.first != rhs.first)
                        return lhs.first > rhs.first;
                    return lhs.second.str() < rhs.second.str();
                });

            if (!candidates.empty() && candidates.front().first > 0) {
                auto top_name = candidates.front().second;
                const auto &top_entry = gate.at(top_name);
                int score_margin = candidates.front().first;
                if (GetSize(candidates) > 1)
                    score_margin = candidates.front().first - candidates[1].first;

                Json suggestion = Json::object {
                    {"pair_id", pair_id},
                    {"snapshot", snapshot_name},
                    {"gold_mod", strip_backslash(gold_mod->name)},
                    {"gate_mod", strip_backslash(gate_mod->name)},
                    {"gold_name", strip_backslash(gold_name)},
                    {"gold_wire_name", strip_backslash(gentry.wire_name)},
                    {"gold_bit_index", gentry.bit_index},
                    {"type", get_match_type_str(gentry.type)},
                    {"suggested_gate_name", strip_backslash(top_name)},
                    {"suggested_gate_wire_name", strip_backslash(top_entry.wire_name)},
                    {"suggested_gate_bit_index", top_entry.bit_index},
                    {"score", candidates.front().first},
                    {"score_margin", score_margin}
                };
                suggestions.push_back(suggestion);
                append_jsonl(sugs_jsonl, suggestion);
                if (conf.telemetry != nullptr && snapshot_name == "pre_async")
                    conf.telemetry->match_suggestions.push_back(suggestion);
            }
        }

        if (!suggestions.empty()) {
            string suggestions_file = conf.tempdir_name + "/match_suggestions_" +
                snapshot_name + "_" + sanitize_filename(pair_id) + ".json";
            write_match_suggestions(suggestions_file, suggestions);
        }
    }

    return result;
}

dict<RTLIL::Module*, std::vector<CutPoint>> match_signals(RTLIL::Design *design, const CheckConfig& conf,
                                                                 ModMap& mod_map, bool emit_match_file,
                                                                 const string &snapshot_name)
{
    assert(design);
    auto gold2gate = mod_map.mod_map_gold;

    dict<RTLIL::Module*, std::vector<CutPoint>> gold2cutpoints;

    for(auto const &[gold, gate] : gold2gate){
        auto gold_mod = design->module(gold);
        auto gate_mod = design->module(gate);
        MatchResult match_result =
            match_signals_module(design, gold_mod, gate_mod, conf, emit_match_file, snapshot_name);
        gold2cutpoints[gold_mod] = match_result.cut_points;
        if (emit_match_file && conf.telemetry != nullptr)
            conf.telemetry->pair_match_stats[get_pair_id(gold, gate)] = match_result.stats;
    }
    return gold2cutpoints;
}

void cutpoints_to_pi_po(RTLIL::Module *mod,
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

    auto cell_has_ff_ports = [&](RTLIL::Cell *cell) {
        return cell->hasPort(ID::Q) && cell->hasPort(ID::D) &&
               (cell->is_builtin_ff() || cell->type == ID($anyinit) || cell->type.contains("DFF"));
    };

    auto find_ff_by_qbit = [&](RTLIL::SigBit qbit) -> RTLIL::Cell* {
        if (!qbit.is_wire())
            return nullptr;
        for (auto cell : mod->cells()) {
            if (!cell_has_ff_ports(cell))
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

        cut_q_bits.insert(qbit_mapped);
        cut_cells.insert(ff);

        RTLIL::Wire *pi_wire = make_port_wire(cp.name, "_pi", 1, true, false);
        RTLIL::SigBit pi_bit(pi_wire);
        pending_q_conns.emplace_back(RTLIL::SigSpec(qbit_port), RTLIL::SigSpec(pi_wire));
        if (qbit_mapped != pi_bit)
            pending_q_conns.emplace_back(RTLIL::SigSpec(qbit_mapped), RTLIL::SigSpec(pi_bit));

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
        RTLIL::Wire *w_out = make_port_wire(cp.name, "_po", 1, false, true);
        mod->connect(RTLIL::SigSpec(w_out), RTLIL::SigSpec(dbit));
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

} // namespace guide_check
YOSYS_NAMESPACE_END
