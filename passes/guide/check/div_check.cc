#include "passes/guide/check/div_check.h"
#include "passes/guide/check/fail_exec.h"
#include <unistd.h>

YOSYS_NAMESPACE_BEGIN
namespace guide_check {

static bool valid_internal_divider_cell(RTLIL::Cell *cell)
{
    if(cell->type != ID($div))
        return false;
    RTLIL::SigSpec A = cell->getPort(ID::A);
    RTLIL::SigSpec B = cell->getPort(ID::B);
    dict<RTLIL::IdString, RTLIL::Const> params = cell->parameters;
    if(params[ID::A_SIGNED].as_bool() != params[ID::B_SIGNED].as_bool())
        return false;
    if(A.size() != B.size())
        return false;
    return true;
}

bool is_divider_cell(RTLIL::Design *design, RTLIL::Cell *cell)
{
    if (valid_internal_divider_cell(cell))
        return true;
    if (cell->get_bool_attribute(ID(divider)))
        return true;
    RTLIL::Module *sub = design->module(cell->type);
    if (sub && sub->get_bool_attribute(ID(divider)))
        return true;
    return false;
}

static void pick_div_operands(RTLIL::Design *design, RTLIL::Cell *cell,
                               RTLIL::SigSpec &op1, RTLIL::SigSpec &op2)
{
    if (cell->type == ID($div)) {
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

std::pair<int,bool> get_divider_width_sign(RTLIL::Design *design, RTLIL::Cell *cell)
{
    bool sign;
    int width;
    RTLIL::SigSpec op1, op2;
    pick_div_operands(design, cell, op1, op2);
    width = op1.size();
    if(cell->type == ID($div))
        sign = cell->parameters[ID::A_SIGNED].as_bool();
    else {
        auto mod = design->module(cell->type);
        log_assert(mod);
        sign = mod->get_bool_attribute(ID(is_signed));
    }
    return {width, sign};
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

static void replace_div_with_stub(RTLIL::Design *design, RTLIL::Module *mod, RTLIL::Cell *cell)
{
    RTLIL::SigSpec a, b;
    pick_div_operands(design, cell, a, b);

    auto add_xor_driver = [&](RTLIL::SigSpec out_sig, const std::string &tag) {
        int w = out_sig.size();
        RTLIL::Cell *x = mod->addCell(unique_cell_name(mod, "__div_xor_" + tag), ID($xor));
        x->parameters[ID::A_SIGNED] = RTLIL::Const(0);
        x->parameters[ID::B_SIGNED] = RTLIL::Const(0);
        x->parameters[ID::A_WIDTH]  = RTLIL::Const(w);
        x->parameters[ID::B_WIDTH]  = RTLIL::Const(w);
        x->parameters[ID::Y_WIDTH]  = RTLIL::Const(w);
        x->setPort(ID::A, resize_u0(a, w));
        x->setPort(ID::B, resize_u0(b, w));
        x->setPort(ID::Y, out_sig);
    };

    if (cell->type == ID($div)) {
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
            if (cell->hasPort(ID::Y))
                add_xor_driver(cell->getPort(ID::Y), "Y");
        }
    }
    mod->remove(cell);
}

void extract_div(RTLIL::Design *design, RTLIL::Module *mod)
{
    std::vector<RTLIL::Cell*> cells = mod->cells();
    for (auto *cell : cells) {
        if (!is_divider_cell(design, cell))
            continue;
        replace_div_with_stub(design, mod, cell);
    }
    mod->fixup_ports();
}

static string dump_verilog(RTLIL::Module *mod, const string &dir_name)
{
    string v_file = dir_name + "/" + strip_backslash(mod->name) + ".v";
    string raw_file = dir_name + "/_" + strip_backslash(mod->name) + ".v";

    string src_attr = mod->get_string_attribute(ID(src));
    string src_path;
    if (!src_attr.empty()) {
        size_t colon = src_attr.find(':');
        if (colon != string::npos)
            src_path = src_attr.substr(0, colon);
    }
    if (!src_path.empty()) {
        FILE *fsrc = fopen(src_path.c_str(), "r");
        if (fsrc) {
            FILE *fdst = fopen(v_file.c_str(), "w");
            if (fdst) {
                char buf[16384];
                size_t n;
                while ((n = fread(buf, 1, sizeof(buf), fsrc)) > 0)
                    fwrite(buf, 1, n, fdst);
                fclose(fdst);
            }
            fclose(fsrc);
            return v_file;
        }
        fclose(fsrc);
    }

    RTLIL::Design *tmp = new RTLIL::Design;
    RTLIL::Module *clone = mod->clone();
    tmp->add(clone);

    run_pass("write_verilog -noattr " + raw_file, tmp);
    delete tmp;

    pool<string> port_names;
    for (auto *w : mod->wires())
        if (w->port_id > 0)
            port_names.insert(strip_backslash(w->name));

    FILE *fin = fopen(raw_file.c_str(), "r");
    FILE *fout = fopen(v_file.c_str(), "w");
    if (!fin || !fout) {
        if (fin) fclose(fin);
        if (fout) fclose(fout);
        return v_file;
    }
    int node_id = 500;
    char buf[8192];
    while (fgets(buf, sizeof(buf), fin)) {
        string line(buf);
        while (!line.empty() && (line.back() == '\n' || line.back() == '\r'))
            line.pop_back();
        size_t p = line.find_first_not_of(" \t");
        if (p != string::npos && line.compare(p, 4, "wire") == 0) {
            size_t semi = line.rfind(';');
            if (semi != string::npos) {
                size_t ns = line.rfind(' ', semi - 1);
                if (ns != string::npos && ns > p) {
                    string name = line.substr(ns + 1, semi - ns - 1);
                    while (!name.empty() && name.back() == ' ')
                        name.pop_back();
                    if (!name.empty() && name[0] == '\\')
                        name = name.substr(1);
                    if (port_names.count(name))
                        continue;
                }
            }
        }
        size_t pos;
        while ((pos = line.find("1'h0")) != string::npos) line.replace(pos, 4, "1'b0");
        while ((pos = line.find("1'h1")) != string::npos) line.replace(pos, 4, "1'b1");
        if (p != string::npos && line.compare(p, 6, "assign") == 0) {
            size_t semi = line.rfind(';');
            if (semi != string::npos)
                line = line.substr(0, semi) + stringf(" /*%d*/", node_id++) + line.substr(semi);
        }
        fprintf(fout, "%s\n", line.c_str());
    }
    fclose(fin);
    fclose(fout);

    unlink(raw_file.c_str());
    return v_file;
}

static string dump_signature(RTLIL::Module *mod, const string &dir_name)
{
    string sig_file = dir_name + "/" + strip_backslash(mod->name) + ".sig";

    std::vector<RTLIL::Wire*> ins, outs;
    for (auto *w : mod->wires()) {
        if (w->port_id > 0 && w->port_input)
            ins.push_back(w);
        if (w->port_id > 0 && w->port_output)
            outs.push_back(w);
    }
    std::sort(ins.begin(), ins.end(),
              [](RTLIL::Wire *a, RTLIL::Wire *b){ return a->port_id < b->port_id; });
    std::sort(outs.begin(), outs.end(),
              [](RTLIL::Wire *a, RTLIL::Wire *b){ return a->port_id < b->port_id; });

    FILE *f = fopen(sig_file.c_str(), "w");
    if (!f) {
        log_error("Cannot open signature file %s.\n", sig_file.c_str());
        return "";
    }
    fprintf(f, "Signature:\n");
    for (auto *w : ins) {
        fprintf(f, "%s = (0", strip_backslash(w->name).c_str());
        for (int i = 1; i < w->width; i++)
            fprintf(f, ", %d", i);
        fprintf(f, ")\n");
    }
    for (auto *w : outs) {
        fprintf(f, "%s = (0", strip_backslash(w->name).c_str());
        for (int i = 1; i < w->width; i++)
            fprintf(f, ", %d", i);
        fprintf(f, ")\n");
    }
    fprintf(f, "\nPolynom Description:\n");
    string a = ins.size() >= 1 ? strip_backslash(ins[0]->name) : "A";
    string b = ins.size() >= 2 ? strip_backslash(ins[1]->name) : "B";
    string y = outs.size() >= 1 ? strip_backslash(outs[0]->name) : "Y";
    string r = outs.size() >= 2 ? strip_backslash(outs[1]->name) : "R";
    fprintf(f, "%s*%s + %s +- %s\n", y.c_str(), b.c_str(), r.c_str(), a.c_str());
    fclose(f);
    return sig_file;
}

bool check_div(RTLIL::Design *design, RTLIL::Module *mod, const string &tempdir_name,
               const MlDumpConfig &dump_cfg, const string &pair_id,
               const string &gold_mod_name, const string &gate_mod_name,
               const string &sig_dir)
{
    log_assert(mod->get_bool_attribute(ID(divider)));

    int width = 0;
    for (auto *w : mod->wires())
        if (w->port_id > 0 && w->port_output) {
            width = w->width;
            break;
        }

    auto v_file = dump_verilog(mod, tempdir_name);
    string sig_file = sig_dir + "/" + std::to_string(width) + "bitSignature.txt";

    auto div_cmd = "divVerify_fmcad22 " + v_file + " " + sig_file;
    std::cout << "Running divVerify: " << div_cmd << std::endl;

    string log_dir = failure_log_dir(dump_cfg);
    CommandResult capture;
    auto ret = exec_cmd(div_cmd, tempdir_name,
                        "divverify-" + sanitize_filename(strip_backslash(mod->name)),
                        log_dir, &capture);

    if(capture.output.find("VERIFICATION SUCCESSFUL") == string::npos) {
        log("DivVerify failed.\n");
        capture.output += "DivVerify failed.\n";
        capture.raw_result_code = ret;
        capture.result_code = ret;
        capture.proof_outcome = "blocked";
        emit_failure_packet(dump_cfg, pair_id, "DIVVERIFY", "divverify_verify",
                            gold_mod_name, gate_mod_name, capture);
        return false;
    }
    return true;
}

std::vector<std::pair<RTLIL::IdString, bool>> check_extract_div(RTLIL::Design *design, DivMap &dm,
                                                                  const string &tempdir_name,
                                                                  const MlDumpConfig &dump_cfg,
                                                                  const string &sig_dir,
                                                                  pool<RTLIL::IdString> *touched_mods)
{
    auto t_start = std::chrono::steady_clock::now();

    pool<Module*> mod_to_check;
    dict<RTLIL::Module*, string> mod_to_pair_id;
    dict<RTLIL::Module*, string> mod_to_gold_name;
    dict<RTLIL::Module*, string> mod_to_gate_name;
    pool<Module*> mod_to_extract;
    pool<Module*> mod_to_blackbox;

    std::vector<std::pair<RTLIL::IdString, bool>> results;

    for(auto &e : dm) {
        if(e.is_div_mod){
            auto goldm = design->module(e.gold_mod);
            auto gatem = design->module(e.gate_mod);
            if (touched_mods) {
                touched_mods->insert(e.gold_mod);
                touched_mods->insert(e.gate_mod);
            }
            mod_to_check.insert(goldm);
            mod_to_check.insert(gatem);
            mod_to_pair_id[goldm] = mod_to_pair_id[gatem] = get_pair_id(e.gold_mod, e.gate_mod);
            mod_to_gold_name[goldm] = mod_to_gold_name[gatem] = strip_backslash(e.gold_mod);
            mod_to_gate_name[goldm] = mod_to_gate_name[gatem] = strip_backslash(e.gate_mod);
            mod_to_blackbox.insert(goldm);
            mod_to_blackbox.insert(gatem);
        }
        else {
            auto goldm = design->module(e.gold_mod);
            auto gatem = design->module(e.gate_mod);
            if (touched_mods) {
                touched_mods->insert(e.gold_mod);
                touched_mods->insert(e.gate_mod);
            }
            if(!goldm || !gatem) continue;
            auto goldc = goldm->cell(e.gold_cell);
            auto gatec = gatem->cell(e.gate_cell);
            if(!goldc || !gatec) continue;
            auto gold_div = design->module(goldc->type);
            auto gate_div = design->module(gatec->type);
            if(goldc->type.isPublic() || goldc->type.begins_with("$paramod")) {
                if(gold_div) {
                    mod_to_check.insert(gold_div);
                    mod_to_pair_id[gold_div] = get_pair_id(e.gold_mod, e.gate_mod);
                    mod_to_gold_name[gold_div] = strip_backslash(e.gold_mod);
                    mod_to_gate_name[gold_div] = strip_backslash(e.gate_mod);
                }
            }
            if(gatec->type.isPublic() || gatec->type.begins_with("$paramod")) {
                if(gate_div) {
                    mod_to_check.insert(gate_div);
                    mod_to_pair_id[gate_div] = get_pair_id(e.gold_mod, e.gate_mod);
                    mod_to_gold_name[gate_div] = strip_backslash(e.gold_mod);
                    mod_to_gate_name[gate_div] = strip_backslash(e.gate_mod);
                }
            }
            mod_to_extract.insert(goldm);
            mod_to_extract.insert(gatem);
        }
    }

    for(auto mod : mod_to_check){
        if(!mod) continue;
        bool result = check_div(design, mod, tempdir_name, dump_cfg, mod_to_pair_id[mod],
                                mod_to_gold_name[mod], mod_to_gate_name[mod], sig_dir);
        results.push_back({mod->name, result});
    }

    for(auto mod : mod_to_extract)
        extract_div(design, mod);
    for(auto mod : mod_to_blackbox)
        mod->set_bool_attribute(ID(blackbox), true);

    timing_stat.check_div_ms += std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - t_start).count();
    return results;
}

DivMap get_div_map(RTLIL::Design *design, const ModMap &mod_map)
{
    auto mmap = mod_map.mod_map_gold;

    struct Div {
        int width; bool sign; RTLIL::IdString type; Cell* cell;
        bool operator<(const Div& other) const {
            if(sign != other.sign) return sign < other.sign;
            return width < other.width;
        }
        bool param_equal(const Div& other) const {
            return (width == other.width) && (sign == other.sign);
        }
    };

    vector<Div> gold_div, gate_div;
    DivMap map;

    for(const auto& [gold_mod_name, gate_mod_name]: mmap) {
        auto gold_mod = design->module(gold_mod_name);
        auto gate_mod = design->module(gate_mod_name);
        if(!gold_mod || !gate_mod) continue;

        bool gold_is_divmod = gold_mod->get_bool_attribute(ID(divider));
        bool gate_is_divmod = gate_mod->get_bool_attribute(ID(divider));

        if (gold_is_divmod || gate_is_divmod) {
            if (gold_is_divmod && gate_is_divmod) {
                map.push_back({gold_mod_name, gate_mod_name, "", "", true});
            } else {
                log_warning("Can not map divider %s and %s: one is not divider!\n",
                            log_id(gold_mod_name), log_id(gate_mod_name));
            }
            continue;
        }

        gold_div.clear(); gate_div.clear();
        for(auto cell: gold_mod->cells())
            if(is_divider_cell(design, cell))
                gold_div.push_back({get_divider_width_sign(design, cell).first,
                                    get_divider_width_sign(design, cell).second,
                                    cell->type, cell});
        for(auto cell: gate_mod->cells())
            if(is_divider_cell(design, cell))
                gate_div.push_back({get_divider_width_sign(design, cell).first,
                                    get_divider_width_sign(design, cell).second,
                                    cell->type, cell});

        if(gold_div.size() != gate_div.size()) {
            log_warning("Module %s and %s have different number of dividers! Skip.\n",
                gold_mod->name, gate_mod->name);
            continue;
        }
        if(gold_div.empty()) continue;

        std::sort(gold_div.begin(), gold_div.end());
        std::sort(gate_div.begin(), gate_div.end());
        bool map_failed = false;
        for(size_t i=0; i<gold_div.size(); i++) {
            if(!gold_div[i].param_equal(gate_div[i])) {
                log_warning("Divider parameter mismatch in %s vs %s. Skip!\n",
                    log_id(gold_mod_name), log_id(gate_mod_name));
                map_failed = true;
                break;
            }
            map.push_back({gold_mod_name, gate_mod_name,
                           gold_div[i].cell->name, gate_div[i].cell->name, false});
        }
        (void)map_failed;
    }
    return map;
}

} // namespace guide_check
YOSYS_NAMESPACE_END
