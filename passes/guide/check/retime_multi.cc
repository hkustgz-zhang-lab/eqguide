#include "passes/guide/check/retime_multi.h"
#include "passes/guide/check/fail_exec.h"

YOSYS_NAMESPACE_BEGIN
namespace guide_check {

bool valid_internal_multiplier_cell(RTLIL::Cell *cell)
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


bool is_multiplier_cell(RTLIL::Design *design, RTLIL::Cell *cell)
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

RTLIL::SigSpec resize_u0(RTLIL::SigSpec src, int width)
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

RTLIL::IdString unique_cell_name(RTLIL::Module *m, const std::string &base)
{
    for (int i = 0;; i++) {
        std::string cand = (i == 0) ? base : stringf("%s$%d", base.c_str(), i);
        RTLIL::IdString id = RTLIL::escape_id(cand);
        if (m->cell(id) == nullptr) return id;
    }
}


// Select two "operand" signals: $mul uses A/B; submodules take the first two input ports
void pick_operands(RTLIL::Design *design, RTLIL::Cell *cell,
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

void replace_mul_with_commutative_stub(RTLIL::Design *design, RTLIL::Module *mod, RTLIL::Cell *cell)
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


// Must ensure the cell is a multiplier.
std::pair<int,bool> get_multiplier_width_sign(RTLIL::Design *design, RTLIL::Cell *cell) 
{   
    bool sign;
    int width;
    RTLIL::SigSpec op1, op2;
    pick_operands(design, cell, op1, op2);
    assert(op1.size() == op2.size());
    
    width = op1.size();

    if(cell->type == ID($mul)) {
        sign = cell->parameters[ID::A_SIGNED].as_bool();
    }
    else {
        auto mod = design->module(cell->type);
        assert(mod);
        sign = mod->get_bool_attribute(ID(is_signed));
    }
    
    return {width, sign};
}


void extract_multi(RTLIL::Design *design, RTLIL::Module *mod)
{
    std::vector<RTLIL::Cell*> cells = mod->cells();
    for (auto *cell : cells) {
        if (!is_multiplier_cell(design, cell))
            continue;
        replace_mul_with_commutative_stub(design, mod, cell);
    }
    mod->fixup_ports();
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




bool check_multi(RTLIL::Design* design, RTLIL::Module* mod, const string& tempdir_name, const string& lib_file,
    const MlDumpConfig &dump_cfg, const string &pair_id, const string &gold_mod_name,
    const string &gate_mod_name, bool amulet){
    log_assert(mod->get_bool_attribute(ID(multiplier)));
    bool is_signed = mod->get_bool_attribute(ID(is_signed));    
    auto aig_file = dump_aig(design, tempdir_name, mod, lib_file);

    amulet = true; // Uses Amulet now.
    if(amulet){
        log("Using amulet to verify the multiplier.\n");
        auto miter_tmp_file = tempdir_name + "/"
            + strip_backslash(mod->name)
            + ".miter.cnf";
        auto rewritten_tmp_file = tempdir_name + "/"
            + strip_backslash(mod->name)
            + ".rewritten.aig";

        auto amulet_sub_cmd = "amulet -substitute " + aig_file + " " + miter_tmp_file  + " " + rewritten_tmp_file + (is_signed? " -signed" : "");
        std::cout << "Running amulet: " << amulet_sub_cmd << std::endl;
        CommandResult substitute_capture;
        string log_dir = failure_log_dir(dump_cfg);
        exec_cmd(amulet_sub_cmd, tempdir_name, "amulet-substitute-" + sanitize_filename(strip_backslash(mod->name)), log_dir, &substitute_capture);
        auto amulet_veri_cmd = "amulet -verify " + rewritten_tmp_file + (is_signed ? " -signed" : "");
        std::cout << "Running amulet: " << amulet_veri_cmd << std::endl;
        CommandResult verify_capture;
        auto ret = exec_cmd(amulet_veri_cmd, tempdir_name, "amulet-verify-" + sanitize_filename(strip_backslash(mod->name)), log_dir, &verify_capture);
        if(ret != 1){
            log("Amulet Verify failed.\n");
            verify_capture.output += "Amulet Verify failed.\n";
            verify_capture.raw_result_code = ret;
            verify_capture.result_code = ret;
            verify_capture.proof_outcome = "blocked";
            emit_failure_packet(dump_cfg, pair_id, "AMULET", "amulet_verify", gold_mod_name, gate_mod_name, verify_capture);
            return false;
        }
        return true;
    } else {
        bool correct = false; 
        log("Using dynphaseorderopt to verify the multiplier.\n");
        auto cmd = "dynphaseorderopt " + aig_file;
        CommandResult capture;
        exectue_and_check(cmd, correct, "CIRCUIT IS CORRECT", tempdir_name,
                          "dynphaseorderopt-" + sanitize_filename(strip_backslash(mod->name)),
                          failure_log_dir(dump_cfg),
                          &capture);
        if (!correct) {
            capture.raw_result_code = capture.exit_status;
            capture.result_code = capture.exit_status;
            capture.proof_outcome = "blocked";
            emit_failure_packet(dump_cfg, pair_id, "AMULET", "dynphaseorderopt", gold_mod_name, gate_mod_name, capture);
        }
        return correct;
    }
}

std::vector<std::pair<RTLIL::IdString, bool>> check_extract_multi(RTLIL::Design* design, MultiMap& mm,
                                                                         const string& tempdir_name,
                                                                         const MlDumpConfig &dump_cfg,
                                                                         pool<RTLIL::IdString> *touched_mods){

    auto t_start = std::chrono::steady_clock::now();
    
    pool<Module*> mod_to_check;
    dict<RTLIL::Module*, string> mod_to_pair_id;
    dict<RTLIL::Module*, string> mod_to_gold_name;
    dict<RTLIL::Module*, string> mod_to_gate_name;
    
    pool<Module*> mod_to_extract;
    pool<Module*> mod_to_blackbox;

    std::vector<std::pair<RTLIL::IdString, bool>> results;
    
    for(auto &e : mm) {
        if(e.is_multi_mod){
            auto goldm = design->module(e.gold_mod);
            auto gatem = design->module(e.gate_mod);
            if (touched_mods != nullptr) {
                touched_mods->insert(e.gold_mod);
                touched_mods->insert(e.gate_mod);
            }
            mod_to_check.insert(goldm);
            mod_to_check.insert(gatem);
            mod_to_pair_id[goldm] = get_pair_id(e.gold_mod, e.gate_mod);
            mod_to_pair_id[gatem] = get_pair_id(e.gold_mod, e.gate_mod);
            mod_to_gold_name[goldm] = strip_backslash(e.gold_mod);
            mod_to_gold_name[gatem] = strip_backslash(e.gold_mod);
            mod_to_gate_name[goldm] = strip_backslash(e.gate_mod);
            mod_to_gate_name[gatem] = strip_backslash(e.gate_mod);
            mod_to_blackbox.insert(goldm);
            mod_to_blackbox.insert(gatem);
        }
        else { 
            auto goldm = design->module(e.gold_mod);
            auto gatem = design->module(e.gate_mod);
            if (touched_mods != nullptr) {
                touched_mods->insert(e.gold_mod);
                touched_mods->insert(e.gate_mod);
            }
            assert(goldm); assert(gatem);
            auto goldc = goldm->cell(e.gold_cell);
            auto gatec = gatem->cell(e.gate_cell);
            assert(goldc); assert(gatec);
            auto gold_mul = design->module(goldc->type);
            auto gate_mul = design->module(gatec->type);
            if(goldc->type.isPublic() || goldc->type.begins_with("$paramod")) {
                mod_to_check.insert(gold_mul);
                mod_to_pair_id[gold_mul] = get_pair_id(e.gold_mod, e.gate_mod);
                mod_to_gold_name[gold_mul] = strip_backslash(e.gold_mod);
                mod_to_gate_name[gold_mul] = strip_backslash(e.gate_mod);
            }
            if(gatec->type.isPublic() || gatec->type.begins_with("$paramod")) {
                mod_to_check.insert(gate_mul);
                mod_to_pair_id[gate_mul] = get_pair_id(e.gold_mod, e.gate_mod);
                mod_to_gold_name[gate_mul] = strip_backslash(e.gold_mod);
                mod_to_gate_name[gate_mul] = strip_backslash(e.gate_mod);
            }
            mod_to_extract.insert(goldm);
            mod_to_extract.insert(gatem);
        }
    }

    for(auto mod: mod_to_check){
        bool result = check_multi(design, mod, tempdir_name, "", dump_cfg, mod_to_pair_id[mod],
                                  mod_to_gold_name[mod], mod_to_gate_name[mod]);
        results.push_back({mod->name,result});
    }

    for(auto mod: mod_to_extract) {
        extract_multi(design, mod);
    }

    for(auto mod: mod_to_blackbox) {
        mod->set_bool_attribute(ID(blackbox), true);
    }
    auto t_end = std::chrono::steady_clock::now();
    timing_stat.check_mul_ms += std::chrono::duration_cast<std::chrono::milliseconds>(t_end-t_start).count();
    return results;
}


MultiMap get_multi_map(RTLIL::Design* design, const ModMap &mod_map) {
    
    auto t_start = std::chrono::steady_clock::now();
    
    auto mmap = mod_map.mod_map_gold;

    struct Multi {
        int width;
        bool sign;
        RTLIL::IdString type;
        Cell* cell;
        bool operator<(const Multi& other) const {
            if(sign != other.sign) return sign < other.sign; 
            return width < other.width;
        }

        bool param_equal(const Multi& other) const {
            return (width == other.width) && (sign == other.sign);
        }
    };

    vector<Multi> gold_multi;
    vector<Multi> gate_multi;

    MultiMap map;
    

    for(const auto& [gold_mod_name, gate_mod_name]: mmap) {
        auto gold_mod = design->module(gold_mod_name);
        auto gate_mod = design->module(gate_mod_name);
        assert(gold_mod);
        assert(gate_mod);

        // Module map
        bool gold_is_mulmod = gold_mod->get_bool_attribute(ID(multiplier));
        bool gate_is_mulmod = gate_mod->get_bool_attribute(ID(multiplier));

        if (gold_is_mulmod || gate_is_mulmod) {
            if (gold_is_mulmod && gate_is_mulmod) {
                MultiMapEntry e;
                e.gold_mod = gold_mod_name;
                e.gate_mod = gate_mod_name;
                e.gold_cell = "";
                e.gate_cell = "";
                e.is_multi_mod = true;
                map.push_back(e);
            } else {
                log_warning("Can not map multiplier %s and %s: One of them is not multiplier!\n",
                            log_id(gold_mod_name), log_id(gate_mod_name));
            }
            continue;
        }



        // Cell map;
        gold_multi.clear();
        gate_multi.clear();    
        for(auto cell: gold_mod->cells()) { 
            if(is_multiplier_cell(design,cell)) {
                auto w_s = get_multiplier_width_sign(design, cell);
                gold_multi.push_back({w_s.first,w_s.second,cell->type,cell});
            }
        }
        for(auto cell: gate_mod->cells()){
            if(is_multiplier_cell(design,cell)) {
                auto w_s = get_multiplier_width_sign(design, cell);
                gate_multi.push_back({w_s.first,w_s.second,cell->type,cell});
            }
        }

        if(gold_multi.size() != gate_multi.size()) { 
            log_warning("Module %s and %s have different number of multipliers! Skip...\n", 
                gold_mod->name, gate_mod->name);
            continue;
        }
        if(gold_multi.empty() || gate_multi.empty()) {
            continue;
        }
        std::sort(gold_multi.begin(),gold_multi.end());
        std::sort(gate_multi.begin(),gate_multi.end());
        bool map_failed = false;
        MultiMap map_tmp;
        for(size_t i=0; i<gold_multi.size(); i++) {
            auto &mul_gold = gold_multi[i];
            auto &mul_gate = gate_multi[i];
            if(!mul_gold.param_equal(mul_gate)){
                log_warning("Cell %s in Module %s has different parameter with Cell %s in Module %s! Skip this two module!\n",
                    mul_gold.cell->name, gold_mod_name, mul_gate.cell->name, gate_mod_name);
                map_failed = true;
                break;
            }
            MultiMapEntry entry;
            entry.gold_mod  = gold_mod_name;
            entry.gate_mod  = gate_mod_name;
            entry.gold_cell = mul_gold.cell->name;
            entry.gate_cell = mul_gate.cell->name;
            entry.is_multi_mod = false;
            map_tmp.push_back(entry);
        }
        if(!map_failed) {
            map.insert(map.end(), map_tmp.begin(), map_tmp.end());
        }
        
    }

    auto t_end = std::chrono::steady_clock::now();
    timing_stat.mul_map_ms += std::chrono::duration_cast<std::chrono::milliseconds>(t_end-t_start).count();


    print_MultiMap(map);
    return map;
}
std::vector<RTLIL::Module*> topo_sort_modules(RTLIL::Design *design)
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

std::vector<RTLIL::Module*> topo_sort_modules(RTLIL::Design *design, const RTLIL::IdString& root){
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

// maybe we should reconstruct  the check_retime.
Results check_retime(const CheckConfig &conf,
                  std::set<std::pair<RTLIL::IdString, RTLIL::IdString>>&retimed_mods)
{
    Results results;
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


    for (auto mod_pair : retimed_mods)
    {
        auto gold_name = mod_pair.first;
        auto gate_name = mod_pair.second;
        auto gold_m = conf.design->module(gold_name);
        auto gate_m = conf.design->module(gate_name);
        if (!gold_m || !gate_m) {
            log_warning("Skipping retime check for missing module pair: gold=%s vs gate=%s\n",
                log_id(gold_name), log_id(gate_name));
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
            .sched_model_file = conf.sched_model_file,
            .match_model_file = conf.match_model_file,
            .accept_sugs_file = conf.accept_sugs_file,
            .local_vali_slice = conf.local_vali_slice,
            .seq_check_cfg = conf.seq_check_cfg,
            .dump_cfg = conf.dump_cfg,
            .sched_model = conf.sched_model,
            .match_model = conf.match_model,
            .telemetry = conf.telemetry,
            .lib_design = conf.lib_design
        };

        //bool dsec_result = abc_dsec(conf_);
        bool result = bmcinduct_check(conf_);

        
        results.push_back({get_orignal_mod_name(gold_m->name, conf.gold_mod->name, conf.gold_prefix),
                        result});
        
    }

    return results;
}


Results check_extract_retime(const ModMap& mmap, const CheckConfig &conf)
{

    std::set<std::pair<RTLIL::IdString, RTLIL::IdString>> retimed_mods;
    auto t_start = std::chrono::steady_clock::now();
    
        
    // TODO: Maybe we should reconstruct the check_retime.
    // In check_retime(), the function construct the module-mapping relations
    // however, we already have this relationship.
    // It is caused by historical reason.
    (void)mmap;
    Results results = check_retime(conf, retimed_mods);
    
    std::set<RTLIL::IdString> blackbox_mods;


    for (auto mod_pair : retimed_mods)
    {
        for (auto mod_name : {mod_pair.first, mod_pair.second})
        {
            if (conf.telemetry != nullptr)
                conf.telemetry->retimed_mods.insert(mod_name);
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
    auto t_end = std::chrono::steady_clock::now();
    timing_stat.check_retime_ms += std::chrono::duration_cast<std::chrono::milliseconds>(t_end-t_start).count();
    return results;
}

} // namespace guide_check
YOSYS_NAMESPACE_END
