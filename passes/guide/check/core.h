#ifndef YOSYS_PASSES_GUIDE_CHECK_CORE_H
#define YOSYS_PASSES_GUIDE_CHECK_CORE_H

#include "passes/guide/check/shared.h"

YOSYS_NAMESPACE_BEGIN
namespace guide_check {

void print_MultiMap(const MultiMap &mm);
std::string strip_backslash(const RTLIL::IdString &id);
RTLIL::Design *empty_design();
string sanitize_filename(const string &s);
string path_dirname(const string &path);
string pair_artifact_path(const string &dir_name, const string &prefix,
                          RTLIL::Module *gold_mod, RTLIL::Module *gate_mod, const string &ext);
string get_pair_id(const RTLIL::IdString &gold_mod, const RTLIL::IdString &gate_mod);
Json match_stats_to_json(const MatchStats &stats);
Json pair_record_to_json(const PairRecord &record);
Json run_record_to_json(const RunRecord &record);
void flatten_std_cells(RTLIL::Design *design, RTLIL::Design *lib_design);
RTLIL::Design *clone_design_for_passes(RTLIL::Design *design);
void lib_import_to_design(RTLIL::Design *design, RTLIL::Design *lib_design);
RTLIL::IdString get_orignal_mod_name(const RTLIL::IdString &mod_name,
                                     const RTLIL::IdString root_mod_name, const string &prefix);
ModMap hier_mod_map(RTLIL::Design *design, CheckConfig &conf);
string dump_aig(RTLIL::Design *design, const string &dir_name, RTLIL::Module *mod, const string &lib_file);
string dump_aig(RTLIL::Design *design, const string &dir_name, RTLIL::Module *mod);
string dump_blif(RTLIL::Design *design, const string &dir_name, RTLIL::Module *mod, const string &lib_file);
int materialize_blackbox_input_consts(RTLIL::Design *design, RTLIL::Module *mod);
string dump_blif_module(RTLIL::Design *design, const string &dir_name, RTLIL::Module *mod,
                        const string &lib_file, int *inserted_bbconsts = nullptr);
string dump_smt2(RTLIL::Design *design, const string &dir_name,
                 std::pair<RTLIL::Module*, RTLIL::Module*> mod_pair, const string &lib_file);
bool abc_cec_module(const CheckConfig &conf, bool fatal = true, CommandResult *deciding_result = nullptr);
bool bmcinduct_check(const CheckConfig &conf);

} // namespace guide_check
YOSYS_NAMESPACE_END

#endif
