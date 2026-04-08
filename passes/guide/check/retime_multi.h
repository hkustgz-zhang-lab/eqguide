#ifndef YOSYS_PASSES_GUIDE_CHECK_RETIME_MULTI_H
#define YOSYS_PASSES_GUIDE_CHECK_RETIME_MULTI_H

#include "passes/guide/check/shared.h"
#include "passes/guide/check/check.h"

YOSYS_NAMESPACE_BEGIN
namespace guide_check {

bool valid_internal_multiplier_cell(RTLIL::Cell *cell);
bool is_multiplier_cell(RTLIL::Design *design, RTLIL::Cell *cell);
RTLIL::SigSpec resize_u0(RTLIL::SigSpec src, int width);
RTLIL::IdString unique_cell_name(RTLIL::Module *m, const std::string &base);
void pick_operands(RTLIL::Design *design, RTLIL::Cell *cell, RTLIL::SigSpec &op1, RTLIL::SigSpec &op2);
void replace_mul_with_commutative_stub(RTLIL::Design *design, RTLIL::Module *mod, RTLIL::Cell *cell);
std::pair<int, bool> get_multiplier_width_sign(RTLIL::Design *design, RTLIL::Cell *cell);
void extract_multi(RTLIL::Design *design, RTLIL::Module *mod);
bool check_multi(RTLIL::Design *design, RTLIL::Module *mod, const string &tempdir_name,
                 const string &lib_file, const MlDumpConfig &dump_cfg, const string &pair_id,
                 const string &gold_mod_name, const string &gate_mod_name, bool amulet = true);
std::vector<std::pair<RTLIL::IdString, bool>> check_extract_multi(RTLIL::Design *design, MultiMap &mm,
                                                                  const string &tempdir_name,
                                                                  const MlDumpConfig &dump_cfg,
                                                                  pool<RTLIL::IdString> *touched_mods = nullptr);
MultiMap get_multi_map(RTLIL::Design *design, const ModMap &mod_map);
std::vector<RTLIL::Module*> topo_sort_modules(RTLIL::Design *design);
std::vector<RTLIL::Module*> topo_sort_modules(RTLIL::Design *design, const RTLIL::IdString &root);
Results check_retime(const CheckConfig &conf,
                     std::set<std::pair<RTLIL::IdString, RTLIL::IdString>> &retimed_mods);
Results check_extract_retime(const ModMap &mmap, const CheckConfig &conf);
RTLIL::Design *prepare_blif_module_design(RTLIL::Design *design, RTLIL::Module *mod,
                                          const string &lib_file = string(),
                                          int *inserted_bbconsts = nullptr);

} // namespace guide_check
YOSYS_NAMESPACE_END

#endif
