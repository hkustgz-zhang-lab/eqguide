#ifndef YOSYS_PASSES_GUIDE_CHECK_DIV_CHECK_H
#define YOSYS_PASSES_GUIDE_CHECK_DIV_CHECK_H

#include "passes/guide/check/shared.h"
#include "passes/guide/check/check.h"

YOSYS_NAMESPACE_BEGIN
namespace guide_check {

struct DivMapEntry {
    RTLIL::IdString gold_mod;
    RTLIL::IdString gate_mod;
    RTLIL::IdString gold_cell;
    RTLIL::IdString gate_cell;
    bool is_div_mod;
};

using DivMap = std::vector<DivMapEntry>;

bool is_divider_cell(RTLIL::Design *design, RTLIL::Cell *cell);
std::pair<int, bool> get_divider_width_sign(RTLIL::Design *design, RTLIL::Cell *cell);
void extract_div(RTLIL::Design *design, RTLIL::Module *mod);
bool check_div(RTLIL::Design *design, RTLIL::Module *mod, const string &tempdir_name,
               const MlDumpConfig &dump_cfg, const string &pair_id,
               const string &gold_mod_name, const string &gate_mod_name,
               const string &sig_dir);
std::vector<std::pair<RTLIL::IdString, bool>> check_extract_div(RTLIL::Design *design, DivMap &dm,
                                                                  const string &tempdir_name,
                                                                  const MlDumpConfig &dump_cfg,
                                                                  const string &sig_dir,
                                                                  pool<RTLIL::IdString> *touched_mods = nullptr);
DivMap get_div_map(RTLIL::Design *design, const ModMap &mod_map);

} // namespace guide_check
YOSYS_NAMESPACE_END

#endif
