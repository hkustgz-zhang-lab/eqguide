#ifndef YOSYS_PASSES_GUIDE_CHECK_REGION_H
#define YOSYS_PASSES_GUIDE_CHECK_REGION_H

#include "passes/guide/check/shared.h"
#include "passes/guide/check/core.h"

YOSYS_NAMESPACE_BEGIN
namespace guide_check {

std::vector<CutPoint> select_local_dff_cutpoints(const std::vector<CutPoint> &all_cps,
                                                 const CutPoint *extra_cand = nullptr);
std::vector<CutPoint> select_support_sliced_dff_cutpoints(RTLIL::Module *gold_mod,
                                                          RTLIL::Module *gate_mod,
                                                          const std::vector<CutPoint> &all_cps,
                                                          const CutPoint &candidate);
LocalValidateResult validate_partition_pair(const CheckConfig &conf, RTLIL::Module *gold_mod,
                                            RTLIL::Module *gate_mod, const std::vector<CutPoint> &cutpoints,
                                            bool allow_bmc_fallback = true);
void run_local_validate_shadow(const CheckConfig &conf, ModMap &mod_map,
                               const dict<RTLIL::Module*, std::vector<CutPoint>> &gold2cutpoints);
Results partition_prove(const CheckConfig &conf, ModMap &mod_map,
                        const dict<RTLIL::Module*, std::vector<CutPoint>> &gold2cutpoints);

} // namespace guide_check
YOSYS_NAMESPACE_END

#endif
