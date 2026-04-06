#ifndef YOSYS_PASSES_GUIDE_CHECK_MATCHING_H
#define YOSYS_PASSES_GUIDE_CHECK_MATCHING_H

#include "passes/guide/check/shared.h"
#include "passes/guide/check/check.h"

YOSYS_NAMESPACE_BEGIN
namespace guide_check {

void write_match_suggestions(const string &path, const Json::array &suggestions);
string match_suggestions_path(const string &match_jsonl);
string match_artifact_dir(const CheckConfig &conf);
MatchResult match_signals_module(RTLIL::Design *design, RTLIL::Module *gold_mod, RTLIL::Module *gate_mod,
                                 const CheckConfig &conf, bool emit_match_file, const string &snapshot_name);
dict<RTLIL::Module*, std::vector<CutPoint>> match_signals(RTLIL::Design *design, const CheckConfig &conf,
                                                          ModMap &mod_map, bool emit_match_file,
                                                          const string &snapshot_name);
void cutpoints_to_pi_po(RTLIL::Module *mod, const std::vector<CutPoint> &cutpoints, bool use_gold);

} // namespace guide_check
YOSYS_NAMESPACE_END

#endif
