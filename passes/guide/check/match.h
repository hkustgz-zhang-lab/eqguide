#ifndef YOSYS_PASSES_GUIDE_CHECK_MATCH_H
#define YOSYS_PASSES_GUIDE_CHECK_MATCH_H

#include "passes/guide/check/shared.h"
#include "passes/guide/check/check.h"

YOSYS_NAMESPACE_BEGIN
namespace guide_check {

struct CutPoint {
	RTLIL::IdString name;
	RTLIL::SigBit gold_sig;
	RTLIL::SigBit gate_sig;
	MatchType type = MatchType::NONE;
	RTLIL::Cell *gold_ff_cell = nullptr;
	RTLIL::Cell *gate_ff_cell = nullptr;
	RTLIL::IdString gold_wire_name;
	int gold_bit_index = 0;
	RTLIL::IdString gate_wire_name;
	int gate_bit_index = 0;
};

struct MatchResult
{
	std::vector<CutPoint> cut_points;
	MatchStats stats;
};

struct NamedSig {
	RTLIL::SigBit sig;
	MatchType type = MatchType::NONE;
	RTLIL::IdString wire_name;
	int bit_index = 0;
};

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
