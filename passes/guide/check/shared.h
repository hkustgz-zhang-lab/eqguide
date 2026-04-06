#ifndef YOSYS_PASSES_GUIDE_CHECK_SHARED_H
#define YOSYS_PASSES_GUIDE_CHECK_SHARED_H

#include "kernel/yosys.h"
#include "kernel/celltypes.h"
#include "kernel/sigtools.h"
#include "kernel/utils.h"
#include "libs/json11/json11.hpp"
#include <cassert>
#include <chrono>
#include <cstdint>
#include <map>
#include <set>
#include <string>
#include <utility>
#include <vector>

YOSYS_NAMESPACE_BEGIN
namespace guide_check {

using json11::Json;

#define TIMINGSTAT_FIELDS(X)            \
	X(abc_cec_ms)                       \
	X(prep_ms)                          \
	X(dump_blif_ms)                     \
	X(read_lib_ms)                      \
	X(hier_mod_map_ms)                  \
	X(signal_map_ms)                    \
	X(check_mul_ms)                     \
	X(mul_map_ms)                       \
	X(check_retime_ms)

struct TimingStat {
#define DECL_FIELD(name) std::uint64_t name = 0;
	TIMINGSTAT_FIELDS(DECL_FIELD)
#undef DECL_FIELD
};

extern TimingStat timing_stat;

using Results = std::vector<std::pair<RTLIL::IdString, bool>>;

struct SeqCheckConfig
{
	int k_induct = 20;
	int step_skip = 0;
	bool weak_mode = false;
	bool no_init = false;
};

struct MlDumpConfig
{
	bool dump_sched = false;
	bool dump_match = false;
	bool dump_fail = false;
	string sched_jsonl;
	string match_jsonl;
	string fail_jsonl;
};

struct PairRecord
{
	string pair_id;
	string gold_mod;
	string gate_mod;
	int gold_dff_cnt = 0;
	int gate_dff_cnt = 0;
	bool has_submodule = false;
	bool retimed = false;
	bool touched_by_multiplier = false;
	int const_blackbox_inputs_inserted = 0;
};

struct MatchStats
{
	int exact_total = 0;
	int pi_cnt = 0;
	int po_cnt = 0;
	int dff_cnt = 0;
	int dff_po_cnt = 0;
	int subckt_cnt = 0;
	int unmatched_gold = 0;
	int unmatched_gate = 0;
	string match_file;
};

struct RunRecord
{
	string pair_id;
	string action;
	int exit_status = -1;
	int result_code = 0;
	double runtime_ms = 0;
	string log_file;
};

struct GuideSchedLinearAction
{
	double bias = 0;
	dict<string, double> weights;
};

struct GuideSchedTreeNode
{
	int feature_index = -1;
	double threshold = 0;
	int left = -1;
	int right = -1;
	double value = 0;
	bool is_leaf = false;
};

struct GuideSchedTree
{
	std::vector<GuideSchedTreeNode> nodes;
};

struct GuideMatchModel
{
	bool loaded = false;
	string path;
	string model_type;
	std::vector<string> feature_names;
	double base_score = 0;
	double learning_rate = 1.0;
	std::vector<GuideSchedTree> trees;
};

struct GuideSchedModel
{
	bool loaded = false;
	string path;
	string model_type;
	std::vector<string> feature_names;
	double base_score = 0;
	double learning_rate = 1.0;
	dict<string, GuideSchedLinearAction> linear_actions;
	std::vector<GuideSchedTree> trees;
};

struct FailurePacket
{
	string pair_id;
	string stage;
	string action;
	std::vector<string> clues;
	MatchStats match;
	int exit_status = -1;
	int result_code = 0;
	double runtime_ms = 0;
	string log_file;
	std::vector<string> recent_actions;
};

struct CommandResult
{
	int exit_status = -1;
	int result_code = 0;
	double runtime_ms = 0;
	string output;
	string log_file;
};

struct GuideTelemetry
{
	std::map<string, MatchStats> pair_match_stats;
	dict<string, int> pair_applied_match_suggestions;
	pool<RTLIL::IdString> retimed_mods;
	pool<RTLIL::IdString> multiplier_mods;
	Json::array match_suggestions;
};

struct CheckConfig
{
	bool nocleanup = false;
	std::string abc_exe_file;
	std::string tempdir_name;
	RTLIL::Design *design = nullptr;
	RTLIL::Module *gold_mod = nullptr;
	RTLIL::Module *gate_mod = nullptr;
	string gold_prefix;
	string gate_prefix;
	string lib_file;
	string sched_model_file;
	string match_model_file;
	string accept_match_suggestions_file;
	bool local_validate_support_slice = false;
	SeqCheckConfig seq_check_cfg;
	MlDumpConfig dump_cfg;
	GuideSchedModel *sched_model = nullptr;
	GuideMatchModel *match_model = nullptr;
	GuideTelemetry *telemetry = nullptr;
	RTLIL::Design *lib_design = nullptr;
};

struct ModMap {
	dict<RTLIL::IdString, RTLIL::IdString> mod_map_gold;
	dict<RTLIL::IdString, RTLIL::IdString> mod_map_gate;
	pool<RTLIL::IdString> mapped_mods_gold;
	pool<RTLIL::IdString> mapped_mods_gate;
	pool<RTLIL::IdString> unmapped_mods_gate;
	pool<RTLIL::IdString> unmapped_mods_gold;
};

struct MultiMapEntry {
	RTLIL::IdString gold_mod;
	RTLIL::IdString gate_mod;
	RTLIL::IdString gold_cell;
	RTLIL::IdString gate_cell;
	bool is_multi_mod;
};

using MultiMap = std::vector<MultiMapEntry>;

#define MATCHTYPE_FIELDS(X)       \
	X(NONE)                       \
	X(PO)                         \
	X(PI)                         \
	X(DFF)                        \
	X(DFF_PO)                     \
	X(SUBCKT_PIPO)

enum class MatchType {
#define DECL_FIELD(name) name,
	MATCHTYPE_FIELDS(DECL_FIELD)
#undef DECL_FIELD
};

enum class ActionKind {
	CEC_MAP,
	CEC_NOMAP,
	DSEC_MAP,
	DSEC_NOMAP
};

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

struct LocalValidateResult
{
	string pair_id;
	int selected_cutpoints = 0;
	int local_exact_total = 0;
	int child_boundary_count = 0;
	int unresolved_child_boundaries = 0;
	int boundary_map_expected = 0;
	int boundary_map_applied = 0;
	int constant_completed_net_count = 0;
	int unresolved_internal_boundaries = 0;
	int module_interface_input_count = 0;
	int state_cut_input_count = 0;
	int child_boundary_input_count = 0;
	int promoted_internal_boundary_count = 0;
	int unresolved_internal_input_count = 0;
	std::vector<string> promoted_internal_boundary_samples;
	std::vector<string> unresolved_internal_input_samples;
	bool ran = false;
	bool proved = false;
	bool residual_hierarchy = false;
	double runtime_ms = 0;
	string validator_backend = "local_abc";
	bool used_bmc_fallback = false;
	bool authoritative_ok = true;
	string unsafe_reason;
	string authoritative_reason;
	string fallback_reason;
};

struct ChildBoundaryPort
{
	RTLIL::IdString parent_mod;
	RTLIL::IdString child_cell;
	RTLIL::IdString child_mod;
	RTLIL::IdString port;
	RTLIL::IdString local_wire;
	int bit_index = 0;
};

struct RegionBoundary
{
	RTLIL::IdString parent_gold_mod;
	RTLIL::IdString parent_gate_mod;
	RTLIL::IdString gold_child_cell;
	RTLIL::IdString gate_child_cell;
	RTLIL::IdString gold_child_mod;
	RTLIL::IdString gate_child_mod;
	RTLIL::IdString gold_port;
	RTLIL::IdString gate_port;
	RTLIL::IdString gold_local_wire;
	RTLIL::IdString gate_local_wire;
	RTLIL::IdString canonical_wire;
	int bit_index = 0;
	string boundary_kind = "child_output";
};

struct PartitionedPair
{
	RTLIL::Module *gold_local = nullptr;
	RTLIL::Module *gate_local = nullptr;
	std::vector<RegionBoundary> boundaries;
	pool<string> boundary_bit_names;
	pool<string> promoted_internal_boundary_bit_names;
	pool<string> allowed_shell_input_bit_names;
	std::vector<string> promoted_internal_boundary_samples;
	std::vector<string> unresolved_internal_input_samples;
	int module_interface_input_count = 0;
	int state_cut_input_count = 0;
	int child_boundary_input_count = 0;
	int promoted_internal_boundary_count = 0;
	int unresolved_internal_input_count = 0;
	int unresolved_internal_boundaries = 0;
	bool residual_hierarchy = false;
};

struct RegionNode
{
	int region_id = -1;
	RTLIL::Module *gold_mod = nullptr;
	RTLIL::Module *gate_mod = nullptr;
	bool is_top = false;
	bool is_leaf = false;
	std::vector<CutPoint> state_cutpoints;
	std::vector<CutPoint> child_boundary_cps;
	std::vector<RegionBoundary> child_boundaries;
	std::vector<int> parent_region_ids;
	std::vector<int> child_region_ids;
	int unresolved_child_boundary_count = 0;
};

struct RegionProofResult
{
	int region_id = -1;
	bool shell_proved = false;
	bool children_discharged = false;
	bool obligation_discharged = false;
	bool proved = false;
	bool authoritative_ok = true;
	string backend;
	string unsafe_reason;
	string authoritative_reason;
	string fallback_reason;
	int selected_cutpoints = 0;
	int local_exact_total = 0;
	int child_boundary_count = 0;
	int unresolved_child_boundaries = 0;
	int boundary_map_expected = 0;
	int boundary_map_applied = 0;
	int constant_completed_net_count = 0;
	int unresolved_internal_boundaries = 0;
	int module_interface_input_count = 0;
	int state_cut_input_count = 0;
	int child_boundary_input_count = 0;
	int promoted_internal_boundary_count = 0;
	int unresolved_internal_input_count = 0;
	std::vector<string> promoted_internal_boundary_samples;
	std::vector<string> unresolved_internal_input_samples;
	bool residual_hierarchy = false;
	double runtime_ms = 0;
};

struct NamedSig {
	RTLIL::SigBit sig;
	MatchType type = MatchType::NONE;
	RTLIL::IdString wire_name;
	int bit_index = 0;
};

inline void print_timing_stat(const TimingStat &s)
{
	std::uint64_t t_total = 0;
	log("Timing Statistics:\n");
#define PRINT_FIELD(name) if (s.name) log("    %s: %.3lf s.\n", #name, s.name / 1000.0);
	TIMINGSTAT_FIELDS(PRINT_FIELD)
#undef PRINT_FIELD
#define ACC_FIELD(name) t_total += s.name;
	TIMINGSTAT_FIELDS(ACC_FIELD)
#undef ACC_FIELD
	log("    Total accounting time: %.3lf s.\n", t_total / 1000.0);
}

inline string get_match_type_str(const MatchType &t)
{
	switch (t) {
#define CASE(name) case MatchType::name: return #name;
		MATCHTYPE_FIELDS(CASE)
#undef CASE
	}
	log_abort();
}

inline string get_action_name(ActionKind action)
{
	switch (action) {
	case ActionKind::CEC_MAP:
		return "cec_map";
	case ActionKind::CEC_NOMAP:
		return "cec_nomap";
	case ActionKind::DSEC_MAP:
		return "dsec_map";
	case ActionKind::DSEC_NOMAP:
		return "dsec_nomap";
	}
	log_abort();
}

} // namespace guide_check
YOSYS_NAMESPACE_END

#endif
