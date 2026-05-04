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
	X(abc_comb_ms)                      \
	X(abc_seq_ms)                       \
	X(prep_ms)                          \
	X(dump_blif_ms)                     \
	X(dump_blif_prep_ms)                \
	X(dump_blif_write_ms)               \
	X(read_lib_ms)                      \
	X(hier_mod_map_ms)                  \
	X(signal_map_ms)                    \
	X(match_ms)                         \
	X(check_mul_ms)                     \
	X(mul_map_ms)                       \
	X(check_retime_ms)                  \
	X(region_dag_ms)                    \
	X(region_shell_ms)                  \
	X(region_shadow_ms)                 \
	X(region_fallback_ms)               \
	X(fail_emit_ms)                     \
	X(hint_gen_ms)

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
	bool mul_touched = false;
	int bb_const_in_cnt = 0;
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
	string proof_outcome;
	double runtime_ms = 0;
	string log_file;
};

struct CommandResult
{
	int exit_status = -1;
	int raw_result_code = 0;
	int result_code = 0;
	string proof_outcome;
	double runtime_ms = 0;
	string output;
	string log_file;
};


struct GuideTelemetry
{
	std::map<string, MatchStats> pair_match_stats;
	std::map<string, PairRecord> pair_records;
	dict<string, int> pair_applied_sugs;
	pool<RTLIL::IdString> retimed_mods;
	pool<RTLIL::IdString> multiplier_mods;
	Json::array match_suggestions;
};

struct GuideSchedModel;
struct GuideMatchModel;

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
	string accept_sugs_file;
	string external_match_file;
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
