#ifndef YOSYS_PASSES_GUIDE_CHECK_REGION_H
#define YOSYS_PASSES_GUIDE_CHECK_REGION_H

#include "passes/guide/check/shared.h"
#include "passes/guide/check/check.h"
#include "passes/guide/check/match.h"

YOSYS_NAMESPACE_BEGIN
namespace guide_check {

struct LocalBitOrigin
{
	string origin_kind;
	string source_id;
	string orig_mod;
	string orig_wire;
	int orig_bit_index = -1;
	string local_bit_name;
	bool came_from_state_cut = false;
	bool came_from_child_boundary = false;
	bool came_from_promoted_boundary = false;
	bool came_from_clone_wire = false;
	bool came_from_alias_or_slice = false;
};

struct LocalValidateResult
{
	string pair_id;
	int cut_cnt = 0;
	int exact_cnt = 0;
	int child_bnd_cnt = 0;
	int unr_child_bnd_cnt = 0;
	int bnd_map_exp = 0;
	int bnd_map_app = 0;
	int const_comp_net_cnt = 0;
	int unr_int_bnd_cnt = 0;
	int iface_in_cnt = 0;
	int state_in_cnt = 0;
	int child_in_cnt = 0;
	int alias_in_cnt = 0;
	int slice_res_cnt = 0;
	int trace_res_in_cnt = 0;
	int trace_prom_cnt = 0;
	int prom_int_bnd_cnt = 0;
	int unr_int_in_cnt = 0;
	int unr_untrace_in_cnt = 0;
	int const_comp_prom_cnt = 0;
	int const_comp_promoted_cnt = 0;
	int const_comp_trace_rem_cnt = 0;
	int const_comp_trace_cnt = 0;
	int const_comp_untrace_cnt = 0;
	int preblif_res_cnt = 0;
	int preblif_trace_cnt = 0;
	int preblif_prom_cnt = 0;
	int preblif_untrace_cnt = 0;
	int preblif_promoted_cnt = 0;
	int blif_res_cnt = 0;
	int blif_trace_cnt = 0;
	int blif_prom_cnt = 0;
	int blif_opaque_out_cnt = 0;
	int blif_lib_resolved_cnt = 0;
	int blif_untrace_cnt = 0;
	int blif_promoted_cnt = 0;
	std::vector<string> prom_int_bnd_samps;
	std::vector<string> unr_int_in_samps;
	std::vector<string> const_comp_prom_samps;
	std::vector<string> const_comp_rem_samps;
	std::vector<string> const_comp_samps;
	std::vector<string> preblif_res_samps;
	std::vector<string> preblif_prom_samps;
	std::vector<string> preblif_rem_samps;
	std::vector<string> blif_res_samps;
	std::vector<string> blif_prom_samps;
	std::vector<string> blif_rem_samps;
	int shell_refine_iter_cnt = 0;
	bool ran = false;
	bool proved = false;
	bool resid_hier = false;
	double runtime_ms = 0;
	string vali_backend = "local_abc";
	bool used_bmc_fb = false;
	bool auth_ok = true;
	string unsafe_why;
	string auth_why;
	string fb_why;
};

struct ChildBoundaryPort
{
	RTLIL::IdString parent_mod;
	RTLIL::IdString child_cell;
	RTLIL::IdString child_mod;
	RTLIL::IdString port;
	RTLIL::IdString local_wire;
	int width = 0;
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
	int width = 0;
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
	dict<string, LocalBitOrigin> gold_bit_origins;
	dict<string, LocalBitOrigin> gate_bit_origins;
	std::vector<string> prom_int_bnd_samps;
	std::vector<string> unr_int_in_samps;
	int iface_in_cnt = 0;
	int state_in_cnt = 0;
	int child_in_cnt = 0;
	int alias_in_cnt = 0;
	int slice_res_cnt = 0;
	int trace_res_in_cnt = 0;
	int trace_prom_cnt = 0;
	int prom_int_bnd_cnt = 0;
	int unr_int_in_cnt = 0;
	int unr_untrace_in_cnt = 0;
	int unr_int_bnd_cnt = 0;
	int const_comp_prom_cnt = 0;
	int const_comp_promoted_cnt = 0;
	int const_comp_trace_rem_cnt = 0;
	int const_comp_trace_cnt = 0;
	int const_comp_untrace_cnt = 0;
	int preblif_res_cnt = 0;
	int preblif_trace_cnt = 0;
	int preblif_prom_cnt = 0;
	int preblif_untrace_cnt = 0;
	int preblif_promoted_cnt = 0;
	int blif_res_cnt = 0;
	int blif_trace_cnt = 0;
	int blif_prom_cnt = 0;
	int blif_opaque_out_cnt = 0;
	int blif_lib_resolved_cnt = 0;
	int blif_untrace_cnt = 0;
	int blif_promoted_cnt = 0;
	std::vector<string> const_comp_prom_samps;
	std::vector<string> const_comp_rem_samps;
	std::vector<string> const_comp_samps;
	std::vector<string> preblif_res_samps;
	std::vector<string> preblif_prom_samps;
	std::vector<string> preblif_rem_samps;
	std::vector<string> blif_res_samps;
	std::vector<string> blif_prom_samps;
	std::vector<string> blif_rem_samps;
	int shell_refine_iter_cnt = 0;
	bool resid_hier = false;
};


std::vector<CutPoint> select_local_dff_cutpoints(const std::vector<CutPoint> &all_cps,
                                                 const CutPoint *extra_cand = nullptr);
std::vector<CutPoint> select_support_sliced_dff_cutpoints(RTLIL::Module *gold_mod,
                                                          RTLIL::Module *gate_mod,
                                                          const std::vector<CutPoint> &all_cps,
                                                          const CutPoint &candidate);
LocalValidateResult validate_partition_pair(const CheckConfig &conf, RTLIL::Module *gold_mod,
                                            RTLIL::Module *gate_mod, const std::vector<CutPoint> &cutpoints,
                                            bool allow_bmc_fallback = true);
void run_local_vali_shadow(const CheckConfig &conf, ModMap &mod_map,
                               const dict<RTLIL::Module*, std::vector<CutPoint>> &gold2cutpoints);

} // namespace guide_check
YOSYS_NAMESPACE_END

#endif
