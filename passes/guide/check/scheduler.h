#ifndef YOSYS_PASSES_GUIDE_CHECK_SCHEDULER_H
#define YOSYS_PASSES_GUIDE_CHECK_SCHEDULER_H

#include "passes/guide/check/shared.h"

YOSYS_NAMESPACE_BEGIN
namespace guide_check {

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

dict<string, double> scheduler_pair_features(const PairRecord &pair_record, const MatchStats &match_stats);
dict<string, double> scheduler_context_features(const string &action,
                                                const PairRecord &pair_record,
                                                const MatchStats &match_stats);
double tree_predict(const GuideSchedTree &tree, const std::vector<double> &features);
bool load_tree_model_common(const string &path, const string &expected_type,
                            GuideSchedModel *sched_model, GuideMatchModel *match_model);
bool load_sched_model(const string &path, GuideSchedModel &model);
bool load_match_model(const string &path, GuideMatchModel &model);
double predict_sched_cost(const GuideSchedModel &model, const string &action,
                          const PairRecord &pair_record, const MatchStats &match_stats);

} // namespace guide_check
YOSYS_NAMESPACE_END

#endif
