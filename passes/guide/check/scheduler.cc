#include "passes/guide/check/scheduler.h"

YOSYS_NAMESPACE_BEGIN
namespace guide_check {

dict<string, double> scheduler_pair_features(const PairRecord &pair_record, const MatchStats &match_stats)
{
    dict<string, double> features;
    features["has_dff"] = (pair_record.gold_dff_cnt != 0 || pair_record.gate_dff_cnt != 0) ? 1.0 : 0.0;
    features["gold_dff_cnt"] = pair_record.gold_dff_cnt;
    features["gate_dff_cnt"] = pair_record.gate_dff_cnt;
    features["has_submodule"] = pair_record.has_submodule ? 1.0 : 0.0;
    features["exact_total"] = match_stats.exact_total;
    features["pi_cnt"] = match_stats.pi_cnt;
    features["po_cnt"] = match_stats.po_cnt;
    features["dff_cnt"] = match_stats.dff_cnt;
    features["dff_po_cnt"] = match_stats.dff_po_cnt;
    features["subckt_cnt"] = match_stats.subckt_cnt;
    features["unmatched_gold"] = match_stats.unmatched_gold;
    features["unmatched_gate"] = match_stats.unmatched_gate;
    features["retimed"] = pair_record.retimed ? 1.0 : 0.0;
    features["touched_by_multiplier"] = pair_record.touched_by_multiplier ? 1.0 : 0.0;
    features["const_blackbox_inputs_inserted"] = pair_record.const_blackbox_inputs_inserted;
    return features;
}

dict<string, double> scheduler_context_features(const string &action,
                                                       const PairRecord &pair_record,
                                                       const MatchStats &match_stats)
{
    dict<string, double> features = scheduler_pair_features(pair_record, match_stats);
    features["act_cec_map"] = action == "cec_map" ? 1.0 : 0.0;
    features["act_cec_nomap"] = action == "cec_nomap" ? 1.0 : 0.0;
    features["act_dsec_map"] = action == "dsec_map" ? 1.0 : 0.0;
    features["act_dsec_nomap"] = action == "dsec_nomap" ? 1.0 : 0.0;
    features["is_dsec"] = (action == "dsec_map" || action == "dsec_nomap") ? 1.0 : 0.0;
    features["use_map"] = (action == "cec_map" || action == "dsec_map") ? 1.0 : 0.0;
    return features;
}

double tree_predict(const GuideSchedTree &tree, const std::vector<double> &features)
{
    int node_index = 0;
    while (node_index >= 0 && node_index < GetSize(tree.nodes)) {
        const auto &node = tree.nodes[node_index];
        if (node.is_leaf)
            return node.value;

        double feature_value = 0;
        if (node.feature_index >= 0 && node.feature_index < GetSize(features))
            feature_value = features[node.feature_index];
        node_index = feature_value <= node.threshold ? node.left : node.right;
    }
    return 0;
}

bool load_tree_model_common(const string &path, const string &expected_type,
                                   GuideSchedModel *sched_model, GuideMatchModel *match_model)
{
    std::ifstream handle(path);
    if (!handle.is_open())
        log_error("Cannot open model file %s.\n", path.c_str());

    std::stringstream buffer;
    buffer << handle.rdbuf();
    string error;
    Json json = Json::parse(buffer.str(), error);
    if (!error.empty())
        log_error("Cannot parse model file %s: %s\n", path.c_str(), error.c_str());

    string model_type = json["model_type"].string_value();
    if (model_type != expected_type)
        log_error("Unexpected model type in %s: got %s expected %s\n",
                  path.c_str(), model_type.c_str(), expected_type.c_str());

    std::vector<string> feature_names;
    for (auto &item : json["feature_names"].array_items())
        if (item.is_string())
            feature_names.push_back(item.string_value());

    std::vector<GuideSchedTree> trees;
    for (auto &tree_json : json["trees"].array_items()) {
        GuideSchedTree tree;
        for (auto &node_json : tree_json["nodes"].array_items()) {
            GuideSchedTreeNode node;
            node.feature_index = node_json["feature_index"].int_value();
            node.threshold = node_json["threshold"].number_value();
            node.left = node_json["left"].int_value();
            node.right = node_json["right"].int_value();
            node.value = node_json["value"].number_value();
            node.is_leaf = node_json["is_leaf"].bool_value();
            tree.nodes.push_back(node);
        }
        if (tree.nodes.empty())
            log_error("Model %s contains an empty tree.\n", path.c_str());
        trees.push_back(tree);
    }

    if (sched_model != nullptr) {
        *sched_model = GuideSchedModel();
        sched_model->path = path;
        sched_model->model_type = model_type;
        sched_model->feature_names = feature_names;
        sched_model->base_score = json["base_score"].number_value();
        sched_model->learning_rate = json["learning_rate"].number_value();
        sched_model->trees = trees;
        sched_model->loaded = true;
    }

    if (match_model != nullptr) {
        *match_model = GuideMatchModel();
        match_model->path = path;
        match_model->model_type = model_type;
        match_model->feature_names = feature_names;
        match_model->base_score = json["base_score"].number_value();
        match_model->learning_rate = json["learning_rate"].number_value();
        match_model->trees = trees;
        match_model->loaded = true;
    }

    return true;
}

bool load_sched_model(const string &path, GuideSchedModel &model)
{
    if (path.empty())
        return false;
    if (model.loaded && model.path == path)
        return true;

    if (model.model_type == "guide_sched_linear_v1") {
        std::ifstream handle(path);
        if (!handle.is_open())
            log_error("Cannot open scheduler model file %s.\n", path.c_str());
        std::stringstream buffer;
        buffer << handle.rdbuf();
        string error;
        Json json = Json::parse(buffer.str(), error);
        if (!error.empty())
            log_error("Cannot parse scheduler model file %s: %s\n", path.c_str(), error.c_str());

        model = GuideSchedModel();
        model.path = path;
        model.model_type = json["model_type"].string_value();
        model.base_score = json["base_score"].number_value();
        model.learning_rate = json["learning_rate"].number_value();
        for (auto &item : json["feature_names"].array_items())
            if (item.is_string())
                model.feature_names.push_back(item.string_value());
        for (auto &it : json["actions"].object_items()) {
            GuideSchedLinearAction action_model;
            action_model.bias = it.second["bias"].number_value();
            for (auto &weight : it.second["weights"].object_items())
                action_model.weights[weight.first] = weight.second.number_value();
            model.linear_actions[it.first] = action_model;
        }
    } else
    if (path.empty())
        return false;
    else
        load_tree_model_common(path, "guide_sched_gbdt_v1", &model, nullptr);

    model.loaded = true;
    return true;
}

bool load_match_model(const string &path, GuideMatchModel &model)
{
    if (path.empty())
        return false;
    if (model.loaded && model.path == path)
        return true;

    return load_tree_model_common(path, "guide_match_gbdt_v1", nullptr, &model);
}

double predict_sched_cost(const GuideSchedModel &model, const string &action,
                                 const PairRecord &pair_record, const MatchStats &match_stats)
{
    if (!model.loaded)
        return 0;

    if (model.model_type == "guide_sched_linear_v1") {
        if (!model.linear_actions.count(action))
            return 0;
        dict<string, double> features = scheduler_context_features(action, pair_record, match_stats);
        double cost = model.linear_actions.at(action).bias;
        for (auto &weight : model.linear_actions.at(action).weights)
            cost += weight.second * (features.count(weight.first) ? features.at(weight.first) : 0.0);
        return cost;
    }

    dict<string, double> features_by_name = scheduler_context_features(action, pair_record, match_stats);
    std::vector<double> features(GetSize(model.feature_names), 0.0);
    for (int i = 0; i < GetSize(model.feature_names); i++)
        if (features_by_name.count(model.feature_names[i]))
            features[i] = features_by_name.at(model.feature_names[i]);

    double cost = model.base_score;
    for (auto &tree : model.trees)
        cost += tree_predict(tree, features);
    return cost;
}

} // namespace guide_check
YOSYS_NAMESPACE_END
