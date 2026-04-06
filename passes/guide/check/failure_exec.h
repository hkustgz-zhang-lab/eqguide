#ifndef YOSYS_PASSES_GUIDE_CHECK_FAILURE_EXEC_H
#define YOSYS_PASSES_GUIDE_CHECK_FAILURE_EXEC_H

#include "passes/guide/check/shared.h"
#include "passes/guide/check/check.h"

YOSYS_NAMESPACE_BEGIN
namespace guide_check {

void append_jsonl(const string &path, const Json &json);
string make_command_log_file(const string &tempdir_name, const string &tag);
string resolve_yosys_smtbmc_executable();
std::vector<string> extract_failure_clues(const string &output);
string partition_unsafe_reason(const CommandResult &command_result);
CommandResult exec_capture(const string &cmd, const string &tempdir_name, const string &tag);
MatchStats get_match_stats(const CheckConfig &conf);
int typed_match_total(const MatchStats &stats);
bool module_has_submodule(RTLIL::Design *design, RTLIL::Module *mod);
bool module_has_dff(RTLIL::Module *mod, bool gate_side);
std::pair<string, std::vector<string>> failure_teacher(const std::vector<string> &clues);
Json string_array_to_json(const std::vector<string> &values);
void emit_failure_packet(const CheckConfig &conf, const string &stage, const string &action,
                         const CommandResult &command_result, const std::vector<RunRecord> &trace);
void emit_failure_packet(const MlDumpConfig &dump_cfg, const string &pair_id, const string &stage,
                         const string &action, const string &gold_mod, const string &gate_mod,
                         const CommandResult &command_result);
int exectue_and_check(const std::string &cmd, bool &correct, const std::string &target_output,
                      const string &tempdir_name = "", const string &tag = "command",
                      CommandResult *capture = nullptr);
int exectue_and_check(const std::string &cmd, int &result,
                      const std::vector<std::pair<std::string, int>> &target_result,
                      const string &tempdir_name = "", const string &tag = "command",
                      CommandResult *capture = nullptr);
int exec_cmd(const string &cmd, const string &tempdir_name = "",
             const string &tag = "command", CommandResult *capture = nullptr);

} // namespace guide_check
YOSYS_NAMESPACE_END

#endif
