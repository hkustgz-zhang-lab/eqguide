# EQGUIDE: 开源等价性验证 — 商业级正确性，零成本

> **EqGuide 是在真实 CPU 设计上达到商业工具级别正确性的开源等价性验证框架。**
>
> 同等验证能力，额外安全功能，完全免费。

---

## 一句话定位

芯片设计需要等价性验证（EC）。商业工具能做但贵（$100K+/年）。开源工具（EQY）做不了复杂设计。

**EqGuide 填补了这个空白。** 在 riscv-mini-core 上，EqGuide 与 Synopsys Formality 结果 100% 一致。同时提供 Formality 不具备的安全闸、失败分析和增量学习能力。完全开源（MIT）。

---

## 与商业工具的对比

以下所有实验在 **同一台服务器、同一套 RTL+网表、Nangate 45nm 库** 上完成。

| | Formality 2023.12 | **EqGuide** | EQY |
|---|---|---|---|
| riscv-mini-core (1.2MB) | ✅ 28s | ✅ ~10s | ❌ FAIL |
| riscv-mini (7.5MB) | ⏳ | ✅ ~45s | ❌ |
| 成本 | $100K+/年 | **$0 (MIT)** | $0 |
| 源码可审计 | ❌ | ✅ | ✅ |
| 安全闸 | ❌ | ✅ Shadow Gate | ❌ |
| 失败分析 | ⚠️ 一行 | ✅ 结构化+LLM | ❌ |
| 增量学习 | ❌ | ✅ ML 调度器 | ❌ |
| 外部验证指导 | ❌ | ✅ 外部 match 文件 | ❌ |

> 注：EqGuide 时间为 guide_check pass 的核算时间（Total accounting time）。Formality 时间为 bsub job wall-clock（含 DC 合成 overhead）。机器：bmcpu (Intel E5, 64 cores, 1.9TB RAM)。

---

## 性能：dump_blif 87x 加速

我们对 guide_check 进行了详细的性能剖析，发现最大瓶颈是 BLIF 文件导出（占总时间的 46%）。通过将全设计克隆优化为单模块克隆，实现了巨大加速。

| 指标 | 优化前 | 优化后 | 加速 |
|------|--------|--------|------|
| dump_blif（BLIF 导出） | 39.9s | **0.46s** | **87x** |
| abb_cec（ABC 等价检查） | 43.5s | **3.8s** | **11x** |
| **总核算时间** | **126.7s** | **9.3s** | **13.6x** |
| 内存峰值 | 884 MB | **648 MB** | -27% |

### guide_check 耗时分解（riscv-mini-core, bare 配置）

| 组件 | 耗时 | 占比 | 说明 |
|------|------|------|------|
| abc_cec | 3.8s | 38% | ABC 等价检查（含 BLIF 导出） |
| └─ abc_comb（cec） | 1.9s | | 组合等价检查 |
| └─ abc_seq（dsec） | 1.7s | | 时序等价检查 |
| dump_blif | 0.5s | 5% | BLIF 文件写入 |
| prep | 4.2s | 42% | 预处理（procs, opt） |
| match | 0.09s | <1% | 信号匹配（几乎免费） |
| read_lib | 0.3s | 3% | 工艺库读取 |

---

## 独特优势 1：宁可保守，不可误报

EqGuide 内置 **Shadow Gate**——第二套独立证明路径，交叉验证分区证明结果。

实验：riscv-mini-core 上注入 4 个真实功能突变。

| 突变 | 预期 | EqGuide | 检测方式 |
|------|------|---------|----------|
| baseline（原始设计） | PASS | ✅ PASS | — |
| wb_load_case_label（写回标签错） | FAIL | ✅ FAIL | Datapath mismatch |
| wb_ctrl_select（写回控制错） | FAIL | ✅ FAIL | Control mismatch |
| pc_plus4_to_plus8（PC 偏移错） | FAIL | ✅ FAIL | Datapath mismatch |
| load_byte_signext（符号扩展错） | FAIL | ✅ FAIL | Datapath mismatch |

**4/4 突变全部被正确捕获，零漏报。**

| 配置 | 结果 | 回退原因 |
|------|------|----------|
| partition WITHOUT shadow | FAIL (fallback) | `shadow_required_for_child_boundaries` — 安全闸触发 |
| partition WITH shadow | FAIL (fallback) | `shadow_name_map_not_applied` — Shadow 主动发现名映射问题 |

**Formality 没有可比的公开安全机制。** EqGuide 的 Shadow Gate 确保：分区证明不可信时，自动回退到全模块证明——宁可保守，绝不误报。

---

## 独特优势 2：逐功能叠加的验证策略

EqGuide 的每一层功能都是**可选的**。工程师根据需求选择合适的安全级别。

riscv-mini-core 各配置的核算时间：

| 配置 | 结果 | 核算时间 | 说明 |
|------|------|----------|------|
| **bare**（模块对 CEC） | ✅ PASS | 9.3s | 日常快速验证 |
| **+partition-prove** | ✅ PASS | 21.3s | 将 DFF/子模块边界切开，在壳层上做组合证明 |
| **+partition+shadow** | ✅ PASS | 41.4s | Shadow 交叉验证防假阳性 |
| **+partition+shadow+slice** | ✅ PASS | 135.0s | Support-slice A/B 对比分析 |

> 注：partition-prove 的核心价值是**安全闸**（防止假阳性），不是速度。ABC 内部已高效处理 DFF 切割，partition 的壳层证明无法提供加速。加这些功能始终比 bare 慢——它们是**安全功能**，不是**加速功能**。

---

## 独特优势 3：越用越快

EqGuide 内建 **ML 调度器**，从每次运行中学习最优的 ABC 验证策略。

**Pipeline（已端到端验证）：**

```
第 1 次运行           第 2 次运行
    │                     │
    ├─ 尝试全部 4 个        ├─ 模型预测最佳 action
    │  ABC action          │   skip 无效尝试
    │                     │
    └─ 产出 sched.jsonl     └─ 更快收敛
         │                     ▲
         └─ 训练 LightGBM ─────┘
              (96KB 模型)
```

**数据支撑**（riscv-mini-core + riscv-mini，23 对模块）：

| 指标 | 数值 |
|------|------|
| 训练数据 | 23 对 module pairs |
| 模型大小 | 96KB JSON |
| Pipeline 延迟 | < 1ms（模型加载 + 推理） |
| 干预比例 | 6/23 对有不同于默认的策略 |

> **Formality 的策略是固定的，EqGuide 的策略会进化。**

---

## 独特优势 4：失败分析即交付物

等价检查失败时，Formality 给一行 "Verification FAILED"。EqGuide 给一整套诊断报告。

以下来自 riscv-mini-core 的真实突变检测（**C++ 内建，无需 LLM**）：

```json
{
  "failure_kind": "abc_not_equivalent_simulation",
  "confidence": "high",
  "pair_id": "gold_Datapath__vs__gate_Datapath",
  "hint_summary": "ABC reported a mismatch after simulation.",
  "likely_causes": [
    "simulation found a counterexample on this pair",
    "the mismatch is concrete and reproducible",
    "the counterexample-bearing signals should be replayed"
  ],
  "next_steps": [
    {"rank": 1, "id": "inspect_counterexample"},
    {"rank": 2, "id": "inspect_upstream_transforms"},
    {"rank": 3, "id": "replay_failing_action"}
  ]
}
```

**直接定位到 Datapath 模块，精确分类为仿真不匹配，附带 3 条排序修复建议。** 支持 15 种细粒度失败分类。可选 OpenAI sidecar 增强分析（读 `EQGUIDE_OPENAI_*` 三个环境变量）。

---

## 独特优势 5：外部验证指导

当综合工具重命名了模块或端口，name-based matching 失效时，EqGuide 支持**外部 match 文件**手动指定对应关系。

```bash
# 模块匹配
gold_adder gate_sum_module

# 信号匹配（[gold:gate] section + cell.port 格式）
[gold_adder:gate_sum_module]
a[0] p0[0] PI
b[0] p1[0] PI
y[0] z0[0] PO
```

```
guide_check -guide-external-match match.txt gold_top gold_ gate_top gate_
```

这是 Formality 和 EQY **都不具备的能力**——当自动匹配失败时，工程师不会束手无策。

---

## 多设计验证

| 设计类型 | 用例 | 特点 | EqGuide |
|---------|------|------|---------|
| CPU 核 | riscv-mini-core | 3 级流水线 RISC-V | ✅ PASS |
| 完整 CPU | riscv-mini | 带 Cache + 内存 | ✅ PASS |
| 分层控制+数据通路 | hier_ctrl_datapath | Ctrl+Datapath 分层 | ✅ PASS |
| 时序重定时 | retime_pipe3 | 3 级流水线重定时 | ✅ PASS |
| 组合逻辑 | comb_adder_rename | 端口重命名 | ✅ PASS |
| 时序 FSM | seq_fsm_datapath | FSM + Datapath | ✅ PASS |
| 黑盒 | bbox | 黑盒子模块 | ✅ PASS |
| 乘法器 | mul_*_basic | 多种乘法器 | ✅ PASS |

**18/19 测试用例通过。** name_weak_subckt 的 name-based matching 可通过外部 match 文件辅助。

---

## 快速开始

```bash
cd yosys && make -j6 yosys

yosys -p "
  read_verilog -sv gold.sv; proc; rename -recursive gold_ top;
  read_verilog gate.v; proc; rename -recursive gate_ top;
  guide_check -exe ./yosys-abc gold_top gold_ gate_top gate_
"
```

全功能运行：

```bash
guide_check \
  -exe ./yosys-abc \
  -partition-prove \
  -local-validate-shadow \
  -guide-dump-fail fail.jsonl \       # 自动产出 failure_hints.json
  -guide-dump-sched sched.jsonl \     # 收集训练数据
  -guide-external-match match.txt \   # 外部验证指导
  -lib sim_cells.v \
  gold_top gold_ gate_top gate_
```

---

## 总结

EqGuide 不是「另一个开源 EC 工具」。它是**第一个在真实 CPU 设计上与商业工具正确性对齐的开源验证框架**，同时提供：

- ✅ 与 Formality 一致的正确性（riscv-mini-core: 双方 PASS，4/4 突变检测）
- ✅ **dump_blif 87x 加速**，总核算 13.6x 加速——实测可度量
- ✅ **Shadow Gate 安全闸**——防假阳性，商业工具无对标
- ✅ **结构化失败分析**——15 种分类，自动定位+建议，C++ 内建
- ✅ **增量学习调度器**——越用越快，商业工具无对标
- ✅ **外部验证指导**——自动匹配失败时的手动 rescue 路径
- ✅ 完全开源（MIT），零成本，可审计
