# DGFlow 论文对齐基础与计算优化实施计划

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [x]`) syntax for tracking.

**Goal:** 按用户“取消本科范围、依论文优化”的新要求，完成可独立检验的密码后端优化和完整论文 CNN 训练基础。

**Architecture:** 继续使用现有已授权的系统与优化设计。密码接口保持不变；训练新增独立模块，不把尚未接通的大模型安全服务包装为完成。完整分块传输、紧凑证明、验证拓扑在对齐文档中明确设计与验收要求。

**Tech Stack:** Python、已安装 arkworks 0.5.0 绑定、PyTorch、pytest。

**Spec:** `docs/research/paper-alignment.md`；继承 `docs/superpowers/specs/2026-10-01-dgflow-system-design.md` 的密码与授权约束，用户本轮指示覆盖本科范围与规模目标。

## Global Constraints

- 保留 v1 交付包和冻结实验数据，不重写为新版本结果。
- 不更换密码群、放松输入校验、复用跨轮秘密或省略证明。
- 所有性能数字须来自真实测量，并区分微基准与端到端。
- 模型中的全部参数训练和导出；当前安全服务的 650 维边界明确披露。
- GPU 不可用时明确拒绝，不静默使用 CPU 冒充 CUDA。

## Tasks

- [x] 1. `tests/crypto/test_native_operations.py` 先验证新MSM等长、空输入与参考结果、恶意群点拒绝；实现 `crypto/backend.py` 与 `crypto/protocol.py` 的受检解析、原生MSM和公共常量优化，跑完整 crypto 测试。
- [x] 2. `tests/training/test_paper_models.py` 先失败再实现 `training/paper_models.py`：582026/878538参数、模型清单及hash、严格向量转换、实际SGD全层更新、设备与非法数据拒绝。
- [x] 3. 新增 `scripts/benchmark_crypto.py`，测量 DKG、证明生成/验证、内积、部分解密、合并，保存参数和源码摘要；在同一机器比较旧/新实现并检查相同整数输出。
- [x] 4. 独立代码审查、集成回归测试与研究说明，交付真实收益和未完成的大模型协议边界。

## Review Focus

旧版本的坏子群点、篡改证明、错误密钥、标签和维度仍应拒绝；MSM不得截断输入；缓存只存公共值且容量有界；模型向量严格匹配清单；计时数据不可把并发任务累计值称作总墙钟。

## 验收记录

全部四项本阶段任务已验收。全套测试 289 passed / 6 skipped；32、650 维各三次配对微基准完成，输出与源码摘要一致。独立审查修复优化模式误跳断言并补回归测试后无剩余必须修复项。完整大模型加密接入仍按对齐设计作为后续阶段，未标为本次完成。
