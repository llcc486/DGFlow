# DGFlow 本科竞赛系统 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 在三台内网电脑上完成具有真实 DMAFE、输入证明、鲁棒筛选、门限聚合和现场展示能力的联邦学习软件。

**Architecture:** 客户端、密钥节点、验证节点、聚合节点分别作为独立进程运行，轮次控制服务管理任务而不持有主密钥。先单机验证协议，再接训练，最后通过同一套接口部署到三台主机。

**Tech Stack:** Python、PyTorch、经验证的 Charm 后端、FastAPI、HTTPX；前端采用 Vue 3 和本地打包的图表组件。SQLite 仅用于各服务的本地状态与去重，不共享同一个数据库文件。

**Spec:** [工程设计约定](../specs/2026-10-01-dgflow-system-design.md)。本文中的路径、接口和命令是拟实现的合同，当前尚不能执行；勾选框均不表示已完成。

## Global Constraints

- 三名本科生、三台 RTX 4060 级电脑；不以工期缩减真实密码步骤。
- 用户既定题目不改；依据论文重建的部分与学生自研的部分分别列清。
- 密码最小验收为 4 客户端、16 维、3 密钥节点、3 聚合节点；演示为 6 客户端、固定批次大小 2。
- 拟用密钥门限 2/3、聚合门限 2/3；真实 DKG，不设完整主密钥持有者。
- 初始训练采用 8×8 MNIST、650 参数线性分类器，全量参数走加密；等权平均。
- 上述设计约定中的 12 项协议硬约束全部适用。
- 协议关系、证明算法、整数界限未确定前，不把后续接口测试通过当成密码完成。

## Review Focus

- 同一轮重试改变明文而复用密钥/标签：Task 5 拒绝第二份提交，并禁止客户端在该标签下重加密不同模型。
- 正常客户端数据偏斜、全体都正常：Task 6 检测器不能因强制二聚类而无条件淘汰一簇。
- 负数、边界整数、零范数、模回绕：Task 2/3 覆盖整数解码与证明范围，Task 6 覆盖零范数。
- 密文集合分叉、旧轮次材料、门限不足和错误部分解密：Task 3/5 必须拒绝或中止，不显示成功。
- 同机角色与单主控的物理故障限制：Task 7 演示先明确故障对象，禁止将聚合进程容错写成任意整机容错。

## 文件与接口边界

```text
src/dgfl/
  common/contracts.py          # 配置、上下文、提交与公开结果类型
  crypto/backend.py            # 群元素、配对、合法编码与反序列化
  crypto/encoding.py           # 定点整数、范围和有界DLP
  crypto/dmafe.py              # 论文中的加密和两类功能解密
  crypto/dkg.py                # 每个参与者的分布式建钥状态
  crypto/proofs.py             # 经审阅的证明关系与算法
  training/data.py             # 固定数据划分与摘要
  training/model.py            # 参数顺序和训练/评测
  training/client.py           # 本地训练→加密提交
  validation/detector.py       # 仅使用允许统计量的筛选
  validation/batches.py        # 固定批次与批准清单
  services/authority.py        # 密钥节点与授权策略
  services/verifier.py         # 上传、验证、筛选
  services/aggregator.py       # 部分解密
  services/coordinator.py      # 任务状态、模型版本
  transport/client.py          # 身份校验、重试、传输
  storage/submissions.py       # 去重与持久状态
  experiments/runner.py        # 四模式和攻击场景
  experiments/metrics.py       # 公共指标与实测输出
  cli.py                      # 启动、诊断、实验、复位入口
web/src/                      # 四个展示页面
configs/                      # 单机、三机、实验配置
tests/                        # 密码、协议、通信、端到端检查
docs/protocol/                # 可核对的协议规格、参数与评审记录
```

在 `contracts.py` 统一定义 `RoundContext`（任务/轮次/客户端/密钥周期/模型摘要/量化版本/维度）、`QuantizationSpec`（尺度/舍入/整数界限/群阶）、`Submission`（上下文/密文/平方范数/证明/摘要）、`Manifest`（批准客户端/密文摘要/0或1权重/批次版本）、`PartialResult`（节点/清单摘要/部分解密）、`RunSummary`（配置摘要/结果路径/状态）。禁止不同模块分别定义不兼容字段。`RoundContext` 内的 client_id 用于身份及证明绑定，公共加密标签不含 client_id，保证同轮各客户端使用共同掩码底数。

## Task 1：协议可实现性与环境验证——甲主责，三人共审

**Files:** 创建 `docs/protocol/protocol-v1.md`、`docs/protocol/parameters-v1.json`、`docs/protocol/review.md`、`src/dgfl/crypto/backend.py`、`tests/crypto/test_backend.py`，锁定依赖与上游提交。

**Interfaces:** `validate_parameters(spec: dict) -> list[str]` 返回明确错误；群元素只经 `serialize_element(element) -> bytes` 和 `deserialize_element(payload: bytes, group_name: str)` 交换。

- [ ] 逐项展开论文的 GlobalSetup、AuthSetup、EKGen、VKGen、DKGen、Encrypt、VerDec、AggDec、AggComb，记录输入、输出、持有者和公式页码。
- [ ] 补齐 DKG 的私信/广播/投诉/中止条件，以及 NIZK 的确切协议来源、完整证明关系、实际密钥绑定、整数范围保证和 Fiat–Shamir 编码。把不能从论文确定的事项列成具体问题交老师审阅，并把最终答复落实为规格；不能以口头“应该可以”通过。
- [ ] 编写后端测试：配对双线性等式成立；合法元素序列化往返一致；错误群、非法长度、非法点或非子群元素被拒绝。
- [ ] 选择实际可运行的环境与群参数，运行 `python -m pytest tests/crypto/test_backend.py -q`；预期全部通过，保存依赖版本、平台和实测耗时。
- [ ] 完成协议审阅记录。若无法落实完整证明，Task 2 的计算实验及 Task 4/5 的骨架仍可推进，但 Task 3 的安全验收保持未通过。

**交付门槛：** 每个必要算法都有具体可编程规格；库安装成功不等于 DGFlow 实现成功。

## Task 2：编码与 DMAFE 小向量正确性——甲主责

**Files:** 创建 `common/contracts.py`、`crypto/encoding.py`、`crypto/dmafe.py`、`tests/crypto/test_encoding.py`、`tests/crypto/test_dmafe.py`、`configs/crypto-smoke.yaml`。

**Interfaces:** `quantize(values: list[float], spec: QuantizationSpec) -> list[int]`；`decode_bounded(element, lower: int, upper: int) -> int`；`encrypt(ctx: RoundContext, values: list[int], client_key) -> bytes`。验证、部分解密与合并的密钥类型须来自 Task 1 的协议规格，不让通用字典掩盖角色差别。

- [ ] 写明舍入规则和边界测试。用两个维度的已知向量 `[1,2]`、`[3,4]`、`[5,6]` 验证和为 `[9,12]`，参考向量 `[2,1]` 时内积依次为 `4,10,16`；再扩到 4 个客户端、16 维并包含负数与零。
- [ ] 从坐标上界 B、维度 d、最大参与数 N 推导平方和至多 dB²、同尺度参考内积绝对值至多 dB²、坐标聚合绝对值至多 NB，确保有唯一整数解释；不同尺度需重新推导。
- [ ] 运行相关测试确认尚未实现时失败，再实现真实群运算与有界 DLP；不通过保存明文的字典完成“解密”。
- [ ] 运行 `python -m pytest tests/crypto/test_encoding.py tests/crypto/test_dmafe.py -q`。预期授权结果与整数参考完全一致；超范围解码明确失败；不同标签、错误材料不产生一个被系统接受的结果。
- [ ] 测量实际最坏解码区间的时间和内存，确定后续量化尺度及模型维度。保留原始测量记录。

**交付门槛：** 精确整数正确性与可承受的解码成本同时满足；浮点误差另与量化明文基线比较。

## Task 3：真实 DKG、证明与门限闭环——甲主责，丙联调

**Files:** 创建 `crypto/dkg.py`、`crypto/proofs.py`、`tests/crypto/test_dkg.py`、`tests/crypto/test_proofs.py`、`tests/crypto/test_threshold.py`。

**Interfaces:** `prove_submission(ctx, values, client_key, ciphertext) -> bytes`；`verify_submission(submission: Submission, public_parameters) -> bool`；`partial_decrypt(manifest: Manifest, submissions: list[Submission], node_key) -> PartialResult`；`combine(manifest: Manifest, parts: list[PartialResult]) -> list[int]`。DKG 每个参与者拥有独立状态，消息类型采用 Task 1 的完整规格。

- [ ] 编写验证失败测试：改动一个密文、虚报平方范数、替换任务/轮次、越界整数、错误密钥关系，均不得导致错误模型获准。
- [ ] 按审阅的构造实现证明与范围/绑定检查；若所选构造不能覆盖某项，回到协议规格处理，不能删除该测试然后声称等效安全。
- [ ] 用独立进程完成 DKG 和份额发放；协调者只转发允许的消息。检查磁盘与日志中没有整份主密钥或其他节点私有份额。
- [ ] 验证 3 个聚合节点中的每个合法两节点组合均给出相同整数聚合；仅一份结果时中止；混合旧轮次或不同清单的部分结果被拒绝。
- [ ] 运行 `python -m pytest tests/crypto/test_dkg.py tests/crypto/test_proofs.py tests/crypto/test_threshold.py -q`；保存结果与协议配置。另注明是否实现恶意部分解密可验证性，未实现时只报告崩溃容错。

**交付门槛：** 小向量的建钥→加密→证明→验证→聚合全部真实执行。mock 仅可保留在测试夹具，不能进入演示配置。

## Task 4：明文训练与参数适配——乙主责，可与 Task 1–3 并行

**Files:** 创建 `training/data.py`、`training/model.py`、`training/client.py`、`tests/training/test_model_codec.py`、`tests/training/test_federated_round.py`、`configs/mnist-small.yaml`。

**Interfaces:** `train_local(model_bytes: bytes, client_id: str, config: dict) -> list[float]`；`evaluate(model_bytes: bytes, split_id: str) -> dict[str, float]`；`flatten_model(model) -> list[float]` 与 `restore_model(values: list[float])` 使用唯一固定次序。

- [ ] 固定 MNIST 数据来源、预处理、训练/测试划分与样本索引；训练样本划成 6 份，不把测试样本送入本地训练。
- [ ] 编写 650 参数展平/恢复完全一致测试，以及人工小模型等权平均正确性测试；先运行确认缺失实现时失败。
- [ ] 实现单机明文联邦学习，固定初始化与种子，记录每轮准确率、损失和本地训练时间；初始全局模型不能为导致参考范数为零的全零向量。
- [ ] 接入 Task 2/3 后，创建“量化明文参考”与“加密输出”对照；固定同一组本地模型输入，聚合整数逐坐标完全相等，不仅比较最终准确率。
- [ ] 运行 `python -m pytest tests/training -q`；再运行固定配置的真实训练，检查多轮能完成并产生有效指标。学习效果以实测为准，不预写准确率目标为既成事实。

**交付门槛：** 同一批本地模型通过密文链路得到与量化明文相同的聚合，且能连续更新模型。

## Task 5：服务、身份与可靠提交——丙主责，网络骨架可并行

**Files:** 创建 `services/authority.py`、`services/verifier.py`、`services/aggregator.py`、`services/coordinator.py`、`transport/client.py`、`storage/submissions.py`、`tests/transport/test_submission.py`、`tests/transport/test_authorization.py`、`tests/integration/test_network_round.py`。

**Interfaces:** `GET /health`；`GET /tasks/{task_id}/rounds/current`；`GET /models/{model_id}`；`POST /updates`；`GET /updates/{submission_id}`。角色专用消息依 Task 1 规格定义。`POST /updates` 成功接收返回 202 和 RECEIVED；异内容重复返回 409，未完成接收的文件不能进入验证队列。

- [ ] 统一消息版本、大小上限、摘要算法与上下文；实现节点证书认证、角色权限和安全二进制解析。独立密码工作进程处理耗时任务。
- [ ] 编写重复/重放测试：同一业务键同一内容只计一次；新编号相同内容仍只计一次；同一业务键不同内容拒绝；旧轮次拒绝；截止后返回明确状态。
- [ ] 实现上传临时文件、完整性校验、原子入库和查询后重试。重启后读取已持久化状态，不为同一轮重新生成一份不同本地模型并复用加密标签。
- [ ] 编写授权测试：陌生证书拒绝、客户端不能请求任意验证函数、冲突清单不能重复获准、非法角色不能取得他人密钥材料。
- [ ] 运行 `python -m pytest tests/transport tests/integration/test_network_round.py -q`；随后用真实 Task 3 后端完成一轮网络执行。HTTP 返回 202 仅证明已接收，界面必须继续显示验证进度。

**交付门槛：** 服务拆成进程后输出正确，认证、去重、恢复和轮次绑定实际生效。

## Task 6：鲁棒筛选与固定批次——乙主责，甲审查可见信息

**Files:** 创建 `validation/detector.py`、`validation/batches.py`、`tests/validation/test_detector.py`、`tests/validation/test_batches.py`、`configs/attacks.yaml`。

**Interfaces:** `score(inner_product: int, local_norm_squared: int, reference_norm_squared: int) -> float`；`select_candidates(scores: dict[str, float], policy: dict) -> set[str]`；`apply_fixed_batches(candidates: set[str], batches: list[list[str]]) -> set[str]`。

- [ ] 明确 k-means 的簇含义、最少样本量、分离阈值及全正常时处理；在开发划分上固定规则。论文未写全的工程决策要记录，不能假称原文原样提供。
- [ ] 写测试：全相同正常分数不被硬拆淘汰；零范数返回明确无效状态；非IID诚实差异单独统计；一名成员缺席时其固定批次整组不进入批准清单；全批次失败时本轮中止。
- [ ] 注入标签翻转和随机/方向反转更新；攻击身份仅写到离线评测真值文件，检测器不可读取。
- [ ] 运行 `python -m pytest tests/validation -q` 并用真实密码模式进行攻击与干净对照。记录检测命中、误拒和连带退出，不要求每次攻击都能识别。

**交付门槛：** 筛选只使用协议允许的信息，批准集合与所有节点的聚合授权一致。

## Task 7：三机部署与四页界面——丙主责

**Files:** 创建 `configs/hosts.example.yaml`、`configs/demo.yaml`、`cli.py`、`web/src/pages/Task.vue`、`Nodes.vue`、`Validation.vue`、`Results.vue`、`docs/deployment.md`、`tests/integration/test_demo.py`。

**Interfaces:** `python -m dgfl.cli doctor --config configs/demo.yaml` 检查环境/证书/数据/端口；`python -m dgfl.cli node --config configs/demo.yaml --host A` 启动本机角色；`python -m dgfl.cli run --config configs/demo.yaml` 创建演示任务。命令均须由本任务实现。

另外实现 `python -m dgfl.cli stop --config configs/demo.yaml --host A` 只停止本项目记录的本机进程；`python -m dgfl.cli reset --config configs/demo.yaml` 归档现有运行并创建新的 task_id 和密钥周期，保留历史实验文件，不复用旧标签从头训练。

- [ ] 按设计表分配角色；每个节点只配置所需证书和私有目录。三机地址写配置，不硬编码在源码。
- [ ] 逐机验证 HTTPS /health；WSL2 环境单独验证跨机网络，按实际模式设置指定端口规则，不关闭整机防火墙。
- [ ] 四页只展示真实任务状态、在线节点、模型指标、验证/剔除理由和对照数据；历史曲线标明运行编号，不自动伪装成现场进度。
- [ ] 验收：正常训练完成；重复上传不重复计入；篡改证明被拒；停止一个聚合进程后有合法两份结果则继续；不足门限中止；客户端掉线按固定批次策略处理。
- [ ] 断开外网但保留局域网，重新启动并完成演示。字体、前端脚本、依赖、数据均可本地访问。

**交付门槛：** 一台电脑打开界面可观察真实三机执行。需保存三机运行配置、日志摘要与现场记录；单机测试不能代替此项。

## Task 8：工程优化与实验证据——乙统筹，甲/丙实现优化

**Files:** 创建 `experiments/runner.py`、`experiments/metrics.py`、`configs/experiments.yaml`、`tests/experiments/test_metric_contract.py`、`docs/results.md`，输出 `results/<run_id>/config.json`、`metrics.csv`、`events.jsonl`。

**Interfaces:** `run_experiment(config: dict) -> RunSummary`；`python -m dgfl.cli experiment --config configs/experiments.yaml`；配置必须含 mode、seed、partition_id、attack、crypto_parameter_id、quantization_id、commit_id。

- [ ] 实现 A 明文、B 加密无投毒筛选、C 论文重建、D 工程优化四模式，记录 B 的具体关闭项。加一条量化明文参考用以定位数值误差。
- [ ] 测量训练、建钥、加密、证明、验证、传输、聚合、DLP 各阶段，先找瓶颈再优化；并行密码任务、公共预计算和序列化优化分别启用，以便归因。
- [ ] 写测试保证计时单位、字节数和轮次状态正确，C/D 使用完全相同的模型与密码配置；不按测试结果筛掉不利的随机种子。
- [ ] 主要干净/攻击对照至少 3 个固定种子，正式报告建议 5 个。IID与非IID分开，攻击比例和故障比例分开扫描，保留每次原始结果。
- [ ] 对比 C/D 输出一致性、总耗时、传输量和故障恢复。把预计算成本、启动成本与稳态成本分别报告，失败/中止也统计。

**交付门槛：** 每个优势结论都有本机实测文件；无改善的项目不写成创新收益。

## Task 9：比赛材料与可重复演示——三人共同负责

**Files:** 创建 `README.md`、`docs/user-manual.md`、`docs/demo-script.md`、`docs/design-report.md`、`THIRD_PARTY_NOTICES.md`、`scripts/package_submission.py`。

**Interfaces:** `python scripts/package_submission.py --output dist/submission` 仅打包明确白名单文件，检查体积并列出清单；不得打包密钥、真实本地数据或非匿名开发信息。

- [ ] 设计报告按截图要求覆盖摘要、方案、功能、技术指标、原理、软件流程、测试与结论，数值从冻结实验文件读取。
- [ ] 用对照表解释“论文方法 / 开源底座 / 学生实现 / 学生改进”，列出依赖许可证与实际使用方式。
- [ ] 准备现场步骤：正常轮次→篡改证明→投毒对照→一个聚合进程停止→复位。每一步写清可观察结果，不预写所有攻击必定成功拦截。
- [ ] 在另一台干净环境按手册安装或用准备好的离线环境恢复，跑起小规模完整例子；依赖问题修复后再生成提交包。
- [ ] 检查匿名设计报告/支持材料、独立审批页、编号命名与 4GB 限制。清理导出文件中的用户名、绝对开发路径等身份信息。

**最终验收：** 三机真实运行、关键负面测试通过、可核对实验数据、完整源代码与手册、可现场复位。提交作品完成与获奖是不同结果，不作奖项保证。

## 建议立即执行的第一项

三人共读设计约定并固定公共字段。甲完成 Task 1 的协议表与 16 维密码实验准备，乙运行小模型明文基线，丙完成独立进程健康检查与一次文件提交。第一轮联合验收的核心产物应是“真实加密聚合与已知整数答案一致”，随后逐项加入证明、训练和三机展示。
