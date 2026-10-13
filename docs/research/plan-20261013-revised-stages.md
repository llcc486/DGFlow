# DGFlow 分层改进方案（修订版执行规格）

本文件是对外部方案的修订版本，作为后续实施的执行规格。修订依据是对本检出的独立复核：读源码、实跑测试，并对身份、检查点、CRS、筛选四条线做交叉核对。

**基线（A0 开工前实测）**：`python -m pytest -q` = 3523 passed, 29 skipped, 0 failed；`git status` 干净；HEAD = `bfbeb46 多机部署实现`。

---

## 0. 与原方案的差异

原方案的诊断约八成准确，处方方向正确。本修订版做了六处改动，其中两处是必须的：

| # | 原方案说法 | 修订后的做法 | 原因 |
|---|---|---|---|
| 1 | `protocol_version` 进入消息、上下文和授权关系 | `protocol_version` **只进入信封头/握手，不进入 `ctx`** | `ctx` 经 `b.digest(ctx)` 进入 `context_hash`（`runner.py:845`、`:1169`）并被证明挑战绑定（`lego.py:84-90`）。写入 `ctx` 会使全部历史证据的 `context_hash` 失去可比性，直接违反"历史实验按原有语义读取" |
| 2 | 修改 `setup_kind` 字符串即可在参数来源之间转换 | 真实漏洞是 **`manifest.json` 完全未认证**，且 `created_at` 不被指纹覆盖 | `lego_registry.py:68-74` 只接受 `'single_party_development'` 一个值；`set(value) != _FIELDS`（`:69`）连添加来源字段都会拒绝。`_fingerprint` 只哈希 `{protocol, circuit, dimension, bits, verifying_key}`（`:88-90`） |
| 3 | 恢复"第一版采用完整全局轮次粒度"（表述为简化选择） | 明确写成 **唯一可行选项**：恢复必然从轮次边界开始并重跑 DKG | DKG 份额设计上不可持久化（`protocol.py:191-192`、`:261-262`），重启后 `reuse` 必为假（`roles.py:750`）并抛 `:755-756`。原地续跑在原理上不可能 |
| 4 | 阈值"冻结到任务策略中" | 把聚类常数从代码**移入配置**，使其进入 `manifest_hash` | `0.45 / 0.25 / 32 / 1e-12` 目前硬编码在 `policy.py:120,122,129,133`，不在 `SCREENING_DEFAULTS`，因此不在 `roles.py:713` 序列化的授权清单里。"冻结"若只写在文档里，换掉整个 `select()` 而保持 5 个配置键不变时摘要不变 |
| 5 | 第 6 条未提"改常数会使已有验收失效" | 第 6 条增加硬性要求：**常数变更即宣告历史攻击/防御结论不适用于新规则** | 与项目既有证据纪律一致（`design-report.md:166` 保留休眠导致的异常运行并声明不用于性能结论） |
| 6 | 第 1 条把"建立基线"当作需要新建的能力 | 改为 **把已有 `implementation_evidence()` 接到交付物上并加门禁**，同时新增 A0 阶段修复当前正在阻塞交付的事故 | `implementation_evidence()`（`runner.py:260-301`）已经产出源码逐文件摘要、依赖版本、原生产物摘要，并明确定义了 `evidence_scope` |

另外补两条原方案缺失的验收：

- **诚实 Non-IID 误排率单列**。第 6 条实验矩阵含 `IID/Non-IID`，但验收门槛只写"干净实验准确率下降 ≤ 2 个百分点"。CIFAR-10 的实测失败正是诚实 Non-IID 形成低相似度簇（`attack-defense.md:83`：round-2 `low center ≈ 0.434`、`gap ≈ 0.439`，两个条件都不满足因而筛选未生效）。只测干净 IID 会漏掉这个模式。
- **目录 fsync**。第 4 条要求"持久化刷新和原子替换"。项目已有正确实现可复用：`evidence._atomic_text`（`evidence.py:143-159`）做了 `os.fsync` + `os.replace`；而角色状态走的 `atomic_json`（`security.py:159-161` → `_115-124`）**没有 fsync**。补充：`os.replace` 之后需对父目录做一次 fsync，否则重命名本身在断电后不保证可见。

---

## A0. 交付链路修复（新增，与 A 并列优先）

原方案未覆盖，但这是当前唯一在阻塞实际交付的一组问题。A0 也服务于 A 的目标：基线要"可对照"，而指纹脱钩说明对照机制尚未接通。

| 任务 | 交付 | 验收 |
|---|---|---|
| A0.1 | 修 `package_submission.py` 的绝对路径检查误报（测试夹具 `C:/runtime` 被当成开发路径） | 真实检出上 `python scripts/package_submission.py --output dist/submission` 退出 0 |
| A0.1b | 真实检出打包 smoke 测试 | 合成夹具无法发现"守卫拒绝真实树"这类回归 |
| A0.2 | `freeze_source.py` 增加机器身份内容扫描 + 清理已泄漏的主机名/用户名/个人路径 | 交付树扫描无命中；无法按 UTF-8 解码的文本文件失败；已知二进制格式记录后放行 |
| A0.3 | 版本边界：逐文件对照冻结验收记录与实际源码 | 每条冻结记录标明是否适用于当前检出；不再把旧结果当作当前证据 |
| A0.4 | 故障用例命名对齐（`run_fault_checks` v2 ↔ `build_report` 标签表） | 新故障证据可生成 `design-report.pdf`；未登记用例报错并给出用例名 |
| A0.5 | CI：把 `test_configurable_batches.py` 纳入 `native-lego` 清单 | σ=3 主张在 CI 中真正执行，而不是被 `importorskip` 跳过 |
| A0.6 | CI：新增真实检出打包与身份扫描门禁 | 打包回归与身份泄漏无法再进入主干 |

---

## A. 版本基线、材料分级、导出隔离

**实施状态（2026-10-13）**

| 项 | 状态 | 落点 |
|---|---|---|
| `protocol_version` 只进 RPC 消息与 `health`，不进 `ctx` | 已完成 | `src/dgfl/versioning.py`、`transport/client.py`、`services/node.py` |
| 训练前版本核对，混用报明确错误 | 已完成 | `experiments/runner.py:require_participant_versions` |
| 版本编号统一（记录/检查点/身份登记/筛选） | 已完成 | `versioning.version_declaration()` |
| 历史记录走显式解析分支 | 已完成 | `verification_materials.is_legacy_combined` / `split_legacy_combined` / `accepts_record` |
| 材料分成可分享层与受限层 | 已完成 | `build` / `build_restricted`（`verification_materials.py`） |
| 受限材料独立开关、独立目录、属主权限 | 已完成 | `RESTRICTED_ENVIRONMENT_FLAG`、`write_restricted`、`roles._write_restricted_material` |
| 导出白名单 | 已完成 | `control.export_view` 与三张字段表 |
| CLI 分开"证明复核"与"授权内积复核" | 已完成 | `verify-proof`、`verify-authorization`、`--restricted-dir` |
| 无函数钥时显示"内积未复核"，不计为通过 | 已完成 | `authorization_not_verified` |
| 材料真实性核对（不止文件摘要） | 已完成 | `src/dgfl/material_authenticity.py`、`verify-material-origin` |

**版本字段的落点（`src/dgfl/versioning.py`）**：`PROTOCOL_VERSION`（RPC 消息与 `health` 声明）、`RECORD_SCHEMA_VERSION`、`CHECKPOINT_SCHEMA_VERSION`、`IDENTITY_REGISTRY_VERSION`、`SCREENING_VERSION`。检查点格式不使用独立版本号，改用检查点自摘要——摘要覆盖格式与内容，严格强于版本号，少一个需要同步维护的字段。

**版本核对的两档语义**：声明了但本实现无法解释的版本**一律拒绝**；**未声明**版本只记录并报告（`evidence.protocol_version_undeclared`），仅在 `strict` 下拒绝。二者是不同的事实：前者是已知不兼容，后者无法与"早于该字段的构建"区分。本项目的角色服务始终声明版本，因此真实部署总是被完整核对；`strict` 供已升级全部机器的运维者启用更强规则。

**材料分级**：`build()` 只产出可分享的证明材料（密文、证明、注册密钥行、参考与上下文）；`build_restricted()` 只产出验证函数钥，并用 `proof_material_digest` 绑定到对应的证明材料，因此离线核对不会把两轮的半份材料拼在一起。受限材料写入 `nodes/<id>/restricted-materials/`（与实验记录不在同一棵树），默认不落盘，启用时以属主权限创建后再写入字节。

**真实性核对的内容**：受信身份登记（`runtime/keys/registry.json`，不采信材料自带的身份声明）、实验上下文与拓扑（读者固定值）、参考模型与上下文摘要的绑定、材料轮次与上下文轮次、证明方案、注册密钥行的群元素合法性、客户端标识与所在条目一致、DKG 转录摘要（读者提供时精确比对）。**无法执行的检查记录为"未核对"，绝不计为通过。**

**尚未完成（本阶段后续）**：受限材料在 Windows/Linux 上的平台权限检查（当前用创建时 mode，Windows 上仅为建议值）；离线核对对客户端签名的直接验证（材料层目前不含客户端签名，绑定由注册密钥行与证明联动承担，需在第 9 阶段随完整证明关系规格一并设计）。

1. **版本字段**：`protocol_version`（信封头/握手）、`record_schema_version`（统一现有散落值：`verification_materials.SCHEMA_VERSION`、`protocol_evidence.schema_version`、`telemetry`）、`screening_version`、`identity_registry_version`。检查点格式用**检查点自摘要**替代独立版本号（摘要覆盖格式与内容，严格强于版本号）。
2. **老记录解析分支**：缺字段时走明确的历史分支；新任务要求所有参与节点支持所需版本。版本协商复用既有 `health` 能力集（`runner.py:493-494`、`control.py:433`）与 `require_client_training_backend`（`runner.py:217`）的预检位置，不新增独立协商协议。
3. **材料分级**：`verification_materials.build` 现在把 `validation_keys`（函数钥）与公开材料写进同一文档（`verification_materials.py:102-111`），而模块 docstring 自称全部公开（`:11-18`），二者矛盾。拆成：
   - 可分享证明材料：密文、证明、公开承诺、上下文、可信参数标识、来源签名；
   - 受限功能解密材料：验证函数钥及其相关信息。
4. **导出白名单**：`GET /api/runs/{run_id}/export`（`control.py:740-744`）目前整体返回记录。加字段白名单。受限材料不进实验下载包、源码包、离线包（当前靠 `package_submission.py:56` 的 `EXCLUDED_DIRECTORIES` 含 `runtime` 而"碰巧"不泄漏，需改为设计上不泄漏）。
5. **受限材料本地保护**：默认不持久化；启用后在归属边缘用受保护本地存储 + 文件访问控制；保护密钥不与材料一起导出；Windows 与 Linux 分别实现权限检查。
6. **CLI 拆分**：`verify-submission` 拆为"证明复核"与"授权内积复核"；无函数钥时显示"内积未复核"，不计为通过。
7. **材料真实性**：现有 `load` 只比对 sidecar 的 sha256（`verification_materials.py:206-210`），只能证明文件未变。新增离线必须核对受信身份登记、客户端签名、DKG 转录或其认证引用、实验上下文；不接受材料文件自带的公钥与身份声明。CLI 已有正确先例可推广：`cli.py:191-194` 明确"验证方从已安装可信设置取参数，材料不能替换自己的验证密钥"。

**验收**：公开导出中无函数钥与身份私钥；篡改来源、参考模型、客户端标识、上下文均被拒绝；历史含函数钥材料识别为受限格式，不静默当公开材料处理；旧实验可查看、导出；版本混用在训练前报明确错误。

---

## B. 检查点、轮次提交、恢复

**实施状态（2026-10-13）**

| 项 | 状态 | 落点 |
|---|---|---|
| 每轮检查点（全局轮次、量化全局模型及摘要、计划、版本） | 已完成 | `src/dgfl/experiments/checkpoint.py` |
| 检查点链（每份记录前序摘要，可验链） | 已完成 | `checkpoint.verify_chain` |
| 提交证书（哪些边缘确认、模型是否一致、所确认检查点摘要） | 已完成 | `checkpoint.commit_certificate` / `write_certificate` |
| 轮次结束的明确转换顺序 | 已完成 | `runner._commit_round_checkpoint`（行写入 → 检查点落盘 → 证书 → 再发布） |
| 文件写入：临时文件 + 完整性 + fsync（文件与父目录）+ 原子替换 | 已完成 | `checkpoint.write` / `write_certificate` |
| 恢复字段（`logical_experiment_id`、`parent_run_id`、`start_round`、`execution_attempt_id`、`key_epoch`） | 已完成 | `runner.start` |
| 恢复创建新执行、旧执行终止并隔离、幂等标识 | 已完成 | `runner.resume` |
| 三个接口 | 已完成 | `GET /runs/{id}/checkpoints`、`GET /runs/{id}/recovery`、`POST /runs/{id}/resume` |
| 看板"从第 N 轮继续" | 已完成 | `web/src/components/RecoveryPanel.vue` |
| CLI `dgflow resume`（含 `--check`） | 已完成 | `src/dgfl/cli.py` |
| 确定性恢复（连续训练与恢复后模型一致） | 已完成并有测试 | `tests/experiments/test_checkpoint_recovery.py` |

**与方案的一处差异**：原方案把"完整全局轮次粒度"表述为第一版的简化选择。实际这是**唯一可行选项**：DKG 份额在 finalize 后即被拒绝并擦除（`protocol.py:191-192`、`:261-262`），重启的边缘无法复用旧周期（`roles.py:750`），因此恢复必然从轮次边界开始并在新周期上重跑 DKG。`resume_plan` 直接把这一点作为 `key_epoch_reason` 报告，而不是留给读者推断。

**与方案的另一处差异**：方案建议新增 `checkpoint_schema_version`。实际改为**检查点自摘要**（`model_sha256` 与整份检查点摘要）：摘要在任何时候都可用，且不会随实现更新而失效；独立版本号需要与摘要同步维护，收益为负。版本信息仍然记录在检查点的 `versions` 字段中，覆盖实现、协议、记录格式、检查点格式与筛选版本。

**已复用而非重建**：每个归属边缘原有的 `task-state.json`（`roles.py:999-1001`）继续承担它已有的职责——下一轮号与期望模型，并在下一轮 `begin` 时拒绝轮次/模型分叉（`roles.py:762-763`）。新增的检查点是**主控侧**的持久化全局状态与提交证书，两者互补而不是重复。

**尚未完成（本阶段后续）**：转换点的崩溃注入测试（在每个转换点强制结束进程，验证不出现"界面显示完成但模型未保存"、重复发布或不同节点接受不同模型）；提交证书中边缘签名目前复用既有的签名的确认行，尚未独立签名检查点摘要，需在第 9 阶段随完整证明关系规格一并设计。

**现状（已核实）**：不存在完整轮次检查点与恢复。`runner.py:823` 的 `epoch` 在轮循环之外；`finish` 只写目标态 `task_state`（`roles.py:999-1001`）；全仓唯一 `fsync` 在 `evidence.py:156`，与角色状态无关。

**已有可复用基础（勿重建）**：每个归属边缘已有 `task-state.json`，在 `finish` 中持久化 `{next_round, reference, mode, policy, status}`（`roles.py:999-1001`），并在下一轮 `begin` 校验轮次连续、模型一致、模式一致，不一致即抛 `'round/model fork rejected'`（`roles.py:762-763`）。防分叉的雏形已存在。

**要补的**：

1. 检查点内容：已完成全局轮次 + 全局量化模型及摘要；模型描述、数据划分摘要、种子、训练配置；固定批次、客户端归属、筛选策略与门限；授权清单摘要、上一检查点摘要；边缘确认签名及协议、实现版本。
2. 检查点**不保存**客户端原始模型、DKG 秘密份额、证明随机数。
3. 轮次结束拆成明确转换：聚合核验完成 → 各边缘持久化准备记录并签名 → 收集一致确认形成提交证书 → 持久化检查点与提交证书 → 发布"本轮完成" → 开始下一轮。第一版维持全边缘确认要求。
4. 写入用临时文件 + 完整性校验 + **fsync（含父目录）** + 原子替换，覆盖磁盘满、文件占用、中途退出。复用 `evidence._atomic_text` 的模式，补齐 `atomic_json` 缺失的 fsync。
5. 恢复必然重跑 DKG 并生成新密钥周期；旧 epoch 哨兵不删除、不复用，防止旧执行迟到消息被接受。

**验收**：在每个转换点强制结束进程，均不出现"界面显示完成但模型未保存"、重复发布、不同节点接受不同模型。

---

## C. 多机本地身份生成与登记

**实施状态（2026-10-13）：已完成全部本机可验证项；真实多机验收未做。**

| 项 | 状态 | 落点 |
|---|---|---|
| 每台机器生成本机签名/密钥交换/TLS 私钥 | 已完成 | `src/dgfl/registration.py:create_local_identity` |
| 登记请求只含公钥、CSR、节点编号、角色与地址 | 已完成 | `build_request` |
| 请求绑定部署标识、有效期、一次性挑战 | 已完成 | `verify_request`（缺一项即拒绝并指出字段） |
| 密钥持有证明（请求自签名） | 已完成 | `_sign_request` + `verify_request` 中的 Ed25519 校验 |
| 一次性挑战的消费账本（真正的重放拒绝） | 已完成 | `consume_challenge`（fsync + 原子替换）+ `ledger_summary` |
| 管理端核对预定拓扑后签发公共登记材料 | 已完成 | `issue`、`registry_from_entries`、`verify_registry` |
| 各机器导入后、启动前核对本机私钥与登记公钥 | 已完成 | `install`、`check_local_identity`、CLI `register-check` |
| 签发环境与日常控制服务分离，CA 不进出普通运行目录 | 已完成 | `create_authority` 要求显式独立路径；平台运行目录实测不含任何节点私钥与 CA 私钥 |
| 独立身份登记版本 | 已完成 | `identity_registry_version` 写入请求、条目与登记表 |
| 部署记录标注信任环境 | 已完成 | `identity_scheme` + `trust_environment`；历史记录按本地集中路径读取 |
| 单机演示标为"单机模拟信任环境" | 已完成 | `init_cluster` 写入，`register-status` 与页面显示 |
| CLI：本机生成、平台签发、启动前核对、状态 | 已完成 | `identity-init`、`register-accept`、`register-check`、`register-status` |
| 多机页面"待登记／已登记／可启动" | 已完成 | `GET /api/registration/status` + `web/src/components/RegistrationPanel.vue` |
| 已有部署继续可用、新身份体系独立版本 | 已完成 | 无 `identity_scheme` 的历史记录按本地集中路径读取，旧目录不迁移 |
| 真实两机或三机认证通信 | **未做** | 需现场验收，不能用本机多地址模拟代替 |

**已核实的现状**：`create_cluster`（`security.py:164-206`）在一台机器上为**所有**节点生成 Ed25519/X25519/P-256 私钥，再由 `bundle_cluster`（`deployment.py:764-820`）按机器分包；控制运行目录因此持有全部机器私钥。CA 私钥从不落盘（`security.py:205`），所以无法单独补发叶子证书，扩容时整体轮换（`security.py:209-246`）。本阶段的登记路径替代的正是这些机制；已有的本地集中路径保留为历史方案，并在部署记录中标注。

**三态的语义（实现中明确区分）**：`pending` 表示平台尚未接受请求；`registered` 表示平台已签发材料；`startable` 表示材料已安装在本机。前两者是平台的事实，第三者是**某台机器**的事实，因此 `pending_registration(machine=...)` 按机器读取，页面不会替另一台机器宣称已就绪。

**实测的负测与性质（`tests/integration/test_registration_onboarding.py`，16 项）**：三机分别生成并登记后全部可启动；平台运行目录逐字节检查不含任何节点私钥与 CA 私钥；同一请求在有效期内重放被账本拒绝；跨部署请求、冒领他机地址、拓扑外节点、把他人签发的材料装到本机、篡改已安装登记表均被拒绝；单机模拟信任环境与历史记录仍可读取。

**验收**：控制运行目录不持有其他机器的身份私钥（已逐字节实测）；冒领节点、替换公钥、错误证书地址、过期登记均被拒绝；**验收**：控制运行目录不持有其他机器的身份私钥；冒领节点、替换公钥、错误证书地址、过期登记均被拒绝；真实两机或三机完成认证通信（`deployment.md:234` 的 `127.0.0.2/.3/.4` 单机多地址验证不算，需现场验收并单独列状态）。

---

## D. 筛选版本化与可解释决策

**实施状态（2026-10-13）：本机可验证项已完成；标定与验证实验未做。**

| 项 | 状态 | 落点 |
|---|---|---|
| 现有规则保留为 `legacy_v1` | 已完成 | `policy.SCREENING_RULE_LEGACY_V1`；`select()` 语义逐字保持 |
| 聚类常数移入配置并进入授权摘要 | 已完成 | `SCREENING_RULE_DEFAULTS` + `RunConfig` 四个字段 |
| 规则名进入签名策略 | 已完成 | `screening_rule` 随 `screening` 进入 `manifest_hash` |
| 参数越界即拒绝 | 已完成 | `screening_settings` 校验四个聚类参数 |
| 每轮保存两簇中心、规模、离散度、分离度、实际阈值、迭代次数 | 已完成 | `select_explained` → 签名授权 `screening_decision` |
| 每个客户端退出的阶段 | 已完成 | `exit_stage`，取值来自 `EXIT_STAGES` 闭集 |
| 四类退出分开统计（证明失败／统计筛选／同组连带／未提交） | 已完成 | `screening_counts` |
| 导出白名单覆盖新字段 | 已完成 | `EXPORT_ROUND_FIELDS`、`EXPORT_VALIDATION_FIELDS` |
| 对 `low center < 0.25` 做候选规则对比 | 已完成（合成输入） | `candidate_decision`、`rule_rejects`、`scripts/evaluate_screening_rules.py` |
| 明确不改成"永远剔除低簇" | 已完成 | 两个候选规则与默认规则的差异已实测并记录 |
| 常数或规则变更即宣告历史结论失效 | 已完成 | 见下方"变更即失效" |
| 用真实数据在独立标定种子上冻结阈值 | **未做** | 需训练实验，见下方实验矩阵 |
| 校验种子与标定种子分离 | **未做** | 同上 |
| 预先固定的误排率与准确率门槛验证 | **未做** | 同上 |

**已核实的原状**：`select()` 原是确定性一维二均值，常数 `0.45 / 0.25 / 32 / 1e-12` 硬编码，因此**替换整个决策过程而保持五个门限字段不变时，`manifest_hash` 不变**。本轮把常数移入 `SCREENING_RULE_DEFAULTS` 并写入 `RunConfig`，使其进入摘要。

**实现中确认并回避的一处行为改变**：把门限默认值一并物化会让未声明门限的历史任务凭空获得 `max_norm_ratio=2.0`。实测该改动会使 `tests/integration/test_roles.py` 中 4 个同构客户端被误排，因此拆分为两类——规则参数（总是物化，因为规则总会运行）与门限（仅在任务声明时物化）。两者都参与校验，只有前者总是写入策略。

**变更即失效**：聚类常数或规则名一经改动，本仓库既有的攻击／防御结论即不适用于新规则，必须重跑并在记录中标注规则名与参数；失败实验保留，不因新规则而删除。`screening_decision.rule` 与 `screening.thresholds` 已写入每轮签名记录，使这一声明可被逐轮核对。

**候选规则对比（合成输入，非标定）**：`scripts/evaluate_screening_rules.py` 在 8 类受控形状×64 种子上对比默认规则与两个候选。观察到（见 `docs/research/evidence/screening-rule-evaluation.json`）：

- `gap_only_v1`（只要求簇分离）在"诚实 Non-IID 少数"场景的剔除率为 100%，而默认规则为 0%——这正是默认规则保留中心门限的理由，也是不能改成"只要分离就剔除低簇"的直接证据。
- 默认规则在"低簇其实是多数（4 对 2）且中心低于 0.25"时剔除 100%。这是**如实记录的潜在误排风险**：中心门限不看簇规模，也不看该簇是否比另一簇更松散。
- `size_dispersion_v1`（低簇须同时更小且更紧）在同样场景剔除 0%，但同时漏掉"规模相等"的攻击场景（剔除 0%）与"攻击簇较松散"场景（剔除约 8%）。

这三条都只是合成输入上的观察，**不能作为防御结论**；脚本自身的输出带了这一声明，并有测试锁定该声明。是否替换默认规则须由下述实验决定。

**尚未完成的实验矩阵（真实数据）**：MNIST/CIFAR-10；IID/Non-IID；无攻击／标签翻转／定向翻转／符号翻转／随机模型／搭便车；无恶意／少数恶意／接近声明边界；恶意同组／分散；多个标定种子 + 未参与调参的校验种子。预先固定的门槛：诚实客户端直接误排率 ≤ 5%（**IID 与 Non-IID 分别报告**）、干净实验平均准确率下降 ≤ 2 个百分点，并报告置信区间与连带退出率。攻击效果报告 OA、ASR、恶意接纳率与逐轮结果。

**验收**：同一输入在不同节点产生相同决定；策略参数与聚类常数都在授权摘要中（已实测：改动任一聚类参数都会破坏边缘签名）；候选未达门槛不替换默认规则（当前默认规则未被替换）。

---

## E. 超时、停止、资源预算、性能

1. 分开连接、健康检查、训练、证明、聚合的超时，不共用过长等待。超时重试复用原请求标识与请求摘要。
2. 停止后立即停止派发新工作；正在执行的原生密码调用在安全边界退出（FFI 无法中断，这是唯一可行语义）。界面区分"已收到停止请求"与"计算已停止"，显示当前等待阶段。强制结束进程后必须进入恢复核对。
3. 云节点缺席继续支持候补。推进前先验证每份结果的身份、上下文、授权集合、DKG 关联与数学关系，再冻结参与子集；迟到结果不能改变已确认集合。`collect_cloud_parts`（`runner.py:150-184`）已实现"批次完成后再选下一批"，现有区分也已正确：`cloud_network_absence`（`runner.py:103-118`）只把缺网归为缺席，TLS/校验失败一律中止，**不得简单归为离线**。
4. 边缘故障第一阶段：等待、重连、节点重启后从检查点恢复。减少全员依赖需另行定义授权与一致性规则，不直接把"全部边缘"替换为密钥门限。
5. 资源分三层：协议硬限制（现有 `check_wire_resources`，`resources.py:81-162`）、主机预算（同机各角色 + 验证进程 + 证明线程的 RAM/显存/CPU）、运行时控制（队列长度、临时磁盘、内存压力、派发速度）。**按机器汇总**，避免每个节点各自认为可用全部内存。RPC 并发、证明进程数、原生线程数共同分配。
6. 临时传输文件设容量与生命周期；清缓存时保留业务幂等凭据。
7. 性能先处理规范编码、重复传输、公开参数加载、已认证转录解析、进程启动。缓存只保存已核验的不可变材料，键含完整上下文与摘要。
8. 主控与边缘的独立安全检查先保留；减少完整合并次数须先明确安全职责归属并通过故障与伪造测试后单独上线。

**验收**：CPU/GPU 合法结果一致；负面用例接受集合不变；同硬件同输入的耗时、峰值内存、通信量及波动可测。资源估算明确标为估算。

---

## F. CRS 来源管理与安全审查材料

1. **来源与可信状态分开记录**。外部导入需核验电路标识、曲线、位宽、PK/VK 一致性、文件摘要、来源凭据。现实漏洞不是 `setup_kind` 中转（只有一个合法值），而是 manifest 未认证 + `created_at` 不被指纹覆盖（`lego_registry.py:73`、`:88-90`）。需要给 manifest 加来源凭据（签名，或至少与 CRS 指纹绑定的外部承诺），并把 `created_at` 纳入指纹。
2. 补电路身份绑定。现状只做形状检查，Rust 源码自己注明 "Shape equality does not establish circuit identity"（`native/dgfl-native/src/lego.rs:124-127`），`bits` 是可信调用方元数据（`:337-341`）。需要一个能写出来的负面测试：同 `(dimension, bits)` 但不同电路的诚实生成 VK 应被拒绝——目前无法写，因为检查不存在。
3. 严格部署策略：角色/实验启动已是 fail-closed（`roles.py:765-771`、`runner.py:521-535`），**部署脚本仍会自动补齐开发参数**（`setup_lego_parameters.py:119-135`、`setup_environment.py:164-190`）。严格模式要作为部署期门禁，而不是新增角色期检查。
4. 完整证明关系的规格与负面测试：密文与数值见证关联、注册密钥关联、上下文绑定、子群检查、可信验证参数来源。数值 SNARK 通过不能替代完整提交验证。
5. 密钥生命周期：明确区分任务内复用与每轮轮换。每轮轮换作为论文对齐与泄漏边界评估模式，额外 DKG 成本单独测量。现有复用模式必须记录允许的函数查询范围与跨轮累积信息（已知边界见 `paper-gap-analysis.md:41`、`architecture-comparison.md:62`），不能把消息防重放表述为函数钥代数撤销。当前 `aggregate_keys`（`protocol.py:316-403`）没有查询计数与上限。

**验收**：参数替换、混用、降级、关联关系篡改均被拒绝；设置来源可追溯。组合安全证明、侧信道评估、独立密码审查列为明确外部审查事项，本机测试不替代其结论。

---

## G. 动态加入与恶意边缘容错（协议扩展）

两项都改变安全模型，须在前述基础稳定后实施。

1. **恶意边缘容错**需同时解决：客户端原始提交的可认证绑定、验证结果独立复核、冲突授权防护、领导者/主控故障后推进、提交证书一致性。**密钥门限与一致性确认门限必须分别定义**，不能把 2-of-3 发钥规则当作完整容错规则。实现前固定敌手能力、故障数量、网络假设、仲裁集合条件，评审后再实现状态机。
2. **动态客户端加入**采用论文追加批次方式：已有组不拆分、不重排；新客户端凑齐 σ 人形成新组，通过成员变更证书在轮次边界加入。成员变化触发新密钥周期并更新归属与资源预算。未凑齐批次的新客户端处于待加入状态。

**验收**：历史分组可追溯；成员变化不污染已开始轮次；不同成员版本的消息不混合；故障下同时检查安全性与能否继续推进。

---

## 每阶段交付物

代码、测试、迁移说明、关联源码摘要的验收结果。失败样例保留；未通过的能力在界面与报告中明确标注。真实多机验收与独立密码审查分别列状态，不由本机模拟测试代替。
