# DGFlow Lab 全项目审计（2026-10-12）

审计对象：本检出 `D:\Desktop\全国密码技术竞赛\Project\DGFlow-source-671a850` 的**当前工作区**（含未提交改动）。
方法：读源码 + 实跑测试 + 复算证据 + 对照文档声明。所有结论都给出可复核的 file:line 或命令。

---

## 0. 规模与实测基线

| 项 | 实测值 |
|---|---|
| `src/dgfl` | 50 个 `.py`，13,737 行 |
| `tests` | 144 个 `.py`，23,710 行（测试/源码 ≈ 1.7×） |
| `web/src` | 45 个文件，4,850 行 |
| `native/dgfl-native/src` | 6 个 `.rs`，1,692 行 |
| `scripts` | 37 个文件 |
| `docs`（`.md`） | 36 个文件，2,343 行 |
| `runtime/` | 985.6 MB（已部署状态） |

**实跑结果（本次审计）**

| 命令 | 结果 |
|---|---|
| `python -m ruff check src tests` | **All checks passed**（与 CI 同范围） |
| `python -m ruff check src tests scripts` | **4 个 I001 错误**，全在 `scripts/`（CI 未覆盖该目录） |
| `python -m pytest -q` | **3428 passed, 29 skipped, 0 failed**（451.65 s） |
| `node --test`（web） | **168 pass, 0 fail** |
| `pytest tests/integration/test_{lego_roles,attack_policy_binding,configurable_batches}.py` | **48 passed**（真实 DKG + Lego 证明 + 门限聚合） |
| `dgfl_native` 0.2.0 | 已加载；`verify_linked` / `VerifiedLego` / `PublicAggregateVerifier` / `AggregatePolynomial` 全部存在 |
| 已安装 CRS | 650/8（PK 1,954,228 B / VK 31,692 B）与 1930/8，均 `single_party_development` |

（`tests` 的 144 个 `.py` = 142 个 `test_*.py` + 2 个辅助模块；无 `conftest.py`，`pythonpath=["src"]` 由 `pyproject.toml` 提供。）

---

## 0.1 风险总览

| 级别 | 数量 | 主题 |
|---|---|---|
| **P0** | 4 | 打包命令必然失败；冻结包泄漏主机名/用户名；证据指纹与交付树脱钩；出厂包文档链接断裂 |
| **P1** | 7 | NVRTC 阻断 CPU 平台离线包；故障脚本与报告生成器命名不一致；`design-report.pdf` 缺失且数字过期；`web/dist` 来源戳三方要求不一致；`rejected_clients` 语义未记录；历史计数互相矛盾；基础提交对象缺失 |
| **P2** | 8 | Python 下限三处不一致；user-manual 轮数范围过期；Rust 源描述错误；pip 配置覆盖声明不符；CI 不覆盖 `scripts/`；前端 166 项无据；读数口径未声明；哈希算法约定漂移 |

**结论**：代码本身质量高且**当前实测全绿**（3428 Python + 168 前端 + 48 真实密码集成，0 失败；`ruff src tests` 干净）。问题**几乎全部集中在交付链路与证据版本管理**，而不是密码或运行时实现。最关键的一点是：文档所引用的"验收/冻结"证据描述的是**已不在工作区的源码状态**，而打包工具目前**无法在当前工作区产出交付物**。

---

## 1. P0 — 交付链路阻断

### 1.1 文档给出的打包命令在当前工作区必然失败

deployment.md 记载的 `python scripts/package_submission.py --output dist/submission` 实测退出 1：

```
Submission packaging failed: Absolute development path in file: web/tests/monitor-charts.test.js
```

- 根因：`scripts/package_submission.py:69` 的 `WINDOWS_ABSOLUTE = re.compile(r"(?<![A-Za-z0-9_])[A-Za-z]:[\\/][^\s\"'<>]+")` 命中了前端单测夹具里的字符串。全量扫描确认命中点**恰好 4 处**：
  - `web/tests/monitor-charts.test.js:28`、`:38` → `C:/runtime`
  - `web/tests/monitor-render.test.js:59`、`:71` → `C:/runtime` / `C:\/runtime/`
- 这些文件都在 **HEAD** 中（由 `f1a828b` 引入），**不是本地未提交改动**。
- CI 从不打包真实仓库：`tests/packaging/test_package_submission.py` 只在 `tmp_path` 合成工程上运行，所以这个回归没有被任何门禁拦住。

**影响**：交付物 `source.zip`、`manifest.json`、`release-check.json` 目前无法生成。

**修复方向（二选一）**：让该校验跳过 `web/tests/`（测试夹具不是开发路径泄漏），或把夹具里的 `C:/runtime` 改成不含盘符的占位路径。

---

## 2. P1 — 功能/证据链缺陷

### 2.1 无 GPU 的受支持平台无法制作完整离线包

- `scripts/prepare_full_offline.py:178-181,197-201,486` 把 `nvidia-cuda-nvrtc-cu12` 当成**依赖根**，`_closure → _installed`（`:142-149`）缺包即 `RuntimeError`。
- 而 `scripts/setup_environment.py:68-78` **只在检测到 GPU 时**才安装 NVRTC。
- 实测：`RuntimeError: PackageNotFoundError: nvidia-cuda-nvrtc-cu12 (CPU-only machine)`。
- `verify_full_offline:383-385` 又强制 `gpu.status == 'included'`，无法绕过。
- 与 deployment.md:321 / README.md:103「受支持平台的 NVRTC」表述冲突——实际是**硬件判定**而非平台判定。

### 2.2 故障检查脚本与报告生成器命名不一致

- `scripts/run_fault_checks.py:267` 写 `schema_version=2`，用例名为 `cloud_threshold_met` / `cloud_threshold_below` / `one_client_down`（`:276-278`）。
- `scripts/build_report.py:119` 仍以 `one_aggregator_down` / `two_aggregators_down` 为键查表 → 新证据第一项即 `KeyError`。
- 实测复现：`NEW(v2) KeyError -> 'cloud_threshold_met'`；`COMMITTED(v1) OK`（已提交的 `docs/submission/evidence/faults/index.json` 是旧名，所以用历史证据仍能出 PDF）。
- **影响**：新故障证据无法生成 `design-report.pdf`，而它是 `package_submission.py:55` 的 `REQUIRED_FILES` 之一。

### 2.3 攻击架构验收所冻结的源码 ≠ 当前工作区源码

- `docs/research/evidence/attack-architecture-20261012.json` 冻结了 51 个源文件的 SHA-256，并声明 `source_unchanged=true`。
- 逐文件复算当前工作区：**47 个一致，4 个已改变**：
  - `src/dgfl/experiments/runner.py`
  - `src/dgfl/services/control.py`
  - `src/dgfl/services/roles.py`
  - `src/dgfl/validation/policy.py`
- 这 4 个正是工作区未提交改动最集中的文件（见 §4）。
- **影响**：`attack-defense-acceptance.md` 把它表述为「本次验收结果」并在 README 首行作为当前入口引用；严格来说该验收属于**已不在工作区的源码状态**，需要重新冻结或明确标注版本边界。

### 2.4 `design-report.pdf` 不存在于本检出，且报告数字严重过期

- `docs/submission/` 下只有 `design-report.md`，**没有 `design-report.pdf`**；它同时是设计报告交付物和 `package_submission.py` 的必填项。
- `design-report.md:192` 写「最终自动化验收：**238 项通过，6 项跳过**」，来源 `docs/submission/evidence/test-summary.json`。
- 本检出实际为 **3428 passed / 29 skipped**，且 `README.md:25,27,168` 自己的历史条目就写着 2,185 / 2,131 / 2,116 项通过。
- 该区域由 `scripts/build_report.py` 从 `docs/submission/evidence/` 重新生成，属**冻结证据**而非当前事实。

### 2.5 完整离线包的 `web/dist` 来源戳要求自相矛盾

- `scripts/setup_environment.py:117-122`：离线接受**没有 `source.sha256`** 的既有构建（`'existing build without source stamp'`）。
- `scripts/prepare_full_offline.py:478` 却强制要求 `web/dist/source.sha256`。
- 本检出 `web/dist/` 只有 `index.html` + `assets/`，**没有来源戳** → 在这个检出上生成完整离线包会先在这里失败。
- 另：`package_submission.py:55` 的 `REQUIRED_FILES` 不含 `web/dist`，但 deployment.md:375 与 `validate_release.py:221-222` 要求它。

---

## 3. P2/P3 — 一致性与质量问题

### 3.1 版本下限三处不一致

| 位置 | 声明 |
|---|---|
| `README.md:52`、`deployment.md:9`、`SOURCE-PACKAGE.md:46` | 锁定部署要求 **Python 3.12+** |
| `scripts/start_demo.ps1:59`、`scripts/start_demo.sh:47` | 实际门禁 `< (3,12)` 即拒绝 → 与文档一致 |
| `pyproject.toml:9` | `requires-python = ">=3.11"` |
| `.github/workflows/ci.yml` | 矩阵含 **3.11** |

即：文档与启动脚本一致，但包元数据与 CI 仍声明支持 3.11。Node 侧则是自洽的（`setup_environment.py:123-128` 强制 ≥22.12，与文档一致）。

### 3.2 用户手册的参数范围过期

`docs/submission/user-manual.md:25,26` 写「全局训练轮数 1–20」「本地训练轮数 1–5」，但：

- 后端 `control.py:137,155`：`rounds 1–100`、`local_epochs 1–20`
- 前端 `web/src/views/Deploy.vue:223,245`（校验）与 `:434,439`（`max` 属性）：同为 1–100 / 1–20
- `docs/research/attack-defense.md:264` 已明确写「允许 1–20 个本地 epoch、最多 100 个全局轮次」

**用户手册是唯一过期的文档。**

### 3.3 Rust 工具链描述与实现不符

- `scripts/deployment_native.py:30-32,205-212`：Rust 默认主源是 **`rsproxy.cn`**，而 `deployment.md:13` 写「自动下载官方最小工具链」。
- deployment.md 的镜像清单**完全没提 Rust/Cargo**，但 README/deployment 又说镜像逐个回退。

### 3.4 用户 pip 配置会被内置镜像覆盖

`scripts/deployment_downloads.py:60-67` 会覆盖用户 `pip.ini` 里的 `index-url`，与 `deployment.md:31`「已有显式 pip/npm 配置也会保留」不符。

### 3.5 CI 不覆盖 `scripts/`

`ruff` 在 `scripts/` 有 4 个 `I001`（`benchmark_compact_validation.py:7`、`benchmark_lego_proof.py:8,49`、`benchmark_paper_training.py:2`）。CI 只跑 `ruff check src tests`，所以未被发现；`scripts/check.ps1:1-5` 自称等同 CI 两道门禁，实际 CI 有 4 个 job。

### 3.6 其他已确认的小问题

- `scripts/prepare_offline.py:46` 硬编码 `NATIVE_VERSIONS{0.1.0, 0.2.0}`。
- `scripts/setup_environment.py:199` 固定写 `.venv` 记录，与 `-PythonPath` 解耦失败。
- `scripts/build_native.ps1:1,9,18-24` Windows 专用，并按 mtime 选 wheel，策略与 `deployment_native.py:152-155` 相悖。
- `scripts/build_report.py:60-61,216` 硬编码本机硬件与 Windows 字体（SimSun），Linux 上无法出 PDF。
- `deployment.py:43,727` 与 `setup_environment.py:149` 的数据目录基准不同：自定义 `runtime` 时 `doctor` 会查错目录。
- `README.md:60` 的 MindSpore 链接与 `training/cifar10.py:29-32`、`deployment.md:90` 不一致。
- `SOURCE-PACKAGE.md:39` 与 `scripts/freeze_source.py:144,156` 冲突（manifest 实际会被写进 ZIP）。
- `src/dgfl/services/tensorboard.py:7` 使用已弃用的 `starlette.middleware.wsgi.WSGIMiddleware`（每次测试输出 deprecation warning）。

---

## 4. 文档内部矛盾与前端死代码

### 4.1 筛选默认值与聚类规则：文档与源码一致

逐项核对**未发现矛盾**：

| 规则 | 源码 | 文档 |
|---|---|---|
| `min_cosine` 默认 | `validation/policy.py:9` = **0.0**；`control.py:160` = 0.0 | `protocol-v1.md:132`「余弦下限（默认 0）」；`design-report.md:94`「默认最小余弦为 0」；`attack-defense.md:14` 一致 |
| `max_norm_ratio` 默认 | `policy.py:9` = **2.0**，比较时用比值平方（`policy.py:85`） | `design-report.md:94`「最大 L2 范数为合格候选群体下中位数的 2 倍」；`attack-defense.md:14`「默认相对上界 2.0，即平方范数大于中位数的 4 倍时拒绝」 |
| `min_norm_ratio` | `policy.py:9` = **None**（默认关闭，`policy.py:45-49` 注明是论文外启发式） | `attack-defense.md:15`、`protocol-v1.md:13` 一致声明默认关闭 |
| 二均值 | `policy.py:120` `hi-lo<.45` 提前全接纳；`:133` 仅当 `hi-lo>=.45 and lo<.25` 才丢低簇 | `design-report.md:77`、`paper-gap-analysis.md:20`、`protocol-v1.md:130` 一致 |
| 中位数取法 | `policy.py:79` `ordered[(len-1)//2]` = 下中位数 | `policy.py:60` 注释与 `design-report.md:94` 一致 |
| 确定性求和 | `policy.py:127-128` 对两个中心用排序后 `math.fsum` | `attack-defense.md:239-243` 记录了 3.11 哈希种子分歧与修复，一致 |

这点值得肯定：筛选层的每个默认值和阈值都能在文档里找到对应声明，且 `tests/validation/test_policy.py`、`test_screen_determinism.py` 有对应回归。

### 4.2 前端监控面板已成死代码

`web/src/views/Monitor.vue` 只有 12 行、仅渲染 `TensorBoardPanel`。以下模块**不被任何 view 引用**：

- `components/NodeMonitorPanel.vue`、`TrainingCharts.vue`、`ResourceCharts.vue`、`MeasuredChart.vue`
- `lib/nodeMonitor.js`、`lib/monitorCharts.js`
- `api.getMonitor()` → `GET /api/runs/{id}/monitor`（后端端点仍活，前端无人调用）

它们只被 `web/tests/monitor-*.test.js` 直接 SSR 渲染测试。这不影响功能，但会增加维护面与误读风险。

### 4.3 门限下限是硬编码 2

`MIN_AUTHORITY_THRESHOLD = MIN_AGGREGATOR_THRESHOLD = 2` 同时写在 `topology.py:12`、`protocol.py` 的 `_bounds`/`_authority_ids`/`combine`、`RunConfig` 的 pydantic 约束中。**密码实现不支持 1-of-n。** 文档已如实声明。

### 4.4 网格约束实际有两层且自洽

`control.py:159` 允许 `grid ∈ [2,32]`，但 `resources.py` 的表单校验会按数据集原图分辨率收窄：实测 `mnist grid=30/32` 与 `cifar10 grid=32` 都被拒绝并给出中文原因（「pooling grid must be an integer in [1, 28]」/「模型维度超过当前 20,000 维上限」）。与 user-manual.md:24 的 2–28 / 2–25 一致，**无漏洞**。

---

## 5. 已确认正确的部分（本次独立复算）

### 5.1 证据链数字全部可复现

独立解析 `docs/submission/evidence/{formal,full-data}/summary.csv`：

- `formal` **18 行**，`full-data` **2 行**，合计 **20 任务，completed=20 / aborted=0 / failed=0** → 与 design-report.md:184 完全一致。
- 逐种子首轮表（design-report.md:145-149）复算：

| 种子 | A/C/D 首轮一致 | 首轮准确率 | C 轮时/s | D 轮时/s | C/D MiB |
|---|---|---|---|---|---|
| 42 | 是 | 46.25% | 644.67 | 211.05 ✅ | 416.16/290.63 ✅ |
| 43 | 是 | 52.75% | 207.42 | 68.54 | 416.16/290.63 |
| 44 | 是 | 39.75% | 204.69 | 67.55 | 416.16/290.63 |

  C 均值 **352.26 s**（报告 352.26 ✅），D 均值 **115.75 s**（报告 115.71，差 0.04 s），C/D 比 **3.04** ✅，D 相对 C 字节 **−30.16%**（报告 −30.17%）。两处 0.01 量级差异属舍入口径，不影响结论。
- 符号翻转表（design-report.md:156-162）六行与原始记录逐项吻合（22.50/26.75、42.25/56.00、33.50/34.50，接纳 1/0，诚实退出 0/1）。
- 全量 MNIST 三轮 82.17/83.20/82.95% 与 `full-data` 记录一致；optimized 单轮均值 637.07 s 与报告 210.75/211.74/214.58 相符。
- **seed 43 的 `encrypted` 单轮 8,365 s 是系统休眠导致的**，文档在 design-report.md:166 如实保留并声明不用于性能结论 —— 这是证据纪律的正面例子。

### 5.2 攻击架构验收证据自洽

`attack-architecture-20261012.json`：`cases=8`、`passed=true`、拓扑 6/3/4、门限 2/2、`source_unchanged=true`、`cleanup.nodes.stopped=13`；`attack-architecture-review-20261012.json`：`accepted=true`、8 案例、`full_cnn_negative_result`（OA 0.6512 / ASR 0.3396 / 条件 ASR 0.3778）与 attack-defense.md:173 完全一致。

### 5.3 匿名化检查：分包路径干净，但冻结路径会泄漏主机名与用户名

**`package_submission.py` 路径**（白名单含 `docs/submission`、`docs/protocol`，不含 `docs/research/evidence`）：对白名单内 47 个文档扫描，无 `@bupt.edu.cn`、`@gmail.com`、`@qq.com`、`学号`、`参赛队员`、`作者：`、绝对用户路径命中。唯一的 `指导教师` 命中是 design-report.md:213 的**否定声明**。**这条路径合格。**

**`freeze_source.py` 路径**（`SOURCE-PACKAGE.md:111` 记载的正式冻结命令）：`freeze_source.py:20` 的 `TREES=('.github','configs','docs','src','tests','scripts','web','offline')` **包含整个 `docs/`**，`:25` 只排除两个论文 PDF，`:41` 只按后缀排除 `.pem/.key/.p12/.pfx` —— **没有任何绝对路径 / 用户名 / 主机名内容扫描**。实测以下内容会进入冻结包：

| 文件 | 泄漏内容 |
|---|---|
| `docs/research/evidence/attack-architecture-review-20261012.json:162,174` | `"hostname": "DESKTOP-GT1VP52"`（= 本机 `$env:COMPUTERNAME`，真实主机名） |
| `docs/research/evidence/native-acceptance.json` | `"working_directory": "D:/Desktop/全国密码技术竞赛/Project/DGFlow-source-671a850"` |
| `docs/research/evidence/integrity-audit-20261007.json` | `"working_directory": "D:\\Desktop\\…\\web"`，以及 `C:\\Users\\eeeee\\AppData\\Local\\Temp\\pytest-of-eeeee\\pytest-185\\…`（**Windows 用户名**，出现 4 次） |
| `docs/research/evidence/combine-optimization-20261004/test-summary.json`、`docs/submission/evidence/test-summary.json` | `C:\\Users\\eeeee\\AppData\\Local\\Temp\\pytest-of-eeeee\\…` |

注意最后一行：**`docs/submission/evidence/test-summary.json` 本身也含用户名**，而它在 `docs/submission` 白名单内 —— 也就是说 `package_submission.py` 那条路径虽然正则扫描通过（它只查 `[A-Za-z]:[\\/]…` 形式的单反斜杠路径，而 JSON 里是转义后的 `C:\\Users\\…`），**用户名依然会随包出厂**。`submission-notes.md:13` 要求「代码注释、截图与运行记录保持匿名」，这条需要修。

### 5.4 证据链的其他已确认问题

| 级别 | 问题 | 证据 |
|---|---|---|
| P0 | **指纹与交付树脱钩**：`test-summary.json:30` 与 `release-provenance.json:5` 的 `ee1c0c2c…`、`environment.json:12` 与 23 个 `result.json` 的 `ac00368a…` **都不等于当前树**（整树 `c4a404d0…`／限旧 22 路径 `c8c4d158…`）；22 个归档源文件中 16 个已改，另新增 28 个 `src/dgfl/*.py`；**39 个提交中没有任何版本命中这两个指纹** | 逐文件 SHA-256 复算 |
| P0 | **238/6/0 无原始产物**：其声明的 `tmp/final-tests.xml` 不存在且被 `.gitignore:11` 忽略；全仓无 `tests="244"` 的 junit。当前树收集 **3457** 项，而仓库最早提交 `5025b8b`（2026-10-08）就已有 878 个 `def test_` | `pytest --collect-only` |
| P0 | **出厂包内文档链接断裂**：`attack-defense-acceptance.md:22,74`、`deployment.md:141`、`SOURCE-PACKAGE.md:15,106` 指向 `docs/research/**`，而该目录不在包白名单内；`tests/packaging/` 不检查链接封闭性 | 488 文件清单核对 |
| P1 | **基础提交对象缺失**：`docs/research/evidence/README.md:21` 的 `34f8602d22…` 与 `freeze_source.py:26` 的 `BASE_COMMIT=671a85063ee…` 均 `git cat-file` 报 not found（仓库只有 39 个提交，最早 `5025b8b`） | `git cat-file` |
| P1 | **`rejected_clients` 语义未记录**：`runner.py:1084` 定义为 `set(key_messages)-set(approved)`，即 rejected ∪ collateral；5 条记录（`36613715`、`63dd108f`、`16e4ad1c`、`b64ba4af`、`9029eb7c`）出现 `accepted+rejected+collateral > len(validations)`；`evidence/README.md:17-25` 未定义该字段 | 逐记录比对 |
| P1 | **历史计数互相矛盾**：README:25/27/168 = 2,185/2,131/2,116，`docs/research/evidence/test-summary.json` = 295，`design-report.md:192` = 238；§7.2 标题「最终自动化验收」相对交付树已过期 | 多文档对照 |
| P2 | §7.2 的 MiB 列只能用**轮级** `rounds[].bytes_sent` 复现（416.1372→416.14），用 `summary.wire_bytes` 则得 416.16；`evidence/README.md:21` 未声明所用字段 | 我的复算与代理复算一致 → 416.14 |
| P2 | `summary.elapsed_seconds` 比各轮之和多 0.5–9.5 s（轮前 health/DKG 开销）未在读数口径说明 | `evidence.py:111-112` |
| P2 | `full-data` 表列名「全数据加密准确率」实际取自 `optimized`（该套件无 `encrypted` 行） | full-data/summary.csv |
| P2 | 哈希算法漂移：归档套件用 canonical JSON，`backend.py:60-62` 现为 `packb`；`evidence.py:81-85` 兼容两者（可复验），但第三方用出厂代码重算会得到不同 `suite_hash` | `suite_hash` 复算命中 |
| P2 | 前端测试数：`attack-defense-acceptance.md:34` 写「前端 166 项通过」，但**任何证据文件都找不到 166**（全仓无此数字；同类监控记录为 133/138/146）；本检出实测 **168** | `node --test` |

### 5.5 CI 门禁的覆盖空洞

CI 有 4 个 job（`.github/workflows/ci.yml`）：`check`（ubuntu+windows × py3.11/3.12，无原生扩展无 torch，**允许跳过**）、`frontend`、`cnn`（**跳一项即失败**）、`native-lego`（maturin 构建 + 8 个指定模块 + **跳一项即失败**）。

以下**完全没有门禁**：

- `scripts/verify_attack_architecture.py`（8 例 / 12 轮真实节点验收）
- `scripts/run_fault_checks.py`（真实停止进程；`tests/experiments/test_fault_script.py` 全 monkeypatch，不真停）
- 全部 benchmark（crypto-paired / paper CNN / attack-defense）
- `scripts/build_report.py`（文档数字生成器）
- `scripts/` 的 ruff（本次实测 4 个 I001）
- 打包的命令行端到端（`tests/packaging/` 只用合成工程，所以 §1.1 的 P0 逃过所有门禁）
- 出厂包内文档链接封闭性

特别值得注意：`tests/integration/test_configurable_batches.py`（σ=3 真实 Lego 两轮）**不在** `native-lego` 的显式模块清单里，而在 `check` 中因 `importorskip('dgfl_native')` 直接跳过 → **该主张在 CI 中从不真正执行**。

### 5.6 文档数字与证据之间的闭环缺口

`build_report.py` 保证「文档数字 = evidence JSON」；但「evidence JSON = 真实运行 / 交付代码」**没有任何自动化闭环**：

- 没有任何测试读取 `docs/**/evidence/**` 或做数字回归。
- 测试只覆盖合成记录的汇总语义（`test_evidence.py`）、证据保全与路径安全（`test_evidence_review.py`）、套件契约（`test_suite_contract.py`）、故障脚本状态机（模拟）、打包白名单与匿名性正则。

这正是 §2.3 与上表 P0 指纹脱钩能够长期存在而不被发现的机制原因。

---

## 6. 架构总览（源码级）

```
┌─ 控制器 1 个  dgfl.cli serve|demo  → uvicorn 127.0.0.1:8765
│    FastAPI + TrustedHost + ControlSafetyMiddleware(同源 + 32 KiB body)
│    内嵌 TensorBoard ASGI 挂 /tensorboard/（不新增端口）
│    RunManager：单活动任务，逐轮编排，原子落盘 result.json
│
├─ 边缘 w=3    9101-9103  Pedersen DKG、归属证明核验、VerDec、共同筛选授权、combine 确认
├─ 云   v=4    9201-9204  校验授权清单 + 密文摘要、部分解密 + 配对像正确性证明
└─ 客户端 n=6  9301-9306  本地训练 → 8bit/scale128 量化 → 加密 → LegoGroth16 证明
                          按 client_authorities 密封给唯一归属边缘

传输：uvicorn HTTPS + mTLS(CERT_REQUIRED)
      ＋ 自研规范二进制信封 MAGIC|ver|sender|recipient|purpose|context|nonce|ct|sig
      Ed25519 签名 + X25519/HKDF-SHA256/AES-256-GCM，信封头作 AAD
      全仓库零 pickle；群元素全部校验长度/曲线/素数阶子群/规范往返
      >24 MiB 自动 8 MiB 分块；大回复 v2 清单 + _download_complete 确认；1 GiB 逻辑上限

新任务证明套件：仅 lego_norm_v1（LegoGroth16 数值电路 + 外层共享响应 Σ）
      ct_j = F·s_j + G·x_j ；K_j = G·s_j + H·k_j ；D = ΣQ_j·x_j + Q_v·v ；Σx_j² = norm
      650 维 / 8 bit → 6501 条约束；完整规范证明 144,777 B（Lego 核心仅 240 B）
```

**与论文的主要差距**（项目已自述，本次核实为真）：完整 CNN 仅接明文 Torch 对照、加密路径硬拒；加密链只到 650/1,930 维线性模型；未实现论文四个对照基线；动态加入批次未实现；double-binding 知识提取与零知识归约未完成；CRS 是单方开发设置。

---

## 7. 建议修复顺序

1. **P0**：修 `package_submission.py:69` 的绝对路径校验（跳过 `web/tests/`，测试夹具不是开发路径泄漏），并在 CI 加一步对真实仓库的打包 smoke test。
2. **P0**：给 `freeze_source.py` 加内容扫描（主机名 `DESKTOP-*`、`[A-Za-z]:[\\/]` 路径、`Users\<name>`、`/home/<name>`），并在打包前清理 `docs/research/evidence` 与 `docs/submission/evidence/test-summary.json` 里的主机名/用户名。
3. **P0**：重新冻结或明确标注版本边界 —— `ee1c0c2c…` / `ac00368a…` 与当前树（`c4a404d0…`）脱钩，`attack-architecture-20261012` 的 4 个源文件已变；同时重新生成本次工作区的 `design-report.pdf` 与 `test-summary.json`，并把 `tmp/final-tests.xml` 纳入可交付证据。
4. **P0**：修出厂包的文档链接封闭性（`docs/research/**` 被引用但不在白名单），或把被引用的研究文档纳入包内。
5. **P1**：改 `prepare_full_offline.py` 的 NVRTC 策略（缺包降级 + 同步 `verify_full_offline` 与文档）。
6. **P1**：对齐 `run_fault_checks.py` v2 命名与 `build_report.py:119` 的 `fault_labels`。
7. **P1**：统一 `web/dist/source.sha256` 的准入要求（`setup_environment.py` vs `prepare_full_offline.py` vs `package_submission.py`）。
8. **P1**：把 `verify_attack_architecture.py`、真实故障检查、打包 e2e 纳入 CI；把 `test_configurable_batches.py` 加入 `native-lego` 清单，使 σ=3 主张真正执行。
9. **P2**：统一 Python 下限（`pyproject.toml` / CI vs 文档与启动脚本）；更新 user-manual 的轮数范围；修正 Rust 源描述、pip 配置保留声明；在 `evidence/README.md` 补充 `rejected_clients`、MiB 字段、`elapsed_s` 差值的读数口径；修正「全数据加密准确率」列名与前端 166 项。

---

## 附：审计期间产生的临时文件

- `tmp/paper.txt` — 为解析 `docs/DGFlow-指导论文.pdf` 生成的纯文本（`tmp/` 在 ruff/打包排除范围内，可删）。
- 在 `.venv` 中安装了 `pypdf`（用于读取论文 PDF；不影响交付包）。
- `tmp/audit-submission-check` 已删除；部署审计代理的 `%TEMP%\dgfl-audit-submission-1/2` 可删。
