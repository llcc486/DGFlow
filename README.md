# DGFlow Lab

**基于去中心化函数加密的隐私保护鲁棒联邦学习系统**

此源码版本包含 MNIST / CIFAR-10 镜像下载、完整部署准备、GPU 自动检测及此前 P1/P2 修复。首次启动脚本会先安装依赖、构建原生后端和前端、准备两种数据集，全部完成后才打开服务；也可先单独部署，再离线启动。源码包不包含环境、数据或运行密钥，详见[源码项目说明](SOURCE-PACKAGE.md)。下文带日期的验收和性能数字属于其原始版本。

当前新建加密实验统一使用 **LegoGroth16**（`lego_norm_v1`），须预先安装并选择与模型维度和 8 位量化匹配的 CRS。`plain` 明文基线不生成密码证明，也不需要 CRS。旧证明方案及其性能记录保留用于历史核对，不再作为新实验选项。

DGFlow Lab 是一个可运行的研究原型，用于观察联邦训练、真实密码计算、输入验证、成员接纳和门限聚合之间的关系。系统提供中文实验台、命令行工具、可配置的客户端、边缘授权与云聚合进程，可导出实验记录并支持单机/三机部署。新部署默认 n=6 个客户端、w=3 个边缘授权节点、v=4 个云聚合节点；可分别配置为 2–100、2–32、2–32，边缘门限 s 与云门限 e 可选 2–w、2–v。

2026-10-06 按论文 §III/§V 调整了分层拓扑：每个客户端只把原始证明与加密提交发给一个归属边缘；所有边缘共享验证函数钥份额，归属边缘核验后共享签名评分、范数、摘要与密文核心，其余边缘共同筛选并授权。轮流分配归属及默认 w=3 是工程选择。论文的 VerDec（V）由归属边缘内部执行，不增加独立网络角色。具体实现与尚存差距见[分层拓扑说明](docs/research/hierarchical-topology-20261006.md)。下文 12 角色及三云性能数字保留为旧配置的历史证据，新默认配置含 13 个角色，尚不能把旧性能直接移用。

已完成本机 12 角色进程、650 参数模型的 18 项场景实验、2 项完整 MNIST 三轮对照和 3 项真实进程故障检查。完整数据明文与加密模型逐轮摘要、批准集合均相同，最终测试准确率为 82.95%。方向反转和范数篡改在本次场景被拒绝，标签翻转仍通过筛选，具体结果及代价均保留。三台物理机器由队伍按手册部署，本次不报告三机实测性能。此项目不构成经过独立审计的生产密码系统，也不声称取得完整系统安全证明。

## 从哪里开始

2026-10-08 完整部署验收：全新虚拟环境自动装齐 Torch、torchvision、当前原生扩展与 NVRTC；禁用外网及 pip 索引后完整离线检查通过。隔离六角色自动完成 GPU 自检，CIFAR-10 / Torch 的一轮明文与 GPU 加密模型摘要一致。原部署 13 个节点已恢复在线，两个数据集、全部训练客户端的 Torch 与主控/边缘 GPU 均就绪；见[部署验收记录](docs/research/evidence/deployment-ready-20261008.json)。

2026-10-08 已修复审查中的 P1/P2：批量实验与报告严格校验请求和实际部署配置、历史聚合子阶段不重复计时、运行目录生命周期锁防止并发覆盖 PID、大回复在完整接收确认后可有界回收。当前协议及交付说明已同步；Python 2,185 项通过、12 项跳过，前端 102 项通过，6 个隔离真实 HTTPS 角色的明密模型摘要一致，验证见[修复验收记录](docs/research/evidence/p1p2-fixes-20261008.json)。本次保留回退后的聚合算法、身份、CRS 和历史结果。大回复完成确认使用 v2 清单，启用修复须同步更新并重启主控与全部角色；新版客户端兼容旧 v1 清单。

2026-10-07 完整性核验已修复任务异常恢复、首次硬件采样阻塞、监控阶段耗时重复统计，以及前端全员在线限制与后端云门限不一致的问题。当次 Python 回归 2,131 项通过、12 项跳过，前端 100 项通过，真实 CIFAR-10 / Lego 证明的隔离门限聚合与明文模型摘要一致。主部署、身份、CRS 与历史记录保留；算法瓶颈和未实现部分见[完整性核验记录](docs/research/evidence/integrity-audit-20261007.json)。该检查不等同于论文级 CNN、安全证明或多机性能复现。

2026-10-06 的训练速度检查涵盖批量份额传输、原生部分解密、GPU 点准备、公开 DKG 系数复用和门限云选择，保留逐坐标证明及各边缘独立核验。重复测量发现早期基线有明显机器状态波动，不能把首次总耗时下降全部算成优化收益；验证、实测口径与剩余范围见[训练速度检查](docs/research/training-speed-20261006.md)。

2026-10-04 修复了恶意部分解密、范数筛选和固定伙伴连带退出、实验对照缓存、控制 API 来源与正文限制，并补齐前端/CNN/原生 Lego CI。新实验默认至少两名幸存成员共同聚合，鲁棒模式加入范数幅度门限；标签翻转仍存在检测边界。密码消息格式已升级，使用新代码时须重启所有角色并创建新任务。交付快照、重新冻结命令见 [源码包说明](SOURCE-PACKAGE.md)，验证结果见 [本次修复记录](docs/research/review-fixes-20261004.md)。

2026-10-02 起按论文规模开展研究优化：新增 582,026 / 878,538 参数的完整 CNN 本地训练模块，以及保持协议语义的原生 MSM、受检点解析和公共预计算优化。当前网页与安全服务支持 MNIST 和 CIFAR-10 的池化线性模型，默认分别为 650 和 1,930 维；完整 CNN 的证明与加密联邦链路尚未接通。大消息已有分块传输，但仍受单次逻辑消息 1 GiB 上限约束。旧提交包及上文实验数字仍属于其原始版本，不能作为新版本性能数据。详见[论文对齐与接入设计](docs/research/paper-alignment.md)、[CNN 接口](docs/research/paper-models.md)和[新实测记录](docs/research/evidence/)。

| 需要完成的操作 | 文档 |
| --- | --- |
| 使用中文实验台、解释指标与错误 | [用户手册](docs/submission/user-manual.md) |
| 安装、单机启动、三机分发与排错 | [部署说明](docs/submission/deployment.md) |
| 准备现场演示并准确说明结果 | [演示脚本](docs/submission/demo-script.md) |
| 了解设计与正式实测证据 | [设计报告](docs/submission/design-report.md) |
| 核对原始数据及统计口径 | [实测证据索引](docs/submission/evidence/README.md) |
| 填写作品编号和准备上传材料 | [提交说明](docs/submission/submission-notes.md) |
| 三人讲解与代码追问准备 | [答辩稿](docs/submission/defense-notes.md) |
| 查阅密码证明关系及其边界 | [证明构造规格](docs/protocol/proof-construction.md) |
| 查看公开上游归属与依赖许可 | [第三方声明](THIRD_PARTY_NOTICES.md) |

## 快速启动：Windows

在项目根目录执行。推荐 Python 3.12，前端源码构建需要 Node.js 22.12+ 与 npm。构建原生密码后端需要 Windows Visual Studio C++ 构建工具与 Windows SDK，Linux 需要 C/C++ 编译器；缺少 Rust 时部署助手会下载到项目自己的临时目录，不修改系统 PATH。GPU 密码计算需要已安装兼容驱动的 NVIDIA 显卡。

先完成一次联网部署：

```powershell
powershell -ExecutionPolicy Bypass -File scripts/start_demo.ps1 -SetupOnly
```

部署包含基础 Python 依赖、CPU 版 PyTorch/torchvision、完整原生密码扩展、检测到 NVIDIA GPU 时所需的 NVRTC、MNIST 与 CIFAR-10、前端依赖和构建结果。CIFAR-10 优先使用 MindSpore 官方镜像，失败后回退原始站点，并校验原始摘要。某一步失败会停止部署，不会提前启动服务。

完成后离线启动：

```powershell
powershell -ExecutionPolicy Bypass -File scripts/start_demo.ps1 -Offline
```

也可直接运行 `scripts/start_demo.ps1`，将上述部署与启动一次完成。GPU 会自动检测，并在节点上线后自动执行精确密码运算自检；通过后页面显示可用，无须再安装 NVIDIA Python 包或手动准备 GPU。默认计算设备仍为 CPU，可在页面选择 GPU。启动后的内核编译仅使用本地文件，不下载依赖。Lego 的模型专用 CRS 仍须按后文单独生成。

打开 [本机实验台](http://127.0.0.1:8765)。先确认数据就绪和节点状态，再创建任务。脚本受本机执行策略限制时，使用部署说明中的手动命令；不必降低系统策略。

部署页可设置 n、w、v 与两层门限并应用到实际本机节点。三维拓扑区分已部署状态与规划预览，支持旋转、缩放和选中节点；归属连线与数据分区、建钥及授权名单使用同一份部署元数据。运行中禁止改变拓扑，已有实验记录、数据缓存和证明参数保留。不带拓扑参数的 `start`/`demo` 沿用已有部署；旧配置缺字段时按实际节点数兼容，原 6/3/3 集群不会自动改成 6/3/4。

例如新建 n=20、w=3、v=4、s=2、e=3 的独立运行目录并启动：

```powershell
.\.venv\Scripts\python.exe -m dgfl.cli init --runtime runtime-paper --client-count 20 --authority-count 3 --aggregator-count 4 --authority-threshold 2 --aggregator-threshold 3
.\.venv\Scripts\python.exe -m dgfl.cli start --runtime runtime-paper
.\.venv\Scripts\python.exe -m dgfl.cli serve --runtime runtime-paper
```

Windows 启动脚本支持 `-ClientCount 20 -AuthorityCount 3 -AggregatorCount 4 -AuthorityThreshold 2 -AggregatorThreshold 3`；Linux 对应 `DGFL_CLIENT_COUNT`、`DGFL_AUTHORITY_COUNT`、`DGFL_AGGREGATOR_COUNT`、`DGFL_AUTHORITY_THRESHOLD`、`DGFL_AGGREGATOR_THRESHOLD` 环境变量。现有本机集群仅在空闲时显式应用配置后事务更新，保留已注册身份；缺少预留身份的历史集群扩容可能需要 TLS 轮换与受管角色重启。

已有依赖和数据缓存后，可使用：

```powershell
.\scripts\start_demo.ps1 -Offline
```

Linux 环境可先执行 `bash scripts/start_demo.sh --setup-only`，再执行 `bash scripts/start_demo.sh --offline`；直接 `bash scripts/start_demo.sh` 可合并部署和启动。非当前验证平台需先核验底层密码 wheel 与依赖兼容性，不将脚本存在等同于跨平台实测通过。

退出控制服务使用终端的 `Ctrl+C`。节点是独立进程，随后运行以下命令停止本运行目录管理的节点：

```powershell
.\.venv\Scripts\python.exe -m dgfl.cli stop
```

## 四种模式

历史研究（2026-10-03）曾接入分层加速至 **5B**：独立并行执行、有界验证进程池、公开固定基预计算、原生 GT、随机加权验证及同曲线紧凑范围/范数证明。5B 为已做代数和负测的实验性二次 IPA 扩展，尚未经独立密码学审计；准确关系见[证明规格第 13–14 节](docs/protocol/proof-construction.md)。5A/5B 与原逐坐标证明已退出当前新建实验入口，原研究材料和结果保留，不能把其性能数字视为当前 LegoGroth16 的性能。

当前 `encrypted`、`dgflow` 和 `optimized` 新实验均使用 `lego_norm_v1`：LegoGroth16 约束范围和平方范数，共享响应的 Sigma 证明连接实际密文和注册密钥。它需要当前源码对应的 `dgfl-native`，以及提前安装并固定指纹的电路专用可信参数；旧原生模块和 Python 回退不能执行此套件。完整 650 维证明的历史微基准、实测口径及设置假设见[加速报告](docs/research/optimization-results.md)和[证明规格第 15 节](docs/protocol/proof-construction.md)。

2026-10-04 新增完整原生 Lego 核验、受检密文点复用和批量授权接口，默认每个授权节点一个验证进程、两条原生计算线程，核验仍为确定性。650 维单份完整核验短测约 282 ms；完整六客户端授权批次与聚合仍有秒级开销。实现和可复验记录见[验证与授权优化报告](docs/research/validation-authorization-optimization-20261004.md)。本机匹配 wheel 位于 `dist/native/`；加载新实现须安装匹配构建并重启全部角色和控制服务。

2026-10-05 增加真实 RPC 承诺内容缓存、原生完整部分解密证明核验、公开 GT 固定底数表及精确子群检查后的快速公开指数运算。保留主控与三个授权节点的四次独立合并；计时包含各自的云 E 重算。优化模式在能力协商通过后减少重复证书传输。相同模型、相同 seed 的隔离进程实测及局限见[合并优化验收](docs/research/combine-optimization-20261005.md)。随机 DKG 批验仍需显式指定 `verification=randomized`。

2026-10-05 最新全流程优化已接入本地原生批量点运算、GT 指数和固定 G2 配对，三云复用多项式系数图像，Authority 复用自身已完整检查的 DKG 转录；主控仍独立完整检查。GPU 将九份证明合并批处理，使用公开底数表和精确 GT 子群判据，每份证明保留独立挑战和逐坐标核验。传输层复用规范编码并协商紧凑材料。相同配置的隔离两轮 CPU 实测 182.06→101.70 秒，GPU 146.05→84.49 秒，模型和决策完全一致，传输减少约 36%。主服务十轮 GPU 验收完成于 424.90 秒，十轮模型与此前记录逐轮一致。详细口径、测试和瓶颈见[完整分析](docs/research/evidence/full-optimization-20261005/analysis.json)及[十轮验收](docs/research/evidence/full-optimization-20261005/live-validation.json)。匹配 wheel 位于 `dist/native/`，扩展版本号仍为 0.2.0，使用构建指纹区分新旧实现。

完整部署会安装当前源码对应的完整原生密码扩展。修改 Rust 源码后，再运行部署助手即可核对指纹并按需重建：

```powershell
powershell -ExecutionPolicy Bypass -File scripts/start_demo.ps1 -SetupOnly
```

Linux 对应 `bash scripts/start_demo.sh --setup-only`。匹配 wheel、来源凭据与安装摘要保存在 `tmp/native-toolchain/`，离线启动需保留相关材料。只手动安装基础 NumPy 环境时，可运行无需证明的明文基线；新加密实验必须加载支持持久参数的 Lego 原生扩展。完整一键部署会要求原生扩展就绪。实际启用状态、原生源码/二进制摘要会写入实验记录。

Lego 的本地实验参数需要明确执行一次离线设置，再在网页选择匹配维度和位宽的 CRS。安装新的原生模块后应重启相关进程，节点 health 会检查实际加载的能力。以下生成操作只保存公共 PK/VK 和清单，角色启动不会代做；这是单方开发设置，正式部署需要另行建立可信设置流程。

```powershell
# MNIST，8×8 池化，650 维
.\.venv\Scripts\python.exe scripts/setup_lego_parameters.py --runtime runtime --dimension 650 --bits 8 --workers 4
# CIFAR-10，RGB 8×8 池化，1,930 维
.\.venv\Scripts\python.exe scripts/setup_lego_parameters.py --runtime runtime --dimension 1930 --bits 8 --workers 4
```

按数据集运行对应命令即可。当前本机 `runtime` 已安装上述两组 8 位开发参数；源码包不携带运行目录，新机器或新运行目录需要自行建立或安装匹配参数。仅新增 CRS 无需重启服务，在部署页点击“刷新已安装参数”，再选择匹配的参数。更改池化网格后，模型维度也会改变，需要安装该维度对应的 CRS；原有参数可以保留。明文基线无需执行这一步。

通过控制 API 创建加密实验时，使用 `"proof_suite":"lego_norm_v1"` 和已安装参数的完整 `proof_crs_hash`；可从 `GET /api/proof-parameters` 获取清单。新任务不接受旧 `legacy`、`compact_range_v1` 或 `compact_norm_v1` 方案。历史 [5B 示例配置](configs/acceleration-5b.json) 仅保留为研究材料，不能直接用于当前新建实验。

| 模式 | 用途与实际边界 |
| --- | --- |
| `plain` 明文基线 | 本地模型对主控可见；不做密码证明，无需 CRS；不做异常相似度筛选，按所选分组策略接纳成员。 |
| `encrypted` 加密聚合 | 使用真实密码与 LegoGroth16 证明验证，须选择匹配 CRS；跳过相似度异常筛选，按所选分组策略接纳成员。不是“完全不验证”的基线。 |
| `dgflow` DGFlow | 使用 LegoGroth16 进行密文验证，须选择匹配 CRS；执行参考方向评分、工程化异常筛选及成员接纳。参考方案与工程补充的归属见设计报告。 |
| `optimized` 改进策略 | 与 `dgflow` 保留同一验证及筛选路径，兼容历史模式名。自动执行对所有模式有界并行；串行对照须显式设置，速度差异必须以同配置实测判断。 |

默认 `regroup` 将至少两名合格成员重新组队，支持奇数人数。选择 `fixed` 时只接纳完整二人组；某成员被拒绝会连带排除其伙伴，声明人数为奇数时末位客户端不参与聚合。

实验支持 `dataset=mnist`（默认）和 `dataset=cifar10`，在部署页选择后准备对应数据。两者均使用线性 softmax 分类器，图像按池化网格降采样后展平。MNIST 默认 `grid=8` 为 64 维输入、650 参数，`grid=28` 为全分辨率、7,850 参数。CIFAR-10 保留 RGB 三通道，默认 `grid=8` 为 192 维输入、1,930 参数；受当前 20,000 维协议上限约束，实验入口支持 `grid=2–25`。CIFAR-10 数据集接入尚不代表论文 878,538 参数 CNN 的完整安全训练。

部署助手提前准备两种数据。单独准备 CIFAR-10 时，优先从 [MindSpore 官方镜像](https://www.mindspore.cn/tutorials/zh-CN/master/dataset/sampler.html) 下载约 162 MB 原始二进制包，网络失败后回退 Toronto 站点，并校验原始 MD5、安全解包到 `data/cifar10/raw`；加载与训练均离线运行：

```powershell
.venv\Scripts\python.exe -m dgfl.cli prepare-data --dataset cifar10
# 使用已有原始压缩包校验，不联网
.venv\Scripts\python.exe -m dgfl.cli prepare-data --dataset cifar10 --offline
```

可用 `--cifar-source HTTPS基址` 指定镜像，`--cifar-timeout 120 --cifar-retries 2` 调整超时与重试；启动脚本对应 `-CifarSource`。完整说明见[部署说明](docs/submission/deployment.md)。

API 使用 `POST /api/data/prepare`，请求体为 `{"dataset":"cifar10"}`；创建实验时同样传入 `"dataset":"cifar10"`。不带请求体的数据准备调用及缺少 `dataset` 的历史配置仍按 MNIST 处理。650 维 Lego 参数不能用于 1,930 维模型；所有新加密实验都须安装并选择维度匹配的 8 位参数，明文基线无需参数。

2026-10-07 已使用真实 CIFAR-10 的 1,200/400 个训练/测试样本，在独立 2 客户端、2 边缘、2 云集群完成明文、加密和 DGFlow 各一轮；三种模式的量化模型摘要一致，测试角色全部关闭。最终 Python 回归 2,116 项通过、12 项跳过，前端 86 项通过；详见 [CIFAR-10 接入验收](docs/research/evidence/cifar10-integration-20261007.json)。这是线性模型集成检查，不代表完整数据准确率、论文 CNN 或性能复现。

同日已安装 CIFAR-10 默认模型对应的 1,930 维、8 位开发 CRS，并在独立集群完成一轮 Lego DGFlow 验收：两客户端证明均有效，聚合模型与明文基线一致。原 650 维参数、主部署密钥及历史记录保留，详见 [CIFAR-10 Lego 参数验收](docs/research/evidence/cifar10-lego-crs-20261007.json)。

维度越高，密码链路的时延与通信量通常随之增长。默认 NumPy 路径在 CPU 上运行；可选 PyTorch 训练实现也使用 CPU/float64。可选 CUDA 后端用于密码批量计算，需通过节点能力检查。

## 必须保留的解释边界

- 数据是公开 MNIST 或 CIFAR-10 的本地重放与客户端划分，并非真实医院、企业或园区的天然数据孤岛；单机进程隔离也不等于独立机构信任域。
- s/w 与 e/v 描述密钥及聚合组件的门限恢复条件。新任务 DKG 仍需要全部 w 个边缘参加；主控作为 RPC 转发和编排节点仍是单点。不能宣称整台物理主机故障后系统必然继续工作，也不能据此声称完整论文安全或性能复现。
- 范围和平方范数关系校验约束提交的一致性，不能证明模型来自诚实训练，也不能证明没有投毒或后门。
- 系统允许公开平方范数、授权内积、相关评分及聚合模型。这些输出可能泄露信息；加密不等于零信息泄漏。
- 界面的“本轮排除聚合节点”是逻辑参与配置，不会终止节点进程，也不能单独作为真实进程宕机证据。

## 目录与证据

`src/dgfl` 为 Python 实现，`web` 为前端，`configs` 为局域网配置示例，`scripts` 为启动和打包工具，`tests` 为测试，`docs/submission` 为匿名交付文档。公开数据缓存写入 `data/mnist`、`data/cifar10`，身份材料写入 `runtime`。

实验记录保存在 `runtime/results/<run_id>/result.json`。界面导出使用同一份后端记录，包含配置、逐轮结果、事件、公开验证信息与汇总指标；未完成的轮次不补造准确率。性能结论不从截图推断。

打包前运行测试并检查匿名材料。完整命令与打包边界见部署说明。默认包包含完整前端源码和构建结果，排除运行时私钥、环境与数据缓存；需要离线重建时，先生成经过校验的 `offline` 目录，再明确使用 `--include-offline` 纳入依赖 wheel 与公开 MNIST 数据。
