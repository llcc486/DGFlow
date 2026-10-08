# 部署说明

下列命令从项目根目录执行，路径均为相对路径。此前单机 12 节点配置、650 参数与 7,850 参数的一轮运行均已完成真实验证；2026-10-06 新默认为 13 个角色，旧性能记录只代表其原配置。本文的三机步骤是可执行部署路径，尚不能作为已经完成三台物理机器测试的声明。最终验收结果以设计报告和实测记录为准。

## 1. 环境与安装

- 项目声明 Python 3.11+；当前锁定环境为 CPython 3.12。复验优先使用 3.12，其他版本先核验依赖兼容性。底层依赖为 `py-arkworks-bls12381==0.5.0`，需要匹配平台和解释器的 wheel，或者具备对应源码编译环境。
- 完整前端源码构建使用 Node.js 22.12+ 或 24 与 npm。提交包已带 `web/dist` 时运行服务不需要 Node.js。
- 首次安装和所选 MNIST / CIFAR-10 数据下载需要网络。离线运行要求事先准备好 Python 环境、完整数据缓存和前端构建结果；“无 CDN”不等于首次安装无需联网。
- 本版本默认 CPU 训练。可选 PyTorch 实现使用 CPU/float64；不用购买或分配 GPU 才能运行这一原型。

Windows 按锁定依赖手动安装：

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements-lock.txt
.\.venv\Scripts\python.exe -m pip install --no-build-isolation --no-deps -e .
.\.venv\Scripts\python.exe -m pip check
```

基础锁文件对应 NumPy 演示环境，包含运行依赖与构建工具，不包含测试依赖和可选 PyTorch。需要执行测试时另装 `pip install -e ".[test]"`；需要可选 CPU 训练后端时另装 `pip install -r requirements-torch.txt`。这两个命令中的 `pip` 均应使用本项目虚拟环境的 `python -m pip`。

完整源码构建前端：

```powershell
Set-Location web
npm.cmd ci
npm.cmd run build
Set-Location ..
```

Linux 手动环境使用 `python3 -m venv .venv`，将下文的 Python 路径改为 `.venv/bin/python`；前端用 `npm`。不同操作系统不得直接复制整个虚拟环境，应重新安装匹配平台的依赖。

## 2. 单机部署

一次性准备并初始化：

```powershell
.\.venv\Scripts\python.exe -m dgfl.cli prepare-data
.\.venv\Scripts\python.exe -m dgfl.cli init
```

`init` 创建身份、证书、公开注册表和 `runtime/cluster.json`。已有配置或密钥时会拒绝覆盖。以后重启应复用此目录，不要每次重新初始化；需要全新身份时选择新的运行目录，而不是覆盖旧密钥。

新部署默认 n=6 个客户端、w=3 个边缘授权节点、v=4 个云聚合节点。客户端范围 2–100，边缘与云范围分别为 2–32；边缘门限 s 为 2–w，云门限 e 为 2–v。对应 CLI 参数为 `--client-count`、`--authority-count`、`--aggregator-count`、`--authority-threshold`、`--aggregator-threshold`，`init`、`start`、`demo` 均支持。两个门限初始默认均为 2；当前密码实现不支持小于 2 的门限。

每个客户端恰好归属一个边缘，默认 `clientN → authority((N−1) mod w+1)`，这是工程分配规则。原始证明与提交只到归属边缘，所有边缘共享函数钥份额；归属边缘执行证明核验与 VerDec，再共享签名的余弦、范数、摘要和密文核心，供所有边缘共同筛选与授权。V/VerDec 是边缘内部操作。详细对照见[分层拓扑说明](../research/hierarchical-topology-20261006.md)。

新建 n=20、w=3、v=4、s=2、e=3 的独立本机集群：

```powershell
.\.venv\Scripts\python.exe -m dgfl.cli init --runtime runtime-paper --client-count 20 --authority-count 3 --aggregator-count 4 --authority-threshold 2 --aggregator-threshold 3
.\.venv\Scripts\python.exe -m dgfl.cli start --runtime runtime-paper
.\.venv\Scripts\python.exe -m dgfl.cli serve --runtime runtime-paper
```

已有本机集群空闲时可通过部署页显式应用，或停掉控制服务后执行带参数的 `start`。未提供的边缘/云数量与门限沿用既有值；不带拓扑参数的 `start`/`demo` 沿用全部既有设置。旧 `cluster.json` 缺字段时按连续节点清单推断数量，门限默认 2，历史 6/3/3 不会在普通重启时扩成 6/3/4。

默认分组策略 `regroup` 接纳任意至少两名合格成员，奇数人数可正常聚合。`fixed` 只接纳完整二人组；声明人数为奇数时末位客户端不参与聚合，伙伴被拒绝的成员也会退出该组。页面等待全部部署节点在线后允许创建实验；运行中客户端掉线仍保留声明成员名单，并按合格人数和所选分组策略决定能否聚合。

拓扑调整保留签名身份、密钥交换身份、实验结果、数据缓存和证明参数。新单机初始化预留最多 100 个客户端、32 个边缘及 32 个云的身份，预留身份不会成为活动节点或任务成员。历史部署缺少新增身份时沿安全事务路径扩容并轮换本机 TLS 证书；CA 签名私钥仍不落盘。角色数量或门限变化会在校验进程归属后停止并重启受管活动角色，失败时恢复原配置和凭据；缩容不删除退役身份，退役节点不能参加新任务。运行中的实验禁止改变拓扑；三机部署需要显式列出全部主机并重新分发，不通过本机页面自动重配。

启动节点，再启动本机控制服务：

```powershell
.\.venv\Scripts\python.exe -m dgfl.cli start
.\.venv\Scripts\python.exe -m dgfl.cli serve
```

也可用 `python -m dgfl.cli demo` 组合“缺失时初始化、启动节点、运行控制服务”，其中 `python` 应为已安装本项目的解释器。`scripts/start_demo.ps1` 和 `scripts/start_demo.sh` 在此基础上处理依赖与数据准备。启动脚本不会替代前端构建。

在另一终端检查：

```powershell
.\.venv\Scripts\python.exe -m dgfl.cli doctor
```

打开 [本机控制页](http://127.0.0.1:8765)。控制界面仅面向本机浏览器；当前 Host/Origin 检查不支持把 8765 任意暴露到公网或直接作为远程管理服务。

浏览器控制请求必须与接收请求的页面来源完全一致，包括协议、主机名和端口；`localhost` 与 `127.0.0.1` 也属于不同来源。没有 `Origin` 头的本机命令行请求仍可使用。所有控制请求的实际正文上限为 32 KiB，分块传输同样受限，超限时在执行操作前返回 413。开发用 Vite 代理保留浏览器访问的 `Host`；若自行添加本机反向代理，应同样保留 `Host`，并仅通过受信代理配置传递 HTTPS 协议信息。

| 角色 | 身份与单机端口 |
| --- | --- |
| authority | `authority1`–`authorityW`，9101–`9100+W`；W 为 2–32，默认 3 |
| aggregator | `aggregator1`–`aggregatorV`，9201–`9200+V`；V 为 2–32，默认 4 |
| client | `client1`–`clientN`，9301–`9300+N`；N 为 2–100，默认 6 |
| coordinator / 控制服务 | 本机 8765；另有用于节点 RPC 的独立身份 |

节点采用 HTTPS/mTLS，控制页面与节点 RPC 不是同一个端口。单机节点监听回环地址。节点日志位于 `runtime/logs`，受管进程记录在 `runtime/pids`，实验结果在 `runtime/results`。

关闭控制服务使用 `Ctrl+C`；随后停止受管节点：

```powershell
.\.venv\Scripts\python.exe -m dgfl.cli stop
```

停止工具会核对 PID、创建时间、命令和路径再结束进程。若返回 `refused`，应人工排查身份不匹配，不要直接杀死该 PID。

## 3. 三机局域网部署

### 3.1 拓扑与边界

先准备 A、B、C 三台机器的稳定内网 IPv4 地址。示例地址只作配置示意，需要替换成实际地址。

| 主机 | 运行角色 | 示例地址 | 需要允许的节点端口 |
| --- | --- | --- | --- |
| A | authority1、aggregator1、aggregator4、client1、client4、coordinator | 192.168.10.11 | 9101、9201、9204、9301、9304 |
| B | authority2、aggregator2、client2、client5 | 192.168.10.12 | 9102、9202、9302、9305 |
| C | authority3、aggregator3、client3、client6 | 192.168.10.13 | 9103、9203、9303、9306 |

防火墙仅向这组实验机器开放需要的节点端口。A 本机浏览器访问 8765；B、C 不需要取得 coordinator 私钥，也不需要启动控制服务。

三机部署仍在每台机器上托管多个角色。它改善进程和主机分布，但不是完整的独立机构治理或安全隔离证明。整台 B/C 故障会同时失去 authority、aggregator 和两个客户端，不能等同于只失去一个聚合器。

### 3.2 一次性配置和按主机分包

在受控的初始化环境中复制并编辑配置：

```powershell
Copy-Item -LiteralPath .\configs\hosts.example.yaml -Destination .\configs\hosts.lan.yaml
```

将文件中各 `host` 改为真实内网 IP，保留示例全部 13 个活动角色身份及 A/B/C 归属。配置只接受主机地址，不填写 `https://` 或端口；角色端口由程序确定。coordinator 必须属于 A。

此示例使用 n=6、w=3、v=4、s=2、e=2，与新默认一致。其他规模应显式列出连续的 `client1`–`clientN`、`authority1`–`authorityW`、`aggregator1`–`aggregatorV`，初始化时传相同的数量与门限。保留旧三云 YAML 时必须传 `--aggregator-count 3`；不要遗漏节点后依靠自动发现。

使用一个全新的专用目录初始化，再分包：

```powershell
.\.venv\Scripts\python.exe -m dgfl.cli init --runtime provisioning-runtime --hosts configs/hosts.lan.yaml
.\.venv\Scripts\python.exe -m dgfl.cli bundle --runtime provisioning-runtime --output machine-bundles
```

输出 `machine-bundles/A/runtime`、`machine-bundles/B/runtime`、`machine-bundles/C/runtime`。每包包含公共 CA、公开身份注册表、共同集群配置、主机标记，以及**本机角色的私钥/身份文件**。只有 A 包包含 coordinator 的私钥。

此初始化工具是集中式的身份/证书准备工具；它与每轮模型加密用的 DKG 不同。初始化目录暂时持有整套传输身份，因此必须保留在受控离线准备环境，不能作为常规三机运行目录到处分发。**不要把完整 `provisioning-runtime/keys` 或全部 machine-bundles 一起复制给每台机器。**

### 3.3 分别安装并启动

每台机器使用同一版本程序，但使用全新的目标运行目录。把对应主机包内的 `runtime` 放到该机器项目根目录的 `runtime`；不要覆盖旧部署目录或合并另一主机的密钥。示例在 A 的新项目目录中：

```powershell
Copy-Item -LiteralPath .\machine-bundles\A\runtime -Destination .\runtime -Recurse
```

B/C 仅接收各自的包并按同样布局放置。三个项目目录各自安装 Python 依赖。每台机器都提前准备公开 MNIST 缓存：

```powershell
.\.venv\Scripts\python.exe -m dgfl.cli prepare-data
```

此处下载/复制的是公开数据。完整缓存位于各项目的 `data/mnist/raw`，训练时按规则选择本地分区；不要称为三个现实机构各自收集的数据。加载器不会在训练期间自动联网下载。

运行 CIFAR-10 时，每台承载客户端的机器以及主控 A 也必须提前准备对应缓存：

```powershell
.\.venv\Scripts\python.exe -m dgfl.cli prepare-data --dataset cifar10
```

缓存位于各项目的 `data/cifar10/raw`。控制台的数据准备只处理主控本机缓存，不会替 B/C 下载；首次准备约下载 162 MB 官方二进制包。现有离线依赖打包工具只自动纳入 MNIST，CIFAR-10 缓存需单独复制并在目标机器显式执行准备命令复核摘要。实验选择 `dataset=cifar10`，默认 RGB 8×8 池化、1,930 参数线性模型；当前入口支持网格 2–25，尚未接通论文完整 CNN 安全训练。

分别执行：

```powershell
# A
.\.venv\Scripts\python.exe -m dgfl.cli start --machine A
# B（在 B 的终端）
.\.venv\Scripts\python.exe -m dgfl.cli start --machine B
# C（在 C 的终端）
.\.venv\Scripts\python.exe -m dgfl.cli start --machine C
```

仅在 A 启动控制服务并执行全群健康检查：

```powershell
.\.venv\Scripts\python.exe -m dgfl.cli serve
.\.venv\Scripts\python.exe -m dgfl.cli doctor
```

`serve` 常驻当前终端，因此 `doctor` 应在 A 的另一个终端执行。B/C 包故意不含 coordinator 身份，当前 `doctor` 的全群 RPC 检查在 B/C 会报告缺少 coordinator；不要为消除这个提示而把 A 私钥复制过去。

若改用自定义 `--runtime`，当前控制/训练代码从该目录的父目录寻找 `data/mnist`。把运行目录放在项目根目录的直接子目录下最容易保持数据路径一致；不要仅把 `--runtime` 指向嵌套分包目录，却仍假设使用默认数据路径。

关闭时在每台机器分别执行匹配的 `stop --machine A/B/C`。它会停止该机所有受管角色，不适合用来模拟“只停止一个聚合器”。

### 3.4 mTLS 检查

证书的地址在初始化时与配置绑定。修改 IP 后只编辑 `cluster.json` 可能导致证书名称不匹配，应使用新目录重新准备配置和身份。不要把 `verify=False`、关闭证书校验、开放任意来源当作部署解决方案。

全群验收至少保留 A/B/C 上各自角色清单、节点健康记录、一次完整真实任务、结果哈希与实际网络配置。没有这些证据时，将状态写为“三机部署说明已提供，物理环境实测待完成”。

## 4. 可用性实验的正确解释

界面的“本轮排除聚合节点”范围是 0–v，仅改变聚合调用的参与名单；剩余 v−排除数 必须至少达到 e，否则拒绝启动。新默认 e=2、v=4 时排除两云仍满足门限，排除三云不足；旧 e=2、v=3 则排除两云不足。此设置不会关闭任何服务，健康页仍可能显示被排除的云在线。

真实进程崩溃测试需要另外记录具体聚合进程、故障时点、剩余健康状态和是否发布模型。当前编排会预检所需节点，并不承诺自动识别任意时点的崩溃后重新选择参与者。已得到足够合法份额时的门限恢复、主动逻辑排除和自动故障切换是三件不同的事。

新任务 DKG 仍依赖全部 w 个边缘完成准备，不由 s/w 恢复门限推导出 DKG 可容错。主控承担工程 RPC 转发与编排，仍是单点；它退出后需重启服务，新加载的未结束记录会被标为中止，不能宣称无缝恢复正在执行的密码轮次。固定批次也会放大客户端退出的可用性损失。此拓扑调整不构成完整论文安全、性能或 PFLlib CNN 复现。

## 5. 测试、离线复验和提交包

已安装测试依赖后运行：

```powershell
.\.venv\Scripts\python.exe -m pytest
```

MNIST 实际训练检查脚本位于 `tests/training/run_mnist_smoke.py`；它的参数应先用 `--help` 核对。公开训练缓存不是测试成功的替代证据。

依赖和数据已经准备完成时，Windows 使用 `start_demo.ps1 -Offline`，Linux 使用 `start_demo.sh --offline`。缓存校验失败会报错，不会静默改写损坏文件。

### 5.1 准备可重建的离线依赖与公开数据

在与目标环境匹配、能够联网的准备机器上，先完成基础依赖安装和 MNIST 校验，再执行：

```powershell
.\.venv\Scripts\python.exe -m dgfl.cli prepare-data
.\.venv\Scripts\python.exe scripts/prepare_offline.py --output offline
.\.venv\Scripts\python.exe scripts/prepare_offline.py --output offline --verify-only
```

准备工具下载基础锁文件中的对应 wheel，复制经过检查的四个 MNIST 原始压缩文件，生成 `offline/manifest.json` 与 `offline/INSTALL.txt`。清单记录文件大小、SHA-256、Python 版本和平台。它不包含节点身份、可选 Torch、CUDA 或 Python 解释器。输出目录已存在时工具会拒绝覆盖；使用 `--verify-only` 复查原目录，或者选择新目录重新准备。已有完整匹配 wheel 缓存时，可追加 `--wheelhouse cached-wheels` 避免再次下载。

目标机器需事先安装与清单匹配的 Python 解释器与操作系统架构。在新的项目目录中，按包内 `offline/INSTALL.txt` 操作。例如，清单确为 Windows x64 / CPython 3.12 时：

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\python.exe -m pip install --no-index --find-links offline/wheelhouse -r offline/requirements-lock.txt
.\.venv\Scripts\python.exe -m pip install --no-index --no-build-isolation --no-deps -e .
.\.venv\Scripts\python.exe -c "import shutil; shutil.copytree('offline/data/mnist', 'data/mnist', dirs_exist_ok=True)"
.\.venv\Scripts\python.exe scripts/prepare_offline.py --output offline --verify-only
.\scripts\start_demo.ps1 -Offline
```

示例以新的数据目录为前提；不要用复制操作覆盖尚需保留的旧实验数据。三机部署时，先分别放好各自的 runtime 包；A 可使用 `start_demo.ps1 -Offline -Machine A`。B/C 完成上述安装和数据复制后，只执行第 3 节的 `cli start --machine B/C` 命令。当前 `demo` 与一键脚本会继续启动控制服务，因此不推荐在 B/C 使用该入口。离线 wheel 包只适用于其记录的平台与解释器，不是通用的跨平台安装包。测试依赖未纳入基础离线锁；要离线执行 pytest，需要另行准备并记录测试依赖。

### 5.2 运行实验矩阵与打包

在节点与控制服务已启动、没有其他活动任务时，将复验记录写入新的本地目录：

```powershell
.\.venv\Scripts\python.exe scripts/run_experiments.py --config configs/experiments.yaml --output runtime/reproductions/formal
```

包内 `docs/submission/evidence` 保存原始交付证据，供查阅与核对，不作为新机器的任务输出目录。矩阵脚本恢复运行时会复用输出目录中的任务标识，因此只有保留原 `runtime` 及其中任务记录、配置也未变化时，才能恢复原输出。更换机器、重新初始化运行目录或修改配置后，都应选择新的输出目录。失败或中止应保留并解释；不能删除失败记录后声称全部成功。具体矩阵配置与性能结论以设计报告为准。

上述矩阵结束后，完整 MNIST 复验使用另一配置和输出目录：

```powershell
.\.venv\Scripts\python.exe scripts/run_experiments.py --config configs/full-data-experiment.yaml --output runtime/reproductions/full-data
```

真实进程故障检查应在所有训练任务结束、实际单机全部活动节点恢复在线后单独执行。脚本按当前 v/e 停止足够的云，分别验证恰好满足和低于门限，再检查固定分组下的客户端缺席；所有进程先核对归属，随后恢复本次停止的角色。不要与训练矩阵同时运行：

```powershell
.\.venv\Scripts\python.exe scripts/run_fault_checks.py --output runtime/reproductions/faults
```

故障检查不恢复旧输出，重复复验需另选尚不存在的输出目录；保留原故障记录及脚本的恢复状态。

具备 README、源码和设计报告后，可生成可核验提交包：

```powershell
.\.venv\Scripts\python.exe scripts/package_submission.py --output dist/submission
```

当前打包器输出 `source.zip` 与 `manifest.json`，记录每个文件的大小和 SHA-256，并检查实际包加清单小于 4 GiB。若主办方对“4G”采用不同口径，以其最终要求为准，提交前人工核对实际大小。

打包采用白名单，默认包含后端源码、测试、配置、完整前端源码及其构建结果、前端锁文件和提交文档；排除 `node_modules`、运行时密钥、完整数据缓存、虚拟环境和开发计划。默认源码 ZIP 不包含可重建的离线依赖包。

如已生成并验证项目根目录中的 `offline`，使用以下命令把经过验证的离线材料一并交付：

```powershell
.\.venv\Scripts\python.exe scripts/package_submission.py --output dist/submission --include-offline
```

打包器重新校验离线清单后才纳入 wheel 与公开数据。核对最终 `manifest.json`，确认实际包含需要的源码、构建结果、文档和离线材料；工具可用不等于本次发布已经完成离线重装实测。

对包含 `offline` 的包执行独立重装校验：

```powershell
.\.venv\Scripts\python.exe scripts/validate_release.py --package dist/submission --output tmp/release-checks
```

校验器会在指定输出目录下新建唯一工作目录，验证 ZIP 与清单，创建全新虚拟环境，从包内 wheel 离线安装，再检查命令入口、真实小向量密码流程、MNIST 读取及前端构建产物。它不启动节点，也不使用现有 `runtime`。默认保留 `release-check-*/report.json` 并清理本次环境；追加 `--keep` 可保留本次解包目录与新环境。当前发布包的 wheel 针对 Windows x64 / CPython 3.12，需在匹配环境下执行。

静态扫描会拒绝敏感密钥文件、明显绝对开发路径和自有材料中的身份字段，但不等于完整匿名性证明。发布前人工检查截图、异常日志、文件属性及文档内容；上游公开版权归属须保留，不应为了匿名而删除第三方许可。
