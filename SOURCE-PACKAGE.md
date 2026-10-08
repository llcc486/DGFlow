# DGFlow 源码项目说明

当前源码版本包含双数据集镜像下载、完整部署准备、GPU 自动识别和此前 P1/P2 修复。源码、测试、配置和必要文档保留；运行材料由部署脚本生成，并由 Git 忽略。

## 本次源码版本

版本标识：`dgflow-20261008-complete-deployment-source`。

MNIST 与 CIFAR-10 均支持 HTTPS 镜像、有限重试、自定义下载源及 `prepare-data --offline`。CIFAR-10 优先使用 MindSpore 官方镜像，回退原始站点，固定校验原始 MD5。部署助手在打开服务之前完成训练依赖、完整原生密码扩展、GPU 编译依赖、两种数据集和前端准备。

GPU 硬件识别不依赖 NVIDIA Python 包；部署时自动安装所需 NVRTC，控制服务启动后自动对主控与边缘节点执行精确密码运算自检。默认计算设备仍为 CPU，自检通过后可在页面选择 GPU。

当前新建加密实验只使用 LegoGroth16（`lego_norm_v1`），必须安装并选择当前模型维度、8 位量化对应的 CRS。`plain` 明文基线不生成密码证明，无需 CRS。旧逐坐标、5A/5B 方案及原性能证据保留用于历史记录与研究核对，不再是当前新实验的选项。

本机已完成全新环境部署、禁网离线检查和 CIFAR-10 / Torch / GPU 真实流程验证，详见[部署验收记录](docs/research/evidence/deployment-ready-20261008.json)。

纯源码包包含前端源码和依赖清单，不包含已安装的环境、完整数据缓存、前端构建产物或运行密钥。需要发布时，按本文末尾命令冻结当前源码。

## 保留内容

- `src/`：Python 服务、训练、密码协议与 CUDA 源码。
- `native/dgfl-native/`：Rust 源码、Cargo.toml、Cargo.lock 和构建配置。
- `web/`：Vue 源码、测试、测试样本、依赖清单及锁文件。
- `tests/`、`scripts/`、`configs/`、`.github/`：回归测试、工具、部署示例与 CI。
- `docs/`：协议说明、研究说明、参考论文及报告资源。部分历史证据由报告生成器和回归测试直接使用，作为必要项目资源保留。
- 根目录 README、依赖清单、pyproject.toml、第三方声明与忽略规则。

完整 CNN 仍是独立本地训练模块，尚未接入安全联邦服务。单归属验证、门限可用性和开发 CRS 的边界仍以 README 与协议说明为准。

## 生成物与既有部署

全新安装不依赖旧部署归档。以下内容由部署或实验生成，不应加入源码包：

- `runtime/`：原部署、身份密钥、CRS、实验结果、节点状态和日志。
- `data/`：已校验的 MNIST 与 CIFAR-10 公开数据缓存。
- `dist/`：上次生成的源码 ZIP、交付清单和校验文件。
- `.venv/`、`web/node_modules/`：原依赖环境。
- `web/dist/`：前端构建产物。
- Python 缓存、egg-info，以及根目录的 `SOURCE-MANIFEST.json`。
- `tmp/native-toolchain/`：项目私有 Rust 工具链、Cargo 缓存、匹配 wheel 与构建指纹。

若自行保留过旧部署归档，可以恢复对应 `runtime/` 和公开数据后继续使用原身份、拓扑、CRS 与历史记录；不要先创建新的同名部署再覆盖。旧虚拟环境不要跨机器或跨操作系统复制。

## 从源码启动

安装 Python 3.12、Node.js 22.12+ 与 npm，并具备系统 C/C++ 构建工具。Windows 原生构建需要 Visual Studio C++ 工具和 Windows SDK，Linux 需要 C/C++ 编译器。NVIDIA GPU 需要系统驱动；其余项目依赖由脚本准备。在项目根目录执行：

```powershell
powershell -ExecutionPolicy Bypass -File scripts/start_demo.ps1 -SetupOnly
powershell -ExecutionPolicy Bypass -File scripts/start_demo.ps1 -Offline
```

第一条联网完成部署，不启动任何节点或控制服务；第二条仅使用已部署环境和缓存启动。直接省略 `-SetupOnly` 也可完成部署后立即启动。Linux 对应 `bash scripts/start_demo.sh --setup-only` 和 `bash scripts/start_demo.sh --offline`。

部署成功后 `.venv/dgflow-deployment.json` 记录依赖版本、原生源码与二进制摘要、GPU 自检、数据及前端状态。失败时不会发布就绪标记，也不会启动服务。源码变化后会重新核对原生与前端构建指纹，旧版本号相同的原生二进制不能冒充当前构建。

下载源可在部署时指定：

```powershell
powershell -ExecutionPolicy Bypass -File scripts/start_demo.ps1 -SetupOnly -CifarSource https://mindspore-website.obs.cn-north-4.myhuaweicloud.com/notebook/datasets/
```

Linux 使用 `DGFL_MNIST_SOURCE` / `DGFL_CIFAR_SOURCE` 环境变量。镜像和离线缓存校验详见[部署说明](docs/submission/deployment.md)。运行中的训练不会下载数据或安装依赖，GPU 内核只在本地编译。Lego 的模型专用 CRS 需单独建立；默认 MNIST 为 650 维、CIFAR-10 为 1,930 维，均为 8 位量化，命令见 [README](README.md)。当前本机 `runtime` 已安装这两组开发参数，但它们不随源码包分发，新机器或新运行目录需另行准备。仅增加参数后，在网页刷新已安装参数并选择匹配指纹即可，无需重启服务。

`scripts/prepare_offline.py` 仍是基础 NumPy + MNIST 材料工具，不包含完整启动所需的 Torch、GPU、当前原生扩展和 CIFAR-10，也不包含模型专用 CRS。只安装这个旧式基础包可用于明文最小演示，不足以通过完整部署检查或运行新加密实验；完整离线启动应先在目标平台完成上述部署，并为加密实验单独准备参数。

## 验证与发布

```powershell
.\.venv\Scripts\python.exe -m ruff check src tests
.\.venv\Scripts\python.exe -m pytest -q
Push-Location web
npm.cmd test
npm.cmd run build
Pop-Location
```

测试依赖需开发者另行安装，例如 `python -m pip install -e ".[test]"`；应用运行不依赖 pytest 或 Ruff。历史 P1/P2 验收保留在 `docs/research/evidence/p1p2-fixes-20261008.json`。

生成纯源码包时，先完成相关测试，然后运行：

```powershell
.\.venv\Scripts\python.exe -B scripts/freeze_source.py --source-only --release-id dgflow-20261008-complete-deployment-source --archive dist/source-release/dgflow-20261008-complete-deployment-source/source.zip
.\.venv\Scripts\python.exe -B scripts/freeze_source.py --verify
```

`--source-only` 排除 `web/dist`、离线材料、历史 Git bundle、数据集、运行目录、环境与构建缓存。需要包含前端构建结果的原有交付模式时，先构建前端并省略此选项。冻结工具会生成新的 SOURCE-MANIFEST.json；运行时数据、依赖环境和构建缓存不应加入源码版本控制。
