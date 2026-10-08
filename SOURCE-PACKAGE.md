# DGFlow 源码项目说明

当前目录已直接整理为最新纯净源码项目，包含 MNIST 下载容错和此前 P1/P2 修复。运行材料和生成物已移到项目外归档；源代码、测试、配置、必要文档及 Git 历史保留。

## 本次源码版本

版本标识：`dgflow-20261008-mnist-download-fix-source`。

在 P1/P2 修复基础上加入 MNIST 下载容错：默认两个 HTTPS 下载源，网络失败后有限重试；支持指定 HTTPS 源、调整网络超时和重试轮数，以及 `prepare-data --offline` 校验本地缓存。Windows/Linux 启动脚本会将离线选项传递给数据准备命令。相关训练数据、CLI、启动脚本及控制 API 回归共 379 项通过、1 项跳过，修改文件的 Ruff 检查通过。

纯源码打包与现有交付打包的相关回归另有 83 项通过、2 项跳过。

当前目录包含前端源码和依赖锁文件，首次使用需要安装依赖并构建前端。上次生成的 ZIP、交付清单与校验文件已移入归档；工作目录不保留生成的清单。需要再次发布时，按本文末尾命令重新冻结当前源码。

## 保留内容

- `src/`：Python 服务、训练、密码协议与 CUDA 源码。
- `native/dgfl-native/`：Rust 源码、Cargo.toml、Cargo.lock 和构建配置。
- `web/`：Vue 源码、测试、测试样本、依赖清单及锁文件。
- `tests/`、`scripts/`、`configs/`、`.github/`：回归测试、工具、部署示例与 CI。
- `docs/`：协议说明、研究说明、参考论文及报告资源。部分历史证据由报告生成器和回归测试直接使用，作为必要项目资源保留。
- 根目录 README、依赖清单、pyproject.toml、第三方声明与忽略规则。

完整 CNN 仍是独立本地训练模块，尚未接入安全联邦服务。单归属验证、门限可用性和开发 CRS 的边界仍以 README 与协议说明为准。

## 已归档内容

本次归档位于项目同级目录 `DGFlow-source-671a850-archive-20261008-02/`，其中保持原相对路径：

单独分发当前源码目录时不包含该归档。全新安装不依赖旧部署归档；已有公开数据缓存可单独复用以避免再次下载。

- `runtime/`：原部署、身份密钥、CRS、实验结果、节点状态和日志。
- `data/`：已校验的完整 MNIST 公开数据缓存。
- `dist/`：上次生成的源码 ZIP、交付清单和校验文件。
- `.venv/`、`web/node_modules/`：原依赖环境。
- `web/dist/`：前端构建产物。
- Python 缓存、egg-info，以及根目录的 `SOURCE-MANIFEST.json`。

归档目录内的 `cleanup-manifest.json` 记录移动路径及整理前摘要，`cleanup-verification.json` 记录整理后的校验结果；`before-docs/` 保存整理前的入口文档和忽略规则。归档保留原始数据，未进行不可恢复删除。

## 从源码启动

在项目根目录创建新的 Python 环境，并构建前端：

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements-lock.txt
.\.venv\Scripts\python.exe -m pip install -e ".[dev]"
Push-Location web
npm.cmd ci
npm.cmd run build
Pop-Location
powershell -ExecutionPolicy Bypass -File scripts/start_demo.ps1
```

启动脚本会准备 MNIST 并为不存在的运行目录初始化新部署。CIFAR-10、可选 Torch、原生扩展及 Lego 参数的准备见 README。归档的虚拟环境仅作备份，开发时按上述命令重新创建环境。

MNIST 下载超时时，可以延长 `prepare-data --mnist-timeout 120` 的等待时间，或在联网机器准备后复制四个原始 `.gz` 文件到 `data/mnist/raw`，再执行 `prepare-data --offline` 验证。默认已支持备用 HTTPS 源和有限重试；完整命令与缓存清单见[部署说明](docs/submission/deployment.md#mnist-下载超时与离线复用)。

本机已将完整 MNIST 缓存保存到本次归档。安装依赖后，若当前源码目录还没有 `data/`，可复用缓存：

```powershell
Copy-Item -LiteralPath ..\DGFlow-source-671a850-archive-20261008-02\data -Destination .\data -Recurse
.\.venv\Scripts\python.exe -m dgfl.cli prepare-data --offline
```

若要沿用旧部署，先将归档中的 `runtime/` 和需要的数据缓存复制回原相对路径，再启动服务。这样才能继续使用原身份、拓扑、CRS 与历史记录；不要先创建新的同名部署再覆盖。

首次安装原生扩展时，按 README 从 `native/dgfl-native` 构建，或使用另行保留且经摘要核对的平台匹配 wheel。本次归档没有原生 wheel 或 `source-history.bundle`；部分依赖旧 Git bundle 的历史微基准需要另行取得对应历史材料。

## 验证与发布

```powershell
.\.venv\Scripts\python.exe -m ruff check src tests
.\.venv\Scripts\python.exe -m pytest -q
Push-Location web
npm.cmd test
npm.cmd run build
Pop-Location
```

P1/P2 修复验收保留在 `docs/research/evidence/p1p2-fixes-20261008.json`。本次目录整理不改变该代码版本。

生成纯源码包时，先完成相关测试，然后运行：

```powershell
.\.venv\Scripts\python.exe -B scripts/freeze_source.py --source-only --release-id dgflow-20261008-mnist-download-fix-source --archive dist/source-release/dgflow-20261008-mnist-download-fix-source/source.zip
.\.venv\Scripts\python.exe -B scripts/freeze_source.py --verify
```

`--source-only` 排除 `web/dist`、离线材料、历史 Git bundle、数据集、运行目录、环境与构建缓存。需要包含前端构建结果的原有交付模式时，先构建前端并省略此选项。冻结工具会生成新的 SOURCE-MANIFEST.json；运行时数据、依赖环境和构建缓存不应加入源码版本控制。
