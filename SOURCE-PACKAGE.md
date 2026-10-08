# DGFlow 源码项目说明

当前目录保留 P1/P2 修复后的代码，已从实验工作目录整理为源码项目。清理仅归档运行材料和生成物，不回退算法、不删除功能，也不初始化或改写 Git 历史。

## 保留内容

- `src/`：Python 服务、训练、密码协议与 CUDA 源码。
- `native/dgfl-native/`：Rust 源码、Cargo.toml、Cargo.lock 和构建配置。
- `web/`：Vue 源码、测试、测试样本、依赖清单及锁文件。
- `tests/`、`scripts/`、`configs/`、`.github/`：回归测试、工具、部署示例与 CI。
- `docs/`：协议说明、研究说明、参考论文及报告资源。部分历史证据由报告生成器和回归测试直接使用，作为必要项目资源保留。
- 根目录 README、依赖清单、pyproject.toml、第三方声明与忽略规则。

完整 CNN 仍是独立本地训练模块，尚未接入安全联邦服务。单归属验证、门限可用性和开发 CRS 的边界仍以 README 与协议说明为准。

## 已归档内容

归档位于项目同级目录 `DGFlow-source-671a850-archive-20261008-01/`，其中保持原相对路径：

- `runtime/`：原部署、身份密钥、CRS、实验结果、节点状态和日志。
- `data/`、`offline/`：公开数据缓存及离线安装材料。
- `tmp/`、`dist/`、`native/wheels/`：临时实验、历史源码包和编译好的 wheel。
- `.venv/`、`web/node_modules/`：原依赖环境。
- `web/dist/`、`native/dgfl-native/target/`：前端和 Rust 构建产物。
- Python 缓存、egg-info、工具缓存，以及历史 `source-history.bundle`、`SOURCE-MANIFEST.json`。

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

若要沿用旧部署，先将归档中的 `runtime/` 和需要的数据缓存复制回原相对路径，再启动服务。这样才能继续使用原身份、拓扑、CRS 与历史记录；不要先创建新的同名部署再覆盖。

首次重新安装原生扩展时，可使用归档 `dist/native/` 中经摘要核对的匹配 wheel，或按 README 从 `native/dgfl-native` 构建。旧 `source-history.bundle` 只含原包历史，需要历史微基准时从归档恢复该文件；它不是当前修改的 Git 历史。

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

本目录不保留已过期的冻结清单。需要发布包时，先完成测试与前端构建，再运行 `scripts/freeze_source.py`；它会生成新的 SOURCE-MANIFEST.json，并可通过 `--archive dist/source-release/source.zip` 生成发布包。运行时数据、依赖环境和构建缓存不应加入源码版本控制。
