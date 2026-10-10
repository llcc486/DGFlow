# 监控与 TensorBoard 接入验收（2026-10-08）

基于 GitHub 新版 `a8f495f1d59f0719cb78e07bf7a0ad2ce54e08f5` 增加监控功能。实现没有调整训练算法、证明构造或聚合结果。使用说明见[监控手册](../submission/monitoring.md)。

## 完成内容

- 监控页提供全局模型测试准确率、交叉熵损失、整机/实验进程 CPU、GPU、显存、系统内存/RSS、磁盘曲线。
- 新增系统容量与实验进程采样，运行中读取独立快照，结束后保存到现有证据。未知值保持 null。
- 自动写入真实 TensorBoard event 文件，支持旧记录补录、重复补录去重、多实例写入和受损尾部恢复。
- 同源挂载原生 TensorBoard Core / Scalars，支持平滑、缩放、按实验对比。无需新增监听端口。
- TensorBoard 依赖及其运行依赖已加入锁文件；旧离线包需重新生成。

## 验证

| 项目 | 结果 |
| --- | --- |
| 前端独立测试 `node --test tests/*.test.js` | 120 passed |
| 前端生产构建 `npm run build` | 通过 |
| 监控、TensorBoard、runner 生命周期相关后端测试 | 67 passed，1 skipped（Windows 符号链接权限） |
| `ruff check src tests` | 通过 |
| 最后静态检查调整后的 telemetry 回归 | 29 passed |
| 依赖检查 | `pip check` 通过；36 项基础运行依赖闭包全部有兼容锁定版本 |
| 浏览器 | 已检查监控页、真实曲线、资源曲线、嵌入式原生 Scalars 页面 |

另执行 experiments / integration / deployment / packaging 较大范围回归：初次 1,429 passed、9 failed、30 skipped。其中 6 项由共享虚拟环境的子进程导入旧源码导致，指定新版 `PYTHONPATH` 后恢复；另 3 项是首次测试进程仍持有修改前的 TensorBoard 模块，涉及旧证据回退和错误恢复。最终版本定向复测这 9 项全部通过。这里记录两次命令的实际结果，不声称首次命令全部通过；没有重新执行完整 GPU 密码测试矩阵。已有 Starlette WSGI/TestClient 和 TensorBoard html5lib 弃用提示保留，不影响此次功能验证。

## 真实运行

使用新建隔离运行目录、6 个真实 HTTPS 角色（客户端/边缘/云各 2 个）、本机 MNIST 缓存完成两次明文联邦实验，并在结束后停止这些临时角色。原有运行目录、身份和服务未改动。

主要验收实验 `782da76faccc45a3865dcd32a2140f13`：NumPy、8×8 池化线性模型、60,000 训练样本、10,000 测试样本、每轮本地训练 5 次、全局 10 轮。最后测试准确率 80.92%，交叉熵 0.8057507198420667。该数值仅用于证明监控链路记录了真实结果，不是本次功能带来的精度提升或密码性能结论。

实际采集 7 个硬件时间点。首个 CPU 利用率为空，后续 6 个有效；GPU 利用率实测为 0，显存读数正常。官方 event reader 读到准确率和损失各 11 点（含初始化第 0 轮），GPU/内存/磁盘各 7 点，CPU 和进程 CPU 各 6 点，与证据一致。结果摘录与原始记录 SHA-256 见[验收证据](evidence/tensorboard-monitoring-20261008.json)。

资源范围是主控所在机器和现有采样器所选 GPU；三机远端硬件未上报。磁盘为运行目录所在文件系统容量。完整运行记录和事件保留在本机验收工作目录，私钥及整个 runtime 不放入源码 ZIP。
