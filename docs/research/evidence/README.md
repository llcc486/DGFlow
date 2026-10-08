# 论文对齐基础版本的证据

这些记录属于 2026-10-02 的研究优化，独立于 `docs/submission/evidence` 中冻结的 v1 数据。

- `test-summary.json`：全项目 pytest 回归。6 项跳过为 Windows 符号链接权限和可选 PDF 解析器缺失；不是密码测试失败。
- `paper-cnn-mnist-smoke.json`：真实原始 MNIST、512 个训练样本、256 个独立测试样本、2 个本地 epoch 的完整 582,026 参数 CNN 训练检查。证明卷积层也更新，不是冻结骨干。它不代表论文准确率、20 客户端联邦训练或大模型加密运行。
- `crypto-paired.json`：冻结 v1 源码与新实现的同进程密码微基准。各阶段包含冷/热缓存、3 次原始样本、中位数及比值；全部等价检查通过才生成对应维度的记录。旧/新源文件分别保存在同名前缀的 `-baseline` 和 `-current` 目录，均不含密钥或真实训练模型。运行期间每个完成的维度才写出一次，核对 `results` 中的维度后再使用数据。

微基准配置为 2 个合成客户端、3 个授权节点、2 份云聚合结果、8 位整数，分别测量 32 和 650 维。单客户端阶段只计算其中一个客户端；它不含多进程 RPC、训练和各节点资源争用，不可将阶段耗时相加后宣称为真实联邦轮时。热合并使用同一输入重放，可能命中 GT 解码缓存，不能当成新一轮模型耗时。

机器：Windows 11，Intel Core i7-14700HX（20 核、28 逻辑处理器）。这些密码测量均为 CPU。机器安装 NVIDIA RTX 4070 Laptop GPU，但目前 PyTorch 是 `2.14.1+cpu`；没有 CUDA 实测结果。该机器配置不同于论文的 Xeon 6982P/128 GB 节点。

复现（顺序执行，避免相互争用 CPU）：

```powershell
.venv/Scripts/python.exe -m pytest -q
.venv/Scripts/python.exe scripts/benchmark_paper_training.py --output tmp/paper-cnn-smoke.json
.venv/Scripts/python.exe scripts/benchmark_crypto.py --dimensions 32 650 --repeats 3 --output tmp/crypto-paired.json
```

密码基准需要本地 Git 历史中的 v1 提交 `34f8602d22c934a2acd3dcb2a36355a20dc5aeb2`，不能只复制一个没有历史的目录后声称完成旧/新比较。脚本禁止 `python -O`，保存两版执行源码快照，并在每个维度发布前核对工作区代码与脚本未改变。三次测量用于初步性能比较，不提供统计显著性或通用提速保证。

独立审阅已确认密码等式保持逐条验证、坏子群输入仍被拒绝、MSM 不截断不等长输入；审阅提出的 `-O` 跳过断言导致误记成功问题已用失败后通过的回归测试修复。
