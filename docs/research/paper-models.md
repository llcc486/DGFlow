# 论文参数量匹配的 CNN 训练基础

本模块实现完整 CNN 的本地训练、参数清单与完整向量导入导出，为后续扩大密码协议向量规模提供训练基础。安全服务现已支持 MNIST 的 2–28 池化网格和 CIFAR-10 的 RGB 2–25 池化网格，默认分别为 650 和 1,930 维线性模型，最高分别为 7,850 和 18,760 维。但**本模块的两个 CNN 仍未接入服务**、实验调度或界面，也没有完成大模型加密联邦训练。

## 论文证据与结构参考

本地 `DGFlow.pdf` 第 10 页明确报告：MNIST 使用 582,026 参数的 CNN，CIFAR-10 使用 878,538 参数的 CNN；评估框架为 PFLlib。论文未给逐层结构、框架 commit、学习率、mini-batch 大小等完整训练配置。本实现是与论文框架及参数量一致的结构重建，不称为作者源码或完整实验复现。

结构参考：[TsingZ0/PFLlib 的 FedAvgCNN](https://github.com/TsingZ0/PFLlib/blob/master/system/flcore/trainmodel/models.py)。参考仓库当前 [LICENSE](https://github.com/TsingZ0/PFLlib/blob/master/LICENSE) 为 **Apache-2.0**，不是 MIT。本模块独立编写 PyTorch 结构和数据合同，未复制其函数体；这里保留项目来源和结构归属。官方 master 链接会变化，完整复现应进一步确定作者实际使用的 commit。

两套网络均使用 5×5 卷积（32 通道）→ReLU→2×2 最大池化→5×5 卷积（64 通道）→ReLU→2×2 最大池化→展平→512 维全连接→ReLU→10 分类输出。卷积不填充，步长 1；所有卷积与全连接都含偏置。所有层参与训练，未冻结特征提取器。

| 模型名 | 原始输入 NCHW | 全连接输入维度 | 参数数目 |
|---|---|---:|---:|
| `paper_cnn_mnist` | `N×1×28×28` | 1024 | 582,026 |
| `paper_cnn_cifar10` | `N×3×32×32` | 1600 | 878,538 |

MNIST 参数分项为 832 + 51,264 + 524,800 + 5,130；CIFAR-10 为 2,432 + 51,264 + 819,712 + 5,130。ReLU 与池化没有可训练参数。

## 使用合同

入口位于 `src/dgfl/training/paper_models.py`：

```python
from dgfl.training.paper_models import (
    build_model, model_manifest, flatten_parameters, load_parameters, train_local,
)

model = build_model("paper_cnn_mnist", seed=42, device="cpu")
manifest = model_manifest(model)
initial = flatten_parameters(model)

# x 是调用方已准备好的非空 N×1×28×28、float32 数组；
# y 是长度 N、取值 0..9 的整数数组。这里没有下载和隐式预处理。
trained = train_local(
    "paper_cnn_mnist", initial,
    architecture_hash=manifest["architecture_hash"],
    x=x, y=y, epochs=10, learning_rate=0.01, batch_size=64,
    seed=42, device="cpu",
)
load_parameters(model, trained, architecture_hash=manifest["architecture_hash"])
```

示例中的学习率与 batch 大小是显式实现选择，并非论文提供的数值；MNIST 每轮 10 本地 epoch 在论文第 10 页有明确依据。本函数仅执行本地训练，不实现 20 客户端训练或全局轮调度。输入归一化、训练/验证/测试划分由调用方明确决定。

模型清单记录 schema、模型名、输入形状、参数名及顺序、各参数形状/数量/dtype、实际层配置、总维度和 SHA-256 架构摘要。向量顺序为 `named_parameters()`，每个张量按 C 序展平，dtype 固定为 `float32`。摘要不包含随机种子、设备或参数值；它用于发现结构/布局不一致，不证明远端诚实执行训练，也不是密码签名。

`load_parameters` 要求调用方提交预期架构摘要。在修改模型前检查摘要、向量维度、dtype 和所有值的有限性；不隐式把 float64、二维数组或含 NaN/Inf 的输入变为合法向量。导出返回独立副本。训练不修改调用方的模型向量、样本或标签，返回的是完整本地模型而非增量。

优化器为普通 SGD 和交叉熵，允许设置 epoch、学习率、batch 大小、种子与设备；当前不隐式增加动量、权重衰减或学习率调度。数据保留在 CPU，仅当前 mini-batch 送到选定设备。

设备允许 `cpu`、`cuda`（第 0 块显卡）、`cuda:N`。CUDA 不可用或索引不存在会明确报错，绝不悄悄回落 CPU。模块初始化不会改变 CPU 全局随机数状态。本机已验证 CPU；CUDA 训练尚未在真实显卡验证，不承诺跨设备或跨 PyTorch 版本逐位相同。

## 验证及下一步

可直接运行真实 MNIST 的离线小样本训练检查（依赖已有、通过发布校验和核对的 `data/mnist/raw`）：

```powershell
.venv/Scripts/python.exe scripts/benchmark_paper_training.py --output tmp/paper-cnn-smoke.json
```

默认使用训练集前 512 张原始 28×28 图像、独立测试集前 256 张图像、CPU 2 线程、2 个本地 epoch。结果记录所有参数数量、卷积层是否更新、损失、样本数、数据与代码摘要；它是单客户端训练流程检查，不用于宣称论文准确率或完整联邦加密性能。本机实跑记录在 `docs/research/evidence/paper-cnn-mnist-smoke.json`。命令可显式指定 `--device cuda:0`，需要另行准备可用 CUDA 版 PyTorch；当前 CPU 环境下此选项明确报错。

`tests/training/test_paper_models.py` 覆盖两模型的结构与参数量、真实前向及反向计算、卷积层和分类层实际更新、展平装载往返、独立副本、固定 CPU 种子复现、架构/维度/dtype/非有限拒绝、数据形状与配置拒绝、CUDA 不可用和索引错误。测试使用明确的合成小数组，只验证计算流程，不报告 MNIST/CIFAR-10 精度。

后续完整加密接入还要处理模型清单绑定、现有 20,000 维上限、建钥与证明内存、整数恢复范围。客户端数量已可配置为 2–100，边缘和云数量分别为 2–32。线性模型维度按数据集通道数与池化网格 `grid` 参数化，MNIST 最高 7,850 坐标、CIFAR-10 最高 18,760 坐标；这些模型仍使用线性分类器。

超过 24 MiB 的请求已有自动分块传输，但单次逻辑消息仍限制为 1 GiB，并未解除全部消息大小约束。Lego 套件需要按模型维度与位宽安装匹配 CRS，证明密钥、完整证明和聚合材料的内存及通信成本也需要实测。不能仅把维度上限调大就称为完整模型安全联邦学习；旧线性模型实验和提交包不因新增本模块而成为 CNN 的结果。
