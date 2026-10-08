# 模型详解：论文 CNN（582,026 / 878,538）与项目密码链路模型（650 维线性）

日期：2026-10-05。
配套阅读：[paper-gap-analysis.md](paper-gap-analysis.md) §2.11（差距定位）、[paper-models.md](paper-models.md)（论文 CNN 训练基础）。

本文只描述代码里真实存在的两个模型，不引入未实现的第三种。所有参数量、张量形状、向量布局均由代码与实测记录核对，不由文档转述。

> **线格式修订后的更新（本文其余部分保留修订前快照）**：§3、§4 描述的硬闸已有两项解除。
> - §3.1 的 64 MiB 单条上限已由**分块传输**解除：超过 24 MiB 的请求按 8 MiB 切块，每块绑定目标动作、块序号/总数与整体 SHA-256 摘要。
> - §4 的第 2、3 道硬闸（`roles.py` 中两处 `policy['dimension'] != 650`）已删除；维度改为按池化网格 `grid` 2–28 参数化，`10(grid²+1)` 个坐标。
> - 编码已由十六进制字符串改为**原始字节 + 紧凑二进制**，实测单客户端封装由 11,450 降到 2,998 B/坐标（3.82×）。文中出现"十六进制""JSON 封装"的表格与推算代表修订前的状态。
> - **§3.2 的证明体积结论不变**：证明仍是 O(d·b) 逐位范围证明，582,026 维约 1.4 GiB，仍需紧凑证明才具可用性。第 1 道硬闸（`_bounds` 的 20,000）也仍然存在。
>
> 详见 [protocol-v1.md](../protocol/protocol-v1.md) 的修订记录。

---

## 0. 一页速览

| 项 | 论文规模 CNN（项目重建） | 项目密码链路模型 |
|---|---|---|
| 实现文件 | `src/dgfl/training/paper_models.py` | `src/dgfl/training/model.py` |
| 框架 | PyTorch `nn.Module` | 手写 NumPy（可选 torch CPU） |
| 类别 | `PaperCNN` | 无类，函数式 `train_local` |
| 参数数目 | **582,026**（MNIST）/ **878,538**（CIFAR-10） | **650** |
| 结构 | 2×(Conv5×5 → ReLU → MaxPool2) → FC512 → ReLU → FC10 | 单层 Linear 64→10 |
| 参数量比 | **×895.4 / ×1351.6** | ×1 |
| 输入 | 原始 `1×28×28` / `3×32×32`，float32 | 池化后 `64` 维，定点整数 |
| 量化 | 无（保持 float32） | scale=128、bits=8 → `[-128,127]` |
| 是否进入密码链路 | **否** | **是** |
| 训练侧实测 | 512 样本 2 epoch、CPU 2 线程：**2.50 s** | 全量 MNIST 单轮加密约 211 s（含密码） |
| 论文依据强度 | 参数量与结构有依据，超参无依据 | 论文未给，属作品自选 |

一句话：**这两个模型不是"同一个模型的两种规模"，而是两个不同用途的东西。** 论文 CNN 是训练侧已备好的、但密码侧完全没接通的复现目标；650 维线性分类器是密码侧的当前实际载荷。二者之间不是调参关系，隔着一整套分块传输与紧凑证明。

---

## 1. 论文规模 CNN（`PaperCNN`）

### 1.1 结构

定义在 `paper_models.py:52-74`，前向为：

```
x → conv1 → relu1 → pool1 → conv2 → relu2 → pool2
  → flatten(x, 1) → fc1 → relu3 → fc2 → logits
```

逐层配置（取自实测清单 `docs/research/evidence/paper-cnn-mnist-smoke.json` 的 `layers` 字段，非文档转述）：

| # | 层 | 类型 | 关键参数 |
|---|---|---|---|
| 1 | `conv1` | `Conv2d` | `in=C_in`, `out=32`, `kernel=5×5`, `stride=1`, `padding=0`, `dilation=1`, `groups=1`, `bias=True`, `padding_mode=zeros` |
| 2 | `relu1` | `ReLU` | `inplace=False` |
| 3 | `pool1` | `MaxPool2d` | `kernel=2`, `stride=2`, `padding=0`, `ceil_mode=False` |
| 4 | `conv2` | `Conv2d` | `in=32`, `out=64`, `kernel=5×5`, `stride=1`, `padding=0`, `bias=True` |
| 5 | `relu2` | `ReLU` | `inplace=False` |
| 6 | `pool2` | `MaxPool2d` | `kernel=2`, `stride=2` |
| 7 | — | `flatten` | `torch.flatten(x, 1)`，C 序 |
| 8 | `fc1` | `Linear` | `in=hidden_input`, `out=512`, `bias=True` |
| 9 | `relu3` | `ReLU` | `inplace=False` |
| 10 | `fc2` | `Linear` | `in=512`, `out=10`, `bias=True` |

**关键点：卷积不填充（`padding=0`），步长 1。** 这决定了特征图收缩速度，也决定了 `fc1` 的输入维度。

### 1.2 空间维度推导

```
MNIST   1×28×28 --conv1(5,s1,p0)--> 32×24×24 --pool1(2)--> 32×12×12
             --conv2(5,s1,p0)--> 64×8×8   --pool2(2)--> 64×4×4  → flatten = 1024

CIFAR10 3×32×32 --conv1--> 32×28×28 --pool1--> 32×14×14
             --conv2--> 64×10×10 --pool2--> 64×5×5 → flatten = 1600
```

`MODEL_SPECS` 里写死的 `hidden_input` 正是这两个数：`1024` / `1600`。

### 1.3 参数量推导（已用几何独立复核）

**MNIST（`paper_cnn_mnist`，1×28×28，hidden=1024）**

| 张量 | 形状 | 计算 | 数量 |
|---|---|---|---|
| `conv1.weight` | `[32,1,5,5]` | 32×1×5×5 | 800 |
| `conv1.bias` | `[32]` | — | 32 |
| `conv2.weight` | `[64,32,5,5]` | 64×32×25 | 51,200 |
| `conv2.bias` | `[64]` | — | 64 |
| `fc1.weight` | `[512,1024]` | 512×1024 | 524,288 |
| `fc1.bias` | `[512]` | — | 512 |
| `fc2.weight` | `[10,512]` | 10×512 | 5,120 |
| `fc2.bias` | `[10]` | — | 10 |
| | | **合计** | **582,026** |

分层小计：conv1=832、conv2=51,264、fc1=524,800、fc2=5,130。

**CIFAR-10（`paper_cnn_cifar10`，3×32×32，hidden=1600）**

| 张量 | 形状 | 数量 |
|---|---|---|
| `conv1.weight` | `[32,3,5,5]` | 2,400 |
| `conv1.bias` | `[32]` | 32 |
| `conv2.weight` | `[64,32,5,5]` | 51,200 |
| `conv2.bias` | `[64]` | 64 |
| `fc1.weight` | `[512,1600]` | 819,200 |
| `fc1.bias` | `[512]` | 512 |
| `fc2.weight` | `[10,512]` | 5,120 |
| `fc2.bias` | `[10]` | 10 |
| | **合计** | **878,538** |

分层小计：conv1=2,432、conv2=51,264、fc1=819,712、fc2=5,130。

### 1.4 三个值得注意的结构事实

1. **两个模型只差 296,512 个参数**（878,538 − 582,026），来源只有两处：
   - `conv1` 多 2 个输入通道：+1,600（32×2×25）
   - `fc1` 输入从 1024 变 1600：+512×576 = +294,912
   - `conv2` 与 `fc2` **完全一致**。
2. **`fc1` 是绝对主体**：占 MNIST 参数的 **90.1%**、CIFAR 参数的 **93.3%**。这解释了为什么"参数量对齐"几乎等价于"`fc1` 输入维度对齐"，也意味着后续若要压缩通信，`fc1` 是唯一值得动的地方。
3. **参数量 ≠ 计算量**：`conv2` 只有 51,264 个参数（占 8.8%），但它是计算量最大的层（64×32×25 次乘加 × 8×8 空间位置）。参数量对齐不代表 FLOPs 对齐。

### 1.5 展平向量布局（密码学关心的就是这个）

`model_manifest` 声明 `flatten_order = "named_parameters/C"`：按 `named_parameters()` 顺序取张量，每个 `reshape(-1)` 后 C 序展平，`torch.cat` 拼接，dtype 固定 `float32`。

MNIST 582,026 维向量的区间划分：

| 区间 | 内容 | 长度 |
|---|---|---|
| `[0, 800)` | `conv1.weight` | 800 |
| `[800, 832)` | `conv1.bias` | 32 |
| `[832, 52032)` | `conv2.weight` | 51,200 |
| `[52032, 52096)` | `conv2.bias` | 64 |
| `[52096, 576384)` | `fc1.weight` | 524,288 |
| `[576384, 576896)` | `fc1.bias` | 512 |
| `[576896, 582016)` | `fc2.weight` | 5,120 |
| `[582016, 582026)` | `fc2.bias` | 10 |

CIFAR-10 对应区间：`[0,2400) [2400,2432) [2432,53632) [53632,53696) [53696,872896) [872896,873408) [873408,878528) [878528,878538)`。

> 注意顺序：**第一个张量是 `conv1.weight`，不是分类头。** `benchmark_paper_training.py:83-85` 专门写了注释提示这一点——如果误以为头部在前，`first_convolution_changed` 这个证据就是错的。

### 1.6 架构摘要（`architecture_hash`）

`model_manifest` 把 schema、模型名、输入形状、dtype、展平顺序、参数名/顺序/形状/numel，以及**每层的实际配置**（卷积的 stride/padding/dilation/groups/bias/padding_mode 等）序列化成排序紧凑 JSON，取 SHA-256。MNIST 模型实测值：

```
8326f15cabd8ee10e7e239ad2e22894fa3c84e2a552c778593b19c1fa3e01c18
```

摘要**不含**参数值、随机种子、设备、train/eval 模式（因此可复现：`test_paper_architecture_counts_logits_and_manifest` 断言 seed=17 与 seed=19 的清单完全相同）。`test_manifest_binds_layer_options_and_flatten_rejects_nonfinite_values` 验证了把 `conv1.stride` 改成 `(2,2)` 会让摘要改变，且旧摘要装载被拒。

文档明确其语义边界：**这是互操作检查，不是远程诚实执行的证明，也不是密码签名。**

### 1.7 训练合同（`train_local`）

| 项 | 实现 |
|---|---|
| 优化器 | `torch.optim.SGD(model.parameters(), lr=lr)`，**无动量、无权重衰减、无学习率调度** |
| 损失 | `nn.functional.cross_entropy` |
| 全部层参与 | 是。`test_..._updates_convolution_and_classifier...` 断言前 800 个（`conv1.weight`）与最后 5,130 个（`fc2`）都发生变化 |
| 冻结骨干 | **没有**。不使用"冻结特征提取器 + 只训分类头"的替代方案 |
| 数据 | 调用方提供 `float32` `NCHW` 数组与 `int` 标签；不下载、不预处理、不划分 |
| 设备 | `cpu` / `cuda` / `cuda:N`；CUDA 不可用或索引越界**显式报错，绝不静默回落 CPU** |
| 随机性 | `np.random.default_rng(seed)` 做 permutation；`build_model` 用 `torch.random.fork_rng` 播种，**不改变全局 RNG 状态**（有测试断言） |
| 返回值 | 完整模型向量（非增量、非差分） |
| 副作用 | 不修改调用方的权重向量、样本、标签（有测试断言） |

**论文依据的强度**：论文 §VI 只给了"582,026 参数 CNN / 878,538 参数 CNN / PFLlib / MNIST 10 轮每轮 10 本地 epoch"这些点。**逐层结构、框架 commit、学习率、batch size、CIFAR-10 本地 epoch 全部未给。** 所以 `paper_models.py` 是"与论文框架及参数量一致的结构重建"，参考 [PFLlib FedAvgCNN](https://github.com/TsingZ0/PFLlib/blob/master/system/flcore/trainmodel/models.py)（Apache-2.0，非 MIT），代码独立编写。示例里的 `learning_rate=0.01`、`batch_size=64` 是**显式的实现选择**，不是论文数值。

### 1.8 实测冒烟（`docs/research/evidence/paper-cnn-mnist-smoke.json`）

| 项 | 值 |
|---|---|
| 范围 | `single-client full-CNN training smoke; no FE/proof/network/federated run` |
| 训练/测试样本 | 512 / 256（原始 MNIST 前缀，非重采样） |
| 预处理 | 原始 28×28、NCHW float32、除以 255（**重建假设**，论文未给） |
| epoch / lr / batch | 2 / 0.01 / 64 |
| 全向量维度 | 582,026 |
| 训练前 | cross-entropy 2.29898，准确率 **16.41%**（42/256） |
| 训练后 | cross-entropy 2.29144，准确率 **19.14%**（49/256） |
| 训练墙钟 | **2.496 s** |
| `first_convolution_changed` | `True`（证明卷积层确实更新） |
| 环境 | Python 3.12.14，torch 2.14.1+**cpu**，`cuda_available: False` |

**这份记录的正确读法**：它是一个"全 582,026 个参数确实参与了真实前向+反向"的流程检查。准确率只从 16.4% 升到 19.1%，因为只用了 512 个样本、2 个 epoch——它**不是**准确率结果，也**不是**联邦结果，更**不是**加密结果。

### 1.9 能力与限制

- ✅ 两个模型的结构与参数量经测试断言（`test_paper_architecture_counts_logits_and_manifest`）。
- ✅ 真实前向+反向、全部层更新、展平装载往返、独立副本、固定 CPU 种子复现、CUDA 显式拒绝、非法数据/配置拒绝，都有测试。
- ❌ **没有 CIFAR-10 数据加载器**。`paper_cnn_cifar10` 只在合成长方体上做过前向+反向（`test_cifar_real_forward_backward_updates_full_model`），从未见过真实 CIFAR-10。
- ❌ **未接入密码链路**。见 §3。
- ❌ 未做 20 客户端联邦训练、未做全局轮调度、未做精度评估。
- ❌ CUDA 路径存在但**未在真实显卡验证**（本机 torch 是 CPU 版）。

---

## 2. 项目密码链路模型（650 维线性 softmax）

### 2.1 结构

`src/dgfl/training/model.py:14-16`：

```python
FEATURES = 64
CLASSES  = 10
PARAMETERS = FEATURES*CLASSES + CLASSES   # = 650
```

**单层线性分类器**：`logits = x @ W + b`，`W ∈ R^{64×10}`，`b ∈ R^{10}`。输入 64 维，输出 10 类。

**没有卷积、没有隐藏层、没有 ReLU**——唯一的非线性是输出端的 softmax（只在损失里）。

### 2.2 线路布局

```
w[0:640]  → W，按 C 序展开的 64×10 权重矩阵
w[640:650] → b，10 个偏置
```

代码里对应 `w[:640].reshape(FEATURES, CLASSES)` 与 `w[640:]`。

### 2.3 输入数据流水线

`data.py` `_pool`：原始 MNIST `28×28` 灰度 → **自适应平均池化到 8×8** → 除以 255 → C 序展平为 64 维。

池化分箱规则与 `torch.nn.functional.adaptive_avg_pool2d` 一致（`start = i*28//8`，`end = ((i+1)*28+7)//8`），保证边界像素全部计入、不丢不重。

对比论文 CNN 的输入：**原始 28×28 全分辨率**。项目把输入压缩了 **12.25 倍**（784→64），这本身就是一条独立于模型的精度损失。

### 2.4 训练

| 项 | 实现 | 备注 |
|---|---|---|
| 优化器 | 普通小批量 SGD + softmax 交叉熵 | 无数值技巧以外的修饰 |
| 数值稳定 | `logits -= logits.max(axis=1, keepdims=True)` | 防溢出 |
| 梯度 | `error = softmax(logits) - onehot`，`error /= len(batch)` | 手写反向 |
| 学习率 | 函数默认 `0.1`，**runner 实际传 `0.3`** | `roles.py:291` |
| batch | 64 | |
| epoch | 配置项，默认 2，范围 1–5 | 论文 MNIST 是 10 |
| backend | `numpy`（默认）或 `torch`（CPU float64） | torch 是可选适配 |
| 初值 | `N(0, 0.01)`，`np.random.default_rng(seed)` | |
| 量化 | `quantize(·, scale=128, bits=8)` → `[-128,127]`，半整数向偶数舍入 | 先剪裁到 `[-1, 0.9921875]` 再乘 128 |

**上传的是完整本地模型，不是梯度差分。** 每轮 650 个坐标全部进入配对群密码链路。

### 2.5 为什么选 650（作品自己的理由）

`design-report.md` §1 的表述是明确的：

> 本科竞赛范围内，作品将深度放在密码机制和工程闭环，选用易于解释的线性分类器。650 参数模型能够让每一个参数都进入真实协议。模型规模、精度和吞吐不外推为大语言模型或生产医院系统的性能。

这是一个**自觉的范围决策**，不是疏忽。问题不在"为什么小"，而在报告与答辩时必须把"650 维"当作作品选择、把"582,026"当作论文目标分开陈述——不能混为一谈。

### 2.6 实测表现

- 全量 MNIST（60,000 训练 / 10,000 测试，均匀分 6 客户端，种子 42）：3 轮准确率 **82.17% / 83.20% / 82.95%**；加密模式与明文模式的整数模型及批准集合完全一致。
- 小规模套件（1,200 训练 / 400 测试）：首轮准确率 39.75%–56.75%。
- 论文对应的是 582,026 参数 CNN 在 MNIST 上的收敛曲线（Fig 3(a)），**两者不可比**。

---

## 3. 从 650 到 582,026：差距的工程后果（量化）

这一节是全文重点。参数量差 895 倍不是数字游戏，它撞上了四道**已经在代码里存在的硬闸**。

### 3.1 单条 RPC 上限 64 MiB

`services/node.py:46-48`：

```python
async for chunk in request.stream():
    payload.extend(chunk)
    if len(payload) > 64*1024*1024: raise HTTPException(413,'node message too large')
```

按 `backend.py` 的编码（G1 压缩 48 B → 96 hex；标量 32 B → 64 hex）折算：

| 对象 | d=650 | d=582,026 | d=878,538 |
|---|---|---|---|
| 密文二进制 | 0.03 MiB | 26.6 MiB | 40.2 MiB |
| 密文十六进制 | 0.06 MiB | **53.3 MiB** | **80.4 MiB** ⛔ |
| `client_share` 的 `s`（hex） | 40.6 KB | 35.5 MiB | 53.5 MiB |
| `client_share` 的 `r`（hex） | 40.6 KB | 35.5 MiB | 53.5 MiB |
| `client_share` 的 `public`（K_j，hex） | 61.0 KB | 53.3 MiB | 80.4 MiB |
| **`client_share` 合计** | 0.14 MiB | **124.3 MiB** ⛔ | **187.4 MiB** ⛔ |

⛔ = 单条消息已超 64 MiB，且这还**没算** JSON 结构开销与 AES-GCM + 十六进制封装的膨胀。

→ **结论：不可能通过改大 `dimension` 常量接上 CNN。** 必须先实现分块传输（每块绑定 task/round/epoch/模型清单摘要/客户端/总维度/坐标范围/块号/总块数/整体提交摘要，并拒绝重放、重叠、缺块、截断、改序、同轮改写）。`paper-alignment.md` §3.1 已把这条列为前置条件。

### 3.2 证明体积（当前构造的主要瓶颈）

当前证明是逐位范围证明，体积 **O(d·b)**，b=8。按 `paper-alignment.md` §3.1 的字段长度推算，每坐标约 **2,576 字节**原始点/标量数据：

| d | 证明原始体积 | 十六进制后 | 未计 |
|---|---|---|---|
| 650 | 1.6 MiB | 3.2 MiB | 密文、认证封装、JSON |
| 582,026 | **约 1.40 GiB** | **约 2.79 GiB** | 同上 |
| 878,538 | 约 2.11 GiB | 约 4.22 GiB | 同上 |

**这是字段长度推算，不是实测通信量**（文档原文如此）。作为量级参照：650 维下实测 `dgflow` 单轮**全网** RPC 收发 436 MiB（6 客户端合计，含 DKG 份额与三份冗余验证），`optimized` 单轮约 290 MiB。

另一个刺眼的比值：582,026 个 8 位量化坐标本身只有 **0.56 MiB** 的载荷信息，却要配 1.40 GiB 的证明——**证明/载荷 ≈ 2,576 : 1**。这正是 `paper-alignment.md` §3.2 说"现有证明虽可作为流式基线，体积不适合直接宣称论文性能"的原因，也是为什么**紧凑证明必须和分块传输同时做，否则接上也没法用**。

### 3.3 DKG 内存与承诺体积

`Authority.__init__`（`protocol.py:38-42`）为 `len(clients) × dimension` 个坐标各生成 `threshold` 个随机系数，`s` 与 `r` 两套，并为每个系数生成一个 G1 承诺：

```
size = len(clients) * dimension
self._s_poly = [[random_scalar() for _ in range(threshold)] for _ in range(size)]
self._r_poly = [[random_scalar() for _ in range(threshold)] for _ in range(size)]
self._commits = [[g1_dump(G*a + H*r) for a,r in zip(ss,rr)] ...]
```

d=582,026、n=6、threshold=2 时：

- `size = 3,492,156`
- 承诺数 = size × threshold = **6,984,312 个 G1 点**，每个以 96 字符十六进制字符串保存 → 仅持有这些字符串就约 **670 MB / authority**
- `_s_poly` / `_r_poly` 各 6,984,312 个 Python 大整数，各自也在数百 MB 量级
- 三个 authority 各持一份，且 `commitments()` 还要**在网络上传输**（每个 authority 约 670 MB 量级）

这是"分布式建钥"在论文规模下的真实成本，也是论文报告"边缘节点加密钥生成 2,015 s"的来源之一。

### 3.4 有界离散对数的硬上限

`backend._log_table`（`backend.py:238-247`）：

```python
step = math.isqrt(width) + 1
if step > 100000:
    raise ValueError('discrete logarithm range exceeds configured memory budget')
```

内积恢复区间是 `[-Σ|z_j|·o, +Σ|z_j|·o]`（`o=offset=128`），所以 `width = 2·Σ|z_j|·o + 1`。代入 `step ≤ 100000` 反解：

```
Σ|z_j| ≤ 39,062,499
```

换算成"参考模型坐标的平均绝对值上限"：

| d | 允许的平均 \|z_j\| | 实际范围 | 是否构成约束 |
|---|---|---|---|
| 650 | ≈ 60,096 | ±128 | **完全无约束** |
| 582,026 | ≈ **67.1** | ±128 | **是真实约束**（取决于参考模型分布） |
| 878,538 | ≈ **44.5** | ±128 | **约束更紧** |

→ d=650 时这条限制形同虚设，所以它从未被触发过；一旦上 CNN，它就会变成随参考模型分布浮动的隐性失败点（`bounded_log` 抛"outside authorized range"）。

`paper-alignment.md` §3.4 和 §1 都明确要求：**论文规模需重新测算内积的整数边界与 BSGS 内存，不能直接提高现有 100,000 婴儿步上限而忽略资源。**

### 3.5 量化：一个容易被忽略的设计问题

当前 `quantize` 对**整个模型使用同一个** `scale=128, bits=8`，等效于把浮点裁到 `[-1, 0.9921875]`。

线性模型的权重（初值 N(0,0.01)，lr 0.3）量级相近，单一 scale 合理。但 CNN 各层权重量级差异很大（卷积核与 `fc1` 的 fan-in 差 25 倍以上），**单一全局 scale 会在大模型上产生不可忽略的饱和**。

而且这里有一条硬约束：`scale`/`bits` 是证明关系里的**公开参数**（绑进 `ctx`、`_bounds`、FS 转录）。要做逐层 scale，等于把公开参数从标量变成向量，**证明关系本身要改**，不是换个量化函数就行。`paper-alignment.md` §3.4 已要求记录"量化饱和率、误差、最终模型、批准集合，分离训练、量化、筛选和密码的影响"。

### 3.6 训练侧不是瓶颈

582,026 参数 CNN，CPU 2 线程，512 样本 2 epoch = **2.50 秒**。

论文 Table III 报 MNIST 10 轮 DGFlow 共 60,107 秒（约 100 分钟/轮），其中论文自己拆解出的边缘节点开销是：密钥生成 + 聚合解密钥生成 2,015 s、输入验证 636 s、聚合组合 99 s，云服务端运行时另计。**绝大部分时间是密码学开销，不是 CNN 训练。**

这解释了整个问题的结构：**"模型接不接得上"完全取决于密码层，而不取决于训练层。** 训练侧其实已经就绪。

---

## 4. 密码侧的三道硬闸（接入时必须先拆）

grep 确认 `paper_models` **只被 `scripts/benchmark_paper_training.py` 和 `tests/training/test_paper_models.py` 引用**；`experiments/runner.py` 的 import 列表里没有它。也就是说两个模型之间目前没有任何数据通路。即使打通，还会撞上：

| # | 位置 | 代码 | 作用 |
|---|---|---|---|
| 1 | `protocol.py` `_bounds` | `not 1 <= d <= 20000` | 维度硬上限 **20,000**，比 582,026 小 29 倍 —— **仍然存在** |
| 2 | ~~`roles.py` `_prepare_data`~~ | ~~`policy['dimension'] != 650` → raise~~ | **已移除**：改为 `_model_geometry()` 校验 `10(grid²+1)` 形状 |
| 3 | ~~`roles.py` `_train`~~ | ~~`policy['dimension'] != 650` → raise~~ | **已移除**：同上 |

runner 里 `policy` 与 `ctx` 的 `dimension` 也已改为由 `grid` 推导，不再是字面量 650。

> 第 2、3 道闸移除后，服务可用维度为 650–7,850（`grid` 2–28）；要再往上需要同时提高 `_bounds` 上限并重新测算 BSGS 内存。

---

## 5. 接入的最小顺序（不要跳步）

1. **分块传输协议**：规范二进制、受认证分块、有界队列；每块绑定 task/round/key_epoch/模型清单摘要/客户端/总维度/坐标范围/块号/总块数/整体提交摘要。补重放、重叠、缺块、截断、改序、同轮改写、混轮、混模型的负测试。**先在小向量上与非分块版本逐整数对齐。**
2. **参数化维度**：拆掉 §4 的三道硬闸，把 20,000 上限、650 常量改为任务策略字段。
3. **重算整数边界与 BSGS**：按论文 §IV-B 的"polynomially bounded interval"重新推导内积区间，重算 `_log_table` 的表宽、内存与时间；明确失败即拒绝，不返回模意义下的近似值。
4. **量化策略**：决定单 scale 还是逐层 scale；若逐层，先改证明关系的公开参数结构。测量饱和率与误差。
5. **紧凑证明**：替换 O(d·b) 的逐位范围证明为论文的 batched Σ + 平方和 ZK 论证。**没有这一步，前四步做完也只是"能跑"，不是"可用"。**
6. 然后才谈 20 客户端、4 云聚合与 CIFAR-10。

`paper-alignment.md` §4 给出的验收顺序与此一致（先小向量密码语义不变 → 完整 CNN 训练合同 → 分块对齐 → 分级向量（650 / 7,850 / 更大）验证内存时间证明体积 → 再启动完整 CNN 的真实加密运行）。

---

## 6. 陈述纪律

**可以说**：
- 项目实现了与论文参数量一致的 582,026 / 878,538 参数 CNN 结构重建，并通过真实前反向验证全部层参与训练。
- 密码链路当前以 650 维线性 softmax 分类器为载荷，650 个坐标全部进入真实配对群协议。

**不能说**：
- ❌ "实现了 582,026 参数 CNN 的安全联邦训练"——密码链路是 650 维。
- ❌ "论文 CNN 已在联邦/加密环境验证"——只在单客户端、512 样本、无密码的冒烟里跑过。
- ❌ "CIFAR-10 模型已验证"——只有合成长方体上的前反向，没有真实 CIFAR-10 数据。
- ❌ 把 82.17%–83.20% 的准确率与论文 Fig 3 的曲线相提并论——不同模型、不同输入分辨率、不同轮数。
- ❌ 把 smoke 里的 16.41% → 19.14% 说成"准确率结果"——它是流程检查，样本量 512/256。
