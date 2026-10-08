# DGFlow 论文对齐差距分析：功能设计逐项区别

日期：2026-10-05。
依据：项目所获论文 `docs/DGFlow-指导论文.pdf`（13 页，SHA-256 `e2421b9a6c56818f70d1b54537f19a9044d7d3b6cf1704e747aa680c7647801b`，与 `paper-alignment.md` 记录的 `DGFlow.pdf` 为同一文件）。
方法：逐节核对论文 §III–§VI 的算法定义、构造、安全结论与实验设置，与 `src/` 下实际执行的代码路径对照；以代码为准，不采信文档中未落到代码的表述。

本文只做差距定位，不新增实验数字，也不把未运行的规模、精度或提速填成结论。

> **2026-10-07 当前实现核验**：下文未改写的表格、代码示例和完成度比例是历史分析，不代表当前代码。当前训练链路已经支持 MNIST 与 CIFAR-10 的池化线性模型，默认分别为 650 / 1,930 维，维度公式为 `10 × (channels × grid² + 1)`；模型仍受 20,000 坐标及消息资源预检约束。两种完整 CNN 尚未接入安全联邦链路。
>
> 当前证明可选 legacy、紧凑 IPA 和 `lego_norm_v1`；不能再把逐位证明的体积或耗时概括为全部方案。Lego 必须使用与维度、位宽匹配的已安装 CRS，当前本机参数是明确标记的单方开发设置。鲁棒筛选已有经证明范数的相对幅度门限、可选平方范数绝对上限及余弦检查；这些工程规则不等同于一般投毒防御证明。
>
> 规模、门限和单归属验证以 2026-10-06 更新为准；DKG 已按任务摊销。当前仍要求全部边缘参与任务初始化及关键轮次流程，云可处理网络缺席，但错误签名或数学证据会终止任务。默认重新组队与固定批次隐私模型存在差异；动态跨轮加入、论文级对比评估、完整安全归约和恶意节点 BFT 尚未完成。本次完整性检查另修复了阶段计时重复统计及异常退出后活动任务无法释放的问题，验证范围见[完整性核验记录](evidence/integrity-audit-20261007.json)。

> **2026-10-06 拓扑更新**：下面差距表和代码示例保留 2026-10-04/05 的历史状态。§2.1 的固定规模、§2.6 的每个边缘重复全验、§2.9 的固定两层门限现已修正：新部署默认 n=6/w=3/v=4/s=2/e=2，支持 n=2–100、w/v=2–32、s=2–w、e=2–v；原始证明与加密提交只到唯一归属边缘，全部边缘共享 VKGen 份额，归属边缘核验后共享签名评分、范数、摘要及密文核心，全部边缘共同筛选授权。默认 w=3 与编号轮流分配均为工程选择，论文未指定该分配算法。现有历史集群与结果不自动改写，真实部署的新任务均使用单归属协议；无 cluster 的旧孤立测试保留兼容路径。详见[分层拓扑对齐](hierarchical-topology-20261006.md)。
>
> 此更新只修正上述拓扑、参数化与验证分工差距。全员 DKG、coordinator 可用性单点、外部安全审查、完整论文性能/安全证明及 PFLlib CNN 端到端复现等差距仍需分别判断；允许配置 20/100 客户端不等于已经完成论文规模性能评估。

> **线格式修订后的更新（本文其余部分保留修订前快照）**：P0 清单的第 3 项已完成前两步。
> - **分块传输已实现**：超过 24 MiB 的请求按 8 MiB 切块，每块绑定目标动作、块序号/总数与整体 SHA-256 摘要；重放、重叠、缺块、截断、改序、混轮、混模型全部拒绝。
> - **`dimension != 650` 硬编码已解除**：维度按池化网格 `grid` 2–28 参数化，服务可用 650–7,850 维。
> - 编码已由十六进制 JSON 改为原始字节 + 紧凑二进制，实测单客户端封装 11,450 → 2,998 B/坐标。
> - **仍未完成**：显式范数上界（P0-1）、紧凑 NIZK（P0-2）、`_bounds` 的 20,000 上限重算、CNN 真正接入密码链路。§2 的差距表与 §5 的"不能声称"清单因此**基本仍然成立**。
>
> 详见 [protocol-v1.md](../protocol/protocol-v1.md) 的修订记录。

---

## 0. 结论速览

一句话：**论文的密码学骨架（DMAFE 的算法定义与代数构造）已被公式级忠实重建；论文的"系统规模、证明效率、对比评估、安全定理"四块基本还没有。**

| # | 维度 | 论文 | 本项目 | 差距等级 |
|---|---|---|---|---|
| 1 | DMAFE 双解密代数构造 | §IV-B | 实现一致（加法记号） | ✅ 已对齐 |
| 2 | 建钥频率：DKG 摊销 | §V-A 步骤 1（原文自相矛盾，见 §6.2） | **已改为任务级 epoch，仪式只跑首轮**，取论文的摊销读法 | ✅ 已对齐 |
| 3 | 验证内积 → 余弦相似度 | §V-A 步骤 3 | 实现一致 | ✅ 已对齐 |
| 4 | 门限部分解密 + 组合 | §V-A 步骤 4 | 实现一致，门限固定 2/3 | 🟡 部分 |
| 5 | 系统规模（n / w / v） | n=20，v=4，可扩到 100 | n=6，w=3，v=3 | ❌ 未对齐 |
| 6 | 模型规模（CNN 参数量） | 582,026 / 878,538 | 密码链路固定 650 维线性分类器 | ❌ 未对齐 |
| 7 | 数据集 | MNIST + CIFAR-10 | 仅 MNIST | ❌ 未对齐 |
| 8 | NIZK 证明构造 | batched Σ + 平方和 ZK 论证 | 逐位范围证明 + 链式表示证明 | 🟡 不同实现 |
| 9 | 证明体积 | 紧凑（论文未给转录） | O(d·b)，每坐标约 2.6 KB 原始 | ❌ 未对齐 |
| 10 | 显式范数上界 | §V-A "strictly bounds the magnitude" | 仅坐标区间隐含上界 | ❌ 未实现 |
| 11 | 验证分工 | 边缘节点验证"所连接的"客户端 | 3 个 authority 各验证全部 6 个客户端 | 🟡 冗余替代 |
| 12 | 良性簇识别 | k-means | 定阈值一维二均值（工程补充） | 🟡 不同实现 |
| 13 | 固定批次 σ | 可配置的多样本隐私参数 | 硬编码每批 2 人、共 3 批 | 🟡 简化 |
| 14 | 动态加入客户端 | 支持，新 σ 客户端成新批 | 不支持，改成员须新建任务 | ❌ 未实现 |
| 15 | 门限参数 ς / ϵ | 任意 ς-out-of-w、ϵ-out-of-v | 均固定 2-of-3 | 🟡 固定化 |
| 16 | 密码群 | 非对称双线性群，MNT224 | BLS12-381 | 🟡 不同曲线 |
| 17 | 实现库 | Charm + PFLlib | py-arkworks-bls12381 + NumPy | 🟡 不同栈 |
| 18 | 安全定理 | 3 个定理 + 4 条性质分析 | 仅方程级审查，组合归约未完成 | ❌ 未完成 |
| 19 | 对比方案 | HybridAlpha / TAPFed / CZGQ / PrivLDFL | 一个都没实现 | ❌ 未实现 |
| 20 | 评估指标 | 轮时、客户端/服务端运行时、通信量、ASR、OA | 准确率、轮时、字节数；无 ASR/OA | ❌ 未对齐 |
| 21 | 可扩展性 | 20–100 客户端 | 最多 6 | ❌ 未实现 |
| 22 | 攻击覆盖 | label-flipping + free-rider，0–50% 攻击比 | label_flip / sign_flip / random / tamper / dropout | 🟡 部分 |

**完成度评估（本文作者判断，非实测）**：密码原语约 85%；完整论文系统约 25–30%；论文的实验评估约 0–5%。

---

## 1. 已经与论文公式级一致的部分

论文 §IV-B `Construction of DMAFE` 用乘法记号给出；实现用 G1/G2 加法记号。逐条对照如下（代码在 [protocol.py](../../src/dgfl/crypto/protocol.py)）：

| 论文算法 | 论文公式 | 实现位置 | 结论 |
|---|---|---|---|
| `GlobalSetup(1^λ)` | `BG=(G,H,GT,p,g,h,e)`，`mpk=(BG,H,ϵ)` | [backend.py](../../src/dgfl/crypto/backend.py) 模块级 `G/H/G2/GT_BASE` | 等价（域分离常量替代 ϵ） |
| `AuthSetup(n,m)` | w 个 authority 用 Pedersen DKG 分发 `n×m` 个 `s_{i,j}`，各自持 `msk_τ={s^(τ)_{i,j}}` | `Authority.__init__/set_commitments/receive_share/finalize` | 等价，且额外分发盲化多项式 `r` |
| `EKGen(msk_τ,i)` | `ek_{τ,i}={s^(τ)_{i,j}}_j` | `Authority.client_share` | 等价（多返回 `r` 与 `public`） |
| `VKGen(msk_τ,i,z)` | `vk_{τ,i,z}=h^{Σ_j s^(τ)_{i,j} z_j}` | `Authority.validation_key` | 一致 |
| `DKGen(msk_τ,j,y)` | `H^(τ)_{j,y}(x)=Σ_i s^(τ)_{i,j} y_i + Σ_k d_{τ,k}x^k`，`dk_{τ,j,y,t}=h^{H(t)}` | `Authority.aggregate_key`（常数项取获准集合之和 + `cloud_threshold-1` 个随机系数） | 一致（`y_i∈{0,1}` 用"只累加获准者"实现） |
| `Encrypt({ek_τ,i},ℓ,x_{i,j})` | 客户端先 Lagrange 合成 `s_{i,j}`，`ct_{i,j}=(f_ℓ)^{s_{i,j}} g^{x_{i,j}}` | `recover_client_key` + `encrypt` | 一致 |
| `VerDec` | `D_i=Π_j e(ct_{i,j},h^{z_j})`，`V_i=D_i/e(f_ℓ,vkey_{i,z})`，`vs_i=log(V_i)` | `validate_inner_product`（MSM 合成 + multi_pairing） | 一致 |
| `AggDec` | `D_{j,t}=Π_i e(ct_{i,j},h^{y_i})`，`E_{j,t}=e(f_ℓ,dkey_{j,y,t})` | `partial_decrypt` | 一致 |
| `AggComb` | 检查所有 `D_{j,t}` 相等；`E_j=Π_t E_{j,t}^{ξ_t}`；`C_j=D_{j,1}/E_j`；`as_j=log(C_j)` | `combine` | 一致 |
| 全局模型 | `m_ℓ=(as_1/Λ,…,as_m/Λ)`，`Λ=|Φ_ℓ|` | runner 中 `quantize(total/(len(approved)*scale))` | 一致（多一步再量化） |
| 标签 `f_ℓ=H(ℓ)` 绑轮次 | 抗 MaMA | `hash_point(ctx)`，`ctx` 含 task/round/key_epoch/model_hash/量化参数 | 等价且更强 |

**这是本项目最扎实的部分**：DMAFE 不是"黑盒调用某个 MCFE 库"，而是按论文公式重写，配对消掩码与有界离散对数恢复都对得上。

---

## 2. 功能设计差异（逐项）

### 2.1 系统拓扑与规模 —— 差距最大的一项

| 角色 | 论文 | 项目 | 代码约束 |
|---|---|---|---|
| 客户端 n | 20（§VI），可扩到 40/60/80/100（Table IV） | 6 | `NODE_PORTS` 只定义 `client1..client6`；runner `range(1,7)`；`apply_batches` 默认 `clients=6` |
| 边缘/授权节点 w | w 个（未给具体值） | 3 | `AUTHORITIES=['authority1','authority2','authority3']`；`_policy` 要求成员严格为 `client1..clientN` |
| 云聚合节点 v | 4（§VI，"simulate them via multiple processes"） | 3 | `NODE_PORTS` 只定义 `aggregator1..aggregator3` |
| 主控 | 论文无独立"coordinator"角色 | 1 个本机控制服务 | [control.py](../../src/dgfl/services/control.py) |

注意 `_policy` 在形式上允许 2–20 个偶数成员，但节点身份表、密钥生成、runner 的客户端列表都硬编码为 6。**因此"扩到 20 客户端"不是改一个配置项就能完成，需要同时扩身份表、扩 DKG 参与方、扩批次规则并重做资源预算。**

### 2.2 建钥：DKG 与门限

- 论文 §V-A 步骤 1：每轮 `Round Initialization` 调 `AuthSetup(n,m)`，`ς`-out-of-`w`；§IV-C 定理 3 声称"抗 ς−1 个被攻破 authority"。
- 项目：每轮 `epoch=uuid4().hex` 触发一次全新 DKG ✅；但
  - `p.Authority(..., [1,2,3], ..., 2, ...)` 把参与方与门限写死为 **3 与 2**；
  - `finalize()` 要求 `set(self._received)==set(self.members)`，`roles.finalize` 要求**全部 3 个 authority 都 ack**；
  - runner 的 `choose_participants` 在安全模式下直接 `raise` 除非 `set(AUTHORITIES) <= online`。

  → 结果是：**份额恢复有 2/3 门限，但建钥过程本身是"全员到齐否则中止"**，不提供论文所说的"少于 ς 个节点被攻破仍安全、其余节点继续"的性质。论文的 DKG 是抗崩溃/抗恶意参与的；项目的是崩溃即中止（文档已如实承认，见 `design-report.md` §4.1、`proof-construction.md` §3）。

### 2.3 加密密钥分发：项目比论文多了一层 Pedersen 绑定

| 项 | 论文 | 项目 |
|---|---|---|
| 客户端收到 | `{s^(τ)_{i,j}}_j` | `s`、`r`、以及公开 `public`（即 `K_{i,j}=g^{s}H^{r}`） |
| 客户端校验 | 无（论文未描述） | `G*s+H*r == g1_load(pub)` |
| 验证者持有 | `{vk}` / `{dk}` | 同样，外加每个客户端的 `K_j` 序列 |

这是**为了把范围证明绑到"实际发放的密钥"而增加的机制**，论文的 NIZK 关系 `R(S,V): Z=Σa_j², c_j=f_ℓ^{s_j}g^{a_j}` 并不含 `K_j`。副作用是每客户端的公开密钥行与证明首消息都变大（论文报 MNIST 每轮每客户端加密密钥 99 MB）。

### 2.4 输入验证：NIZK 构造不同

| 项 | 论文 §V-A 步骤 2 | 项目 |
|---|---|---|
| 关系 | `Z=Σ_j a_j²`，`c_j=f_ℓ^{s_j}g^{a_j}` | 范围（b 位）+ 表示 + 平方 + 已发放密钥绑定 |
| 技术 | "batched Σ-protocol for ciphertext well-formedness" + "zero-knowledge sum-of-squares argument" + Fiat–Shamir | 每坐标 b 个 Pedersen 位承诺 + Schnorr OR；再 4 元联合表示关系；再平方关系；FS 用 SHA-512 mod q |
| CRS | `crs ← NIZKP.Gen(1^λ, L)`（系统初始化一次） | 无 CRS（透明，hash-to-curve + 确定性转录） |
| 体积 | 未给转录；论文 §VI 隐含紧凑 | **O(d·b)**；`paper-alignment.md` 估算 8 位下每坐标约 2,576 字节原始 |
| 证明的额外绑定 | 论文关系不绑密钥承诺 | 绑定 task/round/epoch/client/model/量化参数/`K_j` |

**差异的实质**：项目证明在"绑定强度"上更强（多绑了 DKG 发放密钥与量化上下文），但在"效率"上差 2–3 个数量级。论文 §VI 的整个性能叙事（DGFlow 比 CZGQ/PrivLDFL 快 28%）依赖紧凑的 batched 证明；**用当前逐位证明无法声称论文性能**。`paper-alignment.md` §3.2 已明确写为待办。

同时必须指出：论文**没有给出完整可复用的证明转录**，所以项目这条路线是独立重建，不能称为"作者的证明实现"（文档已如此声明）。

### 2.5 范数上界 —— 论文有，项目没有

- 论文 §V-A 步骤 3 两次明确："**strictly bounds the magnitude of the update**"、"enforces an **explicit upper bound** on the verified `X_i` against magnitude-scaling attacks"；§V-B 也把这条列为抗 MPA 的组成部分。
- 项目 [verify()](../../src/dgfl/crypto/protocol.py) 只有 `not 0<=norm<=d*offset*offset` 这一个**由坐标区间推出的隐含上界**（`d·o²=10,649,600`），没有独立配置、独立校准、独立策略绑定的范数门限。
- `paper-alignment.md` §1 自己承认："当前仅有坐标范围隐含上界；独立任务范数上限及校准仍待实现"。

→ 这是论文明确声称、项目明确缺失的一条**功能**，不是实现细节。

### 2.6 验证分工：3× 冗余替代了连接式委派

**状态更新（2026-10-06）**：本节以下为旧实现记录。真实集群的新任务已改为单归属边缘验证与共享签名结果；其他边缘不再重复原始证明核验，仍共同执行全局筛选与一致授权。V/VerDec 由归属边缘内部执行，不新增独立角色。

- 论文 §V-A 步骤 3："each edge node runs `DMAFE.VKGen(msk_τ, i, z=m_{ℓ-1})` … and shares it with other edge nodes"，然后"**the connected edge node** … computes `Z_i`"、"each edge node runs `VKGen`" —— 即**某一个（客户端所连接的）边缘节点做内积解密**，其余节点只提供函数钥份额。
- 项目 `runner.optional` 对**每个**客户端都调 `validation_key`，然后对**每个** authority 调 `authorize`，每个 authority 内部 `for cid in self.auth.clients:` 遍历全部 6 个客户端做完整验证（`p.verify` + `validate_inner_product` + 筛选），最后 `authorization()` 要求 **≥2 份完全一致的签名决策**。

→ 功能设计上：项目把"验证"从"按连接委派 + 函数钥共享"改成了"**3 份独立全量验证 + 2/3 一致投票**"。这更接近 BFT 许可，代价是验证成本约为论文的 3 倍（论文 MNIST 验证成本 636 s；项目同口径会是数倍）。文档 `protocol-v1.md` §一 也承认"当前每个 authority 验证全部客户端"。

### 2.7 良性簇识别：k-means vs 定阈值二均值

| 项 | 论文 | 项目 |
|---|---|---|
| 算法 | "edge nodes apply the **k-means** algorithm [26] to identify an initially benign client pool" | `select()`：最小/最大分数初始化的一维二均值，最多 32 次迭代 |
| 排除条件 | 未给 | 中心差 `≥0.45` **且** 低中心 `<0.25` |
| 全同分数 | 未给 | 不拆簇，全通过 |

项目的规则是**自补充的固定工程规则**（`protocol-v1.md` §六、`design-report.md` §4.4 均已声明"不声称由原论文逐字给出"）。这是合理的工程化，但与论文的 k-means 在算法、可解释性和超参敏感性上都不同。

### 2.8 固定批次与 MRPL

| 项 | 论文 | 项目 |
|---|---|---|
| 批次划分时机 | System Initialization，一次划分、不相交、不可变 | 任务登记时确定，`batch_size` 必须为 2 |
| 批次大小 σ | **多轮隐私参数**，需在"严格隐私保证 / 客户端掉线概率 / 收敛所需最小活跃数"之间权衡后确定 | 硬编码 2（`_policy` 强制 `batch_size==2`），共 3 批 |
| 批次构成 | 未指定 | 相邻下标成对：`(client1,client2) (client3,client4) (client5,client6)` |
| 秩亏论证 | §V-B 给出参与矩阵秩亏的数学论证 | 无形式化论证；`design-report.md` 只作定性描述 |
| 新加入者 | 新 σ 客户端聚为新批次 | 不支持 |

→ 机制形状一致（整批进/整批出），但**σ 这个论文强调的隐私参数在项目里被固定成 2**，且缺少论文的秩亏形式化。

### 2.9 聚合门限与 SPOF

**状态更新（2026-10-06）**：下述固定 2/3 限制已解除，当前为可配置 s/w 与 e/v（均至少 2）。聚合预检按实际云数量及门限判断；历史三云故障记录仍只代表当时 2/3 配置。自动剔除坏云重试、全员 DKG 及 coordinator 单点等边界没有因此消失。

- 论文 §III-A：`ϵ`-out-of-`v`，"as long as **any ϵ cloud servers** transmit their results"；§IV-C 定理 3：被腐化聚合者 `κ<ϵ` 时**信息论安全**。
- 项目：`partial_decrypt(..., 2, ...)`、`combine(..., 2, ...)` 固定 2；runner 要求 `len(active_clouds)>=2`。
- 实测（`docs/submission/evidence/faults/index.json`）：
  - 停 `aggregator3` → 完成 1 轮 ✅（崩溃容错成立）
  - 停 `aggregator2/3` → 门限预检中止，0 轮 ✅（行为正确）
  - 停 `client1` → `client2` 因固定批次连带退出 ✅
- 2026-10-04 已增加以 DKG 承诺为根的配对像正确性证明，错误 E 和共同伪造的 D 均被拒绝，见[证明规格第 17 节](../protocol/proof-construction.md#17-2026-10-04部分解密正确性证明)。未实现：任意 `ϵ`/`v` 可配置、自动剔除坏云后重试、完整拜占庭容错与跨层共谋分析。原论文关于跨层串谋的声明不能直接转移到本实现。

另外，项目的 **coordinator 本身是可用性单点**（`design-report.md` §2 自认），论文在架构上通过"边缘节点合并"避免了额外的中心角色。

### 2.10 动态客户端 —— 完全未实现

- 论文 §III-A / §V-A 步骤 1 两处强调："DGFlow **supports dynamic clients**, where edge nodes perceive new clients and issue encryption keys to them in the new round"、"sets up the authorities with the updated size, where **newly joined σ clients are clustered into a new batch**"。这是论文相对 CZGQ（"prevents new clients from joining"）的核心卖点之一，也是 Table I 里 DGFlow 的 "Dynamic Addition ✔"。
- 项目 `roles._policy`：
  ```python
  members != [f'client{i}' for i in range(1,len(members)+1)]
  ```
  强制成员必须是 `client1..clientN` 的连续前缀；`begin` 中若 `previous.get('policy') != policy` 直接抛 `'task policy already fixed; create a new task'`。
- → 项目**只能新建任务**，不能在训练中途加入客户端。Table I 中 DGFlow 相对 Lepcat/CZGQ 的一项优势在实现里不存在。

### 2.11 模型与数据 —— 密码链路上的根本差距

| 项 | 论文 | 项目（密码链路） | 备注 |
|---|---|---|---|
| MNIST 模型 | 582,026 参数 CNN（PFLlib FedAvgCNN） | 650 参数线性 softmax（64×10 权重 + 10 偏置） | 见 `design-report.md` §4.5 |
| CIFAR-10 模型 | 878,538 参数 CNN | **不存在** | grep 确认 `cifar` 只出现在 `paper_models.py` 与文档 |
| 数据 | MNIST + CIFAR-10 | 仅 MNIST，28×28 平均池化到 8×8 | `data.py` `_pool` |
| 全局轮次 | MNIST 10 轮，CIFAR-10 30 轮 | 默认 3，上限 20（`RunConfig.rounds`） | |
| 本地 epoch | MNIST 每轮 10 | 默认 2，上限 5 | `RunConfig.local_epochs` |
| 优化器 | PFLlib 默认（论文未给 LR/batch） | 普通 SGD + 交叉熵，lr=0.3，batch=64 | 项目显式声明 lr/batch 是自己选的 |

**关键事实**：`src/dgfl/training/paper_models.py` 确实实现了 582,026 / 878,538 参数的两层 CNN，`tests/training/test_paper_models.py` 覆盖了真实前反向，`scripts/benchmark_paper_training.py` 也跑过 512 样本的真实 MNIST 冒烟（`docs/research/evidence/paper-cnn-mnist-smoke.json`）。

但是 grep 显示 `paper_models` **只被 benchmark 脚本和测试引用**，`runner.py` 从不 import 它；且密码层有三道硬闸：

```python
_bounds:        not 1 <= d <= 20000        # 20,000 维上限 << 582,026
roles._prepare_data: policy['dimension'] != 650   → raise
roles._train:        policy['dimension'] != 650   → raise
```

→ **论文规模模型进入加密联邦训练这件事，目前进度是"训练侧已备好、密码侧完全未接通"。** `paper-alignment.md` §3 已把分块传输、紧凑证明、整数边界与 BSGS 内存重新测算列为前置条件。两个模型的逐层结构、参数量推导、向量布局、实测记录与接入四大硬闸见 [model-comparison.md](model-comparison.md)。

### 2.12 量化与解码边界

| 项 | 论文 | 项目 |
|---|---|---|
| 量化 | §V-A 步骤 2 提到 "quantized value `x_{i,j}`"，未给 scale/bits | scale=128、bits=8、`[-128,127]`、半整数向偶数舍入 |
| 有界 DLP | "resulting inner product fall within a polynomially bounded interval, thus allowing the recovery of the discrete logarithm" | BSGS，查找表上限 100,000 步；内积界 `Σ|z_j|·o`，聚合界 `[-N·o, N·(o-1)]` |
| 范数上界 | 显式上界 | 仅 `d·o²` 隐含（见 2.5） |
| 论文未给的参数 | 量化位宽/尺度、范数上限参数、CIFAR 训练配置 | `paper-alignment.md` §3.2 已列为"复现假设"，需向作者索取 |

项目在 §2.5 提到的 Cauchy–Schwarz 收紧解码区间（`min(o·Σ|z_j|, isqrt(Xi·T))`）是**尚未接入代码的候选优化**（`paper-alignment.md` §3.4 自述）。

### 2.13 密码群与实现栈

| 项 | 论文 | 项目 |
|---|---|---|
| 群 | 非对称双线性群 `e:G×H→GT` | 同 |
| 具体曲线 | **MNT224**（CZGQ/PrivLDFL/DGFlow）；HybridAlpha/TAPFed 用 1024-bit 整数群 | **BLS12-381** |
| 库 | Charm | `py-arkworks-bls12381==0.5.0` |
| 训练框架 | PFLlib | 自写 NumPy SGD（torch CPU 可选） |

→ 曲线不同 ⇒ **不能与论文做同安全参数的秒级性能比较**（`paper-alignment.md` §1 已声明）。BLS12-381 约 128-bit 安全，MNT224 更低，项目这条线其实更强，但代价是群运算更慢。

### 2.14 安全性证明 —— 论文的核心贡献之一，项目为零

论文给出的形式化结论：

| 论文结论 | 内容 | 项目状态 |
|---|---|---|
| 定理 1 | A1（拿到全部密文 + 可查 validatory 解密钥）:`Adv ≤ 2Q·Adv_DDH` | ❌ 无 |
| 定理 2 | A2（拿到全部密文 + 可查 aggregate 解密钥 + 可腐化客户端）:`Adv ≤ 2Q·Adv_DDH` | ❌ 无 |
| 定理 3 | 抗诚实但好奇的 authority 与 aggregator；`ς−1` 共谋抗性；`<ϵ` 聚合者时**信息论安全** | ❌ 无 |
| §V-B | 抗 KEP / MaMA（标签绑定） | ❌ 无形式化；靠代码里 ctx 绑定 |
| §V-B | 抗 MRPL（批次导致参与矩阵秩亏） | ❌ 无形式化 |
| §V-B | 抗 MPA（NIZK 可靠性 + 显式 `X_i` 上界） | 🟡 半条（可靠性有测试，上界缺失） |

项目 `proof-construction.md` §9 明确写的是"检查思路"（proof sketch），并自述"**组合外部审查未完成**"、"没有对本系统组合给出新的完整安全定理"。测试是负测试，不是安全归约。

**这不是"差一点"，而是论文 §IV-C + §V-B 整章的对应物都不存在。**

### 2.15 实验与评估 —— 论文的 §VI 基本没有对应物

| 论文实验 | 内容 | 项目 |
|---|---|---|
| 对比方案 | HybridAlpha[19]、TAPFed[21]、CZGQ[22]、PrivLDFL[24]，均用 Charm 实现 | **一个都没有**（grep `HybridAlpha\|TAPFed\|CZGQ\|PrivLDFL` 在 `src/` 下零命中，仅文档出现） |
| Table III | 总训练时间（MNIST 10 轮 / CIFAR 30 轮） | 无对应表；只有本项目自己的 plain/encrypted/dgflow/optimized 四模式对比 |
| Table IV | 20/40/60/80/100 客户端可扩展性 | 最多 6 客户端 |
| 客户端/服务端运行时分解 | Fig 4 | 无分解到论文粒度 |
| 通信开销 | Fig 5，MNIST 每客户端每轮 203 MB | 有 `bytes_sent` 总量（dgflow 单轮 436 MB / 6 客户端），口径与论文不同（论文是每客户端 payload，项目是 coordinator 全部 RPC 收发） |
| 攻击鲁棒性 | Fig 6 label-flipping（**ASR**）、Fig 7 free-rider（**OA**），攻击比 0–50% | **无 ASR、无 OA 计算**（grep 零命中）；攻击比上限受 `malicious_clients ≤ 2` 限制 |
| 论文所报数字 | 训练时间降 ≥28%、客户端通信降 ≥83%、ASR 0.3%/18.2%、OA 98.7%/72.7% | 均未复现，且当前构造下不可复现 |

关于攻击覆盖，还有两个具体问题：

1. **free-rider 实际不可用**。`model.attack_weights` 支持 `'free_rider'`，但 `RunConfig.attack` 的 `Literal` 不含它，所以界面上根本选不到；且 `_train` 里 `if attack in ('sign_flip','random')` 才会调 `attack_weights`，即使传入 `free_rider` 也只会走到"已训练模型原样返回"的分支，而 `attack_weights` 的 docstring 自己指出：要模拟 free-rider 必须传**本轮全局模型**，传已训练模型是错的。→ 论文 Fig 7 对应的攻击**在当前代码里无法正确执行**。
2. **label-flipping 是"标签整体 +1 偏移"**，不是论文语境下的目标类定向翻转；且论文用 ASR 度量"被误分类到攻击者选定目标类的比例"，项目只记录 `accuracy` 和 `attack_accepted`。

### 2.16 项目自己记录的差距（与本文一致）

`docs/research/paper-alignment.md` 与 `docs/submission/design-report.md` §9 已经如实列出：证明的 O(d·bits) 开销、模型坐标量化、范数及内积泄漏、固定批次损失、主控可用性单点、无 CUDA 实测、无三机实测、无外部密码审查、无大模型加密运行。本文与之一致，只是把"功能设计区别"拆得更细并补上代码级证据。

---

## 3. 项目超出论文的部分（不是差距，但需在报告中区分来源）

### 3.1 密码学扩展（改变威胁模型，需单独论证）

- **`DGFL-AGGREGATE-PAIRING-V1`**：把聚合器从论文的 honest-but-curious 提升到**拜占庭**模型。为每个云函数钥生成配对像正确性证明，合并端逐坐标核验 `E`，并从可信 DKG 转录独立派生承诺常数作锚。论文的 `AggComb` 只用 `D` 相等做一致性检查，而 `E` 本就逐云不同、无法用相等性约束。**代价是 650 维下单次合并约 73 s（占轮时 76%），详见 [aggregate-block.md](aggregate-block.md)。**
- **建钥摊销**：论文 §V-A 步骤 1 把 `AuthSetup` 列在 "Round Initialization" 下，但 §IV-C 的安全博弈 G1 只在 Initialization 跑一次、随后跨多个 label ℓ 查询，且密钥记号无轮次下标。项目按**摊销**实现（见 §7.1），与定理覆盖的构造一致。

### 3.2 工程实现（不改变密码学主张）

论文里没有、项目自建的工程能力：

- 四种可对照模式 `plain / encrypted / dgflow / optimized`（论文只有一种基线）；
- 完整跨进程角色隔离：HTTPS 双向证书 + Ed25519 签名 + X25519/HKDF + AES-GCM 密封信封（论文只给算法，不给网络协议）；
- 持久化不可变业务提交键、任务策略冻结、RPC 幂等重试、原子 JSON 状态；
- 真实进程故障注入实验（停 1 个 / 停 2 个聚合节点、停 1 个客户端）与证据留存；
- 本机 Web 控制台、历史对照、验证逐客户端视图、证据导出与打包校验；
- 论文未涉及的 GT 规范反序列化适配（`backend.gt_load`），用 Fp12 线性基还原而非 pickle；
- 四种客户端证明套件（`legacy` / `compact_range_v1` / `compact_norm_v1` / `lego_norm_v1`）与原生化 GT 批处理。

**3.1 是密码学上的实质扩展，必须给出自己的安全论证；3.2 应在报告里写成"作品工程实现"，不能算作对论文的复现。**

---

## 4. 补齐到论文的最小工作清单（建议优先级）

按"论文声称 + 项目当前缺口 + 可见收益"排序：

**P0 — 决定能否声称"复现论文"**
1. 实现论文的**显式范数上界**（§V-A 步骤 3），并把它绑进任务策略与学生成证明。
2. 实现**紧凑 NIZK**：batched Σ + 平方和 ZK 论证 + Fiat–Shamir，替换逐位范围证明。这是所有性能数字的前提。
3. 训练侧 582,026 / 878,538 参数 CNN **接入密码链路**：~~先做分块传输（绑定 task/round/epoch/清单摘要/块号/总数/整体摘要 + 重放/缺块/乱序负测试），再解除 `dimension != 650` 硬编码~~，再重算 `_bounds` 的 20,000 上限与 BSGS 内存。**（分块传输与维度参数化已完成，见文首更新）**

**P1 — 决定能否声称"与论文可比"**
4. **动态客户端加入**：放宽 `_policy` 的连续前缀约束，支持 `AuthSetup` 用更新后的 n 重跑并把新 σ 客户端聚为新批次。
5. **σ 可配置**：把 `batch_size==2` 变成受策略约束的参数，并补论文 §V-B 的秩亏论证。
6. **可配置门限 ς / ϵ**：替换 `[1,2,3]` + `2` 的硬编码；DKG 从"全员 ack 否则中止"升级为真正的 ς-out-of-w。
7. ~~**验证分工**：改为论文的"连接式委派 + 函数钥共享"~~。2026-10-06 已实现；新的分工与参数组合仍需独立性能评估。

**P2 — 决定能否声称"论文规模"**
8. 2026-10-06 已接通可配置客户端/边缘/云、动态参与方及门限；仍需补充 20–100 客户端的论文粒度资源预算和性能实测。
9. 补 CIFAR-10 数据加载与 878,538 参数模型的端到端加密训练。
10. 补 ASR / OA 指标与 0–50% 攻击比；修好 free-rider（必须传本轮全局模型）。

**P3 — 决定能否声称"性能优越"**
11. 实现至少一个对照方案（CZGQ 或 PrivLDFL）的等价基线，否则 ≥28% / ≥83% 无法验证。
12. 客户端/服务端运行时按论文粒度分解。

**P4 — 学术完整性**
13. 补 §IV-C 定理 1–3 对应的归约文档；补 §V-B 的 MaMA / MRPL / KEP 形式化论证；两者都需要外部密码学审查。
14. 把论文未给的量化、范数上限、CIFAR 训练配置列为**复现假设**并向作者索取。

---

## 5. 应如实保留、不应声称的部分

在当前代码状态下，以下表述**不能写进报告或答辩**：

- ❌ "复现了论文的 582,026 参数 CNN 安全联邦训练"（密码链路是 650 维线性分类器）；
- 已修正：支持配置 20 客户端与 4 云聚合（上限 100/32/32）；不能写成已完成论文规模性能评估。
- ❌ "支持客户端动态加入"（实际必须新建任务）；
- ❌ "DGFlow 比 CZGQ/PrivLDFL 快 28%、通信省 83%"（对照方案未实现，且曲线不同）；
- ❌ "ASR 0.3%、OA 98.7%"（无 ASR/OA 计算）；
- ❌ "已证明 DMAFE 安全性"（无定理，仅方程级审查）；
- ❌ "抗 ς−1 个被攻破 authority"（DKG 全员到齐否则中止）；
- 当前可在已配置 e/v 下由足够合法份额恢复；不能据此宣称自动拜占庭容错或完整论文安全结论。

可如实声称的：**DMAFE 的算法定义与代数构造已按论文公式重建；完整模型参数实际进入配对群密码链路；验证、筛选、固定批次、门限聚合、崩溃容错与故障注入均有可复现的原始记录。**

---

## 6. 论文自身的不足（向原文取证）

前五节讲项目缺什么。本节反过来：**论文有哪些地方不足以支撑复现，或本身存在技术缺口。** 每条给出原文依据。

### 6.1 `AggComb` 不核验 `E` —— 论文的威胁模型不含拜占庭聚合器

论文 §IV-B 的 `AggComb({a_{j,t}})` 只有三步：

```
① checks all D_{j,t} in the collection are equal
② E_j = Π_{t∈K} (E_{j,t})^{ξ_t}
③ C_j = D_{j,1} / E_j,   a_{s_j} = log(C_j)
```

**① 是一致性检查，不是正确性检查。** `D_{j,t} = Π_i e(ct_{i,j}, h^{y_i})` **不依赖 t**，各云算出的 `D` 必须相同，相等即证明它们用了同一批密文。而 `E_{j,t} = e(f_ℓ, dkey_{j,y,t})` **本来就逐云不同**，无法用相等性检查 —— 论文在这一点上就停了。

**这不是论文的疏漏，是威胁模型的边界。** 论文自己写明了：

> **Theorem 3**: The encryption key and functionality result of DMAFE are secure against **honest-but-curious authorities and aggregators**, respectively.

`Byzantine` 全文命中 **0 次**。论文给云列出的威胁只有 honest-but-curious 与**崩溃中断**（由 ϵ-out-of-v 门限容错覆盖）。

**honest-but-curious 的定义就是"遵守协议"**，所以 `E` 永远正确，无需核验。

**项目把聚合器扩展到拜占庭模型**：为每个云函数钥生成配对像正确性证明，合并端逐坐标核验。代价见 §7。

**报告口径应是"扩展威胁模型"，不是"修补论文缺陷"。** 后者会被"论文从未声称要防这个"反驳，而前者站得住。

### 6.2 `AuthSetup` 的执行频率在原文里是矛盾的

§V-A 步骤 1 把它列在 **Round Initialization** 之下：

> "1 Round Initialization. Edge nodes get the client size n, and run DMAFE.AuthSetup(n, m) to set up the authorities."

读起来像每轮一次。但紧接着的一句是：

> "**We note that DGFlow supports dynamic clients and sets up the authorities with the updated size**, where newly joined σ clients are clustered into a new batch."

"with the **updated** size" 只有在"客户端集合变化时才重跑"的前提下才成立。

**两种读法都讲得通，而这是协议里最贵的一步。** 论文既没有明确说摊销，也没有给出 `AuthSetup` 的复杂度或耗时。

**项目已按摊销读法对齐**（见 §7.1）：每个任务只跑一次建钥仪式，后续轮次复用。这既省掉每轮约 14.4 s，也让实现落回论文明确写出的那条分支。论文本身仍应补一句说明，否则复现者会像本项目一样先按每轮实现。

### 6.3 NIZK 只给了定义，没有给 CRS 的来源

§IV-A 定义了 `Gen(1λ, L) → crs`，但全文：

- 未说明 CRS 如何生成（单方？多方仪式？）
- 未声明任何可信设置假设
- 未说明 CRS 能否跨任务复用

`crs` 在 `Prove`/`Verify` 里都是显式输入，来源成谜。**任何复现都必须自行补一个可信设置假设，而论文没有把它列为假设。**

### 6.4 声称 "perfectly sound"，但关系式没有范围约束

§IV-A 原文：

> "The NIZK proof system is supposed to be **perfectly sound**, guaranteeing that the prover can only convince the verifier of a true statement."

而关系式是：

```
R(S,V)=1  iff  Z = Σ_{j∈[m]}(a_j)²   ∧   c_j = f_ℓ^{s_j} g^{a_j}
```

**没有 `a_j ∈ [0, 2^b)` 一类的范围约束。** 在 `Z_p` 上取模，`(a_j)` 与 `(a_j + p)` 给出同一个 `Z`。项目在 [proof-construction.md](../protocol/proof-construction.md) 记录了由此产生的回绕面，并用逐位范围证明堵住。

**"perfectly sound" 是对这个无范围关系的陈述，而这个关系本身不足以约束量化模型值。**

### 6.5 规模、量化、分阶段耗时均未给出

| 缺失项 | 原文状态 | 后果 |
| --- | --- | --- |
| 量化位宽 / scale | 全文只出现一次 "dequantizes it" | 无法复现数值精度 |
| 每阶段耗时 | Table III 只有总时长 | 60,107 s 无法归因 |
| 安全强度声明 | 无 "bits of security" / "security level" 字样 | MNT224 的实际强度未被讨论 |
| CRS 与证明体积 | 未给 | 无法估算通信与存储 |

### 6.6 Table III 里 DGFlow 并不是最快的

| 数据集 | 方案 | 总时长 (s) |
| --- | --- | ---: |
| MNIST | **TAPFed** | **3,634** |
| MNIST | HybridAlpha | 5,142 |
| MNIST | **DGFlow** | **60,107** |
| MNIST | CZGQ | 84,314 |
| MNIST | PrivLDFL | 143,213 |

**DGFlow 比 TAPFed 慢 16.5 倍、比 HybridAlpha 慢 11.7 倍**，只赢 CZGQ 与 PrivLDFL。

论文的表述限定在 "compared to the state-of-the-art **FE-based** PPFL schemes"，这个限定是准确的；但**引用时不能简化为"DGFlow 更高效"**。

另外：HybridAlpha 与 TAPFed 用 1024 位整数群，DGFlow / CZGQ / PrivLDFL 用 MNT224。**群不同意味着对比不是同一起跑线**，论文以 "maintain fair comparison" 一句带过，未给理由。

---

## 7. 本轮新增的实测成本证据

针对 §6.1 的缺口，项目自建的聚合完整性防护已量化（650 维、6 客户端、3 authority、3 云、门限 2，`lego_norm_v1`）：

| 块 | 秒 | 占整轮 |
| --- | ---: | ---: |
| **聚合、证明核验与确认** | **83.14** | **76.0%** |
| 分布式建钥（每轮） | 18.16 | 16.6% |
| 云部分解密 | 5.52 | 5.0% |
| 客户端 + 输入验证（紧凑证明，已是最快套件） | 8.09 | 7.4% |

单次 `combine` 的分项（[验收记录](evidence/validation-authorization-20261004/combine-cost-acceptance.md)）：

| 路径 | 秒 |
| --- | ---: |
| `_verify_aggregate_verification` × 9 条 | 59.57 |
| 最终插值 + 有界离散对数 | ~7.98 |
| `_aggregate_dkg_constants` | 4.67 |
| `_aggregate_numerators`（重算 D） | 2.51 |

**聚合块与客户端证明套件无关**：它用的是固定的 `DGFL-AGGREGATE-PAIRING-V1`，不出现在 `PROOF_SUITES` 中，因此紧凑证明/Lego 的加速完全触不到这 76%。

**两个已实测的方向**（记录以免重复投入）：

| 方向 | 实测 | 结论 |
| --- | --- | --- |
| 承诺解码去重 | 73.30 → 58.32 s（**1.26×**） | ✅ 已采纳 |
| 随机权重批验证 | 5.790 → 5.165 s（**1.12×**） | ❌ GT 侧新增的 `B_j^{w_j}` 恰好抵消 `base^{zs}` 的节省；整轮仅 ~5%，不值得引入概率性 |

**结论：成本集中在 11,700 次 GT 大指数（9 条 × 650 坐标 × 2），这是当前证明结构的内在成本。** 显著下降只能靠减少证明条数（3 云 × 3 authority = 9 条 → 更合适的证明构造），属研究级改动。

**这也让 §6.2 的取舍可量化**：每轮重跑 DKG 花掉 16.6%，换来的是论文未声称的每轮密钥新鲜度；摊销可省约 1.57×，但须先确认这道防线是否有意为之。

### 7.1 DKG 摊销已实施并与论文对齐（2026-10-06）

确认每轮重建并非有意设计后，已按论文的摊销读法改造：

| 位置 | 改动 |
| --- | --- |
| `runner.py` | `epoch` 提到轮循环外（任务级）；`transcript`/`share`/`receive_share`/`finalize` 只在首轮执行 |
| `roles.py` `begin` | 同一 epoch 复用已建好的 `Authority`；仅新 epoch 才重建并重置 `finalized` |
| `roles.py` | 新增 `envelope_context(ctx)`，把密封信封的绑定从 `key_epoch` 扩为 `key_epoch:round_id` —— epoch 变成任务级后，信封层否则会失去跨轮回放防护 |
| 五个测试文件 | 角色测试装置改用同一个 `envelope_context`，不再各自复制线格式 |

**实测（650 维、`lego_norm_v1`、3 轮）**：

| 轮次 | 整轮墙钟 | `dkg_s` | DKG 占比 |
| --- | ---: | ---: | ---: |
| 1 | 49.7 s | **14.81 s** | 29.8% |
| 2 | **36.0 s** | **0.49 s** | 1.4% |
| 3 | **35.7 s** | **0.43 s** | 1.2% |

轮 1 扣掉 DKG 后为 34.9 s，与轮 2/3 的 36 s 吻合，说明摊销没有引入其它副作用。**10 轮合计由约 500 s 降到约 370 s（1.35×）**，且后续轮次越摊越薄。

**MaMA 防护未受影响**：`ctx` 仍逐轮携带 `round_id` 与 `model_hash`，二者照常进入 `f = hash_point(ctx)`。

**回归**：1465 通过、12 跳过、0 失败；ruff 通过；跨版本冻结证明 4/4 仍接受、篡改仍拒绝。
