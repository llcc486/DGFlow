# 聚合块详解

对象：一次轮次里「合并、证明核验与确认」的全部工作，650 维 / 6 客户端 / 3 authority / 3 云 / 门限 2 / `lego_norm_v1`。

实测占整轮 **76%**（约 83 s / 110 s），是当前最大的单项成本，也是论文里没有的机制。

---

## 1. 它在协议里的位置

论文 §V-A 步骤 4「Model Aggregation」：

```
云 R_t:  AggDec  →  a_{j,t} = (D_{j,t}, E_{j,t})
边缘节点: AggComb({a_{j,t}})  →  a_{s_j} = Σ_{i∈Φℓ} x_{i,j}
```

项目在**一次轮次里跑 4 次完整 combine**：主控 1 次，3 个 authority 各 1 次（经 `finish` 动作）。四次并发提交到同一个线程池，所以**墙钟由最慢那次决定，不是相加**。

`combine_and_confirmation_s` 量的就是这一次墙钟。

---

## 2. 它为什么存在 —— 项目扩展了论文的威胁模型

### 先厘清：这不是论文的 bug

论文自己把模型写明了。**定理 3**：

> The encryption key and functionality result of DMAFE are secure against **honest-but-curious authorities and aggregators**, respectively.

`Byzantine` 全文命中 **0 次**。论文给云列出的威胁只有两类：

| 威胁 | 论文的应对 |
| --- | --- |
| honest-but-curious（遵守协议但会偷看） | DMAFE 机密性（定理 3） |
| **崩溃 / 中断**（不返回结果） | ϵ-out-of-v 门限容错 |

**honest-but-curious 的定义就是"遵守协议"** —— 所以 `E` 永远是对的，不需要核验。

**项目把聚合器提升到拜占庭（任意错误输出）**，代价是 76% 轮时。这是**扩展威胁模型**，不是修论文的错。

### 论文的 `AggComb` 检查了什么

```
① checks all D_{j,t} in the collection are equal     ← 唯一检查
② E_j = Π_{t∈K} (E_{j,t})^{ξ_t}
③ C_j = D_{j,1}/E_j,   a_{s_j} = log(C_j)
```

**① 是一致性检查，不是正确性检查。** `D_{j,t} = Π_i e(ct_{i,j}, h^{y_i})` **不依赖 t**，所以各云算出的 `D` 必须相同；相等即证明它们用了同一批密文。

而 `E_{j,t} = e(f_ℓ, dkey_{j,y,t})` **本来就逐云不同**（各云函数钥不同），**无法用相等性检查**。论文在这一点上就停了。

### 拜占庭聚合器能做什么

若某个云把 `E_{j,t}` 乘上偏差 `δ`：

```
C_j = D_j / (δ·E_j)   →   a_{s_j} = Σ x_{i,j} y_i − log δ
```

**可以对每个坐标独立加任意偏移 —— 逐坐标任意篡改全局模型**，而 `D` 相等检查完全看不出来，因为错的是 `E`。

### 触发这次加固的实际攻击

项目的攻击记录（[review-fixes-20261004.md](review-fixes-20261004.md)）：

> | 合法恶意节点修改部分解密 E | ... **原来把 17 改成 7 的篡改被拒绝**；真实合法云身份重新签名的错误结果也被所有 authority 拒绝。 |

关键在于：**攻击者持有真实云身份，签名是有效的。**

[proof-construction.md](../protocol/proof-construction.md) 把这一点说得最直白：

> 旧的仅签名 `D/E` 结果不能被新合并器接受。**签名认证身份；以下证明额外约束实际的配对指数。**

**签名只能证明"这是谁交的"，不能证明"交的值是对的"。** 而拜占庭模型要求的正是后者。

---

## 3. 设计约束：为什么必须用证明，而不能直接重算

看起来边缘节点自己签发了 `dk`，应该能重算 `E`。**但它拿不到 G2 函数钥。**

`aggregate_key` 返回：

```python
'keys': [b.g2_dump(b.G2 * b.scalar(_poly(row, cloud_id))) for row in polys]
```

这份 `keys` **只密封给指定云**。[proof-construction.md:323](../protocol/proof-construction.md)：

> 签名证书及证明连同 G2 函数钥**先密封给对应云**，云发布其部分解密时才公开证书。**coordinator 不能通过公开 authority 动作提前取**...

**这是有意的**：如果 coordinator 拿到函数钥，它就能自己算出部分解密，云这一层就失去意义。

**所以需要一个"不需要 G2 钥也能核验"的构造 —— 这正是 Σ-协议的作用。** `_prove_aggregate_verification` 的 docstring 就是 "without G2 keys"。

> 补充：authority 跑 `finish` 时**确实持有 `keys`**，理论上可直接重算（1,950 次配对 ≈ 2.1 s）。但 4 次 combine 并发，**墙钟由 coordinator 决定，而 coordinator 没有钥**。所以这条只省 CPU，不省墙钟。

---

## 4. 证明的数学结构

对云 `t`、坐标 `j`。记 authority 的多项式承诺为 `C_{j,k} = G·a_{j,k} + H·r_{j,k}`（Pedersen，公开）。

### 陈述与见证

| | 内容 |
|---|---|
| 公开底数 | `base = e(H(ctx), G2)` —— 每轮一个，按上下文规范字节缓存 |
| 见证（秘密） | `s_j = Σ_k a_{j,k} t^k`（云 `t` 的函数钥标量）、`r_j = Σ_k r_{j,k} t^k` |
| 公开像 | `E_j = base^{s_j}` |
| 要证的命题 | 「`E_j` 确实是承诺多项式在 `t` 处的值的配对像」 |

### 协议（Fiat–Shamir 非交互化）

```
证明者（authority）:
  u_j, v_j ← 随机标量
  A_j = G·u_j + H·v_j          ← G1 第一消息
  B_j = base^{u_j}             ← GT 第一消息
  e   = H(statement)           ← statement 含 E/A/B/上下文/承诺/approved
  zs_j = u_j + e·s_j
  zr_j = v_j + e·r_j
  发布 (E, A, B, zs, zr)

核验者（coordinator 或 authority），逐坐标:
  ① commitments[0] == constants[j]         ← 锚定到可信 DKG 转录
  ② C_j = Σ_k C_{j,k}·t^k                   ← MSM
  ③ G·zs_j + H·zr_j − A_j − e·C_j == 0      ← G1 侧，一次 4 点 MSM
  ④ base^{zs_j} == B_j · E_j^{e}            ← GT 侧，两次大指数
```

**步骤 ① 是这套证明的安全根**：它把 `C_{j,0}` 钉在从可信 DKG 转录独立派生的常数上，否则证明者可以自选多项式、自证自话。

`_aggregate_verification_challenge` 在算 `e` 之前把全部字段（suite、authority_id、cloud_id、epoch、context_hash、manifest_hash、transcript_hash、approved、commitments、E、A、B）逐个类型与取值校验一遍 —— **挑战必须覆盖被证明的全部内容，任何字段漏进挑战都是可伪造面。**

---

## 5. 一次 combine 的四个阶段（实测）

| 阶段 | 函数 | 秒 | 占比 |
|---|---|---:|---:|
| 重算 D | `_aggregate_numerators` | 2.51 | 3.4% |
| 派生 DKG 承诺常数 | `_aggregate_dkg_constants` | 4.67 | 6.3% |
| **核验 9 条云证明** | `_verify_aggregate_verification` | **59.57** | **79.7%** |
| 插值 + 有界离散对数 | `_combine` 尾部 | ~7.98 | 10.7% |
| **合计** | | **74.73** | |

**79.7% 集中在证明核验。**

### 为什么是 9 条

**3 份云结果 × 每份 3 个 authority 证明 = 9 条。** 门限是 2，但代码处理的是实际在场的 3 个 authority，不是门限数。

### 单条记录的调用量（650 坐标）

| 原语 | 次数 | 说明 |
|---|---:|---|
| GT 受检解码 `gt_load` | 1,300 | 每坐标 `B`、`E` 各一次 |
| **GT 大指数 `gt_pow`** | **1,300** | 每坐标 `base^{zs}` 与 `E^{e}` |
| G1 受检解码 `g1_load` | 1,950 | 每坐标 2 个承诺点 + 1 个 `A` |
| G1 MSM | 1,300 | 承诺合并 + 4 点验证方程 |
| 标量解码 | 1,300 | `zs`、`zr` |

### 全局调用量（9 条）

| 原语 | 次数 | cProfile 自身耗时 |
|---|---:|---:|
| `NativeGT.pow_bytes` | **20,150** | **25.16 s** |
| `from_compressed_bytes` | 44,850 | 8.79 s |
| `multiexp_unchecked` | 5,850 | 5.82 s |
| `pairing`（重算 D） | 650 | 1.85 s |
| `NativeGT.inverse` | 10,085 | 0.57 s |

**调用计数与 650 维、9 条证明的解析推导逐项吻合**，说明分解没有遗漏。

---

## 6. 为什么这么贵 —— 结构性下界

成本几乎全部是 **GT 大指数**：

```
11,700 次（9 条 × 650 坐标 × 2）  ×  ~1.25 ms  ≈  15 s
```

`NativeGT.pow_bytes` 孤立测 **872 µs**，在 combine 上下文里 **1,249 µs**（1.43×，原因未定位）。

**每坐标两次 GT 大指数是这个证明结构的内在成本：**

- `base^{zs_j}` —— 底数固定（`base` 每轮一个），理论上可预计算
- `E_j^{e}` —— **底数逐坐标不同，不可合并**

**CT 侧无法批量化**：随机权重批验证展开后是

```
base^{Σ w_j zs_j} · Π_j B_j^{w_j} · Π E_j^{e·w_j}
```

`base^{zs}` 的 650 次省成 1 次，**但 `B_j` 原本只是"加载"，现在要变成 650 次求幂** —— 恰好抵消。

---

## 7. 已实测的三个方向

| 方向 | 实测 | 结论 |
|---|---|---|
| **承诺解码去重** | 73.30 → 58.32 s（**1.26×**） | ✅ **已采纳** |
| 随机权重批验证 | 5.790 → 5.165 s（**1.12×**） | ❌ GT 侧抵消 `base^{zs}` 的节省；整轮仅 ~5%，不值得引入概率性 |
| GT 固定底数预计算 | 估算整轮 5–7% | ❌ 不值得改 Rust + 重跑 CRS 验证 |

**去重为什么有效**：同一 authority 的三条云记录携带**同一个** `commitments` 对象，验证器原本对相同的 1,300 个点执行三次 `g1_load`。按对象标识在同一 `combine` 调用内复用后，`from_compressed_bytes` 从 44,850 降到 37,050（正好 −7,800）。

复用的点全部来自本次调用已通过检查的解码结果，**未受检的点无法进入**。

---

## 8. 当前实现的结构

`combine` 只是外壳，**外部调用者不能传句柄**：

```python
def combine(...):
    """Full independent verification; external callers cannot supply handles."""
    return _combine(...)
```

内部句柄一律本地生成，这是防止"跳过核验"的接口设计。

| 机制 | 作用 |
|---|---|
| `native_verifier`（`PublicAggregateVerifier`） | 原生批量核验；`_prepare_aggregate_verification` 只解码不判真，成功后才提升为受检句柄 |
| `decoded_cache` | 按 `('native-checked-g1-v1', authority_id, commitments)` 复用受检解码 |
| `pending_cache` | 批内暂存；**只有整批成功才提升** —— 不拿同伴的结果替代自己的检查 |
| `checked_dkg`（`_CheckedAggregateDKG`） | 复用已核验的转录派生，避免每轮重复 `_aggregate_dkg_constants` |
| `_aggregate_pairing_base` | `base` 按上下文规范字节 `lru_cache(maxsize=128)`；上下文快照保证不会跨轮复用 |
| `compute_device='gpu'` | 走 `GPUAggregateVerifier.verify_many` 批路径 |

**分项计时**（`timings` 字典，仅诊断、不影响结果）：`combine_numerators_s` / `combine_dkg_constants_s` / `combine_proof_verification_s` / `combine_interpolation_s`，另有 `combine_dkg_transcript_reused` 与缓存命中计数。

---

## 9. 结论

**这 83 秒买的是拜占庭聚合器下的聚合完整性。** 它防的攻击是真实的：一个持有合法云身份的节点改一个数，就能逐坐标平移全局模型。

**但它不是论文的缺陷。** 论文明确把聚合器建模为 honest-but-curious（定理 3），云的另一类威胁是崩溃中断（由门限容错覆盖）。**项目把聚合器提升到拜占庭，这是威胁模型的扩展，不是对论文错误的修正。**

**成本已在结构性下界附近** —— 11,700 次 GT 大指数是这个证明结构的必然量，批验证与固定底数实测都不划算。

**唯一能显著下降的路径是减少证明条数**（9 条 → 更少，例如用多点求值让一个 authority 的证明覆盖多个云）。但那是**新的证明构造**，需要重新做安全论证，属研究级改动，不是优化。

**在报告中应该这样写**：

> 论文的 DMAFE 面向 honest-but-curious 聚合器（定理 3），云的另一类故障是崩溃中断。项目在保持论文全部属性的前提下，把聚合器扩展到拜占庭模型：为每个云函数钥生成配对像正确性证明，合并端逐坐标核验。代价是 650 维下单次合并约 73 s（占轮时 76%），已实测的优化空间低于 10%。

**把威胁模型的差异、代价和动机一起写**，否则看到 76% 的人会先问"为什么这么慢"，而不是"这个模型扩展值不值"。
