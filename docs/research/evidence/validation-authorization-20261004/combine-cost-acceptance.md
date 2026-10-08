# 聚合验证加固的成本验收

日期：2026-10-04。范围：650 维、6 客户端、3 authority、3 云结果、门限 2。

## 为什么需要这份记录

`aggregate_key` 的配对像正确性证明与 `combine` 的可信材料强制是**安全加固**，不是性能工作。上线前未完成 650 维完整聚合的性能验收，因此这次加固的代价没有被提前量化。本文补上该缺口。

激活证据见同目录 [activation.json](activation.json)：磁盘源码摘要不能证明进程已加载新版，加固检查是在替换原生扩展并重启全部角色与控制服务后才在实际服务中生效的。

## 加固引入了什么

| 位置 | 内容 |
| --- | --- |
| `aggregate_key` | 新增 DKG 承诺绑定的配对像正确性证明，密封给指定云 |
| `combine` | 强制接收可信 `verification_materials` 与批准的 `packets` |
| `combine` | 从批准密文重算 `D`，从可信 DKG 转录派生承诺常数 |
| `combine` | 逐份逐坐标核验部分解密证明，检查跨云多项式一致性，再重算并核对云的 `E` |

旧版 `combine`（[acceleration-lego/current/src/dgfl/crypto/protocol.py:506](acceleration-lego/current/src/dgfl/crypto/protocol.py#L506)）只检查上下文、清单与各方 `D` 一致后插值恢复，不证明 `E` 正确。

**四次独立合并原本就存在**：旧 runner 已执行主控合并与三个 authority 的 `finish`。变化是每份合并内部增加了检查，不是从一次变成四次。

## 单次 `combine` 的实测分解

同一夹具（3 云 × 3 authority = 9 份证明）下单独计时，三次中位数。

| 路径 | 加固后 | 说明 |
| --- | ---: | --- |
| `_verify_aggregate_verification` × 9 条记录 | **59.57 s** | 每条 6.62 s |
| `_aggregate_dkg_constants` | **4.67 s** | 每次重解码 23,400 个转录点 |
| `_aggregate_numerators`（重算 D） | **2.51 s** | 650 次配对 |
| 最终插值 + `bounded_log` | ~7.98 s | 含 3 份权重合并与 650 次 GT 求逆 |
| **合计** | **74.73 s** | 与线上 `combine_and_confirmation_s` = 73.06 s 吻合 |

**79.7% 集中在 `_verify_aggregate_verification`。**

## 原语级热点（cProfile）

| 原语 | 调用次数 | 自身秒 |
| --- | ---: | ---: |
| `NativeGT.pow_bytes`（混合大小指数） | 20,150 | 25.16 |
| `from_compressed_bytes`（G1 受检解码） | 44,850 | 8.79 |
| `multiexp_unchecked`（MSM） | 5,850 | 5.82 |
| `pairing` | 650 | 1.85 |
| `NativeGT.inverse` | 10,085 | 0.57 |

调用计数与 650 维、6 客户端、3 云 × 3 authority 的解析推导逐项一致。

## 已落地的优化

### 对象身份去重的历史夹具测量

该本地夹具让同一 authority 的三条云记录携带同一个 `commitments` 对象，按对象身份在同一 `combine` 内复用受检解码。实际 RPC 解码会创建不同列表，原实现不能对三云重复内容命中；下表仅保留历史夹具测量，不代表真实角色收益。

| | 去重前 | 去重后 |
| --- | ---: | ---: |
| `combine` 中位数 | 73.30 s | **58.32 s** |
| `from_compressed_bytes` 调用 | 44,850 | **37,050** |

2026-10-05 已改为按 authority 身份与完整规范承诺内容进行调用内去重；命中仍检查当前 DKG 锚与每份证明。真实角色计时和受检原生核验记录见 [本次四进程对照目录](../combine-optimization-20261004/)。不能用这份夹具的 1.26× 代替新版真实 RPC 对照。

### 分项计时（已完成）

最初四个计时未覆盖云 `E` 重算和材料处理。新版补齐 `combine_context_materials_s`、`combine_cloud_E_s`、`combine_total_s`、`combine_cpu_s` 与缓存计数；`round.combine_metrics` 保留主控及三个 authority 各自的上下文、轮号与完整指标，原 `*_max` 继续兼容。不同节点的阶段最大值不能相加当成某个节点的关键路径；进程 CPU 也包含该进程其他线程。

**计时数据刻意不进入 `finish` 响应**：三份确认响应需要逐字段相等，诊断数据不得混入被比对的载荷。

**面板归属问题**：`aggregate_verification_s` 只记录外层证书签名与身份、上下文检查（0.34 s）；逐坐标数学证明核验在 `_verify_aggregate_verification` 内，计入 `combine_and_confirmation_s`。看到 `aggregate_verification_s` 很小并不代表聚合验证便宜。

## 后续措施的当前状态

| # | 措施 | 依据 | 状态 |
| --- | --- | --- | --- |
| ① | 公开 GT 固定底数窗口预计算 | 单次 `combine` 5,850 次公开响应 `T^zs` | 已在独立原生核验器实现；生成端跨全部 authority/cloud 的 11,700 次秘密 `T^s/T^u` 保持原算术 |
| ② | 公共转录点复用 | 四个独立合并进程；每轮新 key_epoch | 未实现跨进程信任缓存；可另行研究节点内部严格上下文绑定的公共点复用 |
| ③ | 原生批解码与完整证明核验 | 缓存内 opaque polynomial 复用，各证明逐坐标检查两条方程 | 已实现 `PublicAggregateVerifier`；保留规范编码、子群、标量与 DKG 锚检查，Python 参考路径继续可用 |

## 未验证事项

- 以上为单夹具、单机计时。**不能外推为论文规模或三机部署的成本。**
- 历史 `pow_bytes` 1,249 µs 是 20,150 次混合大小指数调用的平均，不能当成公开固定底数大指数的单价。
- 本文原始测量没有分别采集四进程墙钟；新版角色对照保留独立指标，仍须避免将并发时间相加。

## 2026-10-05 真实角色验收

相同 CPU 0–7 亲和性、每组两个完整轮次的对照中，确定性模式证明核验由 46.26 降至 22.98 秒，合并与确认由 55.17 降至 33.27 秒；最终随机 DKG 和优化传输方案平均 59.44 秒/轮，对照旧基线为 87.63 秒/轮。新增证书去重相对旧 optimized 传输每轮减少 24.24 MB，但没有测出额外整轮提速。

源码及配套 wheel 已完成验收。用户明确批准后，已在主集群空闲且角色身份核对通过时备份旧扩展、安装新构建并重启全部角色和控制服务，十二个角色实际加载的新 pyd 摘要一致。详细控制条件、中间未提速的结果、四进程分解及实际服务记录见[新版验收报告](../../combine-optimization-20261005.md)；不能把这些数字直接与历史 125.62 秒或旧共享对象夹具比较。
