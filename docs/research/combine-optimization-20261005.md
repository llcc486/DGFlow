# 合并优化验收（2026-10-05）

已按承诺内容缓存、完整原生证明核验、随机 DKG 对照、减少重复传输的顺序完成优化。主控和三个 authority 继续独立核验同一份聚合，各证明逐坐标检查原方程；没有使用少验一份证明换取提速。

工作开始于 2026-10-04，完成及冻结于 2026-10-05；证据目录沿用开始日期。

## 相同处理器条件下的完整角色对照

每组两个完整 650 维 MNIST 轮次、十二个全新独立 mTLS 角色，seed=42，六客户端，非 IID，6000/1000 样本，五本地 epoch，Lego 650×8 位参数。相同 CRS、模型与筛选规则；每个 authority 的 Lego 核验预算为一个进程、两条原生线程，部分解密核验器为一条线程。实验进程与其十二个角色明确限制在 CPU 0–7，实际亲和性记录在每份 JSON 中。主服务亲和性未修改。下表为两轮算术平均，单位秒。

| 路径 | 整轮 | DKG | 验证 | 合并与确认 | 主控证明核验 | 发送 MB/轮 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| 旧实现，确定性 | 87.63 | 11.79 | 4.97 | 55.17 | 46.26 | 118.71 |
| 内容缓存 + 原生核验，确定性 | 66.04 | 12.36 | 4.91 | 33.27 | 22.98 | 118.71 |
| 原生核验 + 随机 DKG | 58.98 | 8.15 | 2.13 | 32.78 | 22.80 | 118.71 |
| 此前 optimized 传输 | 59.05 | 8.32 | 2.07 | 32.99 | 22.76 | 116.32 |
| 新增证书去重的 optimized 传输 | 59.44 | 8.62 | 2.15 | 32.64 | 23.03 | 92.08 |

保持确定性模式时，完整原生核验使证明核验减少 50.3%，合并与确认减少 39.7%，整轮减少 24.6%。

只改变验证模式的 native→randomized 对照中，DKG 加速 1.52×，验证加速 2.31×。默认仍为 deterministic，randomized 必须显式选择；随机加权 DKG 批验仍有相反残差攻击回归保护。所有组前两轮模型摘要、准确率和批准/拒绝集合完全一致。

新增证书去重相对同为 optimized 的旧通信格式，每轮精确减少 24.24 MB（20.8%）。dgflow→optimized 的总差额还包含此前已有的客户端 proof 裁剪，不能全部归因于本次改动。

最终方案相对本组旧基线，平均整轮减少 32.2%。这是每组两轮的本机测量，不代表统计显著性、论文规模或三机部署；完整验证与合并仍是秒级。

## 缓存、原生算术与信任边界

- 缓存限于单次 combine，以 authority 身份和完整规范承诺编码为键；数学证明通过后才保存，命中仍核对当前 DKG 锚及每份证明。真实 RPC 经重新解码后，每个合并均为三次未命中、六次命中。跨 combine 不保留该缓存。
- Rust PublicAggregateVerifier 批量解码并独立核验所有坐标的两条方程。opaque polynomial 绑定 G/H/T，缺少新 API 时保留 Python 参考路径。
- 公开 T 的四位窗口表约 576 KiB；受检 GT 先通过规范编码、非零、精确 cyclotomic 归属和完整 q 阶检查，再使用快速公开指数运算。unitary 条件不足以替代该检查；Rust 独立 oracle 覆盖一般域元素、unitary 非 cyclotomic、cyclotomic 非 q 阶及合法 GT。
- 通用 NativeGT.pow_bytes 与生成端秘密份额/随机数的指数路径未修改。电路、CRS、证明格式及逐坐标方程保持一致。
- finish 先验云签名，再从受认证 body 提取 authority 证书，仍逐份独立验签、检查可信 DKG 来源及数学证明。旧显式列表须与内嵌内容和数量相同，允许重排。只有 optimized 且三个 authority 明确支持时才省去重复字段。

## 四个合并进程的独立计时

最终两轮平均，单位秒。云 E 列是此前漏计的重算；上下文/材料列包含原生核验器及公开表的当次构建。

| 进程 | 重算 D | DKG 常数 | 上下文/材料 | 证明核验 | 重算云 E | 插值恢复 | combine 总计 | 进程 CPU |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| coordinator | 2.16 | 2.35 | 0.10 | 23.03 | 3.60 | 1.30 | 32.54 | 35.16 |
| authority1 | 1.66 | 2.43 | 0.08 | 22.69 | 3.19 | 1.20 | 31.25 | 29.84 |
| authority2 | 1.65 | 2.45 | 0.07 | 22.74 | 3.32 | 1.18 | 31.41 | 29.71 |
| authority3 | 1.69 | 2.41 | 0.07 | 22.82 | 3.27 | 1.18 | 31.45 | 29.99 |

各进程并发执行，其墙钟不能相加；不同进程阶段最大值也不能拼接成一条关键路径。进程 CPU 包含同进程其他线程，不等于证明独占 CPU。计时通过独立且绑定上下文/轮号的 RPC 返回，未混入必须一致的 finish 共识响应。

## 保留中间结果，避免错误归因

最初未限制处理器的 clean baseline 为 52.58 秒/轮；仅修内容缓存为 54.30 秒/轮，没有测出整轮收益；v1 原生 API 为 54.50 秒/轮，也未测出整轮提速。后续 v2 为 38.98 秒/轮，但再后一次随机模式运行时连未改动阶段也明显变慢，所以不将这些组直接累计为最终加速比。上述结果均保留在原始 JSON。固定亲和性能够减少调度差异，仍不能完全排除机器频率和背景活动变化。

第一份 baseline.json 与用户另一个实验同时运行，且最后的旧版诊断 RPC 请求失败，仅作为审计记录。历史 125.62 秒记录与本组机器状态不同，未纳入因果加速比。原来基于共享对象夹具的 1.26× 缓存数字不适用于真实 RPC；旧 pow_bytes 的 1,249 µs 是混合指数平均，不能当作固定底数大指数单价。

## 验证与实际服务

最终 v2 原生扩展下全套 Python：960 passed / 15 skipped / 0 failed。跳过均为已有可选路径，详见 test-summary.json；本次关键原生核验、部分解密攻击与通信回退测试无跳过。另有 Rust 13 项通过、通信专项 186 项通过、前端 19 项通过与构建通过、Ruff 通过。四套冻结旧证明全部仍通过，篡改版本均被拒绝。

在主集群空闲且十二角色身份核对通过后，已备份旧扩展、安装经过验收的 wheel 并重启全部角色及控制服务；十二个角色均报告相同新 pyd 摘要。实际桌面服务的两轮任务 `4e593357b0dc4bb2bbcf01722fc08105` 已完成，模型与隔离对照一致，并实际启用证书去重；该服务使用正常系统调度，其时间单列，不混入固定亲和性对照。

实际服务两轮任务总耗时 71.71 秒，轮墙钟平均 34.15 秒，最终准确率 43.3%。总耗时包含任务初始化，与轮墙钟口径不同；不能将正常调度的数据直接拿来计算固定亲和性对照的加速比。

源码交付版本为 dgflow-20261005-aggregate-opt1；SOURCE-MANIFEST.json 绑定当前完整文件集合。源码 ZIP 与配套 wheel 分开交付；旧 wheel 已单独保留，部署时会备份原安装目录以便回退。

## 证据与复现

[完整汇总](evidence/combine-optimization-20261004/summary.json)、[原生验收](evidence/combine-optimization-20261004/native-acceptance.json)、[测试摘要](evidence/combine-optimization-20261004/test-summary.json)、[冻结证明兼容](evidence/combine-optimization-20261004/frozen-proof-compatibility.json)。[服务激活](evidence/combine-optimization-20261004/activation.json)、[真实服务任务](evidence/combine-optimization-20261004/production-run.json)。

baseline-source.zip 和 checked-source.zip 保存本次公共 Python 源码快照，摘要见 reproduction-artifacts.json，不包含身份、运行数据或 pyc。配套旧 wheel 在 dist/native-baseline-20261004/，新 wheel 在 dist/native/；源码 ZIP 不包含 wheel。复现旧基线时解压 baseline-source.zip 到 tmp/compare-baseline；将相应 wheel 解包到项目内的独立目录，不替换正在运行的服务。需先安装相同 CRS 及缓存 MNIST，并让主服务空闲。

```powershell
.venv\Scripts\python.exe scripts/benchmark_combine_roles.py --runtime runtime-recheck --source-dir src --native-dir tmp/checked-new-wheel --cpu-affinity 0,1,2,3,4,5,6,7 --verification randomized --mode optimized --rounds 2 --output tmp/recheck.json
```

runtime 必须是尚不存在的独立项目子目录，不能使用主 runtime；脚本只关闭自身已核对身份的角色。每份报告记录实际源码、pyd 摘要、模式、各进程计时、亲和性及清理结果。
