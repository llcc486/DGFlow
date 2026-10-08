<script setup>
import { computed } from 'vue'
import LogoMark from '../components/LogoMark.vue'
import LabIcon from '../components/LabIcon.vue'
import { consoleStore as store } from '../lib/store'
import { deployedTopology } from '../lib/deployment.js'

const emit = defineEmits(['navigate'])

const features = [
  {
    icon: 'lock',
    title: '密码学保护本地模型',
    text: '客户端只提交配对群密文。聚合节点执行部分解密，但单独无法解出任何明文模型。',
    points: ['BLS12-381 上的真实配对运算', 'Pedersen 分布式建钥与可配置门限', '密钥周期与轮次标签绑定'],
  },
  {
    icon: 'shield',
    title: '鲁棒输入验证',
    text: '公开平方范数由零知识证明绑定到密文本身，伪造范数无法通过；验证节点结合范数门限与相似度筛除异常更新。',
    points: ['密文绑定的范围与平方范数证明', '验证内积完全在密文上完成', '合格成员重新组队，减少连带排除'],
  },
  {
    icon: 'file',
    title: '可核验的实验证据',
    text: '每轮配置、阶段耗时、通信量、逐客户端判定与拒绝理由全部由后端记录，界面只展示真实结果。',
    points: ['原始任务记录可导出', '跳过与失败原因如实保留', '不推测尚未发生的阶段'],
  },
]

const roles = computed(() => [
  { name: '训练客户端', count: deployedTopology(store.status.value)?.client_count ?? '2–100 可选', duty: '本地训练、量化、加密与证明生成，归属单个边缘', deny: '其他客户端的数据与密钥' },
  { name: '边缘服务器', count: deployedTopology(store.status.value)?.authority_count ?? '2–32 可选', duty: '分布式建钥、固定函数钥、独立验证与授权', deny: '单节点完整全局主密钥' },
  { name: '云服务器', count: deployedTopology(store.status.value)?.aggregator_count ?? '2–32 可选', duty: '核对许可、部分解密、签名结果', deny: '任何客户端明文模型' },
  { name: '控制服务', count: '1', duty: '调度、转发密封消息、记录公开结果', deny: '角色私有份额与个体明文' },
])

const steps = [
  { no: '01', name: '分布式建钥', text: '边缘服务器通过 Pedersen DKG 分发份额，客户端只重建自己的密钥行并核对公开承诺。' },
  { no: '02', name: '本地训练与加密', text: '客户端在本机数据上训练、量化，把每个坐标加密为群元素，并生成绑定密文的范围与范数证明。' },
  { no: '03', name: '密文验证与筛选', text: '验证节点核验证明、在密文上求内积得到余弦相似度，结合范数门限筛选并按配置组队。' },
  { no: '04', name: '门限聚合', text: '云服务器产生带签名的部分解密，达到配置的云门限 ϵ 后才能恢复整数和并生成下一轮模型。' },
]
</script>

<template>
  <div class="nb-page">
    <!-- Hero — mirrors the NEBULA landing headline + logo lockup -->
    <section class="nb-hero">
      <h1 class="nb-hero-title">DGFlow：去中心化云边<span class="accent">联邦学习</span>平台</h1>
      <p class="nb-hero-sub">面向跨机构协同训练的隐私保护与鲁棒聚合研究实验台。<br>完整模型参数真实进入配对群密码链路。</p>
      <div class="nb-hero-mark">
        <LogoMark :size="78" />
        <span class="nb-hero-wordmark">DGFlow</span>
      </div>
      <div class="nb-hero-tagline">Privacy-preserving · Robust aggregation · Auditable evidence</div>
    </section>

    <!-- Credits band — the muted full-width strip NEBULA uses for project provenance -->
    <section class="nb-band">
      <div class="nb-container">
        <div class="nb-credits">
          DGFlow Lab 依据论文 <span class="name">DGFlow: Privacy-Preserving and Robust Cross-Silo Federated Learning in Decentralized Cloud-Edge</span><br>
          重建去中心化多授权方函数加密（DMAFE）与零知识输入验证，形成可运行、可检查的实验系统。
        </div>
        <div class="nb-credits-rule"></div>
        <div class="nb-row" style="justify-content:center; gap:26px">
          <button class="nb-btn primary" @click="emit('navigate', 'deploy')">
            <LabIcon name="play" :size="16" />部署一场实验
          </button>
          <button class="nb-btn outline" @click="emit('navigate', 'dashboard')">
            <LabIcon name="grid" :size="16" />查看看板
          </button>
        </div>
      </div>
    </section>

    <!-- Capability cards -->
    <section class="nb-sect">
      <div class="nb-container">
        <h2 class="nb-section-title left">系统能保证什么</h2>
        <p class="nb-section-sub left">三条设计主线，全部对应后端已实现并留有实测记录的机制。</p>
        <div class="nb-feature-grid" style="margin-top:26px">
          <article v-for="feature in features" :key="feature.title" class="nb-feature">
            <span class="nb-feature-icon"><LabIcon :name="feature.icon" :size="22" /></span>
            <h3>{{ feature.title }}</h3>
            <p>{{ feature.text }}</p>
            <ul><li v-for="point in feature.points" :key="point">{{ point }}</li></ul>
          </article>
        </div>
      </div>
    </section>

    <!-- Roles -->
    <section class="nb-band">
      <div class="nb-container">
        <h2 class="nb-section-title left">角色与信任边界</h2>
        <p class="nb-section-sub left">四个角色分属不同进程与身份，各自持有独立密钥材料。</p>
        <div class="nb-card" style="margin-top:26px">
          <div class="nb-table-scroll">
            <table class="nb-table">
              <thead>
                <tr><th>角色</th><th>数量</th><th>职责</th><th>不应获得的内容</th></tr>
              </thead>
              <tbody>
                <tr v-for="role in roles" :key="role.name">
                  <td><strong>{{ role.name }}</strong></td>
                  <td class="mono">{{ role.count }}</td>
                  <td>{{ role.duty }}</td>
                  <td class="muted">{{ role.deny }}</td>
                </tr>
              </tbody>
            </table>
          </div>
        </div>
      </div>
    </section>

    <!-- Protocol steps -->
    <section class="nb-sect">
      <div class="nb-container">
        <h2 class="nb-section-title left">一轮训练如何完成</h2>
        <p class="nb-section-sub left">安全模式在任务首轮共同建钥，后续轮次复用密钥周期并绑定新的轮次标签。四种实验模式支持按相同模型、编码与数据划分对照。</p>
        <div class="nb-grid cols-4" style="margin-top:26px">
          <article v-for="step in steps" :key="step.no" class="nb-step">
            <header class="nb-step-head">
              <span class="nb-step-no">{{ step.no }}</span>
              <h2 class="nb-step-title">{{ step.name }}</h2>
            </header>
            <div class="nb-step-body"><p class="nb-card-note" style="line-height:1.9">{{ step.text }}</p></div>
          </article>
        </div>
      </div>
    </section>

    <!-- Live status strip -->
    <section class="nb-band tight">
      <div class="nb-container">
        <div class="nb-row between">
          <div class="nb-row" style="gap:22px">
            <span class="nb-checkline" style="padding:0">
              <span class="nb-dot" :class="store.connected.value ? 'online' : 'offline'"></span>
              实验引擎<b>{{ store.connected.value ? '已连接' : '未连接' }}</b>
            </span>
            <span class="nb-checkline" style="padding:0">
              <span class="nb-dot" :class="store.datasetReady.value ? 'online' : 'pending'"></span>
              {{ store.selectedDataset.value === 'cifar10' ? 'CIFAR-10' : 'MNIST' }} 数据<b>{{ store.datasetReady.value ? '已就绪' : '未就绪' }}</b>
            </span>
            <span class="nb-checkline" style="padding:0">
              <span class="nb-dot" :class="store.nodes.value.length ? 'online' : 'offline'"></span>
              节点<b>{{ store.nodes.value.length || '—' }} 个</b>
            </span>
          </div>
          <button class="nb-btn outline small" @click="emit('navigate', 'monitor')">
            <LabIcon name="activity" :size="15" />进入监控
          </button>
        </div>
      </div>
    </section>
  </div>
</template>
