/* ============================================================
   电子投票密码学可视化 — 前端逻辑
   ============================================================ */

// 全局状态
const state = {
  ff: { params: null, keypair: null },
  ec: { params: null, keypair: null },
  votes: [],
  voteChart: null,
  ecChart: null,
  lastCipher: null,
  lastSk: null,
};

// ============================================================
// 工具函数
// ============================================================

async function api(url, data = null) {
  const opts = data
    ? { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(data) }
    : { method: "POST" };
  const res = await fetch(url, opts);
  return res.json();
}

function el(id) { return document.getElementById(id); }

function stepsHTML(steps) {
  return Object.entries(steps).map(([key, val], i) => {
    const labels = { r: "随机数", g: "参数", p: "参数", h: "公钥", m: "明文",
      encrypt: "加密", decrypt: "解密", prove: "证明", verify: "验证",
      commitment: "承诺", challenge: "挑战", response: "响应" };
    const label = labels[key] || key;
    const colors = ["", "green", "yellow", "purple", "red"];
    const color = colors[i % colors.length];
    return `<div class="step-item">
      <span class="step-label ${color}">${label}</span>
      <span class="step-content">${val}</span>
    </div>`;
  }).join("");
}

function resultHTML(text, type = "") {
  return `<p class="${type}">${text}</p>`;
}

// ============================================================
// 页面导航
// ============================================================

document.querySelectorAll(".nav-item").forEach(item => {
  item.addEventListener("click", () => {
    document.querySelectorAll(".nav-item").forEach(i => i.classList.remove("active"));
    document.querySelectorAll(".page").forEach(p => p.classList.remove("active"));
    item.classList.add("active");
    el(`page-${item.dataset.page}`).classList.add("active");
  });
});

// 证明标签页
document.querySelectorAll(".tab").forEach(tab => {
  tab.addEventListener("click", () => {
    const group = tab.closest(".page");
    group.querySelectorAll(".tab").forEach(t => t.classList.remove("active"));
    group.querySelectorAll(".tab-content").forEach(c => c.classList.remove("active"));
    tab.classList.add("active");
    el(`tab-${tab.dataset.tab}`).classList.add("active");
  });
});

// ============================================================
// 系统设置
// ============================================================

async function doSetup() {
  const p = parseInt(el("setup-p").value);
  const g = parseInt(el("setup-g").value);
  const data = await api("/api/ff/setup", { p, g });

  if (!data.success) {
    el("setup-result").innerHTML = resultHTML(`❌ ${data.error}`, "error");
    el("setup-verify").innerHTML = "";
    return;
  }

  state.ff.params = data.params;
  state.ff.keypair = data.keypair;

  el("setup-result").innerHTML = `
    <p><b>系统参数</b></p>
    <p>素数 <code>p = ${data.params.p}</code></p>
    <p>阶 <code>q = (p-1)/2 = ${data.params.q}</code></p>
    <p>生成元 <code>g = ${data.params.g}</code></p>
    <br>
    <p><b>密钥对</b></p>
    <p>公钥 <code>h = g<sup>sk</sup> mod p = ${data.keypair.h}</code></p>
    <p class="success">✓ 系统参数生成成功</p>
  `;

  // 验证
  const sp = data.params;
  const kp = data.keypair;
  const v1 = modPow(sp.g, sp.q, sp.p) === 1;
  const v2 = modPow(kp.h, sp.q, sp.p) === 1;
  const v3 = kp.h % sp.p !== 1;

  el("setup-verify").innerHTML = `
    <div class="verify-item ${v1 ? 'verify-pass' : 'verify-fail'}">
      ${v1 ? '✅' : '❌'} g<sup>q</sup> mod p = ${modPow(sp.g, sp.q, sp.p)} ${v1 ? '== 1 ✓' : '≠ 1 ✗'}
    </div>
    <div class="verify-item ${v2 ? 'verify-pass' : 'verify-fail'}">
      ${v2 ? '✅' : '❌'} h<sup>q</sup> mod p = ${modPow(kp.h, sp.q, sp.p)} ${v2 ? '== 1 ✓' : '≠ 1 ✗'}
    </div>
    <div class="verify-item ${v3 ? 'verify-pass' : 'verify-fail'}">
      ${v3 ? '✅' : '❌'} h mod p = ${kp.h % sp.p} ${v3 ? '≠ 1 ✓' : '== 1 ✗'}
    </div>
  `;
}

// ============================================================
// 加密演示
// ============================================================

async function doEncrypt() {
  const msg = parseInt(el("enc-msg").value);
  const p = parseInt(el("enc-p").value);
  const g = parseInt(el("enc-g").value);

  // 先生成密钥
  const setup = await api("/api/ff/setup", { p, g });
  if (!setup.success) {
    el("encrypt-steps").innerHTML = resultHTML(`❌ 参数错误: ${setup.error}`, "error");
    return;
  }

  const data = await api("/api/ff/encrypt", {
    message: msg, p, g, public_key: setup.keypair.h,
  });

  if (!data.success) {
    el("encrypt-steps").innerHTML = resultHTML(`❌ 加密失败`, "error");
    return;
  }

  state.lastCipher = data.cipher;
  state.lastSk = setup.keypair.sk;
  state.lastP = p;
  state.lastG = g;

  el("btn-decrypt").disabled = false;

  const s = data.steps;
  el("encrypt-steps").innerHTML = `
    <div class="step-item">
      <span class="step-label">参数</span>
      <span class="step-content">p=${s.p}, g=${s.g}, 公钥 h=${s.h}</span>
    </div>
    <div class="step-item">
      <span class="step-label">明文</span>
      <span class="step-content">m = ${s.m}</span>
    </div>
    <div class="step-item">
      <span class="step-label green">随机数</span>
      <span class="step-content">选择随机值 r = ${s.r}，满足 0 < r < q</span>
    </div>
    <div class="step-item">
      <span class="step-label yellow">计算 a</span>
      <span class="step-content">${s.c1_g_r}</span>
    </div>
    <div class="step-item">
      <span class="step-label yellow">计算共享密钥</span>
      <span class="step-content">${s.s_h_r}</span>
    </div>
    <div class="step-item">
      <span class="step-label purple">编码消息</span>
      <span class="step-content">${s.mh_g_m}（同态编码）</span>
    </div>
    <div class="step-item">
      <span class="step-label red">计算 b</span>
      <span class="step-content">${s.c2_s_mh}</span>
    </div>
    <div class="step-item">
      <span class="step-label green">密文</span>
      <span class="step-content"><b>Cipher = (${data.cipher.a}, ${data.cipher.b})</b></span>
    </div>
  `;
}

async function doDecrypt() {
  if (!state.lastCipher) return;
  const data = await api("/api/ff/decrypt", {
    a: state.lastCipher.a, b: state.lastCipher.b,
    sk: state.lastSk, p: state.lastP, g: state.lastG,
  });

  if (!data.success) {
    el("decrypt-result").innerHTML = resultHTML("❌ 解密失败", "error");
    return;
  }

  el("decrypt-result").innerHTML = `
    <p>密文: <code>(${state.lastCipher.a}, ${state.lastCipher.b})</code></p>
    <p>私钥: <code>sk = ${state.lastSk}</code></p>
    <p class="success"><b>解密结果: m = ${data.plaintext}</b></p>
  `;

  const s = data.steps;
  el("decrypt-steps").innerHTML = `
    <div class="step-item">
      <span class="step-label">密文</span>
      <span class="step-content">(${state.lastCipher.a}, ${state.lastCipher.b})</span>
    </div>
    <div class="step-item">
      <span class="step-label yellow">计算共享密钥</span>
      <span class="step-content">${s.s_a_sk}</span>
    </div>
    <div class="step-item">
      <span class="step-label purple">计算逆元</span>
      <span class="step-content">${s.s_inv}</span>
    </div>
    <div class="step-item">
      <span class="step-label yellow">解码</span>
      <span class="step-content">${s.mh}</span>
    </div>
    <div class="step-item">
      <span class="step-label green">结果</span>
      <span class="step-content"><b>${s.decode}</b></span>
    </div>
  `;
}

// ============================================================
// 投票模拟
// ============================================================

function randomVotes() {
  const count = parseInt(el("vote-count").value);
  state.votes = Array.from({ length: count }, () => Math.random() > 0.4 ? 1 : 0);
  renderVoteList();
  el("btn-vote").disabled = false;
}

function renderVoteList() {
  el("vote-list").innerHTML = state.votes.map((v, i) =>
    `<span class="vote-chip ${v ? 'yes' : 'no'}">选民${i + 1}: ${v ? '赞成 ✓' : '反对 ✗'}</span>`
  ).join("");
}

async function doVote() {
  if (!state.votes.length) return;
  const p = parseInt(el("vote-p").value);
  const g = parseInt(el("vote-g").value);

  // 先生成密钥
  const setup = await api("/api/ff/setup", { p, g });
  if (!setup.success) {
    el("vote-result").innerHTML = resultHTML(`❌ ${setup.error}`, "error");
    return;
  }

  // 计票
  const data = await api("/api/ff/tally", {
    votes: state.votes, p, g,
    sk: setup.keypair.sk, public_key: setup.keypair.h,
  });

  if (!data.success) {
    el("vote-result").innerHTML = resultHTML("❌ 计票失败", "error");
    return;
  }

  const s = data.summary;
  el("vote-result").innerHTML = `
    <p>总票数: <code>${s.total}</code></p>
    <p>赞成票: <code style="color:var(--green)">${s.yes}</code></p>
    <p>反对票: <code style="color:var(--red)">${s.no}</code></p>
    <p class="success"><b>计票结果: ${s.yes} 票赞成</b></p>
  `;

  // 图表
  renderVoteChart(s.yes, s.no);

  // 同态步骤
  const yesCount = state.votes.filter(v => v === 1).length;
  const noCount = state.votes.length - yesCount;
  el("vote-steps").innerHTML = `
    <div class="step-item">
      <span class="step-label">投票</span>
      <span class="step-content">${state.votes.map((v, i) =>
        `选民${i+1}: E(${v})`).join("、")}</span>
    </div>
    <div class="step-item">
      <span class="step-label yellow">同态加法</span>
      <span class="step-content">E(sum) = E(1)·E(1)·... = E(${yesCount}) （赞成票加密累加）</span>
    </div>
    <div class="step-item">
      <span class="step-label purple">解密</span>
      <span class="step-content">D(E(sum)) = sum = ${yesCount}</span>
    </div>
    <div class="step-item">
      <span class="step-label green">结果</span>
      <span class="step-content"><b>赞成 ${yesCount} 票，反对 ${noCount} 票</b></span>
    </div>
  `;
}

function renderVoteChart(yes, no) {
  const ctx = el("vote-chart").getContext("2d");
  if (state.voteChart) state.voteChart.destroy();
  state.voteChart = new Chart(ctx, {
    type: "doughnut",
    data: {
      labels: ["赞成", "反对"],
      datasets: [{
        data: [yes, no],
        backgroundColor: ["#22c55e", "#ef4444"],
        borderColor: ["#16a34a", "#dc2626"],
        borderWidth: 2,
      }],
    },
    options: {
      responsive: true,
      plugins: {
        legend: {
          labels: { color: "#e2e8f0", font: { size: 14 } },
        },
      },
    },
  });
}

// ============================================================
// 零知识证明
// ============================================================

async function doKeygenProof() {
  const p = parseInt(el("kg-p").value);
  const g = parseInt(el("kg-g").value);
  const data = await api("/api/ff/proof/keygen", { p, g, id: "keygen-demo" });

  if (!data.success) {
    el("keygen-result").innerHTML = resultHTML(`❌ ${data.error}`, "error");
    return;
  }

  const valid = data.valid;
  el("keygen-result").innerHTML = `
    <p>公钥 <code>h = ${data.params.h}</code></p>
    <p>证明 <code>c = ${data.proof.c}, d = ${data.proof.d}</code></p>
    <p class="${valid ? 'success' : 'error'}"><b>${valid ? '✅ 证明验证通过' : '❌ 证明验证失败'}</b></p>
  `;

  el("keygen-steps").innerHTML = stepsHTML(data.steps);
}

async function doMembershipProof() {
  const vote = parseInt(el("mem-vote").value);
  const data = await api("/api/ff/proof/membership", { vote, p: 23, g: 2, id: "membership-demo" });

  if (!data.success) {
    el("member-result").innerHTML = resultHTML(`❌ ${data.error}`, "error");
    return;
  }

  const valid = data.valid;
  el("member-result").innerHTML = `
    <p>投票值: <code>${data.vote}</code></p>
    <p>密文: <code>(${data.cipher.a}, ${data.cipher.b})</code></p>
    <p class="${valid ? 'success' : 'error'}"><b>${valid ? '✅ 证明验证通过 — 投票值确实为 0 或 1' : '❌ 证明验证失败'}</b></p>
  `;

  el("member-steps").innerHTML = stepsHTML(data.steps);
}

async function doDecryptProof() {
  const msg = parseInt(el("dp-msg").value);
  const data = await api("/api/ff/proof/decrypt", { message: msg, p: 23, g: 2, id: "decrypt-demo" });

  if (!data.success) {
    el("dp-result").innerHTML = resultHTML(`❌ ${data.error}`, "error");
    return;
  }

  const valid = data.valid;
  el("dp-result").innerHTML = `
    <p>原始消息: <code>${msg}</code></p>
    <p>解密结果: <code>${data.plaintext}</code></p>
    <p class="${valid ? 'success' : 'error'}"><b>${valid ? '✅ 解密证明验证通过' : '❌ 证明验证失败'}</b></p>
  `;

  el("dp-steps").innerHTML = stepsHTML(data.steps);
}

// ============================================================
// 椭圆曲线
// ============================================================

async function doECSetup() {
  const data = await api("/api/ec/setup");
  if (!data.success) {
    el("ec-setup-result").innerHTML = resultHTML("❌ 设置失败", "error");
    return;
  }

  state.ec.keypair = { h: data._h, sk: data._sk, g: data._g };

  el("ec-setup-result").innerHTML = `
    <p><b>曲线:</b> <code>${data.curve}</code> (y² = x³ + 7)</p>
    <p><b>生成元 G:</b> <code>${data.generator.x}...</code></p>
    <p><b>公钥:</b> <code>${data.keypair.h}</code></p>
    <p class="success">✓ EC 密钥对生成成功</p>
  `;
}

async function doECVote() {
  if (!state.ec.keypair) {
    alert("请先生成 EC 密钥对");
    return;
  }

  const count = parseInt(el("ec-count").value);
  const votes = Array.from({ length: count }, () => Math.random() > 0.4 ? 1 : 0);
  const data = await api("/api/ec/tally", {
    votes,
    public_key: state.ec.keypair.h,
    secret_key: state.ec.keypair.sk,
  });

  if (!data.success) {
    el("ec-vote-result").innerHTML = resultHTML("❌ 计票失败", "error");
    return;
  }

  const s = data.summary;
  el("ec-vote-result").innerHTML = `
    <p>投票: ${votes.map(v => v ? '✅' : '❌').join(" ")}</p>
    <p>总票数: <code>${s.total}</code></p>
    <p>赞成: <code style="color:var(--green)">${s.yes}</code></p>
    <p>反对: <code style="color:var(--red)">${s.no}</code></p>
    <p class="success"><b>EC 计票完成: ${s.yes} 票赞成</b></p>
  `;

  // 图表
  const ctx = el("ec-chart").getContext("2d");
  if (state.ecChart) state.ecChart.destroy();
  state.ecChart = new Chart(ctx, {
    type: "doughnut",
    data: {
      labels: ["赞成", "反对"],
      datasets: [{
        data: [s.yes, s.no],
        backgroundColor: ["#22c55e", "#ef4444"],
        borderColor: ["#16a34a", "#dc2626"],
        borderWidth: 2,
      }],
    },
    options: {
      responsive: true,
      plugins: {
        legend: {
          labels: { color: "#e2e8f0", font: { size: 14 } },
        },
      },
    },
  });
}

// ============================================================
// 辅助数学函数（前端验证用）
// ============================================================

function modPow(base, exp, mod) {
  let result = 1n;
  base = BigInt(base) % BigInt(mod);
  exp = BigInt(exp);
  mod = BigInt(mod);
  while (exp > 0n) {
    if (exp % 2n === 1n) result = (result * base) % mod;
    exp = exp / 2n;
    base = (base * base) % mod;
  }
  return Number(result);
}
