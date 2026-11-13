/* 本地压缩包安全检查台 —— 原生 JS，无任何外部依赖或网络请求。 */
"use strict";

const MIB = 1024 * 1024;
let currentJobId = null;
let pollTimer = null;
let riskFilter = "all";

const $ = (id) => document.getElementById(id);

// --------------------------------------------------------------------- //
// 工具
// --------------------------------------------------------------------- //
function fmtSize(n) {
  if (n === null || n === undefined) return "—";
  if (n < 1024) return n + " B";
  if (n < MIB) return (n / 1024).toFixed(1) + " KiB";
  if (n < 1024 * MIB) return (n / MIB).toFixed(2) + " MiB";
  return (n / (1024 * MIB)).toFixed(2) + " GiB";
}

function escapeHtml(s) {
  return String(s ?? "").replace(/[&<>"']/g, (c) => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
  }[c]));
}

async function api(url, options) {
  const resp = await fetch(url, options);
  const data = await resp.json().catch(() => ({}));
  if (!resp.ok) throw new Error(data.error || `请求失败（${resp.status}）`);
  return data;
}

function readLimits() {
  return {
    max_entries: Number($("lim-entries").value),
    max_file_size: Number($("lim-file").value) * MIB,
    max_total_size: Number($("lim-total").value) * MIB,
    max_ratio: Number($("lim-ratio").value),
  };
}

function riskLevel(entry) {
  if (entry.risks.some((r) => r.level === "danger")) return "danger";
  if (entry.risks.some((r) => r.level === "warn")) return "warn";
  if (entry.risks.some((r) => r.level === "info")) return "info";
  return "ok";
}

// --------------------------------------------------------------------- //
// 演示包与历史任务
// --------------------------------------------------------------------- //
async function loadDemos() {
  const { demos } = await api("/api/demos");
  $("demo-list").innerHTML = demos.map((d) => `
    <div class="demo-item" data-key="${escapeHtml(d.key)}">
      <div class="t">${escapeHtml(d.title)} <span class="muted small">(${d.format})</span></div>
      <div class="d">${escapeHtml(d.desc)}</div>
    </div>`).join("");
  document.querySelectorAll(".demo-item").forEach((el) => {
    el.addEventListener("click", () => loadDemo(el.dataset.key));
  });
}

async function loadDemo(key) {
  const qs = new URLSearchParams({ limits: JSON.stringify(readLimits()) });
  const data = await api(`/api/demos/${encodeURIComponent(key)}/load?${qs}`, {
    method: "POST",
  });
  currentJobId = data.job_id;
  await refreshJobList();
  pollJob(data.job_id);
}

async function refreshJobList(activeId) {
  const { jobs } = await api("/api/jobs");
  const box = $("job-list");
  if (!jobs.length) {
    box.innerHTML = '<div class="empty small">暂无记录</div>';
    return;
  }
  box.innerHTML = jobs.map((j) => `
    <div class="job-row ${j.job_id === (activeId || currentJobId) ? "active" : ""}"
         data-id="${j.job_id}">
      <span class="name" title="${escapeHtml(j.original_name)}">
        ${escapeHtml(j.original_name)}
      </span>
      <span class="badge ${j.state}">${j.state_label}</span>
    </div>`).join("");
  box.querySelectorAll(".job-row").forEach((el) => {
    el.addEventListener("click", () => {
      currentJobId = el.dataset.id;
      pollJob(currentJobId, true);
      refreshJobList();
    });
  });
}

// --------------------------------------------------------------------- //
// 上传
// --------------------------------------------------------------------- //
$("upload-btn").addEventListener("click", async () => {
  const input = $("file-input");
  if (!input.files.length) {
    $("upload-msg").textContent = "请先选择一个 zip / tar / tar.gz 文件";
    return;
  }
  const file = input.files[0];
  const fd = new FormData();
  fd.append("file", file, file.name);
  const limits = readLimits();
  for (const [k, v] of Object.entries(limits)) fd.append(k, String(v));

  $("upload-msg").textContent = "正在上传……";
  try {
    const data = await api("/api/jobs", { method: "POST", body: fd });
    $("upload-msg").textContent = "上传成功，开始检查";
    currentJobId = data.job_id;
    await refreshJobList();
    pollJob(data.job_id);
  } catch (e) {
    $("upload-msg").textContent = "上传失败：" + e.message;
  }
});

// --------------------------------------------------------------------- //
// 轮询任务状态（扫描中 / 释放中持续刷新）
// --------------------------------------------------------------------- //
function pollJob(jobId, immediate) {
  clearInterval(pollTimer);
  const tick = async () => {
    try {
      const job = await api(`/api/jobs/${jobId}`);
      renderDetail(job);
      await refreshJobList(jobId);
      if (job.state === "scanning" || job.state === "extracting" ||
          job.state === "uploaded") {
        return; // 继续轮询
      }
      clearInterval(pollTimer);
    } catch (e) {
      clearInterval(pollTimer);
      $("detail-card").innerHTML =
        `<div class="error-box">加载任务失败：${escapeHtml(e.message)}</div>`;
    }
  };
  if (immediate) tick();
  else tick();
  pollTimer = setInterval(tick, 1000);
}

// --------------------------------------------------------------------- //
// 详情渲染
// --------------------------------------------------------------------- //
function renderDetail(job) {
  const card = $("detail-card");
  const totals = job.scan_meta?.totals || {};
  const activeRelease = job.releases?.length
    ? job.releases[job.releases.length - 1] : null;

  const filterBtns = `
    <div class="toolbar">
      <strong>风险筛选：</strong>
      <select id="risk-filter">
        <option value="all" ${riskFilter === "all" ? "selected" : ""}>全部条目</option>
        <option value="danger" ${riskFilter === "danger" ? "selected" : ""}>仅危险</option>
        <option value="warn" ${riskFilter === "warn" ? "selected" : ""}>仅警告</option>
        <option value="risk" ${riskFilter === "risk" ? "selected" : ""}>危险+警告</option>
        <option value="safe" ${riskFilter === "safe" ? "selected" : ""}>仅可释放</option>
      </select>
      <button class="secondary" id="report-btn">下载 JSON 检查报告</button>
    </div>`;

  let stateBanner = "";
  if (job.error) {
    stateBanner = `<div class="error-box">${escapeHtml(job.error)}</div>`;
  }
  if (job.scan_meta?.errors?.length) {
    stateBanner += job.scan_meta.errors.map((e) =>
      `<div class="error-box">【${escapeHtml(e.code)}】${escapeHtml(e.message)}</div>`
    ).join("");
  }
  if (activeRelease?.status === "succeeded") {
    stateBanner += `<div class="ok-box">批次 ${escapeHtml(activeRelease.release_id)}
      释放成功：${activeRelease.succeeded.length} 个文件，
      共 ${fmtSize(activeRelease.total_written)}。
      <a href="/api/jobs/${job.job_id}/download?release_id=${activeRelease.release_id}">
        下载本批文件（zip）</a></div>`;
  }

  card.innerHTML = `
    <h2>${escapeHtml(job.original_name)}
      <span class="badge ${job.state}">${job.state_label}</span>
    </h2>
    ${stateBanner}
    <div class="summary">
      <div class="stat"><div class="n">${totals.entries ?? 0}</div><div class="k">条目数</div></div>
      <div class="stat"><div class="n">${job.safe_count ?? 0}</div><div class="k">可释放</div></div>
      <div class="stat"><div class="n">${job.risk_count ?? 0}</div><div class="k">风险条目</div></div>
      <div class="stat"><div class="n">${fmtSize(totals.actual_size)}</div><div class="k">实际读取</div></div>
      <div class="stat"><div class="n">${totals.ratio ?? "—"}</div><div class="k">实际压缩比</div></div>
    </div>
    ${filterBtns}
    <div class="table-wrap">
      <table>
        <thead><tr>
          <th style="width:36px">释放</th>
          <th style="width:48px">序号</th>
          <th>原始名称 / 目标路径与风险</th>
          <th style="width:90px">类型</th>
          <th style="width:110px">声明大小</th>
          <th style="width:110px">实际大小</th>
          <th style="width:100px">检查结果</th>
        </tr></thead>
        <tbody id="entry-tbody"></tbody>
      </table>
    </div>
    <div class="release-panel">
      <button id="extract-btn" ${canExtract(job) ? "" : "disabled"}>
        释放勾选的安全文件
      </button>
      <span class="muted small" id="extract-hint">${extractHint(job)}</span>
      <div id="extract-msg"></div>
    </div>`;

  $("risk-filter").addEventListener("change", (e) => {
    riskFilter = e.target.value;
    renderEntries(job);
  });
  $("report-btn").addEventListener("click", () => downloadReport(job));
  const exBtn = $("extract-btn");
  if (exBtn) exBtn.addEventListener("click", () => doExtract(job));
  renderEntries(job);
  renderReleaseHistory(job);
}

function canExtract(job) {
  return ["scanned", "completed", "failed"].includes(job.state);
}

function extractHint(job) {
  if (job.state === "scanning" || job.state === "uploaded") return "扫描结束前不能释放文件";
  if (job.state === "scan_failed") return "扫描失败，没有可释放条目";
  if (job.state === "extracting") return "正在释放中……";
  return "仅扫描确认安全的普通文件可勾选；风险条目、链接、特殊文件由服务端强制拦截";
}

function renderEntries(job) {
  const tbody = $("entry-tbody");
  let entries = job.entries || [];
  if (riskFilter === "danger") entries = entries.filter((e) => riskLevel(e) === "danger");
  else if (riskFilter === "warn") entries = entries.filter((e) => riskLevel(e) === "warn");
  else if (riskFilter === "risk")
    entries = entries.filter((e) => ["danger", "warn"].includes(riskLevel(e)));
  else if (riskFilter === "safe") entries = entries.filter((e) => e.safe);

  if (!entries.length) {
    tbody.innerHTML = `<tr><td colspan="7" class="empty">当前筛选下没有条目</td></tr>`;
    return;
  }

  tbody.innerHTML = entries.map((e) => {
    const level = riskLevel(e);
    const checkbox = e.safe
      ? `<input type="checkbox" class="pick" data-idx="${e.index}" checked>`
      : `<input type="checkbox" disabled title="服务端禁止释放该条目">`;
    const riskHtml = e.risks.length
      ? e.risks.map((r) =>
          `<div class="row-risk"><span class="${r.level}">●</span>
           <a href="#" class="risk-link" data-idx="${e.index}">
           [${r.level === "danger" ? "危险" : r.level === "warn" ? "警告" : "提示"}]
           ${escapeHtml(r.code)}</a> ${escapeHtml(r.message)}</div>`).join("")
      : `<div class="row-risk"><span class="ok">●</span> 未发现风险</div>`;
    const extracted = e.extraction?.status
      ? `<div class="row-risk">释放：${escapeHtml(e.extraction.status)}
         ${e.extraction.target ? "→ " + escapeHtml(e.extraction.target) : ""}</div>` : "";
    return `<tr>
      <td>${checkbox}</td>
      <td>${e.index}</td>
      <td class="mono">
        <strong>${escapeHtml(e.raw_name)}</strong>
        <div class="muted small">目标：${escapeHtml(e.target_rel || "（无安全落点）")}</div>
        ${riskHtml}${extracted}
      </td>
      <td><span class="tag type">${escapeHtml(e.type_label)}</span></td>
      <td>${fmtSize(e.declared_size)}</td>
      <td>${fmtSize(e.actual_size)}</td>
      <td><span class="tag ${level}">${
        level === "ok" ? "安全" : level === "info" ? "提示" :
        level === "warn" ? "警告" : "危险"}</span></td>
    </tr>`;
  }).join("");

  tbody.querySelectorAll(".risk-link").forEach((a) => {
    a.addEventListener("click", (ev) => {
      ev.preventDefault();
      const entry = job.entries.find((x) => x.index === Number(a.dataset.idx));
      showEntryModal(entry);
    });
  });
}

function renderReleaseHistory(job) {
  if (!job.releases?.length) return;
  const host = $("extract-msg");
  host.innerHTML = job.releases.map((r, i) => {
    const ok = r.status === "succeeded";
    const links = ok
      ? ` <a href="/api/jobs/${job.job_id}/download?release_id=${r.release_id}">打包下载</a>`
      : "";
    return `<div class="${ok ? "ok-box" : "error-box"}">
      第 ${i + 1} 次释放（${r.release_id}）：${ok ? "成功" : "失败"}
      ${ok ? `，${r.succeeded.length} 个文件 / ${fmtSize(r.total_written)}`
            : "，本批已回滚，未留下半成品；原因：" + escapeHtml(r.failed?.message || "")}
      ${r.rejected.length ? `<br>服务端拦截 ${r.rejected.length} 项：` +
        r.rejected.map((x) => escapeHtml(x.reason)).join("；") : ""}
      ${links}
    </div>`;
  }).join("");
}

// --------------------------------------------------------------------- //
// 释放
// --------------------------------------------------------------------- //
async function doExtract(job) {
  const indexes = Array.from(document.querySelectorAll(".pick:checked"))
    .map((c) => Number(c.dataset.idx));
  if (!indexes.length) {
    $("extract-msg").innerHTML =
      '<span class="tag warn">请至少勾选一个安全文件</span>';
    return;
  }
  $("extract-btn").disabled = true;
  $("extract-msg").innerHTML = '<span class="tag info">正在释放……</span>';
  try {
    await api(`/api/jobs/${job.job_id}/extract`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ indexes }),
    });
    pollJob(job.job_id, true);
  } catch (e) {
    $("extract-msg").innerHTML =
      `<span class="tag danger">释放失败：${escapeHtml(e.message)}</span>`;
    $("extract-btn").disabled = false;
  }
}

// --------------------------------------------------------------------- //
// 报告与详情弹窗
// --------------------------------------------------------------------- //
async function downloadReport(job) {
  const data = await api(`/api/jobs/${job.job_id}/report`);
  const blob = new Blob([JSON.stringify(data, null, 2)],
    { type: "application/json" });
  const a = document.createElement("a");
  a.href = URL.createObjectURL(blob);
  a.download = `检查报告_${job.job_id}.json`;
  a.click();
  URL.revokeObjectURL(a.href);
}

function showEntryModal(entry) {
  $("modal-title").textContent = "条目详情：" + entry.raw_name;
  const conflicts = entry.risks
    .filter((r) => r.detail?.other_name)
    .map((r) => `<li>${escapeHtml(r.code)}：与条目
      <strong>${escapeHtml(r.detail.other_name)}</strong> 冲突
      （${escapeHtml(r.detail.note || "")}，落点 ${escapeHtml(r.detail.path || "")}）</li>`)
    .join("");
  $("modal-body").innerHTML = `
    <p><strong>原始名称：</strong><span class="mono">${escapeHtml(entry.raw_name)}</span></p>
    <p><strong>目标相对路径：</strong><span class="mono">${escapeHtml(entry.target_rel || "无")}</span></p>
    <p><strong>类型：</strong>${escapeHtml(entry.type_label)}
       <strong>声明大小：</strong>${fmtSize(entry.declared_size)}
       <strong>实际大小：</strong>${fmtSize(entry.actual_size)}</p>
    <p><strong>SHA-256：</strong><span class="mono small">${escapeHtml(entry.sha256 || "未读取")}</span></p>
    <p><strong>是否可释放：</strong>${entry.safe ? "是" : "否（服务端强制）"}</p>
    <h4>风险原因（${entry.risks.length}）</h4>
    <ul>${entry.risks.map((r) => `
      <li><span class="tag ${r.level}">${r.level}</span>
        <code>${escapeHtml(r.code)}</code> — ${escapeHtml(r.message)}
        <pre>${escapeHtml(JSON.stringify(r.detail, null, 2))}</pre>
      </li>`).join("") || "<li>无</li>"}</ul>
    ${conflicts ? `<h4>冲突涉及的条目</h4><ul>${conflicts}</ul>` : ""}
    ${entry.extraction?.status ? `<h4>释放结果</h4>
      <pre>${escapeHtml(JSON.stringify(entry.extraction, null, 2))}</pre>` : ""}`;
  $("modal-mask").classList.add("show");
}

$("modal-close").addEventListener("click", () =>
  $("modal-mask").classList.remove("show"));
$("modal-mask").addEventListener("click", (e) => {
  if (e.target === $("modal-mask")) $("modal-mask").classList.remove("show");
});

// --------------------------------------------------------------------- //
// 初始化
// --------------------------------------------------------------------- //
(async function init() {
  try {
    await loadDemos();
    await refreshJobList();
  } catch (e) {
    console.error(e);
  }
})();
