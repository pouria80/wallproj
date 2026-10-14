/* Wallet Scanner V4 — Persian RTL dashboard logic (no frameworks, stdlib backend). */
"use strict";

const $ = (id) => document.getElementById(id);
const faNum = (n) => (n ?? 0).toLocaleString("fa-IR");
const fmtTime = (s) => {
  if (s == null || isNaN(s)) return "—";
  s = Math.round(s);
  const h = Math.floor(s / 3600), m = Math.floor((s % 3600) / 60), sec = s % 60;
  if (h > 72) return `${faNum(Math.floor(h / 24))} روز و ${faNum(h % 24)} ساعت`;
  return [h ? faNum(h) + "س" : "", m ? faNum(m) + "د" : "", faNum(sec) + "ث"]
    .filter(Boolean).join(" ");
};

async function api(path, body) {
  const opt = body === undefined ? {} : {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(body),
  };
  const r = await fetch(path, opt);
  if (!r.ok) throw new Error(`${path} → HTTP ${r.status}`);
  return r.json();
}

function cfgPayload() {
  return {
    start_seed: Number($("in-start").value || 0),
    end_seed: Number($("in-end").value || 0),
    num_workers: Number($("in-workers").value || 1),
    chunk_size: Number($("in-chunk").value || 20000),
    threshold_eth: Number($("in-theth").value || 0),
    threshold_usdt: Number($("in-thusd").value || 0),
    live_rpc: $("in-live").checked,
    fingerprint_prune: ($("in-prune") ? $("in-prune").value.trim() : ""),
    parity_filter: ($("in-parity") ? $("in-parity").value : ""),
    cpu_budget: Number(($("in-budget") ? $("in-budget").value : "35")) / 100,
  };
}

/* ---------------- buttons ---------------- */
$("b-start").onclick = async () => {
  try { const r = await api("/api/start", cfgPayload());
        if (!r.ok) flashState("در حال اجرا… یا محدوده نامعتبر"); }
  catch (e) { alert(e.message); }
};
$("b-pause").onclick  = () => api("/api/pause", {}).catch(console.error);
$("b-resume").onclick = () => api("/api/resume", {}).catch(console.error);
$("b-stop").onclick   = () => api("/api/stop", {}).catch(console.error);
$("b-reset").onclick  = async () => {
  if (!confirm("همه وضعیت، چک‌پوینت و یافته‌های این نشست پاک شود؟")) return;
  await api("/api/reset", {}).catch(console.error);
  rateHist.length = 0; drawChart();
};

let stateMsg = "";
function flashState(m) { stateMsg = m; setTimeout(() => (stateMsg = ""), 4000); }

/* ---------------- status polling ---------------- */
const rateHist = [];           // rolling throughput samples for the chart
let lastFundedRows = "";

function render(st) {
  const pill = $("state-pill");
  pill.className = "pill " + (st.running ? (st.paused ? "pause" : "run")
                    : (st.pct_complete >= 100 ? "done" : "idle"));
  pill.textContent = st.running ? (st.paused ? "مکث" : "در حال جست‌وجو")
                  : (st.pct_complete >= 100 ? "✅ کامل شد" : (stateMsg || "متوقف"));

  $("bar").style.width = st.pct_complete + "%";
  $("pct").textContent = `${faNum(st.pct_complete.toLocaleString("fa-IR",{maximumFractionDigits:4}))}٪`
    + `  (${faNum(st.next_lo)} / تا ${faNum(st.end_seed)})`;

  $("st-scanned").textContent = faNum(st.seeds_scanned);
  $("st-cursor").textContent  = faNum(st.next_lo);
  $("st-derived").textContent = faNum(st.wallets_derived);
  $("st-rate").textContent    = st.rate_seeds_per_sec ? faNum(st.rate_seeds_per_sec) : "—";
  $("st-elapsed").textContent = fmtTime(st.elapsed_sec);
  $("st-eta").textContent     = st.eta_sec != null ? fmtTime(st.eta_sec) : "—";
  $("st-bal").textContent     = faNum(st.balances_checked);
  $("st-pending").textContent = faNum(st.pending_checks);
  $("st-errors").textContent  = faNum(st.errors);
  $("last-error").textContent = st.last_error || "";

  const cov = $("coverage-badge");
  if (st.coverage_mode === "REDUCED") {
    cov.className = "cov reduced";
    cov.textContent = "⚠️ پوشش: REDUCED — فیلتر انگشت‌نگاری فعال است (فقط آموزش)";
  } else {
    cov.className = "cov full";
    cov.textContent = "پوشش: FULL 100%";
  }
  $("engine-mode").textContent = st.engine_mode ? ("engine: " + st.engine_mode) : "";

  /* funded table (re-render only when contents change) */
  const rows = (st.funded || []).slice().reverse();
  const key = JSON.stringify(rows.map(r => r.seed));
  if (key !== lastFundedRows) {
    lastFundedRows = key;
    $("funded-count").textContent = faNum(st.funded_count);
    const tb = $("tbl-funded").tBodies[0];
    tb.innerHTML = "";
    $("no-hits").style.display = rows.length ? "none" : "block";
    for (const r of rows) {
      const tr = document.createElement("tr");
      tr.innerHTML =
        `<td>${faNum(r.seed)}</td>` +
        `<td class="ltr">${r.address}</td>` +
        `<td>${Number(r.eth).toFixed(6)}</td>` +
        `<td>${Number(r.usdt).toFixed(2)}</td>` +
        `<td>${Number(r.usdc).toFixed(2)}</td>` +
        `<td class="assets">${Object.entries(r.assets || {}).map(([k,v]) => k + ":" + Number(v).toFixed(4)).join("، ") || "—"}</td>` +
        `<td>${r.found_at || ""}</td>` +
        `<td class="mn" title="${r.mnemonic}">${r.mnemonic}</td>`;
      tb.appendChild(tr);
    }
  }

  /* logs */
  $("logs").textContent = (st.logs || []).join("\n");

  /* throughput history */
  if (st.running && !st.paused) {
    rateHist.push(st.rate_seeds_per_sec || 0);
    if (rateHist.length > 120) rateHist.shift();
    drawChart();
  }
}

function drawChart() {
  const c = $("rate-chart"), ctx = c.getContext("2d");
  const W = c.width = c.clientWidth * devicePixelRatio;
  const H = c.height = 90 * devicePixelRatio;
  ctx.clearRect(0, 0, W, H);
  if (rateHist.length < 2) return;
  const max = Math.max(...rateHist, 1);
  ctx.strokeStyle = "#3fb950"; ctx.lineWidth = 1.5 * devicePixelRatio;
  ctx.beginPath();
  rateHist.forEach((v, i) => {
    const x = (i / (rateHist.length - 1)) * W;
    const y = H - (v / max) * (H - 8) - 4;
    i ? ctx.lineTo(x, y) : ctx.moveTo(x, y);
  });
  ctx.stroke();
  ctx.fillStyle = "#8b949e";
  ctx.font = `${10 * devicePixelRatio}px Tahoma`;
  ctx.fillText(`حداکثر: ${max.toLocaleString()} seed/s`, 8 * devicePixelRatio, 12 * devicePixelRatio);
}

async function poll() {
  try { render(await api("/api/status")); }
  catch (e) { flashState("خطای اتصال به سرور"); }
}
setInterval(poll, 1000);
poll();
