/* wallet-tool v5.1 — Persian admin dashboard logic (loopback only) */
"use strict";

const $ = (id) => document.getElementById(id);
const nf = new Intl.NumberFormat("en-US");

let polling = null;

async function api(path, opts) {
  const r = await fetch(path, opts);
  const j = await r.json().catch(() => ({}));
  if (!r.ok && j.error) throw new Error(j.error);
  return j;
}

function collectConfig() {
  return {
    vuln: $("vuln").value,
    mode: $("mode").value,
    lcg_variant: $("lcg_variant").value,
    start: $("start").value.trim(),
    stop: $("stop").value.trim(),
    stride: +$("stride").value || 1,
    batch: +$("batch").value || 4096,
    coins: $("coins").value.trim() || "btc",
    styles: $("styles").value.trim(),
    max_candidates: +$("max_candidates").value || 0,
    balance: $("balance").value,
    watchlist_path: $("watchlist_path").value.trim(),
    stop_on_hit: $("stop_on_hit").checked,
    min_sat: +$("min_sat").value || 1,
    known_phrase: $("known_phrase").value.trim(),
    auto_fingerprint: $("auto_fingerprint").checked,
    fingerprint_sample_hex: $("fingerprint_sample_hex").value.trim(),
    buckets: $("buckets").value.trim(),
    parity: $("parity").value,
  };
}

function setBadge(cls, txt) {
  const b = $("badge");
  b.className = "badge " + cls;
  b.textContent = txt;
}

async function startScan() {
  try {
    const res = await api("/api/start", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(collectConfig()),
    });
    if (res.ok) {
      setBadge("run", "در حال اجرا");
      $("btn_start").disabled = true;
      $("btn_stop").disabled = false;
      beginPolling();
    } else {
      alert("خطا: " + (res.error || "نامشخص"));
    }
  } catch (e) { alert("خطا: " + e.message); }
}

async function stopScan() {
  await api("/api/stop", { method: "POST" }).catch(() => {});
}

async function classifySample() {
  const hex = $("fingerprint_sample_hex").value.trim();
  if (!hex) { $("fp_out").textContent = "نمونه hex وارد کنید."; return; }
  try {
    const rep = await api("/api/fingerprint", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ sample_hex: hex }),
    });
    $("fp_out").textContent = JSON.stringify(rep, null, 2);
  } catch (e) { $("fp_out").textContent = "خطا: " + e.message; }
}

function statCard(label, value) {
  return `<div class="stat"><b>${value}</b><span>${label}</span></div>`;
}

async function refresh() {
  let s;
  try { s = await api("/api/status"); }
  catch (e) { return; }
  if (!s.stats) {
    if (s.logs) $("logs").textContent = s.logs.join("\n");
    return;
  }
  const st = s.stats, cfg = s.config || {};
  $("covnote").textContent = s.coverage_note || "";
  // V5.1: true progress from engine cursor (percent), not candidate count —
  // filtered/rejected candidates used to skew the bar and hide real ETA.
  const pct = (st.percent == null) ? null : st.percent;
  if (pct != null) $("bar").style.width = (100 * pct).toFixed(1) + "%";
  const etaTxt = (st.eta_s && st.eta_s > 0)
    ? nf.format(Math.round(st.eta_s)) + "s" : "—";

  $("stats").innerHTML = [
    statCard("کاندیدها", nf.format(st.candidates)),
    statCard("آدرس مشتق", nf.format(st.addresses_derived)),
    statCard("رد بلوم", nf.format(st.bloom_skips)),
    statCard("رد محدودیت", nf.format(st.constraint_rejects || 0)),
    statCard("پروب شبکه", nf.format(st.network_probes)),
    statCard("یافته", nf.format(st.hits)),
    statCard("نرخ /s", nf.format(Math.round(st.rate || 0))),
    statCard("زمان (s)", (st.elapsed || 0).toFixed(1)),
    statCard("پیشرفت", pct == null ? "—"
      : nf.format(Math.round(pct * 1000) / 10) + "٪"),
    statCard("ETA", etaTxt),
    statCard("پوشش", st.reduced_coverage
      ? "⚠ REDUCED (" + ((st.coverage_keeps || 1) * 100).toFixed(1) + "%)"
      : "۱۰۰٪"),
  ].join("");

  const tb = $("hits").querySelector("tbody");
  tb.innerHTML = (s.findings || []).map((f) => `
    <tr><td>${f.source}</td><td>${f.t_ms}</td><td>${f.chain_tag}</td>
    <td>${f.style}</td><td class="ltr">${f.address}</td>
    <td>${nf.format(f.balance_sat)}</td><td>${f.tx_count}</td>
    <td>${f.backend}</td></tr>`).join("");

  $("logs").textContent = (s.logs || []).join("\n");

  if (!s.running) {
    $("btn_start").disabled = false;
    $("btn_stop").disabled = true;
    setBadge(st.stopped ? "done" : "idle",
             st.stopped ? "متوقف شد" : (st.finished ? "تمام شد" : "آماده"));
    clearInterval(polling); polling = null;
  } else {
    setBadge("run", "در حال اجرا");
  }
}

function beginPolling() {
  if (polling) return;
  refresh();
  polling = setInterval(refresh, 1500);
}

$("btn_start").addEventListener("click", startScan);
$("btn_stop").addEventListener("click", stopScan);
$("btn_fp").addEventListener("click", classifySample);

// resume polling if a scan is already live when the page opens
refresh().then(beginPollingCheck);
async function beginPollingCheck() {
  try {
    const s = await api("/api/status");
    if (s.running) beginPolling();
  } catch (e) { /* ignore */ }
}
