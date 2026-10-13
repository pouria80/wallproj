const $ = (id) => document.getElementById(id);

async function post(url, body) {
  await fetch(url, { method: "POST", headers: { "content-type": "application/json" },
                     body: JSON.stringify(body || {}) });
}

$("btn-start").onclick = () => post("/api/start", {
  start_seed: +$("start-seed").value || 0,
  end_seed: +$("end-seed").value || 4294967295,
  duration_sec: +$("duration").value || 0,
  batch_size: Math.max(1, +$("batch").value || 50),
  interval_sec: Math.max(0.1, parseFloat($("interval").value) || 1),
  threshold_eth: parseFloat($("threshold").value) || 0,
});

$("btn-stop").onclick = () => post("/api/stop");
$("btn-reset").onclick = async () => { await post("/api/reset"); render(await getStatus()); };

async function getStatus() {
  try { return await (await fetch("/api/status")).json(); }
  catch { return null; }
}

function fmt(n) { return n.toLocaleString("en-US"); }

let lastHitCount = -1;

function render(s) {
  if (!s) return;
  const badge = $("state-badge");
  badge.textContent = s.running ? "در حال پیمایش…" : (s.elapsed_sec > 0 ? "متوقف" : "آماده به کار");
  badge.className = "badge " + (s.running ? "run" : (s.elapsed_sec > 0 ? "done" : "idle"));
  $("btn-start").disabled = s.running;
  $("btn-stop").disabled = !s.running;

  $("st-seeds").textContent = fmt(s.seeds_scanned);
  $("st-wallets").textContent = fmt(s.wallets_derived);
  $("st-checked").textContent = fmt(s.balances_checked);
  $("st-funded").textContent = fmt(s.funded_count);
  $("st-time").textContent = s.elapsed_sec + "s";
  $("st-errors").textContent = fmt(s.errors);

  if (s.funded_count !== lastHitCount) {
    lastHitCount = s.funded_count;
    $("no-hits").style.display = s.funded_count ? "none" : "block";
    $("hits-list").innerHTML = s.funded.map(h => `
      <div class="hit">
        <div class="hit-head">
          <span class="amt">${h.eth.toFixed(6)} ETH</span>
          <span class="seed">seed: ${fmt(h.seed)}</span>
          <span class="time">${h.found_at}</span>
        </div>
        <div class="addr">${h.address}</div>
        <div class="words"><b>۱۲ کلمه:</b> <code>${h.mnemonic}</code></div>
      </div>`).join("");
  }

  $("log").innerHTML = s.logs.map(l => `<li>${l}</li>`).join("");
}

setInterval(async () => render(await getStatus()), 1000);
render(await getStatus());
