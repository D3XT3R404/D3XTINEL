const API_BASE = "http://127.0.0.1:8000";

const btn = document.getElementById("checkBtn");
const urlInput = document.getElementById("urlInput");
const loading = document.getElementById("loading");
const result = document.getElementById("result");

function verdictMap(label) {
  const key = (label || "").toLowerCase();
  if (key === "benign") return { cls: "badge-good", text: "Tidak berbahaya" };
  if (key === "phishing") return { cls: "badge-warn", text: "Terindikasi phishing" };
  if (key === "malware") return { cls: "badge-bad", text: "Berpotensi malware" };
  if (key === "potential_risky") return { cls: "badge-info", text: "Potensial berbahaya" };
  return { cls: "badge-warn", text: "Perlu diperiksa" };
}

function confidenceText(score) {
  if (score >= 0.85) return "Sangat tinggi";
  if (score >= 0.70) return "Tinggi";
  if (score >= 0.50) return "Sedang";
  return "Rendah";
}

function riskText(score) {
  if (score >= 0.75) return "Tinggi";
  if (score >= 0.35) return "Sedang";
  return "Rendah";
}

function probabilityRows(data) {
  const items = [
    ["Aman", data?.ml_probabilities?.benign || 0],
    ["Phishing", data?.ml_probabilities?.phishing || 0],
    ["Malware", data?.ml_probabilities?.malware || 0],
    ["Potensial Berbahaya", data?.ml_probabilities?.potential_risky || 0],
  ];

  return items.map(([name, value]) => {
    const pct = Math.round(value * 100);
    return `
      <div style="margin-bottom:12px">
        <div style="display:flex;justify-content:space-between;gap:10px;margin-bottom:6px">
          <span>${name}</span>
          <span>${pct}%</span>
        </div>
        <div class="meter"><div style="width:${Math.max(2, pct)}%"></div></div>
      </div>
    `;
  }).join("");
}

btn.onclick = async () => {
  const url = urlInput.value.trim();
  if(
    !url.startsWith("http://") &&
    !url.startsWith("https://")
  ){
    url = "https://" + url;
  }
  if (!url) {
    alert("Masukkan URL dulu.");
    return;
  }

  loading.classList.remove("hidden");
  result.classList.add("hidden");
  result.innerHTML = "";

  try {
    const res = await fetch(`${API_BASE}/api/check-url`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url }),
    });

    const data = await res.json();
    const warningHtml = `
  <div class="card">
  <h3>⚠ Security Warning</h3>
  <p>
  Jangan klik link mencurigakan.
  Gunakan hasil scan ini sebagai referensi, bukan keputusan mutlak.
  Jangan pernah memasukkan password, OTP, data bank, atau Informasi Identitas Pribadi (PII)
  ke situs yang tidak terpercaya.
  </p>
  </div>
`;
    if (!res.ok) throw new Error(data?.detail || "Gagal memeriksa URL");

    const verdict = verdictMap(data.label);
    const confPct = Math.round((data.confidence || 0) * 100);
    const riskPct = Math.round((data.risk_score || 0) * 100);
    const vt = data?.vt?.stats || {};
    const reasons = data?.reasons || [];

    const vtTotal =
(vt.malicious||0)+
(vt.suspicious||0)+
(vt.harmless||0)+
(vt.undetected||0);

const maliciousPct=
vtTotal?
Math.round(
(vt.malicious/vtTotal)*100
):0;

const suspiciousPct=
vtTotal?
Math.round(
(vt.suspicious/vtTotal)*100
):0;

const harmlessPct=
vtTotal?
Math.round(
(vt.harmless/vtTotal)*100
):0;

    result.innerHTML = `
      <div class="result-header">
        <div>
          <div class="status-badge ${verdict.cls}">${verdict.text}</div>
          <h2 class="verdict-title">Hasil Pemeriksaan URL</h2>
          <div class="scoreline">
            <div class="score">${confPct}%</div>
            <div>
              <div><b>Confidence</b> (${confidenceText(data.confidence || 0)})</div>
              <div class="subtle">Risk score: ${riskPct}% · Risiko: ${riskText(data.risk_score || 0)}</div>
            </div>
          </div>
        </div>
      </div>

      <div class="grid">
        <div class="card">
          <h3>Ringkasan sederhana</h3>
          <div class="pretty">
${verdict.text}.\n\n${reasons.length ? reasons.map(r => `• ${r}`).join("\n") : "Tidak ada sinyal khusus yang kuat."}
          </div>
        </div>

        <div class="card">
<h3>VirusTotal</h3>

<div class="stats">

<div class="stat">
<div class="k">Malicious</div>
<div class="v">${maliciousPct}%</div>
</div>

<div class="stat">
<div class="k">Suspicious</div>
<div class="v">${suspiciousPct}%</div>
</div>

<div class="stat">
<div class="k">Harmless</div>
<div class="v">${harmlessPct}%</div>
</div>

<div class="stat">
<div class="k">Engines</div>
<div class="v">${vtTotal}</div>
</div>

</div>
</div>

        <div class="card">
          <h3>Probabilitas AI</h3>
          ${probabilityRows(data)}
        </div>

        <div class="card">
          <h3>Alamat yang dicek</h3>
          <div class="url-box">${data.url}</div>
        </div>
      </div>
      <div class="card">
  <h2>⚠ Security Warning</h2>

  <div class="pretty">
Jangan Asal Klik link mencurigakan.
Gunakan hasil scan ini sebagai referensi,
bukan keputusan mutlak.

Jangan pernah memasukkan password,
OTP, data bank, atau Informasi Identitas Pribadi (PII)
ke situs yang tidak terpercaya.
  </div>

</div>
    `;

    result.classList.remove("hidden");
  } catch (e) {
    result.innerHTML = `<div class="card"><b>Error:</b> ${e.message}</div>`;
    result.classList.remove("hidden");
  } finally {
    loading.classList.add("hidden");
  }
};