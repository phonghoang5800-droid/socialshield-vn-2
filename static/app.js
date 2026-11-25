const SAMPLES = {
  momo: "Vi MoMo thong bao quy khach da trung thuong tri an 5.000.000 VND. Truy cap http://momo-nhanthuong-vn.top/claim nhap mat khau va ma OTP de nhan tien ngay trong 15 phut.",
  vcb: "VCB canh bao tai khoan cua quy khach co dau hieu giao dich bat thuong va se bi tam khoa sau 30 phut. Vui long xac minh ngay tai http://vcb-xacminh-baomat.xyz/login",
  job: "Tuyen CTV online tai nha nhan 600.000d/ngay. Nap 200.000d kich hoat nhiem vu don hang de nhan hoa hong 30% ngay lap tuc.",
  otp: "MoMo: Ma xac thuc OTP cua ban la 492815, hieu luc trong 2 phut. Tuyet doi KHONG chia se ma nay cho bat ky ai, ke ca nhan vien MoMo.",
};

const HERO_DEMOS = {
  momo: {
    sender: "SMS · Ví MoMo (Giả mạo)",
    score: "87/100",
    bodyHtml: "Chúc mừng nhận thưởng <mark>5.000.000đ</mark>! Bấm <mark>momo-nhanthuong-vn.top</mark> nhập <mark>OTP</mark> trong 15 phút...",
    foot: "📞 Hotline thật: MoMo 1900 5454 41 · [KB-02]",
    danger: true,
    icon: "✋",
    stamp: "ĐỪNG CHẠM!<br/>LỪA ĐẢO",
    status: "BLOCKED 87",
  },
  job: {
    sender: "Zalo · Tuyển CTV Online",
    score: "78/100",
    bodyHtml: "Việc nhẹ <mark>600k/ngày</mark>. <mark>Nạp 200.000đ</mark> kích hoạt nhiệm vụ đơn hàng nhận hoa hồng 30%...",
    foot: "🛡️ Không cần link vẫn bắt trúng · [KB-07]",
    danger: true,
    icon: "✋",
    stamp: "BẪY CTV!<br/>KHÔNG NẠP",
    status: "BLOCKED 78",
  },
  otp: {
    sender: "SMS · MoMo Chính thức",
    score: "13/100",
    bodyHtml: "Mã xác thực OTP của bạn là 492815, hiệu lực 2 phút. Tuyệt đối KHÔNG chia sẻ mã này cho bất kỳ ai.",
    foot: "✓ Không link lạ · Có cảnh báo bảo mật · [KB-10]",
    danger: false,
    icon: "✓",
    stamp: "AN TOÀN<br/>OTP THẬT",
    status: "SAFE 13",
  },
};

let activeRunId = 0;
let lastResultForCopy = null;
let visionFile = null;
let benchLoaded = false;

function esc(s) {
  return String(s ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;");
}

function wait(ms) {
  return new Promise((r) => setTimeout(r, ms));
}

function highlightDanger(text) {
  let safe = esc(text);
  const rules = [
    /(https?:\/\/[^\s]+|hxxps?:\/\/[^\s]+)/gi,
    /\b(otp|mã\s*otp|mật\s*khẩu|mat\s*khau|cccd|pin)\b/gi,
    /(\d[\d.,]*\s*(?:vnd|vnđ|đ|trieu|triệu|k))\b/gi,
    /\b(tạm\s*khóa|tam\s*khoa|bị\s*khóa|bi\s*khoa|khẩn\s*cấp|khan\s*cap|15\s*phut|30\s*phut|24h|nạp\s*\d+|nap\s*\d+)/gi,
  ];
  for (const r of rules) safe = safe.replace(r, '<span class="danger-mark">$1</span>');
  return safe;
}

function animateScore(el, target) {
  const t0 = performance.now();
  function frame(now) {
    const p = Math.min(1, (now - t0) / 380);
    el.textContent = Math.round(target * (1 - Math.pow(1 - p, 3)));
    if (p < 1) requestAnimationFrame(frame);
  }
  requestAnimationFrame(frame);
}

/* 1. SPA NAVIGATION */
function switchView(name) {
  document.querySelectorAll(".view").forEach((v) => v.classList.remove("active"));
  document.getElementById(`view-${name}`)?.classList.add("active");
  document.querySelectorAll(".nav-tab").forEach((t) => t.classList.toggle("active", t.dataset.nav === name));
  window.scrollTo({ top: 0, behavior: "smooth" });
  if (name === "benchmark" && !benchLoaded) loadBenchmark();
}

document.querySelectorAll("[data-nav]").forEach((el) => {
  el.addEventListener("click", () => switchView(el.dataset.nav));
});

/* 2. OVERVIEW STAMPING MACHINE INTERACTION */
async function triggerHeroDemo(key) {
  const d = HERO_DEMOS[key];
  if (!d) return;

  document.querySelectorAll(".t-tab").forEach((b) => b.classList.toggle("active", b.dataset.demo === key));
  const box = document.getElementById("heroMachine");
  const ticket = document.getElementById("heroTicket");
  const bar = document.getElementById("heroScanBar");
  const stamp = document.getElementById("heroStamp");

  document.getElementById("heroMachineStatus").textContent = "SCANNING...";
  stamp.style.opacity = "0";
  bar.classList.add("active");

  ticket.style.animation = "none";
  void ticket.offsetWidth;
  ticket.style.animation = "";

  document.getElementById("heroSender").textContent = d.sender;
  document.getElementById("heroScoreTag").textContent = d.score;
  document.getElementById("heroBody").innerHTML = d.bodyHtml;
  document.getElementById("heroFoot").textContent = d.foot;

  await wait(480);

  bar.classList.remove("active");
  stamp.style.opacity = "1";
  stamp.classList.remove("stamp-danger", "stamp-safe");
  stamp.classList.add(d.danger ? "stamp-danger" : "stamp-safe");
  stamp.style.animation = "none";
  void stamp.offsetWidth;
  stamp.style.animation = "";

  document.getElementById("heroStampIcon").textContent = d.icon;
  document.getElementById("heroStampText").innerHTML = d.stamp;
  document.getElementById("heroMachineStatus").textContent = d.status;

  box.classList.remove("jolt");
  void box.offsetWidth;
  box.classList.add("jolt");
}

document.querySelectorAll(".t-tab").forEach((btn) => {
  btn.addEventListener("click", () => triggerHeroDemo(btn.dataset.demo));
});

/* 3. VIEW 2: DEDICATED SCANNER */
async function runScan(text, situation = "Chưa bấm link") {
  const runId = ++activeRunId;
  const idle = document.getElementById("stageIdle");
  const scanning = document.getElementById("stageScanning");
  const result = document.getElementById("stageResult");
  const btn = document.getElementById("scanBtn");

  idle.classList.add("hidden");
  result.classList.add("hidden");
  scanning.classList.remove("hidden");
  btn.disabled = true;

  const fc = document.getElementById("flyingCard");
  fc.style.animation = "none";
  void fc.offsetWidth;
  fc.style.animation = "";
  document.getElementById("flyingText").textContent = text;

  const rows = Array.from(document.querySelectorAll("#liveSteps .cs-row"));
  rows.forEach((r) => {
    r.classList.remove("running", "done");
    r.querySelector(".cs-st").textContent = "WAIT";
  });

  const apiPromise = fetch("/api/analyze", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ text, channel: "SMS", situation }),
  }).then((r) => r.json());

  for (let i = 0; i < rows.length; i++) {
    if (runId !== activeRunId) return;
    rows[i].classList.add("running");
    rows[i].querySelector(".cs-st").textContent = "RUN";
    await wait(200);
    if (runId !== activeRunId) return;
    rows[i].classList.remove("running");
    rows[i].classList.add("done");
    rows[i].querySelector(".cs-st").textContent = "OK ✓";
  }

  const data = await apiPromise;
  if (runId !== activeRunId) return;

  await wait(110);
  scanning.classList.add("hidden");
  renderVerdict(data);
  result.classList.remove("hidden");
  btn.disabled = false;
}

function renderVerdict(data) {
  lastResultForCopy = data;
  const banner = document.getElementById("alertBanner");
  const kicker = document.getElementById("alertKicker");
  const headline = document.getElementById("alertHeadline");
  const copyBtn = document.getElementById("copyWarnBtn");

  banner.classList.remove("is-scam", "is-warn", "is-safe");
  const isScam = data.predicted_label === "scam" || data.risk_score >= 61;
  const isSafe = data.predicted_label === "normal" && data.risk_score < 41;

  if (isScam) {
    banner.classList.add("is-scam");
    kicker.textContent = `CẢNH BÁO LỪA ĐẢO · ${data.risk_level.toUpperCase()}`;
    const hasBadUrl = (data.urls || []).some((u) => !u.is_official);
    headline.textContent = hasBadUrl
      ? "✋ DỪNG LẠI! ĐỪNG CHẠM VÀO LINK NÀY"
      : "✋ DỪNG LẠI! ĐỪNG CHUYỂN TIỀN / GỬI OTP";
    document.getElementById("doNowTitle").textContent = "🚫 Việc cần làm ngay:";
    copyBtn.classList.remove("hidden");
  } else if (!isSafe) {
    banner.classList.add("is-warn");
    kicker.textContent = "CẦN KIỂM TRA";
    headline.textContent = "⚠️ KHOAN ĐÃ! XÁC MINH TRƯỚC KHI BẤM";
    document.getElementById("doNowTitle").textContent = "Gợi ý:";
    copyBtn.classList.add("hidden");
  } else {
    banner.classList.add("is-safe");
    kicker.textContent = "ĐÃ KIỂM CHỨNG AN TOÀN";
    headline.textContent = "✓ AN TOÀN — TIN NHẮN HỢP LỆ";
    document.getElementById("doNowTitle").textContent = "Lưu ý nhỏ:";
    copyBtn.classList.add("hidden");
  }

  animateScore(document.getElementById("resScoreNum"), data.risk_score);
  document.getElementById("resCategory").textContent = data.scam_category_label;
  document.getElementById("resGrounding").textContent = `✓ ${(data.citations || []).join(", ")}`;
  document.getElementById("resHighlightedText").innerHTML = isSafe ? esc(data.analyzed_text) : highlightDanger(data.analyzed_text);
  document.getElementById("resExplanation").textContent = data.explanation;

  document.getElementById("resActions").innerHTML = (data.recommended_actions || [])
    .map((a, i) => `<div class="todo-item"><span class="todo-num mono">${i + 1}</span><span>${esc(a)}</span></div>`)
    .join("");

  const topKb = data.retrieved_kb?.[0];
  const hotline = document.getElementById("hotlineStrip");
  if (topKb?.official_channels && !isSafe) {
    hotline.classList.remove("hidden");
    document.getElementById("hotlineText").textContent = topKb.official_channels;
  } else {
    hotline.classList.add("hidden");
  }

  document.getElementById("resLatency").textContent = `${data.total_latency_ms}ms · v1:${data.v1_baseline?.risk_score ?? "—"}`;
  document.getElementById("resTrace").innerHTML = (data.agent_trace || [])
    .map((s) => `<div class="tr-c"><strong class="mono">0${s.step} ${esc(s.tool.split(" ")[0])}</strong> (${s.latency_ms}ms)<div style="color:#52525b">${esc(s.summary)}</div></div>`)
    .join("");

  document.getElementById("resUrlsAndKbs").innerHTML =
    (data.urls || [])
      .map((u) => `<div class="kb-c"><strong>URL: ${esc(u.domain || u.url)}</strong> (${u.risk_score}/100) — ${esc((u.reasons || []).join(" · "))}</div>`)
      .join("") +
    (data.retrieved_kb || [])
      .map((kb) => `<div class="kb-c"><strong>[${esc(kb.id)}] ${esc(kb.title)}</strong> <span class="mono">RRF ${kb.rrf_score}</span><div>${esc(kb.content)}</div></div>`)
      .join("");
}

document.querySelectorAll("#sampleBubbles .sample-card").forEach((btn) => {
  btn.addEventListener("click", () => {
    document.querySelectorAll("#sampleBubbles .sample-card").forEach((b) => b.classList.remove("selected"));
    btn.classList.add("selected");
    const txt = SAMPLES[btn.dataset.sample];
    document.getElementById("msgInput").value = txt;
    runScan(txt, document.getElementById("situationSelect").value);
  });
});

document.getElementById("scanForm").addEventListener("submit", (e) => {
  e.preventDefault();
  const txt = document.getElementById("msgInput").value.trim();
  if (txt.length < 2) return;
  runScan(txt, document.getElementById("situationSelect").value);
});

document.getElementById("copyWarnBtn").addEventListener("click", async () => {
  if (!lastResultForCopy) return;
  const topKb = lastResultForCopy.retrieved_kb?.[0];
  const msg = `⚠️ CẢNH BÁO LỪA ĐẢO (${lastResultForCopy.risk_score}/100 — ${lastResultForCopy.scam_category_label}):\nĐừng bấm link, không gửi OTP hay chuyển tiền!\nTổng đài thật: ${topKb?.official_channels || "Báo cáo 156"}.`;
  try { await navigator.clipboard.writeText(msg); } catch {}
  const t = document.getElementById("toast");
  t.classList.remove("hidden");
  setTimeout(() => t.classList.add("hidden"), 2400);
});

/* 4. VIEW 3: VISION STUDIO */
function setVisionFile(file, autoNote = "") {
  if (!file) return;
  visionFile = file;
  document.getElementById("visionPreviewImg").src = URL.createObjectURL(file);
  document.getElementById("visionPreviewWrap").classList.remove("hidden");
  document.getElementById("visionDropHint").classList.add("hidden");
  if (autoNote) document.getElementById("visionNote").value = autoNote;
}

function generateDemoImage(kind) {
  const c = document.createElement("canvas");
  c.width = 720; c.height = 460;
  const ctx = c.getContext("2d");

  if (kind === "bill") {
    ctx.fillStyle = "#faf7f0"; ctx.fillRect(0, 0, 720, 460);
    ctx.fillStyle = "#111111"; ctx.fillRect(0, 0, 720, 82);
    ctx.fillStyle = "#d4ff00"; ctx.font = "bold 26px sans-serif";
    ctx.fillText("BIÊN LAI CHUYỂN KHOẢN (DEMO BILL GIẢ)", 32, 50);
    ctx.fillStyle = "#ff3b5c"; ctx.font = "bold 44px sans-serif";
    ctx.fillText("15.000.000 VND", 32, 156);
    ctx.fillStyle = "#111111"; ctx.font = "21px sans-serif";
    ctx.fillText("VCB 1029384756 · Nội dung: Nhan tien tai http://vcb-nhantien-24h.xyz", 32, 224);
    ctx.fillStyle = "#b91c1c"; ctx.font = "bold 21px sans-serif";
    ctx.fillText("Tiền đang treo — bấm link nhập OTP để giải ngân ngay!", 32, 290);
    ctx.fillStyle = "#52525b"; ctx.font = "16px monospace";
    ctx.fillText("FONT LECH // MA GD BAT THUONG // DAU HIEU BILL GIA", 32, 390);
  } else {
    ctx.fillStyle = "#e0f2fe"; ctx.fillRect(0, 0, 720, 460);
    ctx.fillStyle = "#111111"; ctx.fillRect(0, 0, 720, 76);
    ctx.fillStyle = "#ffffff"; ctx.font = "bold 24px sans-serif";
    ctx.fillText("Zalo · Hỗ trợ Ví MoMo (Tài khoản lạ)", 32, 46);
    ctx.fillStyle = "#ffffff"; ctx.fillRect(32, 110, 656, 220);
    ctx.fillStyle = "#111111"; ctx.font = "22px sans-serif";
    ctx.fillText("Ví MoMo của anh/chị sắp bị khóa sau 15 phút.", 52, 166);
    ctx.fillText("Bấm http://momo-nhanthuong-vn.top/claim", 52, 214);
    ctx.fillText("và gửi mã OTP 6 số + mật khẩu để mở khóa gấp!", 52, 260);
  }

  c.toBlob((blob) => {
    const file = new File([blob], kind === "bill" ? "demo_bill_gia.png" : "demo_chat_zalo.png", { type: "image/png" });
    const note = kind === "bill"
      ? "Nguoi la gui bill chuyen khoan 15.000.000 VND noi tien dang treo, yeu cau bam http://vcb-nhantien-24h.xyz nhap ma OTP de giai ngan."
      : "Tai khoan Zalo la nhan tin: vi MoMo sap bi khoa sau 15 phut, yeu cau bam http://momo-nhanthuong-vn.top/claim va gui ma OTP mat khau.";
    setVisionFile(file, note);
    runVisionInspect();
  }, "image/png");
}

async function runVisionInspect() {
  if (!visionFile) { alert("Chọn ảnh hoặc bấm nút Demo trước."); return; }
  const laser = document.getElementById("imgLaser");
  const btn = document.getElementById("visionAnalyzeBtn");
  const idle = document.getElementById("visionIdle");
  const box = document.getElementById("visionResultBox");

  laser.classList.remove("hidden");
  btn.disabled = true;

  const fd = new FormData();
  fd.append("file", visionFile);
  fd.append("note", document.getElementById("visionNote").value.trim());
  fd.append("channel", "Ảnh chụp / VLM");
  fd.append("situation", "Chưa bấm link");

  const [data] = await Promise.all([
    fetch("/api/analyze-image", { method: "POST", body: fd }).then((r) => r.json()),
    wait(760),
  ]);

  laser.classList.add("hidden");
  btn.disabled = false;
  idle.classList.add("hidden");
  box.classList.remove("hidden");

  const isScam = data.predicted_label === "scam" || data.risk_score >= 61;
  box.innerHTML = `
    <div class="verdict-stamp-banner ${isScam ? "is-scam" : "is-safe"}">
      <div class="vsb-left">
        <div class="mono vsb-kicker">VLM VISION · ${esc(data.risk_level).toUpperCase()}</div>
        <h3>${isScam ? "✋ ẢNH CÓ DẤU HIỆU LỪA ĐẢO!" : "✓ CHƯA THẤY RỦI RO RÕ RÀNG"}</h3>
      </div>
      <div class="vsb-score mono">${data.risk_score}<small>/100</small></div>
    </div>
    <div class="dissect-card">
      <div class="dc-tags">
        <span class="tag-pop bg-yellow">${esc(data.scam_category_label)}</span>
        <span class="tag-pop bg-mint mono">✓ ${esc((data.citations || []).join(", "))}</span>
      </div>
      <div class="dc-msg">${highlightDanger(data.analyzed_text || "Đã kiểm tra tệp ảnh.")}</div>
      <p class="dc-exp">${esc(data.explanation)}</p>
    </div>
    <div class="todo-list">
      ${(data.recommended_actions || []).map((a, i) => `<div class="todo-item"><span class="todo-num mono">${i + 1}</span><span>${esc(a)}</span></div>`).join("")}
    </div>
  `;
}

document.getElementById("genFakeBillBtn").addEventListener("click", () => generateDemoImage("bill"));
document.getElementById("genFakeChatBtn").addEventListener("click", () => generateDemoImage("chat"));
document.getElementById("visionFile").addEventListener("change", (e) => setVisionFile(e.target.files[0]));
document.getElementById("visionAnalyzeBtn").addEventListener("click", runVisionInspect);

const vDrop = document.getElementById("visionDrop");
vDrop.addEventListener("dragover", (e) => { e.preventDefault(); vDrop.classList.add("dragover"); });
vDrop.addEventListener("dragleave", () => vDrop.classList.remove("dragover"));
vDrop.addEventListener("drop", (e) => { e.preventDefault(); vDrop.classList.remove("dragover"); setVisionFile(e.dataTransfer.files[0]); });

/* 5. VIEW 4: BATCH CSV */
function makeSampleCsvText() {
  return [
    "text",
    `"${SAMPLES.momo}"`,
    `"${SAMPLES.vcb}"`,
    `"${SAMPLES.job}"`,
    `"T a i  k h o a n VCB cua ban sap bi khoa. Gui ma OTP khan cap de mo khoa ngay!"`,
    `"${SAMPLES.otp}"`,
    `"Shopee sieu sale 11.11 ma giam 50k cho don tu 199k trong ngay hom nay."`,
  ].join("\n");
}

async function scanBatchFile(file) {
  const fd = new FormData();
  fd.append("file", file);
  const box = document.getElementById("batchTableBox");
  box.innerHTML = `<div class="empty-msg mono">ĐANG QUÉT...</div>`;
  const data = await fetch("/api/batch-scan", { method: "POST", body: fd }).then((r) => r.json());

  const kpis = document.getElementById("batchKpis");
  kpis.classList.remove("hidden");
  kpis.innerHTML = `
    <div class="kpi-card bg-white"><div class="kc-l mono">ĐÃ QUÉT</div><div class="kc-v mono">${data.total_scanned}</div></div>
    <div class="kpi-card bg-yellow"><div class="kc-l mono">LỪA ĐẢO</div><div class="kc-v mono" style="color:#dc2626">${data.scam_detected}</div></div>
    <div class="kpi-card bg-mint"><div class="kc-l mono">AN TOÀN</div><div class="kc-v mono">${data.total_scanned - data.scam_detected}</div></div>
  `;

  box.innerHTML = `
    <table>
      <thead><tr><th>#</th><th>Tin nhắn</th><th>Nhãn</th><th>Điểm</th><th>Kịch bản</th><th>KB</th></tr></thead>
      <tbody>
        ${data.items.map((r) => `
          <tr>
            <td class="mono">${r.row}</td>
            <td>${esc(r.content.slice(0, 82))}${r.content.length > 82 ? "..." : ""}</td>
            <td class="mono" style="font-weight:800;color:${r.predicted_label === "scam" ? "#dc2626" : "#059669"}">${r.predicted_label === "scam" ? "LỪA ĐẢO" : r.predicted_label === "promo" ? "QUẢNG CÁO" : "AN TOÀN"}</td>
            <td class="mono"><strong>${r.risk_score}/100</strong></td>
            <td>${esc(r.scam_category_label)}</td>
            <td class="mono">${esc((r.citations || []).join(", "))}</td>
          </tr>
        `).join("")}
      </tbody>
    </table>
  `;
}

document.getElementById("runDemoBatchBtn").addEventListener("click", () => {
  scanBatchFile(new File([makeSampleCsvText()], "socialshield_demo_6.csv", { type: "text/csv" }));
});
document.getElementById("downloadCsvBtn").addEventListener("click", () => {
  const blob = new Blob([makeSampleCsvText()], { type: "text/csv;charset=utf-8;" });
  const a = document.createElement("a");
  a.href = URL.createObjectURL(blob); a.download = "socialshield_sample_vn.csv"; a.click();
});
document.getElementById("batchFileInput").addEventListener("change", (e) => {
  if (e.target.files[0]) scanBatchFile(e.target.files[0]);
});

/* 6. HEALTH & BENCHMARK */
async function loadHealth() {
  try {
    const h = await fetch("/api/health").then((r) => r.json());
    document.getElementById("healthText").textContent =
      h.llm_provider !== "hybrid_offline_synthesizer" ? `${h.llm_provider}` : `HYBRID · ${h.kb_chunks} KB`;
  } catch {
    document.getElementById("healthText").textContent = "OFFLINE";
  }
}

async function loadBenchmark() {
  try {
    const b = await fetch("/api/benchmark").then((r) => r.json());
    benchLoaded = true;
    const v1 = b.v1_baseline;
    const v2 = b.v2_agentic_rag;
    const rag = b.rag_retrieval;

    document.getElementById("benchMetaBadge").textContent = `${b.dataset_size} CA UNSEEN · ${b.mode.toUpperCase()}`;
    document.getElementById("benchKpis").innerHTML = `
      <div class="kpi-card bg-lime"><div class="kc-l mono">ACCURACY V2</div><div class="kc-v mono">${(v2.accuracy * 100).toFixed(1)}%</div><div class="kc-s">v1: ${(v1.accuracy * 100).toFixed(1)}% (+${((v2.accuracy - v1.accuracy) * 100).toFixed(2)}%)</div></div>
      <div class="kpi-card bg-mint"><div class="kc-l mono">SCAM RECALL</div><div class="kc-v mono">${(v2.scam_recall * 100).toFixed(1)}%</div><div class="kc-s">FPR OTP thật: ${(v2.false_positive_rate * 100).toFixed(1)}%</div></div>
      <div class="kpi-card bg-lilac"><div class="kc-l mono">RAG RECALL@3</div><div class="kc-v mono">${(rag.recall_at_3 * 100).toFixed(1)}%</div><div class="kc-s">MRR@3: ${rag.mrr_at_3.toFixed(3)}</div></div>
      <div class="kpi-card bg-yellow"><div class="kc-l mono">GROUNDING</div><div class="kc-v mono">${(rag.citation_grounding_rate * 100).toFixed(0)}%</div><div class="kc-s">p50: ${v2.latency_p50_ms} ms</div></div>
    `;

    const rows = [
      ["Accuracy", v1.accuracy * 100, v2.accuracy * 100],
      ["Macro F1", v1.macro_f1 * 100, v2.macro_f1 * 100],
      ["Scam Recall", v1.scam_recall * 100, v2.scam_recall * 100],
      ["Scam Precision", v1.scam_precision * 100, v2.scam_precision * 100],
      ["False Positive Rate", v1.false_positive_rate * 100, v2.false_positive_rate * 100],
    ];

    document.getElementById("benchTableBox").innerHTML = `
      <table>
        <thead><tr><th>Chỉ số</th><th>v1 (ML+Rules)</th><th>v2 (Agentic RAG)</th><th>Delta</th></tr></thead>
        <tbody>
          ${rows.map(([n, a, c]) => {
            const d = c - a;
            return `<tr><td><strong>${n}</strong></td><td class="mono">${a.toFixed(2)}%</td><td class="mono"><strong>${c.toFixed(2)}%</strong></td><td class="mono" style="font-weight:800;color:${d > 0 ? "#059669" : "#52525b"}">${d >= 0 ? "+" : ""}${d.toFixed(2)}%</td></tr>`;
          }).join("")}
        </tbody>
      </table>
    `;

    const cases = b.notable_cases || [];
    document.getElementById("benchCasesBox").innerHTML = cases.length
      ? `<table><thead><tr><th>ID</th><th>v1</th><th>v2</th><th>KB</th><th>Nội dung</th></tr></thead><tbody>${cases.map(
          (c) => `<tr><td class="mono">${esc(c.id)}</td><td class="mono" style="color:#dc2626">${esc(c.v1_pred)} (${c.v1_score})</td><td class="mono" style="color:#059669;font-weight:800">${esc(c.v2_pred)} (${c.v2_score})</td><td class="mono">${esc((c.retrieved_kb || []).join(", "))}</td><td>${esc(c.text_preview)}...</td></tr>`
        ).join("")}</tbody></table>`
      : `<div class="empty-msg mono">100% chính xác.</div>`;
  } catch {}
}

loadHealth();
