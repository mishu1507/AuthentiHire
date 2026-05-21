/* ============================================================
   AuthentiHire v2.0 — Client-Side JavaScript (AI-Powered)
   ============================================================
   Functions:
     1. Input mode toggle (text vs file upload)
     2. File upload handling (drag & drop + click)
     3. analyzeText() — POST to /analyze with text or file
     4. displayResults(data) — render combined AI + rule results
     5. downloadReport() — generate .txt report
     6. resetAnalyzer() — clear everything
   ============================================================ */

// ── DOM References ───────────────────────────────────────────
const textarea       = document.getElementById("job-text");
const wordCounterEl  = document.getElementById("word-counter");
const analyzeBtn     = document.getElementById("analyze-btn");
const clearBtn       = document.getElementById("clear-btn");
const resultsSection = document.getElementById("results-section");
const scoreMeterFill = document.getElementById("score-meter-fill");
const scoreNumber    = document.getElementById("score-number");
const riskBadge      = document.getElementById("risk-badge");
const flagsList      = document.getElementById("flags-list");
const phrasesBox     = document.getElementById("phrases-container");
const recBox         = document.getElementById("recommendation-box");
const recIcon        = document.getElementById("rec-icon");
const recText        = document.getElementById("rec-text");
const scoreSource    = document.getElementById("score-source");

// Input mode elements
const modeTextBtn    = document.getElementById("mode-text-btn");
const textMode       = document.getElementById("text-mode");

// AI section elements
const aiSection      = document.getElementById("ai-section");
const aiConfidence   = document.getElementById("ai-confidence");
const aiReasoning    = document.getElementById("ai-reasoning");
const aiScamType     = document.getElementById("ai-scam-type");
const aiFlagsList    = document.getElementById("ai-flags-list");
const aiFlagsContainer = document.getElementById("ai-flags-container");
const aiPositivesList  = document.getElementById("ai-positives-list");
const aiPositivesContainer = document.getElementById("ai-positives-container");
const ruleBar        = document.getElementById("rule-bar");
const aiBar          = document.getElementById("ai-bar");
const ruleScoreDisp  = document.getElementById("rule-score-display");
const aiScoreDisp    = document.getElementById("ai-score-display");

// Download & reset buttons
const downloadBtn    = document.getElementById("download-btn");
const analyzeAnotherBtn = document.getElementById("analyze-another-btn");

// Store latest result and current mode
let lastResult = null;
let currentMode = "text"; // "text" or "image"
let selectedImage = null;

// Image mode elements
const modeImageBtn      = document.getElementById("mode-image-btn");
const imageMode         = document.getElementById("image-mode");
const imageDropzone     = document.getElementById("image-dropzone");
const imageInput        = document.getElementById("image-input");
const imagePreview      = document.getElementById("image-preview");
const imagePreviewImg   = document.getElementById("image-preview-img");
const removeImageBtn    = document.getElementById("remove-image");
const imageFileInfo     = document.getElementById("image-file-info");
const imageFileName     = document.getElementById("image-file-name");
const extractedTextSection = document.getElementById("extracted-text-section");
const extractedTextContent = document.getElementById("extracted-text-content");

/* ============================================================
   1. INPUT MODE TOGGLE
   ============================================================ */
modeTextBtn.addEventListener("click", () => switchMode("text"));
modeImageBtn.addEventListener("click", () => switchMode("image"));

function switchMode(mode) {
  currentMode = mode;

  // Reset all toggle buttons
  modeTextBtn.classList.remove("active");
  modeImageBtn.classList.remove("active");

  // Hide all modes
  textMode.classList.add("hidden");
  imageMode.classList.add("hidden");

  if (mode === "text") {
    modeTextBtn.classList.add("active");
    textMode.classList.remove("hidden");
  } else {
    modeImageBtn.classList.add("active");
    imageMode.classList.remove("hidden");
  }
}



/* ============================================================
   2b. IMAGE UPLOAD HANDLING
   ============================================================ */

imageDropzone.addEventListener("click", (e) => {
  if (e.target !== imageInput) {
    imageInput.click();
  }
});

imageInput.addEventListener("change", (e) => {
  if (e.target.files.length > 0) {
    handleImage(e.target.files[0]);
  }
});

imageDropzone.addEventListener("dragover", (e) => {
  e.preventDefault();
  imageDropzone.classList.add("dragover");
});

imageDropzone.addEventListener("dragleave", () => {
  imageDropzone.classList.remove("dragover");
});

imageDropzone.addEventListener("drop", (e) => {
  e.preventDefault();
  imageDropzone.classList.remove("dragover");
  if (e.dataTransfer.files.length > 0) {
    handleImage(e.dataTransfer.files[0]);
  }
});

function handleImage(file) {
  const ext = file.name.split(".").pop().toLowerCase();
  const allowed = ["png", "jpg", "jpeg"];

  if (!allowed.includes(ext)) {
    showError(`Unsupported image type: .${ext}. Supported: .png, .jpg, .jpeg`);
    return;
  }

  selectedImage = file;
  imageFileName.textContent = `${file.name} (${formatFileSize(file.size)})`;
  imageFileInfo.classList.remove("hidden");
  imageDropzone.classList.add("hidden");

  // Show preview
  const reader = new FileReader();
  reader.onload = (e) => {
    imagePreviewImg.src = e.target.result;
    imagePreview.classList.remove("hidden");
  };
  reader.readAsDataURL(file);
}

function formatFileSize(bytes) {
  if (bytes < 1024) return bytes + " B";
  if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + " KB";
  return (bytes / (1024 * 1024)).toFixed(1) + " MB";
}

removeImageBtn.addEventListener("click", () => {
  selectedImage = null;
  imageInput.value = "";
  imagePreview.classList.add("hidden");
  imageFileInfo.classList.add("hidden");
  imageDropzone.classList.remove("hidden");
  imagePreviewImg.src = "";
});

/* ============================================================
   3. WORD COUNTER
   ============================================================ */
function wordCounter() {
  const text       = textarea.value.trim();
  const words      = text.length === 0 ? 0 : text.split(/\s+/).filter(Boolean).length;
  const characters = textarea.value.length;

  let display = `${words} word${words !== 1 ? "s" : ""} | ${characters} character${characters !== 1 ? "s" : ""}`;

  if (words > 0 && words < 20) {
    display += " — Add more text for better analysis";
    wordCounterEl.classList.add("warn");
  } else {
    wordCounterEl.classList.remove("warn");
  }

  wordCounterEl.textContent = display;
}

textarea.addEventListener("keyup", wordCounter);
textarea.addEventListener("input", wordCounter);

/* ============================================================
   4. ANALYZE — sends text or file to Flask back-end
   ============================================================ */
analyzeBtn.addEventListener("click", analyzeText);

async function analyzeText() {
  let body;
  let headers = {};

  if (currentMode === "text") {
    const inputText = textarea.value.trim();
    if (!inputText) {
      showError("Please paste a job description or email before analyzing.");
      return;
    }
    body = JSON.stringify({ text: inputText });
    headers["Content-Type"] = "application/json";
  } else {
    // image mode
    if (!selectedImage) {
      showError("Please select a screenshot image to analyze.");
      return;
    }
    body = new FormData();
    body.append("file", selectedImage);
  }

  setLoading(true);

  try {
    const fetchOptions = { method: "POST", body };
    if (headers["Content-Type"]) {
      fetchOptions.headers = headers;
    }

    const response = await fetch("/analyze", fetchOptions);

    if (!response.ok) {
      const errData = await response.json().catch(() => ({}));
      throw new Error(errData.error || `Server responded with status ${response.status}`);
    }

    const data = await response.json();
    displayResults(data);
  } catch (error) {
    console.error("Analysis failed:", error);
    showError(error.message || "Something went wrong while analyzing. Please try again.");
  } finally {
    setLoading(false);
  }
}

function setLoading(loading) {
  if (loading) {
    analyzeBtn.disabled   = true;
    analyzeBtn.classList.add("loading");
    analyzeBtn.innerHTML  = '<span class="spinner"></span> Analyzing with AI...';
  } else {
    analyzeBtn.disabled   = false;
    analyzeBtn.classList.remove("loading");
    analyzeBtn.textContent = "🔍 Analyze with AI";
  }
}

function showError(message) {
  const existing = document.querySelector(".analyzer__error");
  if (existing) existing.remove();

  const el       = document.createElement("div");
  el.className   = "analyzer__error";

  if (message.includes("429") || message.includes("RESOURCE_EXHAUSTED") || message.includes("AI Vision is required")) {
    el.classList.add("quota-error");
    el.style.textAlign = "left";
    el.style.backgroundColor = "#fee2e2";
    el.style.borderLeft = "4px solid #ef4444";
    el.innerHTML = `
      <div style="font-weight: 600; margin-bottom: 0.5rem; color: #b91c1c;">🌐 AI Vision Quota Exceeded / Unavailable</div>
      <div style="font-size: 0.9rem; line-height: 1.4; color: #1f2937;">
        The screenshot analysis is temporarily rate-limited. Don't worry! You can still analyze this instantly:
        <ol style="margin-top: 0.5rem; margin-left: 1.2rem; margin-bottom: 0.8rem;">
          <li>Copy the text from your email or screenshot.</li>
          <li>Paste it in the <strong>📝 Paste Text</strong> tab.</li>
          <li>Click <strong>Analyze with AI</strong> for an instant check!</li>
        </ol>
      </div>
      <button onclick="document.getElementById('mode-text-btn').click(); this.parentElement.remove();" 
              style="background: #ef4444; color: white; border: none; padding: 0.5rem 1rem; border-radius: 4px; cursor: pointer; font-weight: 500; font-family: inherit;">
        Switch to Paste Text Mode
      </button>
    `;
    setTimeout(() => { if(el.parentElement) el.remove(); }, 15000);
  } else {
    el.textContent = `❌ ${message}`;
    setTimeout(() => { if(el.parentElement) el.remove(); }, 6000);
  }

  const card = document.querySelector(".analyzer__card");
  card.appendChild(el);
}

/* ============================================================
   5. DISPLAY RESULTS
   ============================================================ */
function displayResults(data) {
  lastResult = data;

  const level = (data.risk_level || "LOW").toUpperCase();
  const colorMap = {
    LOW:    { css: "low",    color: "#71717a", icon: "🛡️" },
    MEDIUM: { css: "medium", color: "#fbbf24", icon: "⚠️" },
    HIGH:   { css: "high",   color: "#fbbf24", icon: "🚨" },
  };
  const palette = colorMap[level] || colorMap.LOW;

  // ── Score meter ──
  scoreMeterFill.style.background = palette.color;
  animateScore(data.score || 0);

  // ── Risk badge ──
  riskBadge.textContent = `${level} RISK`;
  riskBadge.className   = `score-card__badge ${palette.css}`;

  // ── Scoring source ──
  const sourceLabels = {
    "ai_primary": "🤖 AI-weighted (60% AI + 40% Rules)",
    "ai_secondary": "⚖️ Balanced (40% AI + 60% Rules)",
    "rules_only": "📋 Rule-based only",
  };
  scoreSource.textContent = sourceLabels[data.scoring_source] || "";

  // ── AI Section ──
  if (data.ai_available) {
    aiSection.classList.remove("hidden");

    // Confidence badge
    const conf = data.ai_confidence || 0;
    aiConfidence.textContent = `${conf}% confidence`;
    aiConfidence.className = `ai-section__confidence ${conf >= 70 ? "high-conf" : conf >= 40 ? "med-conf" : "low-conf"}`;

    // Reasoning
    aiReasoning.textContent = data.ai_reasoning || "";

    // Scam type
    const scamTypeLabels = {
      "recruitment_phishing": "🎣 Recruitment Phishing",
      "fee_fraud": "💰 Fee Fraud",
      "data_harvesting": "📊 Data Harvesting",
      "pyramid_scheme": "🔺 Pyramid Scheme",
      "impersonation": "🎭 Impersonation",
      "legitimate": "✅ Appears Legitimate",
      "unknown": "❓ Unknown",
    };
    const scamType = data.scam_type || "unknown";
    aiScamType.textContent = scamTypeLabels[scamType] || scamType;
    aiScamType.className = `ai-section__scam-type ${scamType === "legitimate" ? "legitimate" : scamType === "unknown" ? "" : "scam"}`;

    // AI Flags
    aiFlagsList.innerHTML = "";
    const aiFlags = data.ai_flags || [];
    if (aiFlags.length > 0) {
      aiFlagsContainer.classList.remove("hidden");
      aiFlags.forEach((flag) => {
        const li = document.createElement("li");
        li.textContent = `🚩 ${flag}`;
        aiFlagsList.appendChild(li);
      });
    } else {
      aiFlagsContainer.classList.add("hidden");
    }

    // AI Positive signals
    aiPositivesList.innerHTML = "";
    const positives = data.ai_positive_signals || [];
    if (positives.length > 0) {
      aiPositivesContainer.classList.remove("hidden");
      positives.forEach((sig) => {
        const li = document.createElement("li");
        li.textContent = `✅ ${sig}`;
        aiPositivesList.appendChild(li);
      });
    } else {
      aiPositivesContainer.classList.add("hidden");
    }

    // Score breakdown bars
    const ruleScore = data.rule_score || 0;
    const aiScore = data.ai_score || 0;
    ruleBar.style.width = `${ruleScore}%`;
    aiBar.style.width = `${aiScore}%`;
    ruleScoreDisp.textContent = ruleScore;
    aiScoreDisp.textContent = aiScore;

    // Color the bars
    ruleBar.style.background = ruleScore > 60 ? "#e74c3c" : ruleScore > 30 ? "#f39c12" : "#2ecc71";
    aiBar.style.background = aiScore > 60 ? "#e74c3c" : aiScore > 30 ? "#f39c12" : "#2ecc71";

  } else {
    aiSection.classList.add("hidden");
  }

  // ── Extracted text from image ──
  if (data.is_image_analysis && data.extracted_text) {
    extractedTextSection.classList.remove("hidden");
    extractedTextContent.textContent = data.extracted_text;
  } else {
    extractedTextSection.classList.add("hidden");
  }

  // ── Red flags (rule-based) ──
  flagsList.innerHTML = "";
  const flags = data.flags || [];
  if (flags.length === 0) {
    flagsList.innerHTML = '<li class="no-flags">✅ No major red flags found</li>';
  } else {
    flags.forEach((flag) => {
      const li = document.createElement("li");
      // Categorize flag type for styling
      if (flag.startsWith("Positive:")) {
        li.className = "flag--positive";
        li.textContent = `✅ ${flag}`;
      } else {
        li.textContent = `⚠️ ${flag}`;
      }
      flagsList.appendChild(li);
    });
  }

  // ── Suspicious phrases ──
  phrasesBox.innerHTML = "";
  const phrases = data.highlighted_phrases || [];
  if (phrases.length === 0) {
    phrasesBox.innerHTML = '<span class="no-phrases">✅ No suspicious phrases detected</span>';
  } else {
    phrases.forEach((phrase) => {
      const span       = document.createElement("span");
      span.className   = `phrase-badge${level === "MEDIUM" ? " orange" : ""}`;
      span.textContent = phrase;
      phrasesBox.appendChild(span);
    });
  }

  // ── Recommendation ──
  recIcon.textContent      = palette.icon;
  recText.textContent      = data.recommendation || "Analysis complete.";
  recBox.className         = `recommendation ${palette.css}`;

  // ── Show results & scroll ──
  resultsSection.classList.remove("hidden");
  requestAnimationFrame(() => {
    resultsSection.scrollIntoView({ behavior: "smooth", block: "start" });
  });
}

function animateScore(target) {
  let current  = 0;
  const step   = Math.max(1, Math.ceil(target / 50));
  const timer  = setInterval(() => {
    current += step;
    if (current >= target) {
      current = target;
      clearInterval(timer);
    }
    scoreNumber.textContent = current;
    scoreMeterFill.style.width = `${current}%`;
  }, 20);
}

/* ============================================================
   6. DOWNLOAD REPORT
   ============================================================ */
downloadBtn.addEventListener("click", downloadReport);

function downloadReport() {
  if (!lastResult) {
    showError("No analysis to download. Please analyze a job listing first.");
    return;
  }

  const now   = new Date();
  const stamp = now.toLocaleString("en-US", {
    dateStyle: "full",
    timeStyle: "medium",
  });

  const flags   = (lastResult.flags || []).map((f) => `  - ${f}`).join("\n") || "  None";
  const phrases = (lastResult.highlighted_phrases || []).map((p) => `  - ${p}`).join("\n") || "  None";
  const aiFlags = (lastResult.ai_flags || []).map((f) => `  - ${f}`).join("\n") || "  None";

  let report = `
============================================
   AUTHENTIHIRE v2.0 — AI SCAM ANALYSIS REPORT
   Generated: ${stamp}
============================================

FINAL RISK SCORE : ${lastResult.score} / 100
RISK LEVEL       : ${(lastResult.risk_level || "N/A").toUpperCase()}
SCORING METHOD   : ${lastResult.scoring_source || "N/A"}
`;

  if (lastResult.ai_available) {
    report += `
--------------------------------------------
AI ANALYSIS (Google Gemini):
  AI Score      : ${lastResult.ai_score} / 100
  AI Confidence : ${lastResult.ai_confidence}%
  Scam Type     : ${lastResult.scam_type || "unknown"}
  Reasoning     : ${lastResult.ai_reasoning || "N/A"}

AI-DETECTED RED FLAGS:
${aiFlags}
`;
  }

  report += `
--------------------------------------------
RULE-BASED ANALYSIS:
  Rule Score : ${lastResult.rule_score || lastResult.score} / 100

RED FLAGS DETECTED:
${flags}

--------------------------------------------
SUSPICIOUS PHRASES:
${phrases}

--------------------------------------------
RECOMMENDATION:
  ${lastResult.recommendation || "N/A"}

============================================
  Analyzed by AuthentiHire v2.0 (AI-Powered)
============================================
`;

  const blob = new Blob([report.trim()], { type: "text/plain;charset=utf-8" });
  const url  = URL.createObjectURL(blob);
  const a    = document.createElement("a");
  a.href     = url;
  a.download = "AuthentiHire_AI_Report.txt";
  document.body.appendChild(a);
  a.click();
  setTimeout(() => {
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  }, 100);
}

/* ============================================================
   7. RESET ANALYZER
   ============================================================ */
clearBtn.addEventListener("click", resetAnalyzer);
analyzeAnotherBtn.addEventListener("click", resetAnalyzer);

function resetAnalyzer() {
  // Clear text input
  textarea.value             = "";
  wordCounterEl.textContent  = "0 words | 0 characters";
  wordCounterEl.classList.remove("warn");



  // Clear image input
  selectedImage = null;
  imageInput.value = "";
  imagePreview.classList.add("hidden");
  imageFileInfo.classList.add("hidden");
  imageDropzone.classList.remove("hidden");
  imagePreviewImg.src = "";

  // Switch back to text mode
  switchMode("text");

  // Hide results
  resultsSection.classList.add("hidden");

  // Reset score
  scoreNumber.textContent = "0";
  scoreMeterFill.style.width = "0%";

  // Reset AI section
  aiSection.classList.add("hidden");
  extractedTextSection.classList.add("hidden");

  // Clear stored result
  lastResult = null;

  // Scroll to top
  window.scrollTo({ top: 0, behavior: "smooth" });
}
