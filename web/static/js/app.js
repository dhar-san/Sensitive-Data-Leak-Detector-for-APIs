/**
 * Sensitive Data Leak Detector for APIs (T1-PS7)
 * Frontend Interactive Engine
 */

document.addEventListener("DOMContentLoaded", () => {
  // Global State
  let currentScanResult = null;
  let sampleFiles = [];
  let sevChart = null;
  let typeChart = null;

  // DOM Elements - Navigation
  const navTabs = document.querySelectorAll(".nav-tab");
  const tabContents = document.querySelectorAll(".tab-content");
  const themeToggleBtn = document.getElementById("themeToggleBtn");

  // DOM Elements - Inputs
  const rawPayloadInput = document.getElementById("rawPayloadInput");
  const maskingStyleSelect = document.getElementById("maskingStyleSelect");
  const minSeveritySelect = document.getElementById("minSeveritySelect");
  const presidioCheckbox = document.getElementById("presidioCheckbox");
  const runScanBtn = document.getElementById("runScanBtn");
  const clearInputBtn = document.getElementById("clearInputBtn");
  const formatJsonBtn = document.getElementById("formatJsonBtn");
  const sampleButtonsContainer = document.getElementById("sampleButtonsContainer");
  const inputFormatBadge = document.getElementById("inputFormatBadge");

  // Subtabs (Paste vs Upload)
  const subtabBtns = document.querySelectorAll(".subtab-btn");
  const subtabContents = document.querySelectorAll(".subtab-content");
  const fileDropzone = document.getElementById("fileDropzone");
  const fileUploadInput = document.getElementById("fileUploadInput");
  const selectedFilesList = document.getElementById("selectedFilesList");
  let uploadedFilesQueue = [];

  // Hero Assessment
  const heroShield = document.getElementById("heroShield");
  const heroRiskTitle = document.getElementById("heroRiskTitle");
  const heroRiskDesc = document.getElementById("heroRiskDesc");
  const heroRiskScore = document.getElementById("heroRiskScore");
  const scanLatencyTag = document.getElementById("scanLatencyTag");
  const kpiCritCount = document.getElementById("kpiCritCount");
  const kpiHighCount = document.getElementById("kpiHighCount");
  const kpiMedCount = document.getElementById("kpiMedCount");
  const kpiLowCount = document.getElementById("kpiLowCount");
  const quickRecsList = document.getElementById("quickRecsList");

  // Detailed Dashboard Elements
  const dashTotalFindings = document.getElementById("dashTotalFindings");
  const dashCriticalFindings = document.getElementById("dashCriticalFindings");
  const dashHighFindings = document.getElementById("dashHighFindings");
  const dashMediumFindings = document.getElementById("dashMediumFindings");
  const findingsTableBody = document.getElementById("findingsTableBody");
  const tableSearchInput = document.getElementById("tableSearchInput");
  const filterPills = document.querySelectorAll(".filter-pills .pill-btn");

  // Sanitized Code Viewer
  const maskedPayloadCodeBlock = document.getElementById("maskedPayloadCodeBlock");
  const copyMaskedBtn = document.getElementById("copyMaskedBtn");
  const downloadMaskedBtn = document.getElementById("downloadMaskedBtn");

  // Export
  const exportMenuBtn = document.getElementById("exportMenuBtn");
  const exportDropdownContent = document.getElementById("exportDropdownContent");

  // Modals
  const findingModal = document.getElementById("findingModal");
  const modalCloseBtn = document.getElementById("modalCloseBtn");
  const modalFindingTitle = document.getElementById("modalFindingTitle");
  const modalFindingBody = document.getElementById("modalFindingBody");

  const addRuleModal = document.getElementById("addRuleModal");
  const openAddRuleModalBtn = document.getElementById("openAddRuleModalBtn");
  const addRuleCloseBtn = document.getElementById("addRuleCloseBtn");
  const cancelAddRuleBtn = document.getElementById("cancelAddRuleBtn");
  const addRuleForm = document.getElementById("addRuleForm");

  // Jumps
  document.getElementById("jumpToDashboardBtn").addEventListener("click", () => switchTab("tab-dashboard"));
  document.getElementById("jumpToMaskedBtn").addEventListener("click", () => switchTab("tab-sanitized"));

  // -------------------------------------------------------------
  // 1. Navigation & Theme Switching
  // -------------------------------------------------------------
  function switchTab(targetId) {
    navTabs.forEach((tab) => {
      tab.classList.toggle("active", tab.dataset.target === targetId);
    });
    tabContents.forEach((c) => {
      c.classList.toggle("active", c.id === targetId);
    });

    if (targetId === "tab-rules") {
      loadRules();
    }
  }

  navTabs.forEach((tab) => {
    tab.addEventListener("click", () => switchTab(tab.dataset.target));
  });

  themeToggleBtn.addEventListener("click", () => {
    const root = document.documentElement;
    const current = root.getAttribute("data-theme") || "dark";
    const next = current === "dark" ? "light" : "dark";
    root.setAttribute("data-theme", next);
    themeToggleBtn.innerHTML = next === "dark" ? '<i class="fa-solid fa-moon"></i>' : '<i class="fa-solid fa-sun"></i>';
    showToast(`Switched to ${next} theme`, "info");
  });

  // Subtabs (Paste vs Upload)
  subtabBtns.forEach((btn) => {
    btn.addEventListener("click", () => {
      subtabBtns.forEach((b) => b.classList.remove("active"));
      subtabContents.forEach((c) => c.classList.remove("active"));
      btn.classList.add("active");
      document.getElementById(btn.dataset.subtarget).classList.add("active");
    });
  });

  // -------------------------------------------------------------
  // 2. Fetch Samples & Initialize
  // -------------------------------------------------------------
  async function loadSamples() {
    try {
      const res = await fetch("/api/samples");
      const data = await res.json();
      sampleFiles = data.samples || [];
      renderSampleButtons();
    } catch (err) {
      console.error("Failed to load samples:", err);
      sampleButtonsContainer.innerHTML = '<span class="text-dim">Unable to load preset samples</span>';
    }
  }

  function renderSampleButtons() {
    sampleButtonsContainer.innerHTML = "";
    sampleFiles.forEach((sample) => {
      const btn = document.createElement("button");
      btn.className = "sample-btn";
      btn.title = sample.description;
      btn.innerHTML = `<i class="fa-solid fa-file-code"></i> ${sample.name}`;
      btn.addEventListener("click", () => {
        rawPayloadInput.value = sample.content;
        updateInputBadge(sample.content);
        // Switch to paste view if in upload
        subtabBtns[0].click();
        showToast(`Loaded preset: ${sample.name}`, "info");
        // Automatically run scan on sample click for fast evaluation!
        executeScan();
      });
      sampleButtonsContainer.appendChild(btn);
    });
  }

  // Auto-detect format badge
  rawPayloadInput.addEventListener("input", () => {
    updateInputBadge(rawPayloadInput.value);
  });

  function updateInputBadge(text) {
    const trimmed = text.trim();
    if (!trimmed) {
      inputFormatBadge.textContent = "Empty";
      return;
    }
    if ((trimmed.startsWith("{") && trimmed.endsWith("}")) || (trimmed.startsWith("[") && trimmed.endsWith("]"))) {
      inputFormatBadge.textContent = "JSON Payload";
    } else if (trimmed.includes("\n") && trimmed.startsWith("{")) {
      inputFormatBadge.textContent = "JSON Lines (jsonl)";
    } else {
      inputFormatBadge.textContent = "Plaintext / Log";
    }
  }

  clearInputBtn.addEventListener("click", () => {
    rawPayloadInput.value = "";
    updateInputBadge("");
    uploadedFilesQueue = [];
    selectedFilesList.innerHTML = "";
    showToast("Input cleared", "info");
  });

  formatJsonBtn.addEventListener("click", () => {
    const trimmed = rawPayloadInput.value.trim();
    if (!trimmed) return;
    try {
      const obj = JSON.parse(trimmed);
      rawPayloadInput.value = JSON.stringify(obj, null, 2);
      showToast("JSON formatted cleanly", "success");
    } catch (e) {
      showToast("Cannot prettify: Input is not valid JSON", "error");
    }
  });

  // -------------------------------------------------------------
  // 3. Drag and Drop File Upload
  // -------------------------------------------------------------
  fileDropzone.addEventListener("click", () => fileUploadInput.click());

  fileDropzone.addEventListener("dragover", (e) => {
    e.preventDefault();
    fileDropzone.classList.add("dragover");
  });

  fileDropzone.addEventListener("dragleave", () => {
    fileDropzone.classList.remove("dragover");
  });

  fileDropzone.addEventListener("drop", (e) => {
    e.preventDefault();
    fileDropzone.classList.remove("dragover");
    if (e.dataTransfer.files.length) {
      handleFilesSelected(e.dataTransfer.files);
    }
  });

  fileUploadInput.addEventListener("change", (e) => {
    if (e.target.files.length) {
      handleFilesSelected(e.target.files);
    }
  });

  function handleFilesSelected(files) {
    uploadedFilesQueue = Array.from(files);
    selectedFilesList.innerHTML = "";
    uploadedFilesQueue.forEach((file) => {
      const chip = document.createElement("div");
      chip.className = "file-chip";
      chip.innerHTML = `<i class="fa-solid fa-file"></i> <strong>${file.name}</strong> <small>(${Math.round(file.size / 1024)} KB)</small>`;
      selectedFilesList.appendChild(chip);
    });
    showToast(`Loaded ${files.length} file(s) for scanning`, "info");
  }

  // -------------------------------------------------------------
  // 4. Run Scan Execution
  // -------------------------------------------------------------
  runScanBtn.addEventListener("click", executeScan);

  async function executeScan() {
    runScanBtn.disabled = true;
    runScanBtn.innerHTML = '<i class="fa-solid fa-circle-notch fa-spin"></i> Analyzing...';
    scanLatencyTag.textContent = "Processing...";

    const activeMode = document.querySelector(".subtab-btn.active").dataset.subtarget;

    try {
      let res, data;

      if (activeMode === "mode-upload" && uploadedFilesQueue.length > 0) {
        // Multi-file upload scan
        const formData = new FormData();
        uploadedFilesQueue.forEach((f) => formData.append("files", f));
        formData.append("masking_style", maskingStyleSelect.value);
        formData.append("min_severity", minSeveritySelect.value);

        res = await fetch("/api/scan-file", {
          method: "POST",
          body: formData,
        });
      } else {
        // String scan
        const textToScan = rawPayloadInput.value;
        if (!textToScan.trim()) {
          showToast("Please provide input text or select a preset sample.", "error");
          runScanBtn.disabled = false;
          runScanBtn.innerHTML = '<i class="fa-solid fa-shield-virus"></i> Run Security Scan';
          return;
        }

        res = await fetch("/api/scan", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            text: textToScan,
            masking_style: maskingStyleSelect.value,
            min_severity: minSeveritySelect.value,
            enable_presidio: presidioCheckbox.checked,
          }),
        });
      }

      data = await res.json();
      if (!res.ok) {
        throw new Error(data.error || "Failed to complete scan");
      }

      currentScanResult = data;
      renderScanResults(data);
      showToast(`Scan complete: ${data.total_findings} finding(s) identified`, data.total_findings > 0 ? "info" : "success");
    } catch (err) {
      console.error("Scan error:", err);
      showToast(err.message, "error");
    } finally {
      runScanBtn.disabled = false;
      runScanBtn.innerHTML = '<i class="fa-solid fa-shield-virus"></i> Run Security Scan';
    }
  }

  // -------------------------------------------------------------
  // 5. Render Scan Results & Update UI
  // -------------------------------------------------------------
  function renderScanResults(data) {
    const summary = data.summary;
    const findings = data.findings || [];

    // Latency
    scanLatencyTag.textContent = `${data.duration_ms} ms`;

    // Hero Shield & Risk Status
    heroShield.className = `shield-graphic shield-${summary.overall_risk_level.toLowerCase()}`;
    if (summary.overall_risk_level === "Clean") {
      heroShield.innerHTML = '<i class="fa-solid fa-shield-check"></i>';
    } else if (summary.overall_risk_level === "Critical") {
      heroShield.innerHTML = '<i class="fa-solid fa-triangle-exclamation"></i>';
    } else {
      heroShield.innerHTML = '<i class="fa-solid fa-shield-halved"></i>';
    }

    heroRiskTitle.textContent = `${summary.overall_risk_level.toUpperCase()} RISK`;
    heroRiskDesc.textContent = summary.risk_summary;
    heroRiskScore.textContent = summary.risk_score;

    // Mini counters
    const sevCounts = summary.severity_counts || {};
    kpiCritCount.textContent = sevCounts["Critical"] || 0;
    kpiHighCount.textContent = sevCounts["High"] || 0;
    kpiMedCount.textContent = sevCounts["Medium"] || 0;
    kpiLowCount.textContent = sevCounts["Low"] || 0;

    // Quick Recommendations
    quickRecsList.innerHTML = "";
    if (data.top_recommendations && data.top_recommendations.length > 0) {
      data.top_recommendations.slice(0, 4).forEach((rec) => {
        const li = document.createElement("li");
        li.innerHTML = `<strong>[${rec.priority}] ${rec.title}:</strong> ${rec.recommendation}`;
        quickRecsList.appendChild(li);
      });
    } else {
      quickRecsList.innerHTML = '<li class="empty-rec">✅ No sensitive data leaks detected. No remediation required.</li>';
    }

    // Detailed Dashboard KPIs
    dashTotalFindings.textContent = data.total_findings;
    dashCriticalFindings.textContent = sevCounts["Critical"] || 0;
    dashHighFindings.textContent = sevCounts["High"] || 0;
    dashMediumFindings.textContent = sevCounts["Medium"] || 0;

    // Render Charts
    renderCharts(summary);

    // Populate Findings Table
    populateFindingsTable(findings);

    // Sanitized Code Viewer
    maskedPayloadCodeBlock.textContent = data.masked_payload || "// Empty payload";
  }

  // -------------------------------------------------------------
  // 6. Chart.js Visualizations
  // -------------------------------------------------------------
  function renderCharts(summary) {
    const sevCounts = summary.severity_counts || {};
    const typeCounts = summary.type_counts || {};

    // 1. Severity Doughnut Chart
    const sevCtx = document.getElementById("dashSevChart").getContext("2d");
    if (sevChart) sevChart.destroy();

    const sevLabels = Object.keys(sevCounts);
    const sevData = Object.values(sevCounts);

    sevChart = new Chart(sevCtx, {
      type: "doughnut",
      data: {
        labels: sevLabels,
        datasets: [
          {
            data: sevData,
            backgroundColor: ["#ef4444", "#f97316", "#eab308", "#3b82f6"],
            borderWidth: 0,
          },
        ],
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
          legend: {
            position: "bottom",
            labels: { color: "#94a3b8", boxWidth: 12 },
          },
        },
      },
    });

    // 2. Category Bar Chart
    const typeCtx = document.getElementById("dashTypeChart").getContext("2d");
    if (typeChart) typeChart.destroy();

    const typeLabels = Object.keys(typeCounts);
    const typeData = Object.values(typeCounts);

    typeChart = new Chart(typeCtx, {
      type: "bar",
      data: {
        labels: typeLabels.length ? typeLabels : ["None"],
        datasets: [
          {
            label: "Findings",
            data: typeData.length ? typeData : [0],
            backgroundColor: "#38bdf8",
            borderRadius: 6,
          },
        ],
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
          legend: { display: false },
        },
        scales: {
          x: { ticks: { color: "#94a3b8" }, grid: { display: false } },
          y: { ticks: { color: "#94a3b8", stepSize: 1 }, grid: { color: "rgba(255,255,255,0.05)" }, beginAtZero: true },
        },
      },
    });
  }

  // -------------------------------------------------------------
  // 7. Findings Registry Table & Search / Filter
  // -------------------------------------------------------------
  let currentFilter = "all";

  function populateFindingsTable(findings) {
    findingsTableBody.innerHTML = "";

    const query = tableSearchInput.value.toLowerCase().trim();
    const filtered = findings.filter((f) => {
      const matchSeverity = currentFilter === "all" || f.severity === currentFilter;
      const matchQuery =
        !query ||
        f.location.toLowerCase().includes(query) ||
        f.rule_name.toLowerCase().includes(query) ||
        f.type.toLowerCase().includes(query) ||
        f.recommendation.toLowerCase().includes(query) ||
        f.masked_value.toLowerCase().includes(query);

      return matchSeverity && matchQuery;
    });

    if (filtered.length === 0) {
      findingsTableBody.innerHTML = `<tr><td colspan="8" class="text-center empty-state">No matching findings found.</td></tr>`;
      return;
    }

    filtered.forEach((f) => {
      const tr = document.createElement("tr");
      tr.innerHTML = `
        <td><span class="code-badge">${f.finding_id}</span></td>
        <td><span class="code-badge">${f.location}</span></td>
        <td><strong>${f.rule_name}</strong></td>
        <td>${f.type}</td>
        <td><span class="sev-badge ${f.severity}">${f.severity}</span></td>
        <td><span class="code-badge">${f.masked_value}</span></td>
        <td>${f.recommendation}</td>
        <td><button class="btn-sm btn-ghost view-detail-btn" data-id="${f.finding_id}"><i class="fa-solid fa-arrow-up-right-from-square"></i></button></td>
      `;
      findingsTableBody.appendChild(tr);
    });

    // Attach row detail clicks
    document.querySelectorAll(".view-detail-btn").forEach((b) => {
      b.addEventListener("click", () => {
        const item = findings.find((x) => x.finding_id === b.dataset.id);
        if (item) openFindingModal(item);
      });
    });
  }

  // Filter pills
  filterPills.forEach((p) => {
    p.addEventListener("click", () => {
      filterPills.forEach((x) => x.classList.remove("active"));
      p.classList.add("active");
      currentFilter = p.dataset.filter;
      if (currentScanResult) {
        populateFindingsTable(currentScanResult.findings || []);
      }
    });
  });

  // Table search
  tableSearchInput.addEventListener("input", () => {
    if (currentScanResult) {
      populateFindingsTable(currentScanResult.findings || []);
    }
  });

  // -------------------------------------------------------------
  // 8. Finding Details Drawer Modal
  // -------------------------------------------------------------
  function openFindingModal(f) {
    modalFindingTitle.innerHTML = `<i class="fa-solid fa-shield-virus"></i> ${f.finding_id}: ${f.rule_name}`;

    const standardsHtml = (f.standards || [])
      .map((s) => `<span class="chip">${s}</span>`)
      .join(" ");

    modalFindingBody.innerHTML = `
      <div style="margin-bottom:16px;">
        <span class="sev-badge ${f.severity}">${f.severity}</span>
        <span class="sub-pill" style="margin-left:6px;">${f.type}</span>
        <span class="sub-pill" style="margin-left:6px;">Confidence: ${f.confidence}</span>
      </div>

      <div class="form-group">
        <label>Location Path</label>
        <div class="code-badge" style="padding:8px; display:block;">${f.location}</div>
      </div>

      <div class="form-group">
        <label>Masked Value (FR-5.1)</label>
        <div class="code-badge" style="padding:8px; display:block; color:#38bdf8;">${f.masked_value}</div>
      </div>

      <div class="form-group">
        <label><i class="fa-solid fa-triangle-exclamation"></i> Security Risk Explanation (FR-6.1)</label>
        <div style="background:var(--bg-app); padding:10px; border-radius:6px; border:1px solid var(--border-color); font-size:13px; line-height:1.5;">
          ${f.risk}
        </div>
      </div>

      <div class="form-group">
        <label><i class="fa-solid fa-wrench"></i> Actionable Remediation Fix (FR-6.2)</label>
        <div style="background:var(--bg-app); padding:10px; border-radius:6px; border:1px solid var(--border-color); font-size:13px; line-height:1.5; color:#34d399;">
          ${f.recommendation}
        </div>
      </div>

      <div class="form-group">
        <label><i class="fa-solid fa-book-bookmark"></i> Compliance Standards Mapped (FR-6.4)</label>
        <div class="chips-list">
          ${standardsHtml || '<span class="text-dim">General API Hardening</span>'}
        </div>
      </div>
    `;

    findingModal.classList.add("show");
  }

  modalCloseBtn.addEventListener("click", () => findingModal.classList.remove("show"));
  findingModal.addEventListener("click", (e) => {
    if (e.target === findingModal) findingModal.classList.remove("show");
  });

  // -------------------------------------------------------------
  // 9. Copy & Download Masked Copy (FR-5.4)
  // -------------------------------------------------------------
  copyMaskedBtn.addEventListener("click", () => {
    const text = maskedPayloadCodeBlock.textContent;
    navigator.clipboard.writeText(text).then(() => {
      showToast("Sanitized payload copied to clipboard!", "success");
    });
  });

  downloadMaskedBtn.addEventListener("click", () => {
    const text = maskedPayloadCodeBlock.textContent;
    const blob = new Blob([text], { type: "text/plain" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `sanitized_response_${Date.now()}.json`;
    a.click();
    URL.revokeObjectURL(url);
    showToast("Downloaded sanitized payload", "info");
  });

  // -------------------------------------------------------------
  // 10. Report Export Center (FR-7.4)
  // -------------------------------------------------------------
  exportMenuBtn.addEventListener("click", (e) => {
    e.stopPropagation();
    exportDropdownContent.parentElement.classList.toggle("show");
  });

  document.addEventListener("click", () => {
    exportDropdownContent.parentElement.classList.remove("show");
  });

  exportDropdownContent.querySelectorAll("a").forEach((link) => {
    link.addEventListener("click", async (e) => {
      e.preventDefault();
      const format = link.dataset.format;
      if (!currentScanResult || !currentScanResult.findings) {
        showToast("No scan results to export. Run a scan first.", "error");
        return;
      }

      try {
        const res = await fetch("/api/export", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            format: format,
            findings: currentScanResult.findings,
            files_scanned: ["api_response_payload"],
          }),
        });

        const blob = await res.blob();
        const url = URL.createObjectURL(blob);
        const a = document.createElement("a");
        a.href = url;
        a.download = `api_leak_report_${Date.now()}.${format}`;
        a.click();
        URL.revokeObjectURL(url);
        showToast(`Exported ${format.toUpperCase()} report successfully`, "success");
      } catch (err) {
        showToast("Export failed: " + err.message, "error");
      }
    });
  });

  // -------------------------------------------------------------
  // 11. Detection Rules & Custom Rule Builder (FR-3.6, FR-3.7)
  // -------------------------------------------------------------
  async function loadRules() {
    try {
      const res = await fetch("/api/rules");
      const data = await res.json();
      renderRulesTable(data.rules || []);
      renderAllowList(data.allow_list || []);
    } catch (err) {
      console.error("Rules loading failed:", err);
    }
  }

  function renderRulesTable(rules) {
    const rulesTableBody = document.getElementById("rulesTableBody");
    rulesTableBody.innerHTML = "";

    rules.forEach((r) => {
      const tr = document.createElement("tr");
      tr.innerHTML = `
        <td><span class="code-badge">${r.id}</span></td>
        <td><strong>${r.name}</strong></td>
        <td>${r.type}</td>
        <td><span class="sev-badge ${r.severity}">${r.severity}</span></td>
        <td><span class="code-badge" style="font-size:11px;">${r.pattern || r.field_match || 'Entropy / Custom'}</span></td>
        <td>
          <label class="switch-label">
            <input type="checkbox" class="rule-toggle-checkbox" data-id="${r.id}" ${r.enabled ? "checked" : ""}>
            <span class="slider"></span>
          </label>
        </td>
      `;
      rulesTableBody.appendChild(tr);
    });

    document.querySelectorAll(".rule-toggle-checkbox").forEach((cb) => {
      cb.addEventListener("change", async () => {
        try {
          await fetch("/api/rules/toggle", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ id: cb.dataset.id, enabled: cb.checked }),
          });
          showToast(`Rule '${cb.dataset.id}' ${cb.checked ? "enabled" : "disabled"}`, "info");
        } catch (e) {
          showToast("Failed to toggle rule", "error");
        }
      });
    });
  }

  function renderAllowList(items) {
    const allowListChips = document.getElementById("allowListChips");
    allowListChips.innerHTML = "";
    items.forEach((item) => {
      const chip = document.createElement("span");
      chip.className = "chip";
      chip.textContent = item;
      allowListChips.appendChild(chip);
    });
  }

  // Custom Rule Modal
  openAddRuleModalBtn.addEventListener("click", () => addRuleModal.classList.add("show"));
  addRuleCloseBtn.addEventListener("click", () => addRuleModal.classList.remove("show"));
  cancelAddRuleBtn.addEventListener("click", () => addRuleModal.classList.remove("show"));

  addRuleForm.addEventListener("submit", async (e) => {
    e.preventDefault();
    const payload = {
      id: document.getElementById("newRuleId").value.trim(),
      name: document.getElementById("newRuleName").value.trim(),
      type: document.getElementById("newRuleType").value,
      severity: document.getElementById("newRuleSeverity").value,
      pattern: document.getElementById("newRulePattern").value.trim(),
      risk: document.getElementById("newRuleRisk").value.trim(),
      recommendation: document.getElementById("newRuleRec").value.trim(),
    };

    try {
      const res = await fetch("/api/rules", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error);

      addRuleModal.classList.remove("show");
      addRuleForm.reset();
      showToast(`Custom rule '${payload.id}' added successfully!`, "success");
      loadRules();
    } catch (err) {
      showToast("Failed to save rule: " + err.message, "error");
    }
  });

  // -------------------------------------------------------------
  // 12. Toast Notification Helper
  // -------------------------------------------------------------
  function showToast(message, type = "info") {
    const container = document.getElementById("toastContainer");
    const toast = document.createElement("div");
    toast.className = `toast toast-${type}`;
    const icon =
      type === "success"
        ? '<i class="fa-solid fa-circle-check" style="color:var(--color-clean)"></i>'
        : type === "error"
        ? '<i class="fa-solid fa-circle-xmark" style="color:var(--color-critical)"></i>'
        : '<i class="fa-solid fa-circle-info" style="color:var(--accent-primary)"></i>';

    toast.innerHTML = `${icon} <span>${message}</span>`;
    container.appendChild(toast);

    setTimeout(() => {
      toast.style.opacity = "0";
      toast.style.transform = "translateX(100%)";
      toast.style.transition = "all 0.3s ease";
      setTimeout(() => toast.remove(), 300);
    }, 3500);
  }

  // Initial load
  loadSamples();
});
