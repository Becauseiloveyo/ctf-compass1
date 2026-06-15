(function () {
  if (!window.ctfCompass) {
    installBrowserPreviewApi();
  }

  window.setTimeout(installCtf2ConnectorUi, 0);

  function installBrowserPreviewApi() {
    const textEncoder = new TextEncoder();
    const sandboxRoot = "Browser preview sandbox";
    const previewArtifacts = [
      {
        id: "preview-readme",
        path: "preview://challenge/readme.txt",
        name: "readme.txt",
        family: "text",
        familyLabel: "文本",
        badge: "TXT",
        sizeLabel: "1.3 KB",
        sourceKind: "input",
      },
    ];

    function delay(value, ms = 160) {
      return new Promise((resolve) => window.setTimeout(() => resolve(value), ms));
    }

    function makeArtifact(path, index) {
      const name = String(path || `artifact-${index + 1}.bin`).split(/[\\/]/).pop() || `artifact-${index + 1}.bin`;
      const extension = name.includes(".") ? name.split(".").pop().toLowerCase() : "bin";
      const family = extension === "pcap" || extension === "pcapng"
        ? "network"
        : ["png", "jpg", "jpeg", "gif", "bmp", "webp"].includes(extension)
          ? "image"
          : ["zip", "gz", "rar", "7z"].includes(extension)
            ? "archive"
            : ["txt", "md", "json", "csv", "log"].includes(extension)
              ? "text"
              : "binary";
      const labels = { archive: "压缩包", binary: "二进制", image: "图像", network: "流量", text: "文本" };
      return {
        id: `preview-${Date.now()}-${index}`,
        path: String(path || `preview://${name}`),
        name,
        family,
        familyLabel: labels[family] || "其他",
        badge: extension.toUpperCase(),
        sizeLabel: `${Math.max(1, Math.round(textEncoder.encode(name).length / 2))}.0 KB`,
        sourceKind: "input",
      };
    }

    function buildPreviewAnalysis(payload) {
      const artifacts = (payload.artifacts || []).map((item, index) => typeof item === "string" ? makeArtifact(item, index) : item);
      const flagCandidates = artifacts.length ? [{ value: "flag{browser_preview_demo}", source: "web-polyfill preview result" }] : [];
      return {
        challenge: {
          title: payload.title || "Browser Preview Challenge",
          description: payload.description || "",
          notes: payload.notes || "",
          tags: payload.tags || [],
          artifactCount: artifacts.length,
        },
        classification: {
          primary: "misc",
          label: "杂项",
          confidence: artifacts.length ? 0.72 : 0.34,
          reason: artifacts.length ? "浏览器预览环境使用 mock 数据展示流程。" : "还没有添加附件。",
          evidence: artifacts.length ? ["已添加预览附件。"] : [],
          nextMoves: ["在桌面版中添加真实附件。", "运行自动求解。"],
          tools: ["内置工具箱"],
        },
        artifacts,
        pipelineLog: [],
        pipelineErrors: [],
        solver: {
          status: artifacts.length ? "solved" : "partial",
          title: artifacts.length ? "已找到预览 flag 候选" : "等待附件",
          summary: artifacts.length ? "这是浏览器预览中的演示候选。" : "添加附件后可查看分析面板布局。",
          primaryFlag: flagCandidates[0] || null,
          candidates: flagCandidates,
          confidence: artifacts.length ? 0.72 : 0.34,
          actionsRun: artifacts.length ? 1 : 0,
          artifactCount: artifacts.length,
          missingTools: [],
          failedActions: [],
          nextActions: ["确认候选来源后再提交。"],
        },
        quickFindings: artifacts.length ? ["预览模式：已加载附件布局。"] : ["先添加题目信息或附件，再进行分析。"],
        flagCandidates,
        warnings: ["当前为浏览器预览 mock。"],
        toolStatus: { installed: [], missing: [] },
        bundledTools: [],
        emptyFlagMessage: "暂无 flag 候选。",
      };
    }

    function buildPreviewWebAnalysis(payload) {
      const target = String(payload?.url || "http://127.0.0.1:8080/");
      return {
        target,
        origin: target.replace(/\/$/, ""),
        resolvedAddresses: ["127.0.0.1"],
        requestCount: 3,
        durationMs: 180,
        pages: [{ url: target, status: 200, contentType: "text/html", bytes: 1240, comments: [], forms: [], sourceMaps: [], routeCandidates: [] }],
        errors: [],
        findings: ["浏览器预览只展示 Web 工作区布局。"],
        flagCandidates: [],
        nextSteps: ["使用 Electron 桌面版分析真实靶机。"],
        reportPath: "",
        reportPaths: [],
      };
    }

    const mockChallenges = [
      {
        id: "preview-signin",
        friendlyId: "signin",
        groundId: "BUUCTF",
        groundName: "BUUCTF",
        name: "签到",
        category: "MISC",
        difficulty: "Easy",
        description: "签到题 flag{buu_ctf}",
        points: 1,
        solveCount: 827,
        files: [{ id: "readme", name: "readme.txt", size: 512, type: "text" }],
      },
      {
        id: "preview-warmup",
        friendlyId: "warmup",
        groundId: "BUUCTF",
        groundName: "BUUCTF",
        name: "[HCTF 2018] WarmUp",
        category: "WEB",
        difficulty: "Easy",
        description: "Web 入门题。",
        points: 1,
        solveCount: 467,
        files: [],
      },
    ];

    window.ctfCompass = {
      pickFiles: () => delay(previewArtifacts),
      pickFolder: () => delay(previewArtifacts),
      prepareArtifacts: (paths) => delay((paths || []).map(makeArtifact)),
      analyzeChallenge: (payload) => delay(buildPreviewAnalysis(payload || {}), 260),
      analyzeWebTarget: (payload) => delay(buildPreviewWebAnalysis(payload || {}), 260),
      runArtifactAction: () => delay({ message: "浏览器预览不会运行本地工具。", generatedArtifacts: [] }),
      revealArtifact: () => delay(null),
      loadWorkspace: () => delay(null),
      loadPreviousWorkspace: () => delay(null),
      saveWorkspace: () => delay({ path: "preview://workspace/session.json" }),
      clearWorkspace: () => delay({ cleared: true }),
      getSandboxInfo: () => delay({ root: sandboxRoot, generated: sandboxRoot, downloads: sandboxRoot, tools: sandboxRoot, session: sandboxRoot, bytes: 0, sizeLabel: "0 B", fileCount: 0 }),
      revealSandbox: () => delay({ root: sandboxRoot, sizeLabel: "0 B", fileCount: 0 }),
      clearSandbox: () => delay({ root: sandboxRoot, sizeLabel: "0 B", fileCount: 0 }),
      exportReport: (payload) => delay({ filePath: `preview://${payload?.suggestedName || "ctf-compass-report.md"}` }),
      getMeta: () => delay({ version: "0.9.1", packaged: false, mode: "browser-preview", sandboxRoot }),
      getCtf2Status: () => delay({ connected: false, cookieCount: 0, profile: null }),
      openCtf2Login: () => delay({ opened: true }),
      openCtf2SystemLogin: () => delay({ opened: true }),
      importCtf2Token: () => delay({ connected: true, cookieCount: 0, profile: { username: "preview" } }),
      logoutCtf2: () => delay({ connected: false, cookieCount: 0, profile: null }),
      listCtf2Challenges: (filters) => delay(filterPreviewChallenges(filters || {})),
      importCtf2Challenge: (payload) => delay(importPreviewChallenge(payload || {})),
    };

    function filterPreviewChallenges(filters) {
      const query = String(filters.query || "").toLowerCase();
      const category = String(filters.category || "all").toLowerCase();
      const challenges = mockChallenges.filter((item) => {
        if (category && category !== "all" && item.category.toLowerCase() !== category) return false;
        if (!query) return true;
        return [item.name, item.category, item.description].join("\n").toLowerCase().includes(query);
      });
      return { total: challenges.length, challenges, categories: ["MISC", "WEB"] };
    }

    function importPreviewChallenge(payload) {
      const challenge = mockChallenges.find((item) => item.id === payload.challengeId) || mockChallenges[0];
      return {
        challenge,
        paths: ["preview://ctf2/readme.txt"],
        metadataPath: "preview://ctf2/ctf2-challenge.json",
        artifacts: [makeArtifact("preview://ctf2/readme.txt", 0)],
      };
    }
  }

  function installCtf2ConnectorUi() {
    const nav = document.querySelector(".nav");
    const main = document.querySelector(".main");
    if (!nav || !main || document.getElementById("ctf2-view")) {
      return;
    }

    const uiState = {
      status: null,
      challenges: [],
      categories: [],
      selected: null,
      busy: false,
      searchTimer: null,
    };

    const navButton = document.createElement("button");
    navButton.className = "nav-item ctf2-nav-item";
    navButton.type = "button";
    navButton.dataset.view = "ctf2";
    navButton.innerHTML = `
      <span class="nav-icon" aria-hidden="true">
        <svg viewBox="0 0 24 24" fill="none">
          <path d="M5 5h14v14H5zM8 9h8M8 13h5M8 17h8" />
          <path d="M16 13h.01" />
        </svg>
      </span>
      <span>CTF2</span>
    `;

    const webNav = nav.querySelector('[data-view="web"]');
    if (webNav && webNav.parentElement === nav) {
      webNav.after(navButton);
    } else if (webNav && webNav.parentElement?.classList.contains("nav-group")) {
      webNav.after(navButton);
    } else {
      nav.append(navButton);
    }

    const ctf2View = document.createElement("section");
    ctf2View.id = "ctf2-view";
    ctf2View.className = "view ctf2-view";
    ctf2View.innerHTML = `
      <section class="panel ctf2-connector-panel">
        <div class="panel-head ctf2-head">
          <div>
            <p class="panel-kicker">CTF2</p>
            <h3 class="panel-title">CTF2 题库连接器</h3>
          </div>
          <div class="ctf2-actions">
            <span id="ctf2-account-status" class="scope-badge">检查登录状态...</span>
            <button id="ctf2-login-button" class="secondary-button" type="button">应用内登录</button>
            <button id="ctf2-system-login-button" class="secondary-button" type="button">浏览器登录</button>
            <button id="ctf2-logout-button" class="secondary-button danger-button" type="button">退出</button>
          </div>
        </div>
        <div class="ctf2-status-card">
          <div>
            <strong id="ctf2-status-title">未连接</strong>
            <p id="ctf2-status-note">可用应用内登录；如果 Passkey / Windows Hello 不可用，使用浏览器登录后复制 token。</p>
          </div>
          <span class="ctf2-status-dot" id="ctf2-status-dot"></span>
        </div>
        <div class="ctf2-token-card">
          <label class="field ctf2-token-field">
            <span>浏览器 token</span>
            <input id="ctf2-token-input" type="password" placeholder="从 CTF2 Local Storage 复制 token" autocomplete="off" />
          </label>
          <button id="ctf2-token-import-button" class="primary-button" type="button">验证并连接</button>
        </div>
      </section>

      <div class="ctf2-layout">
        <section class="panel ctf2-list-panel">
          <div class="panel-head compact-head">
            <div>
              <p class="panel-kicker">题库</p>
              <h3 class="panel-title">题目</h3>
            </div>
          </div>
          <div class="ctf2-search-row">
            <input id="ctf2-search-input" class="ctf2-search" type="search" placeholder="题目名、描述或编号" autocomplete="off" />
            <select id="ctf2-category-select"><option value="all">全部</option></select>
            <button id="ctf2-refresh-button" class="secondary-button" type="button">刷新</button>
          </div>
          <p id="ctf2-result-count" class="empty-copy">尚未加载。</p>
          <div id="ctf2-challenge-list" class="ctf2-problem-list"></div>
        </section>

        <aside class="panel ctf2-detail-panel">
          <div class="panel-head compact-head">
            <div>
              <p class="panel-kicker">详情</p>
              <h3 id="ctf2-detail-title" class="panel-title">选择一道题目</h3>
            </div>
          </div>
          <div id="ctf2-detail-meta" class="ctf2-chip-row"></div>
          <p id="ctf2-detail-description" class="ctf2-description">选择题目后可查看描述、附件和导入操作。</p>
          <div id="ctf2-file-list" class="stack-list compact-stack"></div>
          <button id="ctf2-import-button" class="primary-button ctf2-import-button" type="button" disabled>导入附件并自动求解</button>
          <div class="ctf2-training-card">
            <strong>导入逻辑</strong>
            <p>附件下载到软件沙盒后，会写入当前工作台题面和题目信息。</p>
          </div>
        </aside>
      </div>
    `;
    main.append(ctf2View);

    const el = {
      accountStatus: ctf2View.querySelector("#ctf2-account-status"),
      loginButton: ctf2View.querySelector("#ctf2-login-button"),
      systemLoginButton: ctf2View.querySelector("#ctf2-system-login-button"),
      logoutButton: ctf2View.querySelector("#ctf2-logout-button"),
      tokenInput: ctf2View.querySelector("#ctf2-token-input"),
      tokenImportButton: ctf2View.querySelector("#ctf2-token-import-button"),
      statusTitle: ctf2View.querySelector("#ctf2-status-title"),
      statusNote: ctf2View.querySelector("#ctf2-status-note"),
      statusDot: ctf2View.querySelector("#ctf2-status-dot"),
      searchInput: ctf2View.querySelector("#ctf2-search-input"),
      categorySelect: ctf2View.querySelector("#ctf2-category-select"),
      refreshButton: ctf2View.querySelector("#ctf2-refresh-button"),
      resultCount: ctf2View.querySelector("#ctf2-result-count"),
      challengeList: ctf2View.querySelector("#ctf2-challenge-list"),
      detailTitle: ctf2View.querySelector("#ctf2-detail-title"),
      detailMeta: ctf2View.querySelector("#ctf2-detail-meta"),
      detailDescription: ctf2View.querySelector("#ctf2-detail-description"),
      fileList: ctf2View.querySelector("#ctf2-file-list"),
      importButton: ctf2View.querySelector("#ctf2-import-button"),
    };

    function setStatus(message, kind = "info") {
      const banner = document.getElementById("status-banner");
      if (!banner) return;
      banner.textContent = message;
      banner.dataset.kind = kind;
      banner.classList.remove("is-hidden", "is-error");
      banner.classList.toggle("is-error", kind === "error");
    }

    function setBusy(value) {
      uiState.busy = value;
      [el.loginButton, el.systemLoginButton, el.logoutButton, el.tokenImportButton, el.refreshButton, el.importButton]
        .forEach((button) => {
          if (!button) return;
          button.disabled = value || (button === el.logoutButton && !uiState.status?.connected) || (button === el.importButton && !uiState.selected?.files?.length);
          button.classList.toggle("is-disabled", button.disabled);
        });
    }

    function activateCtf2View() {
      document.querySelectorAll(".nav-item").forEach((item) => item.classList.toggle("active", item === navButton));
      document.querySelectorAll(".view").forEach((view) => view.classList.toggle("is-active", view === ctf2View));
      document.body.dataset.view = "ctf2";
      const kicker = document.getElementById("view-kicker");
      const title = document.getElementById("view-title");
      if (kicker) kicker.textContent = "CTF2";
      if (title) title.textContent = "CTF2 题库连接器";
      if (!uiState.challenges.length) {
        refreshCtf2Status().catch(() => {});
        loadChallenges(false).catch(() => {});
      }
    }

    document.addEventListener("click", (event) => {
      const item = event.target.closest?.(".nav-item");
      if (item && item !== navButton) {
        ctf2View.classList.remove("is-active");
      }
    });
    navButton.addEventListener("click", activateCtf2View);

    function renderStatus(note) {
      const connected = Boolean(uiState.status?.connected);
      el.accountStatus.textContent = connected
        ? `已连接${uiState.status?.profile?.username ? ` · ${uiState.status.profile.username}` : ""}`
        : "未连接";
      el.statusTitle.textContent = connected ? "CTF2 已连接" : "CTF2 未连接";
      el.statusNote.textContent = note || (connected ? "可同步题库、下载附件并导入到当前工作台。" : "可使用应用内登录，或浏览器登录后复制 token。");
      el.statusDot.classList.toggle("connected", connected);
      setBusy(false);
    }

    function renderCategories(categories) {
      const current = el.categorySelect.value || "all";
      el.categorySelect.innerHTML = '<option value="all">全部</option>';
      (categories || []).forEach((category) => {
        const option = document.createElement("option");
        option.value = category;
        option.textContent = category;
        el.categorySelect.append(option);
      });
      el.categorySelect.value = Array.from(el.categorySelect.options).some((option) => option.value === current) ? current : "all";
    }

    function renderList(total) {
      el.resultCount.textContent = `当前显示 ${uiState.challenges.length} 道题${Number.isFinite(total) ? ` / 匹配 ${total}` : ""}`;
      el.challengeList.innerHTML = "";
      if (!uiState.challenges.length) {
        const empty = document.createElement("p");
        empty.className = "empty-copy";
        empty.textContent = "没有匹配的题目。";
        el.challengeList.append(empty);
        renderDetail();
        return;
      }
      uiState.challenges.forEach((challenge) => {
        const button = document.createElement("button");
        button.className = `ctf2-problem${uiState.selected?.id === challenge.id ? " active" : ""}`;
        button.type = "button";
        button.innerHTML = `
          <strong>${escapeHtml(challenge.name)}</strong>
          <span>${escapeHtml([challenge.category, challenge.difficulty].filter(Boolean).join(" · ") || "CTF2")}</span>
          <em>${challenge.files?.length ? `${challenge.files.length} 附件` : "无附件"}</em>
        `;
        button.addEventListener("click", () => {
          uiState.selected = challenge;
          renderList(total);
          renderDetail();
        });
        el.challengeList.append(button);
      });
      renderDetail();
    }

    function renderDetail() {
      const selected = uiState.selected;
      el.detailTitle.textContent = selected?.name || "选择一道题目";
      el.detailDescription.textContent = selected?.description || "选择题目后可查看描述、附件和导入操作。";
      el.detailMeta.innerHTML = "";
      if (selected) {
        [selected.category, selected.difficulty, selected.points ? `${selected.points} 分` : "", selected.solveCount ? `${selected.solveCount} solves` : ""]
          .filter(Boolean)
          .forEach((label) => {
            const chip = document.createElement("span");
            chip.textContent = label;
            el.detailMeta.append(chip);
          });
      }
      el.fileList.innerHTML = "";
      const files = selected?.files || [];
      if (!files.length) {
        const empty = document.createElement("p");
        empty.className = "empty-copy";
        empty.textContent = selected ? "该题没有附件；靶机题需要在 CTF2 页面手动启动环境。" : "尚未选择题目。";
        el.fileList.append(empty);
      } else {
        files.forEach((file) => {
          const row = document.createElement("div");
          row.className = "stack-item";
          row.innerHTML = `<strong>${escapeHtml(file.name || "attachment.bin")}</strong><p>${formatBytes(Number(file.size || 0))}</p>`;
          el.fileList.append(row);
        });
      }
      setBusy(uiState.busy);
    }

    async function refreshCtf2Status(note) {
      try {
        uiState.status = await window.ctfCompass.getCtf2Status?.();
        renderStatus(note);
      } catch (error) {
        uiState.status = { connected: false, error: error.message };
        renderStatus(error.message);
      }
    }

    async function loadChallenges(force = false) {
      if (!window.ctfCompass.listCtf2Challenges) {
        el.resultCount.textContent = "当前构建没有接入 CTF2 题库接口。";
        return;
      }
      setBusy(true);
      try {
        const result = await window.ctfCompass.listCtf2Challenges({
          query: el.searchInput.value.trim(),
          category: el.categorySelect.value,
          force,
          limit: 160,
        });
        uiState.challenges = result.challenges || [];
        if (!uiState.challenges.some((item) => item.id === uiState.selected?.id)) {
          uiState.selected = uiState.challenges[0] || null;
        }
        renderCategories(result.categories || []);
        renderList(Number(result.total));
        setStatus(`已加载 CTF2 题库，共匹配 ${result.total || uiState.challenges.length} 道。`);
      } catch (error) {
        setStatus(`CTF2 题库加载失败：${error.message}`, "error");
        await refreshCtf2Status().catch(() => {});
      } finally {
        setBusy(false);
      }
    }

    async function importToken() {
      const token = el.tokenInput.value.trim();
      if (!token) {
        setStatus("请先粘贴 CTF2 token。", "error");
        el.tokenInput.focus();
        return;
      }
      setBusy(true);
      try {
        uiState.status = await window.ctfCompass.importCtf2Token(token);
        el.tokenInput.value = "";
        renderStatus("Token 验证通过，已连接 CTF2。");
        setStatus("CTF2 token 已验证并保存。");
        await loadChallenges(true);
      } catch (error) {
        setStatus(`CTF2 token 验证失败：${error.message}`, "error");
      } finally {
        setBusy(false);
      }
    }

    async function importChallenge() {
      if (!uiState.selected) return;
      if (!window.ctfCompass.importCtf2Challenge) {
        setStatus("当前构建没有接入 CTF2 导入接口。", "error");
        return;
      }
      setBusy(true);
      try {
        setStatus(`正在下载并导入：${uiState.selected.name}`);
        const imported = await window.ctfCompass.importCtf2Challenge({
          challengeId: uiState.selected.id,
          groundId: uiState.selected.groundId,
        });
        const challenge = imported.challenge || uiState.selected;
        const titleInput = document.getElementById("title-input");
        const tagsInput = document.getElementById("tags-input");
        const descriptionInput = document.getElementById("description-input");
        const notesInput = document.getElementById("notes-input");
        if (titleInput) titleInput.value = challenge.name || "";
        if (tagsInput) tagsInput.value = [challenge.category, "CTF2", challenge.groundName || "BUUCTF"].filter(Boolean).join(" ");
        if (descriptionInput) descriptionInput.value = challenge.description || "";
        if (notesInput) notesInput.value = `CTF2 导入：${challenge.groundName || "BUUCTF"}\n附件已下载到沙盒。`;
        renderImportedArtifacts(imported.artifacts || []);
        activateWorkspaceView();
        setStatus("附件已从 CTF2 下载到沙盒，并写入当前工作台。可继续运行自动求解。");
      } catch (error) {
        setStatus(`CTF2 导入失败：${error.message}`, "error");
        await refreshCtf2Status().catch(() => {});
      } finally {
        setBusy(false);
      }
    }

    function renderImportedArtifacts(artifacts) {
      const list = document.getElementById("artifact-preview-list");
      const count = document.getElementById("artifact-count-pill");
      if (!list || !artifacts.length) return;
      list.innerHTML = "";
      artifacts.forEach((artifact) => {
        const row = document.createElement("div");
        row.className = "artifact-row";
        row.innerHTML = `
          <div class="artifact-meta">
            <span class="artifact-badge">${escapeHtml(artifact.badge || "CTF2")}</span>
            <div class="artifact-text">
              <strong>${escapeHtml(artifact.name || "attachment")}</strong>
              <p>${escapeHtml([artifact.familyLabel, artifact.sizeLabel].filter(Boolean).join("  |  "))}</p>
            </div>
          </div>
        `;
        list.append(row);
      });
      if (count) count.textContent = String(artifacts.length);
    }

    function activateWorkspaceView() {
      document.querySelectorAll(".nav-item").forEach((item) => item.classList.toggle("active", item.dataset.view === "workspace"));
      document.querySelectorAll(".view").forEach((view) => view.classList.toggle("is-active", view.id === "workspace-view"));
      document.body.dataset.view = "workspace";
      const kicker = document.getElementById("view-kicker");
      const title = document.getElementById("view-title");
      if (kicker) kicker.textContent = "工作台";
      if (title) title.textContent = "以附件为中心的 CTF 工作台";
    }

    el.loginButton.addEventListener("click", async () => {
      setBusy(true);
      try {
        await window.ctfCompass.openCtf2Login?.();
        setStatus("已打开 CTF2 登录窗口。登录后返回软件刷新状态。");
      } catch (error) {
        setStatus(`打开 CTF2 登录失败：${error.message}`, "error");
      } finally {
        setBusy(false);
        window.setTimeout(() => refreshCtf2Status().catch(() => {}), 800);
      }
    });
    el.systemLoginButton.addEventListener("click", async () => {
      try {
        await window.ctfCompass.openCtf2SystemLogin?.();
        setStatus("已打开系统浏览器登录页。登录后复制 localStorage token 到输入框。");
      } catch (error) {
        setStatus(`打开浏览器登录失败：${error.message}`, "error");
      }
    });
    el.logoutButton.addEventListener("click", async () => {
      setBusy(true);
      try {
        uiState.status = await window.ctfCompass.logoutCtf2?.();
        renderStatus("已退出 CTF2。 ");
      } catch (error) {
        setStatus(`退出 CTF2 失败：${error.message}`, "error");
      } finally {
        setBusy(false);
      }
    });
    el.tokenImportButton.addEventListener("click", importToken);
    el.tokenInput.addEventListener("keydown", (event) => {
      if (event.key === "Enter" && !el.tokenImportButton.disabled) {
        event.preventDefault();
        importToken();
      }
    });
    el.refreshButton.addEventListener("click", () => loadChallenges(true));
    el.importButton.addEventListener("click", importChallenge);
    el.searchInput.addEventListener("input", () => {
      window.clearTimeout(uiState.searchTimer);
      uiState.searchTimer = window.setTimeout(() => loadChallenges(false), 280);
    });
    el.categorySelect.addEventListener("change", () => loadChallenges(false));

    refreshCtf2Status().catch(() => {});
  }

  function escapeHtml(value) {
    return String(value ?? "")
      .replaceAll("&", "&amp;")
      .replaceAll("<", "&lt;")
      .replaceAll(">", "&gt;")
      .replaceAll('"', "&quot;")
      .replaceAll("'", "&#039;");
  }

  function formatBytes(size) {
    if (!size) return "未知大小";
    if (size < 1024) return `${size} B`;
    if (size < 1024 * 1024) return `${(size / 1024).toFixed(1)} KB`;
    return `${(size / 1024 / 1024).toFixed(1)} MB`;
  }
})();
