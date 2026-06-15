(function () {
  if (!window.ctfCompass) {
    installBrowserPreviewApi();
  }

  window.setTimeout(installCtf2ConnectorUi, 0);

  function installBrowserPreviewApi() {
    const sandboxRoot = "Browser preview sandbox";
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

    const delay = (value, ms = 120) => new Promise((resolve) => window.setTimeout(() => resolve(value), ms));
    const makeArtifact = (name = "readme.txt") => ({
      id: `preview-${Date.now()}`,
      path: `preview://ctf2/${name}`,
      name,
      family: "text",
      familyLabel: "文本",
      badge: "TXT",
      sizeLabel: "1.0 KB",
      sourceKind: "input",
    });

    window.ctfCompass = {
      pickFiles: () => delay([makeArtifact()]),
      pickFolder: () => delay([makeArtifact()]),
      prepareArtifacts: (paths) => delay((paths || []).map((path) => makeArtifact(String(path).split(/[\\/]/).pop()))),
      analyzeChallenge: (payload = {}) =>
        delay({
          challenge: { title: payload.title || "Browser Preview", description: payload.description || "", notes: payload.notes || "", tags: payload.tags || [] },
          classification: { primary: "misc", label: "杂项", confidence: 0.5, reason: "浏览器预览。", evidence: [], nextMoves: ["使用桌面版运行真实分析。"], tools: [] },
          artifacts: payload.artifacts || [],
          pipelineLog: [],
          pipelineErrors: [],
          solver: { status: "partial", title: "预览模式", summary: "浏览器预览不会运行本地工具。", candidates: [], confidence: 0.5, nextActions: [] },
          quickFindings: [],
          flagCandidates: [],
          warnings: ["当前为浏览器预览 mock。"],
          toolStatus: { installed: [], missing: [] },
          bundledTools: [],
        }),
      analyzeWebTarget: () => delay({ pages: [], findings: ["浏览器预览不会扫描真实靶机。"], flagCandidates: [], nextSteps: [] }),
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
      return { challenge, paths: ["preview://ctf2/readme.txt"], metadataPath: "preview://ctf2/ctf2-challenge.json", artifacts: [makeArtifact("readme.txt")] };
    }
  }

  function installCtf2ConnectorUi() {
    const nav = document.querySelector(".nav");
    const main = document.querySelector(".main");
    if (!nav || !main || document.getElementById("ctf2-view")) return;

    const state = { status: null, challenges: [], selected: null, busy: false, searchTimer: null };
    const navButton = document.createElement("button");
    navButton.className = "nav-item ctf2-nav-item";
    navButton.type = "button";
    navButton.dataset.view = "ctf2";
    navButton.innerHTML = `
      <span class="nav-icon" aria-hidden="true"><svg viewBox="0 0 24 24" fill="none"><path d="M5 5h14v14H5zM8 9h8M8 13h5M8 17h8" /><path d="M16 13h.01" /></svg></span>
      <span>CTF2</span>
    `;
    const webNav = nav.querySelector('[data-view="web"]');
    if (webNav) webNav.after(navButton);
    else nav.prepend(navButton);

    const view = document.createElement("section");
    view.id = "ctf2-view";
    view.className = "view ctf2-view";
    view.innerHTML = `
      <div class="ctf2-toolbar panel">
        <div>
          <p class="panel-kicker">CTF2 CONNECTOR</p>
          <h3 class="panel-title">直接浏览并导入 CTF2 题目</h3>
          <p class="body-copy">题目列表可公开浏览；附件下载使用独立登录会话，并保存到本应用沙盒。</p>
        </div>
        <div class="ctf2-account-actions">
          <span id="ctf2-account-status" class="scope-badge">检查登录状态...</span>
          <button id="ctf2-diagnose-button" class="secondary-button" type="button">诊断连接</button>
          <button id="ctf2-login-button" class="secondary-button" type="button">应用内登录</button>
          <button id="ctf2-system-login-button" class="secondary-button" type="button">浏览器登录</button>
          <button id="ctf2-logout-button" class="secondary-button danger-button" type="button">退出登录</button>
        </div>
      </div>

      <details class="panel ctf2-token-help" open>
        <summary>浏览器登录令牌</summary>
        <div class="ctf2-token-help-body">
          <p class="body-copy">应用内 Passkey 无法验证时，先点击“浏览器登录”完成验证，再从 CTF2 页面的“应用程序 / Local Storage”复制 token。也可在控制台执行 <code>localStorage.getItem("token")</code>。令牌验证通过后仅加密保存在本机。</p>
          <div class="ctf2-token-row">
            <label class="field ctf2-token-field" for="ctf2-token-input"><span>粘贴 token</span><input id="ctf2-token-input" type="password" placeholder="在这里粘贴 CTF2 token" autocomplete="off" /></label>
            <button id="ctf2-token-import-button" class="primary-button" type="button">验证并连接</button>
          </div>
          <div id="ctf2-diagnostic-list" class="stack-list compact-stack" hidden></div>
        </div>
      </details>

      <div class="ctf2-layout">
        <section class="panel ctf2-browser-panel">
          <div class="ctf2-filters">
            <label class="field ctf2-search-field"><span>搜索题目</span><input id="ctf2-search-input" type="search" placeholder="题目名、描述或编号" autocomplete="off" /></label>
            <label class="field"><span>题型</span><select id="ctf2-category-select"><option value="all">全部</option></select></label>
            <button id="ctf2-refresh-button" class="secondary-button" type="button">刷新题库</button>
          </div>
          <div class="section-label-row"><div><h3 class="section-title">BUUCTF 公开练习题</h3><p id="ctf2-result-count" class="body-copy">尚未加载。</p></div></div>
          <div id="ctf2-challenge-list" class="ctf2-challenge-list"></div>
        </section>

        <aside class="panel ctf2-detail-panel">
          <div class="panel-head compact-head"><div><p class="panel-kicker">SELECTED CHALLENGE</p><h3 id="ctf2-detail-title" class="panel-title">选择一道题目</h3></div></div>
          <div id="ctf2-detail-meta" class="ctf2-detail-meta"></div>
          <p id="ctf2-detail-description" class="body-copy">选择题目后可查看描述、附件和导入操作。</p>
          <div id="ctf2-file-list" class="stack-list compact-stack"></div>
          <button id="ctf2-import-button" class="primary-button ctf2-import-button" type="button" disabled>导入附件并自动求解</button>
          <p class="empty-copy">靶机启动和 flag 提交仍需在 CTF2 页面手动确认，连接器不会自动提交。</p>
        </aside>
      </div>
    `;
    main.append(view);

    const el = {
      account: view.querySelector("#ctf2-account-status"),
      diagnose: view.querySelector("#ctf2-diagnose-button"),
      diagnosticList: view.querySelector("#ctf2-diagnostic-list"),
      login: view.querySelector("#ctf2-login-button"),
      systemLogin: view.querySelector("#ctf2-system-login-button"),
      logout: view.querySelector("#ctf2-logout-button"),
      token: view.querySelector("#ctf2-token-input"),
      importToken: view.querySelector("#ctf2-token-import-button"),
      search: view.querySelector("#ctf2-search-input"),
      category: view.querySelector("#ctf2-category-select"),
      refresh: view.querySelector("#ctf2-refresh-button"),
      count: view.querySelector("#ctf2-result-count"),
      list: view.querySelector("#ctf2-challenge-list"),
      detailTitle: view.querySelector("#ctf2-detail-title"),
      detailMeta: view.querySelector("#ctf2-detail-meta"),
      detailDescription: view.querySelector("#ctf2-detail-description"),
      fileList: view.querySelector("#ctf2-file-list"),
      importChallenge: view.querySelector("#ctf2-import-button"),
    };

    navButton.addEventListener("click", activateCtf2View);
    document.addEventListener("click", (event) => {
      const item = event.target.closest?.(".nav-item");
      if (item && item !== navButton) view.classList.remove("is-active");
    });

    function setStatus(message, kind = "info") {
      const banner = document.getElementById("status-banner");
      if (!banner) return;
      banner.textContent = message;
      banner.dataset.kind = kind;
      banner.classList.remove("is-hidden", "is-error");
      banner.classList.toggle("is-error", kind === "error");
    }

    function setBusy(busy) {
      state.busy = busy;
      [el.login, el.systemLogin, el.logout, el.importToken, el.refresh, el.importChallenge, el.diagnose].forEach((button) => {
        if (!button) return;
        button.disabled = busy || (button === el.logout && !state.status?.connected) || (button === el.importChallenge && !state.selected?.files?.length);
      });
    }

    function activateCtf2View() {
      document.querySelectorAll(".nav-item").forEach((item) => item.classList.toggle("active", item === navButton));
      document.querySelectorAll(".view").forEach((node) => node.classList.toggle("is-active", node === view));
      document.body.dataset.view = "ctf2";
      const kicker = document.getElementById("view-kicker");
      const title = document.getElementById("view-title");
      if (kicker) kicker.textContent = "CTF2 题库";
      if (title) title.textContent = "CTF2 题库连接器";
      if (!state.challenges.length) {
        refreshStatus().catch(() => {});
        loadChallenges(false).catch(() => {});
      }
    }

    function renderStatus() {
      const connected = Boolean(state.status?.connected);
      el.account.textContent = connected
        ? `已登录${state.status?.profile?.username ? ` · ${state.status.profile.username}` : ""}`
        : "未登录 · 可浏览题库";
      setBusy(false);
    }

    function renderCategories(categories) {
      const current = el.category.value || "all";
      el.category.innerHTML = '<option value="all">全部</option>';
      (categories || []).forEach((category) => {
        const option = document.createElement("option");
        option.value = category;
        option.textContent = category;
        el.category.append(option);
      });
      el.category.value = Array.from(el.category.options).some((option) => option.value === current) ? current : "all";
    }

    function renderList(total) {
      el.count.textContent = `当前显示 ${state.challenges.length} 道题${Number.isFinite(total) ? ` / 匹配 ${total}` : ""}`;
      el.list.innerHTML = "";
      if (!state.challenges.length) {
        const empty = document.createElement("p");
        empty.className = "empty-copy";
        empty.textContent = "没有匹配题目，调整搜索或刷新题库。";
        el.list.append(empty);
        renderDetail();
        return;
      }
      state.challenges.forEach((challenge) => {
        const item = document.createElement("button");
        item.type = "button";
        item.className = `ctf2-challenge-item${state.selected?.id === challenge.id ? " is-selected" : ""}`;
        item.innerHTML = `<div class="ctf2-challenge-copy"><strong>${escapeHtml(challenge.name)}</strong><small>${escapeHtml([challenge.category, challenge.difficulty].filter(Boolean).join(" · ") || "CTF2")}</small></div><span class="ctf2-challenge-stats">${challenge.files?.length ? `${challenge.files.length} 附件` : "无附件"}<br />${challenge.solveCount || 0} solves</span>`;
        item.addEventListener("click", () => {
          state.selected = challenge;
          renderList(total);
          renderDetail();
        });
        el.list.append(item);
      });
      renderDetail();
    }

    function renderDetail() {
      const selected = state.selected;
      el.detailTitle.textContent = selected?.name || "选择一道题目";
      el.detailDescription.textContent = selected?.description || "选择题目后可查看描述、附件和导入操作。";
      el.detailMeta.innerHTML = "";
      if (selected) {
        [selected.category, selected.difficulty, selected.points ? `${selected.points} 分` : "", selected.solveCount ? `${selected.solveCount} solves` : ""]
          .filter(Boolean)
          .forEach((label) => {
            const tag = document.createElement("span");
            tag.textContent = label;
            el.detailMeta.append(tag);
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
      setBusy(state.busy);
    }

    async function refreshStatus() {
      try {
        state.status = await window.ctfCompass.getCtf2Status?.();
      } catch (error) {
        state.status = { connected: false, error: error.message };
      }
      renderStatus();
    }

    function renderDiagnostic(rows) {
      el.diagnosticList.hidden = false;
      el.diagnosticList.innerHTML = "";
      rows.forEach((row) => {
        const item = document.createElement("div");
        item.className = "stack-item";
        item.innerHTML = `<strong>${escapeHtml(row.title)}</strong><p>${escapeHtml(row.note)}</p>`;
        el.diagnosticList.append(item);
      });
    }

    async function diagnoseConnection() {
      setBusy(true);
      const rows = [];
      try {
        const status = await window.ctfCompass.getCtf2Status?.();
        state.status = status;
        rows.push({
          title: status?.connected ? "登录状态正常" : "未登录或 token 已失效",
          note: status?.connected
            ? `已识别账号${status.profile?.username ? `：${status.profile.username}` : ""}`
            : status?.error || "题库可公开浏览；下载附件需要应用内登录或浏览器 token。",
        });
        renderStatus();
      } catch (error) {
        rows.push({ title: "登录状态检查失败", note: error.message });
      }

      try {
        const result = await window.ctfCompass.listCtf2Challenges?.({ force: true, limit: 20 });
        rows.push({ title: "公开题库接口正常", note: `成功读取题库，当前匹配 ${result?.total ?? result?.challenges?.length ?? 0} 道。` });
      } catch (error) {
        rows.push({ title: "公开题库接口失败", note: error.message });
      }

      try {
        const sandbox = await window.ctfCompass.getSandboxInfo?.();
        rows.push({ title: "本地沙盒正常", note: sandbox?.downloads ? `下载目录：${sandbox.downloads}` : "沙盒目录可访问。" });
      } catch (error) {
        rows.push({ title: "本地沙盒检查失败", note: error.message });
      }

      renderDiagnostic(rows);
      setBusy(false);
      setStatus("CTF2 连接诊断已完成。若题库正常但下载失败，重点检查 token 是否过期。 ");
    }

    async function loadChallenges(force = false) {
      if (!window.ctfCompass.listCtf2Challenges) {
        el.count.textContent = "当前构建没有接入 CTF2 题库接口。";
        return;
      }
      setBusy(true);
      try {
        const result = await window.ctfCompass.listCtf2Challenges({ query: el.search.value.trim(), category: el.category.value, force, limit: 160 });
        state.challenges = result.challenges || [];
        if (!state.challenges.some((item) => item.id === state.selected?.id)) state.selected = state.challenges[0] || null;
        renderCategories(result.categories || []);
        renderList(Number(result.total));
        setStatus(`已加载 CTF2 题目，共匹配 ${result.total || state.challenges.length} 道。`);
      } catch (error) {
        setStatus(`CTF2 题库加载失败：${error.message}`, "error");
        await refreshStatus().catch(() => {});
      } finally {
        setBusy(false);
      }
    }

    async function importToken() {
      const token = el.token.value.trim();
      if (!token) {
        setStatus("请先粘贴 CTF2 token。", "error");
        el.token.focus();
        return;
      }
      setBusy(true);
      try {
        state.status = await window.ctfCompass.importCtf2Token(token);
        el.token.value = "";
        renderStatus();
        setStatus("CTF2 登录令牌已验证并加密保存在本机。");
        await loadChallenges(true);
      } catch (error) {
        setStatus(`CTF2 token 验证失败：${error.message}`, "error");
      } finally {
        setBusy(false);
      }
    }

    async function importChallenge() {
      if (!state.selected || !window.ctfCompass.importCtf2Challenge) return;
      setBusy(true);
      try {
        setStatus(`正在下载并导入：${state.selected.name}`);
        const imported = await window.ctfCompass.importCtf2Challenge({ challengeId: state.selected.id, groundId: state.selected.groundId });
        const challenge = imported.challenge || state.selected;
        setValue("title-input", challenge.name || "");
        setValue("tags-input", [challenge.category, "CTF2", challenge.groundName || "BUUCTF"].filter(Boolean).join(" "));
        setValue("description-input", challenge.description || "");
        setValue("notes-input", `CTF2 导入：${challenge.groundName || "BUUCTF"}\n附件已下载到沙盒。`);
        if (typeof window.appendPreparedArtifacts === "function") {
          await window.appendPreparedArtifacts(Promise.resolve(imported.artifacts || []));
        } else {
          renderImportedArtifacts(imported.artifacts || []);
        }
        activateWorkspaceView();
        if (typeof window.runAnalysis === "function" && (imported.artifacts || []).length) {
          window.setTimeout(() => window.runAnalysis(false, "CTF2 附件已导入并完成自动求解。"), 0);
          setStatus("附件已从 CTF2 下载到沙盒，正在自动求解。 ");
        } else {
          setStatus("附件已从 CTF2 下载到沙盒，并写入当前工作台。可继续运行自动求解。 ");
        }
      } catch (error) {
        setStatus(`CTF2 导入失败：${error.message}`, "error");
        await refreshStatus().catch(() => {});
      } finally {
        setBusy(false);
      }
    }

    function setValue(id, value) {
      const node = document.getElementById(id);
      if (node) {
        node.value = value;
        node.dispatchEvent(new Event("input", { bubbles: true }));
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
        row.innerHTML = `<div class="artifact-meta"><span class="artifact-badge">${escapeHtml(artifact.badge || "CTF2")}</span><div class="artifact-text"><strong>${escapeHtml(artifact.name || "attachment")}</strong><p>${escapeHtml([artifact.familyLabel, artifact.sizeLabel].filter(Boolean).join("  |  "))}</p></div></div>`;
        list.append(row);
      });
      if (count) count.textContent = String(artifacts.length);
    }

    function activateWorkspaceView() {
      document.querySelectorAll(".nav-item").forEach((item) => item.classList.toggle("active", item.dataset.view === "workspace"));
      document.querySelectorAll(".view").forEach((node) => node.classList.toggle("is-active", node.id === "workspace-view"));
      document.body.dataset.view = "workspace";
      const kicker = document.getElementById("view-kicker");
      const title = document.getElementById("view-title");
      if (kicker) kicker.textContent = "工作台";
      if (title) title.textContent = "以附件为中心的 CTF 工作台";
    }

    el.diagnose.addEventListener("click", diagnoseConnection);
    el.login.addEventListener("click", async () => {
      setBusy(true);
      try {
        await window.ctfCompass.openCtf2Login?.();
        setStatus("已打开 CTF2 应用内登录窗口；如果 Passkey 无法验证，请改用浏览器登录和令牌导入。");
      } catch (error) {
        setStatus(`打开 CTF2 登录失败：${error.message}`, "error");
      } finally {
        setBusy(false);
        window.setTimeout(() => refreshStatus().catch(() => {}), 800);
      }
    });
    el.systemLogin.addEventListener("click", async () => {
      try {
        await window.ctfCompass.openCtf2SystemLogin?.();
        setStatus("已在系统浏览器打开 CTF2。完成登录后，可导入浏览器中的 token。 ");
      } catch (error) {
        setStatus(`打开浏览器登录失败：${error.message}`, "error");
      }
    });
    el.logout.addEventListener("click", async () => {
      setBusy(true);
      try {
        state.status = await window.ctfCompass.logoutCtf2?.();
        renderStatus();
        setStatus("已清除 CTF2 独立登录会话。 ");
      } catch (error) {
        setStatus(`退出 CTF2 失败：${error.message}`, "error");
      } finally {
        setBusy(false);
      }
    });
    el.importToken.addEventListener("click", importToken);
    el.token.addEventListener("keydown", (event) => {
      if (event.key === "Enter" && !el.importToken.disabled) {
        event.preventDefault();
        importToken();
      }
    });
    el.refresh.addEventListener("click", () => loadChallenges(true));
    el.importChallenge.addEventListener("click", importChallenge);
    el.search.addEventListener("input", () => {
      window.clearTimeout(state.searchTimer);
      state.searchTimer = window.setTimeout(() => loadChallenges(false), 280);
    });
    el.category.addEventListener("change", () => loadChallenges(false));

    refreshStatus().catch(() => {});
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
