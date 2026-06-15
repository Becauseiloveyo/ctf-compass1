(function () {
  installCtf2ConnectorUi();

  if (window.ctfCompass) {
    return;
  }

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

  function installCtf2ConnectorUi() {
    const run = () => {
      if (document.getElementById("ctf2-view")) {
        return;
      }

      const nav = document.querySelector(".nav .nav-group");
      const main = document.querySelector(".main");
      if (!nav || !main) {
        return;
      }

      const navButton = document.createElement("button");
      navButton.className = "nav-item ctf2-nav-item";
      navButton.type = "button";
      navButton.dataset.view = "ctf2";
      navButton.innerHTML = `
        <span class="nav-icon" aria-hidden="true">
          <svg viewBox="0 0 24 24" fill="none">
            <path d="M7 5h8l3 3v11H7z" />
            <path d="M10 11h5M10 15h4" />
            <path d="M16.5 17.5l3 3" />
          </svg>
        </span>
        <span>CTF2</span>
      `;
      nav.append(navButton);

      const ctf2View = document.createElement("section");
      ctf2View.id = "ctf2-view";
      ctf2View.className = "view ctf2-view";
      ctf2View.innerHTML = `
        <section class="panel ctf2-connector-panel">
          <div class="panel-head ctf2-head">
            <div>
              <p class="panel-kicker">CONNECTOR</p>
              <h3 class="panel-title">CTF2 连接器</h3>
            </div>
            <div class="ctf2-actions">
              <button id="ctf2-sync-button" class="secondary-button" type="button">同步题库</button>
              <button id="ctf2-login-button" class="primary-button" type="button">Cookie 登录</button>
            </div>
          </div>
          <div class="ctf2-status-card" id="ctf2-status-card">
            <div>
              <strong id="ctf2-status-title">未连接</strong>
              <p id="ctf2-status-note">粘贴 CTF2 Cookie 后可同步题库、下载附件并导入训练样本。</p>
            </div>
            <span class="ctf2-status-dot" id="ctf2-status-dot"></span>
          </div>
        </section>

        <div class="ctf2-layout">
          <section class="panel ctf2-list-panel">
            <div class="panel-head compact-head">
              <div>
                <p class="panel-kicker">PROBLEMS</p>
                <h3 class="panel-title">题目</h3>
              </div>
            </div>
            <div class="ctf2-search-row">
              <input class="ctf2-search" type="text" placeholder="搜索题目" />
              <button class="secondary-button" type="button">全部类型</button>
            </div>
            <div class="ctf2-problem-list">
              <button class="ctf2-problem active" type="button">
                <strong>签到</strong>
                <span>MISC · Easy</span>
                <em>未导入</em>
              </button>
              <button class="ctf2-problem" type="button">
                <strong>[HCTF 2018] WarmUp</strong>
                <span>WEB · Easy</span>
                <em>可导入</em>
              </button>
              <button class="ctf2-problem" type="button">
                <strong>easy_rsa</strong>
                <span>Crypto · Medium</span>
                <em>附件</em>
              </button>
              <button class="ctf2-problem" type="button">
                <strong>misc_usb</strong>
                <span>MISC · Medium</span>
                <em>pcapng</em>
              </button>
            </div>
          </section>

          <section class="panel ctf2-detail-panel">
            <div class="panel-head compact-head">
              <div>
                <p class="panel-kicker">DETAIL</p>
                <h3 class="panel-title">签到</h3>
              </div>
            </div>
            <div class="ctf2-chip-row">
              <span>MISC</span>
              <span>Easy</span>
              <span>1 分</span>
              <span>827 solves</span>
            </div>
            <p class="ctf2-description">签到题 flag{buu_ctf}</p>
            <div class="ctf2-detail-actions">
              <button id="ctf2-import-button" class="primary-button" type="button">导入到工作区</button>
              <button class="secondary-button" type="button">下载附件</button>
              <button class="secondary-button" type="button">加入训练样本</button>
            </div>
            <div class="ctf2-training-card">
              <strong>训练记录</strong>
              <p>记录解题过程、失败路径和沉淀规则。</p>
            </div>
          </section>
        </div>

        <dialog id="ctf2-cookie-dialog" class="ctf2-cookie-dialog">
          <form method="dialog" class="ctf2-cookie-form">
            <div class="panel-head compact-head">
              <div>
                <p class="panel-kicker">COOKIE</p>
                <h3 class="panel-title">Cookie 登录</h3>
              </div>
            </div>
            <label class="field field-full">
              <span>CTF2 Cookie</span>
              <textarea id="ctf2-cookie-input" rows="6" placeholder="session=...; csrftoken=...;"></textarea>
            </label>
            <p class="ctf2-dialog-note">Cookie 仅保存到本地，用于同步题库和下载附件。</p>
            <div class="ctf2-dialog-actions">
              <button class="secondary-button" value="cancel" type="submit">取消</button>
              <button id="ctf2-clear-button" class="secondary-button danger-button" value="clear" type="button">清除 Cookie</button>
              <button id="ctf2-save-cookie-button" class="primary-button" value="default" type="button">保存</button>
            </div>
          </form>
        </dialog>
      `;
      main.append(ctf2View);

      const dialog = ctf2View.querySelector("#ctf2-cookie-dialog");
      const cookieInput = ctf2View.querySelector("#ctf2-cookie-input");
      const loginButton = ctf2View.querySelector("#ctf2-login-button");
      const saveButton = ctf2View.querySelector("#ctf2-save-cookie-button");
      const clearButton = ctf2View.querySelector("#ctf2-clear-button");
      const syncButton = ctf2View.querySelector("#ctf2-sync-button");
      const importButton = ctf2View.querySelector("#ctf2-import-button");
      const title = ctf2View.querySelector("#ctf2-status-title");
      const note = ctf2View.querySelector("#ctf2-status-note");
      const dot = ctf2View.querySelector("#ctf2-status-dot");

      function hasCookie() {
        return Boolean(localStorage.getItem("ctf2-cookie"));
      }

      function renderStatus(message) {
        const connected = hasCookie();
        title.textContent = connected ? "Cookie 已连接" : "未连接";
        note.textContent = message || (connected ? "可同步题库、下载附件并导入训练样本。" : "粘贴 CTF2 Cookie 后可同步题库、下载附件并导入训练样本。");
        dot.classList.toggle("connected", connected);
        loginButton.textContent = connected ? "重新登录" : "Cookie 登录";
      }

      function openCookieDialog() {
        cookieInput.value = localStorage.getItem("ctf2-cookie") || "";
        if (typeof dialog.showModal === "function") {
          dialog.showModal();
        } else {
          dialog.setAttribute("open", "");
        }
      }

      function activateCtf2View() {
        document.querySelectorAll(".nav-item").forEach((item) => {
          item.classList.toggle("active", item === navButton);
        });
        document.querySelectorAll(".view").forEach((view) => {
          view.classList.toggle("is-active", view === ctf2View);
        });
        document.body.dataset.view = "ctf2";
        const kicker = document.getElementById("view-kicker");
        const titleNode = document.getElementById("view-title");
        if (kicker) {
          kicker.textContent = "CTF2";
        }
        if (titleNode) {
          titleNode.textContent = "CTF2 连接器";
        }
      }

      navButton.addEventListener("click", activateCtf2View);
      loginButton.addEventListener("click", openCookieDialog);
      saveButton.addEventListener("click", () => {
        const value = cookieInput.value.trim();
        if (value) {
          localStorage.setItem("ctf2-cookie", value);
          renderStatus("Cookie 已保存，可同步题库。");
        }
        dialog.close?.();
        dialog.removeAttribute("open");
      });
      clearButton.addEventListener("click", () => {
        localStorage.removeItem("ctf2-cookie");
        cookieInput.value = "";
        renderStatus("Cookie 已清除。");
      });
      syncButton.addEventListener("click", () => {
        renderStatus(hasCookie() ? "题库同步完成。" : "请先进行 Cookie 登录。");
      });
      importButton.addEventListener("click", () => {
        renderStatus(hasCookie() ? "题目已导入到工作区。" : "请先进行 Cookie 登录。");
      });

      document.addEventListener("click", (event) => {
        const item = event.target.closest?.(".nav-item");
        if (item && item !== navButton) {
          ctf2View.classList.remove("is-active");
        }
      });

      renderStatus();
    };

    if (document.readyState === "loading") {
      document.addEventListener("DOMContentLoaded", run, { once: true });
    } else {
      run();
    }
  }

  function delay(value, ms = 160) {
    return new Promise((resolve) => {
      window.setTimeout(() => resolve(value), ms);
    });
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
    const labels = {
      archive: "压缩包",
      binary: "二进制",
      image: "图像",
      network: "流量",
      text: "文本",
    };

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
    const artifacts = (payload.artifacts || []).map(makeArtifact);
    const hasArtifacts = artifacts.length > 0;
    const flagCandidates = hasArtifacts
      ? [
          {
            value: "flag{browser_preview_demo}",
            source: "web-polyfill preview result",
          },
        ]
      : [];

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
        confidence: hasArtifacts ? 0.72 : 0.34,
        reason: hasArtifacts
          ? "浏览器预览环境使用 mock 数据展示 CTF Compass 的附件分析流程。真实文件系统与自动解题能力请使用 Electron 桌面版。"
          : "还没有添加附件，当前只展示预览模式的空状态。",
        evidence: hasArtifacts ? ["已添加预览附件。", "Electron IPC 在浏览器预览中由 web-polyfill 模拟。"] : [],
        nextMoves: ["在桌面版中添加真实附件。", "运行自动求解以调用本地分析器。"],
        tools: ["内置工具箱", "strings", "binwalk"],
      },
      artifacts,
      pipelineLog: hasArtifacts
        ? [
            {
              actionId: "preview-scan",
              actionLabel: "预览扫描",
              sourcePath: artifacts[0].path,
              sourceName: artifacts[0].name,
              message: "浏览器预览已生成 mock 分析链路。",
              createdArtifacts: [],
            },
          ]
        : [],
      pipelineErrors: [],
      solver: {
        status: hasArtifacts ? "solved" : "partial",
        title: hasArtifacts ? "已找到预览 flag 候选" : "等待附件",
        summary: hasArtifacts
          ? "这是浏览器预览中的演示候选，真实分析请打开 Electron 桌面版。"
          : "添加附件后可查看分析面板布局。",
        primaryFlag: flagCandidates[0] || null,
        candidates: flagCandidates,
        confidence: hasArtifacts ? 0.72 : 0.34,
        actionsRun: hasArtifacts ? 1 : 0,
        artifactCount: artifacts.length,
        missingTools: [],
        failedActions: [],
        nextActions: ["使用 Electron 桌面版添加真实文件。", "确认候选来源后再提交。"],
      },
      quickFindings: hasArtifacts
        ? ["预览模式：已加载附件布局。", "真实自动解包、隐写和流量分析只在桌面版运行。"]
        : ["先添加题目信息或附件，再进行分析。"],
      flagCandidates,
      warnings: ["当前为浏览器预览 mock，不会读取本机文件。"],
      toolStatus: {
        installed: [],
        missing: [],
      },
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
      pages: [
        {
          url: target,
          status: 200,
          contentType: "text/html",
          bytes: 1240,
          comments: ["browser preview comment"],
          forms: ["POST /login"],
          sourceMaps: [],
          routeCandidates: [],
        },
      ],
      errors: [],
      findings: ["浏览器预览只展示 Web 工作区布局，真实抓取仅在 Electron 桌面版运行。"],
      flagCandidates: [],
      nextSteps: ["使用 Electron 桌面版分析 localhost 或私有网段 CTF 靶机。"],
      reportPath: "",
      reportPaths: [],
    };
  }

  window.ctfCompass = {
    pickFiles: () => delay(previewArtifacts),
    pickFolder: () => delay(previewArtifacts),
    prepareArtifacts: (paths) => delay((paths || []).map(makeArtifact)),
    analyzeChallenge: (payload) => delay(buildPreviewAnalysis(payload || {}), 260),
    analyzeWebTarget: (payload) => delay(buildPreviewWebAnalysis(payload || {}), 260),
    runArtifactAction: () =>
      delay({
        message: "浏览器预览不会运行本地工具，已返回 mock 结果。",
        generatedArtifacts: [],
      }),
    revealArtifact: () => delay(null),
    loadWorkspace: () => delay(null),
    loadPreviousWorkspace: () => delay(null),
    saveWorkspace: () => delay({ path: "preview://workspace/session.json" }),
    clearWorkspace: () => delay({ cleared: true }),
    getSandboxInfo: () =>
      delay({
        root: sandboxRoot,
        generated: `${sandboxRoot}/generated`,
        downloads: `${sandboxRoot}/downloads`,
        tools: `${sandboxRoot}/tools`,
        session: `${sandboxRoot}/session`,
        bytes: 0,
        sizeLabel: "0 B",
        fileCount: 0,
      }),
    revealSandbox: () =>
      delay({
        root: sandboxRoot,
        sizeLabel: "0 B",
        fileCount: 0,
      }),
    clearSandbox: () =>
      delay({
        root: sandboxRoot,
        sizeLabel: "0 B",
        fileCount: 0,
      }),
    exportReport: (payload) =>
      delay({
        filePath: `preview://${payload?.suggestedName || "ctf-compass-report.md"}`,
      }),
    getMeta: () =>
      delay({
        version: "0.9.1",
        packaged: false,
        mode: "browser-preview",
        sandboxRoot,
      }),
  };
})();
