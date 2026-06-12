(function () {
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
        version: "0.5.4",
        packaged: false,
        mode: "browser-preview",
        sandboxRoot,
      }),
  };
})();
