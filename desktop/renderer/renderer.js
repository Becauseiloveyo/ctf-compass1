const STRINGS = {
  brandCaption: "\u6311\u6218\u5de5\u4f5c\u53f0",
  navWorkspace: "\u5de5\u4f5c\u53f0",
  navArtifacts: "\u9644\u4ef6",
  navResults: "\u7ed3\u679c",
  navSettings: "\u8bbe\u7f6e",
  themeTitle: "\u4e3b\u9898",
  themeNote: "\u6d45\u8272\u4f18\u5148\uff0c\u4e5f\u53ef\u5207\u6362\u6697\u9ed1",
  runtimeTitle: "\u5f53\u524d\u73af\u5883",
  exportReportButton: "\u5bfc\u51fa\u62a5\u544a",
  addFilesButton: "\u6dfb\u52a0\u6587\u4ef6",
  addFolderButton: "\u6dfb\u52a0\u6587\u4ef6\u5939",
  runAnalysisButton: "自动求解",
  runDisabledHint: "\u5148\u6dfb\u52a0\u9644\u4ef6\u6216\u586b\u5199\u9898\u9762\uff0c\u518d\u5f00\u59cb\u5206\u6790\u3002",
  quickFilesTitle: "\u6dfb\u52a0\u6587\u4ef6",
  quickFilesNote: "\u56fe\u50cf\u3001txt\u3001zip\u3001ELF\u3001pcap \u90fd\u53ef\u4ee5\u76f4\u63a5\u62d6\u8fdb\u6765",
  quickFolderTitle: "\u626b\u63cf\u76ee\u5f55",
  quickFolderNote: "\u9002\u5408\u6709\u591a\u4e2a\u9644\u4ef6\u6216\u5bfc\u51fa\u6587\u4ef6\u7684\u9898\u76ee",
  quickPasteTitle: "\u8865\u5145\u7ebf\u7d22",
  quickPasteNote: "\u628a\u9898\u9762\u3001hint\u3001\u5df2\u6709\u53d1\u73b0\u7c98\u8d34\u8fdb\u6765",
  quickRunTitle: "自动求解",
  quickRunNote: "递归提取、解码、扫描附件，并直接寻找 flag 候选",
  workspacePanelKicker: "\u9898\u76ee\u5de5\u4f5c\u53f0",
  workspacePanelTitle: "\u9898\u9762\u4e0e\u7ebf\u7d22",
  workspacePanelBadge: "\u79bb\u7ebf\u672c\u5730",
  fieldTitle: "\u9898\u76ee\u6807\u9898",
  fieldTags: "\u6807\u7b7e",
  fieldDescription: "\u9898\u76ee\u63cf\u8ff0",
  fieldNotes: "\u8865\u5145\u7ebf\u7d22",
  artifactPanelKicker: "\u9644\u4ef6\u8f93\u5165",
  artifactPanelTitle: "\u6587\u4ef6\u8d44\u4ea7",
  dropzoneTitle: "\u62d6\u62fd\u6587\u4ef6\u6216\u70b9\u51fb\u6dfb\u52a0",
  dropzoneNote: "\u56fe\u7247\u3001\u6587\u672c\u3001\u538b\u7f29\u5305\u3001ELF\u3001pcap/pcapng \u4f1a\u88ab\u4f5c\u4e3a\u4e00\u7b49\u8f93\u5165",
  discoveryKicker: "\u81ea\u52a8\u53d1\u73b0",
  discoveryTitle: "\u5f53\u524d\u7ebf\u7d22",
  summaryKicker: "求解摘要",
  solverWaitingTitle: "等待自动求解",
  solverWaitingNote: "添加附件后运行，应用会先用内置流水线处理；检测到可用外部工具时会自动调用。",
  solverStatusSolved: "已找到候选",
  solverStatusPartial: "继续补充",
  solverStatusBlocked: "需要介入",
  solverPrimaryFlag: "最高可信候选",
  solverNoFlag: "暂未命中 flag",
  solverRunMeta: "自动动作",
  solverArtifactMeta: "扫描文件",
  solverMissingTools: "可选增强",
  solverFailedActions: "失败动作",
  bundledToolTitle: "内置自动能力",
  bundledToolNote: "这些能力已随应用打包，分析时自动调用，不需要额外安装。",
  failureGuideTitle: "失败任务指南",
  failureEmpty: "没有失败的自动任务。",
  pipelineCreatedLabel: "生成文件",
  workbenchKicker: "\u4e13\u9898\u9762\u677f",
  workbenchTitle: "\u6309\u9644\u4ef6\u65cf\u7fa4\u62c6\u5f00\u7684\u5de5\u4f5c\u53f0",
  pipelineKicker: "\u81ea\u52a8\u5904\u7406",
  pipelineTitle: "\u672c\u5730\u9012\u5f52\u94fe\u8def",
  workbenchQueueTitle: "\u4f18\u5148\u5904\u7406",
  workbenchSignalsTitle: "\u5173\u952e\u4fe1\u53f7",
  workbenchActionsTitle: "\u53ef\u7ee7\u7eed\u6267\u884c",
  workbenchDerivedTitle: "\u81ea\u52a8\u751f\u6210",
  workbenchNoArtifacts: "\u8fd9\u4e00\u7c7b\u76ee\u524d\u6ca1\u6709\u53ef\u7528\u9644\u4ef6\u3002",
  workbenchNoPipeline: "\u8fd8\u6ca1\u6709\u9488\u5bf9\u8fd9\u4e00\u7c7b\u7684\u81ea\u52a8\u94fe\u8def\u3002",
  actionMore: "\u66f4\u591a\u64cd\u4f5c",
  workbenchMetricArtifacts: "\u9644\u4ef6",
  workbenchMetricGenerated: "\u751f\u6210",
  workbenchMetricFlags: "\u5019\u9009",
  familyImage: "\u56fe\u50cf",
  familyAudio: "\u97f3\u9891",
  familyNetwork: "\u6d41\u91cf",
  familyBinary: "\u4e8c\u8fdb\u5236",
  confidenceLabel: "\u7f6e\u4fe1",
  flagKicker: "FLAG",
  flagTitle: "\u5019\u9009\u503c",
  nextKicker: "\u5206\u6790\u8def\u5f84",
  nextTitle: "\u4e0b\u4e00\u6b65",
  findingKicker: "\u9644\u4ef6\u53d1\u73b0",
  findingTitle: "\u91cd\u70b9\u68c0\u67e5\u9879",
  toolKicker: "\u5de5\u5177\u94fe",
  toolTitle: "\u914d\u5408\u4f7f\u7528",
  toolInstalled: "\u5df2\u63a5\u5165",
  toolMissing: "\u672a\u5b89\u88c5",
  toolSuggestedTitle: "\u9898\u578b\u5efa\u8bae",
  toolInstalledTitle: "\u672c\u673a\u53ef\u76f4\u63a5\u8fd0\u884c",
  toolMissingTitle: "可选增强工具",
  toolEmptyInstalled: "\u672a\u68c0\u6d4b\u5230\u53ef\u76f4\u63a5\u8fd0\u884c\u7684\u5916\u90e8\u5de5\u5177\u3002",
  toolMissingNote: "不安装也会使用内置工具箱；安装后只会增加更深的专项扫描。",
  settingsKicker: "\u8fd0\u884c\u7b56\u7565",
  settingsTitle: "\u9879\u76ee\u57fa\u7ebf",
  settingsThemeTitle: "\u754c\u9762\u98ce\u683c",
  settingsThemeNote: "\u9ed8\u8ba4\u767d\u8272\u6781\u7b80\u5e03\u5c40\uff0c\u652f\u6301\u6697\u9ed1\u6a21\u5f0f",
  settingsThemeButton: "\u5207\u6362\u4e3b\u9898",
  settingsRuntimeTitle: "\u6253\u5305\u73af\u5883",
  settingsOfflineTitle: "\u79bb\u7ebf\u5206\u53d1",
  settingsOfflineNote: "\u65b0\u7248\u903b\u8f91\u4e0d\u518d\u4f9d\u8d56\u5916\u90e8 Python\uff0c\u6253\u5305\u540e\u53ef\u76f4\u63a5\u8fd0\u884c",
  settingsCaseSummaryTitle: "\u7ed3\u6848\u5907\u6ce8",
  settingsCaseSummaryNote: "\u8bb0\u4e0b\u4f60\u5df2\u786e\u8ba4\u7684 flag\uff0c\u89e3\u9898\u8def\u5f84\u548c\u63d0\u4ea4\u65f6\u9700\u8981\u7684\u8bf4\u660e\u3002",
  settingsAutoSaveTitle: "\u65b0\u4f1a\u8bdd\u542f\u52a8",
  settingsAutoSaveNote: "\u6bcf\u6b21\u6253\u5f00\u90fd\u4ece\u7a7a\u767d\u5de5\u4f5c\u53f0\u5f00\u59cb\uff1b\u4e0a\u4e00\u8f6e\u9644\u4ef6\u3001\u9898\u9762\u548c\u751f\u6210\u7269\u4e0d\u4f1a\u81ea\u52a8\u6062\u590d\u3002",
  settingsSandboxTitle: "\u6c99\u76d2\u7a7a\u95f4",
  settingsSandboxNote: "\u81ea\u52a8\u751f\u6210\u6587\u4ef6\u3001\u4e34\u65f6\u4f1a\u8bdd\u548c\u672a\u6765\u7684\u4fbf\u643a\u5de5\u5177\u4e0b\u8f7d\u90fd\u6536\u5728\u8fd9\u4e2a\u76ee\u5f55\uff0c\u5220\u6389\u5b83\u5c31\u80fd\u4e00\u8d77\u6e05\u7a7a\u3002",
  settingsSandboxPath: "\u8def\u5f84",
  settingsSandboxSize: "\u5f53\u524d\u5360\u7528",
  openSandboxButton: "\u6253\u5f00\u6c99\u76d2\u76ee\u5f55",
  clearSandboxButton: "\u6e05\u7406\u6c99\u76d2",
  settingsWorkspaceTitle: "\u5de5\u4f5c\u533a\u7ba1\u7406",
  settingsWorkspaceNote: "\u53ef\u4ee5\u5bfc\u51fa Markdown \u62a5\u544a\uff0c\u6216\u76f4\u63a5\u6e05\u7a7a\u5f53\u524d\u8c03\u67e5\u7ebf\u7d22\u3002",
  clearWorkspaceButton: "\u6e05\u7a7a\u5de5\u4f5c\u533a",
  emptyArtifactPreview: "\u8fd8\u6ca1\u6709\u6dfb\u52a0\u9644\u4ef6\u3002",
  emptyArtifactDetail: "\u6ca1\u6709\u53ef\u5c55\u793a\u7684\u9644\u4ef6\uff0c\u5148\u6dfb\u52a0\u6587\u4ef6\u6216\u6587\u4ef6\u5939\u3002",
  emptyResultsCategory: "\u7b49\u5f85\u5206\u6790",
  emptyResultsSummary: "运行后会显示自动动作、候选 flag 和仍需人工补充的信息。",
  emptyFlags: "\u6682\u65e0 flag \u5019\u9009\u3002",
  emptyPipeline: "还没有执行自动动作。",
  statusReady: "\u5148\u6dfb\u52a0\u9898\u76ee\u4fe1\u606f\u6216\u9644\u4ef6\uff0c\u518d\u8fdb\u884c\u5206\u6790\u3002",
  statusAnalyzing: "正在自动求解附件和题目线索...",
  statusDone: "已完成本地自动求解与候选提取。",
  statusArtifactAdded: "\u9644\u4ef6\u5df2\u66f4\u65b0\uff0c\u53ef\u4ee5\u91cd\u65b0\u5206\u6790\u3002",
  statusFocusDescription: "\u8bf7\u76f4\u63a5\u7c98\u8d34\u9898\u9762\u3001hint \u6216\u5f53\u524d\u89c2\u5bdf\u5230\u7684\u53ef\u7591\u70b9\u3002",
  statusActionRunning: "正在执行可自动处理的线索...",
  statusActionDone: "\u5df2\u751f\u6210\u65b0\u7684\u884d\u751f\u6587\u4ef6\uff0c\u5e76\u5df2\u91cd\u65b0\u5206\u6790\u3002",
  statusWorkspaceRestored: "\u5df2\u542f\u52a8\u65b0\u4f1a\u8bdd\uff0c\u4e0a\u6b21\u9644\u4ef6\u4e0d\u4f1a\u81ea\u52a8\u6062\u590d\u3002",
  statusWorkspaceCleared: "\u5f53\u524d\u5de5\u4f5c\u533a\u5df2\u6e05\u7a7a\u3002",
  statusSandboxCleared: "\u6c99\u76d2\u5df2\u6e05\u7406\uff0c\u81ea\u52a8\u751f\u6210\u7684\u9644\u4ef6\u548c\u4e34\u65f6\u5185\u5bb9\u5df2\u79fb\u9664\u3002",
  statusReportExported: "\u5df2\u5bfc\u51fa Markdown \u62a5\u544a\uff1a",
  statusErrorPrefix: "\u5206\u6790\u5931\u8d25\uff1a",
  artifactOpen: "\u6253\u5f00\u4f4d\u7f6e",
  artifactRemove: "\u79fb\u9664",
  artifactProcess: "\u81ea\u52a8\u5904\u7406",
  flagFinalize: "\u8bbe\u4e3a\u6700\u7ec8",
  flagFinalLabel: "\u6700\u7ec8 flag",
  flagFinalEmpty: "\u8fd8\u6ca1\u6709\u6807\u8bb0\u6700\u7ec8 flag\uff0c\u53ef\u4ee5\u5148\u4ece\u5019\u9009\u5217\u8868\u91cc\u786e\u8ba4\u3002",
  flagFinalClear: "\u6e05\u7a7a\u6700\u7ec8 flag",
  evidenceStatusLabel: "\u8bc1\u636e\u72b6\u6001",
  evidenceNoteLabel: "\u5206\u6790\u7b14\u8bb0",
  evidencePinLabel: "\u6807\u4e3a\u91cd\u70b9",
  evidencePinned: "\u91cd\u70b9",
  evidenceTodo: "\u5f85\u68c0\u67e5",
  evidenceChecking: "\u68c0\u67e5\u4e2d",
  evidenceConfirmed: "\u5df2\u786e\u8ba4",
};

const VIEW_COPY = {
  workspace: {
    kicker: "\u5de5\u4f5c\u53f0",
    title: "\u4ee5\u9644\u4ef6\u4e3a\u4e2d\u5fc3\u7684 CTF \u5de5\u4f5c\u53f0",
  },
  artifacts: {
    kicker: "\u9644\u4ef6",
    title: "\u6587\u4ef6\u8d44\u4ea7\u4e0e\u5206\u7c7b\u7ed3\u679c",
  },
  results: {
    kicker: "\u7ed3\u679c",
    title: "flag \u5019\u9009\u3001\u9898\u578b\u5206\u6d41\u4e0e\u89e3\u9898\u8def\u5f84",
  },
  settings: {
    kicker: "\u8bbe\u7f6e",
    title: "\u9879\u76ee\u57fa\u7ebf\u4e0e\u6253\u5305\u7b56\u7565",
  },
};

const state = {
  activeView: "workspace",
  workbenchFamily: "binary",
  theme: localStorage.getItem("ctf-theme") || "dark",
  isBusy: false,
  artifacts: [],
  analysis: null,
  casebook: {
    finalFlag: null,
    summary: "",
    evidenceByPath: {},
  },
};

const WORKSPACE_VERSION = 1;
const EVIDENCE_STATUSES = ["todo", "checking", "confirmed"];
let persistenceReady = false;
let saveTimer = null;

const elements = {
  body: document.body,
  navItems: Array.from(document.querySelectorAll(".nav-item")),
  views: {
    workspace: document.getElementById("workspace-view"),
    artifacts: document.getElementById("artifacts-view"),
    results: document.getElementById("results-view"),
    settings: document.getElementById("settings-view"),
  },
  viewKicker: document.getElementById("view-kicker"),
  viewTitle: document.getElementById("view-title"),
  appMeta: document.getElementById("app-meta"),
  settingsRuntime: document.getElementById("settings-runtime"),
  themeToggle: document.getElementById("theme-toggle"),
  settingsThemeToggle: document.getElementById("settings-theme-toggle"),
  exportReportButton: document.getElementById("export-report-button"),
  settingsExportReportButton: document.getElementById("settings-export-report-button"),
  clearWorkspaceButton: document.getElementById("clear-workspace-button"),
  openSandboxButton: document.getElementById("open-sandbox-button"),
  clearSandboxButton: document.getElementById("clear-sandbox-button"),
  statusBanner: document.getElementById("status-banner"),
  titleInput: document.getElementById("title-input"),
  tagsInput: document.getElementById("tags-input"),
  descriptionInput: document.getElementById("description-input"),
  notesInput: document.getElementById("notes-input"),
  caseSummaryInput: document.getElementById("case-summary-input"),
  pickFilesButton: document.getElementById("pick-files-button"),
  pickFolderButton: document.getElementById("pick-folder-button"),
  runAnalysisButton: document.getElementById("run-analysis-button"),
  quickFilesButton: document.getElementById("quick-files-button"),
  quickFolderButton: document.getElementById("quick-folder-button"),
  quickPasteButton: document.getElementById("quick-paste-button"),
  quickRunButton: document.getElementById("quick-run-button"),
  artifactDropzone: document.getElementById("artifact-dropzone"),
  artifactCountPill: document.getElementById("artifact-count-pill"),
  artifactPreviewList: document.getElementById("artifact-preview-list"),
  discoveryList: document.getElementById("discovery-list"),
  artifactDetailList: document.getElementById("artifact-detail-list"),
  summaryCategory: document.getElementById("summary-category"),
  summaryConfidence: document.getElementById("summary-confidence"),
  summaryText: document.getElementById("summary-text"),
  summaryEvidence: document.getElementById("summary-evidence"),
  solverCard: document.getElementById("solver-card"),
  workbenchTabs: document.getElementById("workbench-tabs"),
  workbenchPanel: document.getElementById("workbench-panel"),
  pipelineList: document.getElementById("pipeline-list"),
  failureList: document.getElementById("failure-list"),
  flagList: document.getElementById("flag-list"),
  nextList: document.getElementById("next-list"),
  findingList: document.getElementById("finding-list"),
  toolList: document.getElementById("tool-list"),
  sandboxPath: document.getElementById("sandbox-path"),
  sandboxSize: document.getElementById("sandbox-size"),
};

function applyStaticCopy() {
  document.querySelectorAll("[data-copy]").forEach((node) => {
    node.textContent = STRINGS[node.dataset.copy] || "";
  });

  elements.titleInput.placeholder = "\u4f8b\u5982\uff1aGhost Session / hidden zip / easy traffic";
  elements.tagsInput.placeholder = "web auth cookie pcap steg reverse";
  elements.descriptionInput.placeholder =
    "\u7c98\u8d34\u9898\u9762\u6216\u9898\u76ee\u7ed9\u51fa\u7684\u76f4\u63a5\u63cf\u8ff0\uff0c\u4e0d\u7528\u8fc7\u5ea6\u7cbe\u7b80\u3002";
  elements.notesInput.placeholder =
    "\u8bb0\u4e0b\u4f60\u5df2\u7ecf\u89c2\u5bdf\u5230\u7684\u73b0\u8c61\uff0c\u4f8b\u5982\uff1aPNG \u5c3e\u90e8\u50cf\u662f\u591a\u4e86 ZIP \u5934\uff0cpcap \u91cc\u6709 cookie\u3002";
  elements.caseSummaryInput.placeholder =
    "\u4f8b\u5982\uff1a\u5df2\u786e\u8ba4 flag \u6765\u81ea zip \u5c3e\u90e8\u9644\u52a0\u6570\u636e\uff0c\u5148\u63d0\u53d6\u518d\u89e3\u5305\uff0c\u6700\u7ec8\u4ece note.txt \u83b7\u5f97\u7ed3\u679c\u3002";
}

function createEmptyCasebook() {
  return {
    finalFlag: null,
    summary: "",
    evidenceByPath: {},
  };
}

function normalizeEvidenceEntry(entry) {
  const status = EVIDENCE_STATUSES.includes(entry?.status) ? entry.status : "todo";
  return {
    status,
    note: String(entry?.note || ""),
    pinned: Boolean(entry?.pinned),
  };
}

function normalizeCasebook(input) {
  const casebook = createEmptyCasebook();
  if (!input || typeof input !== "object") {
    return casebook;
  }

  if (input.finalFlag && input.finalFlag.value) {
    casebook.finalFlag = {
      value: String(input.finalFlag.value),
      source: String(input.finalFlag.source || ""),
    };
  }

  casebook.summary = String(input.summary || "");

  if (input.evidenceByPath && typeof input.evidenceByPath === "object") {
    Object.entries(input.evidenceByPath).forEach(([key, value]) => {
      casebook.evidenceByPath[key] = normalizeEvidenceEntry(value);
    });
  }

  return casebook;
}

function getEvidenceEntry(filePath) {
  if (!state.casebook.evidenceByPath[filePath]) {
    state.casebook.evidenceByPath[filePath] = normalizeEvidenceEntry(null);
  }
  return state.casebook.evidenceByPath[filePath];
}

function evidenceStatusLabel(status) {
  if (status === "checking") {
    return STRINGS.evidenceChecking;
  }
  if (status === "confirmed") {
    return STRINGS.evidenceConfirmed;
  }
  return STRINGS.evidenceTodo;
}

function compactEvidenceByPath() {
  const result = {};
  Object.entries(state.casebook.evidenceByPath || {}).forEach(([key, value]) => {
    const entry = normalizeEvidenceEntry(value);
    if (entry.note || entry.pinned || entry.status !== "todo") {
      result[key] = entry;
    }
  });
  return result;
}

function workspaceHasContent() {
  return Boolean(
    elements.titleInput.value.trim() ||
      elements.tagsInput.value.trim() ||
      elements.descriptionInput.value.trim() ||
      elements.notesInput.value.trim() ||
      elements.caseSummaryInput.value.trim() ||
      state.artifacts.length ||
      state.casebook.finalFlag,
  );
}

function workspaceHasAnalyzableInput() {
  return Boolean(
    elements.titleInput.value.trim() ||
      elements.tagsInput.value.trim() ||
      elements.descriptionInput.value.trim() ||
      elements.notesInput.value.trim() ||
      state.artifacts.length,
  );
}

function buildWorkspaceSnapshot() {
  return {
    version: WORKSPACE_VERSION,
    theme: state.theme,
    activeView: state.activeView,
    workbenchFamily: state.workbenchFamily,
    challenge: {
      title: elements.titleInput.value.trim(),
      tags: splitTags(elements.tagsInput.value),
      description: elements.descriptionInput.value.trim(),
      notes: elements.notesInput.value.trim(),
    },
    artifacts: state.artifacts.map((item) => item.path),
    casebook: {
      finalFlag: state.casebook.finalFlag,
      summary: elements.caseSummaryInput.value.trim(),
      evidenceByPath: compactEvidenceByPath(),
    },
  };
}

async function persistWorkspaceNow() {
  if (!persistenceReady) {
    return;
  }
  await window.ctfCompass.saveWorkspace(buildWorkspaceSnapshot());
}

function scheduleWorkspaceSave() {
  if (!persistenceReady) {
    return;
  }
  window.clearTimeout(saveTimer);
  saveTimer = window.setTimeout(() => {
    persistWorkspaceNow().catch(() => {
      // ignore background persistence failures
    });
  }, 260);
}

function setStatus(message, kind = "info") {
  elements.statusBanner.textContent = message;
  elements.statusBanner.dataset.kind = kind;
  elements.statusBanner.classList.remove("is-hidden", "is-error");
  if (kind === "error") {
    elements.statusBanner.classList.add("is-error");
  }
}

function setButtonDisabled(button, disabled, title = "") {
  button.disabled = disabled;
  button.classList.toggle("is-disabled", disabled);
  button.title = title;
}

function updateActionAvailability() {
  const canAnalyze = workspaceHasAnalyzableInput() && !state.isBusy;
  const analyzeTitle = canAnalyze ? "" : STRINGS.runDisabledHint;
  setButtonDisabled(elements.runAnalysisButton, !canAnalyze, analyzeTitle);
  setButtonDisabled(elements.quickRunButton, !canAnalyze, analyzeTitle);

  const canExport = Boolean(state.analysis) && !state.isBusy;
  setButtonDisabled(elements.exportReportButton, !canExport, canExport ? "" : "\u5148\u8fd0\u884c\u4e00\u6b21\u5206\u6790\u3002");
  setButtonDisabled(elements.settingsExportReportButton, !canExport, canExport ? "" : "\u5148\u8fd0\u884c\u4e00\u6b21\u5206\u6790\u3002");

  [
    elements.pickFilesButton,
    elements.pickFolderButton,
    elements.quickFilesButton,
    elements.quickFolderButton,
    elements.artifactDropzone,
    elements.clearSandboxButton,
  ].forEach((button) => {
    setButtonDisabled(button, state.isBusy);
  });
  elements.body.classList.toggle("is-busy", state.isBusy);
}

function setBusy(isBusy) {
  state.isBusy = isBusy;
  updateActionAvailability();
}

function renderNavBadges() {
  elements.navItems.forEach((button) => {
    let badge = button.querySelector(".nav-count");
    if (!badge) {
      badge = document.createElement("span");
      badge.className = "nav-count";
      button.append(badge);
    }

    const view = button.dataset.view;
    let value = "";
    if (view === "artifacts" && state.artifacts.length) {
      value = String(state.artifacts.length);
    }
    if (view === "results" && state.analysis) {
      value = String(state.analysis.flagCandidates?.length || 0);
    }
    badge.textContent = value;
    badge.hidden = !value;
  });
}

function renderViewHeader() {
  const active = VIEW_COPY[state.activeView];
  elements.body.dataset.view = state.activeView;
  elements.viewKicker.textContent = active.kicker;
  elements.viewTitle.textContent = active.title;

  elements.navItems.forEach((button) => {
    button.classList.toggle("active", button.dataset.view === state.activeView);
  });

  Object.entries(elements.views).forEach(([view, node]) => {
    node.classList.toggle("is-active", view === state.activeView);
  });
  renderNavBadges();
}

function switchView(view) {
  state.activeView = view;
  elements.body.dataset.view = view;
  renderViewHeader();
  scheduleWorkspaceSave();
}

function setTheme(theme) {
  state.theme = theme;
  elements.body.dataset.theme = theme;
  localStorage.setItem("ctf-theme", theme);
  scheduleWorkspaceSave();
}

function toggleTheme() {
  setTheme(state.theme === "light" ? "dark" : "light");
}

function uniqArtifacts(items) {
  const map = new Map();
  items.forEach((item) => {
    map.set(item.path, item);
  });
  return Array.from(map.values());
}

function createArtifactPreviewRow(item) {
  const row = document.createElement("div");
  row.className = "artifact-row";
  row.dataset.family = item.family || "unknown";

  const meta = document.createElement("div");
  meta.className = "artifact-meta";

  const badge = document.createElement("span");
  badge.className = "artifact-badge";
  badge.textContent = item.badge;

  const textWrap = document.createElement("div");
  textWrap.className = "artifact-text";

  const title = document.createElement("strong");
  title.textContent = item.name;

  const subtitle = document.createElement("p");
  subtitle.textContent = `${item.familyLabel}  |  ${item.sizeLabel}`;

  textWrap.append(title, subtitle);
  meta.append(badge, textWrap);

  const removeButton = document.createElement("button");
  removeButton.className = "icon-button";
  removeButton.type = "button";
  removeButton.textContent = "\u2212";
  removeButton.title = STRINGS.artifactRemove;
  removeButton.addEventListener("click", () => {
    state.artifacts = state.artifacts.filter((artifact) => artifact.path !== item.path);
    renderAll();
    scheduleWorkspaceSave();
  });

  row.append(meta, removeButton);
  return row;
}

function renderArtifactPreview() {
  elements.artifactCountPill.textContent = String(state.artifacts.length);
  elements.artifactPreviewList.innerHTML = "";

  if (!state.artifacts.length) {
    const empty = document.createElement("p");
    empty.className = "empty-copy";
    empty.textContent = STRINGS.emptyArtifactPreview;
    elements.artifactPreviewList.append(empty);
    return;
  }

  sortArtifactsForDisplay(state.artifacts).forEach((item) => {
    elements.artifactPreviewList.append(createArtifactPreviewRow(item));
  });
}

function inferPreviewFindings() {
  if (!state.artifacts.length) {
    return [STRINGS.statusReady];
  }

  const familyCount = state.artifacts.reduce((accumulator, item) => {
    accumulator[item.family] = (accumulator[item.family] || 0) + 1;
    return accumulator;
  }, {});

  const findings = [`\u5df2\u52a0\u8f7d ${state.artifacts.length} \u4e2a\u9644\u4ef6\uff0c\u5206\u6790\u65f6\u4f1a\u4f18\u5148\u4ece\u9644\u4ef6\u8bc6\u522b\u9898\u578b\u3002`];

  if (familyCount.image) {
    findings.push("\u56fe\u50cf\u7c7b\u9644\u4ef6\u5df2\u68c0\u6d4b\u5230\uff0c\u53ef\u80fd\u6d89\u53ca\u9690\u5199\u3001\u5143\u6570\u636e\u6216\u5c3e\u90e8\u9690\u85cf\u3002");
  }
  if (familyCount.network) {
    findings.push("\u6d41\u91cf\u7c7b\u9644\u4ef6\u5df2\u68c0\u6d4b\u5230\uff0c\u53ef\u4ee5\u8fdb\u5165 HTTP / DNS / \u4f1a\u8bdd\u91cd\u7ec4\u5206\u6790\u3002");
  }
  if (familyCount.binary) {
    findings.push("\u4e8c\u8fdb\u5236\u9644\u4ef6\u5df2\u68c0\u6d4b\u5230\uff0c\u7ed3\u679c\u4f1a\u504f\u5411 reverse / pwn \u5206\u6d41\u3002");
  }
  if (familyCount.text) {
    findings.push("\u6587\u672c\u7c7b\u9644\u4ef6\u4f1a\u81ea\u52a8\u626b flag \u6837\u5f0f\u3001base64 \u548c hex \u7ebf\u7d22\u3002");
  }

  return findings;
}

function renderDiscoveryPanel() {
  elements.discoveryList.innerHTML = "";
  const items = state.analysis
    ? state.analysis.quickFindings.concat(state.analysis.warnings || [])
    : inferPreviewFindings();

  items.forEach((item) => {
    const box = document.createElement("div");
    box.className = "stack-item";
    box.textContent = item;
    elements.discoveryList.append(box);
  });
}

function sortArtifactsForDisplay(items) {
  return [...items].sort((left, right) => {
    const leftPinned = getEvidenceEntry(left.path).pinned ? 1 : 0;
    const rightPinned = getEvidenceEntry(right.path).pinned ? 1 : 0;
    if (leftPinned !== rightPinned) {
      return rightPinned - leftPinned;
    }
    return left.name.localeCompare(right.name, "zh-CN");
  });
}

function getWorkbenchMeta(family) {
  if (family === "image") {
    return {
      label: STRINGS.familyImage,
      subtitle: "\u56fe\u50cf\u3001\u9690\u5199\u3001\u901a\u9053\u4e0e\u9644\u52a0\u6570\u636e",
      description: "\u628a PNG/JPEG \u7684\u5143\u6570\u636e\u3001QR/\u6761\u7801\u3001LSB \u548c\u53ef\u89c6\u5316\u5bfc\u51fa\u6536\u5728\u540c\u4e00\u4e2a\u9762\u677f\u91cc\u3002",
    };
  }
  if (family === "audio") {
    return {
      label: STRINGS.familyAudio,
      subtitle: "WAV \u5757\u3001LSB\u3001\u97f3\u8c03\u4e0e Morse",
      description: "\u628a\u97f3\u9891\u5143\u6570\u636e\u3001\u6d3b\u52a8\u6bb5\u3001Morse \u5019\u9009\u548c\u6ce2\u5f62/\u9891\u8c31\u56fe\u6536\u5728\u4e00\u8d77\u3002",
    };
  }
  if (family === "network") {
    return {
      label: STRINGS.familyNetwork,
      subtitle: "HTTP / DNS / TLS / TCP \u91cd\u7ec4",
      description: "\u628a pcap/pcapng \u91cc\u7684\u4f1a\u8bdd\u7ebf\u7d22\u3001Cookie/Token \u548c\u5bfc\u51fa\u5bf9\u8c61\u5355\u72ec\u6536\u7eb3\u3002",
    };
  }
  return {
    label: STRINGS.familyBinary,
    subtitle: "ELF / PE / APK \u672c\u5730\u7ed3\u6784\u5316\u62c6\u89e3",
    description: "\u628a section\u3001imports/exports\u3001symbols/relocs\u3001Manifest/DEX \u548c\u6253\u5305\u7ed3\u6784\u96c6\u4e2d\u5728\u4e8c\u8fdb\u5236\u9762\u677f\u3002",
  };
}

function getWorkbenchFamilies(result) {
  const order = ["binary", "network", "image", "audio"];
  return order
    .map((family) => {
      const artifacts = sortArtifactsForDisplay((result.artifacts || []).filter((item) => item.family === family));
      return artifacts.length ? { family, artifacts, meta: getWorkbenchMeta(family) } : null;
    })
    .filter(Boolean);
}

function createMetricPill(value, label) {
  const item = document.createElement("div");
  item.className = "metric-pill";
  item.innerHTML = `<strong>${escapeHtml(String(value))}</strong><span>${escapeHtml(label)}</span>`;
  return item;
}

function createWorkbenchActionChip(label, count) {
  const chip = document.createElement("span");
  chip.className = "chip tool-chip";
  chip.textContent = count > 1 ? `${label} × ${count}` : label;
  return chip;
}

function createWorkbenchPipelineRow(entry) {
  const row = document.createElement("div");
  row.className = "stack-item";
  const createdNames = (entry.createdArtifacts || []).map((artifact) => artifact.name).join("  |  ");
  row.innerHTML = `<strong>${escapeHtml(entry.sourceName)} \u2192 ${escapeHtml(entry.actionLabel)}</strong><p>${escapeHtml(
    entry.message,
  )}</p><small>${escapeHtml(createdNames)}</small>`;
  return row;
}

function renderWorkbench(result) {
  elements.workbenchTabs.innerHTML = "";
  elements.workbenchPanel.innerHTML = "";

  const families = getWorkbenchFamilies(result);
  if (!families.length) {
    elements.workbenchPanel.innerHTML = `<p class="empty-copy">${STRINGS.workbenchNoArtifacts}</p>`;
    return;
  }

  const familySet = new Set(families.map((item) => item.family));
  if (!familySet.has(state.workbenchFamily)) {
    state.workbenchFamily = families[0].family;
  }

  families.forEach((item) => {
    const button = document.createElement("button");
    button.className = `workbench-tab${item.family === state.workbenchFamily ? " active" : ""}`;
    button.type = "button";
    button.innerHTML = `<strong>${escapeHtml(item.meta.label)}</strong><span>${item.artifacts.length}</span>`;
    button.addEventListener("click", () => {
      state.workbenchFamily = item.family;
      renderResults();
      scheduleWorkspaceSave();
    });
    elements.workbenchTabs.append(button);
  });

  const current = families.find((item) => item.family === state.workbenchFamily) || families[0];
  const currentPaths = new Set(current.artifacts.map((item) => item.path));
  const currentFlags = current.artifacts.reduce((sum, artifact) => sum + (artifact.flagCandidates?.length || 0), 0);
  const currentGenerated = current.artifacts.filter((item) => item.sourceKind === "generated").length;
  const currentPipeline = (result.pipelineLog || []).filter((entry) => {
    if (currentPaths.has(entry.sourcePath)) {
      return true;
    }
    return (entry.createdArtifacts || []).some((artifact) => artifact.family === current.family);
  });
  const actionCounts = new Map();
  current.artifacts.forEach((artifact) => {
    (artifact.actions || []).forEach((action) => {
      actionCounts.set(action.label, (actionCounts.get(action.label) || 0) + 1);
    });
  });
  const signalLines = [];
  current.artifacts.forEach((artifact) => {
    (artifact.highlights || []).slice(0, 2).forEach((item) => signalLines.push(`${artifact.name}: ${item}`));
  });

  const hero = document.createElement("div");
  hero.className = "workbench-hero";

  const copy = document.createElement("div");
  copy.className = "workbench-copy";
  copy.innerHTML = `<p class="panel-kicker">${escapeHtml(current.meta.subtitle)}</p><h4>${escapeHtml(
    current.meta.label,
  )}</h4><p class="body-copy">${escapeHtml(current.meta.description)}</p>`;
  hero.append(copy);

  const metrics = document.createElement("div");
  metrics.className = "workbench-metrics";
  metrics.append(
    createMetricPill(current.artifacts.length, STRINGS.workbenchMetricArtifacts),
    createMetricPill(currentGenerated, STRINGS.workbenchMetricGenerated),
    createMetricPill(currentFlags, STRINGS.workbenchMetricFlags),
  );
  hero.append(metrics);
  elements.workbenchPanel.append(hero);

  const body = document.createElement("div");
  body.className = "workbench-body";

  const left = document.createElement("div");
  left.className = "workbench-column";
  const queuePanel = document.createElement("section");
  queuePanel.className = "workbench-subpanel";
  queuePanel.innerHTML = `<div class="panel-head compact-head"><div><p class="panel-kicker">${STRINGS.workbenchQueueTitle}</p></div></div>`;
  current.artifacts.slice(0, 4).forEach((artifact) => {
    queuePanel.append(createDetailCard(artifact, { editableEvidence: false, compactActions: true }));
  });
  left.append(queuePanel);

  const right = document.createElement("div");
  right.className = "workbench-column";

  const signalPanel = document.createElement("section");
  signalPanel.className = "workbench-subpanel";
  signalPanel.innerHTML = `<div class="panel-head compact-head"><div><p class="panel-kicker">${STRINGS.workbenchSignalsTitle}</p></div></div>`;
  if (!signalLines.length) {
    signalPanel.innerHTML += `<p class="empty-copy">${STRINGS.workbenchNoArtifacts}</p>`;
  } else {
    const signalList = document.createElement("div");
    signalList.className = "stack-list";
    signalLines.slice(0, 10).forEach((item) => {
      const box = document.createElement("div");
      box.className = "stack-item";
      box.textContent = item;
      signalList.append(box);
    });
    signalPanel.append(signalList);
  }

  const actionPanel = document.createElement("section");
  actionPanel.className = "workbench-subpanel";
  actionPanel.innerHTML = `<div class="panel-head compact-head"><div><p class="panel-kicker">${STRINGS.workbenchActionsTitle}</p></div></div>`;
  const actionWrap = document.createElement("div");
  actionWrap.className = "chip-row";
  if (!actionCounts.size) {
    actionWrap.innerHTML = `<p class="empty-copy">${STRINGS.workbenchNoArtifacts}</p>`;
  } else {
    [...actionCounts.entries()]
      .sort((leftEntry, rightEntry) => rightEntry[1] - leftEntry[1])
      .forEach(([label, count]) => actionWrap.append(createWorkbenchActionChip(label, count)));
  }
  actionPanel.append(actionWrap);

  const pipelinePanel = document.createElement("section");
  pipelinePanel.className = "workbench-subpanel";
  pipelinePanel.innerHTML = `<div class="panel-head compact-head"><div><p class="panel-kicker">${STRINGS.workbenchDerivedTitle}</p></div></div>`;
  if (!currentPipeline.length) {
    pipelinePanel.innerHTML += `<p class="empty-copy">${STRINGS.workbenchNoPipeline}</p>`;
  } else {
    const pipelineList = document.createElement("div");
    pipelineList.className = "stack-list";
    currentPipeline.slice(0, 8).forEach((entry) => {
      pipelineList.append(createWorkbenchPipelineRow(entry));
    });
    pipelinePanel.append(pipelineList);
  }

  right.append(signalPanel, actionPanel, pipelinePanel);
  body.append(left, right);
  elements.workbenchPanel.append(body);
}

function setFinalFlag(candidate) {
  state.casebook.finalFlag = candidate ? { value: candidate.value, source: candidate.source } : null;
  renderResults();
  scheduleWorkspaceSave();
}

function clearFinalFlag() {
  state.casebook.finalFlag = null;
  renderResults();
  scheduleWorkspaceSave();
}

function createFlagCard(candidate, isFinal) {
  const row = document.createElement("div");
  row.className = `stack-item flag-item${isFinal ? " is-final" : ""}`;

  const head = document.createElement("div");
  head.className = "flag-item-head";
  head.innerHTML = `<div><strong>${escapeHtml(candidate.value)}</strong><small>${escapeHtml(candidate.source || "")}</small></div>`;

  const actions = document.createElement("div");
  actions.className = "flag-actions";

  const actionButton = document.createElement("button");
  actionButton.className = "text-link";
  actionButton.type = "button";
  actionButton.textContent = isFinal ? STRINGS.flagFinalLabel : STRINGS.flagFinalize;
  actionButton.addEventListener("click", () => {
    if (isFinal) {
      clearFinalFlag();
      return;
    }
    setFinalFlag(candidate);
  });

  actions.append(actionButton);
  head.append(actions);
  row.append(head);
  return row;
}

function solverStatusLabel(status) {
  if (status === "solved") {
    return STRINGS.solverStatusSolved;
  }
  if (status === "partial") {
    return STRINGS.solverStatusPartial;
  }
  return STRINGS.solverStatusBlocked;
}

function renderSolverCard(solver) {
  if (!elements.solverCard) {
    return;
  }

  elements.solverCard.innerHTML = "";
  const card = document.createElement("section");
  card.className = `solver-card-inner solver-${solver?.status || "waiting"}`;

  if (!solver) {
    card.innerHTML = `<div class="solver-head"><strong>${STRINGS.solverWaitingTitle}</strong></div><p>${STRINGS.solverWaitingNote}</p>`;
    elements.solverCard.append(card);
    return;
  }

  const confidence = Number(solver.confidence || 0).toFixed(2);
  const head = document.createElement("div");
  head.className = "solver-head";
  head.innerHTML = `<div><span class="solver-status">${escapeHtml(solverStatusLabel(solver.status))}</span><strong>${escapeHtml(
    solver.title || STRINGS.solverNoFlag,
  )}</strong></div><span class="solver-score">${confidence}</span>`;
  card.append(head);

  const summary = document.createElement("p");
  summary.textContent = solver.summary || "";
  card.append(summary);

  const meta = document.createElement("div");
  meta.className = "solver-meta";
  meta.innerHTML = `<span>${STRINGS.solverRunMeta}: ${Number(solver.actionsRun || 0)}</span><span>${STRINGS.solverArtifactMeta}: ${Number(
    solver.artifactCount || 0,
  )}</span>`;
  card.append(meta);

  if (solver.primaryFlag) {
    const flagBox = document.createElement("div");
    flagBox.className = "solver-flag";
    flagBox.innerHTML = `<span>${STRINGS.solverPrimaryFlag}</span><strong>${escapeHtml(solver.primaryFlag.value)}</strong><small>${escapeHtml(
      solver.primaryFlag.source || "",
    )}</small>`;

    const finalButton = document.createElement("button");
    finalButton.className = "text-link";
    finalButton.type = "button";
    finalButton.textContent = STRINGS.flagFinalize;
    finalButton.addEventListener("click", () => {
      setFinalFlag(solver.primaryFlag);
    });
    flagBox.append(finalButton);
    card.append(flagBox);
  }

  if (solver.status !== "solved" && solver.missingTools?.length) {
    const missing = document.createElement("div");
    missing.className = "solver-tool-row";
    missing.innerHTML = `<span>${STRINGS.solverMissingTools}</span>`;
    solver.missingTools.slice(0, 5).forEach((tool) => {
      const chip = createToolChip(tool.label, "missing");
      chip.title = tool.installHint || tool.purpose || "";
      missing.append(chip);
    });
    card.append(missing);
  }

  if (solver.status !== "solved" && solver.failedActions?.length) {
    const failed = document.createElement("div");
    failed.className = "solver-failures";
    failed.innerHTML = `<span>${STRINGS.solverFailedActions}</span>`;
    solver.failedActions.slice(0, 3).forEach((item) => {
      const line = document.createElement("small");
      line.textContent = `${item.actionLabel}: ${item.message}`;
      failed.append(line);
    });
    card.append(failed);
  }

  if (solver.nextActions?.length) {
    const next = document.createElement("ul");
    next.className = "plain-list solver-next";
    solver.nextActions.slice(0, 4).forEach((item) => {
      const li = document.createElement("li");
      li.textContent = item;
      next.append(li);
    });
    card.append(next);
  }

  elements.solverCard.append(card);
}

function createPipelineDetails(entry, index) {
  const details = document.createElement("details");
  details.className = "pipeline-details";
  if (index === 0) {
    details.open = true;
  }

  const createdArtifacts = entry.createdArtifacts || [];
  const summary = document.createElement("summary");
  summary.innerHTML = `<span><strong>${escapeHtml(entry.actionLabel)}</strong><small>${escapeHtml(entry.sourceName || "")}</small></span><em>${createdArtifacts.length}</em>`;
  details.append(summary);

  const body = document.createElement("div");
  body.className = "pipeline-body";
  const message = document.createElement("p");
  message.textContent = entry.message || "";
  body.append(message);

  if (createdArtifacts.length) {
    const created = document.createElement("div");
    created.className = "pipeline-created";
    created.append(createToolChip(`${STRINGS.pipelineCreatedLabel} ${createdArtifacts.length}`));
    createdArtifacts.slice(0, 12).forEach((artifact) => {
      created.append(createToolChip(artifact.name || artifact.path || "artifact"));
    });
    body.append(created);
  }

  details.append(body);
  return details;
}

function createFailureGuideDetails(entry, index) {
  const guide = entry.guide || {};
  const details = document.createElement("details");
  details.className = "failure-details";
  if (index === 0) {
    details.open = true;
  }

  const summary = document.createElement("summary");
  summary.innerHTML = `<span><strong>${escapeHtml(guide.title || entry.actionLabel || STRINGS.failureGuideTitle)}</strong><small>${escapeHtml(
    entry.sourceName || guide.sourceName || "",
  )}</small></span>`;
  details.append(summary);

  const body = document.createElement("div");
  body.className = "failure-body";

  const reason = document.createElement("p");
  reason.textContent = guide.reason || entry.message || "";
  body.append(reason);

  const steps = document.createElement("ol");
  (guide.steps || []).slice(0, 5).forEach((step) => {
    const item = document.createElement("li");
    item.textContent = step;
    steps.append(item);
  });
  if (steps.children.length) {
    body.append(steps);
  }

  if (guide.fallback) {
    const fallback = document.createElement("small");
    fallback.textContent = guide.fallback;
    body.append(fallback);
  }

  details.append(body);
  return details;
}

function renderFailurePanel(result) {
  if (!elements.failureList) {
    return;
  }

  elements.failureList.innerHTML = "";
  const heading = document.createElement("div");
  heading.className = "failure-heading";
  heading.innerHTML = `<strong>${STRINGS.failureGuideTitle}</strong>`;
  elements.failureList.append(heading);

  const errors = result?.pipelineErrors || [];
  if (!errors.length) {
    const empty = document.createElement("p");
    empty.className = "empty-copy";
    empty.textContent = STRINGS.failureEmpty;
    elements.failureList.append(empty);
    return;
  }

  errors.slice(0, 12).forEach((entry, index) => {
    elements.failureList.append(createFailureGuideDetails(entry, index));
  });
}

function createEvidenceSummary(filePath) {
  const evidence = getEvidenceEntry(filePath);
  if (!evidence.note && !evidence.pinned && evidence.status === "todo") {
    return null;
  }

  const wrap = document.createElement("div");
  wrap.className = "evidence-summary";

  const chipRow = document.createElement("div");
  chipRow.className = "chip-row evidence-chip-row";

  const statusChip = document.createElement("span");
  statusChip.className = "chip";
  statusChip.textContent = evidenceStatusLabel(evidence.status);
  chipRow.append(statusChip);

  if (evidence.pinned) {
    const pinnedChip = document.createElement("span");
    pinnedChip.className = "chip tool-chip";
    pinnedChip.textContent = STRINGS.evidencePinned;
    chipRow.append(pinnedChip);
  }

  wrap.append(chipRow);

  if (evidence.note) {
    const note = document.createElement("p");
    note.className = "detail-summary";
    note.textContent = evidence.note;
    wrap.append(note);
  }

  return wrap;
}

function createEvidenceEditor(filePath) {
  const evidence = getEvidenceEntry(filePath);
  const editor = document.createElement("div");
  editor.className = "evidence-editor";

  const toolbar = document.createElement("div");
  toolbar.className = "evidence-toolbar";

  const selectLabel = document.createElement("label");
  selectLabel.className = "field evidence-field";

  const selectTitle = document.createElement("span");
  selectTitle.textContent = STRINGS.evidenceStatusLabel;

  const select = document.createElement("select");
  select.className = "evidence-select";
  EVIDENCE_STATUSES.forEach((status) => {
    const option = document.createElement("option");
    option.value = status;
    option.textContent = evidenceStatusLabel(status);
    option.selected = evidence.status === status;
    select.append(option);
  });
  select.addEventListener("change", () => {
    evidence.status = select.value;
    scheduleWorkspaceSave();
  });
  selectLabel.append(selectTitle, select);

  const pinButton = document.createElement("button");
  pinButton.className = `text-link toggle-chip${evidence.pinned ? " active" : ""}`;
  pinButton.type = "button";
  pinButton.textContent = STRINGS.evidencePinLabel;
  pinButton.addEventListener("click", () => {
    evidence.pinned = !evidence.pinned;
    pinButton.classList.toggle("active", evidence.pinned);
    renderAll();
    scheduleWorkspaceSave();
  });

  toolbar.append(selectLabel, pinButton);
  editor.append(toolbar);

  const noteField = document.createElement("label");
  noteField.className = "field field-full evidence-field";

  const noteLabel = document.createElement("span");
  noteLabel.textContent = STRINGS.evidenceNoteLabel;

  const noteInput = document.createElement("textarea");
  noteInput.className = "evidence-note";
  noteInput.rows = 4;
  noteInput.value = evidence.note;
  noteInput.addEventListener("input", () => {
    evidence.note = noteInput.value;
    scheduleWorkspaceSave();
  });

  noteField.append(noteLabel, noteInput);
  editor.append(noteField);
  return editor;
}

function renderResults() {
  if (!state.analysis) {
    elements.summaryCategory.textContent = STRINGS.emptyResultsCategory;
    elements.summaryConfidence.textContent = "--";
    elements.summaryText.textContent = STRINGS.emptyResultsSummary;
    elements.summaryEvidence.innerHTML = "";
    renderSolverCard(null);
    elements.workbenchTabs.innerHTML = "";
    elements.workbenchPanel.innerHTML = `<p class="empty-copy">${STRINGS.workbenchNoArtifacts}</p>`;
    elements.pipelineList.innerHTML = `<p class="empty-copy">${STRINGS.emptyPipeline}</p>`;
    renderFailurePanel(null);
    elements.flagList.innerHTML = `<p class="empty-copy">${STRINGS.emptyFlags}</p>`;
    elements.nextList.innerHTML = "";
    elements.findingList.innerHTML = `<p class="empty-copy">${STRINGS.emptyArtifactDetail}</p>`;
    elements.toolList.innerHTML = "";
    return;
  }

  const result = state.analysis;
  state.casebook.summary = elements.caseSummaryInput.value.trim();
  elements.summaryCategory.textContent = result.classification.label;
  elements.summaryConfidence.textContent = result.classification.confidence.toFixed(2);
  elements.summaryText.textContent = result.classification.reason;
  elements.summaryEvidence.innerHTML = "";
  result.classification.evidence.forEach((item) => {
    const chip = document.createElement("span");
    chip.className = "chip";
    chip.textContent = item;
    elements.summaryEvidence.append(chip);
  });
  renderSolverCard(result.solver);

  renderWorkbench(result);

  elements.pipelineList.innerHTML = "";
  if (!result.pipelineLog || !result.pipelineLog.length) {
    const emptyPipeline = document.createElement("p");
    emptyPipeline.className = "empty-copy";
    emptyPipeline.textContent = STRINGS.emptyPipeline;
    elements.pipelineList.append(emptyPipeline);
  } else {
    result.pipelineLog.forEach((entry, index) => {
      elements.pipelineList.append(createPipelineDetails(entry, index));
    });
  }
  renderFailurePanel(result);

  elements.flagList.innerHTML = "";
  if (state.casebook.finalFlag) {
    elements.flagList.append(createFlagCard(state.casebook.finalFlag, true));
  } else {
    const emptyFinal = document.createElement("div");
    emptyFinal.className = "stack-item final-flag-empty";
    emptyFinal.innerHTML = `<strong>${STRINGS.flagFinalLabel}</strong><small>${STRINGS.flagFinalEmpty}</small>`;
    elements.flagList.append(emptyFinal);
  }

  if (!result.flagCandidates.length) {
    const empty = document.createElement("p");
    empty.className = "empty-copy";
    empty.textContent = result.emptyFlagMessage;
    elements.flagList.append(empty);
  } else {
    result.flagCandidates.forEach((item) => {
      const isFinal =
        state.casebook.finalFlag &&
        state.casebook.finalFlag.value === item.value &&
        state.casebook.finalFlag.source === item.source;
      elements.flagList.append(createFlagCard(item, isFinal));
    });
  }

  elements.nextList.innerHTML = "";
  const nextItems = result.solver?.nextActions?.length ? result.solver.nextActions : result.classification.nextMoves;
  nextItems.forEach((item) => {
    const li = document.createElement("li");
    li.textContent = item;
    elements.nextList.append(li);
  });

  elements.findingList.innerHTML = "";
  sortArtifactsForDisplay(result.artifacts).forEach((artifact) => {
    elements.findingList.append(createDetailCard(artifact, { editableEvidence: false }));
  });

  renderToolPanel(result);
}

function createToolChip(label, className = "") {
  const chip = document.createElement("span");
  chip.className = `chip tool-chip ${className}`.trim();
  chip.textContent = label;
  return chip;
}

function createToolStatusCard(title, items, className, emptyText) {
  const card = document.createElement("section");
  card.className = `tool-status-card ${className}`;

  const heading = document.createElement("strong");
  heading.textContent = `${title} · ${items.length}`;
  card.append(heading);

  const list = document.createElement("div");
  list.className = "tool-items";
  if (!items.length) {
    const empty = document.createElement("p");
    empty.className = "empty-copy";
    empty.textContent = emptyText;
    list.append(empty);
  } else {
    items.slice(0, 8).forEach((tool) => {
      const chip = createToolChip(tool.label, className);
      chip.title = tool.available ? tool.path || tool.purpose : `${tool.purpose} ${tool.installHint}`;
      list.append(chip);
    });
  }

  card.append(list);
  return card;
}

function renderToolPanel(result) {
  elements.toolList.innerHTML = "";

  if (result.bundledTools?.length) {
    const bundled = document.createElement("section");
    bundled.className = "tool-suggested bundled-tools";
    const title = document.createElement("strong");
    title.textContent = STRINGS.bundledToolTitle;
    const note = document.createElement("p");
    note.className = "empty-copy";
    note.textContent = STRINGS.bundledToolNote;
    const row = document.createElement("div");
    row.className = "classification-tool-row";
    result.bundledTools.forEach((tool) => {
      const chip = createToolChip(tool.label, "installed");
      chip.title = `${tool.replaces}: ${tool.purpose}`;
      row.append(chip);
    });
    bundled.append(title, note, row);
    elements.toolList.append(bundled);
  }

  const suggested = document.createElement("section");
  suggested.className = "tool-suggested";
  const suggestedTitle = document.createElement("strong");
  suggestedTitle.textContent = STRINGS.toolSuggestedTitle;
  const suggestedRow = document.createElement("div");
  suggestedRow.className = "classification-tool-row";
  (result.classification.tools || []).forEach((tool) => {
    suggestedRow.append(createToolChip(tool));
  });
  suggested.append(suggestedTitle, suggestedRow);
  elements.toolList.append(suggested);

  if (!result.toolStatus) {
    return;
  }

  const grid = document.createElement("div");
  grid.className = "tool-status-grid";
  grid.append(
    createToolStatusCard(STRINGS.toolInstalledTitle, result.toolStatus.installed || [], "installed", STRINGS.toolEmptyInstalled),
    createToolStatusCard(STRINGS.toolMissingTitle, result.toolStatus.missing || [], "missing", STRINGS.toolMissingNote),
  );
  elements.toolList.append(grid);
}

function createArtifactActionButton(action, artifact, className = "") {
  const actionButton = document.createElement("button");
  actionButton.className = `text-link artifact-action ${className}`.trim();
  actionButton.type = "button";
  actionButton.textContent = action.label;
  actionButton.title = STRINGS.artifactProcess;
  actionButton.disabled = state.isBusy;
  actionButton.addEventListener("click", () => {
    runArtifactAction(action.id, artifact.path);
  });
  return actionButton;
}

function appendArtifactActionButtons(container, artifact, options = {}) {
  const actionItems = artifact.actions || [];
  const visibleCount = options.compactActions ? 1 : 2;
  actionItems.slice(0, visibleCount).forEach((action, index) => {
    container.append(createArtifactActionButton(action, artifact, index === 0 ? "primary-action" : ""));
  });

  const hiddenActions = actionItems.slice(visibleCount);
  if (!hiddenActions.length) {
    return;
  }

  const menu = document.createElement("details");
  menu.className = "action-menu";
  const summary = document.createElement("summary");
  summary.textContent = `${STRINGS.actionMore} ${hiddenActions.length}`;
  menu.append(summary);

  const menuBody = document.createElement("div");
  menuBody.className = "action-menu-body";
  hiddenActions.forEach((action) => {
    menuBody.append(createArtifactActionButton(action, artifact));
  });
  menu.append(menuBody);
  container.append(menu);
}

function createDetailCard(artifact, options = {}) {
  const card = document.createElement("article");
  card.className = "detail-card";
  card.dataset.family = artifact.family || "unknown";

  const parts = [`${artifact.familyLabel}  |  ${artifact.sizeLabel}  |  ${artifact.badge}`];
  if (artifact.sourceKind === "generated" && artifact.generatedBy) {
    parts.push(`\u81ea\u52a8\u751f\u6210\uff1a${artifact.generatedBy}`);
  }

  const head = document.createElement("div");
  head.className = "detail-head";
  head.innerHTML = `<div><strong>${escapeHtml(artifact.name)}</strong><p>${escapeHtml(
    parts.join("  |  "),
  )}</p></div>`;

  const actions = document.createElement("div");
  actions.className = "detail-actions";

  const openButton = document.createElement("button");
  openButton.className = "text-link artifact-action open-action";
  openButton.type = "button";
  openButton.textContent = STRINGS.artifactOpen;
  openButton.addEventListener("click", () => {
    window.ctfCompass.revealArtifact(artifact.path);
  });
  actions.append(openButton);

  if (artifact.actions && artifact.actions.length) {
    appendArtifactActionButtons(actions, artifact, options);
  }

  head.append(actions);
  card.append(head);

  if (artifact.summary) {
    const summary = document.createElement("p");
    summary.className = "detail-summary";
    summary.textContent = artifact.summary;
    card.append(summary);
  }

  const entries = artifact.highlights && artifact.highlights.length ? artifact.highlights : artifact.suggestions || [];
  if (entries.length) {
    const lines = document.createElement("div");
    lines.className = "detail-bullets";
    entries.forEach((item) => {
      const line = document.createElement("div");
      line.className = "detail-line";
      line.textContent = item;
      lines.append(line);
    });
    card.append(lines);
  }

  if (artifact.toolActions && artifact.toolActions.length) {
    const toolBox = document.createElement("div");
    toolBox.className = "artifact-tools";
    artifact.toolActions.forEach((tool) => {
      const chip = document.createElement("span");
      chip.className = `chip tool-chip ${tool.available ? "installed" : "missing"}`;
      chip.title = tool.available ? tool.executablePath || tool.purpose : `${tool.purpose} ${tool.installHint}`;
      chip.textContent = `${tool.toolLabel} · ${tool.available ? STRINGS.toolInstalled : STRINGS.toolMissing}`;
      toolBox.append(chip);
    });
    if (artifact.toolActions.some((tool) => !tool.available)) {
      const note = document.createElement("small");
      note.textContent = STRINGS.toolMissingNote;
      toolBox.append(note);
    }
    card.append(toolBox);
  }

  if (options.editableEvidence) {
    card.append(createEvidenceEditor(artifact.path));
  } else {
    const summary = createEvidenceSummary(artifact.path);
    if (summary) {
      card.append(summary);
    }
  }

  return card;
}

async function runArtifactAction(actionId, filePath) {
  if (state.isBusy) {
    return;
  }
  setBusy(true);
  try {
    setStatus(STRINGS.statusActionRunning);
    const result = await window.ctfCompass.runArtifactAction({ actionId, filePath });
    if (result.generatedArtifacts && result.generatedArtifacts.length) {
      state.artifacts = uniqArtifacts(state.artifacts.concat(result.generatedArtifacts));
    }
    setBusy(false);
    await runAnalysis({ doneMessage: result.message || STRINGS.statusActionDone });
    return;
  } catch (error) {
    setStatus(`${STRINGS.statusErrorPrefix} ${error.message}`, "error");
  } finally {
    setBusy(false);
  }
}

function renderArtifactDetails() {
  elements.artifactDetailList.innerHTML = "";
  const source = state.analysis ? state.analysis.artifacts : state.artifacts;

  if (!source.length) {
    const empty = document.createElement("p");
    empty.className = "empty-copy";
    empty.textContent = STRINGS.emptyArtifactDetail;
    elements.artifactDetailList.append(empty);
    return;
  }

  sortArtifactsForDisplay(source).forEach((artifact) => {
    elements.artifactDetailList.append(createDetailCard(artifact, { editableEvidence: true }));
  });
}

function renderAll() {
  renderViewHeader();
  renderArtifactPreview();
  renderDiscoveryPanel();
  renderResults();
  renderArtifactDetails();
  updateActionAvailability();
}

function splitTags(value) {
  return value
    .split(/\s+/)
    .map((item) => item.trim())
    .filter(Boolean);
}

async function runAnalysis(options = {}) {
  const { focusResults = true, doneMessage = STRINGS.statusDone } = options;
  if (!workspaceHasAnalyzableInput()) {
    switchView("workspace");
    setStatus(STRINGS.runDisabledHint, "error");
    return;
  }
  if (state.isBusy) {
    return;
  }
  setBusy(true);
  try {
    setStatus(STRINGS.statusAnalyzing);
    const result = await window.ctfCompass.analyzeChallenge({
      title: elements.titleInput.value.trim(),
      description: elements.descriptionInput.value.trim(),
      notes: elements.notesInput.value.trim(),
      tags: splitTags(elements.tagsInput.value),
      artifacts: state.artifacts.map((item) => item.path),
    });
    state.analysis = result;
    renderAll();
    if (focusResults) {
      switchView("results");
    } else {
      renderViewHeader();
    }
    scheduleWorkspaceSave();
    await refreshSandboxInfo();
    setStatus(doneMessage);
  } catch (error) {
    setStatus(`${STRINGS.statusErrorPrefix} ${error.message}`, "error");
  } finally {
    setBusy(false);
  }
}

async function appendPreparedArtifacts(promise) {
  if (state.isBusy) {
    return;
  }
  setBusy(true);
  try {
    const items = await promise;
    if (items.length) {
      state.artifacts = uniqArtifacts(state.artifacts.concat(items));
      renderAll();
      scheduleWorkspaceSave();
      setStatus(STRINGS.statusArtifactAdded);
    }
  } catch (error) {
    setStatus(`${STRINGS.statusErrorPrefix} ${error.message}`, "error");
  } finally {
    setBusy(false);
  }
}

function escapeHtml(value) {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

function buildReportMarkdown() {
  if (!state.analysis) {
    return null;
  }

  const snapshot = buildWorkspaceSnapshot();
  const lines = [
    `# ${snapshot.challenge.title || "CTF Compass Report"}`,
    "",
    `- Generated: ${new Date().toLocaleString("zh-CN")}`,
    `- Category: ${state.analysis.classification.label}`,
    `- Confidence: ${state.analysis.classification.confidence.toFixed(2)}`,
    `- Artifacts: ${state.analysis.artifacts.length}`,
    "",
  ];

  if (state.casebook.finalFlag?.value) {
    lines.push("## Final Flag", "", `- ${state.casebook.finalFlag.value}`, "");
  }

  if (snapshot.challenge.tags.length) {
    lines.push("## Tags", "", snapshot.challenge.tags.map((item) => `- ${item}`).join("\n"), "");
  }

  if (snapshot.challenge.description) {
    lines.push("## Challenge Description", "", snapshot.challenge.description, "");
  }

  if (snapshot.challenge.notes) {
    lines.push("## Working Notes", "", snapshot.challenge.notes, "");
  }

  if (snapshot.casebook.summary) {
    lines.push("## Analyst Conclusion", "", snapshot.casebook.summary, "");
  }

  if (state.analysis.solver) {
    const solver = state.analysis.solver;
    lines.push("## Solver Status", "", `- Status: ${solverStatusLabel(solver.status)}`, `- Confidence: ${Number(solver.confidence || 0).toFixed(2)}`);
    if (solver.primaryFlag?.value) {
      lines.push(`- Primary: ${solver.primaryFlag.value} (${solver.primaryFlag.source || "unknown"})`);
    }
    if (solver.nextActions?.length) {
      lines.push("");
      solver.nextActions.forEach((item) => lines.push(`- ${item}`));
    }
    lines.push("");
  }

  lines.push("## Classification", "", state.analysis.classification.reason, "");

  if (state.analysis.classification.evidence?.length) {
    lines.push("### Evidence", "");
    state.analysis.classification.evidence.forEach((item) => lines.push(`- ${item}`));
    lines.push("");
  }

  if (state.analysis.flagCandidates?.length) {
    lines.push("## Flag Candidates", "");
    state.analysis.flagCandidates.forEach((item) => lines.push(`- ${item.value} (${item.source})`));
    lines.push("");
  }

  if (state.analysis.pipelineLog?.length) {
    lines.push("## Pipeline", "");
    state.analysis.pipelineLog.forEach((item) => {
      lines.push(`- ${item.sourceName} -> ${item.actionLabel}: ${item.message}`);
    });
    lines.push("");
  }

  const nextSteps = state.analysis.solver?.nextActions?.length ? state.analysis.solver.nextActions : state.analysis.classification.nextMoves;
  if (nextSteps?.length) {
    lines.push("## Next Steps", "");
    nextSteps.forEach((item) => lines.push(`- ${item}`));
    lines.push("");
  }

  if (state.analysis.classification.tools?.length) {
    lines.push("## Tools", "");
    state.analysis.classification.tools.forEach((item) => lines.push(`- ${item}`));
    lines.push("");
  }

  const evidenceEntries = Object.entries(compactEvidenceByPath());
  if (evidenceEntries.length) {
    lines.push("## Evidence Notebook", "");
    evidenceEntries.forEach(([filePath, entry]) => {
      const artifact = (state.analysis?.artifacts || state.artifacts).find((item) => item.path === filePath);
      lines.push(`### ${artifact?.name || filePath}`);
      lines.push(`- Status: ${evidenceStatusLabel(entry.status)}`);
      lines.push(`- Pinned: ${entry.pinned ? "yes" : "no"}`);
      if (entry.note) {
        lines.push("", entry.note);
      }
      lines.push("");
    });
  }

  return `${lines.join("\n")}\n`;
}

async function exportReport() {
  try {
    if (!state.analysis) {
      throw new Error("\u8bf7\u5148\u8fd0\u884c\u4e00\u6b21\u5206\u6790\u518d\u5bfc\u51fa\u62a5\u544a\u3002");
    }
    const title = elements.titleInput.value.trim() || "ctf-compass-report";
    const result = await window.ctfCompass.exportReport({
      suggestedName: `${title.replace(/[\\\\/:*?\"<>|]+/g, "-")}.md`,
      content: buildReportMarkdown(),
    });
    if (result?.filePath) {
      setStatus(`${STRINGS.statusReportExported} ${result.filePath}`);
    }
  } catch (error) {
    setStatus(`${STRINGS.statusErrorPrefix} ${error.message}`, "error");
  }
}

async function clearWorkspace() {
  try {
    persistenceReady = false;
    state.artifacts = [];
    state.analysis = null;
    state.casebook = createEmptyCasebook();
    elements.titleInput.value = "";
    elements.tagsInput.value = "";
    elements.descriptionInput.value = "";
    elements.notesInput.value = "";
    elements.caseSummaryInput.value = "";
    await window.ctfCompass.clearWorkspace();
    renderAll();
    switchView("workspace");
    await refreshSandboxInfo();
    persistenceReady = true;
    setStatus(STRINGS.statusWorkspaceCleared);
  } catch (error) {
    persistenceReady = true;
    setStatus(`${STRINGS.statusErrorPrefix} ${error.message}`, "error");
  }
}

async function hydrateWorkspace() {
  try {
    await window.ctfCompass.loadWorkspace();
    persistenceReady = false;
    state.artifacts = [];
    state.analysis = null;
    state.casebook = createEmptyCasebook();
    state.activeView = "workspace";
    state.workbenchFamily = "binary";
    elements.titleInput.value = "";
    elements.tagsInput.value = "";
    elements.descriptionInput.value = "";
    elements.notesInput.value = "";
    elements.caseSummaryInput.value = "";
    renderAll();
    switchView("workspace");
    persistenceReady = true;
    setStatus(STRINGS.statusWorkspaceRestored);
  } catch (error) {
    persistenceReady = true;
    setStatus(`${STRINGS.statusErrorPrefix} ${error.message}`, "error");
  }
}

function updateSandboxInfo(info) {
  if (!info) {
    return;
  }
  elements.sandboxPath.textContent = info.root || "...";
  elements.sandboxPath.title = info.root || "";
  elements.sandboxSize.textContent = `${info.sizeLabel || "0 B"} / ${info.fileCount || 0} \u4e2a\u6587\u4ef6`;
}

async function refreshSandboxInfo() {
  try {
    updateSandboxInfo(await window.ctfCompass.getSandboxInfo());
  } catch (error) {
    elements.sandboxSize.textContent = error.message;
  }
}

async function openSandboxFolder() {
  try {
    updateSandboxInfo(await window.ctfCompass.revealSandbox());
  } catch (error) {
    setStatus(`${STRINGS.statusErrorPrefix} ${error.message}`, "error");
  }
}

async function clearSandboxData() {
  if (state.isBusy) {
    return;
  }
  setBusy(true);
  try {
    const info = await window.ctfCompass.clearSandbox();
    state.artifacts = state.artifacts.filter((artifact) => artifact.sourceKind !== "generated");
    state.analysis = null;
    updateSandboxInfo(info);
    renderAll();
    setStatus(STRINGS.statusSandboxCleared);
  } catch (error) {
    setStatus(`${STRINGS.statusErrorPrefix} ${error.message}`, "error");
  } finally {
    setBusy(false);
  }
}

async function hydrateMeta() {
  const meta = await window.ctfCompass.getMeta();
  const text = `${meta.mode}  |  v${meta.version}`;
  elements.appMeta.textContent = text;
  elements.settingsRuntime.textContent = `${text}  |  sandbox: ${meta.sandboxRoot}`;
  elements.sandboxPath.textContent = meta.sandboxRoot || "...";
  elements.sandboxPath.title = meta.sandboxRoot || "";
  await refreshSandboxInfo();
}

elements.navItems.forEach((button) => {
  button.addEventListener("click", () => {
    switchView(button.dataset.view);
  });
});

elements.themeToggle.addEventListener("click", toggleTheme);
elements.settingsThemeToggle.addEventListener("click", toggleTheme);
elements.exportReportButton.addEventListener("click", exportReport);
elements.settingsExportReportButton.addEventListener("click", exportReport);
elements.clearWorkspaceButton.addEventListener("click", clearWorkspace);
elements.openSandboxButton.addEventListener("click", openSandboxFolder);
elements.clearSandboxButton.addEventListener("click", clearSandboxData);
elements.pickFilesButton.addEventListener("click", () => appendPreparedArtifacts(window.ctfCompass.pickFiles()));
elements.pickFolderButton.addEventListener("click", () => appendPreparedArtifacts(window.ctfCompass.pickFolder()));
elements.quickFilesButton.addEventListener("click", () => appendPreparedArtifacts(window.ctfCompass.pickFiles()));
elements.quickFolderButton.addEventListener("click", () => appendPreparedArtifacts(window.ctfCompass.pickFolder()));
elements.quickPasteButton.addEventListener("click", () => {
  elements.descriptionInput.focus();
  setStatus(STRINGS.statusFocusDescription);
});
elements.runAnalysisButton.addEventListener("click", runAnalysis);
elements.quickRunButton.addEventListener("click", runAnalysis);
elements.artifactDropzone.addEventListener("click", () => appendPreparedArtifacts(window.ctfCompass.pickFiles()));

[elements.titleInput, elements.tagsInput, elements.descriptionInput, elements.notesInput, elements.caseSummaryInput].forEach((input) => {
  input.addEventListener("input", () => {
    state.casebook.summary = elements.caseSummaryInput.value.trim();
    updateActionAvailability();
    scheduleWorkspaceSave();
  });
});

elements.artifactDropzone.addEventListener("dragover", (event) => {
  event.preventDefault();
  elements.artifactDropzone.classList.add("is-dragover");
});

elements.artifactDropzone.addEventListener("dragleave", () => {
  elements.artifactDropzone.classList.remove("is-dragover");
});

elements.artifactDropzone.addEventListener("drop", (event) => {
  event.preventDefault();
  elements.artifactDropzone.classList.remove("is-dragover");
  const paths = Array.from(event.dataTransfer.files || [])
    .map((file) => file.path)
    .filter(Boolean);
  if (paths.length) {
    appendPreparedArtifacts(window.ctfCompass.prepareArtifacts(paths));
  }
});

setTheme(state.theme);
applyStaticCopy();
renderAll();
setStatus(STRINGS.statusReady);
hydrateMeta().catch((error) => {
  setStatus(`${STRINGS.statusErrorPrefix} ${error.message}`, "error");
});
hydrateWorkspace();
