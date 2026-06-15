const fs = require("fs");
const https = require("https");
const { app, BrowserWindow, dialog, ipcMain, screen, shell } = require("electron");
const path = require("path");
const { analyzeChallenge, prepareArtifactsFromEntries, runArtifactAction } = require("./analyzer");
const { analyzeWebTarget } = require("./web-analyzer");
const ctf2Connector = require("./ctf2-connector");

const isDev = !app.isPackaged;
const SANDBOX_DIR_NAME = "sandbox";
const UPDATE_RELEASE_API = "https://api.github.com/repos/Becauseiloveyo/ctf-compass1/releases/latest";

function getInitialWindowBounds() {
  const { width, height } = screen.getPrimaryDisplay().workAreaSize;
  return {
    width: Math.min(width, Math.max(1120, Math.round(width * 0.9))),
    height: Math.min(height, Math.max(720, Math.round(height * 0.9))),
  };
}

function createWindow() {
  const initialBounds = getInitialWindowBounds();
  const mainWindow = new BrowserWindow({
    ...initialBounds,
    minWidth: 980,
    minHeight: 680,
    backgroundColor: "#f7f7f4",
    title: "CTF Compass",
    autoHideMenuBar: true,
    show: false,
    webPreferences: {
      preload: path.join(__dirname, "preload.js"),
      contextIsolation: true,
      nodeIntegration: false,
    },
  });

  mainWindow.once("ready-to-show", () => {
    mainWindow.show();
  });

  mainWindow.loadFile(path.join(__dirname, "renderer", "index.html"));
}

function buildRunOutputRoot() {
  return path.join(sandboxRootPath(), "generated", `analysis-${Date.now()}`);
}

function sandboxRootPath() {
  return path.join(app.getPath("userData"), SANDBOX_DIR_NAME);
}

function sandboxSubPath(name) {
  return path.join(sandboxRootPath(), name);
}

function workspaceFilePath() {
  return path.join(sandboxRootPath(), "session", "current-session.json");
}

function ctf2RootPath() {
  return path.join(sandboxSubPath("downloads"), "ctf2");
}

function ctf2HistoryPath() {
  return path.join(sandboxSubPath("session"), "ctf2-import-history.json");
}

function ensureParentDir(targetPath) {
  fs.mkdirSync(path.dirname(targetPath), { recursive: true });
}

function ensureSandboxLayout() {
  ["generated", "downloads", "tools", "session"].forEach((name) => {
    fs.mkdirSync(sandboxSubPath(name), { recursive: true });
  });
}

function formatBytes(size) {
  if (size < 1024) return `${size} B`;
  if (size < 1024 * 1024) return `${(size / 1024).toFixed(1)} KB`;
  if (size < 1024 * 1024 * 1024) return `${(size / (1024 * 1024)).toFixed(1)} MB`;
  return `${(size / (1024 * 1024 * 1024)).toFixed(1)} GB`;
}

function measureDirectory(rootPath) {
  if (!fs.existsSync(rootPath)) {
    return { bytes: 0, files: 0 };
  }
  const stack = [rootPath];
  let bytes = 0;
  let files = 0;
  while (stack.length) {
    const current = stack.pop();
    let stat;
    try {
      stat = fs.statSync(current);
    } catch (_error) {
      continue;
    }
    if (stat.isDirectory()) {
      fs.readdirSync(current).forEach((name) => stack.push(path.join(current, name)));
      continue;
    }
    if (stat.isFile()) {
      bytes += stat.size;
      files += 1;
    }
  }
  return { bytes, files };
}

function clearSessionWorkspace() {
  const targetPath = workspaceFilePath();
  if (fs.existsSync(targetPath)) {
    fs.unlinkSync(targetPath);
  }
}

function cleanupLegacyRuntimeData() {
  ["generated", "workspace"].forEach((name) => {
    const legacyPath = path.join(app.getPath("userData"), name);
    if (fs.existsSync(legacyPath)) {
      fs.rmSync(legacyPath, { recursive: true, force: true });
    }
  });
}

function getSandboxInfo() {
  ensureSandboxLayout();
  const size = measureDirectory(sandboxRootPath());
  return {
    root: sandboxRootPath(),
    generated: sandboxSubPath("generated"),
    downloads: sandboxSubPath("downloads"),
    ctf2Downloads: ctf2RootPath(),
    tools: sandboxSubPath("tools"),
    session: sandboxSubPath("session"),
    bytes: size.bytes,
    sizeLabel: formatBytes(size.bytes),
    fileCount: size.files,
  };
}

function readCtf2History() {
  ensureSandboxLayout();
  const targetPath = ctf2HistoryPath();
  if (!fs.existsSync(targetPath)) {
    return [];
  }
  try {
    const parsed = JSON.parse(fs.readFileSync(targetPath, "utf8"));
    return Array.isArray(parsed) ? parsed : [];
  } catch (_error) {
    return [];
  }
}

function writeCtf2History(history) {
  const targetPath = ctf2HistoryPath();
  ensureParentDir(targetPath);
  fs.writeFileSync(targetPath, `${JSON.stringify(history.slice(0, 30), null, 2)}\n`, "utf8");
}

function recordCtf2Import(imported, artifacts) {
  const challenge = imported.challenge || {};
  const history = readCtf2History();
  const entry = {
    importedAt: new Date().toISOString(),
    id: challenge.id || "",
    friendlyId: challenge.friendlyId || "",
    name: challenge.name || "Unnamed challenge",
    category: challenge.category || "",
    groundName: challenge.groundName || "",
    attachmentCount: Array.isArray(artifacts) ? artifacts.length : 0,
    paths: imported.paths || [],
    metadataPath: imported.metadataPath || "",
    analyzed: false,
  };
  writeCtf2History([entry, ...history.filter((item) => item.id !== entry.id || item.groundName !== entry.groundName)]);
  return entry;
}

function clearCtf2Data() {
  const root = ctf2RootPath();
  if (fs.existsSync(root)) {
    fs.rmSync(root, { recursive: true, force: true });
  }
  const historyPath = ctf2HistoryPath();
  if (fs.existsSync(historyPath)) {
    fs.unlinkSync(historyPath);
  }
  fs.mkdirSync(root, { recursive: true });
  return {
    cleared: true,
    root,
    history: [],
    size: measureDirectory(root),
  };
}

function fetchJson(url) {
  return new Promise((resolve, reject) => {
    const request = https.get(
      url,
      {
        headers: {
          Accept: "application/vnd.github+json",
          "User-Agent": "CTF-Compass-Updater",
        },
        timeout: 8000,
      },
      (response) => {
        const chunks = [];
        response.on("data", (chunk) => chunks.push(chunk));
        response.on("end", () => {
          const body = Buffer.concat(chunks).toString("utf8");
          let payload = null;
          try {
            payload = body ? JSON.parse(body) : null;
          } catch (_error) {
            payload = { message: body };
          }
          if (response.statusCode < 200 || response.statusCode >= 300) {
            reject(new Error(payload?.message || `GitHub release check failed (${response.statusCode})`));
            return;
          }
          resolve(payload);
        });
      },
    );
    request.on("timeout", () => request.destroy(new Error("检查更新超时。")));
    request.on("error", reject);
  });
}

function versionParts(value) {
  return String(value || "")
    .replace(/^v/i, "")
    .split(/[.-]/)
    .slice(0, 3)
    .map((part) => Number.parseInt(part, 10) || 0);
}

function compareVersions(left, right) {
  const a = versionParts(left);
  const b = versionParts(right);
  for (let index = 0; index < 3; index += 1) {
    if ((a[index] || 0) > (b[index] || 0)) return 1;
    if ((a[index] || 0) < (b[index] || 0)) return -1;
  }
  return 0;
}

async function checkForUpdates() {
  const currentVersion = app.getVersion();
  const release = await fetchJson(UPDATE_RELEASE_API);
  const latestVersion = String(release.tag_name || release.name || "").replace(/^v/i, "");
  return {
    currentVersion,
    latestVersion,
    hasUpdate: compareVersions(latestVersion, currentVersion) > 0,
    name: release.name || release.tag_name || "",
    url: release.html_url || "https://github.com/Becauseiloveyo/ctf-compass1/releases/latest",
    publishedAt: release.published_at || "",
    assetCount: Array.isArray(release.assets) ? release.assets.length : 0,
  };
}

async function selectFiles() {
  const result = await dialog.showOpenDialog({
    title: "Select challenge files",
    properties: ["openFile", "multiSelections"],
  });
  if (result.canceled) return [];
  return prepareArtifactsFromEntries(result.filePaths);
}

async function selectFolder() {
  const result = await dialog.showOpenDialog({
    title: "Select challenge folder",
    properties: ["openDirectory"],
  });
  if (result.canceled || !result.filePaths.length) return [];
  return prepareArtifactsFromEntries(result.filePaths);
}

ipcMain.handle("pick-files", async () => selectFiles());
ipcMain.handle("pick-folder", async () => selectFolder());
ipcMain.handle("prepare-artifacts", async (_event, entryPaths) => prepareArtifactsFromEntries(entryPaths || []));
ipcMain.handle("analyze-challenge", async (_event, payload) => analyzeChallenge(payload || {}, buildRunOutputRoot()));
ipcMain.handle("analyze-web-target", async (_event, payload) => analyzeWebTarget(payload || {}, buildRunOutputRoot()));
ipcMain.handle("ctf2-status", async () => ctf2Connector.getStatus());
ipcMain.handle("ctf2-login", async (event) => ctf2Connector.openLogin(BrowserWindow.fromWebContents(event.sender)));
ipcMain.handle("ctf2-open-system-login", async () => ctf2Connector.openSystemLogin());
ipcMain.handle("ctf2-import-token", async (_event, token) => ctf2Connector.importToken(token));
ipcMain.handle("ctf2-logout", async () => ctf2Connector.logout());
ipcMain.handle("ctf2-list-challenges", async (_event, payload) => ctf2Connector.listChallenges(payload || {}));
ipcMain.handle("ctf2-import-challenge", async (_event, payload) => {
  const imported = await ctf2Connector.importChallenge(payload || {}, sandboxSubPath("downloads"));
  const artifacts = prepareArtifactsFromEntries(imported.paths);
  const historyEntry = recordCtf2Import(imported, artifacts);
  return { ...imported, artifacts, historyEntry };
});
ipcMain.handle("ctf2-history", async () => readCtf2History());
ipcMain.handle("ctf2-clear-data", async () => clearCtf2Data());
ipcMain.handle("ctf2-reveal-downloads", async () => {
  const root = ctf2RootPath();
  fs.mkdirSync(root, { recursive: true });
  await shell.openPath(root);
  return { root };
});
ipcMain.handle("run-artifact-action", async (_event, payload) =>
  runArtifactAction(payload?.actionId, payload?.filePath, buildRunOutputRoot()),
);
ipcMain.handle("reveal-artifact", async (_event, targetPath) => {
  if (targetPath) shell.showItemInFolder(targetPath);
});
ipcMain.handle("open-external", async (_event, url) => {
  const target = String(url || "");
  if (!/^https:\/\/github\.com\/Becauseiloveyo\/ctf-compass1\/releases\/?/i.test(target)) {
    throw new Error("只允许打开 CTF Compass 的 GitHub Releases 页面。");
  }
  await shell.openExternal(target);
  return { opened: true };
});
ipcMain.handle("check-for-updates", async () => checkForUpdates());
ipcMain.handle("load-workspace", async () => {
  ensureSandboxLayout();
  cleanupLegacyRuntimeData();
  clearSessionWorkspace();
  return null;
});
ipcMain.handle("load-previous-workspace", async () => {
  const targetPath = workspaceFilePath();
  if (!fs.existsSync(targetPath)) return null;
  return JSON.parse(fs.readFileSync(targetPath, "utf8"));
});
ipcMain.handle("save-workspace", async (_event, payload) => {
  const targetPath = workspaceFilePath();
  ensureParentDir(targetPath);
  fs.writeFileSync(targetPath, `${JSON.stringify(payload || {}, null, 2)}\n`, "utf8");
  return { path: targetPath };
});
ipcMain.handle("clear-workspace", async () => {
  const targetPath = workspaceFilePath();
  if (fs.existsSync(targetPath)) fs.unlinkSync(targetPath);
  return { cleared: true };
});
ipcMain.handle("sandbox-info", async () => getSandboxInfo());
ipcMain.handle("reveal-sandbox", async () => {
  const info = getSandboxInfo();
  await shell.openPath(info.root);
  return info;
});
ipcMain.handle("clear-sandbox", async () => {
  const root = sandboxRootPath();
  if (fs.existsSync(root)) {
    fs.rmSync(root, { recursive: true, force: true });
  }
  ensureSandboxLayout();
  return getSandboxInfo();
});
ipcMain.handle("export-report", async (_event, payload) => {
  const suggestedName = String(payload?.suggestedName || "ctf-compass-report.md");
  const content = String(payload?.content || "");
  const result = await dialog.showSaveDialog({
    title: "Export Markdown report",
    defaultPath: path.join(app.getPath("documents"), suggestedName),
    filters: [
      { name: "Markdown", extensions: ["md"] },
      { name: "Text", extensions: ["txt"] },
    ],
  });
  if (result.canceled || !result.filePath) return { canceled: true };
  ensureParentDir(result.filePath);
  fs.writeFileSync(result.filePath, content, "utf8");
  return { filePath: result.filePath };
});
ipcMain.handle("app-meta", async () => ({
  version: app.getVersion(),
  packaged: app.isPackaged,
  mode: isDev ? "development" : "production",
  sandboxRoot: sandboxRootPath(),
}));

app.whenReady().then(() => {
  ensureSandboxLayout();
  cleanupLegacyRuntimeData();
  clearSessionWorkspace();
  createWindow();

  app.on("activate", () => {
    if (BrowserWindow.getAllWindows().length === 0) createWindow();
  });
});

app.on("window-all-closed", () => {
  if (process.platform !== "darwin") app.quit();
});
