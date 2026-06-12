const fs = require("fs");
const { app, BrowserWindow, dialog, ipcMain, shell } = require("electron");
const path = require("path");
const { analyzeChallenge, prepareArtifactsFromEntries, runArtifactAction } = require("./analyzer");
const { analyzeWebTarget } = require("./web-analyzer");

const isDev = !app.isPackaged;
const SANDBOX_DIR_NAME = "sandbox";

function createWindow() {
  const mainWindow = new BrowserWindow({
    width: 1500,
    height: 980,
    minWidth: 1240,
    minHeight: 780,
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

function ensureParentDir(targetPath) {
  fs.mkdirSync(path.dirname(targetPath), { recursive: true });
}

function ensureSandboxLayout() {
  ["generated", "downloads", "tools", "session"].forEach((name) => {
    fs.mkdirSync(sandboxSubPath(name), { recursive: true });
  });
}

function formatBytes(size) {
  if (size < 1024) {
    return `${size} B`;
  }
  if (size < 1024 * 1024) {
    return `${(size / 1024).toFixed(1)} KB`;
  }
  if (size < 1024 * 1024 * 1024) {
    return `${(size / (1024 * 1024)).toFixed(1)} MB`;
  }
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
    tools: sandboxSubPath("tools"),
    session: sandboxSubPath("session"),
    bytes: size.bytes,
    sizeLabel: formatBytes(size.bytes),
    fileCount: size.files,
  };
}

async function selectFiles() {
  const result = await dialog.showOpenDialog({
    title: "Select challenge files",
    properties: ["openFile", "multiSelections"],
  });

  if (result.canceled) {
    return [];
  }

  return prepareArtifactsFromEntries(result.filePaths);
}

async function selectFolder() {
  const result = await dialog.showOpenDialog({
    title: "Select challenge folder",
    properties: ["openDirectory"],
  });

  if (result.canceled || !result.filePaths.length) {
    return [];
  }

  return prepareArtifactsFromEntries(result.filePaths);
}

ipcMain.handle("pick-files", async () => selectFiles());
ipcMain.handle("pick-folder", async () => selectFolder());
ipcMain.handle("prepare-artifacts", async (_event, entryPaths) => prepareArtifactsFromEntries(entryPaths || []));
ipcMain.handle("analyze-challenge", async (_event, payload) => analyzeChallenge(payload || {}, buildRunOutputRoot()));
ipcMain.handle("analyze-web-target", async (_event, payload) => analyzeWebTarget(payload || {}, buildRunOutputRoot()));
ipcMain.handle("run-artifact-action", async (_event, payload) =>
  runArtifactAction(payload?.actionId, payload?.filePath, buildRunOutputRoot()),
);
ipcMain.handle("reveal-artifact", async (_event, targetPath) => {
  if (targetPath) {
    shell.showItemInFolder(targetPath);
  }
});
ipcMain.handle("load-workspace", async () => {
  ensureSandboxLayout();
  cleanupLegacyRuntimeData();
  clearSessionWorkspace();
  return null;
});
ipcMain.handle("load-previous-workspace", async () => {
  const targetPath = workspaceFilePath();
  if (!fs.existsSync(targetPath)) {
    return null;
  }

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
  if (fs.existsSync(targetPath)) {
    fs.unlinkSync(targetPath);
  }
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

  if (result.canceled || !result.filePath) {
    return { canceled: true };
  }

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
    if (BrowserWindow.getAllWindows().length === 0) {
      createWindow();
    }
  });
});

app.on("window-all-closed", () => {
  if (process.platform !== "darwin") {
    app.quit();
  }
});
