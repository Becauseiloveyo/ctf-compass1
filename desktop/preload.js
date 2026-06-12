const { contextBridge, ipcRenderer } = require("electron");

contextBridge.exposeInMainWorld("ctfCompass", {
  pickFiles: () => ipcRenderer.invoke("pick-files"),
  pickFolder: () => ipcRenderer.invoke("pick-folder"),
  prepareArtifacts: (paths) => ipcRenderer.invoke("prepare-artifacts", paths),
  analyzeChallenge: (payload) => ipcRenderer.invoke("analyze-challenge", payload),
  analyzeWebTarget: (payload) => ipcRenderer.invoke("analyze-web-target", payload),
  runArtifactAction: (payload) => ipcRenderer.invoke("run-artifact-action", payload),
  revealArtifact: (targetPath) => ipcRenderer.invoke("reveal-artifact", targetPath),
  loadWorkspace: () => ipcRenderer.invoke("load-workspace"),
  loadPreviousWorkspace: () => ipcRenderer.invoke("load-previous-workspace"),
  saveWorkspace: (payload) => ipcRenderer.invoke("save-workspace", payload),
  clearWorkspace: () => ipcRenderer.invoke("clear-workspace"),
  getSandboxInfo: () => ipcRenderer.invoke("sandbox-info"),
  revealSandbox: () => ipcRenderer.invoke("reveal-sandbox"),
  clearSandbox: () => ipcRenderer.invoke("clear-sandbox"),
  exportReport: (payload) => ipcRenderer.invoke("export-report", payload),
  getMeta: () => ipcRenderer.invoke("app-meta"),
});
