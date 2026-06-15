const fs = require("fs");
const path = require("path");
const { app, BrowserWindow, safeStorage, session, shell } = require("electron");

const CTF2_ORIGIN = "https://ctf2.dasctf.com";
const CTF2_PARTITION = "persist:ctf2";
const CACHE_TTL_MS = 5 * 60 * 1000;
const MAX_DOWNLOAD_BYTES = 128 * 1024 * 1024;

let loginWindow = null;
let publicPracticeCache = null;
let accessToken = null;

function connectorSession() {
  return session.fromPartition(CTF2_PARTITION);
}

function tokenPath() {
  return path.join(app.getPath("userData"), "connectors", "ctf2-token.bin");
}

function loadToken() {
  if (accessToken) {
    return accessToken;
  }
  const targetPath = tokenPath();
  if (!fs.existsSync(targetPath) || !safeStorage.isEncryptionAvailable()) {
    return null;
  }
  try {
    accessToken = safeStorage.decryptString(fs.readFileSync(targetPath));
    return accessToken;
  } catch (_error) {
    return null;
  }
}

function saveToken(token) {
  accessToken = String(token || "").trim() || null;
  const targetPath = tokenPath();
  if (!accessToken) {
    if (fs.existsSync(targetPath)) {
      fs.unlinkSync(targetPath);
    }
    return;
  }
  if (!safeStorage.isEncryptionAvailable()) {
    return;
  }
  fs.mkdirSync(path.dirname(targetPath), { recursive: true });
  fs.writeFileSync(targetPath, safeStorage.encryptString(accessToken));
}

async function captureLoginToken() {
  if (!loginWindow || loginWindow.isDestroyed()) {
    return null;
  }
  try {
    const token = await loginWindow.webContents.executeJavaScript("localStorage.getItem('token')", true);
    if (token) {
      saveToken(token);
    }
    return token || null;
  } catch (_error) {
    return null;
  }
}

function sanitizeSegment(value, fallback = "challenge") {
  const normalized = String(value || "")
    .replace(/[<>:"/\\|?*\x00-\x1f]/g, "-")
    .replace(/\s+/g, " ")
    .trim()
    .slice(0, 80);
  return normalized || fallback;
}

function plainText(value) {
  return String(value || "")
    .replace(/<br\s*\/?>/gi, "\n")
    .replace(/<[^>]+>/g, " ")
    .replace(/[ \t]+\n/g, "\n")
    .replace(/\n{3,}/g, "\n\n")
    .trim();
}

function unwrapApiPayload(payload) {
  if (payload && typeof payload === "object" && payload.success === true && "data" in payload) {
    return payload.data;
  }
  return payload;
}

async function requestJson(urlPath, options = {}) {
  const token = options.tokenOverride === undefined ? loadToken() : String(options.tokenOverride || "").trim();
  const response = await connectorSession().fetch(`${CTF2_ORIGIN}${urlPath}`, {
    method: options.method || "GET",
    headers: {
      Accept: "application/json",
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
      ...(options.headers || {}),
    },
    body: options.body,
  });
  const refreshedToken = response.headers.get("x-new-token");
  if (refreshedToken && options.saveRefreshedToken !== false) {
    saveToken(refreshedToken);
  }
  const text = await response.text();
  let payload = null;
  try {
    payload = text ? JSON.parse(text) : null;
  } catch (_error) {
    payload = text;
  }
  if (!response.ok) {
    const message =
      payload?.error?.details ||
      payload?.error?.message ||
      payload?.message ||
      `CTF2 request failed (${response.status})`;
    const error = new Error(String(message));
    error.status = response.status;
    throw error;
  }
  return unwrapApiPayload(payload);
}

function normalizeImportedToken(value) {
  let token = String(value || "").trim();
  if (!token) {
    throw new Error("请粘贴 CTF2 登录令牌。");
  }
  if (token.length > 16 * 1024) {
    throw new Error("登录令牌内容过长，请确认没有粘贴整段网页内容。");
  }
  if ((token.startsWith('"') && token.endsWith('"')) || (token.startsWith("'") && token.endsWith("'"))) {
    try {
      token = JSON.parse(token);
    } catch (_error) {
      token = token.slice(1, -1);
    }
  }
  if (token && typeof token === "object") {
    token = token.token || token.accessToken || token.access_token || "";
  }
  token = String(token || "").trim().replace(/^Bearer\s+/i, "");
  if (!token || /\s/.test(token)) {
    throw new Error("登录令牌格式无效，请只粘贴 localStorage 中的 token 值。");
  }
  return token;
}

async function importToken(value) {
  const token = normalizeImportedToken(value);
  const profile = await requestJson("/api/v1/users/profile/", {
    tokenOverride: token,
    saveRefreshedToken: false,
  });
  if (!profile || typeof profile !== "object" || Array.isArray(profile)) {
    throw new Error("CTF2 未返回有效用户资料，请重新登录后复制最新 token。");
  }
  saveToken(token);
  const status = await getStatus();
  if (!status.connected) {
    saveToken(null);
    throw new Error("CTF2 token 验证失败或已经过期，请重新登录后再试。");
  }
  return status;
}

async function getStatus() {
  const cookies = await connectorSession().cookies.get({ url: CTF2_ORIGIN });
  await captureLoginToken();
  let profile = null;
  try {
    profile = await requestJson("/api/v1/users/profile/");
  } catch (error) {
    if (error.status !== 401 && error.status !== 403) {
      return {
        connected: false,
        cookieCount: cookies.length,
        error: error.message,
      };
    }
  }
  return {
    connected: Boolean(profile),
    cookieCount: cookies.length,
    profile: profile
      ? {
          id: profile.id || profile.user_id || "",
          username: profile.username || profile.nickname || profile.name || "",
          avatar: profile.avatar || "",
        }
      : null,
  };
}

async function openLogin(parentWindow) {
  if (loginWindow && !loginWindow.isDestroyed()) {
    loginWindow.focus();
    return { opened: true, reused: true };
  }

  loginWindow = new BrowserWindow({
    parent: parentWindow || undefined,
    width: 1120,
    height: 820,
    minWidth: 900,
    minHeight: 680,
    title: "登录 CTF2",
    autoHideMenuBar: true,
    webPreferences: {
      partition: CTF2_PARTITION,
      contextIsolation: true,
      nodeIntegration: false,
      sandbox: true,
    },
  });
  loginWindow.webContents.setWindowOpenHandler(({ url }) => {
    if (url.startsWith(CTF2_ORIGIN)) {
      return { action: "allow" };
    }
    shell.openExternal(url);
    return { action: "deny" };
  });
  loginWindow.on("closed", () => {
    loginWindow = null;
  });
  loginWindow.on("close", () => {
    captureLoginToken().catch(() => {});
  });
  loginWindow.webContents.on("did-navigate", () => {
    captureLoginToken().catch(() => {});
  });
  loginWindow.webContents.on("did-navigate-in-page", () => {
    captureLoginToken().catch(() => {});
  });
  await loginWindow.loadURL(`${CTF2_ORIGIN}/login`);
  return { opened: true, reused: false };
}

async function logout() {
  try {
    await requestJson("/api/v1/auth/logout/", { method: "POST" });
  } catch (_error) {
    // Clearing the isolated session is authoritative even if the API session expired.
  }
  await connectorSession().clearStorageData();
  saveToken(null);
  return getStatus();
}

async function openSystemLogin() {
  await shell.openExternal(`${CTF2_ORIGIN}/login`);
  return { opened: true };
}

function flattenPracticeGrounds(payload) {
  const data = unwrapApiPayload(payload);
  const grounds = Array.isArray(data) ? data : Array.isArray(data?.data) ? data.data : [];
  return grounds.flatMap((ground) =>
    (Array.isArray(ground.challenges) ? ground.challenges : []).map((challenge) => ({
      id: challenge.id,
      friendlyId: challenge.friendly_id || "",
      groundId: ground.id,
      groundName: ground.name || "",
      name: challenge.name || "Unnamed challenge",
      category: challenge.category || "OTHER",
      difficulty: challenge.difficulty || "",
      description: plainText(challenge.description),
      points: Number(challenge.points || 0),
      solveCount: Number(challenge.solve_count || 0),
      hasContainer: Boolean(challenge.has_container),
      files: (Array.isArray(challenge.files) ? challenge.files : []).map((file) => ({
        id: file.id,
        name: file.file_name || "attachment.bin",
        size: Number(file.file_size || 0),
        type: file.file_type || "",
      })),
    })),
  );
}

async function fetchPublicChallenges(force = false) {
  if (!force && publicPracticeCache && Date.now() - publicPracticeCache.createdAt < CACHE_TTL_MS) {
    return publicPracticeCache.challenges;
  }
  // Public practice can be browsed without a login token. Do not send a stale token here;
  // otherwise an expired token can break read-only browsing even though the endpoint is public.
  const payload = await requestJson("/api/v1/public/practice/", { tokenOverride: "" });
  const challenges = flattenPracticeGrounds(payload);
  publicPracticeCache = { createdAt: Date.now(), challenges };
  return challenges;
}

async function listChallenges(filters = {}) {
  const query = String(filters.query || "").trim().toLowerCase();
  const category = String(filters.category || "").trim().toLowerCase();
  const ground = String(filters.ground || "BUUCTF").trim().toLowerCase();
  const limit = Math.max(1, Math.min(500, Number(filters.limit || 120)));
  const all = await fetchPublicChallenges(Boolean(filters.force));
  const filtered = all.filter((challenge) => {
    if (ground && challenge.groundName.toLowerCase() !== ground) {
      return false;
    }
    if (category && category !== "all" && challenge.category.toLowerCase() !== category) {
      return false;
    }
    if (!query) {
      return true;
    }
    return [challenge.name, challenge.category, challenge.description, challenge.friendlyId]
      .join("\n")
      .toLowerCase()
      .includes(query);
  });
  const sorted = filtered.sort((left, right) => right.solveCount - left.solveCount || left.name.localeCompare(right.name));
  return {
    total: filtered.length,
    challenges: sorted.slice(0, limit),
    categories: Array.from(new Set(all.filter((item) => !ground || item.groundName.toLowerCase() === ground).map((item) => item.category))).sort(),
  };
}

async function downloadFile(challenge, file, downloadRoot) {
  const token = loadToken();
  const url = `/api/v1/practice/${encodeURIComponent(challenge.groundId)}/challenges/${encodeURIComponent(challenge.id)}/files/${encodeURIComponent(file.id)}/?is_private=false`;
  const response = await connectorSession().fetch(`${CTF2_ORIGIN}${url}`, {
    headers: {
      Accept: "application/octet-stream",
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
    },
  });
  if (!response.ok) {
    const error = new Error(response.status === 401 ? "请先连接 CTF2，可使用应用内登录或浏览器令牌导入。" : `附件下载失败 (${response.status})`);
    error.status = response.status;
    throw error;
  }
  const declaredLength = Number(response.headers.get("content-length") || 0);
  if (declaredLength > MAX_DOWNLOAD_BYTES) {
    throw new Error(`附件超过 ${Math.round(MAX_DOWNLOAD_BYTES / 1024 / 1024)} MB 安全限制。`);
  }
  const bytes = Buffer.from(await response.arrayBuffer());
  if (bytes.length > MAX_DOWNLOAD_BYTES) {
    throw new Error(`附件超过 ${Math.round(MAX_DOWNLOAD_BYTES / 1024 / 1024)} MB 安全限制。`);
  }
  fs.mkdirSync(downloadRoot, { recursive: true });
  const targetPath = path.join(downloadRoot, sanitizeSegment(file.name, `attachment-${file.id}`));
  fs.writeFileSync(targetPath, bytes);
  return targetPath;
}

async function importChallenge(input, sandboxDownloadsRoot) {
  const challenges = await fetchPublicChallenges();
  const challenge = challenges.find((item) => item.id === input?.challengeId && item.groundId === input?.groundId);
  if (!challenge) {
    throw new Error("没有在 CTF2 公共题库中找到该题目，请刷新题库后重试。");
  }
  if (!challenge.files.length) {
    throw new Error("该题目没有可下载附件；靶机题需要在 CTF2 页面中手动启动环境。");
  }
  const status = await getStatus();
  if (!status.connected) {
    throw new Error("附件下载需要连接 CTF2，请先使用应用内登录或浏览器令牌导入。");
  }

  const challengeRoot = path.join(
    sandboxDownloadsRoot,
    "ctf2",
    `${sanitizeSegment(challenge.name)}-${sanitizeSegment(challenge.friendlyId || challenge.id.slice(0, 8))}`,
  );
  const paths = [];
  for (const file of challenge.files) {
    paths.push(await downloadFile(challenge, file, challengeRoot));
  }
  const metadataPath = path.join(challengeRoot, "ctf2-challenge.json");
  fs.writeFileSync(metadataPath, `${JSON.stringify(challenge, null, 2)}\n`, "utf8");
  return { challenge, paths, metadataPath };
}

module.exports = {
  getStatus,
  importToken,
  importChallenge,
  listChallenges,
  logout,
  openLogin,
  openSystemLogin,
};
