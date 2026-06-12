const dns = require("dns").promises;
const fs = require("fs");
const net = require("net");
const path = require("path");
const { analyzeChallenge } = require("./analyzer");

const DEFAULT_LIMITS = {
  maxPages: 24,
  maxDepth: 2,
  maxBodyBytes: 1024 * 1024,
  maxDurationMs: 25_000,
  requestTimeoutMs: 6_000,
};

const COMMON_CTF_PATHS = [
  "/robots.txt",
  "/sitemap.xml",
  "/.well-known/security.txt",
  "/flag",
  "/flag.txt",
  "/admin",
  "/debug",
  "/source",
  "/backup.zip",
  "/.git/HEAD",
];

const FLAG_PATTERNS = [
  /\b(?:flag|ctf|key|answer|picoCTF|moectf|actf|hitcon|sekai|balsn|uiuctf|n1ctf)\{[^{}\r\n]{3,160}\}/gi,
  /\b[a-zA-Z0-9_]{2,32}\{[^{}\r\n]{3,160}\}/g,
  /\bFLAG[-_:][A-Za-z0-9_./+=-]{6,160}\b/g,
];

function dedupe(values) {
  return Array.from(new Set(values.filter(Boolean)));
}

function isPrivateIPv4(address) {
  const parts = address.split(".").map(Number);
  if (parts.length !== 4 || parts.some((item) => !Number.isInteger(item) || item < 0 || item > 255)) return false;
  return (
    parts[0] === 10 ||
    parts[0] === 127 ||
    (parts[0] === 169 && parts[1] === 254) ||
    (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) ||
    (parts[0] === 192 && parts[1] === 168)
  );
}

function isPrivateIPv6(address) {
  const normalized = address.toLowerCase().split("%")[0];
  return normalized === "::1" || normalized.startsWith("fc") || normalized.startsWith("fd") || /^fe[89ab]/.test(normalized);
}

function isPrivateAddress(address) {
  const version = net.isIP(address);
  return version === 4 ? isPrivateIPv4(address) : version === 6 ? isPrivateIPv6(address) : false;
}

async function validateLocalTarget(targetUrl) {
  let parsed;
  try {
    parsed = new URL(String(targetUrl || "").trim());
  } catch (_error) {
    throw new Error("请输入完整 URL，例如 http://127.0.0.1:3000。");
  }
  if (!["http:", "https:"].includes(parsed.protocol)) {
    throw new Error("Web 分析仅支持 HTTP/HTTPS。");
  }
  if (parsed.username || parsed.password) {
    throw new Error("URL 中不能包含账号或密码，请使用靶场自身登录流程。");
  }
  const host = parsed.hostname.toLowerCase();
  let addresses = [];
  if (host === "localhost" || host.endsWith(".localhost")) {
    addresses = ["127.0.0.1"];
  } else if (net.isIP(host)) {
    addresses = [host];
  } else {
    try {
      addresses = (await dns.lookup(host, { all: true, verbatim: true })).map((entry) => entry.address);
    } catch (error) {
      throw new Error(`无法解析目标主机：${error.message}`);
    }
  }
  if (!addresses.length || addresses.some((address) => !isPrivateAddress(address))) {
    throw new Error("主动 Web 分析仅允许 localhost、回环地址和私有网段靶机。");
  }
  parsed.hash = "";
  return { url: parsed, addresses: dedupe(addresses) };
}

function isTextContentType(contentType) {
  return /(?:text\/|json|javascript|xml|x-www-form-urlencoded|svg)/i.test(contentType || "");
}

async function readResponseBody(response, maxBytes) {
  if (!response.body) return Buffer.alloc(0);
  const reader = response.body.getReader();
  const chunks = [];
  let size = 0;
  while (size < maxBytes) {
    const { done, value } = await reader.read();
    if (done) break;
    const chunk = Buffer.from(value);
    const remaining = maxBytes - size;
    chunks.push(chunk.subarray(0, remaining));
    size += Math.min(chunk.length, remaining);
    if (chunk.length > remaining) {
      await reader.cancel();
      break;
    }
  }
  return Buffer.concat(chunks);
}

function normalizeCandidateUrl(value, baseUrl, origin) {
  const candidate = String(value || "").trim().replace(/&amp;/gi, "&");
  if (!candidate || /^(?:data|javascript|mailto|tel):/i.test(candidate)) return null;
  try {
    const parsed = new URL(candidate, baseUrl);
    parsed.hash = "";
    if (!["http:", "https:"].includes(parsed.protocol) || parsed.origin !== origin) return null;
    return parsed.href;
  } catch (_error) {
    return null;
  }
}

function extractFlagCandidates(text, source) {
  const candidates = [];
  FLAG_PATTERNS.forEach((pattern) => {
    for (const match of String(text || "").matchAll(pattern)) {
      candidates.push({ value: match[0].trim(), source });
    }
  });
  return candidates;
}

function extractWebClues(text, pageUrl, contentType, origin) {
  const urls = [];
  const comments = [];
  const forms = [];
  const routeCandidates = [];
  const sourceMaps = [];
  const addUrl = (value) => {
    const normalized = normalizeCandidateUrl(value, pageUrl, origin);
    if (normalized) urls.push(normalized);
  };

  if (/html|xml|svg/i.test(contentType)) {
    for (const match of text.matchAll(/<!--([\s\S]*?)-->/g)) {
      const value = match[1].trim();
      if (value) comments.push(value.slice(0, 500));
    }
    for (const match of text.matchAll(/\b(?:href|src|action)\s*=\s*["']([^"'#]+)["']/gi)) addUrl(match[1]);
    for (const match of text.matchAll(/<form\b([^>]*)>/gi)) {
      const action = /\baction\s*=\s*["']([^"']+)["']/i.exec(match[1])?.[1] || pageUrl;
      const method = /\bmethod\s*=\s*["']([^"']+)["']/i.exec(match[1])?.[1] || "GET";
      forms.push(`${method.toUpperCase()} ${normalizeCandidateUrl(action, pageUrl, origin) || action}`);
    }
  }

  for (const match of text.matchAll(/(?:sourceMappingURL=|["'`](\/[^"'`\s]{1,240}))[^\r\n]*/g)) {
    const value = match[1] || match[0].replace(/^.*sourceMappingURL=/, "").trim();
    const normalized = normalizeCandidateUrl(value, pageUrl, origin);
    if (normalized) {
      if (/sourceMappingURL=/.test(match[0])) sourceMaps.push(normalized);
      else routeCandidates.push(normalized);
      urls.push(normalized);
    }
  }
  for (const match of text.matchAll(/\b(?:fetch|axios\.(?:get|post)|open)\s*\(\s*["'`]([^"'`]+)["'`]/gi)) addUrl(match[1]);
  for (const match of text.matchAll(/(?:^|\s)(\/(?:api|admin|debug|internal|hidden|secret|flag|backup|source)[A-Za-z0-9_./?=&%-]*)/gi)) {
    const normalized = normalizeCandidateUrl(match[1], pageUrl, origin);
    if (normalized) routeCandidates.push(normalized);
  }
  if (/robots\.txt$/i.test(new URL(pageUrl).pathname)) {
    for (const match of text.matchAll(/^(?:Allow|Disallow|Sitemap):\s*(\S+)/gim)) addUrl(match[1]);
  }
  if (/sitemap\.xml$/i.test(new URL(pageUrl).pathname)) {
    for (const match of text.matchAll(/<loc>([^<]+)<\/loc>/gi)) addUrl(match[1]);
  }

  return {
    urls: dedupe(urls),
    comments: dedupe(comments).slice(0, 30),
    forms: dedupe(forms).slice(0, 30),
    routeCandidates: dedupe(routeCandidates).slice(0, 80),
    sourceMaps: dedupe(sourceMaps).slice(0, 20),
  };
}

function headerObject(headers) {
  const result = {};
  headers.forEach((value, key) => {
    result[key] = value;
  });
  return result;
}

async function fetchLocalPage(url, origin, limits) {
  let current = new URL(url);
  for (let redirect = 0; redirect < 5; redirect += 1) {
    await validateLocalTarget(current.href);
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), limits.requestTimeoutMs);
    let response;
    try {
      response = await fetch(current, {
        method: "GET",
        redirect: "manual",
        signal: controller.signal,
        headers: {
          Accept: "text/html,application/xhtml+xml,application/json,text/plain,application/javascript,*/*;q=0.4",
          "User-Agent": "CTF-Compass-Local-Web-Analyzer/0.6",
        },
      });
    } catch (error) {
      clearTimeout(timer);
      throw new Error(error.name === "AbortError" ? "请求超时" : error.message);
    }
    clearTimeout(timer);
    if (response.status >= 300 && response.status < 400 && response.headers.get("location")) {
      const next = new URL(response.headers.get("location"), current);
      if (next.origin !== origin) throw new Error("目标重定向到了范围外地址，已停止。");
      current = next;
      continue;
    }
    const body = await readResponseBody(response, limits.maxBodyBytes);
    return {
      url: current.href,
      status: response.status,
      contentType: response.headers.get("content-type") || "",
      headers: headerObject(response.headers),
      body,
      truncated: Number(response.headers.get("content-length") || 0) > body.length,
    };
  }
  throw new Error("重定向次数超过限制。");
}

function buildPageFindings(page, clues) {
  const findings = [];
  const headers = page.headers;
  const text = page.text || "";
  if (clues.comments.length) findings.push(`${page.url}：发现 ${clues.comments.length} 条 HTML 注释。`);
  if (clues.forms.length) findings.push(`${page.url}：发现表单 ${clues.forms.join(" / ")}`);
  if (clues.sourceMaps.length) findings.push(`${page.url}：发现 source map ${clues.sourceMaps.join(" / ")}`);
  if (clues.routeCandidates.length) findings.push(`${page.url}：发现可疑路由 ${clues.routeCandidates.slice(0, 6).join(" / ")}`);
  if (headers["set-cookie"]) findings.push(`${page.url}：响应设置 Cookie，需检查 HttpOnly / Secure / SameSite 与会话边界。`);
  if (headers.server || headers["x-powered-by"]) {
    findings.push(`${page.url}：技术栈头 ${headers.server || ""} ${headers["x-powered-by"] || ""}`.trim());
  }
  if (!headers["content-security-policy"] && /html/i.test(page.contentType)) findings.push(`${page.url}：未发现 Content-Security-Policy。`);
  if (/index of \//i.test(text)) findings.push(`${page.url}：疑似目录列表。`);
  if (/(?:stack trace|traceback|exception|debug mode|sql syntax|warning:)/i.test(text)) findings.push(`${page.url}：出现调试或错误信息。`);
  if (/(?:password|secret|token|api[_-]?key|admin|internal|backup|todo|fixme)/i.test(text)) findings.push(`${page.url}：正文包含敏感线索关键词。`);
  if ([401, 403].includes(page.status)) findings.push(`${page.url}：访问受限，可能是需要会话或特定请求头的入口。`);
  return findings;
}

function sanitizeName(value) {
  return String(value || "web-target").replace(/[^A-Za-z0-9._-]+/g, "-").replace(/^-+|-+$/g, "").slice(0, 80) || "web-target";
}

function inferDownloadName(pageUrl, contentType, index) {
  const parsed = new URL(pageUrl);
  const rawName = path.basename(parsed.pathname) || `download-${index}`;
  const safeName = sanitizeName(rawName);
  if (path.extname(safeName)) return `${String(index).padStart(3, "0")}-${safeName}`;
  const extension = /zip/i.test(contentType)
    ? ".zip"
    : /gzip/i.test(contentType)
      ? ".gz"
      : /png/i.test(contentType)
        ? ".png"
        : /jpe?g/i.test(contentType)
          ? ".jpg"
          : /gif/i.test(contentType)
            ? ".gif"
            : /pdf/i.test(contentType)
              ? ".pdf"
              : /octet-stream/i.test(contentType)
                ? ".bin"
                : ".dat";
  return `${String(index).padStart(3, "0")}-${safeName}${extension}`;
}

function shouldSaveResponse(pageUrl, contentType, headers, body) {
  if (!body.length) return false;
  const extension = path.extname(new URL(pageUrl).pathname).toLowerCase();
  return (
    !isTextContentType(contentType) ||
    /attachment/i.test(headers["content-disposition"] || "") ||
    [".zip", ".gz", ".tgz", ".tar", ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".pdf", ".pcap", ".pcapng", ".bin", ".elf", ".exe", ".apk"].includes(
      extension,
    )
  );
}

function buildMarkdownReport(result) {
  const lines = [
    "# CTF COMPASS LOCAL WEB REPORT",
    "",
    `- Target: ${result.target}`,
    `- Resolved: ${result.resolvedAddresses.join(", ")}`,
    `- Pages: ${result.pages.length}`,
    `- Requests: ${result.requestCount}`,
    `- Duration: ${result.durationMs} ms`,
    `- Downloaded artifacts: ${result.downloadedFiles.length}`,
    "",
    "## Flag Candidates",
    "",
  ];
  if (result.flagCandidates.length) result.flagCandidates.forEach((item) => lines.push(`- \`${item.value}\` from ${item.source}`));
  else lines.push("- None found.");
  lines.push("", "## Findings", "");
  result.findings.forEach((item) => lines.push(`- ${item}`));
  if (!result.findings.length) lines.push("- No high-signal finding.");
  lines.push("", "## Pages", "");
  result.pages.forEach((page) => {
    lines.push(`### ${page.status} ${page.url}`, "");
    lines.push(`- Content-Type: ${page.contentType || "unknown"}`);
    if (page.comments.length) lines.push(`- Comments: ${page.comments.join(" | ")}`);
    if (page.forms.length) lines.push(`- Forms: ${page.forms.join(" | ")}`);
    if (page.routeCandidates.length) lines.push(`- Routes: ${page.routeCandidates.join(" | ")}`);
    lines.push("");
  });
  lines.push("## Next Steps", "");
  result.nextSteps.forEach((item) => lines.push(`- ${item}`));
  lines.push("");
  return lines.join("\n");
}

async function analyzeWebTarget(payload, outputRoot) {
  if (!payload?.authorized) {
    throw new Error("请先确认该目标是你有权测试的本地靶机或 CTF 环境。");
  }
  const validated = await validateLocalTarget(payload.url);
  const limits = {
    ...DEFAULT_LIMITS,
    maxPages: Math.max(1, Math.min(Number(payload.maxPages) || DEFAULT_LIMITS.maxPages, 60)),
    maxDepth: Math.max(0, Math.min(Number(payload.maxDepth) || DEFAULT_LIMITS.maxDepth, 4)),
  };
  const startTime = Date.now();
  fs.mkdirSync(outputRoot, { recursive: true });
  const downloadRoot = path.join(outputRoot, "web-downloads");
  const origin = validated.url.origin;
  const queue = [{ url: validated.url.href, depth: 0, reason: "target" }];
  if (payload.probeCommonPaths) {
    COMMON_CTF_PATHS.forEach((candidate) => queue.push({ url: new URL(candidate, origin).href, depth: 0, reason: "common-path" }));
  }
  const seen = new Set();
  const pages = [];
  const errors = [];
  const findings = [];
  const flagCandidates = [];
  const discoveredUrls = [];
  const downloadedFiles = [];

  while (queue.length && pages.length + errors.length < limits.maxPages && Date.now() - startTime < limits.maxDurationMs) {
    const item = queue.shift();
    if (!item || seen.has(item.url)) continue;
    seen.add(item.url);
    try {
      const fetched = await fetchLocalPage(item.url, origin, limits);
      const text = isTextContentType(fetched.contentType) ? fetched.body.toString("utf8") : "";
      const clues = text ? extractWebClues(text, fetched.url, fetched.contentType, origin) : { urls: [], comments: [], forms: [], routeCandidates: [], sourceMaps: [] };
      const page = {
        url: fetched.url,
        status: fetched.status,
        contentType: fetched.contentType,
        bytes: fetched.body.length,
        truncated: fetched.truncated,
        reason: item.reason,
        headers: fetched.headers,
        comments: clues.comments,
        forms: clues.forms,
        routeCandidates: clues.routeCandidates,
        sourceMaps: clues.sourceMaps,
      };
      pages.push(page);
      if (fetched.status >= 200 && fetched.status < 400 && shouldSaveResponse(fetched.url, fetched.contentType, fetched.headers, fetched.body)) {
        fs.mkdirSync(downloadRoot, { recursive: true });
        const downloadPath = path.join(downloadRoot, inferDownloadName(fetched.url, fetched.contentType, downloadedFiles.length + 1));
        fs.writeFileSync(downloadPath, fetched.body);
        downloadedFiles.push(downloadPath);
        findings.push(`${fetched.url}：已将二进制/附件响应保存并纳入本地递归分析。`);
      }
      findings.push(...buildPageFindings({ ...page, text }, clues));
      flagCandidates.push(...extractFlagCandidates(text, fetched.url));
      flagCandidates.push(...extractFlagCandidates(Object.entries(fetched.headers).map(([key, value]) => `${key}: ${value}`).join("\n"), `${fetched.url} headers`));
      discoveredUrls.push(...clues.urls);
      if (item.depth < limits.maxDepth) {
        clues.urls.forEach((url) => queue.push({ url, depth: item.depth + 1, reason: "crawl" }));
      }
    } catch (error) {
      errors.push({ url: item.url, message: error.message });
    }
  }

  let downloadedAnalysis = null;
  if (downloadedFiles.length) {
    downloadedAnalysis = await analyzeChallenge(
      {
        title: `Web downloads from ${validated.url.host}`,
        description: "Same-origin files downloaded by the authorized local Web analyzer.",
        tags: ["web", "downloaded-artifact"],
        artifacts: downloadedFiles,
      },
      path.join(outputRoot, "download-analysis"),
    );
    flagCandidates.push(...(downloadedAnalysis.flagCandidates || []));
    findings.push(...(downloadedAnalysis.quickFindings || []).map((item) => `下载附件：${item}`));
  }

  const uniqueFlags = [];
  const flagKeys = new Set();
  flagCandidates.forEach((item) => {
    const key = `${item.value}@@${item.source}`;
    if (!flagKeys.has(key)) {
      flagKeys.add(key);
      uniqueFlags.push(item);
    }
  });
  const uniqueFindings = dedupe(findings).slice(0, 120);
  const nextSteps = [];
  if (uniqueFlags.length) nextSteps.push("核对 flag 候选所在响应与题目提交格式，确认后再提交。");
  if (pages.some((page) => page.forms.length)) nextSteps.push("使用浏览器开发者工具手动检查表单字段、请求方法和会话变化；本工具不会自动提交表单。");
  if (pages.some((page) => page.sourceMaps.length)) nextSteps.push("优先查看 source map 中的源文件、路由和被前端隐藏的校验逻辑。");
  if (pages.some((page) => page.status === 401 || page.status === 403)) nextSteps.push("对受限入口检查题目给出的账号、Cookie、Token 或代理抓包线索。");
  if (!uniqueFlags.length) nextSteps.push("未直接发现 flag；检查可疑路由、注释、脚本、robots.txt 和响应头，再在浏览器中手动验证高价值入口。");

  const result = {
    target: validated.url.href,
    origin,
    resolvedAddresses: validated.addresses,
    requestCount: pages.length + errors.length,
    durationMs: Date.now() - startTime,
    limits,
    pages,
    errors,
    discoveredUrls: dedupe(discoveredUrls).slice(0, 200),
    downloadedFiles,
    downloadedAnalysis: downloadedAnalysis
      ? {
          classification: downloadedAnalysis.classification,
          artifactCount: downloadedAnalysis.artifacts?.length || 0,
          solver: downloadedAnalysis.solver,
        }
      : null,
    findings: uniqueFindings,
    flagCandidates: uniqueFlags.slice(0, 40),
    nextSteps: dedupe(nextSteps),
    scope: {
      localOnly: true,
      sameOrigin: true,
      methods: ["GET"],
      executedJavaScript: false,
      submittedForms: false,
    },
  };

  const baseName = sanitizeName(validated.url.hostname);
  const jsonPath = path.join(outputRoot, `${baseName}-web-report.json`);
  const markdownPath = path.join(outputRoot, `${baseName}-web-report.md`);
  fs.writeFileSync(jsonPath, `${JSON.stringify(result, null, 2)}\n`, "utf8");
  fs.writeFileSync(markdownPath, `${buildMarkdownReport(result)}\n`, "utf8");
  return { ...result, reportPaths: [markdownPath, jsonPath], reportPath: markdownPath };
}

module.exports = {
  analyzeWebTarget,
  validateLocalTarget,
};
