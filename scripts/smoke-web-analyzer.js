const fs = require("fs");
const http = require("http");
const path = require("path");
const AdmZip = require("adm-zip");
const { analyzeWebTarget } = require("../desktop/web-analyzer");

async function main() {
  const expectedFlag = "flag{local_web_crawl_smoke}";
  const archiveFlag = "flag{local_web_download_smoke}";
  const backupZip = new AdmZip();
  backupZip.addFile("backup/flag.txt", Buffer.from(`${archiveFlag}\n`, "utf8"));
  const backupBuffer = backupZip.toBuffer();
  const server = http.createServer((request, response) => {
    const url = new URL(request.url, "http://127.0.0.1");
    if (url.pathname === "/") {
      response.setHeader("Content-Type", "text/html; charset=utf-8");
      response.setHeader("Set-Cookie", "ctf_session=smoke; HttpOnly; SameSite=Lax");
      response.end(`<!doctype html>
        <!-- TODO: remove debug route before release -->
        <a href="/notes">notes</a>
        <script src="/app.js"></script>
        <form method="post" action="/login"><input name="username"></form>`);
      return;
    }
    if (url.pathname === "/robots.txt") {
      response.setHeader("Content-Type", "text/plain");
      response.end("User-agent: *\nDisallow: /hidden-room\n");
      return;
    }
    if (url.pathname === "/app.js") {
      response.setHeader("Content-Type", "application/javascript");
      response.end('fetch("/api/status");\n//# sourceMappingURL=/app.js.map\n');
      return;
    }
    if (url.pathname === "/app.js.map") {
      response.setHeader("Content-Type", "application/json");
      response.end(JSON.stringify({ version: 3, sources: ["src/app.js"], names: [], mappings: "" }));
      return;
    }
    if (url.pathname === "/hidden-room") {
      response.setHeader("Content-Type", "text/plain");
      response.end(`training result: ${expectedFlag}\n`);
      return;
    }
    if (url.pathname === "/notes") {
      response.setHeader("Content-Type", "text/plain");
      response.end("internal backup and admin route review");
      return;
    }
    if (url.pathname === "/api/status") {
      response.setHeader("Content-Type", "application/json");
      response.end('{"debug":true,"status":"ok"}');
      return;
    }
    if (url.pathname === "/backup.zip") {
      response.setHeader("Content-Type", "application/zip");
      response.setHeader("Content-Disposition", 'attachment; filename="backup.zip"');
      response.end(backupBuffer);
      return;
    }
    response.statusCode = url.pathname === "/admin" ? 403 : 404;
    response.setHeader("Content-Type", "text/plain");
    response.end("not found");
  });

  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  try {
    const address = server.address();
    const root = path.resolve(__dirname, "..", "tmp", "web-smoke", String(Date.now()));
    fs.mkdirSync(root, { recursive: true });
    const result = await analyzeWebTarget(
      {
        url: `http://127.0.0.1:${address.port}/`,
        authorized: true,
        probeCommonPaths: true,
        maxPages: 30,
        maxDepth: 3,
      },
      root,
    );
    if (!result.flagCandidates.some((item) => item.value === expectedFlag)) {
      throw new Error(`expected ${expectedFlag}, got ${JSON.stringify(result.flagCandidates)}`);
    }
    if (!result.flagCandidates.some((item) => item.value === archiveFlag) || !result.downloadedFiles.some((filePath) => filePath.endsWith("backup.zip"))) {
      throw new Error(`downloaded ZIP was not recursively solved: ${JSON.stringify(result.flagCandidates)}`);
    }
    if (!result.pages.some((page) => page.url.endsWith("/robots.txt")) || !result.pages.some((page) => page.url.endsWith("/hidden-room"))) {
      throw new Error("robots.txt route discovery did not crawl the hidden route");
    }
    if (!result.pages.some((page) => page.sourceMaps.some((item) => item.endsWith("/app.js.map")))) {
      throw new Error("source map discovery was not reported");
    }
    if (!result.findings.some((item) => /Cookie/.test(item)) || !result.findings.some((item) => /表单/.test(item))) {
      throw new Error("expected Cookie and form findings");
    }
    if (!result.reportPaths.every((filePath) => fs.existsSync(filePath))) {
      throw new Error("web reports were not generated");
    }

    let publicDenied = false;
    try {
      await analyzeWebTarget({ url: "https://example.com", authorized: true }, path.join(root, "public-denied"));
    } catch (error) {
      publicDenied = /仅允许 localhost|私有网段/.test(error.message);
    }
    if (!publicDenied) {
      throw new Error("public target should be denied by default");
    }
    console.log(
      JSON.stringify(
        {
          status: "passed",
          target: result.target,
          pages: result.pages.length,
          findings: result.findings.length,
          flags: result.flagCandidates,
          reportPaths: result.reportPaths,
        },
        null,
        2,
      ),
    );
  } finally {
    await new Promise((resolve) => server.close(resolve));
  }
}

main().catch((error) => {
  console.error(error?.stack || error?.message || String(error));
  process.exitCode = 1;
});
