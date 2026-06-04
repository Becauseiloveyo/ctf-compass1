const fs = require("fs");
const path = require("path");
const AdmZip = require("adm-zip");
const { analyzeChallenge } = require("../desktop/analyzer");

const DEFAULT_SAMPLE = path.resolve(__dirname, "..", "tmp", "input", "a05ed035-b476-49d6-9b32-462ff13c5944.zip");
const DEFAULT_EXPECTED_FLAG = "flag{96efd0a2037d06f34199e921079778ee}";

function fail(message) {
  console.error(message);
  process.exitCode = 1;
}

function resetDir(dirPath) {
  fs.rmSync(dirPath, { recursive: true, force: true });
  fs.mkdirSync(dirPath, { recursive: true });
}

function writeText(filePath, content) {
  fs.mkdirSync(path.dirname(filePath), { recursive: true });
  fs.writeFileSync(filePath, content);
  return filePath;
}

function collectFlags(result) {
  return (result.flagCandidates || []).map((item) => item.value);
}

async function runCase(root, name, payload, expectedFlag) {
  const outputRoot = path.join(root, `${name}-out`);
  const result = await analyzeChallenge(payload, outputRoot);
  const flags = collectFlags(result);

  if (!flags.includes(expectedFlag)) {
    throw new Error(`case ${name}: expected ${expectedFlag}, got ${flags.join(", ") || "no flags"}`);
  }

  if (result.pipelineErrors && result.pipelineErrors.length) {
    throw new Error(`case ${name}: unexpected pipeline errors: ${JSON.stringify(result.pipelineErrors, null, 2)}`);
  }

  return {
    name,
    status: result.solver?.status,
    primaryFlag: result.solver?.primaryFlag?.value,
    actionsRun: result.solver?.actionsRun,
    artifacts: result.challenge?.artifactCount,
  };
}

function markZipAsPseudoEncrypted(zipPath) {
  const buffer = fs.readFileSync(zipPath);
  let offset = 0;

  while (offset + 4 <= buffer.length) {
    const signature = buffer.readUInt32LE(offset);

    if (signature === 0x04034b50 && offset + 30 <= buffer.length) {
      const flags = buffer.readUInt16LE(offset + 6);
      buffer.writeUInt16LE(flags | 0x0001, offset + 6);
      const nameLength = buffer.readUInt16LE(offset + 26);
      const extraLength = buffer.readUInt16LE(offset + 28);
      offset += Math.max(4, 30 + nameLength + extraLength);
      continue;
    }

    if (signature === 0x02014b50 && offset + 46 <= buffer.length) {
      const flags = buffer.readUInt16LE(offset + 8);
      buffer.writeUInt16LE(flags | 0x0001, offset + 8);
      const nameLength = buffer.readUInt16LE(offset + 28);
      const extraLength = buffer.readUInt16LE(offset + 30);
      const commentLength = buffer.readUInt16LE(offset + 32);
      offset += Math.max(4, 46 + nameLength + extraLength + commentLength);
      continue;
    }

    offset += 1;
  }

  fs.writeFileSync(zipPath, buffer);
}

function createZipWithComment(zipPath, flag) {
  const zip = new AdmZip();
  zip.addFile("note.txt", Buffer.from("zip comment smoke fixture\n"));
  zip.addZipComment(flag);
  fs.mkdirSync(path.dirname(zipPath), { recursive: true });
  zip.writeZip(zipPath);
  return zipPath;
}

function createPseudoEncryptedZip(zipPath, flag) {
  const zip = new AdmZip();
  zip.addFile("flag.txt", Buffer.from(`${flag}\n`));
  fs.mkdirSync(path.dirname(zipPath), { recursive: true });
  zip.writeZip(zipPath);
  markZipAsPseudoEncrypted(zipPath);
  return zipPath;
}

async function main() {
  const root = path.resolve(__dirname, "..", "tmp", "smoke", String(Date.now()));
  resetDir(root);

  const results = [];
  const directFlag = "flag{direct_text_smoke}";
  const directTextPath = writeText(path.join(root, "input", "direct.txt"), `plain hit: ${directFlag}\n`);
  results.push(
    await runCase(
      root,
      "direct-text",
      {
        title: "direct text smoke",
        description: "Direct flag extraction from a text attachment.",
        artifacts: [directTextPath],
      },
      directFlag,
    ),
  );

  const zipCommentFlag = "flag{zip_comment_smoke}";
  const zipCommentPath = createZipWithComment(path.join(root, "input", "comment.zip"), zipCommentFlag);
  results.push(
    await runCase(
      root,
      "zip-comment",
      {
        title: "zip comment smoke",
        description: "ZIP global comments should be surfaced as generated clue reports.",
        artifacts: [zipCommentPath],
      },
      zipCommentFlag,
    ),
  );

  const pseudoZipFlag = "flag{pseudo_zip_smoke}";
  const pseudoZipPath = createPseudoEncryptedZip(path.join(root, "input", "pseudo.zip"), pseudoZipFlag);
  results.push(
    await runCase(
      root,
      "pseudo-encrypted-zip",
      {
        title: "pseudo encrypted zip smoke",
        description: "ZIP entries marked encrypted but not actually encrypted should be repaired locally.",
        artifacts: [pseudoZipPath],
      },
      pseudoZipFlag,
    ),
  );

  const samplePath = path.resolve(process.env.CTF_COMPASS_SAMPLE || DEFAULT_SAMPLE);
  const expectedFlag = process.env.CTF_COMPASS_EXPECTED_FLAG || DEFAULT_EXPECTED_FLAG;
  if (fs.existsSync(samplePath)) {
    results.push(
      await runCase(
        root,
        "f5-recursive-sample",
        {
          title: "smoke F5 JPEG",
          description: "Regression sample for ZIP -> JPEG F5 -> pseudo-encrypted ZIP -> flag.txt.",
          notes: "password abc123",
          artifacts: [samplePath],
        },
        expectedFlag,
      ),
    );
  } else {
    results.push({
      name: "f5-recursive-sample",
      status: "skipped",
      reason: `sample not found at ${samplePath}`,
    });
  }

  console.log(JSON.stringify({ root, results }, null, 2));
}

main().catch((error) => {
  fail(error?.stack || error?.message || String(error));
});
