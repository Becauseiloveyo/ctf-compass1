const fs = require("fs");
const path = require("path");
const zlib = require("zlib");
const AdmZip = require("adm-zip");
const { PNG } = require("pngjs");
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

const SMOKE_DTMF_COMBINED = {
  0: "2277",
  1: "1906",
  2: "2033",
  3: "2174",
  4: "1979",
  5: "2106",
  6: "2247",
  7: "2061",
  8: "2188",
  9: "2329",
};

const SMOKE_MULTITAP = {
  a: ["2", 1], b: ["2", 2], c: ["2", 3],
  d: ["3", 1], e: ["3", 2], f: ["3", 3],
  g: ["4", 1], h: ["4", 2], i: ["4", 3],
  j: ["5", 1], k: ["5", 2], l: ["5", 3],
  m: ["6", 1], n: ["6", 2], o: ["6", 3],
  p: ["7", 1], q: ["7", 2], r: ["7", 3], s: ["7", 4],
  t: ["8", 1], u: ["8", 2], v: ["8", 3],
  w: ["9", 1], x: ["9", 2], y: ["9", 3], z: ["9", 4],
};

function encodeDtmfMultitap(text) {
  return Array.from(text.toLowerCase())
    .flatMap((char) => {
      const [key, count] = SMOKE_MULTITAP[char];
      return Array.from({ length: count }, () => SMOKE_DTMF_COMBINED[key]).concat("2418");
    })
    .join("");
}

function createAlphabetToneWav(filePath, message, toneMs = 75, sampleRate = 8000) {
  const sequence = `abcdefghijklmnopqrstuvwxyz${message}`;
  const samplesPerTone = Math.round((sampleRate * toneMs) / 1000);
  const data = Buffer.alloc(sequence.length * samplesPerTone * 2);
  let sampleIndex = 0;
  for (const char of sequence) {
    const frequency = 500 + (char.charCodeAt(0) - 97) * 50;
    for (let index = 0; index < samplesPerTone; index += 1) {
      const value = Math.round(Math.sin((2 * Math.PI * frequency * index) / sampleRate) * 22000);
      data.writeInt16LE(value, sampleIndex * 2);
      sampleIndex += 1;
    }
  }
  const wav = Buffer.alloc(44 + data.length);
  wav.write("RIFF", 0);
  wav.writeUInt32LE(36 + data.length, 4);
  wav.write("WAVEfmt ", 8);
  wav.writeUInt32LE(16, 16);
  wav.writeUInt16LE(1, 20);
  wav.writeUInt16LE(1, 22);
  wav.writeUInt32LE(sampleRate, 24);
  wav.writeUInt32LE(sampleRate * 2, 28);
  wav.writeUInt16LE(2, 32);
  wav.writeUInt16LE(16, 34);
  wav.write("data", 36);
  wav.writeUInt32LE(data.length, 40);
  data.copy(wav, 44);
  fs.mkdirSync(path.dirname(filePath), { recursive: true });
  fs.writeFileSync(filePath, wav);
  return filePath;
}

function createInterleavedPngFixture(filePath, blockSize = 256) {
  const images = [35, 95, 155].map((color) => {
    const png = new PNG({ width: 64, height: 64 });
    for (let index = 0; index < png.data.length; index += 4) {
      const pixel = index / 4;
      png.data[index] = (color + pixel * 17) & 0xff;
      png.data[index + 1] = (170 + pixel * 31) & 0xff;
      png.data[index + 2] = (120 + pixel * 47) & 0xff;
      png.data[index + 3] = 255;
    }
    const encoded = PNG.sync.write(png);
    const paddedLength = Math.ceil(encoded.length / blockSize) * blockSize;
    return Buffer.concat([encoded, Buffer.alloc(paddedLength - encoded.length)]);
  });
  const blocks = [];
  const blockCount = Math.max(...images.map((image) => image.length / blockSize));
  for (let block = 0; block < blockCount; block += 1) {
    images.forEach((image) => blocks.push(image.subarray(block * blockSize, (block + 1) * blockSize)));
  }
  fs.mkdirSync(path.dirname(filePath), { recursive: true });
  fs.writeFileSync(filePath, Buffer.concat(blocks));
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

async function runNoFlagCase(root, name, payload) {
  const outputRoot = path.join(root, `${name}-out`);
  const result = await analyzeChallenge(payload, outputRoot);
  const flags = collectFlags(result);

  if (flags.length || result.solver?.status === "solved") {
    throw new Error(`case ${name}: expected no trusted flags, got ${flags.join(", ") || result.solver?.status}`);
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

async function runInterleavedRecoveryCase(root, fixturePath) {
  const outputRoot = path.join(root, "interleaved-png-recovery-out");
  const result = await analyzeChallenge(
    {
      title: "interleaved PNG recovery smoke",
      description: "Recover several files distributed in round-robin fixed-size blocks.",
      artifacts: [fixturePath],
    },
    outputRoot,
  );
  const recoveryLog = result.pipelineLog.find((item) => item.actionId === "recover-interleaved-files");
  const recoveredPngs = recoveryLog?.createdArtifacts?.filter((item) => /interleaved-\d+\.png$/i.test(item.name)) || [];
  const contactSheet = recoveryLog?.createdArtifacts?.find((item) => /contact-sheet\.png$/i.test(item.name));
  if (recoveredPngs.length !== 3 || !contactSheet) {
    throw new Error(`case interleaved-png-recovery: expected three PNGs and contact sheet, got ${JSON.stringify(recoveryLog, null, 2)}`);
  }
  recoveredPngs.forEach((item) => PNG.sync.read(fs.readFileSync(item.path)));
  return {
    name: "interleaved-png-recovery",
    status: result.solver?.status,
    actionsRun: result.solver?.actionsRun,
    artifacts: result.challenge?.artifactCount,
  };
}

async function runReportFlagCase(root, name, payload, expectedFlag, reportSuffix, reportPattern) {
  const outputRoot = path.join(root, `${name}-out`);
  const result = await analyzeChallenge(payload, outputRoot);
  const flags = collectFlags(result);
  if (!flags.includes(expectedFlag)) {
    throw new Error(`case ${name}: expected ${expectedFlag}, got ${flags.join(", ") || "no flags"}`);
  }
  if (result.pipelineErrors && result.pipelineErrors.length) {
    throw new Error(`case ${name}: unexpected pipeline errors: ${JSON.stringify(result.pipelineErrors, null, 2)}`);
  }
  const generatedPaths = result.pipelineLog.flatMap((entry) => entry.createdArtifacts.map((artifact) => artifact.path));
  const reportPath = generatedPaths.find((filePath) => filePath.endsWith(reportSuffix));
  if (!reportPath) {
    throw new Error(`case ${name}: missing ${reportSuffix}: ${generatedPaths.join(", ")}`);
  }
  const report = fs.readFileSync(reportPath, "utf8");
  if (!reportPattern.test(report)) {
    throw new Error(`case ${name}: generated report does not contain ${reportPattern}: ${report}`);
  }
  return {
    name,
    status: result.solver?.status,
    primaryFlag: result.solver?.primaryFlag?.value,
    actionsRun: result.solver?.actionsRun,
    artifacts: result.challenge?.artifactCount,
  };
}

async function runCoreDumpCase(root, corePath) {
  const outputRoot = path.join(root, "elf-core-dump-out");
  const result = await analyzeChallenge(
    {
      title: "synthetic ELF core dump smoke",
      description: "Recover registers, signal, notes, and load mappings from an ELF core dump.",
      tags: ["pwn", "core", "forensic"],
      artifacts: [corePath],
    },
    outputRoot,
  );
  if (result.pipelineErrors && result.pipelineErrors.length) {
    throw new Error(`case elf-core-dump: unexpected pipeline errors: ${JSON.stringify(result.pipelineErrors, null, 2)}`);
  }
  const generatedPaths = result.pipelineLog.flatMap((entry) => entry.createdArtifacts.map((artifact) => artifact.path));
  const reportPath = generatedPaths.find((filePath) => filePath.endsWith("-core-report.txt"));
  if (!reportPath) {
    throw new Error(`case elf-core-dump: missing core report: ${generatedPaths.join(", ")}`);
  }
  const report = fs.readFileSync(reportPath, "utf8");
  if (!/signals: 11/.test(report) || !/RIP: 0x401337/.test(report) || !/RSP: 0x7fffffffe000/.test(report) || !/NT_PRSTATUS/.test(report)) {
    throw new Error(`case elf-core-dump: incomplete core report: ${report}`);
  }
  return {
    name: "elf-core-dump",
    status: result.solver?.status,
    actionsRun: result.solver?.actionsRun,
    artifacts: result.challenge?.artifactCount,
  };
}

async function runPwnCase(root, elfPath, expectedFlag) {
  const outputRoot = path.join(root, "pwn-elf-static-out");
  const result = await analyzeChallenge(
    {
      title: "synthetic pwn ELF smoke",
      description: "Validate checksec-lite, risky imports, and short ROP gadget detection.",
      tags: ["pwn", "elf", "rop"],
      artifacts: [elfPath],
    },
    outputRoot,
  );
  const flags = collectFlags(result);
  if (!flags.includes(expectedFlag)) {
    throw new Error(`case pwn-elf-static: expected ${expectedFlag}, got ${flags.join(", ") || "no flags"}`);
  }
  if (result.pipelineErrors && result.pipelineErrors.length) {
    throw new Error(`case pwn-elf-static: unexpected pipeline errors: ${JSON.stringify(result.pipelineErrors, null, 2)}`);
  }
  if (result.classification?.id !== "pwn") {
    throw new Error(`case pwn-elf-static: expected pwn classification, got ${result.classification?.id || "unknown"}`);
  }

  const elfArtifact = result.artifacts.find((artifact) => artifact.path === elfPath);
  const highlightText = (elfArtifact?.highlights || []).join("\n");
  if (!/checksec-lite: RELRO=full NX=on PIE=on Canary=yes/.test(highlightText)) {
    throw new Error(`case pwn-elf-static: missing expected checksec highlight: ${highlightText}`);
  }
  const keywordText = (elfArtifact?.keywords || []).join(" ");
  if (!/gets/.test(highlightText) || !/\brop\b/.test(keywordText) || !/\bgadget\b/.test(keywordText)) {
    throw new Error(`case pwn-elf-static: missing risky function highlight or gadget keywords: ${highlightText}\n${keywordText}`);
  }

  const generatedPaths = result.pipelineLog.flatMap((entry) => entry.createdArtifacts.map((artifact) => artifact.path));
  const checksecPath = generatedPaths.find((filePath) => filePath.endsWith("-checksec-lite.txt"));
  const surfacePath = generatedPaths.find((filePath) => filePath.endsWith("-pwn-surface.txt"));
  const pathsPath = generatedPaths.find((filePath) => filePath.endsWith("-pwn-paths.txt"));
  const ioProfilePath = generatedPaths.find((filePath) => filePath.endsWith("-pwn-io-profile.txt"));
  const pwnStringsPath = generatedPaths.find((filePath) => filePath.endsWith("-pwn-interesting-strings.txt"));
  const gadgetPath = generatedPaths.find((filePath) => filePath.endsWith("-rop-gadgets-lite.txt"));
  const capabilityPath = generatedPaths.find((filePath) => filePath.endsWith("-rop-capabilities-lite.txt"));
  const runtimePath = generatedPaths.find((filePath) => filePath.endsWith("-elf-runtime-profile.txt"));
  const memoryPath = generatedPaths.find((filePath) => filePath.endsWith("-pwn-memory-surface.txt"));
  const seccompPath = generatedPaths.find((filePath) => filePath.endsWith("-seccomp-bpf.txt"));
  if (!checksecPath || !surfacePath || !pathsPath || !ioProfilePath || !pwnStringsPath || !gadgetPath || !capabilityPath || !runtimePath || !memoryPath || !seccompPath) {
    throw new Error(`case pwn-elf-static: missing generated pwn reports: ${generatedPaths.join(", ")}`);
  }
  if (!/RELRO: full/.test(fs.readFileSync(checksecPath, "utf8")) || !/gets: critical/.test(fs.readFileSync(surfacePath, "utf8"))) {
    throw new Error("case pwn-elf-static: generated checksec or pwn surface report is incomplete");
  }
  if (!/stack overflow \/ ret2libc \/ ROP/.test(fs.readFileSync(pathsPath, "utf8"))) {
    throw new Error("case pwn-elf-static: generated pwn path report is incomplete");
  }
  const ioProfile = fs.readFileSync(ioProfilePath, "utf8");
  if (!/mode: network-service/.test(ioProfile) || !/\balarm\b/.test(ioProfile) || !/\bprctl\b/.test(ioProfile) || !/\bseccomp\b/.test(ioProfile)) {
    throw new Error(`case pwn-elf-static: generated pwn I/O profile is incomplete: ${ioProfile}`);
  }
  const pwnStrings = fs.readFileSync(pwnStringsPath, "utf8");
  if (!/\/bin\/sh/.test(pwnStrings) || !/Choice:/.test(pwnStrings) || !/%p %p %n/.test(pwnStrings)) {
    throw new Error(`case pwn-elf-static: generated interesting strings report is incomplete: ${pwnStrings}`);
  }
  if (!/pop rdi; ret/.test(fs.readFileSync(gadgetPath, "utf8"))) {
    throw new Error("case pwn-elf-static: generated gadget report is incomplete");
  }
  const capabilities = fs.readFileSync(capabilityPath, "utf8");
  if (!/argument-control: rdi, rsi, rdx/.test(capabilities) || !/syscall: yes/.test(capabilities) || !/stack-pivot: yes/.test(capabilities)) {
    throw new Error(`case pwn-elf-static: generated ROP capability report is incomplete: ${capabilities}`);
  }
  const runtimeProfile = fs.readFileSync(runtimePath, "utf8");
  if (!/role: pie-executable/.test(runtimeProfile) || !/build-id: 00112233445566778899aabbccddeeff00112233/.test(runtimeProfile) || !/GLIBC_2.31/.test(runtimeProfile)) {
    throw new Error(`case pwn-elf-static: generated ELF runtime profile is incomplete: ${runtimeProfile}`);
  }
  const memoryProfile = fs.readFileSync(memoryPath, "utf8");
  if (!/staging: \.dynamic/.test(memoryProfile) || !/executable: \.text/.test(memoryProfile)) {
    throw new Error(`case pwn-elf-static: generated memory surface report is incomplete: ${memoryProfile}`);
  }
  const seccompProfile = fs.readFileSync(seccompPath, "utf8");
  if (!/read/.test(seccompProfile) || !/write/.test(seccompProfile) || !/openat/.test(seccompProfile) || !/ALLOW/.test(seccompProfile) || !/KILL/.test(seccompProfile)) {
    throw new Error(`case pwn-elf-static: generated seccomp BPF report is incomplete: ${seccompProfile}`);
  }

  return {
    name: "pwn-elf-static",
    status: result.solver?.status,
    primaryFlag: result.solver?.primaryFlag?.value,
    actionsRun: result.solver?.actionsRun,
    artifacts: result.challenge?.artifactCount,
  };
}

async function runAarch64PwnCase(root, elfPath) {
  const outputRoot = path.join(root, "pwn-aarch64-static-out");
  const result = await analyzeChallenge(
    {
      title: "synthetic AArch64 pwn smoke",
      description: "Validate non-x86 ELF triage and lightweight return/syscall gadget detection.",
      tags: ["pwn", "aarch64", "elf"],
      artifacts: [elfPath],
    },
    outputRoot,
  );
  if (result.pipelineErrors && result.pipelineErrors.length) {
    throw new Error(`case pwn-aarch64-static: unexpected pipeline errors: ${JSON.stringify(result.pipelineErrors, null, 2)}`);
  }
  if (result.classification?.id !== "pwn") {
    throw new Error(`case pwn-aarch64-static: expected pwn classification, got ${result.classification?.id || "unknown"}`);
  }
  const generatedPaths = result.pipelineLog.flatMap((entry) => entry.createdArtifacts.map((artifact) => artifact.path));
  const gadgetPath = generatedPaths.find((filePath) => filePath.endsWith("-rop-gadgets-lite.txt"));
  const capabilityPath = generatedPaths.find((filePath) => filePath.endsWith("-rop-capabilities-lite.txt"));
  if (!gadgetPath || !/svc #0/.test(fs.readFileSync(gadgetPath, "utf8")) || !/\bret\b/.test(fs.readFileSync(gadgetPath, "utf8"))) {
    throw new Error("case pwn-aarch64-static: missing AArch64 ret/svc gadget report");
  }
  if (!capabilityPath || !/syscall: yes/.test(fs.readFileSync(capabilityPath, "utf8"))) {
    throw new Error("case pwn-aarch64-static: missing AArch64 syscall capability");
  }
  return {
    name: "pwn-aarch64-static",
    status: result.solver?.status,
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

function writeTarField(header, offset, length, value) {
  const buffer = Buffer.from(String(value), "ascii");
  buffer.copy(header, offset, 0, Math.min(buffer.length, length));
}

function writeTarOctal(header, offset, length, value) {
  const text = Math.max(0, Number(value) || 0)
    .toString(8)
    .padStart(length - 1, "0")
    .slice(-(length - 1));
  writeTarField(header, offset, length, `${text}\0`);
}

function createTarBuffer(entries) {
  const chunks = [];
  entries.forEach((entry) => {
    const data = Buffer.isBuffer(entry.data) ? entry.data : Buffer.from(entry.data, "utf8");
    const header = Buffer.alloc(512);
    writeTarField(header, 0, 100, entry.name);
    writeTarOctal(header, 100, 8, 0o644);
    writeTarOctal(header, 108, 8, 0);
    writeTarOctal(header, 116, 8, 0);
    writeTarOctal(header, 124, 12, data.length);
    writeTarOctal(header, 136, 12, Math.floor(Date.now() / 1000));
    header.fill(32, 148, 156);
    writeTarField(header, 156, 1, "0");
    writeTarField(header, 257, 6, "ustar\0");
    writeTarField(header, 263, 2, "00");
    let checksum = 0;
    for (const byte of header) checksum += byte;
    writeTarOctal(header, 148, 8, checksum);
    chunks.push(header, data, Buffer.alloc((512 - (data.length % 512)) % 512));
  });
  chunks.push(Buffer.alloc(1024));
  return Buffer.concat(chunks);
}

function createTgz(tgzPath, flag) {
  const tar = createTarBuffer([
    { name: "clues/readme.txt", data: "recursive tar smoke fixture\n" },
    { name: "nested/flag.txt", data: `${flag}\n` },
  ]);
  fs.mkdirSync(path.dirname(tgzPath), { recursive: true });
  fs.writeFileSync(tgzPath, zlib.gzipSync(tar));
  return tgzPath;
}

function createBmpLsb(bmpPath, text, width = 32, height = 16) {
  const bits = Array.from(Buffer.from(text, "utf8")).flatMap((byte) => byte.toString(2).padStart(8, "0").split("").map(Number));
  if (bits.length > width * height) {
    throw new Error("BMP smoke fixture is too small for payload");
  }

  const bitsPerPixel = 24;
  const rowStride = Math.floor((bitsPerPixel * width + 31) / 32) * 4;
  const dataOffset = 54;
  const buffer = Buffer.alloc(dataOffset + rowStride * height);
  buffer.write("BM", 0, "ascii");
  buffer.writeUInt32LE(buffer.length, 2);
  buffer.writeUInt32LE(dataOffset, 10);
  buffer.writeUInt32LE(40, 14);
  buffer.writeInt32LE(width, 18);
  buffer.writeInt32LE(height, 22);
  buffer.writeUInt16LE(1, 26);
  buffer.writeUInt16LE(bitsPerPixel, 28);
  buffer.writeUInt32LE(0, 30);
  buffer.writeUInt32LE(rowStride * height, 34);

  for (let storedY = 0; storedY < height; storedY += 1) {
    const logicalY = height - 1 - storedY;
    for (let x = 0; x < width; x += 1) {
      const pixel = logicalY * width + x;
      const offset = dataOffset + storedY * rowStride + x * 3;
      buffer[offset] = 0x80 | (bits[pixel] || 0);
      buffer[offset + 1] = 0x80;
      buffer[offset + 2] = 0x80;
    }
  }

  fs.mkdirSync(path.dirname(bmpPath), { recursive: true });
  fs.writeFileSync(bmpPath, buffer);
  return bmpPath;
}

function createGifSplitComment(gifPath, chunks) {
  const header = Buffer.from("GIF89a", "ascii");
  const logicalScreen = Buffer.from([0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00]);
  const commentParts = [Buffer.from([0x21, 0xfe])];
  chunks.forEach((chunk) => {
    const data = Buffer.from(chunk, "utf8");
    commentParts.push(Buffer.from([data.length]), data);
  });
  commentParts.push(Buffer.from([0x00, 0x3b]));
  fs.mkdirSync(path.dirname(gifPath), { recursive: true });
  fs.writeFileSync(gifPath, Buffer.concat([header, logicalScreen, ...commentParts]));
  return gifPath;
}

function createGifDescriptorBits(gifPath, text) {
  const values = Array.from(Buffer.from(text, "utf8")).flatMap((byte) => [
    (byte >> 6) & 0x03,
    (byte >> 4) & 0x03,
    (byte >> 2) & 0x03,
    byte & 0x03,
  ]);
  const header = Buffer.from("GIF89a", "ascii");
  const logicalScreen = Buffer.from([0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00]);
  const frames = values.map((value) =>
    Buffer.from([
      0x2c,
      0x00, 0x00, 0x00, 0x00,
      0x01, 0x00, 0x01, 0x00,
      value << 4,
      0x02,
      0x02, 0x44, 0x01,
      0x00,
    ]),
  );
  fs.mkdirSync(path.dirname(gifPath), { recursive: true });
  fs.writeFileSync(gifPath, Buffer.concat([header, logicalScreen, ...frames, Buffer.from([0x3b])]));
  return gifPath;
}

function createMp4HiddenTrack(mp4Path, flag) {
  const box = (type, payload) => {
    const data = Buffer.isBuffer(payload) ? payload : Buffer.from(payload || "", "utf8");
    const result = Buffer.alloc(8 + data.length);
    result.writeUInt32BE(result.length, 0);
    result.write(type, 4, 4, "ascii");
    data.copy(result, 8);
    return result;
  };
  const ftyp = box("ftyp", Buffer.from("isom\0\0\2\0isomiso2", "binary"));
  const mdat = box("mdat", Buffer.from("video-smoke", "ascii"));
  const moov = box("moov", box("mvhd", Buffer.alloc(24)));
  const hiddenTrack = box("free", Buffer.from(`hidden-track ${flag}`, "utf8"));
  fs.mkdirSync(path.dirname(mp4Path), { recursive: true });
  fs.writeFileSync(mp4Path, Buffer.concat([ftyp, mdat, moov, hiddenTrack]));
  return mp4Path;
}

function createUsbKeyboardPcap(filePath, text) {
  const pairs = {
    "\n": [0, 40], " ": [0, 44], "-": [0, 45], "_": [2, 45], "=": [0, 46], "+": [2, 46],
    "[": [0, 47], "{": [2, 47], "]": [0, 48], "}": [2, 48], "\\": [0, 49], "|": [2, 49],
    ";": [0, 51], ":": [2, 51], "'": [0, 52], "\"": [2, 52], ",": [0, 54], "<": [2, 54],
    ".": [0, 55], ">": [2, 55], "/": [0, 56], "?": [2, 56],
  };
  "abcdefghijklmnopqrstuvwxyz".split("").forEach((char, index) => {
    pairs[char] = [0, 4 + index];
    pairs[char.toUpperCase()] = [2, 4 + index];
  });
  const shiftedDigits = ["!", "@", "#", "$", "%", "^", "&", "*", "(", ")"];
  "1234567890".split("").forEach((char, index) => {
    pairs[char] = [0, 30 + index];
    pairs[shiftedDigits[index]] = [2, 30 + index];
  });

  const packets = [];
  for (const char of text) {
    const pair = pairs[char];
    if (!pair) throw new Error(`unsupported HID smoke character: ${char}`);
    for (const report of [Buffer.from([pair[0], 0, pair[1], 0, 0, 0, 0, 0]), Buffer.alloc(8)]) {
      const usbPcap = Buffer.alloc(27);
      usbPcap.writeUInt16LE(27, 0);
      usbPcap.writeUInt32LE(report.length, 23);
      packets.push(Buffer.concat([usbPcap, report]));
    }
  }

  const globalHeader = Buffer.alloc(24);
  globalHeader.writeUInt32LE(0xa1b2c3d4, 0);
  globalHeader.writeUInt16LE(2, 4);
  globalHeader.writeUInt16LE(4, 6);
  globalHeader.writeUInt32LE(65535, 16);
  globalHeader.writeUInt32LE(249, 20);
  const records = packets.map((packet, index) => {
    const header = Buffer.alloc(16);
    header.writeUInt32LE(index, 0);
    header.writeUInt32LE(packet.length, 8);
    header.writeUInt32LE(packet.length, 12);
    return Buffer.concat([header, packet]);
  });
  fs.mkdirSync(path.dirname(filePath), { recursive: true });
  fs.writeFileSync(filePath, Buffer.concat([globalHeader, ...records]));
  return filePath;
}

function reverseByteBits(value) {
  let result = 0;
  for (let bit = 0; bit < 8; bit += 1) {
    result = (result << 1) | ((value >> bit) & 1);
  }
  return result;
}

function createSpiVcd(filePath, flag) {
  const payload = Buffer.concat([
    Buffer.from([0xde, 0xad, 0xbe, 0xef]),
    Buffer.from(Array.from(Buffer.from(flag, "utf8"), (byte) => reverseByteBits(byte ^ 0x55))),
  ]);
  const bits = Array.from(payload).flatMap((byte) => byte.toString(2).padStart(8, "0").split(""));
  const lines = [
    "$version CTF Compass smoke $end",
    "$timescale 1ns $end",
    "$scope module logic $end",
    "$var wire 1 ! CLK $end",
    "$var wire 1 # MISO $end",
    "$upscope $end",
    "$enddefinitions $end",
    "#0",
    "0!",
    "0#",
  ];
  let timestamp = 10;
  bits.forEach((bit) => {
    lines.push(`#${timestamp}`, `${bit}#`, `1!`);
    timestamp += 10;
    lines.push(`#${timestamp}`, "0!");
    timestamp += 10;
  });
  fs.mkdirSync(path.dirname(filePath), { recursive: true });
  fs.writeFileSync(filePath, `${lines.join("\n")}\n`);
  return filePath;
}

function createUartVcd(filePath, flag) {
  const bytes = Buffer.from(flag, "utf8");
  const lines = [
    "$version CTF Compass UART smoke $end",
    "$timescale 1ns $end",
    "$scope module logic $end",
    "$var wire 1 ! TX $end",
    "$upscope $end",
    "$enddefinitions $end",
    "#0",
    "1!",
  ];
  const bitPeriod = 10;
  let timestamp = 20;
  bytes.forEach((byte) => {
    const frame = [0, ...Array.from({ length: 8 }, (_unused, bit) => (byte >> bit) & 1), 1];
    frame.forEach((bit) => {
      lines.push(`#${timestamp}`, `${bit}!`);
      timestamp += bitPeriod;
    });
  });
  lines.push(`#${timestamp}`, "1!");
  fs.mkdirSync(path.dirname(filePath), { recursive: true });
  fs.writeFileSync(filePath, `${lines.join("\n")}\n`);
  return filePath;
}

function createI2cVcd(filePath, flag) {
  const bytes = Buffer.concat([Buffer.from([0x42]), Buffer.from(flag, "utf8")]);
  const lines = [
    "$version CTF Compass I2C smoke $end",
    "$timescale 1ns $end",
    "$scope module logic $end",
    "$var wire 1 ! SCL $end",
    "$var wire 1 # SDA $end",
    "$upscope $end",
    "$enddefinitions $end",
    "#0",
    "0!",
    "1#",
  ];
  let timestamp = 10;
  bytes.forEach((byte) => {
    const frameBits = [...byte.toString(2).padStart(8, "0").split("").map(Number), 0];
    frameBits.forEach((bit) => {
      lines.push(`#${timestamp}`, `${bit}#`);
      timestamp += 5;
      lines.push(`#${timestamp}`, "1!");
      timestamp += 5;
      lines.push(`#${timestamp}`, "0!");
      timestamp += 5;
    });
  });
  fs.mkdirSync(path.dirname(filePath), { recursive: true });
  fs.writeFileSync(filePath, `${lines.join("\n")}\n`);
  return filePath;
}

function createCanLog(filePath, flag) {
  const payload = Buffer.from(flag, "utf8");
  const lines = [];
  for (let offset = 0; offset < payload.length; offset += 8) {
    lines.push(`(1710000000.${String(offset).padStart(6, "0")}) can0 321#${payload.subarray(offset, offset + 8).toString("hex").toUpperCase()}`);
  }
  return writeText(filePath, `${lines.join("\n")}\n`);
}

function createIcmpCovertPcap(filePath, flag) {
  const chunks = [];
  const payload = Buffer.from(flag, "utf8");
  for (let offset = 0; offset < payload.length; offset += 7) {
    const part = payload.subarray(offset, offset + 7);
    const ethernet = Buffer.alloc(14);
    ethernet.fill(0x11, 0, 6);
    ethernet.fill(0x22, 6, 12);
    ethernet.writeUInt16BE(0x0800, 12);
    const ip = Buffer.alloc(20);
    ip[0] = 0x45;
    ip.writeUInt16BE(20 + 8 + part.length, 2);
    ip.writeUInt16BE(0x1200 + chunks.length, 4);
    ip[8] = 64;
    ip[9] = 1;
    ip.set([10, 0, 0, 1], 12);
    ip.set([10, 0, 0, 2], 16);
    const icmp = Buffer.alloc(8);
    icmp[0] = 8;
    icmp.writeUInt16BE(0x4242, 4);
    icmp.writeUInt16BE(chunks.length, 6);
    chunks.push(Buffer.concat([ethernet, ip, icmp, part]));
  }
  const globalHeader = Buffer.alloc(24);
  globalHeader.writeUInt32LE(0xa1b2c3d4, 0);
  globalHeader.writeUInt16LE(2, 4);
  globalHeader.writeUInt16LE(4, 6);
  globalHeader.writeUInt32LE(65535, 16);
  globalHeader.writeUInt32LE(1, 20);
  const records = chunks.map((packet, index) => {
    const header = Buffer.alloc(16);
    header.writeUInt32LE(1710000000 + index, 0);
    header.writeUInt32LE(packet.length, 8);
    header.writeUInt32LE(packet.length, 12);
    return Buffer.concat([header, packet]);
  });
  fs.mkdirSync(path.dirname(filePath), { recursive: true });
  fs.writeFileSync(filePath, Buffer.concat([globalHeader, ...records]));
  return filePath;
}

function createLogicCsv(filePath, flag) {
  const bits = Array.from(Buffer.from(flag, "utf8")).flatMap((byte) => byte.toString(2).padStart(8, "0").split(""));
  const rows = ["IN0,IN1,IN2,IN3,Target_OUT"];
  let oneIndex = 0;
  let zeroIndex = 0;
  bits.forEach((bit) => {
    if (bit === "1") {
      rows.push(oneIndex++ % 2 === 0 ? "1,1,0,0,0" : "0,0,1,1,0");
    } else {
      rows.push(zeroIndex++ % 2 === 0 ? "1,0,1,0,1" : "0,1,0,1,1");
    }
  });
  fs.mkdirSync(path.dirname(filePath), { recursive: true });
  fs.writeFileSync(filePath, `${rows.join("\n")}\n`);
  return filePath;
}

function createPngWrongDimensions(filePath, width = 64, height = 24) {
  const png = new PNG({ width, height });
  for (let index = 0; index < png.data.length; index += 4) {
    png.data[index] = 36;
    png.data[index + 1] = 112;
    png.data[index + 2] = 96;
    png.data[index + 3] = 255;
  }
  const buffer = PNG.sync.write(png);
  buffer.writeUInt32BE(1, 16);
  buffer.writeUInt32BE(1, 20);
  fs.mkdirSync(path.dirname(filePath), { recursive: true });
  fs.writeFileSync(filePath, buffer);
  return filePath;
}

async function runPngDimensionCase(root, pngPath) {
  const result = await analyzeChallenge(
    {
      title: "PNG wrong dimensions smoke",
      description: "Detect a modified IHDR and generate repaired dimension candidates.",
      artifacts: [pngPath],
    },
    path.join(root, "png-dimension-repair-out"),
  );
  const repairLog = result.pipelineLog.find((item) => item.actionId === "repair-png-dimensions");
  const repaired = repairLog?.createdArtifacts?.find((item) => /64x24\.png$/i.test(item.name));
  if (!repaired) {
    throw new Error(`case png-dimension-repair: expected repaired 64x24 PNG, got ${JSON.stringify(result.pipelineLog, null, 2)}`);
  }
  const decoded = PNG.sync.read(fs.readFileSync(repaired.path));
  if (decoded.width !== 64 || decoded.height !== 24) {
    throw new Error(`case png-dimension-repair: repaired PNG is not readable as 64x24`);
  }
  return {
    name: "png-dimension-repair",
    status: result.solver?.status,
    actionsRun: result.solver?.actionsRun,
    artifacts: result.challenge?.artifactCount,
  };
}

function createSafetensorsFixture(filePath, flag) {
  const header = Buffer.from(
    JSON.stringify({
      __metadata__: { challenge: flag, prompt: "inspect model metadata safely" },
      "layer.weight": { dtype: "F32", shape: [1, 1], data_offsets: [0, 4] },
    }),
    "utf8",
  );
  const prefix = Buffer.alloc(8);
  prefix.writeBigUInt64LE(BigInt(header.length));
  fs.mkdirSync(path.dirname(filePath), { recursive: true });
  fs.writeFileSync(filePath, Buffer.concat([prefix, header, Buffer.alloc(4)]));
  return filePath;
}

async function runModelCase(root, modelPath, expectedFlag) {
  const result = await analyzeChallenge(
    {
      title: "model reverse smoke",
      description: "Inspect Safetensors metadata without executing model content.",
      artifacts: [modelPath],
    },
    path.join(root, "model-reverse-out"),
  );
  if (!collectFlags(result).includes(expectedFlag)) {
    throw new Error(`case model-reverse: expected ${expectedFlag}, got ${collectFlags(result).join(", ") || "no flags"}`);
  }
  if (!result.pipelineLog.some((item) => item.actionId === "extract-model-clues")) {
    throw new Error("case model-reverse: model report action did not run");
  }
  return {
    name: "model-reverse",
    status: result.solver?.status,
    primaryFlag: result.solver?.primaryFlag?.value,
    actionsRun: result.solver?.actionsRun,
    artifacts: result.challenge?.artifactCount,
  };
}

function align(value, alignment) {
  return Math.ceil(value / alignment) * alignment;
}

function createClassicSeccompProgram() {
  const instruction = (code, jt, jf, k) => {
    const buffer = Buffer.alloc(8);
    buffer.writeUInt16LE(code, 0);
    buffer[2] = jt;
    buffer[3] = jf;
    buffer.writeUInt32LE(k >>> 0, 4);
    return buffer;
  };
  return Buffer.concat([
    instruction(0x20, 0, 0, 0),
    instruction(0x15, 0, 1, 0),
    instruction(0x06, 0, 0, 0x7fff0000),
    instruction(0x15, 0, 1, 1),
    instruction(0x06, 0, 0, 0x7fff0000),
    instruction(0x15, 0, 1, 257),
    instruction(0x06, 0, 0, 0x7fff0000),
    instruction(0x06, 0, 0, 0),
  ]);
}

function createPwnElf64(filePath, flag) {
  const dynstrValues = [
    "",
    "libc.so.6",
    "gets",
    "printf",
    "system",
    "read",
    "__stack_chk_fail",
    "socket",
    "accept",
    "alarm",
    "prctl",
    "seccomp",
    "malloc",
    "free",
    "setvbuf",
  ];
  const dynstrOffsets = new Map();
  let dynstrLength = 0;
  const dynstrChunks = dynstrValues.map((value) => {
    dynstrOffsets.set(value, dynstrLength);
    const chunk = Buffer.from(`${value}\0`, "ascii");
    dynstrLength += chunk.length;
    return chunk;
  });
  const dynstr = Buffer.concat(dynstrChunks);

  const dynsym = Buffer.alloc(dynstrValues.length * 24);
  dynstrValues.slice(1).forEach((name, index) => {
    const offset = (index + 1) * 24;
    dynsym.writeUInt32LE(dynstrOffsets.get(name), offset);
    dynsym[offset + 4] = 0x12;
  });

  const rela = Buffer.alloc((dynstrValues.length - 1) * 24);
  dynstrValues.slice(1).forEach((_name, index) => {
    const offset = index * 24;
    rela.writeBigUInt64LE(BigInt(0x601000 + index * 8), offset);
    rela.writeBigUInt64LE((BigInt(index + 1) << 32n) | 7n, offset + 8);
  });

  const dynamic = Buffer.alloc(48);
  dynamic.writeBigUInt64LE(1n, 0);
  dynamic.writeBigUInt64LE(BigInt(dynstrOffsets.get("libc.so.6")), 8);
  dynamic.writeBigUInt64LE(24n, 16);
  dynamic.writeBigUInt64LE(0n, 24);
  dynamic.writeBigUInt64LE(0n, 32);
  dynamic.writeBigUInt64LE(0n, 40);
  const buildIdNote = Buffer.alloc(36);
  buildIdNote.writeUInt32LE(4, 0);
  buildIdNote.writeUInt32LE(20, 4);
  buildIdNote.writeUInt32LE(3, 8);
  buildIdNote.write("GNU\0", 12, "ascii");
  Buffer.from("00112233445566778899aabbccddeeff00112233", "hex").copy(buildIdNote, 16);
  const rodataText = Buffer.from(`${flag}\0Choice:\0Index:\0Size:\0Content:\0/bin/sh\0leak: %p %p %n\0flag.txt\0GLIBC_2.31\0`, "ascii");
  const rodata = Buffer.concat([rodataText, Buffer.alloc((8 - (rodataText.length % 8)) % 8), createClassicSeccompProgram()]);

  const sectionNames = ["", ".text", ".rodata", ".interp", ".dynstr", ".dynsym", ".rela.plt", ".dynamic", ".note.GNU-stack", ".note.gnu.build-id", ".shstrtab"];
  const shstrOffsets = new Map();
  let shstrLength = 0;
  const shstr = Buffer.concat(
    sectionNames.map((name) => {
      shstrOffsets.set(name, shstrLength);
      const chunk = Buffer.from(`${name}\0`, "ascii");
      shstrLength += chunk.length;
      return chunk;
    }),
  );

  const sections = [
    { name: "", type: 0, flags: 0n, address: 0n, data: Buffer.alloc(0), align: 0, link: 0, info: 0, entrySize: 0 },
    {
      name: ".text",
      type: 1,
      flags: 6n,
      address: 0x401000n,
      data: Buffer.from([
        0x5f, 0xc3,
        0x5e, 0x41, 0x5f, 0xc3,
        0x5a, 0xc3,
        0x0f, 0x05, 0xc3,
        0xc9, 0xc3,
        0x48, 0x94, 0xc3,
        0x48, 0x83, 0xc4, 0x20, 0xc3,
        0xc3,
      ]),
      align: 16,
      link: 0,
      info: 0,
      entrySize: 0,
    },
    {
      name: ".rodata",
      type: 1,
      flags: 2n,
      address: 0x402000n,
      data: rodata,
      align: 8,
      link: 0,
      info: 0,
      entrySize: 0,
    },
    { name: ".interp", type: 1, flags: 2n, address: 0x400200n, data: Buffer.from("/lib64/ld-linux-x86-64.so.2\0", "ascii"), align: 1, link: 0, info: 0, entrySize: 0 },
    { name: ".dynstr", type: 3, flags: 2n, address: 0x403000n, data: dynstr, align: 1, link: 0, info: 0, entrySize: 0 },
    { name: ".dynsym", type: 11, flags: 2n, address: 0x404000n, data: dynsym, align: 8, link: 4, info: 1, entrySize: 24 },
    { name: ".rela.plt", type: 4, flags: 2n, address: 0x405000n, data: rela, align: 8, link: 5, info: 1, entrySize: 24 },
    { name: ".dynamic", type: 6, flags: 3n, address: 0x406000n, data: dynamic, align: 8, link: 4, info: 0, entrySize: 16 },
    { name: ".note.GNU-stack", type: 1, flags: 0n, address: 0n, data: Buffer.alloc(0), align: 1, link: 0, info: 0, entrySize: 0 },
    { name: ".note.gnu.build-id", type: 7, flags: 2n, address: 0x407000n, data: buildIdNote, align: 4, link: 0, info: 0, entrySize: 0 },
    { name: ".shstrtab", type: 3, flags: 0n, address: 0n, data: shstr, align: 1, link: 0, info: 0, entrySize: 0 },
  ];

  const programHeaderCount = 3;
  let cursor = align(64 + programHeaderCount * 56, 0x10);
  sections.slice(1).forEach((section) => {
    cursor = align(cursor, Math.max(1, section.align));
    section.offset = cursor;
    cursor += section.data.length;
  });
  const sectionHeaderOffset = align(cursor, 0x10);
  const buffer = Buffer.alloc(sectionHeaderOffset + sections.length * 64);

  buffer.set([0x7f, 0x45, 0x4c, 0x46, 2, 1, 1, 0], 0);
  buffer.writeUInt16LE(3, 16);
  buffer.writeUInt16LE(62, 18);
  buffer.writeUInt32LE(1, 20);
  buffer.writeBigUInt64LE(0x401000n, 24);
  buffer.writeBigUInt64LE(64n, 32);
  buffer.writeBigUInt64LE(BigInt(sectionHeaderOffset), 40);
  buffer.writeUInt16LE(64, 52);
  buffer.writeUInt16LE(56, 54);
  buffer.writeUInt16LE(programHeaderCount, 56);
  buffer.writeUInt16LE(64, 58);
  buffer.writeUInt16LE(sections.length, 60);
  buffer.writeUInt16LE(10, 62);

  const writeProgramHeader = (index, type, flags, offset, address, fileSize, memorySize) => {
    const start = 64 + index * 56;
    buffer.writeUInt32LE(type, start);
    buffer.writeUInt32LE(flags, start + 4);
    buffer.writeBigUInt64LE(BigInt(offset), start + 8);
    buffer.writeBigUInt64LE(BigInt(address), start + 16);
    buffer.writeBigUInt64LE(BigInt(address), start + 24);
    buffer.writeBigUInt64LE(BigInt(fileSize), start + 32);
    buffer.writeBigUInt64LE(BigInt(memorySize), start + 40);
    buffer.writeBigUInt64LE(8n, start + 48);
  };
  const interp = sections[3];
  writeProgramHeader(0, 3, 4, interp.offset, interp.address, interp.data.length, interp.data.length);
  writeProgramHeader(1, 0x6474e551, 6, 0, 0, 0, 0);
  writeProgramHeader(2, 0x6474e552, 4, sections[7].offset, sections[7].address, sections[7].data.length, sections[7].data.length);

  sections.slice(1).forEach((section) => section.data.copy(buffer, section.offset));
  sections.forEach((section, index) => {
    const start = sectionHeaderOffset + index * 64;
    buffer.writeUInt32LE(shstrOffsets.get(section.name) || 0, start);
    buffer.writeUInt32LE(section.type, start + 4);
    buffer.writeBigUInt64LE(section.flags, start + 8);
    buffer.writeBigUInt64LE(section.address, start + 16);
    buffer.writeBigUInt64LE(BigInt(section.offset || 0), start + 24);
    buffer.writeBigUInt64LE(BigInt(section.data.length), start + 32);
    buffer.writeUInt32LE(section.link, start + 40);
    buffer.writeUInt32LE(section.info, start + 44);
    buffer.writeBigUInt64LE(BigInt(section.align || 0), start + 48);
    buffer.writeBigUInt64LE(BigInt(section.entrySize || 0), start + 56);
  });

  fs.mkdirSync(path.dirname(filePath), { recursive: true });
  fs.writeFileSync(filePath, buffer);
  return filePath;
}

function createElfCoreFixture(filePath) {
  const description = Buffer.alloc(112 + 27 * 8);
  description.writeUInt32LE(11, 12);
  const registerBase = 112;
  const registers = {
    4: 0x7fffffffe100n,
    10: 0x41414141n,
    12: 0x1337n,
    13: 0x402000n,
    14: 0x403000n,
    16: 0x401337n,
    19: 0x7fffffffe000n,
  };
  Object.entries(registers).forEach(([index, value]) => description.writeBigUInt64LE(value, registerBase + Number(index) * 8));
  const noteName = Buffer.from("CORE\0", "ascii");
  const note = Buffer.alloc(12 + align(noteName.length, 4) + align(description.length, 4));
  note.writeUInt32LE(noteName.length, 0);
  note.writeUInt32LE(description.length, 4);
  note.writeUInt32LE(1, 8);
  noteName.copy(note, 12);
  description.copy(note, 12 + align(noteName.length, 4));

  const programHeaderCount = 2;
  const noteOffset = align(64 + programHeaderCount * 56, 8);
  const loadOffset = align(noteOffset + note.length, 16);
  const loadData = Buffer.from("synthetic core mapping", "ascii");
  const buffer = Buffer.alloc(loadOffset + loadData.length);
  buffer.set([0x7f, 0x45, 0x4c, 0x46, 2, 1, 1, 0], 0);
  buffer.writeUInt16LE(4, 16);
  buffer.writeUInt16LE(62, 18);
  buffer.writeUInt32LE(1, 20);
  buffer.writeBigUInt64LE(64n, 32);
  buffer.writeUInt16LE(64, 52);
  buffer.writeUInt16LE(56, 54);
  buffer.writeUInt16LE(programHeaderCount, 56);
  buffer.writeUInt16LE(64, 58);

  const writeProgramHeader = (index, type, flags, offset, address, fileSize, memorySize) => {
    const start = 64 + index * 56;
    buffer.writeUInt32LE(type, start);
    buffer.writeUInt32LE(flags, start + 4);
    buffer.writeBigUInt64LE(BigInt(offset), start + 8);
    buffer.writeBigUInt64LE(BigInt(address), start + 16);
    buffer.writeBigUInt64LE(BigInt(address), start + 24);
    buffer.writeBigUInt64LE(BigInt(fileSize), start + 32);
    buffer.writeBigUInt64LE(BigInt(memorySize), start + 40);
    buffer.writeBigUInt64LE(8n, start + 48);
  };
  writeProgramHeader(0, 4, 4, noteOffset, 0, note.length, note.length);
  writeProgramHeader(1, 1, 5, loadOffset, 0x400000, loadData.length, 0x2000);
  note.copy(buffer, noteOffset);
  loadData.copy(buffer, loadOffset);
  fs.mkdirSync(path.dirname(filePath), { recursive: true });
  fs.writeFileSync(filePath, buffer);
  return filePath;
}

function createAarch64PwnElf(filePath) {
  createPwnElf64(filePath, "flag{aarch64_static_smoke}");
  const buffer = fs.readFileSync(filePath);
  buffer.writeUInt16LE(183, 18);
  const textStart = buffer.indexOf(Buffer.from([0x5f, 0xc3, 0x5e, 0x41, 0x5f, 0xc3]));
  if (textStart < 0) {
    throw new Error("unable to locate synthetic ELF text section");
  }
  Buffer.from([
    0xc0, 0x03, 0x5f, 0xd6,
    0x01, 0x00, 0x00, 0xd4,
    0x00, 0x02, 0x1f, 0xd6,
    0xfd, 0x7b, 0xc1, 0xa8,
    0xc0, 0x03, 0x5f, 0xd6,
  ]).copy(buffer, textStart);
  fs.writeFileSync(filePath, buffer);
  return filePath;
}

function createBrainfuckPrint(text) {
  let current = 0;
  let program = "";
  for (const char of text) {
    const target = char.charCodeAt(0);
    const up = (target - current + 256) & 0xff;
    const down = (current - target + 256) & 0xff;
    if (up <= down) {
      program += "+".repeat(up);
    } else {
      program += "-".repeat(down);
    }
    program += ".";
    current = target;
  }
  return program;
}

function brainfuckToOok(program) {
  const map = {
    ">": "Ook. Ook?",
    "<": "Ook? Ook.",
    "+": "Ook. Ook.",
    "-": "Ook! Ook!",
    ".": "Ook! Ook.",
    ",": "Ook. Ook!",
    "[": "Ook! Ook?",
    "]": "Ook? Ook!",
  };
  return Array.from(program).map((op) => map[op]).filter(Boolean).join(" ");
}

function affineEncode(text, multiplier, shift) {
  return String(text || "").replace(/[A-Za-z]/g, (char) => {
    const code = char.charCodeAt(0);
    const base = code >= 97 ? 97 : 65;
    const value = code - base;
    return String.fromCharCode(((value * multiplier + shift) % 26) + base);
  });
}

function railFenceEncode(text, rails) {
  const rows = Array.from({ length: rails }, () => []);
  let rail = 0;
  let direction = 1;
  for (const char of String(text || "")) {
    rows[rail].push(char);
    if (rail === 0) direction = 1;
    if (rail === rails - 1) direction = -1;
    rail += direction;
  }
  return rows.map((row) => row.join("")).join("");
}

function base91Encode(text) {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!#$%&()*+,./:;<=>?@[]^_`{|}~\"";
  const bytes = Buffer.from(text, "utf8");
  let accumulator = 0;
  let bits = 0;
  let output = "";

  for (const byte of bytes) {
    accumulator |= byte << bits;
    bits += 8;
    if (bits > 13) {
      let value = accumulator & 8191;
      if (value > 88) {
        accumulator >>= 13;
        bits -= 13;
      } else {
        value = accumulator & 16383;
        accumulator >>= 14;
        bits -= 14;
      }
      output += alphabet[value % 91] + alphabet[Math.floor(value / 91)];
    }
  }

  if (bits) {
    output += alphabet[accumulator % 91];
    if (bits > 7 || accumulator > 90) {
      output += alphabet[Math.floor(accumulator / 91)];
    }
  }

  return output;
}

function z85Encode(text) {
  const alphabet = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ.-:+=^!/*?&<>()[]{}@%$#";
  const buffer = Buffer.from(text, "utf8");
  if (buffer.length % 4 !== 0) {
    throw new Error("Z85 smoke fixture text length must be divisible by 4");
  }

  let output = "";
  for (let index = 0; index < buffer.length; index += 4) {
    let value = buffer.readUInt32BE(index);
    const encoded = new Array(5);
    for (let digit = 4; digit >= 0; digit -= 1) {
      encoded[digit] = alphabet[value % 85];
      value = Math.floor(value / 85);
    }
    output += encoded.join("");
  }
  return output;
}

function dna2BitEncode(text) {
  const alphabet = ["A", "C", "G", "T"];
  return Array.from(Buffer.from(text, "utf8"))
    .map((byte) => byte.toString(2).padStart(8, "0").match(/../g).map((bits) => alphabet[parseInt(bits, 2)]).join(""))
    .join("");
}

function a1z26Encode(text) {
  return String(text || "")
    .toUpperCase()
    .split("")
    .map((char) => (/[A-Z]/.test(char) ? String(char.charCodeAt(0) - 64) : char === "-" ? "/" : ""))
    .filter(Boolean)
    .join(" ");
}

function uuencodeText(text, fileName = "flag.txt") {
  const bytes = Buffer.from(text, "utf8");
  const lines = [`begin 644 ${fileName}`];
  for (let offset = 0; offset < bytes.length; offset += 45) {
    const chunk = bytes.subarray(offset, offset + 45);
    let line = String.fromCharCode((chunk.length & 0x3f) + 32);
    for (let index = 0; index < chunk.length; index += 3) {
      const block = Buffer.concat([chunk.subarray(index, index + 3), Buffer.alloc(Math.max(0, 3 - (chunk.length - index)))]);
      const values = [block[0] >> 2, ((block[0] & 0x03) << 4) | (block[1] >> 4), ((block[1] & 0x0f) << 2) | (block[2] >> 6), block[2] & 0x3f];
      line += values.map((value) => String.fromCharCode((value & 0x3f) + 32)).join("");
    }
    lines.push(line);
  }
  lines.push("`", "end");
  return `${lines.join("\n")}\n`;
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

  const placeholderPath = writeText(path.join(root, "input", "placeholder-flag.txt"), "uoftctf{FAKEFLAG}\n");
  results.push(
    await runNoFlagCase(root, "placeholder-flag-filter", {
      title: "placeholder flag filter smoke",
      description: "Distribution placeholders must not become direct or transformed flag candidates.",
      artifacts: [placeholderPath],
    }),
  );

  const randomFlagPath = writeText(
    path.join(root, "input", "random-braces.txt"),
    "zzz{zzzzzz}\n74Ea{`qp9Df}\nNjpkz{2Omvqk~}\nlmv{rr>3[p}\n",
  );
  results.push(
    await runNoFlagCase(root, "random-flag-shape-filter", {
      title: "random transformed brace text",
      description: "Low-diversity and punctuation-heavy transformed strings must not mark a task solved.",
      artifacts: [randomFlagPath],
    }),
  );

  const dtmfMessage = "onlyninetieskidswillrememberthis";
  const dtmfFlag = `FLAG{${dtmfMessage}}`;
  const dtmfPath = writeText(path.join(root, "input", "dtmf-combined.txt"), `${encodeDtmfMultitap(dtmfMessage)}\n`);
  results.push(
    await runCase(
      root,
      "dtmf-combined-multitap",
      {
        title: "DTMF combined-frequency smoke",
        description: "Decode the alphanumeric message and wrap it in `FLAG{}`.",
        artifacts: [dtmfPath],
      },
      dtmfFlag,
    ),
  );

  const alphabetToneFlag = "flag{tonealphabetwavesmoke}";
  const alphabetTonePath = createAlphabetToneWav(
    path.join(root, "input", "alphabet-tones.wav"),
    "flagopenbrackettonealphabetwavesmokeclosebracket",
  );
  results.push(
    await runCase(
      root,
      "wav-alphabet-tone-map",
      {
        title: "WAV alphabet tone mapping smoke",
        description: "Use the leading alphabet tones as the decode key.",
        artifacts: [alphabetTonePath],
      },
      alphabetToneFlag,
    ),
  );

  const interleavedPngPath = createInterleavedPngFixture(path.join(root, "input", "interleaved.png"));
  results.push(await runInterleavedRecoveryCase(root, interleavedPngPath));

  const usbFlag = "flag{usb_hid_smoke}";
  const usbPcapPath = createUsbKeyboardPcap(path.join(root, "input", "usb-keyboard.pcap"), usbFlag);
  results.push(
    await runCase(
      root,
      "usb-hid-keyboard",
      {
        title: "USB HID keyboard smoke",
        description: "USBPcap keyboard reports should be reconstructed into text.",
        artifacts: [usbPcapPath],
      },
      usbFlag,
    ),
  );

  const vcdFlag = "flag{vcd_spi_signal_smoke}";
  const vcdPath = createSpiVcd(path.join(root, "input", "logic.vcd"), vcdFlag);
  results.push(
    await runCase(
      root,
      "vcd-spi-signal",
      {
        title: "VCD SPI signal smoke",
        description: "Sample a VCD bus and reverse a simple per-byte transform.",
        tags: ["hardware", "vcd", "spi"],
        artifacts: [vcdPath],
      },
      vcdFlag,
    ),
  );

  const uartFlag = "flag{uart_signal_smoke}";
  const uartPath = createUartVcd(path.join(root, "input", "uart.vcd"), uartFlag);
  results.push(
    await runReportFlagCase(
      root,
      "vcd-uart-signal",
      {
        title: "VCD UART signal smoke",
        description: "Recover an asynchronous 8N1 UART byte stream without an external decoder.",
        tags: ["hardware", "vcd", "uart"],
        artifacts: [uartPath],
      },
      uartFlag,
      "-signal-analysis.txt",
      /## UART attempts[\s\S]*TX period=10 .*frames=/,
    ),
  );

  const i2cFlag = "flag{i2c_signal_smoke}";
  const i2cPath = createI2cVcd(path.join(root, "input", "i2c.vcd"), i2cFlag);
  results.push(
    await runReportFlagCase(
      root,
      "vcd-i2c-signal",
      {
        title: "VCD I2C signal smoke",
        description: "Sample SCL rising edges, remove ACK bits, and recover the I2C data stream.",
        tags: ["hardware", "vcd", "i2c"],
        artifacts: [i2cPath],
      },
      i2cFlag,
      "-signal-analysis.txt",
      /I2C SCL\/SDA offset=.*ack=1\.00/,
    ),
  );

  const canFlag = "flag{can_payload_smoke}";
  const canPath = createCanLog(path.join(root, "input", "candump.log"), canFlag);
  results.push(
    await runReportFlagCase(
      root,
      "can-log-payload",
      {
        title: "CAN candump payload smoke",
        description: "Aggregate CAN payloads by arbitration ID and recover readable content.",
        tags: ["hardware", "can", "candump"],
        artifacts: [canPath],
      },
      canFlag,
      "-signal-analysis.txt",
      /kind: can-log[\s\S]*0x321/,
    ),
  );

  const icmpFlag = "flag{icmp_covert_smoke}";
  const icmpPath = createIcmpCovertPcap(path.join(root, "input", "icmp-covert.pcap"), icmpFlag);
  results.push(
    await runReportFlagCase(
      root,
      "icmp-covert-traffic",
      {
        title: "ICMP covert traffic smoke",
        description: "Concatenate ICMP echo payloads and surface covert-channel candidates.",
        tags: ["misc", "pcap", "icmp", "covert"],
        artifacts: [icmpPath],
      },
      icmpFlag,
      "-traffic-summary.txt",
      /ICMP payload[\s\S]*flag\{icmp_covert_smoke\}/,
    ),
  );

  const logicCsvFlag = "flag{logic_csv_gate_smoke}";
  const logicCsvPath = createLogicCsv(path.join(root, "input", "logic.csv"), logicCsvFlag);
  results.push(
    await runCase(
      root,
      "logic-csv-gates",
      {
        title: "logic CSV gate smoke",
        description: "Recover a bitstream from a common four-input gate expression.",
        tags: ["hardware", "logic", "csv"],
        artifacts: [logicCsvPath],
      },
      logicCsvFlag,
    ),
  );

  const wrongDimensionPng = createPngWrongDimensions(path.join(root, "input", "wrong-dimensions.png"));
  results.push(await runPngDimensionCase(root, wrongDimensionPng));

  const modelFlag = "flag{model_metadata_smoke}";
  const modelPath = createSafetensorsFixture(path.join(root, "input", "challenge.safetensors"), modelFlag);
  results.push(await runModelCase(root, modelPath, modelFlag));

  const pwnFlag = "flag{pwn_static_smoke}";
  const pwnElfPath = createPwnElf64(path.join(root, "input", "pwn-smoke.elf"), pwnFlag);
  results.push(await runPwnCase(root, pwnElfPath, pwnFlag));

  const aarch64ElfPath = createAarch64PwnElf(path.join(root, "input", "pwn-aarch64-smoke.elf"));
  results.push(await runAarch64PwnCase(root, aarch64ElfPath));

  const corePath = createElfCoreFixture(path.join(root, "input", "crash.core"));
  results.push(await runCoreDumpCase(root, corePath));

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

  const tgzFlag = "flag{tgz_tar_recursive_smoke}";
  const tgzPath = createTgz(path.join(root, "input", "recursive.tgz"), tgzFlag);
  results.push(
    await runCase(
      root,
      "tgz-tar-recursive",
      {
        title: "tgz tar recursive smoke",
        description: "TGZ should inflate to TAR and recursively expose the flag file.",
        artifacts: [tgzPath],
      },
      tgzFlag,
    ),
  );

  const bmpFlag = "flag{bmp_lsb_smoke}";
  const bmpPath = createBmpLsb(path.join(root, "input", "hidden.bmp"), bmpFlag);
  results.push(
    await runCase(
      root,
      "bmp-lsb",
      {
        title: "bmp lsb smoke",
        description: "BMP blue-channel LSB should be decoded locally.",
        artifacts: [bmpPath],
      },
      bmpFlag,
    ),
  );

  const gifFlag = "flag{gif_comment_smoke}";
  const gifPath = createGifSplitComment(path.join(root, "input", "comment.gif"), ["flag{gif_", "comment_", "smoke}"]);
  results.push(
    await runCase(
      root,
      "gif-split-comment",
      {
        title: "gif split comment smoke",
        description: "GIF comment sub-blocks should be reassembled before flag scanning.",
        artifacts: [gifPath],
      },
      gifFlag,
    ),
  );

  const gifDescriptorFlag = "flag{gif_descriptor_bits_smoke}";
  const gifDescriptorPath = createGifDescriptorBits(path.join(root, "input", "descriptor-bits.gif"), gifDescriptorFlag);
  results.push(
    await runCase(
      root,
      "gif-descriptor-bits",
      {
        title: "gif descriptor bitstream smoke",
        description: "GIF image descriptor packed bits should be reconstructed into bytes.",
        artifacts: [gifDescriptorPath],
      },
      gifDescriptorFlag,
    ),
  );

  const mp4Flag = "flag{mp4_hidden_track_smoke}";
  const mp4Path = createMp4HiddenTrack(path.join(root, "input", "hidden-track.mp4"), mp4Flag);
  results.push(
    await runCase(
      root,
      "mp4-hidden-track",
      {
        title: "mp4 hidden track smoke",
        description: "A trailing free box after moov should be identified and repaired as a track.",
        artifacts: [mp4Path],
      },
      mp4Flag,
    ),
  );

  const quotedPrintableFlag = "FLAG-QP-SMOKE";
  const quotedPrintablePath = writeText(path.join(root, "input", "quoted-printable.txt"), "=46=4C=41=47=2D=51=50=2D=53=4D=4F=4B=45\n");
  results.push(
    await runCase(
      root,
      "quoted-printable-text",
      {
        title: "quoted printable smoke",
        description: "Quoted-Printable byte escapes should decode locally.",
        artifacts: [quotedPrintablePath],
      },
      quotedPrintableFlag,
    ),
  );

  const uuencodeFlag = "FLAG-UUENCODE-SMOKE";
  const uuencodePath = writeText(path.join(root, "input", "uuencode.txt"), uuencodeText(uuencodeFlag));
  results.push(
    await runCase(
      root,
      "uuencode-text",
      {
        title: "uuencode smoke",
        description: "UUEncode blocks should decode locally.",
        artifacts: [uuencodePath],
      },
      uuencodeFlag,
    ),
  );

  const base91Flag = "FLAG-BASE91-SMOKE";
  const base91Path = writeText(path.join(root, "input", "base91.txt"), `${base91Encode(base91Flag)}\n`);
  results.push(
    await runCase(
      root,
      "base91-text",
      {
        title: "base91 smoke",
        description: "Base91 text should decode locally.",
        artifacts: [base91Path],
      },
      base91Flag,
    ),
  );

  const z85Flag = "FLAG-Z85-SMOKE12";
  const z85Path = writeText(path.join(root, "input", "z85.txt"), `${z85Encode(z85Flag)}\n`);
  results.push(
    await runCase(
      root,
      "z85-text",
      {
        title: "z85 smoke",
        description: "Z85 text should decode locally.",
        artifacts: [z85Path],
      },
      z85Flag,
    ),
  );

  const a1z26Flag = "FLAG-AZ-SMOKE";
  const a1z26Path = writeText(path.join(root, "input", "a1z26.txt"), `${a1z26Encode(a1z26Flag)}\n`);
  results.push(
    await runCase(
      root,
      "a1z26-text",
      {
        title: "a1z26 smoke",
        description: "A1Z26 number streams should decode locally.",
        artifacts: [a1z26Path],
      },
      a1z26Flag,
    ),
  );

  const natoFlag = "FLAG-NATO-SMOKE";
  const natoPath = writeText(
    path.join(root, "input", "nato.txt"),
    "foxtrot lima alpha golf dash november alpha tango oscar dash sierra mike oscar kilo echo\n",
  );
  results.push(
    await runCase(
      root,
      "nato-text",
      {
        title: "nato phonetic smoke",
        description: "NATO phonetic words should decode locally.",
        artifacts: [natoPath],
      },
      natoFlag,
    ),
  );

  const dnaFlag = "FLAG-DNA-SMOKE";
  const dnaPath = writeText(path.join(root, "input", "dna.txt"), `${dna2BitEncode(dnaFlag)}\n`);
  results.push(
    await runCase(
      root,
      "dna-2bit-text",
      {
        title: "dna two bit smoke",
        description: "DNA 2-bit nucleotide streams should decode locally.",
        artifacts: [dnaPath],
      },
      dnaFlag,
    ),
  );

  const affineFlag = "FLAG-AFFINE-SMOKE";
  const affinePath = writeText(path.join(root, "input", "affine.txt"), `${affineEncode(affineFlag, 5, 8)}\n`);
  results.push(
    await runCase(
      root,
      "affine-text",
      {
        title: "affine cipher smoke",
        description: "Small affine brute force should recover the flag candidate.",
        artifacts: [affinePath],
      },
      affineFlag,
    ),
  );

  const railFlag = "FLAG-RAIL-SMOKE";
  const railPath = writeText(path.join(root, "input", "rail.txt"), `${railFenceEncode(railFlag, 3)}\n`);
  results.push(
    await runCase(
      root,
      "rail-fence-text",
      {
        title: "rail fence smoke",
        description: "Rail fence brute force should recover the flag candidate.",
        artifacts: [railPath],
      },
      railFlag,
    ),
  );

  const morseFlag = "FLAG-MORSE-SMOKE";
  const morsePath = writeText(
    path.join(root, "input", "morse.txt"),
    "..-. .-.. .- --. -....- -- --- .-. ... . -....- ... -- --- -.- .\n",
  );
  results.push(
    await runCase(
      root,
      "morse-text",
      {
        title: "morse misc smoke",
        description: "Text Morse should be decoded locally without audio tooling.",
        artifacts: [morsePath],
      },
      morseFlag,
    ),
  );

  const polybiusFlag = "FLAG-POLYBIUS-SMOKE";
  const polybiusPath = writeText(path.join(root, "input", "polybius.txt"), "21 31 11 22 / 35 34 31 54 12 24 45 43 / 43 32 34 25 15\n");
  results.push(
    await runCase(
      root,
      "polybius-text",
      {
        title: "polybius misc smoke",
        description: "Polybius coordinates should be decoded locally.",
        artifacts: [polybiusPath],
      },
      polybiusFlag,
    ),
  );

  const ookFlag = "FLAG-OOK-SMOKE";
  const ookPath = writeText(path.join(root, "input", "ook.txt"), `${brainfuckToOok(createBrainfuckPrint(ookFlag))}\n`);
  results.push(
    await runCase(
      root,
      "ook-text",
      {
        title: "ook brainfuck dialect smoke",
        description: "Ook should normalize to Brainfuck and emit a flag candidate.",
        artifacts: [ookPath],
      },
      ookFlag,
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
