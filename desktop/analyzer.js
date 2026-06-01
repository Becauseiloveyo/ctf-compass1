const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const zlib = require("zlib");
const AdmZip = require("adm-zip");
const Quagga = require("@ericblade/quagga2").default;
const ExifParser = require("exif-parser");
const jpeg = require("jpeg-js");
const jsQR = require("jsqr");
const { PNG } = require("pngjs");
const { getToolActionsForArtifact, getToolStatusSummary, isToolActionAutoRunnable, runToolAction } = require("./toolkit");

const MAX_FILES = 160;
const MAX_SAMPLE_BYTES = 1024 * 1024;
const MAX_TEXT_BYTES = 512 * 1024;
const MAX_ARCHIVE_ENTRIES = 80;
const MAX_ARCHIVE_TOTAL_BYTES = 32 * 1024 * 1024;
const MAX_PIPELINE_DEPTH = 3;
const MAX_TRAFFIC_BYTES = 24 * 1024 * 1024;
const MAX_TRAFFIC_FRAMES = 12000;
const MAX_HTTP_OBJECTS = 24;
const MAX_HTTP_BODY_BYTES = 512 * 1024;
const MAX_AUDIO_BYTES = 12 * 1024 * 1024;
const MAX_AUDIO_SAMPLES = 600000;
const MAX_AUDIO_PREVIEW_SAMPLES = 180000;
const MAX_AUDIO_ANALYSIS_SAMPLES = 320000;
const MAX_AUDIO_SPECTROGRAM_COLUMNS = 360;
const MAX_AUDIO_SPECTROGRAM_BINS = 96;
const BARCODE_READERS = [
  "code_128_reader",
  "code_39_reader",
  "code_93_reader",
  "codabar_reader",
  "ean_reader",
  "ean_8_reader",
  "upc_reader",
  "upc_e_reader",
  "i2of5_reader",
  "2of5_reader",
];
const BARCODE_ATTEMPTS = [
  {
    inputStream: { size: 0 },
    locate: true,
    locator: { patchSize: "medium", halfSample: false },
    decoder: { readers: BARCODE_READERS },
  },
  {
    inputStream: { size: 0 },
    locate: false,
    decoder: { readers: BARCODE_READERS },
  },
  {
    inputStream: { size: 1200 },
    locate: true,
    locator: { patchSize: "large", halfSample: false },
    decoder: { readers: BARCODE_READERS },
  },
];
const MORSE_DECODE_MAP = {
  ".-": "A",
  "-...": "B",
  "-.-.": "C",
  "-..": "D",
  ".": "E",
  "..-.": "F",
  "--.": "G",
  "....": "H",
  "..": "I",
  ".---": "J",
  "-.-": "K",
  ".-..": "L",
  "--": "M",
  "-.": "N",
  "---": "O",
  ".--.": "P",
  "--.-": "Q",
  ".-.": "R",
  "...": "S",
  "-": "T",
  "..-": "U",
  "...-": "V",
  ".--": "W",
  "-..-": "X",
  "-.--": "Y",
  "--..": "Z",
  "-----": "0",
  ".----": "1",
  "..---": "2",
  "...--": "3",
  "....-": "4",
  ".....": "5",
  "-....": "6",
  "--...": "7",
  "---..": "8",
  "----.": "9",
  ".-.-.-": ".",
  "--..--": ",",
  "..--..": "?",
  "-..-.": "/",
  "-....-": "-",
  "..--.-": "_",
  ".--.-.": "@",
};

const EMBEDDED_SIGNATURES = [
  { id: "zip", label: "ZIP", ext: ".zip", magic: Buffer.from([0x50, 0x4b, 0x03, 0x04]) },
  { id: "gzip", label: "GZIP", ext: ".gz", magic: Buffer.from([0x1f, 0x8b, 0x08]) },
  { id: "png", label: "PNG", ext: ".png", magic: Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]) },
  { id: "pdf", label: "PDF", ext: ".pdf", magic: Buffer.from("%PDF") },
  { id: "elf", label: "ELF", ext: ".elf", magic: Buffer.from([0x7f, 0x45, 0x4c, 0x46]) },
  { id: "sevenzip", label: "7Z", ext: ".7z", magic: Buffer.from([0x37, 0x7a, 0xbc, 0xaf, 0x27, 0x1c]) },
  { id: "rar", label: "RAR", ext: ".rar", magic: Buffer.from([0x52, 0x61, 0x72, 0x21, 0x1a, 0x07]) },
];

const COPY = {
  app: {
    unnamed: "\u672a\u547d\u540d\u9898\u76ee",
    noFlags: "\u6682\u672a\u53d1\u73b0\u76f4\u63a5 flag\uff0c\u4f18\u5148\u68c0\u67e5\u9644\u4ef6\u7ec6\u8282\u3001\u7f16\u7801\u53d8\u6362\u548c\u6d41\u91cf\u4f1a\u8bdd\u3002",
    truncated: `\u4e3a\u4fdd\u8bc1\u901f\u5ea6\uff0c\u672c\u6b21\u6700\u591a\u89e3\u6790 ${MAX_FILES} \u4e2a\u6587\u4ef6\u3002`,
  },
  categories: {
    crypto: "\u5bc6\u7801",
    web: "Web",
    reverse: "\u9006\u5411",
    pwn: "Pwn",
    forensic: "\u53d6\u8bc1",
    misc: "\u6742\u9879",
  },
  families: {
    text: "\u6587\u672c",
    image: "\u56fe\u50cf",
    audio: "\u97f3\u9891",
    network: "\u6d41\u91cf",
    archive: "\u538b\u7f29\u5305",
    binary: "\u4e8c\u8fdb\u5236",
    document: "\u6587\u6863",
    unknown: "\u5176\u4ed6",
  },
  summary: {
    crypto: "\u5148\u5904\u7406\u7f16\u7801\u3001\u6570\u5b66\u5173\u7cfb\u548c\u53c2\u6570\u590d\u7528\u95ee\u9898\uff0c\u518d\u5224\u65ad\u662f\u5426\u8fdb\u5165\u5bc6\u7801\u5206\u6790\u3002",
    web: "\u5148\u68b3\u7406\u8def\u7531\u3001\u8bf7\u6c42\u3001Cookie\u3001\u4e0a\u4f20\u70b9\u548c\u4f1a\u8bdd\u8fb9\u754c\uff0c\u518d\u9501\u5b9a\u6f0f\u6d1e\u7c7b\u578b\u3002",
    reverse: "\u4ece strings\u3001\u5bfc\u5165\u8868\u3001\u67b6\u6784\u548c\u6821\u9a8c\u6d41\u7a0b\u5165\u624b\uff0c\u5148\u6062\u590d\u7a0b\u5e8f\u903b\u8f91\u518d\u5904\u7406 flag \u8def\u5f84\u3002",
    pwn: "\u5148\u5224\u65ad\u4e8c\u8fdb\u5236\u4fdd\u62a4\u3001I/O \u6a21\u5f0f\u548c\u5185\u5b58\u539f\u8bed\uff0c\u4e0d\u8981\u5728\u6ca1\u5b9a\u6027\u524d\u76f2\u731c\u5229\u7528\u94fe\u3002",
    forensic: "\u5148\u4fdd\u5168\u8bc1\u636e\uff0c\u68b3\u7406\u9644\u4ef6\u548c\u6d41\u91cf\u75d5\u8ff9\uff0c\u91cd\u70b9\u770b\u9690\u85cf\u6570\u636e\u3001\u5d4c\u5957\u6587\u4ef6\u548c\u4ea4\u4e92\u8bb0\u5f55\u3002",
    misc: "\u9898\u76ee\u53ef\u80fd\u6d89\u53ca\u56fe\u50cf\u9690\u5199\u3001\u7f16\u7801\u53d8\u6362\u3001\u6587\u4ef6\u9690\u85cf\u6216\u534f\u8bae\u7ec4\u88c5\uff0c\u5148\u505a\u7c7b\u578b\u7f29\u7a84\u3002",
  },
  nextMoves: {
    crypto: [
      "\u5148\u628a\u9644\u4ef6\u91cc\u53ef\u89c1\u7684\u5b57\u7b26\u4e32\u3001base64\u3001hex \u548c\u6570\u5b66\u5e38\u91cf\u62bd\u51fa\u6765\u3002",
      "\u68c0\u67e5\u662f\u5426\u6709 XOR\u3001RSA\u3001\u91cd\u590d nonce\u3001padding \u5f02\u5e38\u6216\u5bc6\u6587\u5206\u5757\u7279\u5f81\u3002",
      "\u5982\u679c\u9644\u4ef6\u662f txt\u3001log \u6216 payload\uff0c\u5148\u628a\u7f16\u7801\u5c42\u8fd8\u539f\u518d\u8003\u8651\u5bc6\u7801\u5c42\u3002",
    ],
    web: [
      "\u7528\u9644\u4ef6\u548c\u9898\u9762\u68b3\u7406 URL\u3001Cookie\u3001Token\u3001\u4e0a\u4f20\u70b9\u548c\u8fd4\u56de\u5f02\u5e38\u4fe1\u606f\u3002",
      "\u5982\u679c\u6709 pcap \u6216 HTTP \u65e5\u5fd7\uff0c\u5148\u91cd\u5efa\u4f1a\u8bdd\u3001\u53c2\u6570\u548c\u6587\u4ef6\u4f20\u8f93\u8def\u5f84\u3002",
      "\u4f18\u5148\u5224\u65ad\u662f auth\u3001template\u3001upload\u3001deserialize \u8fd8\u662f SSRF \u65b9\u5411\u3002",
    ],
    reverse: [
      "\u5148\u770b strings \u548c\u5bfc\u5165\u51fd\u6570\uff0c\u786e\u8ba4\u7a0b\u5e8f\u662f\u5426\u5b58\u5728\u660e\u663e\u7684\u6821\u9a8c\u548c\u89e3\u7801\u903b\u8f91\u3002",
      "\u5bf9 ELF\u3001PE\u3001APK \u5206\u522b\u505a\u67b6\u6784\u548c\u884c\u4e3a\u5206\u6d41\uff0c\u4f18\u5148\u8ddf\u8fdb flag \u751f\u6210\u8def\u5f84\u3002",
      "\u5982\u679c strings \u91cc\u6709 flag \u7247\u6bb5\u3001key\u3001check \u7b49\u63d0\u793a\uff0c\u76f4\u63a5\u56de\u5230\u76f8\u5e94\u51fd\u6570\u3002",
    ],
    pwn: [
      "\u68c0\u67e5 ELF \u548c libc \u7ebf\u7d22\uff0c\u786e\u8ba4\u4fdd\u62a4\u9879\u540e\u518d\u9009\u62e9 ret2libc\u3001ROP \u6216 heap \u65b9\u5411\u3002",
      "\u5148\u627e\u8f93\u5165\u70b9\u3001\u5d29\u6e83\u70b9\u548c\u63a7\u5236\u6d41\u6539\u5199\u53ef\u80fd\u6027\uff0c\u4e0d\u8981\u76f4\u63a5\u731c\u5229\u7528\u94fe\u3002",
      "\u5982\u679c\u9644\u4ef6\u91cc\u6709 core\u3001log \u6216 pcap\uff0c\u628a\u8f93\u5165\u6d41\u7a0b\u4e0e\u5185\u5b58\u5f02\u5e38\u5bf9\u5e94\u8d77\u6765\u3002",
    ],
    forensic: [
      "\u4f18\u5148\u6309\u9644\u4ef6\u7c7b\u578b\u5206\u7ec4\uff1a\u56fe\u50cf\u3001\u6587\u672c\u3001\u6d41\u91cf\u5305\u3001\u538b\u7f29\u5305\u3001\u4e8c\u8fdb\u5236\u3002",
      "\u5bf9 pcap/pcapng \u5148\u770b HTTP\u3001DNS\u3001TLS \u63e1\u624b\u3001\u5bfc\u51fa\u5bf9\u8c61\u548c cookie/token\u3002",
      "\u5bf9\u56fe\u50cf\u548c\u538b\u7f29\u5305\u5148\u67e5\u770b\u9690\u85cf\u6587\u4ef6\u3001\u989d\u5916\u5c3e\u90e8\u6570\u636e\u548c\u5143\u6570\u636e\u3002",
    ],
    misc: [
      "\u5148\u7528\u9644\u4ef6\u63d0\u793a\u7f29\u5c0f\u9898\u578b\uff0c\u4e0d\u8981\u53ea\u9760\u6807\u9898\u548c\u63cf\u8ff0\u3002",
      "\u56fe\u50cf\u8d70\u9690\u5199\u3001\u6587\u672c\u8d70\u7f16\u7801/\u52a0\u5bc6\u3001pcap \u8d70\u6d41\u91cf\u8fd8\u539f\uff0c\u538b\u7f29\u5305\u8d70\u5d4c\u5957\u6587\u4ef6\u5206\u6790\u3002",
      "\u672a\u627e\u5230\u76f4\u63a5 flag \u65f6\uff0c\u4ece\u6700\u6709\u4fe1\u606f\u91cf\u7684\u9644\u4ef6\u5f00\u59cb\u5012\u63a8\u3002",
    ],
  },
  tools: {
    crypto: ["CyberChef", "SageMath", "Python \u7b14\u8bb0\u672c"],
    web: ["Burp Suite", "\u6d4f\u89c8\u5668\u5f00\u53d1\u8005\u5de5\u5177", "ffuf / dirsearch"],
    reverse: ["Ghidra", "IDA Free", "strings", "binwalk"],
    pwn: ["pwndbg", "checksec", "GDB", "ROPgadget"],
    forensic: ["Wireshark", "Autopsy", "binwalk", "exiftool"],
    misc: ["CyberChef", "binwalk", "zsteg", "Wireshark"],
  },
};

const BUNDLED_TOOL_CAPABILITIES = [
  {
    id: "strings-lite",
    label: "内置 strings-lite",
    replaces: "strings",
    purpose: "提取 ASCII / UTF-16 字符串、URL、token 和 flag 样式候选。",
  },
  {
    id: "binwalk-lite",
    label: "内置 binwalk-lite",
    replaces: "binwalk scan",
    purpose: "按魔数扫描 ZIP、GZIP、PNG、PDF、ELF、7Z、RAR 等嵌入载荷并递归提取。",
  },
  {
    id: "ciphey-lite",
    label: "内置 ciphey-lite",
    replaces: "Ciphey",
    purpose: "自动尝试 Base64/Base58、Hex、Base32、Ascii85、URL、二进制/十进制字节、ROT/Caesar、Bacon、Brainfuck、零宽/空白隐写、单字节 XOR 和压缩文本层。",
  },
  {
    id: "zsteg-lite",
    label: "内置 zsteg-lite",
    replaces: "zsteg",
    purpose: "扫描 PNG 文本块与常见 RGB/RGBA 低位平面可读文本候选。",
  },
  {
    id: "tshark-lite",
    label: "内置 tshark-lite",
    replaces: "TShark basic",
    purpose: "离线解析 pcap/pcapng 基础帧、HTTP、DNS、TLS SNI、Cookie/Token 和 HTTP 对象。",
  },
  {
    id: "binary-lite",
    label: "内置 rabin2/exif-lite",
    replaces: "rabin2 / exiftool subset",
    purpose: "解析 ELF/PE/APK/PDF/WAV/JPEG/PNG 的关键结构和元数据线索。",
  },
];

const CATEGORY_RULES = {
  crypto: ["rsa", "aes", "xor", "cipher", "nonce", "modulus", "prime", "decrypt", "encrypt", "base64", "hex"],
  web: ["http", "https", "cookie", "session", "jwt", "request", "route", "upload", "template", "csrf", "xss", "sql", "login"],
  reverse: ["binary", "elf", "pe32", "exe", "dll", "ghidra", "ida", "strings", "disasm", "symbol", "apk", "java"],
  pwn: ["overflow", "heap", "rop", "libc", "canary", "format string", "uaf", "fastbin", "tcache", "stack smashing"],
  forensic: ["pcap", "pcapng", "traffic", "dns", "http", "memory", "disk", "metadata", "artifact", "timeline", "capture"],
  misc: ["stego", "steganography", "puzzle", "logic", "encoding", "qr", "audio", "image", "hidden", "zip"],
};

const KNOWN_FLAG_PREFIX = /\b(?:flag|ctf|key|answer|picoCTF|moectf|actf|hitcon|sekai|balsn|uiuctf|n1ctf)\{/i;
const LOOSE_FLAG_PREFIX = /\bflag\s*[:=_-]\s*[a-zA-Z0-9_\/+=-]{6,160}\b/i;
const LOOSE_FLAG_PREFIX_GLOBAL = /\bflag\s*[:=_-]\s*[a-zA-Z0-9_\/+=-]{6,160}\b/gi;
const NATURAL_TEXT_HINT = /\b(?:the|this|that|flag|password|secret|cookie|session|token|login|http|https|user|admin|hello|world|image|file|data|text)\b/i;
const OFFICE_DOCUMENT_EXTENSIONS = [".docx", ".xlsx", ".pptx", ".docm", ".xlsm", ".pptm", ".odt", ".ods", ".odp"];

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

function dedupeStrings(values) {
  return Array.from(new Set(values.filter(Boolean)));
}

function attachToolBackedActions(artifact) {
  const toolActions = getToolActionsForArtifact(artifact);
  artifact.toolActions = toolActions;

  const runnable = toolActions.filter((item) => item.available);
  runnable.forEach((item) => {
    artifact.actions.push({
      id: item.id,
      label: item.label,
    });
  });

  const runnableLabels = dedupeStrings(runnable.map((item) => item.toolLabel));
  if (runnableLabels.length) {
    artifact.highlights.push(`可直接调用外部工具：${runnableLabels.join(" / ")}。`);
  }

  const missingLabels = dedupeStrings(toolActions.filter((item) => !item.available).map((item) => item.toolLabel));
  if (missingLabels.length) {
    artifact.suggestions.push(`安装后可增强自动化：${missingLabels.join(" / ")}。`);
  }
}

function sanitizeSegment(value) {
  return String(value || "")
    .replace(/[<>:"/\\|?*\x00-\x1f]/g, "_")
    .replace(/\s+/g, "-")
    .slice(0, 80);
}

function shortHash(value) {
  return crypto.createHash("sha1").update(String(value)).digest("hex").slice(0, 8);
}

function safeArchivePath(entryName) {
  return entryName
    .split(/[\\/]+/)
    .filter(Boolean)
    .map((segment) => sanitizeSegment(segment) || "_")
    .join(path.sep);
}

function extractPrintableSegments(text, minLength = 8, maxCount = 20) {
  return dedupeStrings(
    Array.from(text.matchAll(new RegExp(`[\\x20-\\x7E]{${minLength},}`, "g")))
      .map((match) => match[0].trim())
      .filter((value) => value.length >= minLength)
      .slice(0, maxCount),
  );
}

function base32Decode(value) {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  let bits = "";
  const cleaned = value.toUpperCase().replace(/=+$/g, "");
  for (const char of cleaned) {
    const index = alphabet.indexOf(char);
    if (index === -1) {
      throw new Error("Invalid base32");
    }
    bits += index.toString(2).padStart(5, "0");
  }

  const bytes = [];
  for (let offset = 0; offset + 8 <= bits.length; offset += 8) {
    bytes.push(parseInt(bits.slice(offset, offset + 8), 2));
  }
  return Buffer.from(bytes);
}

function ascii85Decode(value) {
  const cleaned = String(value || "")
    .replace(/^<~/, "")
    .replace(/~>$/, "")
    .replace(/\s+/g, "");

  if (!cleaned) {
    return Buffer.alloc(0);
  }

  const bytes = [];
  let block = [];

  for (const char of cleaned) {
    if (char === "z" && !block.length) {
      bytes.push(0, 0, 0, 0);
      continue;
    }

    const code = char.charCodeAt(0);
    if (code < 33 || code > 117) {
      throw new Error("Invalid ascii85");
    }

    block.push(code - 33);
    if (block.length === 5) {
      let value32 = 0;
      block.forEach((item) => {
        value32 = value32 * 85 + item;
      });
      bytes.push((value32 >>> 24) & 0xff, (value32 >>> 16) & 0xff, (value32 >>> 8) & 0xff, value32 & 0xff);
      block = [];
    }
  }

  if (block.length) {
    const originalLength = block.length;
    while (block.length < 5) {
      block.push(84);
    }
    let value32 = 0;
    block.forEach((item) => {
      value32 = value32 * 85 + item;
    });
    const tail = [(value32 >>> 24) & 0xff, (value32 >>> 16) & 0xff, (value32 >>> 8) & 0xff, value32 & 0xff];
    bytes.push(...tail.slice(0, originalLength - 1));
  }

  return Buffer.from(bytes);
}

function base58Decode(value) {
  const alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
  const cleaned = String(value || "").trim();
  let number = 0n;

  for (const char of cleaned) {
    const index = alphabet.indexOf(char);
    if (index === -1) {
      throw new Error("Invalid base58");
    }
    number = number * 58n + BigInt(index);
  }

  const bytes = [];
  while (number > 0n) {
    bytes.unshift(Number(number & 0xffn));
    number >>= 8n;
  }
  for (const char of cleaned) {
    if (char !== "1") {
      break;
    }
    bytes.unshift(0);
  }
  return Buffer.from(bytes);
}

function extractUnicodeStrings(buffer, minLength = 4, maxCount = 3000) {
  const matches = [];

  for (const start of [0, 1]) {
    let current = [];
    for (let index = start; index + 1 < buffer.length; index += 2) {
      const code = buffer.readUInt16LE(index);
      const isPrintable = code === 9 || code === 10 || code === 13 || (code >= 32 && code <= 126);
      if (isPrintable) {
        current.push(String.fromCharCode(code));
        continue;
      }
      if (current.length >= minLength) {
        matches.push(current.join(""));
        if (matches.length >= maxCount) {
          return dedupeStrings(matches);
        }
      }
      current = [];
    }

    if (current.length >= minLength && matches.length < maxCount) {
      matches.push(current.join(""));
    }
  }

  return dedupeStrings(matches).slice(0, maxCount);
}

function scoreDecodedText(text) {
  if (!text) {
    return 0;
  }
  const printable = (text.match(/[\x20-\x7e]/g) || []).length / text.length;
  const spaces = (text.match(/\s/g) || []).length;
  const common = (text.match(/[etaoinshrdlu]/gi) || []).length;
  const flagBonus = /flag\{|ctf\{|key\{/i.test(text) ? 12 : 0;
  const asciiPenalty = (text.match(/[^\x09\x0a\x0d\x20-\x7e]/g) || []).length * 0.5;
  return printable * 6 + spaces * 0.08 + common * 0.04 + flagBonus - asciiPenalty;
}

function trySingleByteXor(buffer) {
  const results = [];
  for (let key = 1; key < 256; key += 1) {
    const decodedBuffer = Buffer.alloc(buffer.length);
    for (let index = 0; index < buffer.length; index += 1) {
      decodedBuffer[index] = buffer[index] ^ key;
    }
    const text = decodeBufferAsText(decodedBuffer).trim();
    if (!text || text.length < 6) {
      continue;
    }
    const score = scoreDecodedText(text);
    if (score < 5) {
      continue;
    }
    results.push({
      type: "xor",
      key,
      value: text.slice(0, 240),
      score,
    });
  }

  return results.sort((left, right) => right.score - left.score).slice(0, 5);
}

function caesarShift(text, shift) {
  return text.replace(/[A-Za-z]/g, (char) => {
    const code = char.charCodeAt(0);
    const base = code >= 97 ? 97 : 65;
    return String.fromCharCode(((code - base + shift + 26) % 26) + base);
  });
}

function tryInflateVariants(buffer) {
  if (!buffer || buffer.length < 6 || buffer.length > 128 * 1024) {
    return [];
  }

  const variants = [];
  const attempts = [
    { type: "gunzip", label: "GUNZIP", run: () => zlib.gunzipSync(buffer, { maxOutputLength: MAX_TEXT_BYTES }) },
    { type: "inflate", label: "INFLATE", run: () => zlib.inflateSync(buffer, { maxOutputLength: MAX_TEXT_BYTES }) },
    { type: "inflate-raw", label: "INFLATE-RAW", run: () => zlib.inflateRawSync(buffer, { maxOutputLength: MAX_TEXT_BYTES }) },
  ];

  attempts.forEach((attempt) => {
    try {
      const inflated = attempt.run();
      if (inflated && inflated.length && inflated.length <= MAX_TEXT_BYTES) {
        variants.push({
          type: attempt.type,
          label: attempt.label,
          buffer: inflated,
        });
      }
    } catch (_error) {
      // ignore unsupported streams
    }
  });

  const deduped = new Map();
  variants.forEach((item) => {
    deduped.set(item.buffer.toString("base64"), item);
  });
  return Array.from(deduped.values());
}

function pushDecodedResult(bucket, item) {
  const value = String(item.value || "").trim();
  if (!value || value.length < 4) {
    return;
  }

  const score = typeof item.score === "number" ? item.score : scoreDecodedText(value);
  const strict = Boolean(item.strict);
  const looksLikeFlag = KNOWN_FLAG_PREFIX.test(value) || LOOSE_FLAG_PREFIX.test(value);
  const looksLikeNaturalText = NATURAL_TEXT_HINT.test(value) || /\s/.test(value);

  if (strict && !looksLikeFlag && (!looksLikeNaturalText || score < 8)) {
    return;
  }
  if (score < 4 && !/flag\{|ctf\{|key\{/i.test(value)) {
    return;
  }

  bucket.push({
    type: item.type,
    label: item.label,
    value: value.slice(0, 240),
    score,
  });
}

function isMostlyCjkText(text) {
  const chars = Array.from(String(text || "")).filter((char) => char.trim());
  if (chars.length < 8) {
    return false;
  }
  const cjkCount = chars.filter((char) => {
    const codePoint = char.codePointAt(0);
    return (codePoint >= 0x3400 && codePoint <= 0x9fff) || (codePoint >= 0xf900 && codePoint <= 0xfaff);
  }).length;
  return cjkCount / chars.length >= 0.45;
}

function collectUnicodeProjectionDecodes(text, bucket) {
  if (!isMostlyCjkText(text)) {
    return;
  }

  const chars = Array.from(text).filter((char) => char.codePointAt(0) <= 0xffff);
  if (chars.length < 8) {
    return;
  }

  const variants = [
    {
      label: "UTF-8 bytes from CJK codepoints (BE)",
      bytes: chars.flatMap((char) => {
        const codePoint = char.codePointAt(0);
        return [(codePoint >> 8) & 0xff, codePoint & 0xff];
      }),
    },
    {
      label: "UTF-8 bytes from CJK codepoints (LE)",
      bytes: chars.flatMap((char) => {
        const codePoint = char.codePointAt(0);
        return [codePoint & 0xff, (codePoint >> 8) & 0xff];
      }),
    },
  ];

  variants.forEach((variant) => {
    const decoded = Buffer.from(variant.bytes).toString("utf8").replace(/\0/g, "").trim();
    if (!decoded || decoded === text || decoded.includes("\ufffd")) {
      return;
    }

    const flags = findFlagCandidates(decoded, variant.label);
    const printableScore = scorePrintableRatio(Buffer.from(decoded, "utf8"));
    if (flags.length || NATURAL_TEXT_HINT.test(decoded) || printableScore > 0.72) {
      pushDecodedResult(bucket, {
        type: "unicode-projection",
        label: variant.label,
        value: decoded,
        score: scoreDecodedText(decoded) + (flags.length ? 3 : 0),
        strict: true,
      });
    }
  });
}

function addDerivedTextResult(bucket, type, label, value, options = {}) {
  const decoded = String(value || "").replace(/\0/g, "").trim();
  if (!decoded || decoded.length < 4 || decoded.includes("\ufffd")) {
    return;
  }

  const flags = findFlagCandidates(decoded, label);
  const score = scoreDecodedText(decoded) + (flags.length ? 3 : 0) + (options.scoreBoost || 0);
  const printable = scorePrintableRatio(Buffer.from(decoded, "utf8"));
  const hasUsefulWords = NATURAL_TEXT_HINT.test(decoded) || /\b(?:flag|ctf|key|secret|password|congrat|success|answer)\b/i.test(decoded);
  if (!flags.length && !hasUsefulWords && score < 6.8 && printable < 0.84) {
    return;
  }

  pushDecodedResult(bucket, {
    type,
    label,
    value: decoded,
    score,
    strict: score < 8 && !flags.length,
  });
}

function collectBitsAsText(bits, label, bucket) {
  const cleaned = String(bits || "").replace(/[^01]/g, "");
  if (cleaned.length < 32) {
    return;
  }

  for (let start = 0; start < 8 && start + 32 <= cleaned.length; start += 1) {
    const usable = cleaned.slice(start, cleaned.length - ((cleaned.length - start) % 8));
    if (usable.length < 32) {
      continue;
    }
    const bytes = [];
    for (let index = 0; index + 8 <= usable.length && bytes.length < MAX_TEXT_BYTES; index += 8) {
      bytes.push(parseInt(usable.slice(index, index + 8), 2));
    }
    const decoded = Buffer.from(bytes).toString("utf8");
    addDerivedTextResult(bucket, "bitstream", `${label} offset ${start}`, decoded, { scoreBoost: start === 0 ? 0.4 : 0 });
  }
}

function collectZeroWidthDecodes(text, bucket) {
  const chars = Array.from(String(text || ""));
  const zeroWidthSet = new Set(["\u200b", "\u200c", "\u200d", "\u2060", "\ufeff", "\u180e"]);
  const sequence = chars.filter((char) => zeroWidthSet.has(char));
  if (sequence.length >= 32) {
    const unique = dedupeStrings(sequence);
    if (unique.length === 2) {
      const [first, second] = unique;
      collectBitsAsText(sequence.map((char) => (char === first ? "0" : "1")).join(""), "zero-width 0/1", bucket);
      collectBitsAsText(sequence.map((char) => (char === second ? "0" : "1")).join(""), "zero-width 1/0", bucket);
    }
  }

  const tagText = chars
    .map((char) => {
      const codePoint = char.codePointAt(0);
      return codePoint >= 0xe0020 && codePoint <= 0xe007e ? String.fromCharCode(codePoint - 0xe0000) : "";
    })
    .join("");
  if (tagText.length >= 4) {
    addDerivedTextResult(bucket, "unicode-tags", "Unicode tag characters", tagText, { scoreBoost: 1 });
  }
}

function collectWhitespaceStegoDecodes(text, bucket) {
  const trailing = String(text || "")
    .split(/\r?\n/)
    .map((line) => {
      const match = line.match(/[ \t]+$/);
      return match ? match[0] : "";
    })
    .join("");

  if (trailing.length < 32 || !/[ \t]/.test(trailing)) {
    return;
  }

  collectBitsAsText(trailing.replace(/ /g, "0").replace(/\t/g, "1"), "trailing whitespace space=0 tab=1", bucket);
  collectBitsAsText(trailing.replace(/ /g, "1").replace(/\t/g, "0"), "trailing whitespace space=1 tab=0", bucket);
}

function collectNumericAndEscapeDecodes(text, bucket) {
  const source = String(text || "");
  const binaryMatches = dedupeStrings(
    Array.from(source.matchAll(/(?:^|[^01])((?:[01]{8}[\s,;:_-]*){4,})(?=$|[^01])/g))
      .map((match) => match[1])
      .slice(0, 12),
  );
  binaryMatches.forEach((value) => {
    const bits = (value.match(/[01]{8}/g) || []).join("");
    collectBitsAsText(bits, "binary bytes", bucket);
  });

  const hexByteMatches = dedupeStrings(
    [
      ...Array.from(source.matchAll(/((?:\\x[0-9a-fA-F]{2}){4,})/g)).map((match) => match[1]),
      ...Array.from(source.matchAll(/((?:0x[0-9a-fA-F]{2}[\s,;:_-]*){4,})/g)).map((match) => match[1]),
    ].slice(0, 12),
  );
  hexByteMatches.forEach((value) => {
    const bytes = (value.match(/[0-9a-fA-F]{2}/g) || []).map((item) => parseInt(item, 16));
    addDerivedTextResult(bucket, "hex-bytes", "escaped hex bytes", Buffer.from(bytes).toString("utf8"), { scoreBoost: 0.6 });
  });

  const decimalMatches = dedupeStrings(
    Array.from(source.matchAll(/(?:^|[^\d])((?:\d{2,3}[\s,;:_-]+){3,}\d{2,3})(?=$|[^\d])/g))
      .map((match) => match[1])
      .slice(0, 12),
  );
  decimalMatches.forEach((value) => {
    const numbers = (value.match(/\d{1,3}/g) || []).map((item) => Number(item));
    if (numbers.length >= 4 && numbers.every((item) => item >= 0 && item <= 255)) {
      addDerivedTextResult(bucket, "decimal-bytes", "decimal byte values", Buffer.from(numbers).toString("utf8"), { scoreBoost: 0.5 });
    }
  });

  const htmlEntityMatches = dedupeStrings(Array.from(source.matchAll(/((?:&#(?:x[0-9a-fA-F]+|\d+);){4,})/g)).map((match) => match[1]).slice(0, 12));
  htmlEntityMatches.forEach((value) => {
    const chars = Array.from(value.matchAll(/&#(x[0-9a-fA-F]+|\d+);/g)).map((match) => {
      const token = match[1];
      return String.fromCodePoint(token.toLowerCase().startsWith("x") ? parseInt(token.slice(1), 16) : parseInt(token, 10));
    });
    addDerivedTextResult(bucket, "html-entities", "HTML numeric entities", chars.join(""), { scoreBoost: 0.6 });
  });
}

function atbashText(text) {
  return String(text || "").replace(/[A-Za-z]/g, (char) => {
    const code = char.charCodeAt(0);
    const base = code >= 97 ? 97 : 65;
    return String.fromCharCode(base + (25 - (code - base)));
  });
}

function rot47Text(text) {
  return String(text || "").replace(/[!-~]/g, (char) => {
    const code = char.charCodeAt(0);
    return String.fromCharCode(33 + ((code - 33 + 47) % 94));
  });
}

function collectClassicalCipherDecodes(text, bucket, wholeTextTransformAllowed) {
  if (!wholeTextTransformAllowed) {
    return;
  }
  addDerivedTextResult(bucket, "rot47", "ROT47", rot47Text(text), { scoreBoost: 0.2 });
  addDerivedTextResult(bucket, "atbash", "ATBASH", atbashText(text), { scoreBoost: 0.2 });
}

function decodeBaconLetters(sequence, inverse = false) {
  const alphabet = "abcdefghijklmnopqrstuvwxyz";
  const bits = String(sequence || "")
    .replace(/[^abAB]/g, "")
    .toLowerCase()
    .replace(/[ab]/g, (char) => {
      const bit = char === "a" ? "0" : "1";
      return inverse ? (bit === "0" ? "1" : "0") : bit;
    });
  const chars = [];
  for (let index = 0; index + 5 <= bits.length; index += 5) {
    const value = parseInt(bits.slice(index, index + 5), 2);
    chars.push(value < 26 ? alphabet[value] : "?");
  }
  return chars.join("");
}

function collectBaconDecodes(text, bucket) {
  const matches = dedupeStrings(
    Array.from(String(text || "").matchAll(/(?:^|[^abAB])((?:[abAB][\s,;:_-]*){25,})(?=$|[^abAB])/g))
      .map((match) => match[1])
      .slice(0, 8),
  );
  matches.forEach((value) => {
    addDerivedTextResult(bucket, "bacon", "Bacon A=0 B=1", decodeBaconLetters(value), { scoreBoost: 0.4 });
    addDerivedTextResult(bucket, "bacon", "Bacon A=1 B=0", decodeBaconLetters(value, true), { scoreBoost: 0.2 });
  });
}

function runBrainfuck(program, maxSteps = 300000, maxOutput = 4096) {
  const code = String(program || "").replace(/[^\+\-\<\>\.\,\[\]]/g, "");
  if (code.length < 12) {
    return "";
  }

  const jump = new Map();
  const stack = [];
  for (let index = 0; index < code.length; index += 1) {
    if (code[index] === "[") {
      stack.push(index);
    } else if (code[index] === "]") {
      const open = stack.pop();
      if (open === undefined) {
        return "";
      }
      jump.set(open, index);
      jump.set(index, open);
    }
  }
  if (stack.length) {
    return "";
  }

  const tape = new Uint8Array(30000);
  let pointer = 0;
  let instruction = 0;
  let steps = 0;
  let output = "";

  while (instruction < code.length && steps < maxSteps && output.length < maxOutput) {
    const op = code[instruction];
    if (op === "+") tape[pointer] = (tape[pointer] + 1) & 0xff;
    else if (op === "-") tape[pointer] = (tape[pointer] + 255) & 0xff;
    else if (op === ">") pointer = Math.min(tape.length - 1, pointer + 1);
    else if (op === "<") pointer = Math.max(0, pointer - 1);
    else if (op === ".") output += String.fromCharCode(tape[pointer]);
    else if (op === "[" && tape[pointer] === 0) instruction = jump.get(instruction);
    else if (op === "]" && tape[pointer] !== 0) instruction = jump.get(instruction);
    instruction += 1;
    steps += 1;
  }

  return output;
}

function collectBrainfuckDecodes(text, bucket) {
  const matches = dedupeStrings(
    Array.from(String(text || "").matchAll(/[\+\-\<\>\.\,\[\]\s]{20,}/g))
      .map((match) => match[0])
      .filter((value) => (value.match(/[\+\-\<\>\.\,\[\]]/g) || []).length >= 12 && value.includes("."))
      .slice(0, 6),
  );
  matches.forEach((value) => {
    addDerivedTextResult(bucket, "brainfuck", "Brainfuck output", runBrainfuck(value), { scoreBoost: 1 });
  });
}

function collectTextVariantsFromBuffer(buffer, label, bucket) {
  const decoded = decodeBufferAsText(buffer).trim();
  pushDecodedResult(bucket, {
    type: label.toLowerCase(),
    label,
    value: decoded,
  });

  if (buffer.length <= 2048) {
    trySingleByteXor(buffer).forEach((item) => {
      pushDecodedResult(bucket, {
        type: "xor",
        label: `${label} -> XOR 0x${item.key.toString(16).padStart(2, "0")}`,
        value: item.value,
        score: item.score,
        strict: true,
      });
    });
  }

  tryInflateVariants(buffer).forEach((variant) => {
    pushDecodedResult(bucket, {
      type: variant.type,
      label: `${label} -> ${variant.label}`,
      value: decodeBufferAsText(variant.buffer),
    });

    if (variant.buffer.length <= 2048) {
      trySingleByteXor(variant.buffer).forEach((item) => {
        pushDecodedResult(bucket, {
          type: "xor",
          label: `${label} -> ${variant.label} -> XOR 0x${item.key.toString(16).padStart(2, "0")}`,
          value: item.value,
          score: item.score,
          strict: true,
        });
      });
    }
  });
}

function smartDecodeTextContent(buffer) {
  const text = decodeBufferAsText(buffer);
  const encoded = findEncodedSegments(text);
  const results = [];
  const directFlagHits = findFlagCandidates(text, "inline").length;
  const wholeTextTransformAllowed =
    buffer.length <= 4096 &&
    directFlagHits === 0 &&
    !NATURAL_TEXT_HINT.test(text) &&
    ((text.match(/\s/g) || []).length <= Math.max(2, text.length * 0.06));

  collectUnicodeProjectionDecodes(text, results);
  collectZeroWidthDecodes(text, results);
  collectWhitespaceStegoDecodes(text, results);
  collectNumericAndEscapeDecodes(text, results);
  collectBaconDecodes(text, results);
  collectBrainfuckDecodes(text, results);

  encoded.base64.forEach((value) => {
    try {
      collectTextVariantsFromBuffer(Buffer.from(value, "base64"), "BASE64", results);
    } catch (_error) {
      // ignore
    }
  });

  encoded.hex.forEach((value) => {
    try {
      collectTextVariantsFromBuffer(Buffer.from(value, "hex"), "HEX", results);
    } catch (_error) {
      // ignore
    }
  });

  const base32Matches = dedupeStrings(
    Array.from(text.matchAll(/(?:^|[^A-Z2-7])([A-Z2-7]{16,}={0,6})(?=$|[^A-Z2-7=])/g)).map((match) => match[1]).slice(0, 12),
  );
  base32Matches.forEach((value) => {
    try {
      collectTextVariantsFromBuffer(base32Decode(value), "BASE32", results);
    } catch (_error) {
      // ignore
    }
  });

  const base58Matches = dedupeStrings(
    Array.from(text.matchAll(/(?:^|[^1-9A-HJ-NP-Za-km-z])([1-9A-HJ-NP-Za-km-z]{16,})(?=$|[^1-9A-HJ-NP-Za-km-z])/g))
      .map((match) => match[1])
      .slice(0, 10),
  );
  base58Matches.forEach((value) => {
    try {
      collectTextVariantsFromBuffer(base58Decode(value), "BASE58", results);
    } catch (_error) {
      // ignore
    }
  });

  const ascii85Matches = dedupeStrings(Array.from(text.matchAll(/<~[\s\S]{10,}?~>/g)).map((match) => match[0]).slice(0, 8));
  ascii85Matches.forEach((value) => {
    try {
      collectTextVariantsFromBuffer(ascii85Decode(value), "ASCII85", results);
    } catch (_error) {
      // ignore
    }
  });

  const urlMatches = dedupeStrings(Array.from(text.matchAll(/(?:%[0-9a-fA-F]{2}){4,}/g)).map((match) => match[0]).slice(0, 12));
  urlMatches.forEach((value) => {
    try {
      collectTextVariantsFromBuffer(Buffer.from(decodeURIComponent(value), "utf8"), "URL", results);
    } catch (_error) {
      // ignore
    }
  });

  if (wholeTextTransformAllowed) {
    const rot13 = caesarShift(text, 13);
    pushDecodedResult(results, {
      type: "rot13",
      label: "ROT13",
      value: rot13,
      strict: true,
    });

    const caesarResults = [];
    for (let shift = 1; shift < 26; shift += 1) {
      const shifted = caesarShift(text, shift);
      pushDecodedResult(caesarResults, {
        type: "caesar",
        label: `CAESAR +${shift}`,
        value: shifted,
        score: scoreDecodedText(shifted) - (shift === 13 ? 0.5 : 0),
        strict: true,
      });
    }
    caesarResults
      .sort((left, right) => (right.score || 0) - (left.score || 0))
      .slice(0, 4)
      .forEach((item) => results.push(item));
    collectClassicalCipherDecodes(text, results, wholeTextTransformAllowed);
  }

  if (buffer.length <= 2048 && wholeTextTransformAllowed) {
    trySingleByteXor(buffer).forEach((item) => {
      pushDecodedResult(results, {
        type: "xor",
        label: `XOR 0x${item.key.toString(16).padStart(2, "0")}`,
        value: item.value,
        score: item.score,
        strict: true,
      });
    });
  }

  const deduped = new Map();
  results.forEach((item) => {
    const key = `${item.type}@@${item.label}@@${item.value}`;
    const current = deduped.get(key);
    if (!current || (item.score || 0) > (current.score || 0)) {
      deduped.set(key, item);
    }
  });

  return Array.from(deduped.values())
    .sort((left, right) => (right.score || 0) - (left.score || 0))
    .slice(0, 20)
    .map(({ type, label, value }) => ({ type, label, value }));
}

function detectEmbeddedPayloads(buffer, offset = 128) {
  const hits = [];
  for (const signature of EMBEDDED_SIGNATURES) {
    const index = markerAfterOffset(buffer, signature.magic, offset);
    if (index !== -1) {
      hits.push({
        ...signature,
        offset: index,
      });
    }
  }

  return hits
    .sort((left, right) => left.offset - right.offset)
    .filter((item, index, array) => index === 0 || item.offset !== array[index - 1].offset || item.id !== array[index - 1].id);
}

function scanEmbeddedSignatures(buffer, offset = 0, limit = 80) {
  const hits = [];
  for (const signature of EMBEDDED_SIGNATURES) {
    let cursor = offset;
    while (cursor < buffer.length && hits.length < limit) {
      const index = markerAfterOffset(buffer, signature.magic, cursor);
      if (index === -1) {
        break;
      }
      hits.push({
        ...signature,
        offset: index,
      });
      cursor = index + Math.max(1, signature.magic.length);
    }
  }

  return hits
    .sort((left, right) => left.offset - right.offset || left.id.localeCompare(right.id))
    .filter((item, index, array) => index === 0 || item.offset !== array[index - 1].offset || item.id !== array[index - 1].id)
    .slice(0, limit);
}

function normalizeText(value) {
  return String(value || "").toLowerCase();
}

function isLikelyTextExtension(extension) {
  return [
    ".txt",
    ".md",
    ".log",
    ".csv",
    ".json",
    ".yaml",
    ".yml",
    ".xml",
    ".html",
    ".htm",
    ".js",
    ".ts",
    ".py",
    ".php",
    ".java",
    ".c",
    ".cpp",
    ".go",
    ".rs",
    ".sh",
    ".ps1",
    ".ini",
    ".cfg",
    ".conf",
  ].includes(extension);
}

function isOfficePackageExtension(extension) {
  return OFFICE_DOCUMENT_EXTENSIONS.includes(extension);
}

function detectMagic(buffer) {
  if (
    buffer.length >= 12 &&
    buffer.subarray(0, 4).toString("ascii") === "RIFF" &&
    buffer.subarray(8, 12).toString("ascii") === "WAVE"
  ) {
    return "wav";
  }
  if (buffer.length >= 8 && buffer.subarray(0, 8).equals(Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]))) {
    return "png";
  }
  if (buffer.length >= 3 && buffer.subarray(0, 3).equals(Buffer.from([0xff, 0xd8, 0xff]))) {
    return "jpeg";
  }
  if (buffer.length >= 6 && buffer.subarray(0, 6).toString("ascii") === "GIF89a") {
    return "gif";
  }
  if (buffer.length >= 4 && (buffer.readUInt32LE(0) === 0xa1b2c3d4 || buffer.readUInt32LE(0) === 0xd4c3b2a1)) {
    return "pcap";
  }
  if (buffer.length >= 4 && buffer.readUInt32BE(0) === 0x0a0d0d0a) {
    return "pcapng";
  }
  if (buffer.length >= 4 && buffer.subarray(0, 4).equals(Buffer.from([0x50, 0x4b, 0x03, 0x04]))) {
    return "zip";
  }
  if (buffer.length >= 4 && buffer.subarray(0, 4).toString("ascii") === "\u007fELF") {
    return "elf";
  }
  if (buffer.length >= 2 && buffer.subarray(0, 2).toString("ascii") === "MZ") {
    return "pe";
  }
  if (buffer.length >= 4 && buffer.subarray(0, 4).toString("ascii") === "%PDF") {
    return "pdf";
  }
  if (buffer.length >= 3 && buffer[0] === 0x1f && buffer[1] === 0x8b && buffer[2] === 0x08) {
    return "gzip";
  }
  return "";
}

function extractAsciiStrings(buffer, minLength = 4, maxCount = 3000) {
  const matches = [];
  let current = [];

  for (const byte of buffer) {
    const isPrintable = byte >= 32 && byte <= 126;
    if (isPrintable) {
      current.push(String.fromCharCode(byte));
      continue;
    }
    if (current.length >= minLength) {
      matches.push(current.join(""));
      if (matches.length >= maxCount) {
        break;
      }
    }
    current = [];
  }

  if (current.length >= minLength && matches.length < maxCount) {
    matches.push(current.join(""));
  }

  return matches;
}

function decodeBufferAsText(buffer) {
  let text = buffer.toString("utf8").replace(/\0/g, "");
  const replacementCount = (text.match(/\uFFFD/g) || []).length;
  if (replacementCount > text.length * 0.02) {
    text = buffer.toString("latin1").replace(/\0/g, "");
  }
  return text;
}

function readSample(filePath, maxBytes) {
  const stat = fs.statSync(filePath);
  const length = Math.min(stat.size, maxBytes);
  const buffer = Buffer.alloc(length);
  const fd = fs.openSync(filePath, "r");
  fs.readSync(fd, buffer, 0, length, 0);
  fs.closeSync(fd);
  return { stat, buffer };
}

function scorePrintableRatio(buffer) {
  if (!buffer.length) {
    return 0;
  }
  let printable = 0;
  for (const byte of buffer) {
    if (byte === 9 || byte === 10 || byte === 13 || (byte >= 32 && byte <= 126)) {
      printable += 1;
    }
  }
  return printable / buffer.length;
}

function detectFamily(filePath, sample) {
  const extension = path.extname(filePath).toLowerCase();
  const magic = detectMagic(sample);

  if (magic === "pdf" || isOfficePackageExtension(extension) || [".doc", ".xls", ".ppt"].includes(extension)) {
    return { family: "document", badge: magic === "pdf" ? "PDF" : extension.slice(1).toUpperCase() || "DOC" };
  }
  if (["png", "jpeg", "gif"].includes(magic) || [".png", ".jpg", ".jpeg", ".gif", ".bmp", ".webp", ".svg"].includes(extension)) {
    return { family: "image", badge: magic ? magic.toUpperCase() : extension.slice(1).toUpperCase() || "IMG" };
  }
  if (magic === "wav" || [".wav", ".mp3", ".flac", ".ogg", ".m4a"].includes(extension)) {
    return { family: "audio", badge: magic ? magic.toUpperCase() : extension.slice(1).toUpperCase() || "AUDIO" };
  }
  if (["pcap", "pcapng"].includes(magic) || [".pcap", ".pcapng", ".cap"].includes(extension)) {
    return { family: "network", badge: magic.toUpperCase() || extension.slice(1).toUpperCase() || "PCAP" };
  }
  if (extension === ".apk") {
    return { family: "binary", badge: "APK" };
  }
  if (["zip", "gzip"].includes(magic) || [".zip", ".7z", ".rar", ".tar", ".gz", ".tgz"].includes(extension)) {
    return { family: "archive", badge: magic.toUpperCase() || extension.slice(1).toUpperCase() || "ZIP" };
  }
  if (["elf", "pe"].includes(magic) || [".exe", ".dll", ".bin", ".so", ".elf", ".apk", ".jar"].includes(extension)) {
    return { family: "binary", badge: magic.toUpperCase() || extension.slice(1).toUpperCase() || "BIN" };
  }
  if (isLikelyTextExtension(extension) || scorePrintableRatio(sample) > 0.88) {
    return { family: "text", badge: extension.slice(1).toUpperCase() || "TXT" };
  }
  return { family: "unknown", badge: extension.slice(1).toUpperCase() || "FILE" };
}

function findFlagCandidates(text, source) {
  const candidates = [];
  const patterns = [
    /\b(?:flag|ctf|key|answer|picoCTF|moectf|actf|hitcon|sekai|balsn|uiuctf|n1ctf)\{[^{}\r\n]{3,160}\}/gi,
    /\b[a-zA-Z0-9_]{2,32}\{[^{}\r\n]{3,160}\}/g,
    LOOSE_FLAG_PREFIX_GLOBAL,
  ];

  for (const pattern of patterns) {
    for (const match of text.matchAll(pattern)) {
      const value = match[0].trim();
      if (/^flag\s+(?:candidate|candidates|value|values|source|format|result|results)\b/i.test(value)) {
        continue;
      }
      candidates.push({
        value,
        source,
      });
    }
  }

  return candidates;
}

function findEncodedSegments(text) {
  const base64 = dedupeStrings(
    Array.from(text.matchAll(/(?:^|[^A-Za-z0-9+/])([A-Za-z0-9+/]{12,}={0,2})(?=$|[^A-Za-z0-9+/=])/g))
      .map((match) => match[1])
      .filter((value) => value.length % 4 === 0)
      .slice(0, 12),
  );

  const hex = dedupeStrings(
    Array.from(text.matchAll(/(?:^|[^0-9a-fA-F])(((?:[0-9a-fA-F]{2}){10,}))(?=$|[^0-9a-fA-F])/g))
      .map((match) => match[1])
      .slice(0, 12),
  );

  return { base64, hex };
}

function decodeInterestingSegments(encoded) {
  const findings = [];

  for (const value of encoded.base64) {
    try {
      const decoded = Buffer.from(value, "base64").toString("utf8");
      if (!decoded || decoded.length < 4) {
        continue;
      }
      if ((decoded.match(/[\uFFFD]/g) || []).length > decoded.length * 0.1) {
        continue;
      }
      findings.push({
        type: "base64",
        value: decoded.slice(0, 180),
      });
    } catch (_error) {
      // ignore
    }
  }

  for (const value of encoded.hex) {
    try {
      const decoded = Buffer.from(value, "hex").toString("utf8");
      if (!decoded || decoded.length < 4) {
        continue;
      }
      findings.push({
        type: "hex",
        value: decoded.slice(0, 180),
      });
    } catch (_error) {
      // ignore
    }
  }

  return findings;
}

function readPngDimensions(buffer) {
  if (detectMagic(buffer) !== "png" || buffer.length < 24) {
    return null;
  }
  return {
    width: buffer.readUInt32BE(16),
    height: buffer.readUInt32BE(20),
  };
}

function decodeImageRaster(buffer) {
  const magic = detectMagic(buffer);
  if (magic === "png") {
    const parsed = PNG.sync.read(buffer, { checkCRC: false });
    return {
      format: "png",
      width: parsed.width,
      height: parsed.height,
      data: parsed.data,
    };
  }
  if (magic === "jpeg") {
    const parsed = jpeg.decode(buffer, { useTArray: true, formatAsRGBA: true, tolerantDecoding: true });
    return {
      format: "jpeg",
      width: parsed.width,
      height: parsed.height,
      data: Buffer.from(parsed.data),
    };
  }
  return null;
}

function detectQrPayload(buffer) {
  let raster;
  try {
    raster = decodeImageRaster(buffer);
  } catch (_error) {
    return null;
  }

  if (!raster || !raster.width || !raster.height) {
    return null;
  }

  try {
    const code = jsQR(new Uint8ClampedArray(raster.data), raster.width, raster.height, {
      inversionAttempts: "attemptBoth",
    });
    return code && code.data ? code.data.trim() : null;
  } catch (_error) {
    return null;
  }
}

function decodeSingleBarcode(filePath, config) {
  return new Promise((resolve) => {
    try {
      Quagga.decodeSingle(
        {
          src: filePath,
          ...config,
        },
        (result) => {
          const value = result?.codeResult?.code;
          resolve(value ? String(value).trim() : null);
        },
      );
    } catch (_error) {
      resolve(null);
    }
  });
}

async function detectBarcodePayload(filePath) {
  if (!filePath || !fs.existsSync(filePath)) {
    return null;
  }

  for (const attempt of BARCODE_ATTEMPTS) {
    const value = await decodeSingleBarcode(filePath, attempt);
    if (value) {
      return value;
    }
  }

  return null;
}

function makeGrayPng(width, height, pixelSelector) {
  const png = new PNG({ width, height });
  for (let y = 0; y < height; y += 1) {
    for (let x = 0; x < width; x += 1) {
      const pixelOffset = (y * width + x) * 4;
      const value = Math.max(0, Math.min(255, pixelSelector(pixelOffset)));
      png.data[pixelOffset] = value;
      png.data[pixelOffset + 1] = value;
      png.data[pixelOffset + 2] = value;
      png.data[pixelOffset + 3] = 255;
    }
  }
  return PNG.sync.write(png);
}

function makeColorPng(width, height, pixelSelector) {
  const png = new PNG({ width, height });
  for (let y = 0; y < height; y += 1) {
    for (let x = 0; x < width; x += 1) {
      const pixelOffset = (y * width + x) * 4;
      const [r, g, b, a = 255] = pixelSelector(x, y);
      png.data[pixelOffset] = Math.max(0, Math.min(255, r));
      png.data[pixelOffset + 1] = Math.max(0, Math.min(255, g));
      png.data[pixelOffset + 2] = Math.max(0, Math.min(255, b));
      png.data[pixelOffset + 3] = Math.max(0, Math.min(255, a));
    }
  }
  return PNG.sync.write(png);
}

function computePercentile(values, percentile) {
  if (!values.length) {
    return 0;
  }
  const sorted = [...values].sort((left, right) => left - right);
  const position = Math.max(0, Math.min(sorted.length - 1, (sorted.length - 1) * percentile));
  const lower = Math.floor(position);
  const upper = Math.ceil(position);
  if (lower === upper) {
    return sorted[lower];
  }
  const weight = position - lower;
  return sorted[lower] * (1 - weight) + sorted[upper] * weight;
}

function readNormalizedWavSample(buffer, wavInfo, sampleOffset, bytesPerSample) {
  if (sampleOffset + bytesPerSample > buffer.length) {
    return 0;
  }
  if (wavInfo.bitsPerSample === 8) {
    return (buffer[sampleOffset] - 128) / 128;
  }
  if (wavInfo.bitsPerSample === 16) {
    return Math.max(-1, Math.min(1, buffer.readInt16LE(sampleOffset) / 32768));
  }
  if (wavInfo.bitsPerSample === 24) {
    const value = (buffer[sampleOffset + 2] << 16) | (buffer[sampleOffset + 1] << 8) | buffer[sampleOffset];
    const signed = value & 0x800000 ? value - 0x1000000 : value;
    return Math.max(-1, Math.min(1, signed / 8388608));
  }
  if (wavInfo.bitsPerSample === 32) {
    if (wavInfo.audioFormat === 3) {
      return Math.max(-1, Math.min(1, buffer.readFloatLE(sampleOffset)));
    }
    return Math.max(-1, Math.min(1, buffer.readInt32LE(sampleOffset) / 2147483648));
  }
  return 0;
}

function extractMonoAudioTrack(buffer, wavInfo, limitSamples = MAX_AUDIO_ANALYSIS_SAMPLES) {
  if (!wavInfo || wavInfo.dataOffset < 0 || !wavInfo.channels || !wavInfo.bitsPerSample) {
    return null;
  }
  if (![1, 3].includes(wavInfo.audioFormat) || ![8, 16, 24, 32].includes(wavInfo.bitsPerSample)) {
    return null;
  }

  const bytesPerSample = Math.ceil(wavInfo.bitsPerSample / 8);
  const frameSize = Math.max(1, wavInfo.channels * bytesPerSample);
  const dataEnd = Math.min(buffer.length, wavInfo.dataOffset + wavInfo.dataSize);
  const totalFrames = Math.floor((dataEnd - wavInfo.dataOffset) / frameSize);
  if (!totalFrames) {
    return null;
  }

  const step = Math.max(1, Math.ceil(totalFrames / Math.max(1, limitSamples)));
  const samples = new Float32Array(Math.ceil(totalFrames / step));
  let writeIndex = 0;

  for (let frameIndex = 0; frameIndex < totalFrames; frameIndex += step) {
    const frameOffset = wavInfo.dataOffset + frameIndex * frameSize;
    let mixed = 0;
    let channelCount = 0;
    for (let channel = 0; channel < wavInfo.channels; channel += 1) {
      const sampleOffset = frameOffset + channel * bytesPerSample;
      mixed += readNormalizedWavSample(buffer, wavInfo, sampleOffset, bytesPerSample);
      channelCount += 1;
    }
    samples[writeIndex] = channelCount ? mixed / channelCount : 0;
    writeIndex += 1;
  }

  return {
    samples: samples.subarray(0, writeIndex),
    sampleRate: wavInfo.sampleRate / step,
    sourceStep: step,
    durationSeconds: totalFrames / wavInfo.sampleRate,
  };
}

function fillShortGaps(flags, maxGap) {
  const output = flags.slice();
  let index = 0;
  while (index < output.length) {
    if (output[index]) {
      index += 1;
      continue;
    }
    const gapStart = index;
    while (index < output.length && !output[index]) {
      index += 1;
    }
    const gapEnd = index;
    const gapLength = gapEnd - gapStart;
    const hasLeft = gapStart > 0 && output[gapStart - 1];
    const hasRight = gapEnd < output.length && output[gapEnd];
    if (hasLeft && hasRight && gapLength <= maxGap) {
      for (let cursor = gapStart; cursor < gapEnd; cursor += 1) {
        output[cursor] = true;
      }
    }
  }
  return output;
}

function removeShortActivity(flags, minRun) {
  const output = flags.slice();
  let index = 0;
  while (index < output.length) {
    if (!output[index]) {
      index += 1;
      continue;
    }
    const runStart = index;
    while (index < output.length && output[index]) {
      index += 1;
    }
    const runEnd = index;
    if (runEnd - runStart < minRun) {
      for (let cursor = runStart; cursor < runEnd; cursor += 1) {
        output[cursor] = false;
      }
    }
  }
  return output;
}

function estimateToneFrequency(samples, sampleRate) {
  if (!samples || samples.length < 8 || !sampleRate) {
    return 0;
  }
  let crossings = 0;
  let previous = samples[0] >= 0 ? 1 : -1;
  for (let index = 1; index < samples.length; index += 1) {
    const current = samples[index] >= 0 ? 1 : -1;
    if (current !== previous) {
      crossings += 1;
      previous = current;
    }
  }
  const durationSeconds = samples.length / sampleRate;
  if (!durationSeconds) {
    return 0;
  }
  const frequency = crossings / (2 * durationSeconds);
  if (!Number.isFinite(frequency) || frequency < 40 || frequency > sampleRate / 2) {
    return 0;
  }
  return frequency;
}

function summarizeDominantFrequencies(segments) {
  const buckets = new Map();
  segments.forEach((segment) => {
    if (!segment.frequencyHz) {
      return;
    }
    const rounded = Math.round(segment.frequencyHz / 10) * 10;
    const current = buckets.get(rounded) || 0;
    buckets.set(rounded, current + segment.durationSeconds);
  });

  return [...buckets.entries()]
    .sort((left, right) => right[1] - left[1])
    .slice(0, 3)
    .map(([frequencyHz, durationSeconds]) => ({ frequencyHz, durationSeconds }));
}

function decodeMorseFromRuns(runs) {
  const activeRuns = runs.filter((item) => item.active && item.durationSeconds >= 0.03);
  if (activeRuns.length < 3) {
    return [];
  }

  const candidateUnits = runs
    .filter((item) => item.durationSeconds >= 0.03 && item.durationSeconds <= 0.7)
    .map((item) => item.durationSeconds);
  if (!candidateUnits.length) {
    return [];
  }

  const unit = computePercentile(candidateUnits, 0.22);
  if (!unit || unit < 0.025 || unit > 0.45) {
    return [];
  }

  const tokens = [];
  let symbol = "";
  runs.forEach((run) => {
    const units = run.durationSeconds / unit;
    if (run.active) {
      symbol += units <= 2.2 ? "." : "-";
      return;
    }
    if (units <= 2.2) {
      return;
    }
    if (symbol) {
      tokens.push(symbol);
      symbol = "";
    }
    tokens.push(units <= 5.5 ? " " : " / ");
  });
  if (symbol) {
    tokens.push(symbol);
  }

  const pattern = tokens
    .join("")
    .replace(/\s+/g, " ")
    .replace(/(?:\s*\/\s*)+$/g, "")
    .replace(/^(?:\s*\/\s*)+/g, "")
    .trim();
  if (!pattern || !/[.-]/.test(pattern)) {
    return [];
  }

  const words = pattern.split(" / ").map((entry) => entry.trim()).filter(Boolean);
  const decodedWords = [];
  let validChars = 0;

  words.forEach((word) => {
    const letters = word.split(" ").filter(Boolean);
    const decoded = letters
      .map((letter) => {
        const value = MORSE_DECODE_MAP[letter] || "?";
        if (value !== "?") {
          validChars += 1;
        }
        return value;
      })
      .join("");
    decodedWords.push(decoded);
  });

  const text = decodedWords.join(" ").trim();
  if (validChars < 3 || !text || /^[?\s]+$/.test(text)) {
    return [];
  }

  return [
    {
      text,
      pattern,
      unitMilliseconds: Math.round(unit * 1000),
    },
  ];
}

function analyzeWavSignal(buffer, wavInfo, options = {}) {
  const track = extractMonoAudioTrack(buffer, wavInfo, options.maxSamples || MAX_AUDIO_ANALYSIS_SAMPLES);
  if (!track || track.samples.length < 64 || track.sampleRate < 100) {
    return null;
  }

  const hopSeconds = options.hopSeconds || 0.01;
  const windowSeconds = options.windowSeconds || 0.02;
  const hopSize = Math.max(8, Math.round(track.sampleRate * hopSeconds));
  const windowSize = Math.max(hopSize * 2, Math.round(track.sampleRate * windowSeconds));
  if (track.samples.length < windowSize) {
    return null;
  }

  const frames = [];
  const rmsValues = [];
  for (let start = 0; start + windowSize <= track.samples.length; start += hopSize) {
    let energy = 0;
    for (let index = 0; index < windowSize; index += 1) {
      const sample = track.samples[start + index];
      energy += sample * sample;
    }
    const rms = Math.sqrt(energy / windowSize);
    rmsValues.push(rms);
    frames.push({ startSample: start, rms });
  }

  if (!frames.length) {
    return null;
  }

  const threshold = Math.max(0.02, computePercentile(rmsValues, 0.9) * 0.3);
  let activeFlags = frames.map((frame) => frame.rms >= threshold);
  activeFlags = fillShortGaps(activeFlags, Math.max(1, Math.round(0.03 / hopSeconds)));
  activeFlags = removeShortActivity(activeFlags, Math.max(2, Math.round(0.04 / hopSeconds)));

  const runs = [];
  let runStart = 0;
  for (let index = 1; index <= activeFlags.length; index += 1) {
    if (index < activeFlags.length && activeFlags[index] === activeFlags[runStart]) {
      continue;
    }
    const active = activeFlags[runStart];
    const startSeconds = (runStart * hopSize) / track.sampleRate;
    const endSample = index >= activeFlags.length ? track.samples.length : Math.min(track.samples.length, (index - 1) * hopSize + windowSize);
    const endSeconds = endSample / track.sampleRate;
    runs.push({
      active,
      startSeconds,
      endSeconds,
      durationSeconds: Math.max(0, endSeconds - startSeconds),
      startSample: runStart * hopSize,
      endSample,
    });
    runStart = index;
  }

  const activeSegments = runs
    .filter((item) => item.active && item.durationSeconds >= 0.04)
    .map((item) => {
      const segmentSamples = track.samples.subarray(item.startSample, item.endSample);
      return {
        startSeconds: item.startSeconds,
        endSeconds: item.endSeconds,
        durationSeconds: item.durationSeconds,
        frequencyHz: estimateToneFrequency(segmentSamples, track.sampleRate),
      };
    });

  const dominantFrequencies = summarizeDominantFrequencies(activeSegments);
  const morseCandidates = decodeMorseFromRuns(runs);

  return {
    sampleRate: track.sampleRate,
    threshold,
    activeSegments,
    dominantFrequencies,
    morseCandidates,
  };
}

function spectrogramColor(value) {
  const stops = [
    [16, 20, 28],
    [21, 66, 92],
    [17, 127, 117],
    [89, 178, 244],
    [247, 241, 181],
  ];
  const clamped = Math.max(0, Math.min(1, value));
  const scaled = clamped * (stops.length - 1);
  const lower = Math.floor(scaled);
  const upper = Math.min(stops.length - 1, Math.ceil(scaled));
  const weight = scaled - lower;
  const left = stops[lower];
  const right = stops[upper];
  return [
    Math.round(left[0] * (1 - weight) + right[0] * weight),
    Math.round(left[1] * (1 - weight) + right[1] * weight),
    Math.round(left[2] * (1 - weight) + right[2] * weight),
  ];
}

function renderWavSpectrogram(buffer, wavInfo, options = {}) {
  const track = extractMonoAudioTrack(buffer, wavInfo, options.maxSamples || MAX_AUDIO_ANALYSIS_SAMPLES);
  if (!track || track.samples.length < 128 || track.sampleRate < 100) {
    return null;
  }

  const windowSize = Math.min(512, Math.max(128, 2 ** Math.floor(Math.log2(Math.max(128, track.sampleRate * 0.05)))));
  const width = Math.max(72, Math.min(MAX_AUDIO_SPECTROGRAM_COLUMNS, Math.floor(track.samples.length / Math.max(32, Math.floor(windowSize / 2)))));
  const height = MAX_AUDIO_SPECTROGRAM_BINS;
  const maxStart = Math.max(0, track.samples.length - windowSize);
  const minFrequency = 60;
  const maxFrequency = Math.min(track.sampleRate / 2, 4800);
  const frequencies = Array.from({ length: height }, (_item, index) => {
    const ratio = height === 1 ? 0 : index / (height - 1);
    return minFrequency * ((maxFrequency / minFrequency) ** ratio);
  });
  const window = Array.from({ length: windowSize }, (_item, index) => 0.5 - 0.5 * Math.cos((2 * Math.PI * index) / (windowSize - 1)));
  const matrix = Array.from({ length: width }, () => new Float32Array(height));
  let maxMagnitude = 0;

  for (let x = 0; x < width; x += 1) {
    const start = width === 1 ? 0 : Math.floor((x / (width - 1)) * maxStart);
    const segment = track.samples.subarray(start, start + windowSize);
    for (let index = 0; index < height; index += 1) {
      const frequency = frequencies[index];
      const omega = (2 * Math.PI * frequency) / track.sampleRate;
      const coeff = 2 * Math.cos(omega);
      let q0 = 0;
      let q1 = 0;
      let q2 = 0;
      for (let cursor = 0; cursor < segment.length; cursor += 1) {
        q0 = coeff * q1 - q2 + segment[cursor] * window[cursor];
        q2 = q1;
        q1 = q0;
      }
      const magnitude = Math.sqrt(Math.max(0, q1 * q1 + q2 * q2 - coeff * q1 * q2));
      const logMagnitude = Math.log1p(magnitude);
      matrix[x][index] = logMagnitude;
      maxMagnitude = Math.max(maxMagnitude, logMagnitude);
    }
  }

  if (!maxMagnitude) {
    return null;
  }

  return makeColorPng(width, height, (x, y) => {
    const index = height - 1 - y;
    const normalized = matrix[x][index] / maxMagnitude;
    const [r, g, b] = spectrogramColor(normalized);
    return [r, g, b, 255];
  });
}

function parseWavBuffer(buffer) {
  if (detectMagic(buffer) !== "wav" || buffer.length < 44) {
    return null;
  }

  const info = {
    audioFormat: 0,
    channels: 0,
    sampleRate: 0,
    byteRate: 0,
    blockAlign: 0,
    bitsPerSample: 0,
    durationSeconds: 0,
    metadata: {},
    chunks: [],
    dataOffset: -1,
    dataSize: 0,
  };

  let offset = 12;
  while (offset + 8 <= buffer.length) {
    const id = buffer.subarray(offset, offset + 4).toString("ascii");
    const size = buffer.readUInt32LE(offset + 4);
    const dataStart = offset + 8;
    const dataEnd = dataStart + size;
    if (dataEnd > buffer.length) {
      break;
    }

    info.chunks.push({ id, size });

    if (id === "fmt " && size >= 16) {
      info.audioFormat = buffer.readUInt16LE(dataStart);
      info.channels = buffer.readUInt16LE(dataStart + 2);
      info.sampleRate = buffer.readUInt32LE(dataStart + 4);
      info.byteRate = buffer.readUInt32LE(dataStart + 8);
      info.blockAlign = buffer.readUInt16LE(dataStart + 12);
      info.bitsPerSample = buffer.readUInt16LE(dataStart + 14);
    } else if (id === "data") {
      info.dataOffset = dataStart;
      info.dataSize = size;
    } else if (id === "LIST" && size >= 4) {
      const listType = buffer.subarray(dataStart, dataStart + 4).toString("ascii");
      if (listType === "INFO") {
        let inner = dataStart + 4;
        while (inner + 8 <= dataEnd) {
          const subId = buffer.subarray(inner, inner + 4).toString("ascii");
          const subSize = buffer.readUInt32LE(inner + 4);
          const subStart = inner + 8;
          const subEnd = subStart + subSize;
          if (subEnd > dataEnd) {
            break;
          }
          const value = decodeBufferAsText(buffer.subarray(subStart, subEnd)).replace(/\0/g, "").trim();
          if (value) {
            info.metadata[subId] = value;
          }
          inner = subEnd + (subSize % 2);
        }
      }
    } else if (/^I[A-Z0-9 ]{3}$/.test(id)) {
      const value = decodeBufferAsText(buffer.subarray(dataStart, dataEnd)).replace(/\0/g, "").trim();
      if (value) {
        info.metadata[id] = value;
      }
    }

    offset = dataEnd + (size % 2);
  }

  if (info.byteRate && info.dataSize) {
    info.durationSeconds = info.dataSize / info.byteRate;
  }

  return info;
}

function buildWavSampleStreams(buffer, wavInfo) {
  if (!wavInfo || wavInfo.dataOffset < 0 || !wavInfo.channels || !wavInfo.bitsPerSample) {
    return [];
  }

  const bytesPerSample = Math.ceil(wavInfo.bitsPerSample / 8);
  const frameSize = Math.max(1, wavInfo.channels * bytesPerSample);
  const dataEnd = Math.min(buffer.length, wavInfo.dataOffset + wavInfo.dataSize);
  const sampleCount = Math.min(MAX_AUDIO_SAMPLES, Math.floor((dataEnd - wavInfo.dataOffset) / frameSize));
  const streams = Array.from({ length: wavInfo.channels }, () => []);
  const mixed = [];

  for (let sampleIndex = 0; sampleIndex < sampleCount; sampleIndex += 1) {
    const frameOffset = wavInfo.dataOffset + sampleIndex * frameSize;
    for (let channel = 0; channel < wavInfo.channels; channel += 1) {
      const sampleOffset = frameOffset + channel * bytesPerSample;
      const leastByte = buffer[sampleOffset];
      const bit = leastByte & 1;
      streams[channel].push(bit);
      mixed.push(bit);
    }
  }

  return streams.map((bits, index) => ({
    channel: `CH${index + 1}`,
    bits,
  })).concat(
    mixed.length
      ? [
          {
            channel: "MIX",
            bits: mixed,
          },
        ]
      : [],
  );
}

function collectAudioLSBCandidates(buffer, wavInfo) {
  const streams = buildWavSampleStreams(buffer, wavInfo);
  const results = [];

  streams.forEach((stream) => {
    const decoded = decodeBufferAsText(bitsToBuffer(stream.bits));
    const flags = findFlagCandidates(decoded, `WAV-LSB-${stream.channel}`);
    const printable = extractPrintableSegments(decoded, 10, 10);
    if (!flags.length && !printable.length) {
      return;
    }
    results.push({
      channel: stream.channel,
      flags,
      printable,
    });
  });

  return results;
}

function makeWaveformPng(width, height, drawColumn) {
  const png = new PNG({ width, height });
  png.data.fill(248);
  for (let x = 0; x < width; x += 1) {
    drawColumn(png, x);
  }
  return PNG.sync.write(png);
}

function drawVertical(png, x, top, bottom, r, g, b) {
  const start = Math.max(0, Math.min(top, bottom));
  const end = Math.min(png.height - 1, Math.max(top, bottom));
  for (let y = start; y <= end; y += 1) {
    const offset = (y * png.width + x) * 4;
    png.data[offset] = r;
    png.data[offset + 1] = g;
    png.data[offset + 2] = b;
    png.data[offset + 3] = 255;
  }
}

function renderWavWaveform(buffer, wavInfo, width = 1024, height = 280) {
  if (!wavInfo || wavInfo.dataOffset < 0 || !wavInfo.channels || !wavInfo.bitsPerSample) {
    return null;
  }

  const bytesPerSample = Math.ceil(wavInfo.bitsPerSample / 8);
  const frameSize = Math.max(1, wavInfo.channels * bytesPerSample);
  const dataEnd = Math.min(buffer.length, wavInfo.dataOffset + wavInfo.dataSize);
  const totalFrames = Math.floor((dataEnd - wavInfo.dataOffset) / frameSize);
  if (!totalFrames) {
    return null;
  }

  const channelHeights = Math.max(1, Math.floor(height / Math.max(1, wavInfo.channels)));

  function sampleValue(frameIndex, channel) {
    const offset = wavInfo.dataOffset + frameIndex * frameSize + channel * bytesPerSample;
    if (wavInfo.bitsPerSample === 8) {
      return (buffer[offset] - 128) / 128;
    }
    if (wavInfo.bitsPerSample === 16) {
      return Math.max(-1, Math.min(1, buffer.readInt16LE(offset) / 32768));
    }
    if (wavInfo.bitsPerSample === 24) {
      const value = (buffer[offset + 2] << 16) | (buffer[offset + 1] << 8) | buffer[offset];
      const signed = value & 0x800000 ? value - 0x1000000 : value;
      return Math.max(-1, Math.min(1, signed / 8388608));
    }
    if (wavInfo.bitsPerSample === 32) {
      if (wavInfo.audioFormat === 3) {
        return Math.max(-1, Math.min(1, buffer.readFloatLE(offset)));
      }
      return Math.max(-1, Math.min(1, buffer.readInt32LE(offset) / 2147483648));
    }
    return 0;
  }

  return makeWaveformPng(width, height, (png, x) => {
    const startFrame = Math.floor((x / width) * totalFrames);
    const endFrame = Math.min(totalFrames, Math.floor(((x + 1) / width) * totalFrames) || startFrame + 1);
    for (let channel = 0; channel < wavInfo.channels; channel += 1) {
      let min = 1;
      let max = -1;
      for (let frame = startFrame; frame < endFrame; frame += 1) {
        const value = sampleValue(frame, channel);
        min = Math.min(min, value);
        max = Math.max(max, value);
      }
      const topBase = channel * channelHeights;
      const mid = topBase + Math.floor(channelHeights / 2);
      const top = mid - Math.round(max * (channelHeights * 0.42));
      const bottom = mid - Math.round(min * (channelHeights * 0.42));
      drawVertical(png, x, top, bottom, 20, 132, 120);
    }
  });
}

function iteratePngChunks(buffer) {
  const chunks = [];
  if (detectMagic(buffer) !== "png" || buffer.length < 8) {
    return chunks;
  }

  let offset = 8;
  while (offset + 8 <= buffer.length) {
    const length = buffer.readUInt32BE(offset);
    const type = buffer.subarray(offset + 4, offset + 8).toString("ascii");
    const dataStart = offset + 8;
    const dataEnd = dataStart + length;
    if (dataEnd + 4 > buffer.length) {
      break;
    }
    chunks.push({
      type,
      data: buffer.subarray(dataStart, dataEnd),
    });
    offset = dataEnd + 4;
    if (type === "IEND") {
      break;
    }
  }

  return chunks;
}

function extractPngTextChunks(buffer) {
  const results = [];
  for (const chunk of iteratePngChunks(buffer)) {
    try {
      if (chunk.type === "tEXt") {
        const separator = chunk.data.indexOf(0);
        if (separator !== -1) {
          const keyword = chunk.data.subarray(0, separator).toString("latin1");
          const text = chunk.data.subarray(separator + 1).toString("latin1");
          results.push(`${keyword}: ${text}`);
        }
      } else if (chunk.type === "zTXt") {
        const separator = chunk.data.indexOf(0);
        if (separator !== -1 && separator + 2 <= chunk.data.length) {
          const keyword = chunk.data.subarray(0, separator).toString("latin1");
          const method = chunk.data[separator + 1];
          if (method === 0) {
            const inflated = zlib.inflateSync(chunk.data.subarray(separator + 2)).toString("utf8");
            results.push(`${keyword}: ${inflated}`);
          }
        }
      } else if (chunk.type === "iTXt") {
        let cursor = 0;
        const firstNull = chunk.data.indexOf(0, cursor);
        if (firstNull === -1 || firstNull + 5 > chunk.data.length) {
          continue;
        }
        const keyword = chunk.data.subarray(0, firstNull).toString("utf8");
        const compressionFlag = chunk.data[firstNull + 1];
        const compressionMethod = chunk.data[firstNull + 2];
        cursor = firstNull + 3;
        const languageEnd = chunk.data.indexOf(0, cursor);
        if (languageEnd === -1) {
          continue;
        }
        cursor = languageEnd + 1;
        const translatedEnd = chunk.data.indexOf(0, cursor);
        if (translatedEnd === -1) {
          continue;
        }
        cursor = translatedEnd + 1;
        const textData = chunk.data.subarray(cursor);
        const text =
          compressionFlag === 1 && compressionMethod === 0 ? zlib.inflateSync(textData).toString("utf8") : textData.toString("utf8");
        results.push(`${keyword}: ${text}`);
      }
    } catch (_error) {
      // ignore malformed chunk payloads
    }
  }
  return dedupeStrings(results).slice(0, 20);
}

function bitsToBuffer(bits, bitOrder = "msb") {
  const bytes = [];
  for (let index = 0; index + 7 < bits.length; index += 8) {
    let value = 0;
    if (bitOrder === "lsb") {
      for (let bit = 0; bit < 8; bit += 1) {
        value |= bits[index + bit] << bit;
      }
    } else {
      for (let bit = 0; bit < 8; bit += 1) {
        value = (value << 1) | bits[index + bit];
      }
    }
    bytes.push(value);
  }
  return Buffer.from(bytes);
}

function buildPngStreams(parsed, traversal = "xy") {
  const streams = {
    R: [],
    G: [],
    B: [],
    A: [],
    RGB: [],
    RGBA: [],
  };

  const emit = (x, y) => {
    const index = (y * parsed.width + x) * 4;
    const r = parsed.data[index];
    const g = parsed.data[index + 1];
    const b = parsed.data[index + 2];
    const a = parsed.data[index + 3];
    streams.R.push(r);
    streams.G.push(g);
    streams.B.push(b);
    streams.A.push(a);
    streams.RGB.push(r, g, b);
    streams.RGBA.push(r, g, b, a);
  };

  if (traversal === "yx") {
    for (let x = 0; x < parsed.width; x += 1) {
      for (let y = 0; y < parsed.height; y += 1) {
        emit(x, y);
      }
    }
  } else {
    for (let y = 0; y < parsed.height; y += 1) {
      for (let x = 0; x < parsed.width; x += 1) {
        emit(x, y);
      }
    }
  }

  return streams;
}

function collectPngLSBCandidates(buffer) {
  if (detectMagic(buffer) !== "png") {
    return [];
  }

  let parsed;
  try {
    parsed = PNG.sync.read(buffer, { checkCRC: false });
  } catch (_error) {
    return [];
  }

  const results = [];
  ["xy", "yx"].forEach((traversal) => {
    const streams = buildPngStreams(parsed, traversal);
    Object.entries(streams).forEach(([name, values]) => {
      [0, 1, 2].forEach((bitPlane) => {
        ["msb", "lsb"].forEach((bitOrder) => {
          const bits = values.map((value) => (value >> bitPlane) & 1);
          const decoded = decodeBufferAsText(bitsToBuffer(bits, bitOrder));
          const flags = findFlagCandidates(decoded, `PNG-${traversal}-${name}-bit${bitPlane}-${bitOrder}`);
          const printable = extractPrintableSegments(decoded, 12, 8);
          const score = Math.max(scoreDecodedText(decoded), flags.length ? 24 : 0);
          if (!flags.length && (!printable.length || score < 8)) {
            return;
          }
          results.push({
            traversal,
            channel: name,
            bitPlane,
            bitOrder,
            flags,
            printable,
            score,
          });
        });
      });
    });
  });

  const deduped = new Map();
  results.forEach((item) => {
    const key = `${item.channel}@@${item.bitPlane}@@${item.bitOrder}@@${item.traversal}@@${item.printable.join("||")}@@${item.flags
      .map((entry) => entry.value)
      .join("||")}`;
    const current = deduped.get(key);
    if (!current || item.score > current.score) {
      deduped.set(key, item);
    }
  });

  return Array.from(deduped.values())
    .sort((left, right) => right.score - left.score)
    .slice(0, 18);
}

function markerAfterOffset(buffer, marker, offset) {
  const index = buffer.indexOf(marker, offset);
  return index >= offset ? index : -1;
}

function readUInt16(buffer, offset, littleEndian) {
  return littleEndian ? buffer.readUInt16LE(offset) : buffer.readUInt16BE(offset);
}

function readUInt32(buffer, offset, littleEndian) {
  return littleEndian ? buffer.readUInt32LE(offset) : buffer.readUInt32BE(offset);
}

function formatIPv4(buffer, offset) {
  return `${buffer[offset]}.${buffer[offset + 1]}.${buffer[offset + 2]}.${buffer[offset + 3]}`;
}

function formatIPv6(buffer, offset) {
  const parts = [];
  for (let index = 0; index < 16; index += 2) {
    parts.push(buffer.readUInt16BE(offset + index).toString(16));
  }
  return parts.join(":").replace(/\b:?(?:0:){2,}/, "::");
}

function parseTcpSegment(buffer) {
  if (buffer.length < 20) {
    return null;
  }
  const srcPort = buffer.readUInt16BE(0);
  const dstPort = buffer.readUInt16BE(2);
  const headerLength = ((buffer[12] >> 4) & 0x0f) * 4;
  if (headerLength < 20 || headerLength > buffer.length) {
    return null;
  }
  return {
    protocol: "tcp",
    srcPort,
    dstPort,
    payload: buffer.subarray(headerLength),
    flags: buffer[13],
  };
}

function parseUdpDatagram(buffer) {
  if (buffer.length < 8) {
    return null;
  }
  const srcPort = buffer.readUInt16BE(0);
  const dstPort = buffer.readUInt16BE(2);
  const length = Math.min(buffer.readUInt16BE(4), buffer.length);
  return {
    protocol: "udp",
    srcPort,
    dstPort,
    payload: buffer.subarray(8, length),
  };
}

function parseIpPacket(buffer) {
  if (!buffer.length) {
    return null;
  }

  const version = buffer[0] >> 4;
  if (version === 4) {
    if (buffer.length < 20) {
      return null;
    }
    const headerLength = (buffer[0] & 0x0f) * 4;
    if (headerLength < 20 || headerLength > buffer.length) {
      return null;
    }
    const protocol = buffer[9];
    const payload = buffer.subarray(headerLength);
    const base = {
      ipVersion: 4,
      srcIp: formatIPv4(buffer, 12),
      dstIp: formatIPv4(buffer, 16),
    };
    if (protocol === 6) {
      const tcp = parseTcpSegment(payload);
      return tcp ? { ...base, ...tcp } : null;
    }
    if (protocol === 17) {
      const udp = parseUdpDatagram(payload);
      return udp ? { ...base, ...udp } : null;
    }
    return { ...base, protocol: String(protocol), payload };
  }

  if (version === 6) {
    if (buffer.length < 40) {
      return null;
    }
    const nextHeader = buffer[6];
    const payload = buffer.subarray(40);
    const base = {
      ipVersion: 6,
      srcIp: formatIPv6(buffer, 8),
      dstIp: formatIPv6(buffer, 24),
    };
    if (nextHeader === 6) {
      const tcp = parseTcpSegment(payload);
      return tcp ? { ...base, ...tcp } : null;
    }
    if (nextHeader === 17) {
      const udp = parseUdpDatagram(payload);
      return udp ? { ...base, ...udp } : null;
    }
    return { ...base, protocol: String(nextHeader), payload };
  }

  return null;
}

function parseFramePayload(frameData, linkType) {
  if (!frameData.length) {
    return null;
  }

  if (linkType === 1) {
    if (frameData.length < 14) {
      return null;
    }
    let etherType = frameData.readUInt16BE(12);
    let offset = 14;
    if ((etherType === 0x8100 || etherType === 0x88a8) && frameData.length >= 18) {
      etherType = frameData.readUInt16BE(16);
      offset = 18;
    }
    if (etherType !== 0x0800 && etherType !== 0x86dd) {
      return null;
    }
    return parseIpPacket(frameData.subarray(offset));
  }

  if (linkType === 101 || linkType === 228) {
    return parseIpPacket(frameData);
  }

  return null;
}

function parseClassicPcap(buffer) {
  if (buffer.length < 24) {
    return [];
  }

  const magicLE = buffer.readUInt32LE(0);
  let littleEndian = true;
  if ([0xa1b2c3d4, 0xa1b23c4d].includes(magicLE)) {
    littleEndian = true;
  } else if ([0xd4c3b2a1, 0x4d3cb2a1].includes(magicLE)) {
    littleEndian = false;
  } else {
    return [];
  }

  const linkType = readUInt32(buffer, 20, littleEndian);
  const frames = [];
  let offset = 24;

  while (offset + 16 <= buffer.length && frames.length < MAX_TRAFFIC_FRAMES) {
    const capturedLength = readUInt32(buffer, offset + 8, littleEndian);
    const dataStart = offset + 16;
    const dataEnd = dataStart + capturedLength;
    if (capturedLength < 0 || dataEnd > buffer.length) {
      break;
    }
    frames.push({
      data: buffer.subarray(dataStart, dataEnd),
      linkType,
    });
    offset = dataEnd;
  }

  return frames;
}

function parsePcapNg(buffer) {
  if (buffer.length < 28 || buffer.readUInt32BE(0) !== 0x0a0d0d0a) {
    return [];
  }

  const bom = buffer.subarray(8, 12);
  const littleEndian = bom.equals(Buffer.from([0x4d, 0x3c, 0x2b, 0x1a]));
  const bigEndian = bom.equals(Buffer.from([0x1a, 0x2b, 0x3c, 0x4d]));
  if (!littleEndian && !bigEndian) {
    return [];
  }

  const le = littleEndian;
  const linkTypes = [];
  const frames = [];
  let offset = 0;

  while (offset + 12 <= buffer.length && frames.length < MAX_TRAFFIC_FRAMES) {
    const blockType = readUInt32(buffer, offset, le);
    const blockLength = readUInt32(buffer, offset + 4, le);
    if (blockLength < 12 || offset + blockLength > buffer.length) {
      break;
    }

    if (blockType === 1 && blockLength >= 20) {
      linkTypes.push(readUInt16(buffer, offset + 8, le));
    } else if (blockType === 6 && blockLength >= 32) {
      const interfaceId = readUInt32(buffer, offset + 8, le);
      const capturedLength = readUInt32(buffer, offset + 20, le);
      const dataStart = offset + 28;
      const dataEnd = dataStart + capturedLength;
      if (dataEnd <= offset + blockLength - 4) {
        frames.push({
          data: buffer.subarray(dataStart, dataEnd),
          linkType: linkTypes[interfaceId] || linkTypes[0] || 1,
        });
      }
    } else if (blockType === 3 && blockLength >= 20) {
      const packetLength = readUInt32(buffer, offset + 8, le);
      const dataStart = offset + 12;
      const dataEnd = dataStart + Math.min(packetLength, blockLength - 16);
      if (dataEnd <= offset + blockLength - 4) {
        frames.push({
          data: buffer.subarray(dataStart, dataEnd),
          linkType: linkTypes[0] || 1,
        });
      }
    }

    offset += blockLength;
  }

  return frames;
}

function parseCaptureFrames(buffer) {
  const magic = detectMagic(buffer);
  if (magic === "pcap") {
    return parseClassicPcap(buffer);
  }
  if (magic === "pcapng") {
    return parsePcapNg(buffer);
  }
  return [];
}

function parseDnsName(buffer, startOffset, depth = 0) {
  if (depth > 8 || startOffset >= buffer.length) {
    return { name: "", nextOffset: startOffset };
  }

  const labels = [];
  let offset = startOffset;
  let jumped = false;
  let nextOffset = startOffset;

  while (offset < buffer.length) {
    const length = buffer[offset];
    if (length === 0) {
      nextOffset = jumped ? nextOffset : offset + 1;
      break;
    }
    if ((length & 0xc0) === 0xc0) {
      if (offset + 1 >= buffer.length) {
        break;
      }
      const pointer = ((length & 0x3f) << 8) | buffer[offset + 1];
      const target = parseDnsName(buffer, pointer, depth + 1);
      if (target.name) {
        labels.push(target.name);
      }
      nextOffset = jumped ? nextOffset : offset + 2;
      jumped = true;
      break;
    }
    if (offset + 1 + length > buffer.length) {
      break;
    }
    labels.push(buffer.subarray(offset + 1, offset + 1 + length).toString("utf8"));
    offset += length + 1;
    if (!jumped) {
      nextOffset = offset;
    }
  }

  return {
    name: labels.join("."),
    nextOffset: nextOffset || offset,
  };
}

function parseDnsMessage(buffer) {
  if (buffer.length < 12) {
    return null;
  }

  const questionCount = buffer.readUInt16BE(4);
  const answerCount = buffer.readUInt16BE(6);
  const questions = [];
  const answers = [];
  let offset = 12;

  for (let index = 0; index < Math.min(questionCount, 20); index += 1) {
    const parsed = parseDnsName(buffer, offset);
    offset = parsed.nextOffset;
    if (offset + 4 > buffer.length) {
      return { questions, answers };
    }
    const type = buffer.readUInt16BE(offset);
    offset += 4;
    if (parsed.name) {
      questions.push(`${parsed.name} [${type}]`);
    }
  }

  for (let index = 0; index < Math.min(answerCount, 30); index += 1) {
    const parsed = parseDnsName(buffer, offset);
    offset = parsed.nextOffset;
    if (offset + 10 > buffer.length) {
      break;
    }
    const type = buffer.readUInt16BE(offset);
    const dataLength = buffer.readUInt16BE(offset + 8);
    const dataOffset = offset + 10;
    if (dataOffset + dataLength > buffer.length) {
      break;
    }

    let value = "";
    if (type === 1 && dataLength === 4) {
      value = formatIPv4(buffer, dataOffset);
    } else if (type === 28 && dataLength === 16) {
      value = formatIPv6(buffer, dataOffset);
    } else if (type === 5 || type === 12 || type === 2) {
      value = parseDnsName(buffer, dataOffset).name;
    } else if (type === 16 && dataLength >= 1) {
      const size = buffer[dataOffset];
      value = buffer.subarray(dataOffset + 1, dataOffset + 1 + Math.min(size, dataLength - 1)).toString("utf8");
    }

    if (parsed.name || value) {
      answers.push(`${parsed.name || "<name>"} [${type}] ${value}`.trim());
    }

    offset = dataOffset + dataLength;
  }

  return {
    questions: dedupeStrings(questions),
    answers: dedupeStrings(answers),
  };
}

function parseTlsServerNames(buffer) {
  if (buffer.length < 9 || buffer[0] !== 0x16) {
    return [];
  }
  const handshakeType = buffer[5];
  if (handshakeType !== 0x01) {
    return [];
  }

  let offset = 9;
  if (offset + 34 > buffer.length) {
    return [];
  }
  offset += 34;

  const sessionLength = buffer[offset];
  offset += 1 + sessionLength;
  if (offset + 2 > buffer.length) {
    return [];
  }

  const cipherLength = buffer.readUInt16BE(offset);
  offset += 2 + cipherLength;
  if (offset + 1 > buffer.length) {
    return [];
  }

  const compressionLength = buffer[offset];
  offset += 1 + compressionLength;
  if (offset + 2 > buffer.length) {
    return [];
  }

  const extensionLength = buffer.readUInt16BE(offset);
  offset += 2;
  const extensionEnd = Math.min(buffer.length, offset + extensionLength);
  const names = [];

  while (offset + 4 <= extensionEnd) {
    const type = buffer.readUInt16BE(offset);
    const length = buffer.readUInt16BE(offset + 2);
    const dataStart = offset + 4;
    const dataEnd = dataStart + length;
    if (dataEnd > extensionEnd) {
      break;
    }

    if (type === 0x0000 && length >= 5) {
      let cursor = dataStart + 2;
      while (cursor + 3 <= dataEnd) {
        const nameType = buffer[cursor];
        const nameLength = buffer.readUInt16BE(cursor + 1);
        const nameStart = cursor + 3;
        const nameEnd = nameStart + nameLength;
        if (nameEnd > dataEnd) {
          break;
        }
        if (nameType === 0) {
          names.push(buffer.subarray(nameStart, nameEnd).toString("utf8"));
        }
        cursor = nameEnd;
      }
    }

    offset = dataEnd;
  }

  return dedupeStrings(names).slice(0, 12);
}

function parseHttpPayload(buffer) {
  if (!buffer.length) {
    return null;
  }

  const text = decodeBufferAsText(buffer.subarray(0, Math.min(buffer.length, MAX_HTTP_BODY_BYTES + 4096)));
  const headerEnd = text.indexOf("\r\n\r\n") !== -1 ? text.indexOf("\r\n\r\n") : text.indexOf("\n\n");
  const splitIndex = headerEnd === -1 ? text.length : headerEnd;
  const headerText = text.slice(0, splitIndex);
  const lines = headerText.split(/\r?\n/).filter(Boolean);
  if (!lines.length) {
    return null;
  }

  const firstLine = lines[0].trim();
  const methods = ["GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH"];
  const isRequest = methods.some((method) => firstLine.startsWith(`${method} `));
  const isResponse = firstLine.startsWith("HTTP/");
  if (!isRequest && !isResponse) {
    return null;
  }

  const headers = {};
  lines.slice(1).forEach((line) => {
    const separator = line.indexOf(":");
    if (separator === -1) {
      return;
    }
    const key = line.slice(0, separator).trim().toLowerCase();
    const value = line.slice(separator + 1).trim();
    if (key) {
      headers[key] = value;
    }
  });

  let bodyBuffer = Buffer.alloc(0);
  if (headerEnd !== -1) {
    const delimiterLength = text.indexOf("\r\n\r\n") !== -1 ? 4 : 2;
    const headerBytes = Buffer.from(text.slice(0, splitIndex + delimiterLength), "utf8").length;
    bodyBuffer = buffer.subarray(Math.min(headerBytes, buffer.length), Math.min(buffer.length, headerBytes + MAX_HTTP_BODY_BYTES));
  }

  const result = {
    type: isRequest ? "request" : "response",
    firstLine,
    headers,
    bodyBuffer,
  };

  if (isRequest) {
    const match = firstLine.match(/^([A-Z]+)\s+(\S+)/);
    if (match) {
      result.method = match[1];
      result.path = match[2];
    }
  } else {
    const match = firstLine.match(/^HTTP\/\d\.\d\s+(\d+)/);
    if (match) {
      result.statusCode = Number(match[1]);
    }
  }

  return result;
}

function normalizeSessionKey(packet) {
  const left = `${packet.srcIp}:${packet.srcPort}`;
  const right = `${packet.dstIp}:${packet.dstPort}`;
  return [left, right].sort().join(" <-> ");
}

function analyzeTrafficBuffer(buffer) {
  const frames = parseCaptureFrames(buffer);
  const summary = {
    frameCount: frames.length,
    sessionCount: 0,
    httpRequests: [],
    dnsQueries: [],
    dnsAnswers: [],
    tlsServerNames: [],
    cookies: [],
    tokens: [],
    sessions: [],
    exportedObjects: [],
  };

  if (!frames.length) {
    return summary;
  }

  const sessions = new Map();

  frames.forEach((frame) => {
    const packet = parseFramePayload(frame.data, frame.linkType);
    if (!packet || !packet.payload) {
      return;
    }

    if (packet.protocol === "tcp" || packet.protocol === "udp") {
      const sessionKey = normalizeSessionKey(packet);
      const current = sessions.get(sessionKey) || {
        key: sessionKey,
        protocol: packet.protocol.toUpperCase(),
        endpoints: `${packet.srcIp}:${packet.srcPort} -> ${packet.dstIp}:${packet.dstPort}`,
        packets: 0,
        bytes: 0,
      };
      current.packets += 1;
      current.bytes += packet.payload.length;
      sessions.set(sessionKey, current);
    }

    if (packet.protocol === "udp" && (packet.srcPort === 53 || packet.dstPort === 53)) {
      const dns = parseDnsMessage(packet.payload);
      if (dns) {
        summary.dnsQueries.push(...dns.questions);
        summary.dnsAnswers.push(...dns.answers);
      }
      return;
    }

    if (packet.protocol !== "tcp" || !packet.payload.length) {
      return;
    }

    const http = parseHttpPayload(packet.payload);
    if (http) {
      if (http.type === "request") {
        summary.httpRequests.push(
          `${http.method || "HTTP"} ${http.headers.host || packet.dstIp}${http.path || ""}`,
        );
      }
      if (http.headers.cookie) {
        summary.cookies.push(http.headers.cookie);
      }
      if (http.headers.authorization || http.headers["x-token"] || http.headers.token) {
        summary.tokens.push(http.headers.authorization || http.headers["x-token"] || http.headers.token);
      }

      if (summary.exportedObjects.length < MAX_HTTP_OBJECTS) {
        const body = http.bodyBuffer || Buffer.alloc(0);
        const contentType = String(http.headers["content-type"] || "");
        const isTextLike = /json|xml|html|text|javascript|x-www-form-urlencoded/i.test(contentType);
        const baseName = `http-${String(summary.exportedObjects.length + 1).padStart(3, "0")}`;
        summary.exportedObjects.push({
          name: `${baseName}-${http.type}.txt`,
          content: Buffer.from(`${http.firstLine}\n${Object.entries(http.headers)
            .map(([key, value]) => `${key}: ${value}`)
            .join("\n")}\n`, "utf8"),
        });
        if (body.length) {
          let ext = ".bin";
          if (/json/i.test(contentType)) {
            ext = ".json";
          } else if (/html/i.test(contentType)) {
            ext = ".html";
          } else if (/xml/i.test(contentType)) {
            ext = ".xml";
          } else if (/javascript/i.test(contentType)) {
            ext = ".js";
          } else if (isTextLike) {
            ext = ".txt";
          }
          summary.exportedObjects.push({
            name: `${baseName}-body${ext}`,
            content: body,
          });
        }
      }
      return;
    }

    const tlsNames = parseTlsServerNames(packet.payload);
    if (tlsNames.length) {
      summary.tlsServerNames.push(...tlsNames);
    }
  });

  summary.dnsQueries = dedupeStrings(summary.dnsQueries).slice(0, 30);
  summary.dnsAnswers = dedupeStrings(summary.dnsAnswers).slice(0, 30);
  summary.httpRequests = dedupeStrings(summary.httpRequests).slice(0, 30);
  summary.tlsServerNames = dedupeStrings(summary.tlsServerNames).slice(0, 20);
  summary.cookies = dedupeStrings(summary.cookies).slice(0, 12);
  summary.tokens = dedupeStrings(summary.tokens).slice(0, 12);
  summary.sessions = Array.from(sessions.values())
    .sort((left, right) => right.bytes - left.bytes)
    .slice(0, 12);
  summary.sessionCount = sessions.size;

  return summary;
}

function buildTrafficSummaryText(fileName, summary) {
  const lines = [
    `# TRAFFIC SUMMARY`,
    `file: ${fileName}`,
    `frames: ${summary.frameCount}`,
    `sessions: ${summary.sessionCount}`,
    "",
  ];

  if (summary.httpRequests.length) {
    lines.push("# HTTP");
    summary.httpRequests.forEach((item) => lines.push(item));
    lines.push("");
  }
  if (summary.dnsQueries.length || summary.dnsAnswers.length) {
    lines.push("# DNS");
    summary.dnsQueries.forEach((item) => lines.push(`Q ${item}`));
    summary.dnsAnswers.forEach((item) => lines.push(`A ${item}`));
    lines.push("");
  }
  if (summary.tlsServerNames.length) {
    lines.push("# TLS-SNI");
    summary.tlsServerNames.forEach((item) => lines.push(item));
    lines.push("");
  }
  if (summary.cookies.length) {
    lines.push("# COOKIE");
    summary.cookies.forEach((item) => lines.push(item));
    lines.push("");
  }
  if (summary.tokens.length) {
    lines.push("# TOKEN");
    summary.tokens.forEach((item) => lines.push(item));
    lines.push("");
  }
  if (summary.sessions.length) {
    lines.push("# SESSIONS");
    summary.sessions.forEach((item) => lines.push(`${item.protocol} ${item.endpoints} packets=${item.packets} bytes=${item.bytes}`));
    lines.push("");
  }

  return `${lines.join("\n")}\n`;
}

function decodePdfLiteralString(value) {
  return String(value || "")
    .replace(/\\([\\()])/g, "$1")
    .replace(/\\n/g, "\n")
    .replace(/\\r/g, "\r")
    .replace(/\\t/g, "\t");
}

function findPdfStreams(buffer) {
  const streams = [];
  let offset = 0;

  while (offset < buffer.length) {
    const streamIndex = buffer.indexOf(Buffer.from("stream"), offset);
    if (streamIndex === -1) {
      break;
    }

    let dataStart = streamIndex + 6;
    if (buffer[dataStart] === 0x0d && buffer[dataStart + 1] === 0x0a) {
      dataStart += 2;
    } else if (buffer[dataStart] === 0x0a || buffer[dataStart] === 0x0d) {
      dataStart += 1;
    }

    const endIndex = buffer.indexOf(Buffer.from("endstream"), dataStart);
    if (endIndex === -1) {
      break;
    }

    const dictionaryText = buffer.subarray(Math.max(0, streamIndex - 256), streamIndex).toString("latin1");
    const raw = buffer.subarray(dataStart, endIndex);
    const trimmed =
      raw.length > 1 && raw[raw.length - 2] === 0x0d && raw[raw.length - 1] === 0x0a
        ? raw.subarray(0, raw.length - 2)
        : raw.length > 0 && (raw[raw.length - 1] === 0x0a || raw[raw.length - 1] === 0x0d)
          ? raw.subarray(0, raw.length - 1)
          : raw;

    streams.push({
      dictionaryText,
      raw: trimmed,
    });

    offset = endIndex + 9;
  }

  return streams;
}

function analyzePdfBuffer(buffer) {
  if (detectMagic(buffer) !== "pdf") {
    return null;
  }

  const latin = buffer.toString("latin1");
  const utf = decodeBufferAsText(buffer);
  const metadata = {};
  const urls = dedupeStrings(Array.from(utf.matchAll(/\bhttps?:\/\/[^\s"'<>]+/gi)).map((match) => match[0]).slice(0, 20));
  const xmpPackets = dedupeStrings(Array.from(latin.matchAll(/<x:xmpmeta[\s\S]{0,200000}?<\/x:xmpmeta>/gi)).map((match) => match[0]).slice(0, 6));
  const extractedStreams = [];

  Array.from(latin.matchAll(/\/(Title|Author|Subject|Keywords|Creator|Producer)\s*\(((?:\\.|[^\\)]){1,400})\)/g)).forEach((match) => {
    metadata[match[1]] = decodePdfLiteralString(match[2]);
  });

  findPdfStreams(buffer).forEach((stream, index) => {
    let decodedBuffer = stream.raw;
    if (/FlateDecode/i.test(stream.dictionaryText)) {
      try {
        decodedBuffer = zlib.inflateSync(stream.raw, { maxOutputLength: MAX_TEXT_BYTES });
      } catch (_error) {
        return;
      }
    }

    const decodedText = decodeBufferAsText(decodedBuffer);
    const printable = extractPrintableSegments(decodedText, 8, 20);
    const flags = findFlagCandidates(decodedText, `PDF-STREAM-${index + 1}`);
    if (!printable.length && !flags.length) {
      return;
    }

    extractedStreams.push({
      index: index + 1,
      flags,
      printable,
      text: decodedText.slice(0, MAX_TEXT_BYTES),
    });
  });

  return {
    metadata,
    urls,
    xmpPackets,
    extractedStreams,
  };
}

function buildPdfSummaryText(fileName, report) {
  const lines = [`# PDF SUMMARY`, `file: ${fileName}`, ""];

  const metadataEntries = Object.entries(report.metadata || {});
  if (metadataEntries.length) {
    lines.push("# METADATA");
    metadataEntries.forEach(([key, value]) => lines.push(`${key}: ${value}`));
    lines.push("");
  }
  if (report.urls && report.urls.length) {
    lines.push("# URL");
    report.urls.forEach((item) => lines.push(item));
    lines.push("");
  }
  if (report.extractedStreams && report.extractedStreams.length) {
    lines.push("# STREAMS");
    report.extractedStreams.forEach((item) => {
      lines.push(`stream-${item.index}`);
      item.flags.forEach((flag) => lines.push(flag.value));
      item.printable.forEach((entry) => lines.push(entry));
      lines.push("");
    });
  }
  if (report.xmpPackets && report.xmpPackets.length) {
    lines.push("# XMP");
    report.xmpPackets.forEach((_item, index) => lines.push(`xmp-${index + 1}.xml`));
    lines.push("");
  }

  return `${lines.join("\n")}\n`;
}

function readUIntValue(buffer, offset, size, littleEndian = true) {
  if (offset < 0 || offset + size > buffer.length) {
    return 0;
  }
  if (size === 1) {
    return buffer[offset];
  }
  if (size === 2) {
    return littleEndian ? buffer.readUInt16LE(offset) : buffer.readUInt16BE(offset);
  }
  if (size === 4) {
    return littleEndian ? buffer.readUInt32LE(offset) : buffer.readUInt32BE(offset);
  }
  return 0;
}

function readBigUIntValue(buffer, offset, littleEndian = true) {
  if (offset < 0 || offset + 8 > buffer.length) {
    return 0n;
  }
  return littleEndian ? buffer.readBigUInt64LE(offset) : buffer.readBigUInt64BE(offset);
}

function toSafeNumber(value) {
  if (typeof value === "bigint") {
    return value <= BigInt(Number.MAX_SAFE_INTEGER) ? Number(value) : null;
  }
  return Number.isFinite(value) ? value : null;
}

function formatHex(value) {
  if (value === null || value === undefined) {
    return "0x0";
  }
  if (typeof value === "bigint") {
    return `0x${value.toString(16)}`;
  }
  return `0x${Math.max(0, Number(value)).toString(16)}`;
}

function readCString(buffer, offset, maxLength = 256) {
  if (!Number.isFinite(offset) || offset < 0 || offset >= buffer.length) {
    return "";
  }
  const end = Math.min(buffer.length, offset + maxLength);
  let cursor = offset;
  while (cursor < end && buffer[cursor] !== 0) {
    cursor += 1;
  }
  return buffer.subarray(offset, cursor).toString("utf8").replace(/\0/g, "").trim();
}

function formatUnixTimestamp(timestampSeconds) {
  if (!timestampSeconds) {
    return "";
  }
  const date = new Date(timestampSeconds * 1000);
  return Number.isNaN(date.getTime()) ? "" : date.toISOString();
}

function getElfTypeLabel(type) {
  const labels = {
    1: "REL",
    2: "EXEC",
    3: "DYN",
    4: "CORE",
  };
  return labels[type] || `TYPE-${type}`;
}

function getElfMachineLabel(machine) {
  const labels = {
    3: "x86",
    8: "MIPS",
    20: "PowerPC",
    40: "ARM",
    62: "x86-64",
    183: "AArch64",
    243: "RISC-V",
  };
  return labels[machine] || `EM-${machine}`;
}

function getElfSymbolTypeLabel(info) {
  const labels = {
    0: "NOTYPE",
    1: "OBJECT",
    2: "FUNC",
    3: "SECTION",
    4: "FILE",
    5: "COMMON",
    6: "TLS",
  };
  return labels[info & 0x0f] || `TYPE-${info & 0x0f}`;
}

function getElfSymbolBindLabel(info) {
  const labels = {
    0: "LOCAL",
    1: "GLOBAL",
    2: "WEAK",
  };
  return labels[(info >> 4) & 0x0f] || `BIND-${(info >> 4) & 0x0f}`;
}

function parseElfSymbolSection(buffer, sections, section, littleEndian, is64) {
  const stringSection = sections[section.link];
  const symbolOffset = toSafeNumber(section.offset);
  const symbolSize = toSafeNumber(section.size);
  const stringOffset = stringSection ? toSafeNumber(stringSection.offset) : null;
  const stringSize = stringSection ? toSafeNumber(stringSection.size) : null;
  if (
    symbolOffset === null ||
    symbolSize === null ||
    symbolOffset + symbolSize > buffer.length ||
    !stringSection ||
    stringOffset === null ||
    stringSize === null ||
    stringOffset + stringSize > buffer.length
  ) {
    return null;
  }

  const entrySize = Math.max(toSafeNumber(section.entrySize) || 0, is64 ? 24 : 16);
  if (!entrySize) {
    return null;
  }
  const stringTable = buffer.subarray(stringOffset, stringOffset + stringSize);
  const namesByIndex = [];
  const functions = [];
  const globals = [];
  const objects = [];
  let count = 0;
  const maxSymbols = Math.min(512, Math.floor(symbolSize / entrySize));

  for (let index = 0; index < maxSymbols; index += 1) {
    const offset = symbolOffset + index * entrySize;
    if (offset + entrySize > symbolOffset + symbolSize) {
      break;
    }
    const nameOffset = readUIntValue(buffer, offset, 4, littleEndian);
    const info = buffer[offset + (is64 ? 4 : 12)] || 0;
    const name = nameOffset < stringTable.length ? readCString(stringTable, nameOffset, 256) : "";
    namesByIndex[index] = name;
    if (!name) {
      continue;
    }
    count += 1;
    const type = getElfSymbolTypeLabel(info);
    const bind = getElfSymbolBindLabel(info);
    const label = `${name} [${type}/${bind}]`;
    if (type === "FUNC" && functions.length < 40) {
      functions.push(label);
    }
    if (bind === "GLOBAL" && globals.length < 40) {
      globals.push(label);
    }
    if (type === "OBJECT" && objects.length < 40) {
      objects.push(label);
    }
  }

  return {
    name: section.name,
    count,
    functions: dedupeStrings(functions),
    globals: dedupeStrings(globals),
    objects: dedupeStrings(objects),
    namesByIndex,
  };
}

function parseElfRelocationSection(buffer, sections, section, littleEndian, is64, symbolNameMaps) {
  const relocationOffset = toSafeNumber(section.offset);
  const relocationSize = toSafeNumber(section.size);
  if (relocationOffset === null || relocationSize === null || relocationOffset + relocationSize > buffer.length) {
    return null;
  }

  const isRela = section.type === 4;
  const entrySize = Math.max(toSafeNumber(section.entrySize) || 0, is64 ? (isRela ? 24 : 16) : (isRela ? 12 : 8));
  if (!entrySize) {
    return null;
  }

  const count = Math.min(512, Math.floor(relocationSize / entrySize));
  const targetSection = Number.isInteger(section.info) && section.info >= 0 && section.info < sections.length ? sections[section.info] : null;
  const namesByIndex =
    Number.isInteger(section.link) && symbolNameMaps.has(section.link) ? symbolNameMaps.get(section.link) : [];
  const symbols = [];

  for (let index = 0; index < count; index += 1) {
    const offset = relocationOffset + index * entrySize;
    if (offset + entrySize > relocationOffset + relocationSize) {
      break;
    }
    const info = is64 ? readBigUIntValue(buffer, offset + 8, littleEndian) : BigInt(readUIntValue(buffer, offset + 4, 4, littleEndian));
    const symbolIndex = is64 ? Number(info >> 32n) : Number(info >> 8n);
    const symbolName = namesByIndex[symbolIndex];
    if (symbolName && symbols.length < 20) {
      symbols.push(symbolName);
    }
  }

  return {
    name: section.name,
    target: targetSection?.name || "",
    count,
    symbols: dedupeStrings(symbols),
  };
}

function parseElfBinary(buffer) {
  if (detectMagic(buffer) !== "elf" || buffer.length < 52) {
    return null;
  }

  const elfClass = buffer[4];
  const is64 = elfClass === 2;
  const littleEndian = buffer[5] !== 2;
  if (![1, 2].includes(elfClass)) {
    return null;
  }

  const headerSize = is64 ? 64 : 52;
  if (buffer.length < headerSize) {
    return null;
  }

  const readWord = (offset, size) => readUIntValue(buffer, offset, size, littleEndian);
  const readAddr = (offset) => (is64 ? readBigUIntValue(buffer, offset, littleEndian) : BigInt(readWord(offset, 4)));
  const type = readWord(16, 2);
  const machine = readWord(18, 2);
  const entry = readAddr(is64 ? 24 : 24);
  const programHeaderOffset = is64 ? readBigUIntValue(buffer, 32, littleEndian) : BigInt(readWord(28, 4));
  const sectionHeaderOffset = is64 ? readBigUIntValue(buffer, 40, littleEndian) : BigInt(readWord(32, 4));
  const programHeaderSize = readWord(is64 ? 54 : 42, 2);
  const programHeaderCount = readWord(is64 ? 56 : 44, 2);
  const sectionHeaderSize = readWord(is64 ? 58 : 46, 2);
  const sectionHeaderCount = readWord(is64 ? 60 : 48, 2);
  const sectionNameIndex = readWord(is64 ? 62 : 50, 2);

  const rawSections = [];
  const sectionHeaderStart = toSafeNumber(sectionHeaderOffset);
  if (sectionHeaderStart !== null && sectionHeaderSize >= (is64 ? 64 : 40)) {
    const maxSections = Math.min(sectionHeaderCount, 128);
    for (let index = 0; index < maxSections; index += 1) {
      const offset = sectionHeaderStart + index * sectionHeaderSize;
      if (offset < 0 || offset + sectionHeaderSize > buffer.length) {
        break;
      }
      const nameOffset = readWord(offset, 4);
      const sectionType = readWord(offset + 4, 4);
      const fileOffset = is64 ? readBigUIntValue(buffer, offset + 24, littleEndian) : BigInt(readWord(offset + 16, 4));
      const size = is64 ? readBigUIntValue(buffer, offset + 32, littleEndian) : BigInt(readWord(offset + 20, 4));
      const entrySize = is64 ? readBigUIntValue(buffer, offset + 56, littleEndian) : BigInt(readWord(offset + 36, 4));
      const link = readWord(offset + (is64 ? 40 : 24), 4);
      const info = readWord(offset + (is64 ? 44 : 28), 4);
      rawSections.push({
        index,
        nameOffset,
        type: sectionType,
        offset: fileOffset,
        size,
        entrySize,
        link,
        info,
      });
    }
  }

  let sectionNames = null;
  if (sectionNameIndex < rawSections.length) {
    const table = rawSections[sectionNameIndex];
    const tableOffset = toSafeNumber(table.offset);
    const tableSize = toSafeNumber(table.size);
    if (tableOffset !== null && tableSize !== null && tableOffset + tableSize <= buffer.length) {
      sectionNames = buffer.subarray(tableOffset, tableOffset + tableSize);
    }
  }

  const sections = rawSections.map((section) => {
    const name = sectionNames ? readCString(sectionNames, section.nameOffset, 128) : "";
    return {
      ...section,
      name: name || `section_${section.index}`,
    };
  });

  let interpreter = "";
  const programHeaderStart = toSafeNumber(programHeaderOffset);
  if (programHeaderStart !== null && programHeaderSize >= (is64 ? 56 : 32)) {
    const maxHeaders = Math.min(programHeaderCount, 64);
    for (let index = 0; index < maxHeaders; index += 1) {
      const offset = programHeaderStart + index * programHeaderSize;
      if (offset < 0 || offset + programHeaderSize > buffer.length) {
        break;
      }
      const programType = readWord(offset, 4);
      if (programType !== 3) {
        continue;
      }
      const fileOffset = is64 ? toSafeNumber(readBigUIntValue(buffer, offset + 8, littleEndian)) : readWord(offset + 4, 4);
      const fileSize = is64 ? toSafeNumber(readBigUIntValue(buffer, offset + 32, littleEndian)) : readWord(offset + 16, 4);
      if (fileOffset !== null && fileSize !== null && fileOffset + fileSize <= buffer.length) {
        interpreter = readCString(buffer, fileOffset, Math.min(fileSize, 256));
        break;
      }
    }
  }

  const dynamicSection = sections.find((section) => section.name === ".dynamic");
  const dynstrSection = sections.find((section) => section.name === ".dynstr");
  const neededLibraries = [];
  let runpath = "";
  let soname = "";
  if (dynamicSection && dynstrSection) {
    const dynamicOffset = toSafeNumber(dynamicSection.offset);
    const dynamicSize = toSafeNumber(dynamicSection.size);
    const dynstrOffset = toSafeNumber(dynstrSection.offset);
    const dynstrSize = toSafeNumber(dynstrSection.size);
    if (
      dynamicOffset !== null &&
      dynamicSize !== null &&
      dynstrOffset !== null &&
      dynstrSize !== null &&
      dynamicOffset + dynamicSize <= buffer.length &&
      dynstrOffset + dynstrSize <= buffer.length
    ) {
      const dynstr = buffer.subarray(dynstrOffset, dynstrOffset + dynstrSize);
      const entrySize = Math.max(is64 ? 16 : 8, toSafeNumber(dynamicSection.entrySize) || 0);
      for (let offset = dynamicOffset; offset + entrySize <= dynamicOffset + dynamicSize; offset += entrySize) {
        const tag = is64 ? readBigUIntValue(buffer, offset, littleEndian) : BigInt(readWord(offset, 4));
        const value = is64 ? readBigUIntValue(buffer, offset + 8, littleEndian) : BigInt(readWord(offset + 4, 4));
        if (tag === 0n) {
          break;
        }
        const stringOffset = toSafeNumber(value);
        if (stringOffset === null || stringOffset >= dynstr.length) {
          continue;
        }
        const text = readCString(dynstr, stringOffset, 256);
        if (!text) {
          continue;
        }
        if (tag === 1n) {
          neededLibraries.push(text);
        } else if (tag === 14n) {
          soname = text;
        } else if (tag === 15n || tag === 29n) {
          runpath = text;
        }
      }
    }
  }

  let commentPreview = [];
  const commentSection = sections.find((section) => section.name === ".comment");
  if (commentSection) {
    const commentOffset = toSafeNumber(commentSection.offset);
    const commentSize = toSafeNumber(commentSection.size);
    if (commentOffset !== null && commentSize !== null && commentOffset + commentSize <= buffer.length) {
      commentPreview = extractPrintableSegments(buffer.subarray(commentOffset, commentOffset + commentSize).toString("latin1"), 4, 12);
    }
  }

  const symbolTables = [];
  const symbolNameMaps = new Map();
  sections
    .filter((section) => section.type === 2 || section.type === 11)
    .forEach((section) => {
      const table = parseElfSymbolSection(buffer, sections, section, littleEndian, is64);
      if (table) {
        symbolTables.push(table);
        symbolNameMaps.set(section.index, table.namesByIndex);
      }
    });

  const relocations = sections
    .filter((section) => section.type === 4 || section.type === 9)
    .map((section) => parseElfRelocationSection(buffer, sections, section, littleEndian, is64, symbolNameMaps))
    .filter(Boolean);

  return {
    format: is64 ? "ELF64" : "ELF32",
    endian: littleEndian ? "LE" : "BE",
    type: getElfTypeLabel(type),
    machine: getElfMachineLabel(machine),
    entry,
    interpreter,
    sections: sections.slice(0, 64).map((section) => ({
      name: section.name,
      type: section.type,
      offset: section.offset,
      size: section.size,
    })),
    neededLibraries: dedupeStrings(neededLibraries).slice(0, 24),
    runpath,
    soname,
    commentPreview,
    symbolTables: symbolTables.map((table) => ({
      name: table.name,
      count: table.count,
      functions: table.functions,
      globals: table.globals,
      objects: table.objects,
    })),
    relocations,
  };
}

function buildElfSummaryText(fileName, report) {
  const lines = [`# ELF SUMMARY`, `file: ${fileName}`, ""];
  lines.push(`format: ${report.format}`);
  lines.push(`endian: ${report.endian}`);
  lines.push(`type: ${report.type}`);
  lines.push(`machine: ${report.machine}`);
  lines.push(`entry: ${formatHex(report.entry)}`);
  lines.push("");
  if (report.interpreter) {
    lines.push("# INTERPRETER");
    lines.push(report.interpreter);
    lines.push("");
  }
  if (report.neededLibraries.length) {
    lines.push("# NEEDED");
    report.neededLibraries.forEach((item) => lines.push(item));
    lines.push("");
  }
  if (report.soname || report.runpath) {
    lines.push("# DYNAMIC");
    if (report.soname) {
      lines.push(`soname: ${report.soname}`);
    }
    if (report.runpath) {
      lines.push(`runpath: ${report.runpath}`);
    }
    lines.push("");
  }
  if (report.commentPreview.length) {
    lines.push("# COMMENT");
    report.commentPreview.forEach((item) => lines.push(item));
    lines.push("");
  }
  if (report.symbolTables.length) {
    lines.push("# SYMBOLS");
    report.symbolTables.forEach((table) => {
      lines.push(`${table.name} count=${table.count}`);
      if (table.functions.length) {
        lines.push(`functions: ${table.functions.join(", ")}`);
      }
      if (table.globals.length) {
        lines.push(`globals: ${table.globals.join(", ")}`);
      }
      if (table.objects.length) {
        lines.push(`objects: ${table.objects.join(", ")}`);
      }
      lines.push("");
    });
  }
  if (report.relocations.length) {
    lines.push("# RELOCATIONS");
    report.relocations.forEach((entry) => {
      lines.push(`${entry.name} target=${entry.target || "?"} count=${entry.count}`);
      if (entry.symbols.length) {
        lines.push(`symbols: ${entry.symbols.join(", ")}`);
      }
      lines.push("");
    });
  }
  if (report.sections.length) {
    lines.push("# SECTIONS");
    report.sections.forEach((section) => {
      lines.push(`${section.name} type=${section.type} offset=${formatHex(section.offset)} size=${formatHex(section.size)}`);
    });
    lines.push("");
  }
  return `${lines.join("\n")}\n`;
}

function getPeMachineLabel(machine) {
  const labels = {
    0x14c: "x86",
    0x1c0: "ARM",
    0x1c4: "ARMv7",
    0x8664: "x86-64",
    0xaa64: "ARM64",
  };
  return labels[machine] || `MACHINE-${machine}`;
}

function getPeSubsystemLabel(subsystem) {
  const labels = {
    1: "Native",
    2: "Windows GUI",
    3: "Windows CUI",
    5: "OS/2 CUI",
    7: "POSIX CUI",
    9: "Windows CE",
    10: "EFI Application",
    14: "Xbox",
    16: "Boot",
  };
  return labels[subsystem] || `SUBSYSTEM-${subsystem}`;
}

function peRvaToOffset(rva, sections, sizeOfHeaders = 0) {
  if (!rva) {
    return null;
  }
  if (rva < sizeOfHeaders) {
    return rva;
  }
  for (const section of sections) {
    const start = section.virtualAddress;
    const end = start + Math.max(section.virtualSize, section.rawSize);
    if (rva >= start && rva < end) {
      return section.rawOffset + (rva - start);
    }
  }
  return null;
}

function parsePeBinary(buffer) {
  if (detectMagic(buffer) !== "pe" || buffer.length < 0x40) {
    return null;
  }

  const peOffset = buffer.readUInt32LE(0x3c);
  if (peOffset <= 0 || peOffset + 24 > buffer.length || buffer.subarray(peOffset, peOffset + 4).toString("ascii") !== "PE\u0000\u0000") {
    return null;
  }

  const coffOffset = peOffset + 4;
  const machine = buffer.readUInt16LE(coffOffset);
  const numberOfSections = buffer.readUInt16LE(coffOffset + 2);
  const timestamp = buffer.readUInt32LE(coffOffset + 4);
  const optionalHeaderSize = buffer.readUInt16LE(coffOffset + 16);
  const optionalOffset = coffOffset + 20;
  if (optionalOffset + optionalHeaderSize > buffer.length || optionalHeaderSize < 96) {
    return null;
  }

  const optionalMagic = buffer.readUInt16LE(optionalOffset);
  const is64 = optionalMagic === 0x20b;
  const entryPointRva = buffer.readUInt32LE(optionalOffset + 16);
  const imageBase = is64 ? buffer.readBigUInt64LE(optionalOffset + 24) : BigInt(buffer.readUInt32LE(optionalOffset + 28));
  const subsystem = buffer.readUInt16LE(optionalOffset + 68);
  const sizeOfHeaders = buffer.readUInt32LE(optionalOffset + 60);
  const dataDirectoryOffset = optionalOffset + (is64 ? 112 : 96);
  const sectionOffset = optionalOffset + optionalHeaderSize;

  const sections = [];
  for (let index = 0; index < Math.min(numberOfSections, 96); index += 1) {
    const offset = sectionOffset + index * 40;
    if (offset + 40 > buffer.length) {
      break;
    }
    const name = buffer.subarray(offset, offset + 8).toString("latin1").replace(/\0/g, "").trim() || `section_${index}`;
    sections.push({
      name,
      virtualSize: buffer.readUInt32LE(offset + 8),
      virtualAddress: buffer.readUInt32LE(offset + 12),
      rawSize: buffer.readUInt32LE(offset + 16),
      rawOffset: buffer.readUInt32LE(offset + 20),
      characteristics: buffer.readUInt32LE(offset + 36),
    });
  }

  const importedLibraries = [];
  const importedFunctions = [];
  if (dataDirectoryOffset + 16 <= buffer.length) {
    const importRva = buffer.readUInt32LE(dataDirectoryOffset + 8);
    const importOffset = peRvaToOffset(importRva, sections, sizeOfHeaders);
    const thunkSize = is64 ? 8 : 4;
    if (importOffset !== null) {
      for (let index = 0; index < 128; index += 1) {
        const offset = importOffset + index * 20;
        if (offset + 20 > buffer.length) {
          break;
        }
        const originalFirstThunk = buffer.readUInt32LE(offset);
        const nameRva = buffer.readUInt32LE(offset + 12);
        const firstThunk = buffer.readUInt32LE(offset + 16);
        if (!originalFirstThunk && !nameRva && !firstThunk) {
          break;
        }

        const nameOffset = peRvaToOffset(nameRva, sections, sizeOfHeaders);
        const libraryName = nameOffset !== null ? readCString(buffer, nameOffset, 128) : `import_${index + 1}`;
        const thunkRva = originalFirstThunk || firstThunk;
        let thunkOffset = peRvaToOffset(thunkRva, sections, sizeOfHeaders);
        const functions = [];
        for (let thunkIndex = 0; thunkOffset !== null && thunkIndex < 96 && thunkOffset + thunkSize <= buffer.length; thunkIndex += 1, thunkOffset += thunkSize) {
          const thunkValue = is64 ? buffer.readBigUInt64LE(thunkOffset) : BigInt(buffer.readUInt32LE(thunkOffset));
          if (thunkValue === 0n) {
            break;
          }
          const ordinalFlag = is64 ? 0x8000000000000000n : 0x80000000n;
          if ((thunkValue & ordinalFlag) !== 0n) {
            const ordinal = Number(thunkValue & 0xffffn);
            functions.push(`ordinal:${ordinal}`);
            continue;
          }
          const functionNameOffset = peRvaToOffset(Number(thunkValue), sections, sizeOfHeaders);
          if (functionNameOffset === null || functionNameOffset + 2 > buffer.length) {
            continue;
          }
          const functionName = readCString(buffer, functionNameOffset + 2, 128);
          if (functionName) {
            functions.push(functionName);
            importedFunctions.push(`${libraryName}!${functionName}`);
          }
        }
        importedLibraries.push({
          name: libraryName,
          functions: dedupeStrings(functions).slice(0, 32),
        });
      }
    }
  }

  let exportName = "";
  const exportedFunctions = [];
  if (dataDirectoryOffset + 8 <= buffer.length) {
    const exportRva = buffer.readUInt32LE(dataDirectoryOffset);
    const exportOffset = peRvaToOffset(exportRva, sections, sizeOfHeaders);
    if (exportOffset !== null && exportOffset + 40 <= buffer.length) {
      const nameRva = buffer.readUInt32LE(exportOffset + 12);
      const ordinalBase = buffer.readUInt32LE(exportOffset + 16);
      const numberOfFunctions = buffer.readUInt32LE(exportOffset + 20);
      const numberOfNames = buffer.readUInt32LE(exportOffset + 24);
      const addressOfNames = buffer.readUInt32LE(exportOffset + 32);
      const addressOfNameOrdinals = buffer.readUInt32LE(exportOffset + 36);
      const exportNameOffset = peRvaToOffset(nameRva, sections, sizeOfHeaders);
      if (exportNameOffset !== null) {
        exportName = readCString(buffer, exportNameOffset, 256);
      }
      const namesOffset = peRvaToOffset(addressOfNames, sections, sizeOfHeaders);
      const ordinalsOffset = peRvaToOffset(addressOfNameOrdinals, sections, sizeOfHeaders);
      if (namesOffset !== null && ordinalsOffset !== null) {
        const maxNames = Math.min(numberOfNames, numberOfFunctions, 160);
        for (let index = 0; index < maxNames; index += 1) {
          const namePtrOffset = namesOffset + index * 4;
          const ordinalPtrOffset = ordinalsOffset + index * 2;
          if (namePtrOffset + 4 > buffer.length || ordinalPtrOffset + 2 > buffer.length) {
            break;
          }
          const functionNameRva = buffer.readUInt32LE(namePtrOffset);
          const functionNameOffset = peRvaToOffset(functionNameRva, sections, sizeOfHeaders);
          if (functionNameOffset === null) {
            continue;
          }
          const functionName = readCString(buffer, functionNameOffset, 160);
          if (!functionName) {
            continue;
          }
          const ordinal = ordinalBase + buffer.readUInt16LE(ordinalPtrOffset);
          exportedFunctions.push(`${functionName} @${ordinal}`);
        }
      }
    }
  }

  const cliDirectoryOffset = dataDirectoryOffset + 14 * 8;
  const dotNet = cliDirectoryOffset + 8 <= buffer.length && buffer.readUInt32LE(cliDirectoryOffset) !== 0;

  return {
    format: is64 ? "PE32+" : "PE32",
    machine: getPeMachineLabel(machine),
    timestamp,
    timestampIso: formatUnixTimestamp(timestamp),
    subsystem: getPeSubsystemLabel(subsystem),
    entryPointRva,
    imageBase,
    sections,
    importedLibraries,
    importedFunctions: dedupeStrings(importedFunctions).slice(0, 120),
    exportName,
    exportedFunctions: dedupeStrings(exportedFunctions).slice(0, 160),
    dotNet,
  };
}

function buildPeSummaryText(fileName, report) {
  const lines = [`# PE SUMMARY`, `file: ${fileName}`, ""];
  lines.push(`format: ${report.format}`);
  lines.push(`machine: ${report.machine}`);
  lines.push(`subsystem: ${report.subsystem}`);
  lines.push(`entryPointRva: ${formatHex(report.entryPointRva)}`);
  lines.push(`imageBase: ${formatHex(report.imageBase)}`);
  if (report.timestampIso) {
    lines.push(`timestamp: ${report.timestampIso}`);
  }
  if (report.dotNet) {
    lines.push(`dotNet: true`);
  }
  lines.push("");
  if (report.importedLibraries.length) {
    lines.push("# IMPORTS");
    report.importedLibraries.forEach((library) => {
      lines.push(`${library.name}${library.functions.length ? ` => ${library.functions.join(", ")}` : ""}`);
    });
    lines.push("");
  }
  if (report.exportedFunctions.length) {
    lines.push("# EXPORTS");
    if (report.exportName) {
      lines.push(`library: ${report.exportName}`);
    }
    report.exportedFunctions.forEach((item) => lines.push(item));
    lines.push("");
  }
  if (report.sections.length) {
    lines.push("# SECTIONS");
    report.sections.forEach((section) => {
      lines.push(
        `${section.name} va=${formatHex(section.virtualAddress)} raw=${formatHex(section.rawOffset)} size=${formatHex(section.rawSize)} flags=${formatHex(section.characteristics)}`,
      );
    });
    lines.push("");
  }
  return `${lines.join("\n")}\n`;
}

function looksLikeJavaPackageName(value) {
  return /^(?:[A-Za-z][\w$]*\.){1,}[A-Za-z][\w$]*$/.test(value);
}

function readDexUleb128(buffer, offset) {
  let result = 0;
  let shift = 0;
  let cursor = offset;
  while (cursor < buffer.length && shift <= 28) {
    const byte = buffer[cursor];
    result |= (byte & 0x7f) << shift;
    cursor += 1;
    if ((byte & 0x80) === 0) {
      return { value: result >>> 0, nextOffset: cursor };
    }
    shift += 7;
  }
  return { value: 0, nextOffset: offset };
}

function readAndroidLength8(buffer, offset) {
  if (offset >= buffer.length) {
    return { value: 0, nextOffset: offset };
  }
  const first = buffer[offset];
  if ((first & 0x80) === 0) {
    return { value: first, nextOffset: offset + 1 };
  }
  if (offset + 1 >= buffer.length) {
    return { value: first & 0x7f, nextOffset: buffer.length };
  }
  return { value: ((first & 0x7f) << 8) | buffer[offset + 1], nextOffset: offset + 2 };
}

function readAndroidLength16(buffer, offset) {
  if (offset + 2 > buffer.length) {
    return { value: 0, nextOffset: offset };
  }
  const first = buffer.readUInt16LE(offset);
  if ((first & 0x8000) === 0) {
    return { value: first, nextOffset: offset + 2 };
  }
  if (offset + 4 > buffer.length) {
    return { value: first & 0x7fff, nextOffset: buffer.length };
  }
  const second = buffer.readUInt16LE(offset + 2);
  return { value: ((first & 0x7fff) << 16) | second, nextOffset: offset + 4 };
}

function parseAndroidStringPoolChunk(buffer, chunkOffset) {
  if (chunkOffset + 28 > buffer.length) {
    return [];
  }
  const chunkType = buffer.readUInt16LE(chunkOffset);
  const headerSize = buffer.readUInt16LE(chunkOffset + 2);
  const chunkSize = buffer.readUInt32LE(chunkOffset + 4);
  if (chunkType !== 0x0001 || headerSize < 28 || chunkSize <= headerSize || chunkOffset + chunkSize > buffer.length) {
    return [];
  }

  const stringCount = buffer.readUInt32LE(chunkOffset + 8);
  const flags = buffer.readUInt32LE(chunkOffset + 16);
  const stringsStart = buffer.readUInt32LE(chunkOffset + 20);
  if (!stringCount || stringCount > 4096) {
    return [];
  }

  const utf8 = (flags & 0x00000100) !== 0;
  const offsetsStart = chunkOffset + headerSize;
  const dataStart = chunkOffset + stringsStart;
  const values = [];

  for (let index = 0; index < stringCount; index += 1) {
    const entryOffset = offsetsStart + index * 4;
    if (entryOffset + 4 > chunkOffset + chunkSize) {
      break;
    }
    const relative = buffer.readUInt32LE(entryOffset);
    let stringOffset = dataStart + relative;
    if (stringOffset < dataStart || stringOffset >= chunkOffset + chunkSize) {
      continue;
    }

    let text = "";
    if (utf8) {
      const skippedUtf16 = readAndroidLength8(buffer, stringOffset);
      const byteLengthInfo = readAndroidLength8(buffer, skippedUtf16.nextOffset);
      stringOffset = byteLengthInfo.nextOffset;
      const byteEnd = Math.min(chunkOffset + chunkSize, stringOffset + byteLengthInfo.value);
      text = buffer.subarray(stringOffset, byteEnd).toString("utf8");
    } else {
      const charLengthInfo = readAndroidLength16(buffer, stringOffset);
      stringOffset = charLengthInfo.nextOffset;
      const byteEnd = Math.min(chunkOffset + chunkSize, stringOffset + charLengthInfo.value * 2);
      text = buffer.subarray(stringOffset, byteEnd).toString("utf16le");
    }

    text = text.replace(/\0/g, "").trim();
    if (text) {
      values.push(text);
    }
  }

  return dedupeStrings(values);
}

function extractAndroidStringPools(buffer) {
  const collected = [];
  for (let offset = 0; offset + 28 <= buffer.length; offset += 4) {
    if (buffer.readUInt16LE(offset) !== 0x0001) {
      continue;
    }
    const headerSize = buffer.readUInt16LE(offset + 2);
    const chunkSize = buffer.readUInt32LE(offset + 4);
    if (headerSize < 28 || chunkSize <= headerSize || offset + chunkSize > buffer.length) {
      continue;
    }
    parseAndroidStringPoolChunk(buffer, offset).forEach((item) => collected.push(item));
  }
  return dedupeStrings(collected);
}

function parseDexBuffer(buffer) {
  if (buffer.length < 112 || (!buffer.subarray(0, 4).equals(Buffer.from("dex\n")) && !buffer.subarray(0, 4).equals(Buffer.from("cdex")))) {
    return null;
  }

  const stringIdsSize = buffer.readUInt32LE(56);
  const stringIdsOffset = buffer.readUInt32LE(60);
  const typeIdsSize = buffer.readUInt32LE(64);
  const typeIdsOffset = buffer.readUInt32LE(68);
  const methodIdsSize = buffer.readUInt32LE(88);
  const methodIdsOffset = buffer.readUInt32LE(92);
  if (
    stringIdsOffset + stringIdsSize * 4 > buffer.length ||
    typeIdsOffset + typeIdsSize * 4 > buffer.length ||
    methodIdsOffset + methodIdsSize * 8 > buffer.length
  ) {
    return null;
  }

  const strings = [];
  for (let index = 0; index < Math.min(stringIdsSize, 4096); index += 1) {
    const dataOffset = buffer.readUInt32LE(stringIdsOffset + index * 4);
    if (!dataOffset || dataOffset >= buffer.length) {
      strings.push("");
      continue;
    }
    const lengthInfo = readDexUleb128(buffer, dataOffset);
    let cursor = lengthInfo.nextOffset;
    while (cursor < buffer.length && buffer[cursor] !== 0) {
      cursor += 1;
    }
    strings.push(buffer.subarray(lengthInfo.nextOffset, cursor).toString("utf8").replace(/\0/g, ""));
  }

  const typeDescriptors = [];
  for (let index = 0; index < Math.min(typeIdsSize, 4096); index += 1) {
    const descriptorIndex = buffer.readUInt32LE(typeIdsOffset + index * 4);
    typeDescriptors.push(strings[descriptorIndex] || "");
  }

  const methods = [];
  for (let index = 0; index < Math.min(methodIdsSize, 512); index += 1) {
    const offset = methodIdsOffset + index * 8;
    const classIndex = buffer.readUInt16LE(offset);
    const nameIndex = buffer.readUInt32LE(offset + 4);
    const classDescriptor = typeDescriptors[classIndex] || "";
    const methodName = strings[nameIndex] || "";
    if (!methodName) {
      continue;
    }
    methods.push(`${classDescriptor || "?"} -> ${methodName}`);
  }

  return {
    stringCount: stringIdsSize,
    typeCount: typeIdsSize,
    methodCount: methodIdsSize,
    classDescriptors: dedupeStrings(
      typeDescriptors.filter((item) => /^L[^;]+;$/.test(item)).map((item) => item.replace(/^L/, "").replace(/;$/, "").replace(/\//g, ".")),
    ).slice(0, 160),
    methods: dedupeStrings(methods).slice(0, 160),
    strings: dedupeStrings(strings.filter((item) => item && (looksLikeJavaPackageName(item) || /^https?:\/\//i.test(item) || KNOWN_FLAG_PREFIX.test(item)))).slice(0, 160),
  };
}

function parseApkPackage(filePath) {
  const zip = new AdmZip(filePath);
  const entries = zip.getEntries().filter((entry) => !entry.isDirectory);
  if (!entries.length) {
    return null;
  }

  const manifestEntry = entries.find((entry) => entry.entryName === "AndroidManifest.xml");
  const manifestBuffer = manifestEntry ? manifestEntry.getData() : Buffer.alloc(0);
  const manifestStrings = manifestBuffer.length
    ? dedupeStrings(
        extractAndroidStringPools(manifestBuffer).concat(extractAsciiStrings(manifestBuffer, 4, 600), extractUnicodeStrings(manifestBuffer, 4, 400)),
      )
    : [];
  const manifestText = manifestStrings.join("\n");
  const permissions = dedupeStrings(
    Array.from(manifestText.matchAll(/\b(?:android|com(?:\.[A-Za-z0-9_]+)+)\.permission\.[A-Za-z0-9_.]+\b/g)).map((match) => match[0]),
  ).slice(0, 32);
  const packageNames = dedupeStrings(
    Array.from(manifestText.matchAll(/\b(?:[A-Za-z][\w$]*\.){1,}[A-Za-z][\w$]*\b/g))
      .map((match) => match[0])
      .filter(
        (item) =>
          looksLikeJavaPackageName(item) &&
          !item.startsWith("android.") &&
          !item.startsWith("androidx.") &&
          !item.startsWith("java.") &&
          !/(Activity|Service|Receiver|Provider)$/.test(item),
      ),
  ).slice(0, 24);
  const components = dedupeStrings(
    Array.from(manifestText.matchAll(/\b(?:[A-Za-z][\w$]*\.)*[A-Za-z][\w$]*(?:Activity|Service|Receiver|Provider)\b/g)).map((match) => match[0]),
  ).slice(0, 24);
  const dexEntries = entries.filter((entry) => /(^|\/)classes\d*\.dex$/i.test(entry.entryName));
  const dexStrings = [];
  const dexMethods = [];
  const dexClasses = [];
  dexEntries.slice(0, 3).forEach((entry) => {
    const content = entry.getData();
    const parsedDex = parseDexBuffer(content);
    if (parsedDex) {
      parsedDex.strings.slice(0, 100).forEach((item) => dexStrings.push(item));
      parsedDex.methods.slice(0, 120).forEach((item) => dexMethods.push(item));
      parsedDex.classDescriptors.slice(0, 120).forEach((item) => dexClasses.push(item));
      return;
    }
    const strings = dedupeStrings(extractAsciiStrings(content, 6, 500).concat(extractUnicodeStrings(content, 6, 200)));
    strings
      .filter((item) => looksLikeJavaPackageName(item) || /^https?:\/\//i.test(item) || KNOWN_FLAG_PREFIX.test(item))
      .slice(0, 80)
      .forEach((item) => dexStrings.push(item));
  });

  const resourceEntry = entries.find((entry) => entry.entryName === "resources.arsc");
  const resourceStrings = resourceEntry ? extractAndroidStringPools(resourceEntry.getData()).slice(0, 200) : [];

  const nativeAbis = dedupeStrings(
    entries.map((entry) => {
      const match = /^lib\/([^/]+)\//i.exec(entry.entryName);
      return match ? match[1] : "";
    }),
  ).filter(Boolean);

  return {
    entryCount: entries.length,
    dexEntries: dexEntries.map((entry) => entry.entryName),
    assetCount: entries.filter((entry) => /^assets\//i.test(entry.entryName)).length,
    metaCount: entries.filter((entry) => /^META-INF\//i.test(entry.entryName)).length,
    nativeAbis,
    packageNames,
    permissions,
    components,
    manifestStrings: manifestStrings.slice(0, 120),
    dexStrings: dedupeStrings(dexStrings).slice(0, 120),
    dexMethods: dedupeStrings(dexMethods).slice(0, 160),
    dexClasses: dedupeStrings(dexClasses).slice(0, 120),
    resourceStrings,
  };
}

function buildApkSummaryText(fileName, report) {
  const lines = [`# APK SUMMARY`, `file: ${fileName}`, ""];
  lines.push(`entries: ${report.entryCount}`);
  lines.push(`dexFiles: ${report.dexEntries.length}`);
  lines.push(`assets: ${report.assetCount}`);
  lines.push(`metaInf: ${report.metaCount}`);
  if (report.nativeAbis.length) {
    lines.push(`abis: ${report.nativeAbis.join(", ")}`);
  }
  lines.push("");
  if (report.packageNames.length) {
    lines.push("# PACKAGE");
    report.packageNames.forEach((item) => lines.push(item));
    lines.push("");
  }
  if (report.permissions.length) {
    lines.push("# PERMISSIONS");
    report.permissions.forEach((item) => lines.push(item));
    lines.push("");
  }
  if (report.components.length) {
    lines.push("# COMPONENTS");
    report.components.forEach((item) => lines.push(item));
    lines.push("");
  }
  if (report.dexEntries.length) {
    lines.push("# DEX");
    report.dexEntries.forEach((item) => lines.push(item));
    lines.push("");
  }
  if (report.dexClasses.length) {
    lines.push("# DEX CLASSES");
    report.dexClasses.forEach((item) => lines.push(item));
    lines.push("");
  }
  if (report.dexMethods.length) {
    lines.push("# DEX METHODS");
    report.dexMethods.forEach((item) => lines.push(item));
    lines.push("");
  }
  if (report.dexStrings.length) {
    lines.push("# DEX STRINGS");
    report.dexStrings.forEach((item) => lines.push(item));
    lines.push("");
  }
  if (report.resourceStrings.length) {
    lines.push("# RESOURCES");
    report.resourceStrings.forEach((item) => lines.push(item));
    lines.push("");
  }
  if (report.manifestStrings.length) {
    lines.push("# MANIFEST STRINGS");
    report.manifestStrings.forEach((item) => lines.push(item));
    lines.push("");
  }
  return `${lines.join("\n")}\n`;
}

async function buildArtifactSignals(filePath) {
  const extension = path.extname(filePath).toLowerCase();
  const sampleLimit =
    extension === ".txt"
      ? MAX_TEXT_BYTES
      : [".wav", ".mp3", ".flac", ".ogg", ".m4a"].includes(extension)
        ? MAX_AUDIO_BYTES
      : [".pcap", ".pcapng", ".cap"].includes(extension)
        ? MAX_TRAFFIC_BYTES
        : MAX_SAMPLE_BYTES;
  const { stat, buffer } = readSample(filePath, sampleLimit);
  const descriptor = detectFamily(filePath, buffer);
  const artifact = {
    id: filePath,
    path: filePath,
    name: path.basename(filePath),
    extension: extension || "",
    family: descriptor.family,
    familyLabel: COPY.families[descriptor.family],
    badge: descriptor.badge,
    size: stat.size,
    sizeLabel: formatBytes(stat.size),
    summary: "",
    highlights: [],
    suggestions: [],
    keywords: [],
    flagCandidates: [],
    actions: [],
    toolActions: [],
    embeddedPayloads: [],
  };

  let searchableText = "";

  if (artifact.family === "text" || artifact.family === "document") {
    searchableText = decodeBufferAsText(buffer);
  } else {
    searchableText = dedupeStrings(extractAsciiStrings(buffer, 4).concat(extractUnicodeStrings(buffer, 4))).join("\n");
  }

  const encodedSegments = findEncodedSegments(searchableText);
  const decodedSegments = decodeInterestingSegments(encodedSegments);
  const smartDecoded = artifact.family === "text" || artifact.family === "document" ? smartDecodeTextContent(buffer) : [];
  const directFlags = findFlagCandidates(searchableText, artifact.name);
  const decodedFlags = decodedSegments.flatMap((item) => findFlagCandidates(item.value, `${artifact.name} (${item.type})`));
  const smartFlags = smartDecoded.flatMap((item) => findFlagCandidates(item.value, `${artifact.name} (${item.label})`));
  artifact.flagCandidates = dedupeStrings([...directFlags, ...decodedFlags, ...smartFlags].map((item) => `${item.value}@@${item.source}`)).map((entry) => {
    const [value, source] = entry.split("@@");
    return { value, source };
  });

  const lowered = normalizeText(searchableText);
  let embeddedPayloads = detectEmbeddedPayloads(buffer, artifact.family === "image" ? 128 : 64).filter((item) => item.offset > 0);
  if ((artifact.family === "archive" && artifact.badge === "ZIP") || isOfficePackageExtension(extension) || artifact.badge === "APK") {
    embeddedPayloads = embeddedPayloads.filter((item) => item.id !== "zip");
  }
  artifact.embeddedPayloads = embeddedPayloads;
  const trafficSummary = artifact.family === "network" ? analyzeTrafficBuffer(buffer) : null;
  const pdfReport = artifact.badge === "PDF" ? analyzePdfBuffer(buffer) : null;
  let elfReport = null;
  let peReport = null;
  let apkReport = null;
  let imageRaster = null;
  let qrPayload = null;
  let barcodePayload = null;
  let wavInfo = null;
  let audioLSB = [];
  let audioSignal = null;
  if (artifact.family === "image") {
    try {
      imageRaster = decodeImageRaster(buffer);
      qrPayload = imageRaster ? detectQrPayload(buffer) : null;
      barcodePayload = imageRaster ? await detectBarcodePayload(filePath) : null;
    } catch (_error) {
      imageRaster = null;
      qrPayload = null;
      barcodePayload = null;
    }
  }
  if (artifact.family === "audio" && artifact.badge === "WAV") {
    try {
      wavInfo = parseWavBuffer(buffer);
      audioLSB = wavInfo ? collectAudioLSBCandidates(buffer, wavInfo) : [];
      audioSignal = wavInfo ? analyzeWavSignal(buffer, wavInfo, { maxSamples: MAX_AUDIO_PREVIEW_SAMPLES }) : null;
    } catch (_error) {
      wavInfo = null;
      audioLSB = [];
      audioSignal = null;
    }
  }
  if (artifact.family === "binary") {
    try {
      if (artifact.badge === "ELF" || extension === ".elf" || extension === ".so") {
        elfReport = parseElfBinary(buffer);
      } else if (artifact.badge === "PE" || [".exe", ".dll"].includes(extension)) {
        peReport = parsePeBinary(buffer);
      } else if (artifact.badge === "APK" || extension === ".apk") {
        apkReport = parseApkPackage(filePath);
      }
    } catch (_error) {
      elfReport = null;
      peReport = null;
      apkReport = null;
    }
  }

  if (artifact.family === "image") {
    artifact.summary = "\u56fe\u50cf\u7c7b\u9644\u4ef6\uff0c\u9002\u5408\u68c0\u67e5\u5143\u6570\u636e\u3001\u9690\u5199\u3001\u50cf\u7d20\u901a\u9053\u548c\u5c3e\u90e8\u9644\u52a0\u6570\u636e\u3002";
    const pngSize = readPngDimensions(buffer);
    if (imageRaster && !pngSize) {
      artifact.highlights.push(`${artifact.badge} ${imageRaster.width} x ${imageRaster.height}`);
    }
    if (pngSize) {
      artifact.highlights.push(`PNG ${pngSize.width} x ${pngSize.height}`);
      artifact.keywords.push("image", "png");
      artifact.actions.push({
        id: "extract-png-text",
        label: "\u63d0\u53d6 PNG \u6587\u672c\u5757",
      });
      artifact.actions.push({
        id: "extract-png-lsb",
        label: "\u63d0\u53d6 PNG \u4f4e\u4f4d\u5e73\u9762",
      });
      const textChunks = extractPngTextChunks(buffer);
      if (textChunks.length) {
        artifact.highlights.push(`PNG \u5185\u90e8\u6587\u672c\u5757 ${textChunks.length} \u6761\u3002`);
      }
      const bitCandidates = collectPngLSBCandidates(buffer);
      if (bitCandidates.length) {
        artifact.highlights.push(`PNG \u4f4e\u4f4d\u5e73\u9762\u547d\u4e2d ${bitCandidates.length} \u7ec4\u53ef\u8bfb\u7ebf\u7d22\u3002`);
      }
    }
    if (imageRaster) {
      artifact.actions.push({
        id: "extract-image-views",
        label: "\u5bfc\u51fa\u56fe\u50cf\u901a\u9053",
      });
    }
    if (embeddedPayloads.length) {
      artifact.highlights.push(`\u68c0\u6d4b\u5230 ${embeddedPayloads.length} \u4e2a\u9644\u52a0\u8d44\u6599\u5934\uff0c\u53ef\u80fd\u5b58\u5728\u5d4c\u5165\u6587\u4ef6\u3002`);
      artifact.keywords.push(...embeddedPayloads.map((item) => item.id));
      artifact.actions.push({
        id: "extract-appended-payloads",
        label: "\u63d0\u53d6\u9644\u52a0\u8d44\u6599",
      });
    }
    if (qrPayload) {
      artifact.highlights.push("\u68c0\u6d4b\u5230\u4e8c\u7ef4\u7801\u5185\u5bb9\u3002");
      artifact.keywords.push("qr", "code");
      artifact.actions.push({
        id: "extract-image-qr",
        label: "\u63d0\u53d6\u4e8c\u7ef4\u7801",
      });
      artifact.flagCandidates = dedupeStrings(
        artifact.flagCandidates.map((item) => `${item.value}@@${item.source}`).concat(findFlagCandidates(qrPayload, `${artifact.name} (QR)`).map((item) => `${item.value}@@${item.source}`)),
      ).map((entry) => {
        const [value, source] = entry.split("@@");
        return { value, source };
      });
    }
    if (barcodePayload && barcodePayload !== qrPayload) {
      artifact.highlights.push("\u68c0\u6d4b\u5230\u4e00\u7ef4\u6761\u7801\u5185\u5bb9\u3002");
      artifact.keywords.push("barcode", "code");
      artifact.actions.push({
        id: "extract-image-barcode",
        label: "\u63d0\u53d6\u6761\u7801",
      });
      artifact.flagCandidates = dedupeStrings(
        artifact.flagCandidates
          .map((item) => `${item.value}@@${item.source}`)
          .concat(findFlagCandidates(barcodePayload, `${artifact.name} (BARCODE)`).map((item) => `${item.value}@@${item.source}`)),
      ).map((entry) => {
        const [value, source] = entry.split("@@");
        return { value, source };
      });
    }
    if (lowered.includes("flag")) {
      artifact.highlights.push("\u56fe\u50cf strings \u91cc\u51fa\u73b0 flag \u5173\u952e\u5b57\u3002");
    }
    if (artifact.badge === "JPEG") {
      artifact.actions.push({
        id: "extract-image-metadata",
        label: "\u63d0\u53d6\u56fe\u50cf\u5143\u6570\u636e",
      });
      artifact.actions.push({
        id: "extract-jpeg-segments",
        label: "\u63d0\u53d6 JPEG \u6bb5",
      });
      const jpegSegments = parseJpegSegments(buffer);
      if (jpegSegments.length) {
        artifact.highlights.push(`JPEG \u6bb5 ${jpegSegments.length} \u4e2a\u3002`);
      }
      const xmpCount = jpegSegments.filter((item) => item.kind === "xmp").length;
      const commentCount = jpegSegments.filter((item) => item.kind === "comment").length;
      const photoshopCount = jpegSegments.filter((item) => item.kind === "photoshop").length;
      if (xmpCount) {
        artifact.highlights.push(`JPEG XMP \u7247\u6bb5 ${xmpCount} \u4e2a\u3002`);
      }
      if (commentCount) {
        artifact.highlights.push(`JPEG \u6ce8\u91ca\u6bb5 ${commentCount} \u4e2a\u3002`);
      }
      if (photoshopCount) {
        artifact.highlights.push(`JPEG Photoshop APP13 \u7247\u6bb5 ${photoshopCount} \u4e2a\u3002`);
      }
      try {
        const metadata = ExifParser.create(buffer).parse();
        const tagCount = Object.keys(metadata.tags || {}).length;
        if (tagCount) {
          artifact.highlights.push(`JPEG EXIF \u6807\u7b7e ${tagCount} \u6761\u3002`);
        }
      } catch (_error) {
        // ignore
      }
    }
    artifact.suggestions.push("\u67e5 EXIF/XMP/COM/APP \u6bb5\u3001\u901a\u9053\u9690\u5199\u3001LSB \u548c\u5c3e\u90e8\u9644\u52a0\u6587\u4ef6\u3002");
  } else if (artifact.family === "audio") {
    artifact.summary = "\u97f3\u9891\u7c7b\u9644\u4ef6\uff0c\u9002\u5408\u68c0\u67e5 RIFF \u5757\u3001\u5143\u6570\u636e\u3001strings\u3001PCM LSB \u548c\u53ef\u89c6\u5316\u8f68\u8ff9\u3002";
    artifact.keywords.push("audio");
    if (wavInfo) {
      artifact.highlights.push(
        `WAV ${wavInfo.channels}ch ${wavInfo.sampleRate}Hz ${wavInfo.bitsPerSample}bit ${wavInfo.durationSeconds.toFixed(2)}s`,
      );
      if (Object.keys(wavInfo.metadata).length) {
        artifact.highlights.push(`WAV \u5143\u6570\u636e ${Object.keys(wavInfo.metadata).length} \u6761\u3002`);
      }
      if (audioLSB.length) {
        artifact.highlights.push(`WAV LSB \u547d\u4e2d ${audioLSB.length} \u7ec4\u53ef\u8bfb\u7ebf\u7d22\u3002`);
      }
      if (audioSignal && audioSignal.activeSegments.length) {
        artifact.highlights.push(`\u97f3\u9891\u6d3b\u52a8\u6bb5 ${audioSignal.activeSegments.length} \u6bb5\u3002`);
      }
      if (audioSignal && audioSignal.dominantFrequencies.length) {
        artifact.highlights.push(
          `\u4e3b\u9891\u6bb5\u7ea6 ${audioSignal.dominantFrequencies.map((item) => `${Math.round(item.frequencyHz)}Hz`).join(" / ")}`,
        );
      }
      if (audioSignal && audioSignal.morseCandidates.length) {
        artifact.highlights.push(`\u68c0\u6d4b\u5230 Morse \u5019\u9009\uff1a${audioSignal.morseCandidates[0].text}`);
        artifact.keywords.push("morse", "tone");
        artifact.flagCandidates = dedupeStrings(
          artifact.flagCandidates
            .map((item) => `${item.value}@@${item.source}`)
            .concat(
              audioSignal.morseCandidates.flatMap((item) =>
                findFlagCandidates(item.text, `${artifact.name} (MORSE)`).map((flag) => `${flag.value}@@${flag.source}`),
              ),
            ),
        ).map((entry) => {
          const [value, source] = entry.split("@@");
          return { value, source };
        });
      }
      artifact.actions.push({
        id: "extract-audio-clues",
        label: "\u63d0\u53d6\u97f3\u9891\u7ebf\u7d22",
      });
      artifact.actions.push({
        id: "extract-audio-views",
        label: "\u5bfc\u51fa\u97f3\u9891\u89c6\u56fe",
      });
    }
    artifact.actions.push({
      id: "extract-strings",
      label: "\u5bfc\u51fa strings",
    });
    artifact.suggestions.push("\u5148\u770b fmt/data/LIST \u5757\uff0c\u518d\u62bd strings\u3001LSB\u3001\u4e3b\u9891\u6bb5\u548c\u9891\u8c31/\u6ce2\u5f62\u56fe\u3002");
  } else if (artifact.family === "network") {
    artifact.summary = "\u6d41\u91cf\u7c7b\u9644\u4ef6\uff0c\u4f18\u5148\u6309 HTTP\u3001DNS\u3001TLS \u548c TCP \u4f1a\u8bdd\u8fd8\u539f\u7ebf\u7d22\u3002";
    artifact.keywords.push("pcap", "traffic", "network");
    if (stat.size > sampleLimit) {
      artifact.highlights.push(`\u6d41\u91cf\u6587\u4ef6\u8f83\u5927\uff0c\u5f53\u524d\u5148\u5206\u6790\u524d ${formatBytes(sampleLimit)} \u5185\u5bb9\u3002`);
    }
    if (trafficSummary && trafficSummary.frameCount) {
      artifact.highlights.push(`\u5df2\u89e3\u6790 ${trafficSummary.frameCount} \u5e27\uff0c\u547d\u4e2d ${trafficSummary.sessionCount} \u4e2a\u4f1a\u8bdd\u3002`);
    }
    if (trafficSummary && trafficSummary.httpRequests.length) {
      artifact.highlights.push(`\u53d1\u73b0 HTTP \u8bf7\u6c42 ${trafficSummary.httpRequests.length} \u6761\u3002`);
      artifact.keywords.push("http", "web");
    }
    if (trafficSummary && trafficSummary.dnsQueries.length) {
      artifact.highlights.push(`\u53d1\u73b0 DNS \u57df\u540d ${trafficSummary.dnsQueries.length} \u6761\u3002`);
      artifact.keywords.push("dns");
    }
    if (trafficSummary && trafficSummary.tlsServerNames.length) {
      artifact.highlights.push(`TLS SNI \u57df\u540d ${trafficSummary.tlsServerNames.length} \u6761\u3002`);
      artifact.keywords.push("tls");
    }
    if (trafficSummary && (trafficSummary.cookies.length || trafficSummary.tokens.length)) {
      artifact.highlights.push("\u53d1\u73b0 Cookie / Token / Authorization \u7c7b\u4fe1\u606f\u3002");
      artifact.keywords.push("cookie", "session");
    }
    if (lowered.includes("http/1.") || lowered.includes("get /") || lowered.includes("post /") || lowered.includes("host:")) {
      artifact.highlights.push("\u53d1\u73b0 HTTP \u8bf7\u6c42\u6216 Host \u7ebf\u7d22\u3002");
      artifact.keywords.push("http", "web");
    }
    if (lowered.includes("cookie") || lowered.includes("authorization") || lowered.includes("token")) {
      artifact.highlights.push("\u53d1\u73b0 Cookie / Token / Authorization \u7c7b\u4fe1\u606f\u3002");
      artifact.keywords.push("cookie", "session");
    }
    if (lowered.includes("dns")) {
      artifact.highlights.push("\u53d1\u73b0 DNS \u5173\u952e\u5b57\u7ebf\u7d22\u3002");
    }
    artifact.suggestions.push("Wireshark \u53ef\u4f18\u5148\u8fc7\u6ee4 http\u3001dns\u3001tcp.stream\uff0c\u67e5\u5bf9\u8c61\u5bfc\u51fa\u548c\u4f1a\u8bdd\u91cd\u7ec4\u3002");
    artifact.actions.push({
      id: "extract-traffic-sessions",
      label: "\u63d0\u53d6\u6d41\u91cf\u4f1a\u8bdd",
    });
    artifact.actions.push({
      id: "extract-strings",
      label: "\u5bfc\u51fa strings",
    });
  } else if (artifact.family === "archive") {
    artifact.summary = "\u538b\u7f29\u5305\u7c7b\u9644\u4ef6\uff0c\u5e38\u89c1\u7ebf\u7d22\u662f\u5d4c\u5957\u6587\u4ef6\u3001\u8bc4\u8bba\u3001\u989d\u5916\u76ee\u5f55\u6216\u5bc6\u7801\u63d0\u793a\u3002";
    artifact.keywords.push("archive", "zip");
    if (artifact.badge === "GZIP") {
      artifact.highlights.push("GZIP \u538b\u7f29\u6d41\uff0c\u53ef\u76f4\u63a5\u89e3\u538b\u7ee7\u7eed\u9012\u5f52\u5206\u6790\u3002");
    }
    artifact.suggestions.push("\u89e3\u538b\u540e\u68c0\u67e5\u9690\u85cf\u76ee\u5f55\u3001\u6ce8\u91ca\u3001\u5d4c\u5957\u6587\u4ef6\u548c\u4e0e flag \u76f8\u5173\u7684\u6587\u4ef6\u540d\u3002");
    artifact.actions.push({
      id: "extract-archive",
      label: artifact.badge === "GZIP" ? "\u89e3\u538b GZIP" : "\u89e3\u5305 ZIP",
    });
  } else if (artifact.family === "binary") {
    artifact.summary = "\u4e8c\u8fdb\u5236\u7c7b\u9644\u4ef6\uff0c\u53ef\u4ece strings\u3001\u5bfc\u5165\u8868\u3001\u6821\u9a8c\u5b57\u7b26\u4e32\u548c\u63a7\u5236\u6d41\u5207\u5165\u3002";
    artifact.keywords.push("binary");
    const unicodeStrings = extractUnicodeStrings(buffer, 4, 120);
    if (artifact.badge === "APK" || extension === ".apk") {
      artifact.summary = "\u5b89\u5353 APK \u5305\uff0c\u53ef\u4ece Manifest\u3001DEX\u3001\u6743\u9650\u3001native lib \u548c\u5185\u5d4c\u8d44\u6e90\u5207\u5165\u3002";
      artifact.keywords.push("apk", "android", "mobile");
      artifact.highlights.push(`APK \u5305\u4f53\uff0c\u5305\u542b ${apkReport ? apkReport.entryCount : "?"} \u4e2a\u6587\u4ef6\u6761\u76ee\u3002`);
      if (apkReport && apkReport.dexEntries.length) {
        artifact.highlights.push(`DEX ${apkReport.dexEntries.length} \u4e2a\uff0c\u9002\u5408\u7ee7\u7eed\u5206\u6790 classes \u4e0e\u5b57\u7b26\u4e32\u6c60\u3002`);
      }
      if (apkReport && apkReport.dexMethods.length) {
        artifact.highlights.push(`DEX \u65b9\u6cd5\u7d22\u5f15 ${apkReport.dexMethods.length} \u6761\u3002`);
      }
      if (apkReport && apkReport.permissions.length) {
        artifact.highlights.push(`Manifest \u6743\u9650 ${apkReport.permissions.length} \u6761\u3002`);
      }
      if (apkReport && apkReport.resourceStrings.length) {
        artifact.highlights.push(`resources.arsc \u5b57\u7b26\u4e32 ${apkReport.resourceStrings.length} \u6761\u3002`);
      }
      if (apkReport && apkReport.nativeAbis.length) {
        artifact.highlights.push(`Native ABI\uff1a${apkReport.nativeAbis.join(" / ")}`);
      }
      if (apkReport && apkReport.packageNames.length) {
        artifact.highlights.push(`\u5305\u540d\u5019\u9009\uff1a${apkReport.packageNames[0]}`);
      }
      artifact.actions.push({
        id: "extract-apk-package",
        label: "\u62c6\u89e3 APK",
      });
      artifact.actions.push({
        id: "extract-strings",
        label: "\u5bfc\u51fa strings",
      });
      artifact.suggestions.push("\u5148\u770b AndroidManifest\u3001\u6743\u9650\u3001DEX \u5b57\u7b26\u4e32\u3001native lib \u548c assets \u8d44\u6e90\u3002");
    } else if (artifact.badge === "ELF" || extension === ".elf" || extension === ".so") {
      artifact.highlights.push("ELF \u4e8c\u8fdb\u5236\uff0c\u504f\u5411\u9006\u5411\u6216 pwn \u6d41\u7a0b\u3002");
      artifact.keywords.push("elf", "reverse");
      if (elfReport) {
        artifact.highlights.push(`${elfReport.format} ${elfReport.machine} ${elfReport.type} entry ${formatHex(elfReport.entry)}`);
        if (elfReport.interpreter) {
          artifact.highlights.push(`\u52a8\u6001\u88c5\u8f7d\u5668\uff1a${elfReport.interpreter}`);
        }
        if (elfReport.neededLibraries.length) {
          artifact.highlights.push(`\u4f9d\u8d56 so ${elfReport.neededLibraries.length} \u4e2a\u3002`);
        }
        if (elfReport.symbolTables.length || elfReport.relocations.length) {
          const symbolCount = elfReport.symbolTables.reduce((sum, table) => sum + table.count, 0);
          artifact.highlights.push(`ELF \u7b26\u53f7 ${symbolCount} \u4e2a\uff0c\u91cd\u5b9a\u4f4d\u6bb5 ${elfReport.relocations.length} \u4e2a\u3002`);
        }
      }
      artifact.actions.push({
        id: "extract-binary-clues",
        label: "\u63d0\u53d6 ELF / PE \u7ebf\u7d22",
      });
      artifact.actions.push({
        id: "extract-strings",
        label: "\u5bfc\u51fa strings",
      });
      artifact.suggestions.push("\u5148\u770b ELF \u5934\u3001.interp\u3001.dynamic\u3001\u4f9d\u8d56 so \u548c\u53ef\u7591 section\u3002");
    } else if (artifact.badge === "PE" || [".exe", ".dll"].includes(extension)) {
      artifact.highlights.push("PE \u4e8c\u8fdb\u5236\uff0c\u53ef\u4ece section\u3001imports \u548c\u5b50\u7cfb\u7edf\u5207\u5165\u3002");
      artifact.keywords.push("pe", "windows", "reverse");
      if (peReport) {
        artifact.highlights.push(`${peReport.format} ${peReport.machine} ${peReport.subsystem}`);
        if (peReport.importedLibraries.length) {
          artifact.highlights.push(`\u5bfc\u5165 DLL ${peReport.importedLibraries.length} \u4e2a\u3002`);
        }
        if (peReport.exportedFunctions.length) {
          artifact.highlights.push(`\u5bfc\u51fa\u7b26\u53f7 ${peReport.exportedFunctions.length} \u4e2a\u3002`);
        }
        if (peReport.dotNet) {
          artifact.highlights.push("\u68c0\u6d4b\u5230 .NET/CLI \u76ee\u5f55\u3002");
        }
      }
      artifact.actions.push({
        id: "extract-binary-clues",
        label: "\u63d0\u53d6 ELF / PE \u7ebf\u7d22",
      });
      artifact.actions.push({
        id: "extract-strings",
        label: "\u5bfc\u51fa strings",
      });
      artifact.suggestions.push("\u5148\u770b PE \u53ef\u9009\u5934\u3001section\u3001imports\u3001\u65f6\u95f4\u6233\u548c\u662f\u5426 .NET\u3002");
    }
    if (unicodeStrings.length) {
      artifact.highlights.push(`\u63d0\u53d6\u5230 ${unicodeStrings.length} \u6761 UTF-16 \u5b57\u7b26\u4e32\u3002`);
    }
    if (lowered.includes("glibc") || lowered.includes("malloc") || lowered.includes("free(") || lowered.includes("stack smashing")) {
      artifact.highlights.push("\u51fa\u73b0 libc \u6216\u5185\u5b58\u7ba1\u7406\u5173\u952e\u5b57\u3002");
      artifact.keywords.push("libc", "heap");
    }
    if (lowered.includes("flag") || lowered.includes("correct") || lowered.includes("wrong")) {
      artifact.highlights.push("strings \u91cc\u51fa\u73b0\u6821\u9a8c\u6216 flag \u76f8\u5173\u5b57\u7b26\u4e32\u3002");
    }
    if (!artifact.suggestions.length) {
      artifact.suggestions.push("\u5148 strings\uff0c\u518d\u67e5\u5bfc\u5165\u51fd\u6570\u3001\u6bd4\u8f83\u903b\u8f91\u548c flag \u751f\u6210\u8def\u5f84\u3002");
    }
    if (!artifact.actions.some((item) => item.id === "extract-strings")) {
      artifact.actions.push({
        id: "extract-strings",
        label: "\u5bfc\u51fa strings",
      });
    }
  } else if (artifact.family === "text") {
    artifact.summary = "\u6587\u672c\u7c7b\u9644\u4ef6\uff0c\u4f18\u5148\u68c0\u67e5 flag \u6837\u5f0f\u3001base64\u3001hex\u3001URL \u548c\u9690\u85cf\u63d0\u793a\u3002";
    artifact.keywords.push("text");
    if (encodedSegments.base64.length) {
      artifact.highlights.push(`\u53d1\u73b0 ${encodedSegments.base64.length} \u6bb5\u53ef\u7591 Base64 \u5185\u5bb9\u3002`);
      artifact.keywords.push("base64", "encoding");
    }
    if (encodedSegments.hex.length) {
      artifact.highlights.push(`\u53d1\u73b0 ${encodedSegments.hex.length} \u6bb5\u53ef\u7591 Hex \u5185\u5bb9\u3002`);
      artifact.keywords.push("hex", "encoding");
    }
    if (decodedSegments.length) {
      artifact.highlights.push("\u5df2\u4ece\u7f16\u7801\u6bb5\u4e2d\u8fd8\u539f\u51fa\u53ef\u8bfb\u5185\u5bb9\u3002");
      artifact.actions.push({
        id: "decode-encoded-text",
        label: "\u89e3\u7801 Base64 / Hex",
      });
    }
    if (
      smartDecoded.some((item) =>
        ["xor", "rot13", "caesar", "base32", "bitstream", "unicode-tags", "bacon", "brainfuck", "rot47", "atbash", "decimal-bytes", "hex-bytes"].includes(item.type),
      )
    ) {
      artifact.highlights.push("\u68c0\u6d4b\u5230\u53ef\u8fdb\u4e00\u6b65\u89e3\u7801\u7684\u6587\u672c\u9690\u5199\u6216\u7ecf\u5178\u7f16\u7801\u7ebf\u7d22\u3002");
      if (!artifact.actions.some((item) => item.id === "decode-encoded-text")) {
        artifact.actions.push({
          id: "decode-encoded-text",
          label: "\u89e3\u7801\u6587\u672c\u9690\u5199",
        });
      }
    }
    artifact.suggestions.push("\u5bf9\u6587\u672c\u4f18\u5148\u505a base/hex/XOR/ROT\u3001\u96f6\u5bbd/\u7a7a\u767d\u9690\u5199\u548c\u5206\u5757\u91cd\u7ec4\u3002");
  } else if (artifact.family === "document") {
    artifact.summary = "\u6587\u6863\u7c7b\u9644\u4ef6\uff0c\u9700\u8981\u68c0\u67e5\u5185\u5d4c\u6587\u672c\u3001\u5173\u952e\u5b57\u3001\u9644\u4ef6\u548c\u5143\u6570\u636e\u3002";
    if (artifact.badge === "PDF" && pdfReport) {
      const metadataCount = Object.keys(pdfReport.metadata || {}).length;
      if (metadataCount) {
        artifact.highlights.push(`PDF \u5143\u6570\u636e ${metadataCount} \u6761\u3002`);
      }
      if (pdfReport.urls.length) {
        artifact.highlights.push(`PDF URL ${pdfReport.urls.length} \u6761\u3002`);
      }
      if (pdfReport.xmpPackets.length) {
        artifact.highlights.push(`PDF XMP \u5305 ${pdfReport.xmpPackets.length} \u4e2a\u3002`);
      }
      if (pdfReport.extractedStreams.length) {
        artifact.highlights.push(`PDF \u53ef\u8bfb stream ${pdfReport.extractedStreams.length} \u4e2a\u3002`);
      }
      artifact.actions.push({
        id: "extract-pdf-content",
        label: "\u63d0\u53d6 PDF \u5185\u5bb9",
      });
      artifact.suggestions.push("\u62bd\u51fa PDF \u5143\u6570\u636e\u3001XMP\u3001Flate stream \u548c URL\uff0c\u68c0\u67e5\u662f\u5426\u9690\u85cf flag \u6216\u7ebf\u7d22\u3002");
    } else if (isOfficePackageExtension(extension)) {
      artifact.highlights.push("\u6587\u6863\u662f\u6253\u5305\u683c\u5f0f\uff0c\u53ef\u4ee5\u76f4\u63a5\u62c6\u51fa XML\u3001\u5a92\u4f53\u548c\u5d4c\u5165\u5bf9\u8c61\u3002");
      artifact.actions.push({
        id: "extract-document-package",
        label: "\u62c6\u6587\u6863\u5305",
      });
      artifact.suggestions.push("\u5148\u62c6\u51fa word/xl/ppt \u5185\u90e8 XML \u548c media \u76ee\u5f55\uff0c\u518d\u9012\u5f52\u5206\u6790\u3002");
    } else {
      artifact.suggestions.push("\u5c1d\u8bd5\u62bd\u51fa\u6587\u672c\u3001\u627e\u9690\u85cf\u9875\u9762/\u9644\u4ef6\uff0c\u5e76\u68c0\u67e5\u5143\u6570\u636e\u3002");
    }
  } else {
    artifact.summary = "\u672a\u660e\u786e\u5206\u7c7b\u7684\u9644\u4ef6\uff0c\u53ef\u5148\u62bd strings \u548c\u8bc6\u522b\u6587\u4ef6\u5934\u3001\u5c3e\u90e8\u6216\u5d4c\u5957\u5185\u5bb9\u3002";
    artifact.suggestions.push("\u5148\u770b\u6587\u4ef6\u5934\u5c3e\u548c strings\uff0c\u518d\u51b3\u5b9a\u8fdb\u4e00\u6b65\u5de5\u5177\u3002");
  }

  if (embeddedPayloads.length && artifact.family !== "image") {
    artifact.highlights.push(`\u53d1\u73b0 ${embeddedPayloads.length} \u4e2a\u53ef\u80fd\u7684\u9644\u52a0\u8d44\u6599\u5934\u3002`);
    artifact.suggestions.push("\u68c0\u67e5\u6587\u4ef6\u4e2d\u90e8/\u5c3e\u90e8\u662f\u5426\u5d4c\u5165 ZIP\u3001GZIP\u3001PNG \u6216 PDF\u3002");
    artifact.actions.push({
      id: "extract-appended-payloads",
      label: "\u63d0\u53d6\u9644\u52a0\u8d44\u6599",
    });
  }

  const urls = dedupeStrings(Array.from(searchableText.matchAll(/\bhttps?:\/\/[^\s"'<>]+/gi)).map((match) => match[0]).slice(0, 4));
  if (urls.length) {
    artifact.highlights.push(`\u53d1\u73b0 URL \u7ebf\u7d22 ${urls.length} \u6761\u3002`);
    artifact.keywords.push("http", "url");
  }

  artifact.actions.push({
    id: "run-builtin-toolbox",
    label: "内置工具箱扫描",
  });

  attachToolBackedActions(artifact);

  if (artifact.flagCandidates.length) {
    artifact.highlights.unshift(`\u53d1\u73b0 ${artifact.flagCandidates.length} \u4e2a flag \u5019\u9009\u3002`);
  }

  artifact.highlights = dedupeStrings(artifact.highlights).slice(0, 5);
  artifact.suggestions = dedupeStrings(artifact.suggestions).slice(0, 4);
  artifact.keywords = dedupeStrings(artifact.keywords);
  artifact.actions = dedupeStrings(artifact.actions.map((item) => `${item.id}@@${item.label}`)).map((item) => {
    const [id, label] = item.split("@@");
    return { id, label };
  });

  return artifact;
}

function createEmptyScores() {
  return {
    crypto: 0,
    web: 0,
    reverse: 0,
    pwn: 0,
    forensic: 0,
    misc: 0,
  };
}

function classifyChallenge(payload, artifacts) {
  const scores = createEmptyScores();
  const reasons = [];
  const textSource = [
    payload.title || "",
    payload.description || "",
    payload.notes || "",
    ...(payload.tags || []),
    ...artifacts.map((artifact) => `${artifact.name} ${artifact.summary} ${artifact.highlights.join(" ")} ${artifact.keywords.join(" ")}`),
  ]
    .join(" ")
    .toLowerCase();

  for (const [category, words] of Object.entries(CATEGORY_RULES)) {
    let hitCount = 0;
    for (const word of words) {
      if (textSource.includes(word)) {
        scores[category] += 1;
        hitCount += 1;
      }
    }
    if (hitCount) {
      reasons.push(`${COPY.categories[category]} \u547d\u4e2d ${hitCount} \u4e2a\u6587\u672c\u7ebf\u7d22`);
    }
  }

  for (const artifact of artifacts) {
    if (artifact.family === "network") {
      scores.forensic += 3;
      scores.web += 1;
    }
    if (artifact.family === "audio") {
      scores.misc += 2;
      scores.forensic += 1;
    }
    if (artifact.family === "image") {
      scores.misc += 2;
      scores.forensic += 1;
    }
    if (artifact.family === "archive") {
      scores.forensic += 1;
      scores.misc += 1;
    }
    if (artifact.family === "binary") {
      scores.reverse += 2;
      scores.pwn += artifact.badge === "ELF" ? 1 : 0;
    }
    if (artifact.family === "text" && artifact.keywords.includes("base64")) {
      scores.crypto += 1;
      scores.misc += 1;
    }
    if (artifact.flagCandidates.length && artifact.family === "text") {
      scores.misc += 1;
    }
  }

  const ranking = Object.entries(scores).sort((left, right) => right[1] - left[1]);
  const [category, bestScore] = ranking[0];
  const secondScore = ranking[1][1];
  const confidence = bestScore <= 0 ? 0.32 : Math.min(0.96, 0.48 + bestScore * 0.035 + (bestScore - secondScore) * 0.06);

  const evidence = dedupeStrings(reasons.concat(buildEvidenceFromArtifacts(artifacts))).slice(0, 6);

  return {
    id: category,
    label: COPY.categories[category],
    confidence,
    reason:
      evidence[0] ||
      "\u672a\u547d\u4e2d\u5f3a\u7279\u5f81\uff0c\u76ee\u524d\u4ee5\u9644\u4ef6\u5f62\u6001\u548c\u7ebf\u7d22\u5bc6\u5ea6\u505a\u4e3a\u521d\u59cb\u5224\u65ad\u3002",
    evidence,
    summary: COPY.summary[category],
    nextMoves: COPY.nextMoves[category],
    tools: COPY.tools[category],
  };
}

function buildEvidenceFromArtifacts(artifacts) {
  const evidence = [];
  const familyCount = artifacts.reduce((accumulator, artifact) => {
    accumulator[artifact.family] = (accumulator[artifact.family] || 0) + 1;
    return accumulator;
  }, {});

  for (const [family, count] of Object.entries(familyCount)) {
    evidence.push(`${COPY.families[family]} ${count} \u4e2a`);
  }

  artifacts.forEach((artifact) => {
    artifact.highlights.slice(0, 2).forEach((item) => {
      evidence.push(`${artifact.name}: ${item}`);
    });
  });

  return evidence;
}

function buildQuickFindings(artifacts, flagCandidates, pipelineLog) {
  const findings = [];

  if (flagCandidates.length) {
    findings.push(`\u5df2\u63d0\u53d6 ${flagCandidates.length} \u4e2a flag \u5019\u9009\uff0c\u53ef\u4f18\u5148\u4eba\u5de5\u9a8c\u8bc1\u3002`);
  }

  if (pipelineLog.length) {
    findings.push(`\u5df2\u81ea\u52a8\u751f\u6210 ${pipelineLog.length} \u4e2a\u884d\u751f\u7ed3\u679c\uff0c\u5e76\u5bf9\u5176\u4e2d\u7684\u6587\u4ef6\u7ee7\u7eed\u9012\u5f52\u5206\u6790\u3002`);
  }

  const families = artifacts.reduce((accumulator, artifact) => {
    accumulator[artifact.family] = (accumulator[artifact.family] || 0) + 1;
    return accumulator;
  }, {});

  if (families.network) {
    findings.push("\u68c0\u6d4b\u5230\u6d41\u91cf\u9644\u4ef6\uff0c\u5e94\u5f00\u542f HTTP/DNS/TCP \u4f1a\u8bdd\u89c6\u89d2\u3002");
  }
  if (families.image) {
    findings.push("\u68c0\u6d4b\u5230\u56fe\u50cf\u9644\u4ef6\uff0c\u5e94\u52a0\u5165 EXIF\u3001\u50cf\u7d20\u901a\u9053\u548c\u5c3e\u90e8\u9690\u85cf\u6570\u636e\u68c0\u67e5\u3002");
  }
  if (families.audio) {
    findings.push("\u68c0\u6d4b\u5230\u97f3\u9891\u9644\u4ef6\uff0c\u5e94\u68c0\u67e5 RIFF \u5757\u3001PCM LSB\u3001strings\u3001\u4e3b\u9891\u6bb5\u3001Morse \u5019\u9009\u548c\u9891\u8c31/\u6ce2\u5f62\u89c6\u56fe\u3002");
  }
  if (families.binary) {
    findings.push("\u68c0\u6d4b\u5230\u4e8c\u8fdb\u5236\u9644\u4ef6\uff0c\u5e94\u5148\u68c0\u67e5 ELF / PE \u5934\u3001sections\u3001imports \u6216 APK Manifest / DEX \u518d\u8fdb\u5165\u9006\u5411\u3002");
  }
  if (families.archive) {
    findings.push("\u68c0\u6d4b\u5230\u538b\u7f29\u5305\uff0c\u5efa\u8bae\u5c06\u5d4c\u5957\u5185\u5bb9\u4f5c\u4e3a\u65b0\u9898\u6e90\u7ee7\u7eed\u5206\u6790\u3002");
  }

  if (!findings.length) {
    findings.push("\u5148\u6dfb\u52a0\u9644\u4ef6\u6216\u8865\u5145\u66f4\u5177\u4f53\u7684\u63cf\u8ff0\uff0c\u518d\u8ba9\u5de5\u4f5c\u53f0\u7ed9\u51fa\u66f4\u7cbe\u786e\u7684\u5206\u6d41\u3002");
  }

  return findings;
}

function scoreFlagCandidate(candidate) {
  const value = String(candidate.value || "");
  const source = String(candidate.source || "");
  let score = 0.62;

  if (KNOWN_FLAG_PREFIX.test(value)) {
    score += 0.22;
  }
  if (/^(?:flag|ctf|picoctf)\{/i.test(value)) {
    score += 0.08;
  }
  if (/metadata|strings|lsb|png|jpeg|http|dns|ciphey|zsteg|binwalk|text|payload/i.test(source)) {
    score += 0.04;
  }
  if (value.length > 180 || /\s{2,}/.test(value)) {
    score -= 0.18;
  }

  return Math.max(0.25, Math.min(0.98, score));
}

function collectRelevantMissingTools(artifacts) {
  const byTool = new Map();
  artifacts.forEach((artifact) => {
    (artifact.toolActions || []).forEach((toolAction) => {
      if (toolAction.available) {
        return;
      }
      const key = toolAction.tool || toolAction.toolLabel;
      const current = byTool.get(key) || {
        tool: toolAction.tool,
        label: toolAction.toolLabel,
        purpose: toolAction.purpose,
        installHint: toolAction.installHint,
        homepage: toolAction.homepage,
        actions: [],
      };
      current.actions.push(toolAction.label);
      byTool.set(key, current);
    });
  });

  return Array.from(byTool.values()).map((item) => ({
    ...item,
    actions: dedupeStrings(item.actions).slice(0, 4),
  }));
}

function getBundledToolStatus() {
  return BUNDLED_TOOL_CAPABILITIES.map((tool) => ({
    ...tool,
    available: true,
    source: "bundled",
  }));
}

function buildFailureGuide(error, action, artifact) {
  const actionId = String(action?.id || "");
  const message = error?.message || String(error || "");
  const guide = {
    title: "检查输入和依赖",
    reason: message,
    steps: [
      "确认附件没有损坏，并重新运行一次自动求解。",
      "如果题目给过密码、key、hint 或 flag 格式，把它们补充到题面/备注后重跑。",
    ],
    fallback: "保留原始附件，先查看内置工具箱报告和 strings 输出，再决定是否手动介入。",
  };

  if (actionId === "extract-archive") {
    guide.title = "压缩包未能自动解包";
    guide.steps = [
      "确认压缩包是否加密；如果题目给过密码，把密码写入备注后重新分析。",
      "检查是否是 RAR/7Z/TAR 等当前内置解包不支持的格式；这类文件可选使用 7-Zip 或 binwalk 复核。",
      "如果是嵌套压缩包，先确认第一层是否成功提取，再从生成文件继续分析。",
    ];
    guide.fallback = "内置解包覆盖 ZIP/GZIP；复杂压缩格式建议用 7-Zip、binwalk 或手动指定密码处理。";
  } else if (actionId === "decode-encoded-text") {
    guide.title = "文本没有可直接还原的编码层";
    guide.steps = [
      "检查文本是否需要密钥、移位量、字典或题目 hint，而不是纯 Base64/Hex/ROT/XOR。",
      "尝试把可疑片段单独放进文本附件再运行，减少噪声。",
      "如果像古典密码或多层弱加密，安装 Ciphey 后重跑可获得更深的自动尝试。",
    ];
    guide.fallback = "内置 ciphey-lite 已覆盖常见编码、文本隐写和单字节 XOR；未知密钥类密码仍需要题目线索。";
  } else if (actionId === "extract-png-lsb") {
    guide.title = "PNG 低位平面未命中";
    guide.steps = [
      "确认图片是否被二次压缩或转换；优先使用题目原始 PNG。",
      "检查是否需要特定通道、位序、坐标顺序或密码；这些通常来自题目标题/描述/hint。",
      "安装 zsteg 后重跑，用完整 LSB 组合暴力扫描补充内置 zsteg-lite。",
    ];
    guide.fallback = "内置 zsteg-lite 只跑常见 RGB/RGBA 低位可读文本，深度隐写仍建议 zsteg/stegsolve。";
  } else if (actionId === "extract-png-text") {
    guide.title = "PNG 文本块为空";
    guide.steps = [
      "这通常表示没有 tEXt/zTXt/iTXt 文本块，不代表图片没有隐藏信息。",
      "继续查看内置工具箱报告中的低位平面、尾部附加数据和 strings 结果。",
      "如果题目提示 metadata/comment，确认是否拿到了原始 PNG，而不是平台预览图或截图。",
    ];
    guide.fallback = "PNG 文本块只是隐写入口之一；没有文本块时应转向 LSB、调色板、像素通道或附加文件。";
  } else if (actionId === "extract-image-qr" || actionId === "extract-image-barcode") {
    guide.title = "图码识别失败";
    guide.steps = [
      "尝试裁剪、旋转、提高对比度或恢复原图分辨率后重新导入。",
      "如果图码被遮挡或需要先做通道分离，先运行/查看图像通道导出结果。",
      "检查图片尾部是否有附加数据，真正的 flag 可能不在可见图码中。",
    ];
    guide.fallback = "内置识别适合清晰 QR/条码；严重变形图码需要人工预处理。";
  } else if (actionId === "extract-traffic-sessions" || actionId.startsWith("tool:tshark")) {
    guide.title = "流量解析不完整";
    guide.steps = [
      "确认文件是 pcap/pcapng，且没有被截断或二次压缩。",
      "优先查看 HTTP、DNS、TLS SNI、Cookie/Token；若内置摘要为空，安装 Wireshark/TShark 后重跑。",
      "如果题目是分片/非标准协议，需要按端口或 TCP stream 手动还原。",
    ];
    guide.fallback = "内置 tshark-lite 只覆盖常见 HTTP/DNS/TLS 线索，深度协议分析建议 TShark/Wireshark。";
  } else if (actionId.startsWith("tool:")) {
    const tool = action?.tool || actionId.split(":")[1] || "外部工具";
    guide.title = `${tool} 未能执行`;
    guide.steps = [
      "确认工具已经安装并加入 PATH，然后重新打开应用或重新运行分析。",
      "如果工具对 Windows 支持不稳定，优先使用 WSL/Kali 中的同名工具处理该附件。",
      "查看内置工具箱报告；大多数基础 strings、签名扫描、编码解码和 PNG LSB 已有内置替代。",
    ];
    guide.fallback = "外部工具只是增强项，缺失时应用会继续使用内置轻量适配器。";
  } else if (actionId === "run-builtin-toolbox") {
    guide.title = "内置工具箱扫描失败";
    guide.steps = [
      "确认文件可读取且未被其他程序锁定。",
      "如果文件非常大，先截取题目相关附件或按目录分批导入。",
      "保留原文件，手动运行对应外部工具验证是否存在损坏或格式异常。",
    ];
    guide.fallback = "内置工具箱不会修改原文件，失败通常与文件读取、格式异常或超大附件有关。";
  }

  return {
    ...guide,
    actionId,
    actionLabel: action?.label || actionId,
    sourceName: artifact?.name || "",
    sourcePath: artifact?.path || "",
  };
}

function buildSolverResult(artifacts, flagCandidates, pipelineLog, pipelineErrors, toolStatus) {
  const byValue = new Map();
  flagCandidates.forEach((candidate) => {
    const value = String(candidate.value || "");
    if (!value) {
      return;
    }
    const scored = {
      ...candidate,
      score: scoreFlagCandidate(candidate),
      sources: [candidate.source].filter(Boolean),
    };
    const existing = byValue.get(value);
    if (!existing || scored.score > existing.score) {
      byValue.set(value, {
        ...scored,
        sources: dedupeStrings([...(existing?.sources || []), ...scored.sources]),
      });
      return;
    }
    existing.sources = dedupeStrings([...(existing.sources || []), ...scored.sources]);
  });
  const rankedCandidates = Array.from(byValue.values())
    .map((candidate) => ({
      ...candidate,
      source: candidate.sources?.length ? candidate.sources.join(" / ") : candidate.source,
    }))
    .sort((left, right) => right.score - left.score);
  const primaryFlag = rankedCandidates[0] || null;
  const missingTools = collectRelevantMissingTools(artifacts);
  const failedActions = (pipelineErrors || []).slice(0, 5);
  const installedToolCount = (toolStatus?.installed || []).length;
  const nextActions = [];

  if (primaryFlag) {
    nextActions.push("验证候选 flag 的来源文件和格式，确认是否可直接提交。");
    if (rankedCandidates.length > 1) {
      nextActions.push("存在多个候选值时，优先选择格式更完整、来源更直接的结果。");
    }
    return {
      status: "solved",
      title: "已找到 flag 候选",
      summary: `自动流水线找到了 ${rankedCandidates.length} 个候选值，优先结果来自：${primaryFlag.source}。`,
      primaryFlag,
      candidates: rankedCandidates,
      confidence: primaryFlag.score,
      actionsRun: pipelineLog.length,
      artifactCount: artifacts.length,
      missingTools: [],
      failedActions: [],
      nextActions,
    };
  }

  if (missingTools.length) {
    nextActions.push(`安装或加入 PATH：${missingTools.slice(0, 5).map((item) => item.label).join(" / ")}，然后重新运行自动求解。`);
  }
  if (failedActions.length) {
    nextActions.push("检查失败的自动动作输出，优先处理超时、缺依赖、加密压缩包或损坏附件。");
  }
  nextActions.push("补充原始附件、压缩包密码、题目提示或已知 flag 格式后重跑。");

  const status = pipelineLog.length || installedToolCount ? "partial" : "blocked";
  return {
    status,
    title: status === "partial" ? "已自动处理，暂未命中 flag" : "缺少可继续自动化的输入",
    summary:
      status === "partial"
        ? `已执行 ${pipelineLog.length} 个本地动作并递归扫描 ${artifacts.length} 个文件，但没有抽取到可提交 flag。`
        : "当前输入不足或缺少必要工具，暂时无法继续自动求解。",
    primaryFlag: null,
    candidates: [],
    confidence: status === "partial" ? 0.46 : 0.28,
    actionsRun: pipelineLog.length,
    artifactCount: artifacts.length,
    missingTools,
    failedActions,
    nextActions,
  };
}

function collectPaths(entries, maxFiles = MAX_FILES) {
  const unique = new Set();
  const files = [];
  let truncated = false;

  function walk(entryPath) {
    if (files.length >= maxFiles) {
      truncated = true;
      return;
    }
    if (!entryPath || unique.has(entryPath) || !fs.existsSync(entryPath)) {
      return;
    }
    unique.add(entryPath);

    const stat = fs.statSync(entryPath);
    if (stat.isDirectory()) {
      for (const child of fs.readdirSync(entryPath)) {
        walk(path.join(entryPath, child));
        if (files.length >= maxFiles) {
          truncated = true;
          break;
        }
      }
      return;
    }

    files.push(entryPath);
  }

  entries.forEach((entry) => walk(entry));
  return { files, truncated };
}

function prepareArtifactsFromEntries(entries) {
  const collection = collectPaths(entries);
  return collection.files.map((filePath) => {
    const stat = fs.statSync(filePath);
    const descriptor = detectFamily(filePath, readSample(filePath, Math.min(MAX_SAMPLE_BYTES, 64 * 1024)).buffer);
    return {
      id: filePath,
      path: filePath,
      name: path.basename(filePath),
      family: descriptor.family,
      familyLabel: COPY.families[descriptor.family],
      badge: descriptor.badge,
      sizeLabel: formatBytes(stat.size),
    };
  });
}

function ensureOutputRoot(outputRoot) {
  fs.mkdirSync(outputRoot, { recursive: true });
}

function writeGeneratedFile(outputRoot, fileName, content) {
  ensureOutputRoot(outputRoot);
  const finalPath = path.join(outputRoot, fileName);
  fs.writeFileSync(finalPath, content);
  return finalPath;
}

function buildGeneratedDescriptor(filePath) {
  const stat = fs.statSync(filePath);
  const descriptor = detectFamily(filePath, readSample(filePath, Math.min(MAX_SAMPLE_BYTES, 64 * 1024)).buffer);
  return {
    path: filePath,
    name: path.basename(filePath),
    family: descriptor.family,
    familyLabel: COPY.families[descriptor.family],
    badge: descriptor.badge,
    sizeLabel: formatBytes(stat.size),
    sourceKind: "generated",
  };
}

function createActionOutputRoot(outputRoot, filePath, actionId) {
  return path.join(outputRoot, `${sanitizeSegment(path.parse(filePath).name)}-${shortHash(filePath)}-${sanitizeSegment(actionId)}`);
}

function extractAppendedZip(filePath, outputRoot) {
  const buffer = fs.readFileSync(filePath);
  const offset = markerAfterOffset(buffer, Buffer.from([0x50, 0x4b, 0x03, 0x04]), 128);
  if (offset === -1) {
    throw new Error("\u6ca1\u6709\u627e\u5230\u53ef\u63d0\u53d6\u7684 ZIP \u5934\u3002");
  }

  const generatedName = `${sanitizeSegment(path.parse(filePath).name)}-embedded.zip`;
  const outPath = writeGeneratedFile(outputRoot, generatedName, buffer.subarray(offset));
  return {
    message: "\u5df2\u4ece\u56fe\u50cf\u5c3e\u90e8\u63d0\u53d6 ZIP \u9644\u52a0\u6570\u636e\u3002",
    createdFiles: [outPath],
  };
}

function extractAppendedPayloads(filePath, outputRoot) {
  const buffer = fs.readFileSync(filePath);
  const payloads = detectEmbeddedPayloads(buffer, 64).filter((item) => item.offset > 0);
  if (!payloads.length) {
    throw new Error("\u6ca1\u6709\u627e\u5230\u53ef\u63d0\u53d6\u7684\u9644\u52a0\u8d44\u6599\u5934\u3002");
  }

  ensureOutputRoot(outputRoot);
  const createdFiles = [];

  payloads.forEach((payload, index) => {
    const generatedName = `${index + 1}-${payload.id}${payload.ext}`;
    const outPath = writeGeneratedFile(outputRoot, generatedName, buffer.subarray(payload.offset));
    createdFiles.push(outPath);
  });

  return {
    message: "\u5df2\u63d0\u53d6\u9644\u52a0\u8d44\u6599\u5e76\u7ee7\u7eed\u7eb3\u5165\u5206\u6790\u3002",
    createdFiles,
  };
}

function extractZipEntries(zip, outputRoot) {
  ensureOutputRoot(outputRoot);
  const entries = zip.getEntries().filter((entry) => !entry.isDirectory);
  if (!entries.length) {
    return [];
  }

  let totalBytes = 0;
  const createdFiles = [];

  for (const entry of entries.slice(0, MAX_ARCHIVE_ENTRIES)) {
    totalBytes += entry.header.size || 0;
    if (totalBytes > MAX_ARCHIVE_TOTAL_BYTES) {
      break;
    }

    const relativePath = safeArchivePath(entry.entryName);
    if (!relativePath) {
      continue;
    }
    const finalPath = path.join(outputRoot, relativePath);
    ensureOutputRoot(path.dirname(finalPath));
    fs.writeFileSync(finalPath, entry.getData());
    createdFiles.push(finalPath);
  }

  return createdFiles;
}

function extractArchive(filePath, outputRoot) {
  const sample = readSample(filePath, 16).buffer;
  if (detectMagic(sample) === "gzip" || path.extname(filePath).toLowerCase() === ".gz") {
    const buffer = fs.readFileSync(filePath);
    const inflated = zlib.gunzipSync(buffer, { maxOutputLength: MAX_ARCHIVE_TOTAL_BYTES });
    const parsed = path.parse(filePath);
    let generatedName = sanitizeSegment(parsed.name) || `${sanitizeSegment(parsed.base)}-inflated`;
    if (!path.extname(generatedName)) {
      generatedName = `${generatedName}.bin`;
    }
    const outPath = writeGeneratedFile(outputRoot, generatedName, inflated);
    return {
      message: "\u5df2\u89e3\u538b GZIP \u5e76\u7ee7\u7eed\u7eb3\u5165\u5206\u6790\u3002",
      createdFiles: [outPath],
    };
  }

  const zip = new AdmZip(filePath);
  const createdFiles = extractZipEntries(zip, outputRoot);
  if (!createdFiles.length) {
    throw new Error("\u538b\u7f29\u5305\u4e2d\u6ca1\u6709\u53ef\u63d0\u53d6\u7684\u6587\u4ef6\u3002");
  }

  return {
    message: "\u5df2\u89e3\u5305 ZIP \u5e76\u5c06\u5185\u5bb9\u7eb3\u5165\u7ee7\u7eed\u5206\u6790\u3002",
    createdFiles,
  };
}

function extractBinaryClues(filePath, outputRoot) {
  const buffer = fs.readFileSync(filePath);
  const baseName = sanitizeSegment(path.parse(filePath).name);
  const createdFiles = [];

  const elfReport = parseElfBinary(buffer);
  if (elfReport) {
    createdFiles.push(writeGeneratedFile(outputRoot, `${baseName}-elf-summary.txt`, buildElfSummaryText(path.basename(filePath), elfReport)));
    if (elfReport.neededLibraries.length) {
      createdFiles.push(writeGeneratedFile(outputRoot, `${baseName}-elf-needed.txt`, `${elfReport.neededLibraries.join("\n")}\n`));
    }
    if (elfReport.commentPreview.length) {
      createdFiles.push(writeGeneratedFile(outputRoot, `${baseName}-elf-comment.txt`, `${elfReport.commentPreview.join("\n")}\n`));
    }
    if (elfReport.symbolTables.length) {
      const symbolLines = [];
      elfReport.symbolTables.forEach((table) => {
        symbolLines.push(`# ${table.name} (${table.count})`);
        dedupeStrings([...table.functions, ...table.globals, ...table.objects]).forEach((item) => symbolLines.push(item));
        symbolLines.push("");
      });
      createdFiles.push(writeGeneratedFile(outputRoot, `${baseName}-elf-symbols.txt`, `${symbolLines.join("\n")}\n`));
    }
    if (elfReport.relocations.length) {
      const relocationLines = [];
      elfReport.relocations.forEach((entry) => {
        relocationLines.push(`# ${entry.name} -> ${entry.target || "?"} (${entry.count})`);
        entry.symbols.forEach((item) => relocationLines.push(item));
        relocationLines.push("");
      });
      createdFiles.push(writeGeneratedFile(outputRoot, `${baseName}-elf-relocations.txt`, `${relocationLines.join("\n")}\n`));
    }
    return {
      message: "\u5df2\u63d0\u53d6 ELF \u5934\u3001section\u3001\u52a8\u6001\u4f9d\u8d56\u3001\u7b26\u53f7\u4e0e\u91cd\u5b9a\u4f4d\u7ebf\u7d22\u3002",
      createdFiles: dedupeStrings(createdFiles),
    };
  }

  const peReport = parsePeBinary(buffer);
  if (peReport) {
    createdFiles.push(writeGeneratedFile(outputRoot, `${baseName}-pe-summary.txt`, buildPeSummaryText(path.basename(filePath), peReport)));
    if (peReport.importedFunctions.length) {
      createdFiles.push(writeGeneratedFile(outputRoot, `${baseName}-pe-imports.txt`, `${peReport.importedFunctions.join("\n")}\n`));
    }
    if (peReport.exportedFunctions.length) {
      createdFiles.push(writeGeneratedFile(outputRoot, `${baseName}-pe-exports.txt`, `${peReport.exportedFunctions.join("\n")}\n`));
    }
    return {
      message: "\u5df2\u63d0\u53d6 PE \u53ef\u9009\u5934\u3001section\u3001imports\u3001exports \u548c\u5b50\u7cfb\u7edf\u7ebf\u7d22\u3002",
      createdFiles: dedupeStrings(createdFiles),
    };
  }

  throw new Error("\u76ee\u524d\u53ea\u652f\u6301 ELF / PE \u7ed3\u6784\u5316\u7ebf\u7d22\u63d0\u53d6\u3002");
}

function extractApkPackage(filePath, outputRoot) {
  const report = parseApkPackage(filePath);
  if (!report) {
    throw new Error("\u6ca1\u6709\u89e3\u6790\u5230\u53ef\u7528\u7684 APK \u5185\u5bb9\u3002");
  }

  ensureOutputRoot(outputRoot);
  const baseName = sanitizeSegment(path.parse(filePath).name);
  const zip = new AdmZip(filePath);
  const createdFiles = [];
  createdFiles.push(writeGeneratedFile(outputRoot, `${baseName}-apk-summary.txt`, buildApkSummaryText(path.basename(filePath), report)));
  if (report.manifestStrings.length) {
    createdFiles.push(writeGeneratedFile(outputRoot, `${baseName}-manifest-strings.txt`, `${report.manifestStrings.join("\n")}\n`));
  }
  if (report.dexStrings.length) {
    createdFiles.push(writeGeneratedFile(outputRoot, `${baseName}-dex-strings.txt`, `${report.dexStrings.join("\n")}\n`));
  }
  if (report.dexMethods.length) {
    createdFiles.push(writeGeneratedFile(outputRoot, `${baseName}-dex-methods.txt`, `${report.dexMethods.join("\n")}\n`));
  }
  if (report.resourceStrings.length) {
    createdFiles.push(writeGeneratedFile(outputRoot, `${baseName}-resources-strings.txt`, `${report.resourceStrings.join("\n")}\n`));
  }
  extractZipEntries(zip, outputRoot).forEach((item) => createdFiles.push(item));

  return {
    message: "\u5df2\u62c6\u89e3 APK\uff0c\u5bfc\u51fa Manifest / resources / DEX \u7ebf\u7d22\u5e76\u7ee7\u7eed\u9012\u5f52\u5206\u6790\u3002",
    createdFiles: dedupeStrings(createdFiles),
  };
}

function decodeEncodedText(filePath, outputRoot) {
  const buffer = fs.readFileSync(filePath);
  const decoded = smartDecodeTextContent(buffer);

  if (!decoded.length) {
    throw new Error("\u6ca1\u6709\u627e\u5230\u53ef\u76f4\u63a5\u89e3\u7801\u7684 Base/Hex/XOR/ROT/\u96f6\u5bbd/\u7a7a\u767d/Bacon/Brainfuck \u7ebf\u7d22\u3002");
  }

  const sections = decoded.map((item, index) => {
    return `# ${item.label || item.type.toUpperCase()} ${index + 1}\n${item.value}\n`;
  });
  const generatedName = `${sanitizeSegment(path.parse(filePath).name)}-decoded.txt`;
  const outPath = writeGeneratedFile(outputRoot, generatedName, sections.join("\n"));
  return {
    message: "\u5df2\u5c06\u89e3\u7801\u5185\u5bb9\u8f93\u51fa\u4e3a\u6587\u672c\u6587\u4ef6\u3002",
    createdFiles: [outPath],
  };
}

function exportStrings(filePath, outputRoot) {
  const buffer = fs.readFileSync(filePath);
  const asciiStrings = extractAsciiStrings(buffer, 4, 10000);
  const unicodeStrings = extractUnicodeStrings(buffer, 4, 4000);
  if (!asciiStrings.length && !unicodeStrings.length) {
    throw new Error("\u6ca1\u6709\u63d0\u53d6\u5230\u53ef\u7528 strings\u3002");
  }

  const sections = [];
  if (asciiStrings.length) {
    sections.push("# ASCII", ...asciiStrings, "");
  }
  if (unicodeStrings.length) {
    sections.push("# UTF16-LE", ...unicodeStrings, "");
  }

  const generatedName = `${sanitizeSegment(path.parse(filePath).name)}-strings.txt`;
  const outPath = writeGeneratedFile(outputRoot, generatedName, `${sections.join("\n")}\n`);
  return {
    message: "\u5df2\u5bfc\u51fa ASCII / UTF-16 strings \u7ed3\u679c\u3002",
    createdFiles: [outPath],
  };
}

function formatOffset(offset) {
  return `0x${Number(offset || 0).toString(16).padStart(8, "0")}`;
}

function appendReportSection(lines, title, entries, emptyText) {
  lines.push(`## ${title}`);
  if (!entries.length) {
    lines.push(emptyText || "(none)", "");
    return;
  }
  entries.forEach((entry) => lines.push(entry));
  lines.push("");
}

function buildBuiltinToolboxReport(filePath) {
  const stat = fs.statSync(filePath);
  const maxBytes = Math.min(stat.size, Math.max(MAX_TRAFFIC_BYTES, MAX_ARCHIVE_TOTAL_BYTES));
  const buffer = readSample(filePath, maxBytes).buffer;
  const descriptor = detectFamily(filePath, buffer);
  const fileName = path.basename(filePath);
  const text = descriptor.family === "text" || descriptor.family === "document" ? decodeBufferAsText(buffer) : extractAsciiStrings(buffer, 4, 5000).join("\n");
  const lines = [
    "# BUILTIN TOOLBOX REPORT",
    `file: ${fileName}`,
    `size: ${formatBytes(stat.size)}`,
    `family: ${COPY.families[descriptor.family] || descriptor.family}`,
    `badge: ${descriptor.badge}`,
    `scanBytes: ${formatBytes(buffer.length)}`,
    "",
    "本报告由打包内置能力生成，不依赖外部 PATH 工具。",
    "",
  ];

  appendReportSection(
    lines,
    "bundled adapters",
    BUNDLED_TOOL_CAPABILITIES.map((tool) => `- ${tool.label}: ${tool.replaces} | ${tool.purpose}`),
  );

  const signatureHits = scanEmbeddedSignatures(buffer, 0, 60).map((item) => {
    const note = item.offset > 0 ? "embedded/appended candidate" : "file header";
    return `- ${formatOffset(item.offset)} ${item.label}${item.ext} (${note})`;
  });
  appendReportSection(lines, "binwalk-lite signature scan", signatureHits, "未发现可识别的嵌入文件头。");

  const asciiStrings = extractAsciiStrings(buffer, 5, 500);
  const unicodeStrings = extractUnicodeStrings(buffer, 5, 200);
  const suspiciousStrings = dedupeStrings(
    asciiStrings
      .concat(unicodeStrings)
      .filter((value) => /flag|ctf|key|secret|password|token|cookie|http|zip|base64|xor|admin|login/i.test(value))
      .slice(0, 80),
  );
  appendReportSection(lines, "strings-lite suspicious strings", suspiciousStrings.map((item) => `- ${item}`), "未发现明显可疑字符串。");

  const directFlags = findFlagCandidates(text, `${fileName} (built-in strings)`);
  appendReportSection(lines, "flag hits", directFlags.map((item) => `- ${item.value} (${item.source})`), "未直接命中 flag 样式。");

  const decoded = smartDecodeTextContent(Buffer.from(text, "utf8"));
  appendReportSection(
    lines,
    "ciphey-lite decode attempts",
    decoded.slice(0, 12).map((item) => `- ${item.label}: ${String(item.value).slice(0, 500)}`),
    "未发现可直接自动还原的编码层。",
  );

  if (descriptor.badge === "PNG") {
    const pngText = extractPngTextChunks(buffer);
    appendReportSection(lines, "zsteg-lite PNG text chunks", pngText.map((item) => `- ${item}`), "未发现 PNG 文本块。");
    const lsb = collectPngLSBCandidates(buffer);
    const lsbLines = lsb.slice(0, 12).flatMap((item) => {
      const header = `- ${item.traversal.toUpperCase()} ${item.channel} bit${item.bitPlane} ${item.bitOrder.toUpperCase()}`;
      return [header, ...item.printable.slice(0, 4).map((entry) => `  ${entry}`), ...item.flags.map((entry) => `  ${entry.value}`)];
    });
    appendReportSection(lines, "zsteg-lite PNG LSB", lsbLines, "未发现常见低位平面可读文本。");
  }

  if (descriptor.family === "network") {
    try {
      const traffic = analyzeTrafficBuffer(buffer);
      const trafficLines = [
        `- frames: ${traffic.frameCount}`,
        `- http requests: ${traffic.httpRequests.length}`,
        `- dns queries: ${traffic.dnsQueries.length}`,
        `- tls sni: ${traffic.tlsServerNames.length}`,
        ...traffic.httpRequests.slice(0, 12).map((item) => `- HTTP ${item.method || ""} ${item.host || ""}${item.uri || ""}`.trim()),
        ...traffic.dnsQueries.slice(0, 12).map((item) => `- DNS ${item.name || ""} ${item.answer || ""}`.trim()),
      ];
      appendReportSection(lines, "tshark-lite traffic summary", trafficLines, "未解析到流量摘要。");
    } catch (error) {
      appendReportSection(lines, "tshark-lite traffic summary", [`- parse failed: ${error.message}`]);
    }
  }

  if (descriptor.badge === "PDF") {
    const report = analyzePdfBuffer(buffer);
    appendReportSection(
      lines,
      "exif-lite PDF",
      [
        `- metadata: ${report.metadata.length}`,
        `- urls: ${report.urls.length}`,
        `- xmp packets: ${report.xmpPackets.length}`,
        `- readable streams: ${report.extractedStreams.length}`,
        ...report.metadata.slice(0, 20).map((item) => `- ${item}`),
        ...report.urls.slice(0, 12).map((item) => `- ${item}`),
      ],
    );
  }

  if (descriptor.badge === "JPEG") {
    const segments = parseJpegSegments(buffer);
    appendReportSection(
      lines,
      "exif-lite JPEG",
      [
        `- segments: ${segments.length}`,
        `- comments: ${segments.filter((item) => item.kind === "comment").length}`,
        `- xmp: ${segments.filter((item) => item.kind === "xmp").length}`,
        ...extractJpegComments(buffer).slice(0, 20).map((item) => `- ${item}`),
      ],
    );
  }

  const elfReport = descriptor.badge === "ELF" ? parseElfBinary(buffer) : null;
  if (elfReport) {
    const elfSymbols = dedupeStrings(elfReport.symbolTables.flatMap((table) => [...table.functions, ...table.globals, ...table.objects])).slice(0, 80);
    appendReportSection(
      lines,
      "rabin2-lite ELF",
      [
        `- machine: ${elfReport.machine}`,
        `- entry: ${formatHex(elfReport.entry)}`,
        `- sections: ${elfReport.sections.length}`,
        `- symbols: ${elfSymbols.length}`,
        ...elfReport.neededLibraries.map((item) => `- needed: ${item}`),
        ...elfSymbols.slice(0, 40).map((item) => `- symbol: ${item}`),
      ],
    );
  }

  const peReport = descriptor.badge === "PE" ? parsePeBinary(buffer) : null;
  if (peReport) {
    appendReportSection(
      lines,
      "rabin2-lite PE",
      [
        `- machine: ${peReport.machine}`,
        `- subsystem: ${peReport.subsystem}`,
        `- sections: ${peReport.sections.length}`,
        `- imports: ${peReport.importedFunctions.length}`,
        ...peReport.importedFunctions.slice(0, 40).map((item) => `- import: ${item}`),
      ],
    );
  }

  return `${lines.join("\n")}\n`;
}

function runBuiltinToolbox(filePath, outputRoot) {
  const report = buildBuiltinToolboxReport(filePath);
  const outPath = writeGeneratedFile(outputRoot, `${sanitizeSegment(path.parse(filePath).name)}-builtin-toolbox.txt`, report);
  return {
    message: "已运行内置工具箱：strings-lite、binwalk-lite、ciphey-lite、zsteg/tshark/rabin2/exif 子集。",
    createdFiles: [outPath],
  };
}

function extractTrafficSessions(filePath, outputRoot) {
  const buffer = fs.readFileSync(filePath);
  const limited = buffer.length > MAX_TRAFFIC_BYTES ? buffer.subarray(0, MAX_TRAFFIC_BYTES) : buffer;
  const summary = analyzeTrafficBuffer(limited);
  if (!summary.frameCount) {
    throw new Error("\u6ca1\u6709\u4ece pcap/pcapng \u4e2d\u89e3\u6790\u5230\u53ef\u7528\u7684\u6570\u636e\u5e27\u3002");
  }

  ensureOutputRoot(outputRoot);
  const createdFiles = [];
  const summaryName = `${sanitizeSegment(path.parse(filePath).name)}-traffic-summary.txt`;
  const summaryPath = writeGeneratedFile(outputRoot, summaryName, buildTrafficSummaryText(path.basename(filePath), summary));
  createdFiles.push(summaryPath);

  summary.exportedObjects.slice(0, MAX_HTTP_OBJECTS).forEach((item) => {
    createdFiles.push(writeGeneratedFile(outputRoot, item.name, item.content));
  });

  return {
    message: "\u5df2\u63d0\u53d6 HTTP / DNS / TLS / \u4f1a\u8bdd\u7ebf\u7d22\uff0c\u5e76\u5bfc\u51fa\u53ef\u7ee7\u7eed\u5206\u6790\u7684\u5bf9\u8c61\u3002",
    createdFiles,
  };
}

function extractImageQr(filePath, outputRoot) {
  const buffer = fs.readFileSync(filePath);
  const payload = detectQrPayload(buffer);
  if (!payload) {
    throw new Error("\u6ca1\u6709\u4ece\u56fe\u50cf\u4e2d\u89e3\u6790\u5230\u4e8c\u7ef4\u7801\u5185\u5bb9\u3002");
  }

  const outPath = writeGeneratedFile(
    outputRoot,
    `${sanitizeSegment(path.parse(filePath).name)}-qr.txt`,
    `${payload}\n`,
  );
  return {
    message: "\u5df2\u63d0\u53d6\u4e8c\u7ef4\u7801\u5185\u5bb9\u5e76\u7ee7\u7eed\u7eb3\u5165\u5206\u6790\u3002",
    createdFiles: [outPath],
  };
}

async function extractImageBarcode(filePath, outputRoot) {
  const payload = await detectBarcodePayload(filePath);
  if (!payload) {
    throw new Error("\u6ca1\u6709\u4ece\u56fe\u50cf\u4e2d\u89e3\u6790\u5230\u6761\u7801\u5185\u5bb9\u3002");
  }

  const outPath = writeGeneratedFile(
    outputRoot,
    `${sanitizeSegment(path.parse(filePath).name)}-barcode.txt`,
    `${payload}\n`,
  );
  return {
    message: "\u5df2\u63d0\u53d6\u4e00\u7ef4\u6761\u7801\u5185\u5bb9\u5e76\u7ee7\u7eed\u7eb3\u5165\u5206\u6790\u3002",
    createdFiles: [outPath],
  };
}

function buildLumaArray(raster) {
  const values = new Uint8Array(raster.width * raster.height);
  for (let index = 0; index < values.length; index += 1) {
    const offset = index * 4;
    values[index] = Math.round(0.299 * raster.data[offset] + 0.587 * raster.data[offset + 1] + 0.114 * raster.data[offset + 2]);
  }
  return values;
}

function renderEdgeMap(raster) {
  const luma = buildLumaArray(raster);
  return makeGrayPng(raster.width, raster.height, (offset) => {
    const pixel = offset / 4;
    const x = pixel % raster.width;
    const y = Math.floor(pixel / raster.width);
    const center = luma[pixel];
    const right = x + 1 < raster.width ? luma[pixel + 1] : center;
    const down = y + 1 < raster.height ? luma[pixel + raster.width] : center;
    const edge = Math.min(255, Math.abs(center - right) * 4 + Math.abs(center - down) * 4);
    return edge;
  });
}

function renderJpegBlockMap(raster) {
  const luma = buildLumaArray(raster);
  return makeGrayPng(raster.width, raster.height, (offset) => {
    const pixel = offset / 4;
    const x = pixel % raster.width;
    const y = Math.floor(pixel / raster.width);
    let score = 0;
    if (x > 0 && x % 8 === 0) {
      score += Math.abs(luma[pixel] - luma[pixel - 1]) * 8;
    }
    if (y > 0 && y % 8 === 0) {
      score += Math.abs(luma[pixel] - luma[pixel - raster.width]) * 8;
    }
    return Math.min(255, score);
  });
}

function extractImageViews(filePath, outputRoot) {
  const buffer = fs.readFileSync(filePath);
  const raster = decodeImageRaster(buffer);
  if (!raster) {
    throw new Error("\u76ee\u524d\u53ea\u652f\u6301 PNG / JPEG \u7684\u901a\u9053\u5bfc\u51fa\u3002");
  }

  ensureOutputRoot(outputRoot);
  const createdFiles = [];
  const baseName = sanitizeSegment(path.parse(filePath).name);
  const { width, height, data } = raster;

  const channels = [
    { name: "red", index: 0, enabled: true },
    { name: "green", index: 1, enabled: true },
    { name: "blue", index: 2, enabled: true },
    { name: "alpha", index: 3, enabled: data.some((_, idx) => idx % 4 === 3 && data[idx] !== 255) },
  ].filter((item) => item.enabled);

  channels.forEach((channel) => {
    const pngBuffer = makeGrayPng(width, height, (offset) => data[offset + channel.index]);
    createdFiles.push(writeGeneratedFile(outputRoot, `${baseName}-${channel.name}.png`, pngBuffer));
  });

  [0, 1, 2, 3].forEach((bitPlane) => {
    const pngBuffer = makeGrayPng(width, height, (offset) => {
      const r = data[offset];
      const g = data[offset + 1];
      const b = data[offset + 2];
      const luminance = Math.round(0.299 * r + 0.587 * g + 0.114 * b);
      return ((luminance >> bitPlane) & 1) * 255;
    });
    createdFiles.push(writeGeneratedFile(outputRoot, `${baseName}-luma-bit${bitPlane}.png`, pngBuffer));
  });

  const inversePng = makeGrayPng(width, height, (offset) => {
    const r = data[offset];
    const g = data[offset + 1];
    const b = data[offset + 2];
    const luminance = Math.round(0.299 * r + 0.587 * g + 0.114 * b);
    return 255 - luminance;
  });
  createdFiles.push(writeGeneratedFile(outputRoot, `${baseName}-inverse-luma.png`, inversePng));
  createdFiles.push(writeGeneratedFile(outputRoot, `${baseName}-edges.png`, renderEdgeMap(raster)));
  if (raster.format === "jpeg") {
    createdFiles.push(writeGeneratedFile(outputRoot, `${baseName}-jpeg-blocks.png`, renderJpegBlockMap(raster)));
  }

  return {
    message: "\u5df2\u5bfc\u51fa RGB/\u4eae\u5ea6\u901a\u9053\u3001\u66f4\u591a\u4f4e\u4f4d\u5e73\u9762\u3001\u8fb9\u7f18\u56fe\u548c JPEG \u5757\u6548\u5e94\u89c6\u56fe\u3002",
    createdFiles,
  };
}

function buildAudioSummaryText(fileName, wavInfo, lsbCandidates, audioSignal, strings) {
  const lines = [`# AUDIO SUMMARY`, `file: ${fileName}`, ""];
  if (wavInfo) {
    lines.push(`format: ${wavInfo.audioFormat}`);
    lines.push(`channels: ${wavInfo.channels}`);
    lines.push(`sampleRate: ${wavInfo.sampleRate}`);
    lines.push(`bitsPerSample: ${wavInfo.bitsPerSample}`);
    lines.push(`duration: ${wavInfo.durationSeconds.toFixed(2)}s`);
    lines.push("");
    if (wavInfo.chunks.length) {
      lines.push("# CHUNKS");
      wavInfo.chunks.forEach((chunk) => lines.push(`${chunk.id} ${chunk.size}`));
      lines.push("");
    }
    const metadataEntries = Object.entries(wavInfo.metadata || {});
    if (metadataEntries.length) {
      lines.push("# METADATA");
      metadataEntries.forEach(([key, value]) => lines.push(`${key}: ${value}`));
      lines.push("");
    }
  }
  if (audioSignal) {
    if (audioSignal.dominantFrequencies.length) {
      lines.push("# DOMINANT FREQUENCIES");
      audioSignal.dominantFrequencies.forEach((item) => {
        lines.push(`${Math.round(item.frequencyHz)} Hz (${item.durationSeconds.toFixed(2)}s active)`);
      });
      lines.push("");
    }
    if (audioSignal.activeSegments.length) {
      lines.push("# ACTIVITY SEGMENTS");
      audioSignal.activeSegments.slice(0, 32).forEach((segment, index) => {
        const frequency = segment.frequencyHz ? ` @ ${Math.round(segment.frequencyHz)} Hz` : "";
        lines.push(
          `${index + 1}. ${segment.startSeconds.toFixed(2)}s -> ${segment.endSeconds.toFixed(2)}s (${segment.durationSeconds.toFixed(2)}s)${frequency}`,
        );
      });
      if (audioSignal.activeSegments.length > 32) {
        lines.push(`... ${audioSignal.activeSegments.length - 32} more segments`);
      }
      lines.push("");
    }
    if (audioSignal.morseCandidates.length) {
      lines.push("# MORSE CANDIDATES");
      audioSignal.morseCandidates.forEach((candidate, index) => {
        lines.push(`${index + 1}. ${candidate.text}`);
        lines.push(`pattern: ${candidate.pattern}`);
        lines.push(`unit: ${candidate.unitMilliseconds} ms`);
        lines.push("");
      });
    }
  }
  if (strings.length) {
    lines.push("# STRINGS PREVIEW");
    strings.slice(0, 24).forEach((entry) => lines.push(entry));
    if (strings.length > 24) {
      lines.push(`... ${strings.length - 24} more strings`);
    }
    lines.push("");
  }
  if (lsbCandidates.length) {
    lines.push("# LSB");
    lsbCandidates.forEach((item) => {
      lines.push(item.channel);
      item.flags.forEach((flag) => lines.push(flag.value));
      item.printable.forEach((entry) => lines.push(entry));
      lines.push("");
    });
  }
  return `${lines.join("\n")}\n`;
}

function extractAudioClues(filePath, outputRoot) {
  const buffer = fs.readFileSync(filePath);
  const wavInfo = parseWavBuffer(buffer);
  const lsbCandidates = wavInfo ? collectAudioLSBCandidates(buffer, wavInfo) : [];
  const audioSignal = wavInfo ? analyzeWavSignal(buffer, wavInfo, { maxSamples: MAX_AUDIO_ANALYSIS_SAMPLES }) : null;
  const strings = dedupeStrings(extractAsciiStrings(buffer, 6, 1200).concat(extractUnicodeStrings(buffer, 6, 400)));

  const hasSignal = audioSignal && (audioSignal.activeSegments.length || audioSignal.morseCandidates.length || audioSignal.dominantFrequencies.length);
  if (!wavInfo && !lsbCandidates.length && !strings.length && !hasSignal) {
    throw new Error("\u6ca1\u6709\u4ece\u97f3\u9891\u9644\u4ef6\u4e2d\u63d0\u53d6\u5230\u9ad8\u4fe1\u53f7\u7ebf\u7d22\u3002");
  }

  ensureOutputRoot(outputRoot);
  const createdFiles = [];
  const baseName = sanitizeSegment(path.parse(filePath).name);
  createdFiles.push(
    writeGeneratedFile(outputRoot, `${baseName}-audio-summary.txt`, buildAudioSummaryText(path.basename(filePath), wavInfo, lsbCandidates, audioSignal, strings)),
  );
  if (lsbCandidates.length) {
    const sections = lsbCandidates.flatMap((item) => {
      const lines = [`# ${item.channel}`];
      item.flags.forEach((flag) => lines.push(flag.value));
      item.printable.forEach((entry) => lines.push(entry));
      lines.push("");
      return lines;
    });
    createdFiles.push(writeGeneratedFile(outputRoot, `${baseName}-audio-lsb.txt`, `${sections.join("\n")}\n`));
  }
  if (strings.length) {
    createdFiles.push(writeGeneratedFile(outputRoot, `${baseName}-audio-strings.txt`, `${strings.join("\n")}\n`));
  }
  if (hasSignal) {
    const toneLines = [`# AUDIO TONES`, `file: ${path.basename(filePath)}`, ""];
    if (audioSignal.dominantFrequencies.length) {
      toneLines.push("# DOMINANT");
      audioSignal.dominantFrequencies.forEach((item) => {
        toneLines.push(`${Math.round(item.frequencyHz)} Hz (${item.durationSeconds.toFixed(2)}s active)`);
      });
      toneLines.push("");
    }
    if (audioSignal.activeSegments.length) {
      toneLines.push("# SEGMENTS");
      audioSignal.activeSegments.forEach((segment, index) => {
        const frequency = segment.frequencyHz ? `${Math.round(segment.frequencyHz)} Hz` : "unknown";
        toneLines.push(
          `${index + 1}. ${segment.startSeconds.toFixed(3)}s -> ${segment.endSeconds.toFixed(3)}s (${segment.durationSeconds.toFixed(3)}s) ${frequency}`,
        );
      });
      toneLines.push("");
    }
    createdFiles.push(writeGeneratedFile(outputRoot, `${baseName}-audio-tones.txt`, `${toneLines.join("\n")}\n`));
  }
  if (audioSignal && audioSignal.morseCandidates.length) {
    const morseLines = [`# AUDIO MORSE`, `file: ${path.basename(filePath)}`, ""];
    audioSignal.morseCandidates.forEach((candidate, index) => {
      morseLines.push(`${index + 1}. ${candidate.text}`);
      morseLines.push(`pattern: ${candidate.pattern}`);
      morseLines.push(`unit: ${candidate.unitMilliseconds} ms`);
      morseLines.push("");
    });
    createdFiles.push(writeGeneratedFile(outputRoot, `${baseName}-audio-morse.txt`, `${morseLines.join("\n")}\n`));
  }

  return {
    message: "\u5df2\u63d0\u53d6 WAV \u5757\u4fe1\u606f\u3001strings\u3001PCM LSB\u3001\u97f3\u8c03\u5206\u6bb5\u548c Morse \u5019\u9009\u3002",
    createdFiles: dedupeStrings(createdFiles),
  };
}

function extractAudioViews(filePath, outputRoot) {
  const buffer = fs.readFileSync(filePath);
  const wavInfo = parseWavBuffer(buffer);
  if (!wavInfo) {
    throw new Error("\u76ee\u524d\u53ea\u652f\u6301 WAV \u97f3\u9891\u7684\u6ce2\u5f62\u89c6\u56fe\u5bfc\u51fa\u3002");
  }
  const createdFiles = [];
  const baseName = sanitizeSegment(path.parse(filePath).name);
  const waveform = renderWavWaveform(buffer, wavInfo);
  const spectrogram = renderWavSpectrogram(buffer, wavInfo);
  if (waveform) {
    createdFiles.push(writeGeneratedFile(outputRoot, `${baseName}-waveform.png`, waveform));
  }
  if (spectrogram) {
    createdFiles.push(writeGeneratedFile(outputRoot, `${baseName}-spectrogram.png`, spectrogram));
  }
  if (!createdFiles.length) {
    throw new Error("\u6ca1\u6709\u751f\u6210 WAV \u6ce2\u5f62\u56fe\u6216\u9891\u8c31\u56fe\u3002");
  }
  return {
    message: "\u5df2\u5bfc\u51fa WAV \u6ce2\u5f62\u56fe\u548c\u9891\u8c31\u56fe\u3002",
    createdFiles,
  };
}

function extractPdfContent(filePath, outputRoot) {
  const buffer = fs.readFileSync(filePath);
  const report = analyzePdfBuffer(buffer);
  if (!report) {
    throw new Error("\u4e0d\u662f\u53ef\u89e3\u6790\u7684 PDF \u6587\u6863\u3002");
  }

  const hasContent =
    Object.keys(report.metadata || {}).length || report.urls.length || report.xmpPackets.length || report.extractedStreams.length;
  if (!hasContent) {
    throw new Error("\u6ca1\u6709\u4ece PDF \u4e2d\u63d0\u53d6\u5230\u9ad8\u4fe1\u53f7\u5185\u5bb9\u3002");
  }

  ensureOutputRoot(outputRoot);
  const createdFiles = [];
  const baseName = sanitizeSegment(path.parse(filePath).name);
  createdFiles.push(writeGeneratedFile(outputRoot, `${baseName}-pdf-summary.txt`, buildPdfSummaryText(path.basename(filePath), report)));

  report.xmpPackets.forEach((packet, index) => {
    createdFiles.push(writeGeneratedFile(outputRoot, `${baseName}-xmp-${index + 1}.xml`, packet));
  });

  report.extractedStreams.forEach((stream) => {
    createdFiles.push(writeGeneratedFile(outputRoot, `${baseName}-pdf-stream-${stream.index}.txt`, `${stream.text}\n`));
  });

  return {
    message: "\u5df2\u63d0\u53d6 PDF \u5143\u6570\u636e\u3001XMP\u3001stream \u548c URL \u7ebf\u7d22\u3002",
    createdFiles: dedupeStrings(createdFiles),
  };
}

function extractDocumentPackage(filePath, outputRoot) {
  return extractArchive(filePath, outputRoot);
}

function extractJpegComments(buffer) {
  if (detectMagic(buffer) !== "jpeg" || buffer.length < 4) {
    return [];
  }

  const comments = [];
  let offset = 2;

  while (offset + 4 <= buffer.length) {
    if (buffer[offset] !== 0xff) {
      offset += 1;
      continue;
    }

    const marker = buffer[offset + 1];
    offset += 2;

    if (marker === 0xd9 || marker === 0xda) {
      break;
    }
    if (marker === 0x01 || (marker >= 0xd0 && marker <= 0xd7)) {
      continue;
    }
    if (offset + 2 > buffer.length) {
      break;
    }

    const length = buffer.readUInt16BE(offset);
    if (length < 2 || offset + length > buffer.length) {
      break;
    }

    const data = buffer.subarray(offset + 2, offset + length);
    if (marker === 0xfe) {
      const text = decodeBufferAsText(data).trim();
      if (text) {
        comments.push(text);
      }
    } else if (marker === 0xe1 || marker === 0xe2) {
      extractPrintableSegments(decodeBufferAsText(data), 8, 10).forEach((item) => comments.push(item));
    }

    offset += length;
  }

  return dedupeStrings(comments).slice(0, 40);
}

function getJpegMarkerName(marker) {
  if (marker === 0xda) {
    return "SOS";
  }
  if (marker === 0xd9) {
    return "EOI";
  }
  if (marker === 0xfe) {
    return "COM";
  }
  if (marker >= 0xe0 && marker <= 0xef) {
    return `APP${marker - 0xe0}`;
  }
  if (marker >= 0xc0 && marker <= 0xcf) {
    return `SOF${marker - 0xc0}`;
  }
  return `0x${marker.toString(16).padStart(2, "0").toUpperCase()}`;
}

function identifyJpegSegmentKind(marker, data) {
  if (marker === 0xfe) {
    return "comment";
  }
  if (marker === 0xe0 && data.subarray(0, 5).toString("ascii") === "JFIF\0") {
    return "jfif";
  }
  if (marker === 0xe1 && data.subarray(0, 6).toString("ascii") === "Exif\0\0") {
    return "exif";
  }
  if (marker === 0xe1 && data.subarray(0, 29).toString("utf8").startsWith("http://ns.adobe.com/xap/1.0/")) {
    return "xmp";
  }
  if (marker === 0xe2 && data.subarray(0, 12).toString("ascii") === "ICC_PROFILE\0") {
    return "icc";
  }
  if (marker === 0xed && data.subarray(0, 13).toString("ascii") === "Photoshop 3.0") {
    return "photoshop";
  }
  if (marker === 0xee && data.subarray(0, 5).toString("ascii") === "Adobe") {
    return "adobe";
  }
  return "segment";
}

function parseJpegSegments(buffer) {
  if (detectMagic(buffer) !== "jpeg" || buffer.length < 4) {
    return [];
  }

  const segments = [];
  let offset = 2;

  while (offset + 4 <= buffer.length) {
    while (offset < buffer.length && buffer[offset] === 0xff) {
      offset += 1;
    }
    if (offset >= buffer.length) {
      break;
    }

    const marker = buffer[offset];
    offset += 1;

    if (marker === 0xd9) {
      break;
    }
    if (marker === 0xda) {
      break;
    }
    if (marker === 0x01 || (marker >= 0xd0 && marker <= 0xd7)) {
      continue;
    }
    if (offset + 2 > buffer.length) {
      break;
    }

    const length = buffer.readUInt16BE(offset);
    if (length < 2 || offset + length > buffer.length) {
      break;
    }

    const data = buffer.subarray(offset + 2, offset + length);
    const markerName = getJpegMarkerName(marker);
    const kind = identifyJpegSegmentKind(marker, data);
    segments.push({
      marker,
      markerName,
      kind,
      offset: offset - 1,
      size: data.length,
      data,
    });

    offset += length;
  }

  return segments;
}

function segmentPreviewText(segment) {
  if (segment.kind === "comment") {
    return decodeBufferAsText(segment.data).trim();
  }
  if (segment.kind === "xmp") {
    const zero = segment.data.indexOf(0);
    const payload = zero === -1 ? segment.data : segment.data.subarray(zero + 1);
    return decodeBufferAsText(payload).trim();
  }
  return extractPrintableSegments(decodeBufferAsText(segment.data), 8, 8).join(" | ");
}

function buildJpegSegmentSummary(segments, fileName) {
  const lines = [`# JPEG SEGMENTS`, `file: ${fileName}`, `count: ${segments.length}`, ""];
  segments.forEach((segment, index) => {
    lines.push(
      `[${String(index + 1).padStart(2, "0")}] ${segment.markerName} kind=${segment.kind} offset=${segment.offset} size=${segment.size}`,
    );
    const preview = segmentPreviewText(segment);
    if (preview) {
      lines.push(preview);
    }
    lines.push("");
  });
  return `${lines.join("\n")}\n`;
}

function extractJpegSegments(filePath, outputRoot) {
  const buffer = fs.readFileSync(filePath);
  const segments = parseJpegSegments(buffer);
  if (!segments.length) {
    throw new Error("\u6ca1\u6709\u63d0\u53d6\u5230\u53ef\u7528\u7684 JPEG \u6bb5\u3002");
  }

  ensureOutputRoot(outputRoot);
  const createdFiles = [];
  const summaryName = `${sanitizeSegment(path.parse(filePath).name)}-jpeg-segments.txt`;
  createdFiles.push(writeGeneratedFile(outputRoot, summaryName, buildJpegSegmentSummary(segments, path.basename(filePath))));

  segments.forEach((segment, index) => {
    const prefix = `${String(index + 1).padStart(2, "0")}-${segment.markerName.toLowerCase()}-${segment.kind}`;
    if (segment.kind === "comment") {
      const text = decodeBufferAsText(segment.data).trim();
      if (text) {
        createdFiles.push(writeGeneratedFile(outputRoot, `${prefix}.txt`, `${text}\n`));
      }
      return;
    }

    if (segment.kind === "xmp") {
      const zero = segment.data.indexOf(0);
      const payload = zero === -1 ? segment.data : segment.data.subarray(zero + 1);
      if (payload.length) {
        createdFiles.push(writeGeneratedFile(outputRoot, `${prefix}.xml`, payload));
      }
      return;
    }

    if (segment.kind === "icc") {
      const headerLength = 14;
      const payload = segment.data.length > headerLength ? segment.data.subarray(headerLength) : segment.data;
      createdFiles.push(writeGeneratedFile(outputRoot, `${prefix}.icc`, payload));
      return;
    }

    if (segment.kind === "exif") {
      const payload = segment.data.length > 6 ? segment.data.subarray(6) : segment.data;
      createdFiles.push(writeGeneratedFile(outputRoot, `${prefix}.exif.bin`, payload));
      const preview = extractPrintableSegments(decodeBufferAsText(payload), 8, 20);
      if (preview.length) {
        createdFiles.push(writeGeneratedFile(outputRoot, `${prefix}.txt`, `${preview.join("\n")}\n`));
      }
      return;
    }

    const printable = extractPrintableSegments(decodeBufferAsText(segment.data), 8, 20);
    if (printable.length) {
      createdFiles.push(writeGeneratedFile(outputRoot, `${prefix}.txt`, `${printable.join("\n")}\n`));
    } else if (["photoshop", "adobe", "segment"].includes(segment.kind) && segment.data.length) {
      createdFiles.push(writeGeneratedFile(outputRoot, `${prefix}.bin`, segment.data));
    }
  });

  return {
    message: "\u5df2\u62c6\u51fa JPEG \u6bb5\u3001\u6ce8\u91ca\u548c APP \u5185\u5bb9\uff0c\u5e76\u7ee7\u7eed\u7eb3\u5165\u5206\u6790\u3002",
    createdFiles: dedupeStrings(createdFiles),
  };
}

function extractImageMetadata(filePath, outputRoot) {
  const buffer = fs.readFileSync(filePath);
  const lines = [];
  try {
    const metadata = ExifParser.create(buffer).parse();
    Object.entries(metadata.tags || {}).forEach(([key, value]) => {
      lines.push(`${key}: ${value}`);
    });
  } catch (_error) {
    // ignore
  }

  const strings = extractAsciiStrings(buffer, 6, 500);
  const comments = strings.filter((value) => /flag|comment|author|software|icc|photoshop|adobe/i.test(value)).slice(0, 40);
  comments.forEach((value) => lines.push(value));
  extractJpegComments(buffer).forEach((value) => lines.push(value));

  if (!lines.length) {
    throw new Error("\u6ca1\u6709\u63d0\u53d6\u5230\u660e\u663e\u7684\u56fe\u50cf\u5143\u6570\u636e\u6216\u6ce8\u91ca\u5185\u5bb9\u3002");
  }

  const generatedName = `${sanitizeSegment(path.parse(filePath).name)}-metadata.txt`;
  const outPath = writeGeneratedFile(outputRoot, generatedName, `${lines.join("\n")}\n`);
  return {
    message: "\u5df2\u63d0\u53d6\u56fe\u50cf\u5143\u6570\u636e\u548c\u53ef\u7591\u6ce8\u91ca\u6587\u672c\u3002",
    createdFiles: [outPath],
  };
}

function extractPngText(filePath, outputRoot) {
  const buffer = fs.readFileSync(filePath);
  const chunks = extractPngTextChunks(buffer);
  if (!chunks.length) {
    throw new Error("\u6ca1\u6709\u63d0\u53d6\u5230 PNG \u6587\u672c\u5757\u3002");
  }

  const generatedName = `${sanitizeSegment(path.parse(filePath).name)}-png-text.txt`;
  const outPath = writeGeneratedFile(outputRoot, generatedName, `${chunks.join("\n")}\n`);
  return {
    message: "\u5df2\u63d0\u53d6 PNG \u6587\u672c\u5757\u3002",
    createdFiles: [outPath],
  };
}

function extractPngLsb(filePath, outputRoot) {
  const buffer = fs.readFileSync(filePath);
  const candidates = collectPngLSBCandidates(buffer);
  if (!candidates.length) {
    throw new Error("\u6ca1\u6709\u63d0\u53d6\u5230\u53ef\u7528\u7684 PNG \u4f4e\u4f4d\u5e73\u9762\u6587\u672c\u5019\u9009\u3002");
  }

  const sections = candidates.flatMap((item) => {
    const lines = [`# ${item.traversal.toUpperCase()} ${item.channel} bit${item.bitPlane} ${item.bitOrder.toUpperCase()}`];
    item.printable.forEach((entry) => lines.push(entry));
    item.flags.forEach((entry) => lines.push(entry.value));
    lines.push("");
    return lines;
  });
  const generatedName = `${sanitizeSegment(path.parse(filePath).name)}-png-lsb.txt`;
  const outPath = writeGeneratedFile(outputRoot, generatedName, `${sections.join("\n")}\n`);
  return {
    message: "\u5df2\u5bfc\u51fa PNG \u4f4e\u4f4d\u5e73\u9762\u5019\u9009\u6587\u672c\u3002",
    createdFiles: [outPath],
  };
}

async function runArtifactActionInternal(actionId, filePath, outputRoot) {
  if (!filePath || !fs.existsSync(filePath)) {
    throw new Error("\u76ee\u6807\u9644\u4ef6\u4e0d\u5b58\u5728\u3002");
  }

  const baseDir = createActionOutputRoot(outputRoot, filePath, actionId);

  if (String(actionId || "").startsWith("tool:")) {
    return runToolAction(actionId, filePath, baseDir);
  }

  if (actionId === "run-builtin-toolbox") {
    return runBuiltinToolbox(filePath, baseDir);
  }
  if (actionId === "extract-appended-zip" || actionId === "extract-appended-payloads") {
    return actionId === "extract-appended-zip" ? extractAppendedZip(filePath, baseDir) : extractAppendedPayloads(filePath, baseDir);
  }
  if (actionId === "extract-archive") {
    return extractArchive(filePath, baseDir);
  }
  if (actionId === "extract-image-metadata") {
    return extractImageMetadata(filePath, baseDir);
  }
  if (actionId === "extract-jpeg-segments") {
    return extractJpegSegments(filePath, baseDir);
  }
  if (actionId === "extract-image-qr") {
    return extractImageQr(filePath, baseDir);
  }
  if (actionId === "extract-image-barcode") {
    return extractImageBarcode(filePath, baseDir);
  }
  if (actionId === "extract-image-views") {
    return extractImageViews(filePath, baseDir);
  }
  if (actionId === "extract-audio-clues") {
    return extractAudioClues(filePath, baseDir);
  }
  if (actionId === "extract-audio-views") {
    return extractAudioViews(filePath, baseDir);
  }
  if (actionId === "extract-binary-clues") {
    return extractBinaryClues(filePath, baseDir);
  }
  if (actionId === "extract-apk-package") {
    return extractApkPackage(filePath, baseDir);
  }
  if (actionId === "extract-pdf-content") {
    return extractPdfContent(filePath, baseDir);
  }
  if (actionId === "extract-document-package") {
    return extractDocumentPackage(filePath, baseDir);
  }
  if (actionId === "decode-encoded-text") {
    return decodeEncodedText(filePath, baseDir);
  }
  if (actionId === "extract-traffic-sessions") {
    return extractTrafficSessions(filePath, baseDir);
  }
  if (actionId === "extract-strings") {
    return exportStrings(filePath, baseDir);
  }
  if (actionId === "extract-png-text") {
    return extractPngText(filePath, baseDir);
  }
  if (actionId === "extract-png-lsb") {
    return extractPngLsb(filePath, baseDir);
  }

  throw new Error(`Unsupported action: ${actionId}`);
}

function shouldAutoRun(actionId, artifact) {
  if (String(actionId || "").startsWith("tool:")) {
    return artifact.depth === 0 && isToolActionAutoRunnable(actionId);
  }
  if (actionId === "run-builtin-toolbox") {
    return artifact.depth === 0;
  }
  if (actionId === "extract-appended-zip" || actionId === "extract-appended-payloads") {
    return true;
  }
  if (actionId === "extract-archive") {
    return artifact.depth < MAX_PIPELINE_DEPTH;
  }
  if (actionId === "extract-image-metadata") {
    return artifact.depth === 0;
  }
  if (actionId === "extract-jpeg-segments") {
    return artifact.badge === "JPEG" && artifact.depth === 0;
  }
  if (actionId === "extract-image-qr") {
    return artifact.family === "image" && artifact.depth === 0;
  }
  if (actionId === "extract-image-barcode") {
    return artifact.family === "image" && artifact.depth === 0;
  }
  if (actionId === "extract-image-views") {
    return false;
  }
  if (actionId === "extract-audio-clues") {
    return artifact.family === "audio" && artifact.depth === 0;
  }
  if (actionId === "extract-audio-views") {
    return false;
  }
  if (actionId === "extract-binary-clues") {
    return artifact.family === "binary" && artifact.badge !== "APK" && artifact.depth === 0;
  }
  if (actionId === "extract-apk-package") {
    return artifact.badge === "APK" && artifact.depth < MAX_PIPELINE_DEPTH;
  }
  if (actionId === "extract-pdf-content") {
    return artifact.badge === "PDF" && artifact.depth === 0;
  }
  if (actionId === "extract-document-package") {
    return artifact.family === "document" && isOfficePackageExtension(artifact.extension) && artifact.depth < MAX_PIPELINE_DEPTH;
  }
  if (actionId === "decode-encoded-text") {
    return artifact.depth < MAX_PIPELINE_DEPTH;
  }
  if (actionId === "extract-traffic-sessions") {
    return artifact.family === "network" && artifact.depth === 0;
  }
  if (actionId === "extract-strings") {
    return artifact.family === "binary" || artifact.family === "network";
  }
  if (actionId === "extract-png-text" || actionId === "extract-png-lsb") {
    return artifact.depth < MAX_PIPELINE_DEPTH;
  }
  return false;
}

async function buildPipelineArtifacts(rootPaths, outputRoot) {
  const queue = rootPaths.map((filePath) => ({
    filePath,
    depth: 0,
    sourceKind: "input",
    generatedBy: null,
    parentPath: null,
  }));

  const seen = new Set();
  const artifacts = [];
  const pipelineLog = [];
  const pipelineErrors = [];

  while (queue.length && artifacts.length < MAX_FILES) {
    const current = queue.shift();
    if (seen.has(current.filePath) || !fs.existsSync(current.filePath)) {
      continue;
    }
    seen.add(current.filePath);

    const artifact = await buildArtifactSignals(current.filePath);
    artifact.depth = current.depth;
    artifact.sourceKind = current.sourceKind;
    artifact.generatedBy = current.generatedBy;
    artifact.parentPath = current.parentPath;
    artifacts.push(artifact);

    for (const action of artifact.actions || []) {
      if (!shouldAutoRun(action.id, artifact)) {
        continue;
      }
      try {
        const result = await runArtifactActionInternal(action.id, artifact.path, outputRoot);
        const createdArtifacts = result.createdFiles
          .filter((createdPath) => fs.existsSync(createdPath))
          .map((createdPath) => buildGeneratedDescriptor(createdPath));

        if (!createdArtifacts.length) {
          continue;
        }

        pipelineLog.push({
          actionId: action.id,
          actionLabel: action.label,
          sourcePath: artifact.path,
          sourceName: artifact.name,
          message: result.message,
          createdArtifacts,
        });

        createdArtifacts.forEach((created) => {
          queue.push({
            filePath: created.path,
            depth: current.depth + 1,
            sourceKind: "generated",
            generatedBy: action.label,
            parentPath: artifact.path,
          });
        });
      } catch (error) {
        pipelineErrors.push({
          actionId: action.id,
          actionLabel: action.label,
          sourcePath: artifact.path,
          sourceName: artifact.name,
          message: error?.message || String(error),
          guide: buildFailureGuide(error, action, artifact),
        });
      }
    }
  }

  return { artifacts, pipelineLog, pipelineErrors };
}

async function analyzeChallenge(payload, outputRoot) {
  const title = String(payload.title || "").trim();
  const description = String(payload.description || "").trim();
  const notes = String(payload.notes || "").trim();
  const tags = Array.isArray(payload.tags)
    ? payload.tags.map((item) => String(item).trim()).filter(Boolean)
    : String(payload.tags || "")
        .split(/\s+/)
        .map((item) => item.trim())
        .filter(Boolean);

  if (!title && !description && !notes && (!payload.artifacts || !payload.artifacts.length)) {
    throw new Error("\u8bf7\u81f3\u5c11\u8f93\u5165\u9898\u76ee\u4fe1\u606f\u6216\u6dfb\u52a0\u4e00\u4e2a\u9644\u4ef6\u3002");
  }

  const collection = collectPaths(payload.artifacts || []);
  const pipeline = await buildPipelineArtifacts(collection.files, outputRoot);
  const inlineFlags = [
    ...findFlagCandidates(title, "\u6807\u9898"),
    ...findFlagCandidates(description, "\u63cf\u8ff0"),
    ...findFlagCandidates(notes, "\u8865\u5145\u7ebf\u7d22"),
  ];
  const allFlagCandidates = dedupeStrings(
    inlineFlags
      .concat(pipeline.artifacts.flatMap((artifact) => artifact.flagCandidates))
      .map((item) => `${item.value}@@${item.source}`),
  ).map((entry) => {
    const [value, source] = entry.split("@@");
    return { value, source };
  });

  const classification = classifyChallenge({ title, description, notes, tags }, pipeline.artifacts);
  const quickFindings = buildQuickFindings(pipeline.artifacts, allFlagCandidates, pipeline.pipelineLog);
  const toolStatus = getToolStatusSummary();
  const bundledTools = getBundledToolStatus();
  const solver = buildSolverResult(pipeline.artifacts, allFlagCandidates, pipeline.pipelineLog, pipeline.pipelineErrors, toolStatus);
  const warnings = [];

  if (collection.truncated) {
    warnings.push(COPY.app.truncated);
  }

  return {
    challenge: {
      title: title || COPY.app.unnamed,
      description,
      notes,
      tags,
      artifactCount: pipeline.artifacts.length,
    },
    classification,
    artifacts: pipeline.artifacts,
    pipelineLog: pipeline.pipelineLog,
    pipelineErrors: pipeline.pipelineErrors,
    solver,
    quickFindings,
    flagCandidates: allFlagCandidates,
    warnings,
    toolStatus,
    bundledTools,
    emptyFlagMessage: COPY.app.noFlags,
  };
}

async function runArtifactAction(actionId, filePath, outputRoot) {
  const result = await runArtifactActionInternal(actionId, filePath, outputRoot);

  return {
    message: result.message,
    generatedArtifacts: result.createdFiles.map((createdPath) => ({
      ...buildGeneratedDescriptor(createdPath),
      generatedBy: actionId,
      parentPath: filePath,
    })),
  };
}

module.exports = {
  analyzeChallenge,
  prepareArtifactsFromEntries,
  runArtifactAction,
};
