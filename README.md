# CTF Compass

CTF Compass is a safe, extensible desktop app for lawful CTF practice. It is designed around a file-first workflow: challenge statements, images, text files, archives, binaries, and traffic captures are treated as first-class inputs instead of optional notes.

## Scope

This project is intentionally limited to legitimate CTF training workflows:

- classify challenge types from metadata, notes, and attached artifacts
- extract likely flag candidates from text, ASCII / UTF-16 strings, recursive encoded content, and CJK codepoint byte projection
- automatically unpack ZIP and GZIP content and continue recursive analysis
- automatically decode base64, base58, hex, base32, ascii85, URL-encoded, binary/decimal byte streams, escaped byte text, single-byte XOR, ROT/Caesar, Bacon, Brainfuck, zero-width text, whitespace stego, Unicode tag text, and compressed text layers when they produce useful local results
- automatically extract solvable image clues such as appended payloads, PNG text chunks, low-bit-plane candidates, and JPEG COM / XMP / APP segment payloads
- automatically decode QR and 1D barcode payloads from local images and export RGB / luminance / edge / JPEG-block visualization views for image-based challenges
- automatically summarize local traffic captures, extracting HTTP requests, DNS names, TLS SNI, cookies/tokens, and exported HTTP objects
- automatically extract PDF metadata, XMP packets, readable Flate streams, and OOXML/Office package contents for recursive local analysis
- automatically inspect WAV metadata, PCM LSB candidates, tone / morse hints, and waveform / spectrogram views for audio-based local challenges
- automatically inspect ELF / PE / APK attachments, extracting headers, sections, imports / exports, symbol / relocation summaries, interpreter / shared-library hints, manifest strings, DEX method indexes, Android string-pool resources, and unpacked package contents for recursive local analysis
- run a bundled local toolbox on each root artifact, covering strings-lite, binwalk-lite, ciphey-lite, zsteg-lite, tshark-lite, and rabin2/exif-lite style checks without external downloads
- detect local professional CTF tools on PATH and auto-run safe adapters instead of showing placeholder guidance
- run installed tool adapters for ExifTool, binwalk, zsteg, TShark, Ciphey, rabin2, jadx, and apktool, then import generated output back into the recursive solver
- show missing tool status and installation hints per artifact so the user knows exactly why a deeper action is unavailable
- produce a solver status: solved, partially solved, or blocked, with the highest-confidence flag candidate and concrete next action
- collapse extraction steps in the UI and attach a task-specific recovery guide to each failed automatic action
- start each launch with a fresh empty workspace so previous attachments and challenge text are not restored automatically
- isolate generated files, temporary sessions, future portable tool downloads, and local helper assets under one sandbox directory that can be opened or cleared from Settings
- export Markdown investigation reports that include classification, pipeline output, final flag, and artifact-level notebook entries
- provide dedicated desktop workbench panes for binary / traffic / image / audio families instead of showing everything in one generic result list
- surface solving checklists and methodology guides
- help organize evidence, observations, and likely next steps in one desktop workspace

This project does **not** target real-world systems and should not be used for unauthorized activity.

## Current Capability Areas

- `crypto`: simple encoded content discovery, category hints, and workflow guidance
- `web`: challenge metadata and traffic-based session/auth clue routing
- `reverse`: ELF / PE / APK structure extraction, strings/import/export/symbol triage, and flow hints
- `pwn`: ELF-oriented routing with loader/shared-library clues and protection-oriented next steps
- `forensic`: pcap/pcapng session extraction, archive recursion, document extraction, and hidden-artifact oriented workflow hints
- `misc`: image/stego and mixed-artifact triage with local auto-processing where deterministic

## Tool-Backed Workflow

CTF Compass uses a two-layer workflow:

- Built-in analyzers handle deterministic local tasks such as recursive ZIP/GZIP extraction, strings, encoded text layers, PNG text chunks, PNG LSB candidates, QR/barcode detection, basic pcap triage, PDF/Office unpacking, WAV clues, and ELF/PE/APK structure summaries.
- A bundled toolbox report is generated automatically for each root artifact. It mimics the common workflow of `strings`, `binwalk`, `Ciphey`, `zsteg`, `TShark`, `rabin2`, and `exiftool` where a lightweight in-app implementation is practical.
- External tool adapters run mature local tools when they are installed. Safe scan/extract adapters are executed automatically during solver runs, while heavier decompile/export actions remain available from each artifact card.

Supported adapters:

- `ExifTool`: metadata extraction for images, documents, audio, archives, and binaries
- `binwalk`: signature scan and embedded-file extraction
- `zsteg`: PNG/BMP LSB steganography scan
- `TShark`: HTTP/DNS extraction and HTTP object export from traffic captures
- `Ciphey`: automatic decode/decrypt attempts for text-like artifacts
- `rabin2`: ELF/PE/Mach-O header, section, import, and string triage
- `jadx`: APK/DEX Java decompilation
- `apktool`: APK resource and smali unpacking

If a tool is missing, the artifact card and solver panel show it as `未安装` with the install direction. After installing and reopening/rerunning analysis, the matching action becomes available and can participate in automatic solving.

## Sandbox Mode

Runtime output is intentionally grouped under Electron `userData/sandbox/`:

- `generated/`: recursive analysis output, extracted files, tool reports, and derived artifacts
- `downloads/`: reserved for future portable tool downloads
- `tools/`: reserved for future portable helper binaries
- `session/`: temporary session state, cleared on app launch

Deleting the sandbox folder removes generated analysis data and future bundled helper tools together. The app also exposes `打开沙盒目录` and `清理沙盒` in Settings. Original challenge files selected from disk are never copied or deleted by sandbox cleanup.

## Repository Layout

- `src/ctf_compass/`: application package
- `desktop/`: Electron desktop shell and UI
- `docs/`: architecture and challenge methodology guides
- `plugins/`: future plugin definitions for category-specific helpers

## Desktop App

```powershell
npm install
npm run dev
```

Create a Windows desktop build:

```powershell
npm run dist:dir
```

The unpacked Windows app will be written to `release/win-unpacked/`.

A downloadable zip can be created from the unpacked build. The current local package name is `release/CTF-Compass-0.4.6-win-x64.zip`.

## Next Steps

1. Add dedicated workbench panes for PDF / Office so document-style attachments stop falling back to the generic results grid.
2. Add an optional tool installer/bootstrap page that can generate Windows/WSL setup commands without silently changing the host.
3. Deepen local binary routes with APK resource-id mapping, fuller DEX proto/method views, PE protection/export grouping, and ELF relocation detail views.
4. Add category-specific plugin modules and release automation for GitHub Releases / installers.
