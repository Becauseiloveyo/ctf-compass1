# Challenge Methods

## Crypto

- Identify whether the problem is encoding, classical cipher, block cipher, stream cipher, hash misuse, RSA, ECC, or custom math.
- Check for repeated structure, fixed alphabets, padding artifacts, modulus leaks, or nonce reuse.
- Separate "decode" tasks from actual cryptanalysis before choosing a path.

## Web

- Map endpoints, parameters, sessions, roles, and file upload surfaces.
- Check auth logic, input validation, template rendering, deserialization, SSRF-like pivots inside the challenge boundary, and common CTF misconfigurations.
- Use the guide to narrow the vulnerability class before attempting any challenge-specific exploit path.

## Reverse

- Start with file type, architecture, symbols, strings, imports, and anti-debug clues.
- Reconstruct high-level logic before patching or tracing.
- Record all constants, comparisons, and encoded data paths.

## Pwn

- Identify architecture, protections, I/O model, memory corruption surface, and intended primitive.
- Confirm NX, PIE, RELRO, stack canaries, and libc assumptions.
- Use checksec-lite and the risky-import summary to prioritize likely stack overflow, format-string, ret2libc, ROP, or heap-oriented paths before opening a debugger.
- Use the I/O profile to distinguish stdio binaries from network services, and treat `alarm`, `fork`, `prctl`, or `seccomp` imports as runtime constraints that must be recovered before selecting a path.
- Match provided executables, loaders, libc files, and core dumps by architecture, ELF role, GNU Build ID, and GLIBC version instead of using the host runtime by default.
- Review writable, executable, RWX, and staging sections before selecting direct shellcode, staged input, stack pivot, or ORW paths.
- Review menu prompts, format literals, shell paths, and flag-file strings as navigation clues; they are not proof of exploitability without confirming references and data flow.
- Treat short gadget candidates as orientation data only; confirm offsets and runtime mappings inside the provided challenge environment.
- Build exploit hypotheses only inside the provided challenge runtime.

## Forensic

- Confirm container/file types first.
- Build a timeline from metadata, ZIP/GZIP/TAR/TGZ archives, and embedded artifacts.
- Check for hidden layers such as nested archives, slack space, stego, or packet exfiltration traces.
- For USB captures, reconstruct HID keyboard reports and mouse movement before treating the capture as ordinary TCP/IP traffic.

## Misc

- Treat it as classification first, not brute force.
- Check whether it reduces to encoding, stego, logic, scripting, or protocol analysis.
- For text-heavy misc, try deterministic local routes first: base encodings including Base91 and Z85, URL/quoted-printable/UUEncode, DTMF combined frequencies and phone multitap input, A1Z26, NATO phonetic words, Morse, Polybius, DNA 2-bit streams, Bacon, Brainfuck/Ook, ROT/Caesar/Affine/Rail Fence, XOR, zero-width characters, and whitespace stego.
- For file-heavy misc, recurse through archives and generated artifacts before switching to manual tooling. Check PNG/BMP bit planes, fixed-block interleaving, modified PNG dimensions, GIF extension and image-descriptor bits, JPEG segments/DCT stego, MP4 box/chunk-table anomalies, and appended payloads before assuming the visible media is the full challenge.
- For WAV tone challenges, test whether the opening sequence is a training alphabet before assuming the signal is Morse or DTMF.
- Treat model and Pickle-style attachments as untrusted. Extract metadata, tensors, operators, and strings without importing or executing them.
