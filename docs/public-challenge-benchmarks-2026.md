# Public Challenge Benchmarks 2026

This document records validation against recently released public CTF challenges. Challenge assets are not redistributed by CTF Compass; clone the linked upstream repositories to reproduce the checks.

## Sources

- [UofTCTF 2026 public challenges](https://github.com/UofTCTF/uoftctf-2026-chals-public)
- [Jeanne d'Hack CTF 2026](https://github.com/JeanneD-Hack-CTF/JeanneD-Hack-CTF-2026)
- [Fennec CTF 2026 public challenges](https://github.com/Underr00ted/Fennec-CTF-2026-challenges)
- [DownUnderCTF 2025 public challenges](https://github.com/DownUnderCTF/Challenges_2025_Public)

## Results

| Challenge | Category | CTF Compass result | Automated output |
| --- | --- | --- | --- |
| Jeanne d'Hack: Goofy Fantasy | Misc / GIF stego | Solved | Reads packed two-bit values from GIF image descriptors and recovers the published flag. |
| Jeanne d'Hack: Navi's Mania | Misc / MP4 repair | Partial, repair completed | Detects a suspicious trailing `free` box after `moov`, rewrites it to `trak`, and exports a repaired MP4. |
| Jeanne d'Hack: Blind Distribution | Misc / MP4 repair | Partial, repair completed | Detects unsorted `stco`/`co64` chunk offsets, sorts them, and exports a repaired MP4. |
| UofTCTF: babybof | Pwn | Partial static triage | Unpacks the challenge, identifies ELF64 x86-64, partial RELRO, NX, no PIE, no canary, risky `gets`/`printf`/`system`, and prioritizes ret2win/stack-overflow paths. |
| UofTCTF: baby-exfil | Forensic / pcapng | Partial | Extracts HTTP, DNS, TLS SNI, session, and object clues. Full challenge-specific exfil reconstruction remains a manual gap. |
| Fennec CTF: EE | Hardware / VCD / SPI | Solved | Parses the VCD, identifies useful clock/data pairs, samples both edges and bit orders, applies bit reversal and single-byte XOR, and recovers the published flag. |
| Fennec CTF: Ch1p | Hardware / logic CSV | Solved | Detects binary columns, tests common gate expressions and bit orders, and recovers the published flag from the resulting bitstream. |
| Fennec CTF: ARMy | Pwn / AArch64 | Partial static triage | Identifies ELF64 AArch64, protections and fixed-address/GOT paths, suppresses the embedded fake flag, and exports AArch64 `ret`, branch, and `svc` gadget candidates. |
| DownUnderCTF: Down To Modulate Frequencies! | Misc / DTMF text | Solved | Maps four-digit combined frequencies to DTMF keys, applies phone multitap decoding, reads the flag-format hint, and recovers the published flag. |
| DownUnderCTF: BeepBeep | Misc / WAV tones | Solved | Detects the leading 26-tone alphabet, estimates the tone duration, maps the remaining signal, normalizes spoken bracket tokens, and recovers the published flag. |
| DownUnderCTF: scrapbooking | Misc / interleaved PNG | Partial, recovery completed | Detects three round-robin 1024-byte PNG streams, reconstructs each image, trims trailing interleave padding, and generates a text-aligned contact sheet. |
| DownUnderCTF: Fishy Website | Misc / traffic | Correctly partial | Rejects random XOR-produced brace strings instead of incorrectly marking the challenge solved; challenge-specific RC4 key recovery remains a manual gap. |

## Improvements Driven By These Challenges

- Added GIF image-descriptor bitstream extraction.
- Added bounded large-file MP4 analysis and Misc classification.
- Added MP4 top-level box reports, hidden-track repair, and chunk-offset sorting.
- Stopped treating coincidental media/packet magic bytes as appended archives.
- Filtered obvious fake, placeholder, UUID, and transformed-placeholder flag candidates.
- Stopped reporting routine "no decodable text found" outcomes as failed tasks.
- Added VCD clock/data edge sampling with common bit-order and byte-transform recovery.
- Added binary logic-CSV gate-expression enumeration.
- Fixed non-x86 ELF Pwn analysis and added lightweight AArch64, ARM, MIPS, and RISC-V return/syscall gadget scanning.
- Expanded leetspeak fake-flag filtering so obvious decoys do not mark a challenge solved.
- Added DTMF combined-frequency and phone multitap decoding with challenge-provided flag-format wrapping.
- Added bounded Goertzel-based WAV alphabet-tone mapping.
- Added fixed-block round-robin file recovery and aligned PNG contact sheets.
- Raised solved-state confidence and filtered low-diversity or punctuation-heavy random brace strings.

## Reproduction Notes

Run the app against each upstream `dist` attachment or challenge artifact. Generated reports and repaired files are written inside the CTF Compass sandbox. A `partial` result means deterministic local processing completed but the final challenge flag still requires challenge-specific reasoning, exploitation, or interaction.
