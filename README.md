# DroidSeal · Android Release Seal

[English](README.md) | [中文](README.zh-CN.md)

[![License: Apache-2.0](https://img.shields.io/badge/License-Apache--2.0-181717.svg?logo=github&logoColor=white)](https://github.com/noontiger/droidseal/blob/main/LICENSE)
[![npm](https://img.shields.io/npm/v/droidseal.svg?logo=npm&logoColor=white&color=cb3837)](https://www.npmjs.com/package/droidseal)
[![PyPI](https://img.shields.io/pypi/v/droidseal.svg?logo=pypi&logoColor=white&color=3775a9)](https://pypi.org/project/droidseal)

**Android Release Seal** helps you do most of what you can do before commercial hardening — environment diagnostics, source & APK audit, R8 obfuscation, zipalign, apksigner signing, and final verification. One command, end to end.

## What it does

- **Audit**: static audit of projects and APKs — permissions, targetSdk, signing schemes, hardcoded secrets, DEX/TLS heuristics, native library hardening, third-party dependencies, and a CycloneDX SBOM;
- **Release**: runs `zipalign → apksigner sign → verify` in the official order, with automatic rollback on failure and independent artifacts per step;
- **Outputs**: APK + SHA-256 + JSON/Markdown reports + a release gate + SBOM.

<img width="960" alt="DroidSeal interface screenshot" src="droidseal-screenshot.png" />

## Install

| Channel | How |
|---|---|
| npm | `npm install --global droidseal` |
| PyPI | `pip install droidseal` |
| GitHub Releases | Download the Windows zip / Linux tar.gz directly |

> **Windows note**: if SmartScreen blocks the exe when double-clicked, right-click → Properties → Unblock. The TUI needs a terminal: run `droidseal` in PowerShell, or double-click the bundled `droidseal-gui.cmd` launcher.

## Usage

```powershell
droidseal              # Interactive TUI wizard (one-click / guided)
droidseal doctor       # Non-interactive environment diagnostics
droidseal --version
```

## Platform & status

- **Platforms**: Windows x64 / Linux x64;
- **Status**: 1.0.0 stable — the CLI, output layout, and report format are now stable;
- **Software requirements**: an ANSI/Unicode-capable interactive monospace terminal (required for the TUI); Bun 1.3+ for source runs; JDK/Gradle/Android Build Tools are auto-discovered or downloaded per flow (Node only for Capacitor Web builds);
- **Hardware (practical, not hard limits)**: ~500 MB disk (the 100 MB executable + toolchain + outputs), ≥2 GB RAM (more for large APKs — parsing is memory-sensitive with failure-safe limits), x64 dual-core CPU.

## Security boundary

A defensive tool: by default it does not unpack, pack, inject hooks, or add anti-debug code; everything runs locally and never uploads your APK, paths, or signing information.

## Architecture, innovation & self-developed parts

### Innovation highlights

1. **Fully self-developed APK format handling**: byte-level ZIP/ARSC/AXML/DEX/ELF parsing and rewriting with no heavy parser dependencies (supply-chain convergence, explicit failure semantics);
2. **Deterministic post-processing**: unmodified ZIP entries reuse the original compressed bytes to avoid reordering/recompression/signature-digest churn;
3. **Failure rollback**: each step uses an independent APK artifact; "skip and roll back" keeps the last valid output;
4. **Self-developed anti-debug stub** (C + Kotlin + CMake, opt-in source integration);
5. **Auditable results**: signature verification + SHA-256 + JSON/Markdown reports + CycloneDX SBOM + confidence-aware release gate;
6. **Local-first by default**: never uploads APKs, paths or signing info; no unpacking/packing/hook injection out of the box;
7. **Single binary, three channels**: Bun-compiled single-file executable with zero runtime npm dependencies, published to npm/PyPI/GitHub Releases from one source;
8. **Bilingual TUI with three entry points** (guided / one-click / doctor).

### Self-developed vs third-party calls

- **Self-developed (business core)**: `src/core` (30 modules — ZIP/DEX/ELF/ARSC/AXML parsing & audit, pipeline orchestration, signing policy, release gate), `src/ui` (TUI + i18n), the anti-debug stub, `scripts` (build/release/gate tooling), dual launchers;
- **Third-party (rendering/build layer)**: OpenTUI (terminal rendering), Solid.js (reactive UI), Terser (build compression; only for opt-in Web JS handling), TypeScript/Bun (toolchain), external Android tools (keytool/Gradle/zipalign/apksigner/aapt — discovered and validated by DroidSeal itself).

### Pipeline visualization (per-step self/third-party)

The route winds top-to-bottom: left column ①-⑦ goes down, then the flow turns at the bottom and the right column ⑧-⑭ goes back up (S-shape). Each box shows "Self: …" or "3rd-party: …".

```text
① Environment check — Self: discovery/validation/restore
↓
② Prepare workspace — Self: input validation/APK copy
↓
③ Keystore — 3rd-party: keytool / Self: secret-safe
↓
④ Source audit — Self: project-audit/r8-rules
↓
⑤ Build release APK — 3rd-party: Gradle Wrapper
↓
⑥ APK audit — Self: ZIP/DEX/ELF/ARSC/AXML / 3rd-party: aapt
↓
⑦ Local hardening — Self: evidence/confidence
↓
⑧ Release normalization — Self: manifest rewrite/debug cleanup
↓
⑨ Web JS handling (opt-in) — 3rd-party: Terser / Self: whitelist/atomic write
↓
⑩ Resource obfuscation (opt-in) — Self: arsc-obfuscate
↓
⑪ ZIP alignment — 3rd-party: zipalign
↓
⑫ APK signing — 3rd-party: apksigner / Self: key handling/redaction
↓
⑬ Final verification — 3rd-party: apksigner verify / Self: SHA-256
↓
⑭ Report — Self: report/gate/SBOM/fix packs
```

All format parsing/rewriting/audit/reporting is self-developed (offline, low supply-chain footprint); rendering uses OpenTUI/Solid (third-party); external tools are only invoked where the official toolchain requires them, always through DroidSeal's own discovery, SHA-256 validation and fallback orchestration.

## License & brand

- Open-source license: [Apache License 2.0](https://github.com/noontiger/droidseal/blob/main/LICENSE)
- Name & logo usage: [TRADEMARKS.md](https://github.com/noontiger/droidseal/blob/main/TRADEMARKS.md) (reviews, tutorials and sharing with attribution are welcome)
- Third-party notices: [THIRD_PARTY_NOTICES.md](https://github.com/noontiger/droidseal/blob/main/THIRD_PARTY_NOTICES.md)

<img src="https://raw.githubusercontent.com/noontiger/droidseal/main/droidseal-logo.png" width="420" alt="DroidSeal" />
