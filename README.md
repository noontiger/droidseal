# DroidSeal · Android Release Seal

[English](README.md) | [中文](README.zh-CN.md)

[![License: Apache-2.0](https://img.shields.io/badge/License-Apache--2.0-blue.svg)](https://github.com/noontiger/droidseal/blob/main/LICENSE)
[![npm](https://img.shields.io/npm/v/droidseal.svg?logo=npm)](https://www.npmjs.com/package/droidseal)
[![PyPI](https://img.shields.io/pypi/v/droidseal.svg?logo=pypi)](https://pypi.org/project/droidseal)

**Android Release Seal** helps you do most of what you can do before commercial hardening — environment diagnostics, source & APK audit, R8 obfuscation, zipalign, apksigner signing, and final verification, before commercial hardening, one command, end to end.

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
- **Status**: 1.0.0 stable — the CLI, output layout, and report format are now stable.

## Security boundary

A defensive tool: by default it does not unpack, pack, inject hooks, or add anti-debug code; everything runs locally and never uploads your APK, paths, or signing information.

## License & brand

- Open-source license: [Apache License 2.0](https://github.com/noontiger/droidseal/blob/main/LICENSE)
- Name & logo usage: [TRADEMARKS.md](https://github.com/noontiger/droidseal/blob/main/TRADEMARKS.md) (reviews, tutorials and sharing with attribution are welcome)
- Third-party notices: [THIRD_PARTY_NOTICES.md](https://github.com/noontiger/droidseal/blob/main/THIRD_PARTY_NOTICES.md)

<img src="https://raw.githubusercontent.com/noontiger/droidseal/main/droidseal-logo.png" width="420" alt="DroidSeal" />
