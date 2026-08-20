# DroidSeal · Android Release Seal

[English](README.md) | [中文](README.zh-CN.md)

[![GitHub Stars](https://img.shields.io/github/stars/noontiger/droidseal?style=for-the-badge&logo=github&color=00a8cc)](https://github.com/noontiger/droidseal/stargazers)
[![GitHub Forks](https://img.shields.io/github/forks/noontiger/droidseal?style=for-the-badge&logo=github&color=7aa2ff)](https://github.com/noontiger/droidseal/forks)
[![GitHub Issues](https://img.shields.io/github/issues/noontiger/droidseal?style=for-the-badge&logo=github&color=1d4258)](https://github.com/noontiger/droidseal/issues)
[![Last Commit](https://img.shields.io/github/last-commit/noontiger/droidseal?style=for-the-badge&logo=github&color=00a8cc)](https://github.com/noontiger/droidseal/commits/main)

[![npm Version](https://img.shields.io/npm/v/droidseal?style=for-the-badge&logo=npm&color=00a8cc)](https://www.npmjs.com/package/droidseal)
[![npm Downloads](https://img.shields.io/npm/dm/droidseal?style=for-the-badge&logo=npm&color=7aa2ff)](https://www.npmjs.com/package/droidseal)
[![PyPI Version](https://img.shields.io/pypi/v/droidseal?style=for-the-badge&logo=pypi&color=00a8cc)](https://pypi.org/project/droidseal)
[![PyPI Downloads](https://img.shields.io/pypi/dm/droidseal?style=for-the-badge&logo=pypi&color=7aa2ff)](https://pypi.org/project/droidseal)
[![npm Total Downloads](https://img.shields.io/npm/dt/droidseal?style=for-the-badge&logo=npm&color=00a8cc)](https://www.npmjs.com/package/droidseal)
[![PyPI Total Downloads](https://img.shields.io/pypi/dt/droidseal?style=for-the-badge&logo=pypi&color=00a8cc)](https://pypi.org/project/droidseal)
[![License: Apache-2.0](https://img.shields.io/github/license/noontiger/droidseal?style=for-the-badge&color=1d4258)](https://github.com/noontiger/droidseal/blob/main/LICENSE)

**Android Release Seal** helps you do most of what you can do before commercial hardening — environment diagnostics, source & APK audit, R8 obfuscation, zipalign, apksigner signing, and final verification. One command, end to end.

```bash
$ droidseal
[01] Environment check ........ ok
[02] Prepare workspace ....... ok
[03] Keystore ............... ok
[04] Source security audit ... ok
[05] Build release APK ....... ok
[06] APK security audit ...... ok
[07] Local hardening ......... ok
[08] Release normalization ... ok
[09] Web JS handling ....... skipped (optional)
[10] Resource obfuscation .. skipped (optional)
[11] ZIP alignment .......... ok
[12] APK signing ............ ok
[13] Final verification ..... ok
[14] Report ................ ok
› Final APK and audit report generated
```

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
