# DroidSeal · 安卓发布封签

[English](README.md) | [中文](README.zh-CN.md)

[![License: Apache-2.0](https://img.shields.io/badge/License-Apache--2.0-181717.svg?logo=github&logoColor=white)](https://github.com/noontiger/droidseal/blob/main/LICENSE)
[![npm](https://img.shields.io/npm/v/droidseal.svg?logo=npm&logoColor=white&color=cb3837)](https://www.npmjs.com/package/droidseal)
[![PyPI](https://img.shields.io/pypi/v/droidseal.svg?logo=pypi&logoColor=white&color=3775a9)](https://pypi.org/project/droidseal)

**安卓发布封签**帮你完成商业加固前能做的大多数事——环境诊断、源码与 APK 审计、R8 混淆、zipalign 对齐、apksigner 签名与最终验证，商业加固前，一键端到端。

## 能做什么

- **审计**：项目与 APK 静态审计——权限、targetSdk、签名方案、硬编码密钥、DEX/TLS 启发式、Native so 加固、第三方依赖与 CycloneDX SBOM；
- **发布**：按官方顺序执行 `zipalign → apksigner 签名 → 验证`，失败自动回退，每步独立制品；
- **产物**：APK + SHA-256 + JSON/Markdown 报告 + 发布门禁 + SBOM。

<img width="960" alt="DroidSeal 界面截图" src="droidseal-screenshot.png" />

## 安装

| 渠道 | 方式 |
|---|---|
| npm | `npm install --global droidseal` |
| PyPI | `pip install droidseal` |
| GitHub Releases | 直接下载 Windows zip / Linux tar.gz |

> **Windows 提示**：双击 exe 被 SmartScreen 拦截时，右键 → 属性 → 解除锁定。TUI 需在终端中运行：PowerShell 执行 `droidseal`，或双击随包附带的 `droidseal-gui.cmd` 启动器。

## 使用

```powershell
droidseal              # 交互式 TUI 向导（一键 / 分步）
droidseal doctor       # 非交互环境诊断
droidseal --version
```

## 平台与状态

- **平台**：Windows x64 / Linux x64；
- **状态**：1.0.0 正式版——CLI、输出目录与报告格式现已稳定；
- **软件要求**：支持 ANSI/Unicode 的交互式等宽字体终端（TUI 必需）；源码运行需 Bun 1.3+；JDK/Gradle/Android Build Tools 按流程自动发现或下载（Node 仅 Capacitor Web 构建时）；
- **硬件（实用建议，非硬性下限）**：约 500 MB 磁盘（100 MB 可执行文件 + 工具链 + 产物）、≥2 GB 内存（大 APK 更高——解析内存敏感，带失败安全上限）、x64 双核 CPU。

## 安全边界

防御性工具：默认不脱壳、不加壳、不注入 Hook / 反调试代码；完全本地运行，不上传 APK、路径或签名信息。

## 架构、创新与自研部分

### 创新亮点

1. **APK 格式处理全自研**:ZIP 中央目录、ARSC 资源表、AXML、DEX、ELF 的解析与改写全部自研(字节级),不依赖庞大解析器传递依赖(供应链收敛、失败语义明确);
2. **确定性后处理**:未修改的 ZIP 条目复用原始压缩字节,减少重排/重压缩/签名摘要的意外变化;
3. **失败可回退**:每步独立 APK 制品,"跳过并回退"保留步骤前有效产物;
4. **自研反调试桩**(C + Kotlin + CMake,可选源码集成);
5. **结果可审计**:签名验证 + SHA-256 + JSON/Markdown 报告 + CycloneDX SBOM + 置信度感知发布门禁;
6. **纯本地优先**:不上传 APK、路径或签名信息;默认不脱壳、不加壳、不注入;
7. **单二进制三渠道发布**:Bun 编译单文件 exe,运行时零 npm 依赖,npm/PyPI/GitHub Release 同源发布;
8. **双语 TUI + 三入口**(分步/一键/诊断)。

### 自研部分 vs 第三方调用

- **自研**(业务核心):`src/core`(30 个模块——ZIP/DEX/ELF/ARSC/AXML 解析与审计、流水线编排、签名策略、发布门禁)、`src/ui`(TUI + i18n)、反调试桩、`scripts`(构建/发布/门禁脚本)、双启动器;
- **第三方**(渲染/构建层):OpenTUI(终端渲染)、Solid.js(响应式 UI)、Terser(构建压缩,仅可选 Web JS 处理)、TypeScript/Bun(工具链)、外部 Android 工具(keytool/Gradle/zipalign/apksigner/aapt——经自研发现与校验编排)。

### 流水线可视化(每步自研/第三方)

路线从上到下弯折:左列 ①-⑦ 自上而下,底部「流向」折返后右列 ⑧-⑭ 自下而上(蛇形)。每步箱内标注「自研:…」或「第三方:…」。

```text
┌──────────────────────────────┐      ┌──────────────────────────────┐
│ ① 环境诊断                   │      │ ⑭ 生成报告                   │
│ 自研:工具发现/校验/恢复        │      │ 自研:报告/门禁/SBOM/修复包     │
└──────────────────────────────┘      └──────────────────────────────┘
              │                                    ▲
              ▼                                    │
┌──────────────────────────────┐      ┌──────────────────────────────┐
│ ② 准备工作区                 │      │ ⑬ 最终验证                   │
│ 自研:输入验证/APK 复制         │      │ 第三方:apksigner verify      │
└──────────────────────────────┘      │ 自研:SHA-256 计算/编排        │
              │                        └──────────────────────────────┘
              ▼                                    ▲
┌──────────────────────────────┐      ┌──────────────────────────────┐
│ ③ 签名库                     │      │ ⑫ APK 签名                   │
│ 第三方:keytool                │      │ 第三方:apksigner              │
│ 自研:密码安全处理              │      │ 自研:密钥处理/脱敏             │
└──────────────────────────────┘      └──────────────────────────────┘
              │                                    ▲
              ▼                                    │
┌──────────────────────────────┐      ┌──────────────────────────────┐
│ ④ 源码安全审计               │      │ ⑪ ZIP 对齐                   │
│ 自研:project-audit/r8-rules  │      │ 第三方:zipalign               │
└──────────────────────────────┘      └──────────────────────────────┘
              │                                    ▲
              ▼                                    │
┌──────────────────────────────┐      ┌──────────────────────────────┐
│ ⑤ 构建 Release APK           │      │ ⑩ 资源名混淆(可选)            │
│ 第三方:Gradle Wrapper         │      │ 自研:arsc-obfuscate           │
└──────────────────────────────┘      └──────────────────────────────┘
              │                                    ▲
              ▼                                    │
┌──────────────────────────────┐      ┌──────────────────────────────┐
│ ⑥ APK 安全审计               │      │ ⑨ Web JS 处理(可选)           │
│ 自研:ZIP/DEX/ELF/ARSC/AXML   │      │ 第三方:Terser 压缩             │
│ 第三方:aapt 补充              │      │ 自研:白名单/原子写出           │
└──────────────────────────────┘      └──────────────────────────────┘
              │                                    ▲
              ▼                                    │
┌──────────────────────────────┐      ┌──────────────────────────────┐
│ ⑦ 本地安全防护               │      │ ⑧ Release 归一化              │
│ 自研:证据核验/置信度           │      │ 自研:Manifest 改写/调试清理    │
└──────────────┬───────────────┘      └──────────────┬───────────────┘
               └──────────────► 流向 ──►──────────────┘
```

所有格式解析/改写/审计/报告均为自研(离线、低供应链依赖);渲染用 OpenTUI/Solid(第三方);外部工具只在官方强制环节调用,均经自研发现、SHA-256 校验与降级编排。

## 许可与品牌

- 开源许可：[Apache License 2.0](https://github.com/noontiger/droidseal/blob/main/LICENSE)
- 名称与 Logo 使用：[TRADEMARKS.md](https://github.com/noontiger/droidseal/blob/main/TRADEMARKS.md)（评测、教程、分享注明来源即可）
- 第三方声明：[THIRD_PARTY_NOTICES.md](https://github.com/noontiger/droidseal/blob/main/THIRD_PARTY_NOTICES.md)

<img src="https://raw.githubusercontent.com/noontiger/droidseal/main/droidseal-logo.png" width="420" alt="DroidSeal" />
