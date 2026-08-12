# Third-Party Software, Tools, and Services

除非另有说明，DroidSeal 自身的源代码、文档和示例采用 MIT License。第三方软件继续受各自许可证、通知、服务条款、订阅和分发条件约束，不由 DroidSeal 重新授权。

## JavaScript 与 TypeScript 依赖

### 二进制中实际嵌入的应用组件

| 组件 | 锁定版本 | 许可证 | 上游 |
| --- | ---: | --- | --- |
| Bun runtime | 1.3.14 | Bun 本体 MIT；静态链接组件另见 Bun 官方清单 | https://github.com/oven-sh/bun |
| `@opentui/core` / Windows x64 native core | 0.4.5 | MIT | https://github.com/anomalyco/opentui |
| `@opentui/solid` | 0.4.5 | MIT | https://github.com/anomalyco/opentui |
| `solid-js` | 1.9.12 | MIT | https://github.com/solidjs/solid |
| `terser`（运行时 Web JS 处理部分） | 5.49.0 | BSD-2-Clause | https://github.com/terser/terser |

### 直接开发依赖

| 组件 | 锁定版本 | 许可证 | 上游 |
| --- | ---: | --- | --- |
| `@types/bun` | 1.3.14 | MIT | https://github.com/oven-sh/bun |
| `typescript` | 5.9.3 | Apache-2.0 | https://github.com/microsoft/TypeScript |

`bun.lock` 锁定的传递依赖还包含 MIT、Apache-2.0、BSD-2-Clause、BSD-3-Clause、ISC、BlueOak-1.0.0 和 CC-BY-4.0 许可组件。正式发布源码包或二进制前，应根据锁文件重新生成完整依赖清单，并随发行物提供适用的许可证和 NOTICE 文本。

npm 二进制包不声明 runtime npm dependencies，而是把上述实际运行代码编入 `droidseal.exe`。发行包随附：

- `licenses/Bun-1.3.14-LICENSE.md`：取自 Bun `bun-v1.3.14` 官方标签，列出 JavaScriptCore/WebKit 及其他静态链接组件和相应许可；
- `licenses/OpenTUI-MIT.txt`；
- `licenses/SolidJS-MIT.txt`；
- `licenses/Terser-BSD-2-Clause.txt`。

Bun 官方许可说明明确指出其静态链接 LGPL-2 的 JavaScriptCore/WebKit，并说明修改、重新链接所需材料。DroidSeal 的 MIT 源码、构建脚本和精确 Bun 版本保持在公开仓库；发布者仍应在正式分发前复核 LGPL 重新链接材料及 Bun 清单中各静态库的通知义务。本文件记录工程边界，不构成法律意见。

## 项目治理文档

`CODE_OF_CONDUCT.md` 改编自 Contributor Covenant 2.1，按照 Creative Commons Attribution 4.0 International License 提供。其归属链接已保留在该文件中。

## Android 开发工具

DroidSeal 可能发现、下载、安装或调用第三方提供的工具，包括：

- Bun runtime；
- Java Development Kit 实现和 `keytool`；
- Android SDK Command-line Tools 与 Build Tools；
- `aapt`、`aapt2`、`zipalign` 和 `apksigner`；
- Gradle 和项目自带 Gradle Wrapper。

这些工具不采用 DroidSeal 的 MIT License。通过 DroidSeal 下载、定位、安装或调用组件，不会授予超出组件发布方许可证和条款的任何权利。

## 自动下载的工具

DroidSeal 提供下载选项时会：

- 标明发布方和组件；
- 使用官方或明确受信任的来源；
- 使用发布方提供的 SHA-256 或其他记录在案的完整性机制验证下载；
- 在需要时显示适用许可说明；
- 不静默修改系统 `PATH`；
- 仅在用户明确确认后安装。

用户仍需判断组件许可证和条款是否适用于其组织和用途。Android SDK 组件通过官方 `sdkmanager` 安装，相关许可由组件发布方管理。

## 离线工具链包（`scripts/bundle-toolchain.ts`）

本机工作副本还可运行 `bun run bundle:local`，将已安装的 Bun、Node.js/npm/npx、项目 npm 依赖、JDK 与 Android Build Tools 集中复制到被忽略的 `dependencies/` 目录；`droidseal.cmd` 只在本机使用该目录，不把其中二进制纳入开源发布物。

为支持无网络环境运行，DroidSeal 提供 `bun run bundle:toolchain` 脚本，在**用户自己的联网机器**上预取并校验 Eclipse Temurin 21 与 Android SDK Build Tools，生成便携目录 `droidseal-bundle/`（含 `bundle-manifest.json` 的 SHA-256 清单）。使用者将其复制到 `~/.droidseal/bundle` 或用 `DROIDSEAL_BUNDLE_DIR` 指向它，DroidSeal 即可离线解析这些工具。

关于许可与再分发：

- **Eclipse Temurin（OpenJDK）** 采用 GPLv2 with Classpath Exception，其二进制由 Adoptium 官方源下载并按发布方 SHA-256 校验。
- **Android SDK Build Tools** 受 Android SDK Terms and Conditions 约束，**通常禁止再分发**。因此该脚本只在运行者本机通过官方 `sdkmanager` 安装（视为运行者已接受 Google 许可），DroidSeal **不随仓库或 npm 包分发任何 JDK 或 Android SDK 二进制**（`droidseal-bundle/` 已在 `.gitignore` 排除）。
- 生成的离线包仅供运行者在其被授权的机器/组织内部使用；对外再分发该包须自行确认符合上述上游条款。

## 第三方商标

Android、Java、Gradle、Bun、OpenTUI、Solid 及其他第三方产品名称和商标归各自权利人所有。它们出现在 DroidSeal 文档中仅表示技术引用、兼容或互操作，不表示背书或赞助。

## 正式发行物

正式发行物应由 CI 生成并附带：

- 打包依赖及版本清单；
- SPDX 许可证标识和必需许可证文本；
- SBOM；
- SHA-256 校验和；
- 构建来源证明或 artifact attestation；
- 无法识别许可证的依赖告警。

本文件是总体政策，不替代每个正式版本对应的依赖许可证清单。