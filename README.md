# DroidSeal

**Android 发布封签**

**A simple, local-first Android release security pipeline.**

**一个简单易用、本地优先的 Android 安全发布流水线。**
<img width="1920" height="1020" alt="screenshot" src="https://github.com/user-attachments/assets/6a6033c5-a82b-4fb4-bcfe-dfbfa9958b5b" />
```text
██████╗ ██████╗  ██████╗ ██╗██████╗ ███████╗███████╗ █████╗ ██╗
██╔══██╗██╔══██╗██╔═══██╗██║██╔══██╗██╔════╝██╔════╝██╔══██╗██║
██║  ██║██████╔╝██║   ██║██║██║  ██║███████╗█████╗  ███████║██║
██║  ██║██╔══██╗██║   ██║██║██║  ██║╚════██║██╔══╝  ██╔══██║██║
██████╔╝██║  ██║╚██████╔╝██║██████╔╝███████║███████╗██║  ██║███████╗
╚═════╝ ╚═╝  ╚═╝ ╚═════╝ ╚═╝╚═════╝ ╚══════╝╚══════╝╚═╝  ╚═╝╚══════╝
```

DroidSeal is a simple, local-first Android release security pipeline for building, auditing, aligning, signing, verifying, and reporting Android release artifacts.

DroidSeal（Android 发布封签）将 Android 发布产物的构建、审计、对齐、签名、验证和报告组织成一条完全在本地运行、步骤清晰、失败可回退且结果可审计的安全发布流水线。

- **简单易用**：通过分步向导和一键流程降低 Android 发布工具链的使用门槛；
- **本地优先**：不连接模型服务，不上传 APK、文件路径或签名凭据；
- **结果可验证**：输出签名验证结果、SHA-256、JSON 和 Markdown 报告；
- **步骤可回退**：每一步使用独立制品，失败后恢复最近的有效 APK；
- **边界明确**：默认不注入脱壳、Hook、反调试或运行时篡改代码。

## 能做什么

- 从已有 APK 开始，或调用 Android 项目的 Gradle Wrapper 构建 release APK。
- 审计项目中的 R8、资源优化、Manifest 和明文签名密码风险。
- 审计 APK 的 ZIP 中央目录、路径穿越、重复条目、极端压缩比、DEX、SO 架构和二进制 Manifest；Manifest 优先由内置 AXML 解析器直读，`aapt` 作为元数据补充与回退。
- 深度静态审计（纯本地、纯静态、只读，不改写 APK）：权限模型与高风险权限、targetSdk/64 位合规、签名方案与证书深度、深链与导出组件、meta-data/资源/DEX/.so 中的硬编码密钥、DEX 弱加密与不安全 TLS 等启发式风险、Native .so 加固（NX/RELRO/Canary/FORTIFY/TEXTREL）、网络安全配置与备份规则（源码与 APK AXML）、第三方 SDK/依赖清单及 CycloneDX SBOM（不做在线 CVE/许可证猜测）。
- 执行安全审计基线，记录 DEX 未加密、无反调试、无完整性校验等残留风险。
- 按 Android 官方顺序执行 `zipalign → apksigner sign → apksigner verify`。
- 使用已有 JKS/PKCS12，或根据逐项提示创建新签名库。
- 每步使用独立 APK 文件；失败时解释原因，执行“跳过并回退”，保留步骤前的有效产物。
- 最终输出 APK、SHA-256、JSON/Markdown 报告；源码构建额外输出精确 Gradle 变体的 R8 发布证据 manifest；所有输入输出 CycloneDX SBOM、许可证待核验清单、置信度感知发布门禁与纵深防御覆盖矩阵；对 NSC、备份等可模板化发现自动生成不覆盖源码的修复包与机器可读计划。

## 当前状态与支持范围

- **版本阶段**：Alpha（`0.1.0`）。CLI、输出目录和报告格式在 `1.0.0` 前仍可能调整；
- **输入范围**：已有 APK，或能够通过 Gradle Wrapper 生成 APK 的 Android 应用项目；
- **产物范围**：当前处理 APK，不支持 AAB，也不宣称支持 Play App Signing；
- **交互方式**：完整处理流程使用交互式 TUI；非交互命令目前提供 `doctor`、`--help` 和 `--version`；
- **平台状态**：当前主要在 Windows 完成实际流程验证；macOS 和 Linux 仍需持续验证终端、JDK 与 Android Build Tools 兼容性；
- **终端要求**：启动 TUI 需要支持 ANSI/Unicode 的交互式等宽字体终端。

## 安全边界

DroidSeal 面向你拥有或获授权处理的 Android 应用，提供防御性发布加固工作流。

内置功能不会自动执行脱壳、绕过 HTTPS 证书校验、绕过 root/Frida/Xposed 检测、内存篡改、未授权 Hook 或代码提取。相关攻击方法只作为威胁模型，转换为合法的防护检查和工程建议。

DEX 加密、VMP、类抽取、自定义类加载器等不是通用 ZIP 后处理。它们需要和应用启动链路集成，并经过设备、ROM、Android 版本和商店渠道的兼容测试。因此 DroidSeal：

1. 默认执行可验证的审计、对齐、签名和验证；
2. 保护步骤只做安全审计基线，不改写 DEX，也不内置或调用加壳/VMP 工具；
3. 主动加固需你在源码接入授权方案后再构建，其产物仍会重新对齐、签名和验证；
4. 报告会明确区分“已验证”和“仅建议”的控制项。

## 快速开始

通过 npm 全局安装（Windows x64）：

```powershell
npm install --global droidseal
droidseal
```

非交互环境诊断和命令帮助：

```powershell
droidseal doctor
droidseal --help
```

### 从源码运行（面向开发者）

要求 Bun 1.3 或更高版本：

```powershell
cd C:\Users\User\DroidSeal
bun install --frozen-lockfile
bun run dev
bun src/index.tsx doctor
bun src/index.tsx --help
```

### npm 二进制发布（Windows x64）

发布构建不会修改 `src/`：它先用 Bun bundle 和锁定的 Terser 5.49.0 做保守压缩、顶层标识符 mangle，再用 `bun --compile` 生成 `dist/droidseal.exe`。中间 JavaScript 位于临时目录并在构建结束后删除；npm tarball 的白名单不包含 `src/`、`scripts/`、`tests/`、`docs/`、技术路线、锁文件或 source map。

```powershell
bun run build
node .\bin\droidseal.cjs --version
npm pack --dry-run
# 登录并确认包内容后：
npm publish
```

发布后的安装与运行方式：

```powershell
npm install --global droidseal
droidseal
```

`bin/droidseal.cjs` 只负责校验 `droidseal.exe` 的 SHA-256、设置 OpenTUI 资源目录并透传参数；业务实现位于编译后的 PE 可执行文件中。OpenTUI 的 Windows x64 原生 DLL 被嵌入 exe，worker/WASM/查询文件按哈希清单随包发布，普通安装不再下载运行时 npm 依赖。`package.json` 通过 `os`/`cpu` 明确拒绝非 Windows x64 平台。

这能阻止从 npm 包直接取得 DroidSeal 的 TypeScript/TSX 和 source map，并显著提高静态阅读门槛，但**不能承诺源码不可逆**：客户端二进制始终可能被专业逆向，而且公开 MIT 仓库本身仍提供源码。构建没有套 UPX 等通用压缩壳，以免明显增加杀毒软件启发式误报；秘密、授权决策和高价值规则仍不应只放在客户端。
### 本机完整依赖目录（Windows）

运行下列命令会把本机 Bun、Node.js/npm/npx、锁定的 npm 包、JDK 与 Android Build Tools 复制到项目内的 `dependencies/`：

```powershell
bun run bundle:local
.\droidseal.cmd
```

`droidseal.cmd` 会设置隔离的 `JAVA_HOME`、`ANDROID_SDK_ROOT`、`NODE_PATH` 和 `PATH`，确保优先使用项目内依赖。Gradle Wrapper 与匹配的 Gradle 发行版仍由待处理的 Android 项目自身提供，因为它们取决于该项目的 AGP/Gradle 版本。

正式发布后的包名和命令名统一为 `droidseal`；发布前应先执行本文“开发与验证”中的完整检查。

## 工具自动发现

DroidSeal 会按以下顺序定位工具：

1. 项目内 `dependencies/` 或 `DROIDSEAL_BUNDLE_DIR`；
2. 当前 `PATH`；
3. `JAVA_HOME/bin`；
4. `ANDROID_SDK_ROOT`；
5. `ANDROID_HOME`；
6. Windows 的 `%LOCALAPPDATA%\Android\Sdk`；
7. macOS/Linux 的常见 Android SDK 目录；
8. DroidSeal 管理的 `~/.droidseal/tools`；
9. Android 项目根目录的 `gradlew` 或 `gradlew.bat`。

所选流程可能使用：

| 工具 | 用途 | 是否可以降级 |
| --- | --- | --- |
| Bun | 运行 DroidSeal | 否 |
| Java/JDK | Gradle、keytool、apksigner | 对已有未签名审计可部分降级 |
| Gradle Wrapper | 从源码构建 APK | 输入已有 APK 时不需要 |
| aapt | 读取二进制 Manifest 和包元数据 | 缺失时保留 ZIP 审计，并报告降级 |
| zipalign | 签名前对齐及最终验证 | 可由用户跳过，但不推荐 |
| apksigner | APK 签名和签名验证 | 选择“不签名”时可跳过 |
| keytool | 验证或创建签名库 | 选择“不签名”时可跳过 |

### 缺失工具恢复

环境诊断发现所选流程的必需工具不可用时，会在启动构建或签名前暂停，并提供：

- **下载并继续**：从 Android 官方仓库或 Eclipse Adoptium 官方 API 下载；
- **查看安装说明**：显示手动安装和 Gradle Wrapper 修复方式；
- **已安装，重新检测**：保留向导配置和现有步骤，从环境诊断处重新检查并继续。

自动下载的归档会使用发布方提供的 SHA-256 校验。验证成功后才会解压到用户目录下的 `.droidseal/tools`，不会静默修改系统 `PATH`。Android Build Tools 通过官方 `sdkmanager` 安装；点击下载按钮表示用户确认对应官方组件许可。

Gradle Wrapper 与具体项目的 Android Gradle Plugin/Gradle 版本绑定，因此不会自动猜测生成。缺失时会提示从版本库恢复，或用匹配版本的 Gradle 创建。


## 两种操作模式

### 分步处理

每一步执行前再次显示用途和影响。可以点击“执行此步”，或对可选步骤点击“跳过”。

如果步骤失败：

1. 部分输出只会位于本次运行的 `artifacts` 目录；
2. 失败输出会被移除；
3. `currentArtifact` 恢复为步骤开始前的 APK；
4. 界面显示分类错误、详细解释和修复建议；
5. 点击“跳过并回退，进入下一步”继续。

### 一键处理

填写所有必要信息后，14 个步骤连续执行。一般步骤失败会自动回退并继续；如果所选流程缺少必需工具，则暂停并等待下载或手动修复，检测通过后自动续跑。依赖缺失 APK 的后续步骤会明确说明并跳过，报告步骤仍会尽量运行。

### 如何理解“跳过”

“跳过”表示本步骤没有执行或没有改写 APK，但不一定是失败。TUI 和报告会显示具体类型：

| 跳过类型 | 含义 | 示例 |
| --- | --- | --- |
| 不适用 | 当前输入不需要这一步 | 输入 APK 时不执行源码审计和 Gradle 构建 |
| 用户选择 | 分步模式中用户主动跳过 | 手动跳过 APK 安全审计 |
| 按配置 | 向导配置决定不执行 | 安全审计基线不改写 APK |
| 安全保护 | 为避免破坏有效产物而跳过 | 保留现有 v2/v3 签名时不重新 zipalign |
| 缺少前置 APK | 前面的失败导致没有可处理文件 | 构建失败后无法执行 apksigner |

右侧进度面板分别显示“已处理、成功、跳过、失败”。跳过会计入“已处理”，并自动跟随当前步骤；最终总结会列出每个跳过步骤的类型。

例如，输入一个已有有效签名的 APK，同时选择“不重新签名”时，面板仍会显示“已处理 14”；源码审计、Gradle 构建、签名库、签名以及不适用或按安全策略不执行的后处理会分别标为跳过，具体成功/跳过数量取决于配置和 APK 状态。

这表示 14 步都已得到结果，并不是只有标为“成功”的步骤得到了处理。判断整个流程是否走完请看“已处理”，判断是否出现问题请看“失败”和各步骤解释。

## 聊天与快捷命令

首页可以直接输入“一键处理”“分步处理”或“环境诊断”。

| 命令 | 作用 |
| --- | --- |
| `/guided` | 开始分步向导 |
| `/oneclick` | 开始一键向导 |
| `/doctor` | 检查 JDK 和 Android SDK |
| `/help` | 显示操作和安全边界 |
| `/restart` | 返回首页，开始新任务 |
| `/quit` | 退出 |

聊天解析器是本地确定性状态机，不会把用户输入发送给第三方。

### 交互区域缩放

缩放仅作用于左下角交互区域，顶部状态区和右下角处理进度保持稳定：

| 操作 | 作用 |
| --- | --- |
| `Ctrl` + `+` / `=` | 放大一级 |
| `Ctrl` + `-` | 缩小一级 |
| `Ctrl` + `0` | 恢复 100% |
| `Ctrl` + 鼠标滚轮 | 向上放大、向下缩小 |

倍率范围为 80%–150%，当前值显示在输入区和底栏。支持 Kitty 键盘协议的终端会把组合键交给 DroidSeal；如果宿主终端截获组合键，则由宿主终端执行真实字体缩放。TUI 无法通过通用终端协议强制修改宿主字体大小，因此 DroidSeal 调整的是交互区域的间距与内容密度。

## 向导会询问的内容

### 输入与构建

- 输入类型：已有 APK 或 Android 项目。
- APK 文件/项目根目录。
- Gradle 任务，默认 `assembleRelease`。
- 可选的自定义构建 APK 路径；留空时自动选择最新 APK。
- 输出目录：APK 输入默认使用 APK 同级的 `droidseal-output`，项目输入默认使用项目根目录下的 `droidseal-output`，可直接回车采用默认值。

Android 项目构建只使用项目自己的 Wrapper：

```text
gradlew.bat <task> --console=plain --no-daemon
```

命令以参数数组直接启动，不通过 shell 拼接。

### 应用保护

DroidSeal 默认使用 **local-safe 本地安全档**：源码输入会审计并在 release 未开启时强制 R8/资源裁剪；APK 侧继续完成 `debuggable=false`、调试残留清理、严格静态审计、可选 Web JavaScript 发布处理、可选资源名混淆、对齐、签名与最终验证。默认不重写既有 DEX 业务方法，也不劫持未知 APK 的 Application 启动链。

保护步骤依据已有证据生成覆盖清单，不再固定声称某项能力“不存在”：

| 发现 | 证据规则 |
| --- | --- |
| `DEX_STANDARD_FORMAT_PRESENT` | APK 结构直接确认存在标准 `classes*.dex`，属于已确认的商业加壳边界。 |
| `ANTI_DEBUG_NOT_OBSERVED` | 严格扫描未观察到反调试信号；只按低置信度提示，不能证明功能不存在。 |
| `RUNTIME_INTEGRITY_NOT_OBSERVED` | 未观察到 attestation/签名自检信号；同样只作低置信度覆盖提示。 |

审计结果带“已确认/高/中/低”证据置信度。源码侧尽量定位具体调用与参数；DEX 字符串池只有在 API、动作或危险字面量形成交叉证据时才上报风险。单独出现 `Runtime`、`ProcessBuilder`、`MD5`、WebView setter 或 PendingIntent 类名不会直接判为漏洞。

商业加固（DEX 加密/抽取、VMP、成熟运行时壳）需要专用加载器、设备兼容性矩阵和持续维护，不由 DroidSeal 对未知 APK 事后合成。如确有需要，请在**源码**接入已获授权的方案后再构建，DroidSeal 会在其后照常审计、对齐、签名并验证。

#### 混合应用 Web JavaScript 发布处理

向导可显式开启 Terser 发布处理。DroidSeal 只处理 APK 中严格路径白名单 `assets/public/**/*.js` 与 `assets/www/**/*.js`，并移除这些目录下的 source map；不会猜测或改写其他资产目录。它会从各目录的 `index.html` 识别 `<script type="module" src="...">`：ES module 可安全执行顶层标识符 mangle，普通脚本则保留可能被 HTML、插件桥接或其他脚本调用的顶层全局名，只压缩并混淆局部标识符。

所有目标脚本必须先在内存中完成 UTF-8 解码、Terser 解析和转换，随后重建 APK 并重新解析核对条目数、Manifest、脚本内容及 source map 移除结果，最后才原子写出新 APK。任一脚本语法失败、ZIP 大小异常、重复目标条目或资源上限超限都会整步回退，不留下半成品。

该步骤会使原 APK 签名失效，因此在选择“不重新签名”且现有签名有效或无法确认时，以 `WEB_ASSET_MINIFY_SKIPPED_TO_PRESERVE_SIGNATURE` 保守跳过。启用时应配置发布签名库，并在输出后真机回归启动、路由、懒加载、离线资源与 Capacitor/Cordova 插件桥接。

Terser 只提高直接阅读和复制 JavaScript 的门槛，**不等于源码保密**。字符串、协议和客户端算法仍可被动态观察；密钥、授权判断与高价值业务规则必须放到服务端。

#### WebView 调试 release 审计

对使用 WebView 的 Android application 模块，源码审计会忽略注释和字符串示例，并只用 `src/main`、`src/release`、`src/debug` 中可复核的调用形成四态结论：

| 状态 | finding | 门禁语义 |
| --- | --- | --- |
| 显式 `false`，无 release true/动态参数 | `SOURCE_WEBVIEW_DEBUGGING_EXPLICITLY_DISABLED` | 已观察到明确关闭；仍需 release 真机确认 DevTools 不可发现 |
| 仅 `BuildConfig.DEBUG` 条件/参数或 `src/debug` 为 true | `SOURCE_WEBVIEW_DEBUGGING_DEBUG_ONLY` | 已观察到仅调试构建开启 |
| main/release 中无保护的 true，或逻辑在 release 为 true | `SOURCE_WEBVIEW_DEBUGGING_ENABLED_IN_RELEASE` | confirmed high，发布门禁进入 `review` |
| 未见显式关闭，或参数无法静态解析 | `SOURCE_WEBVIEW_DEBUGGING_NOT_EXPLICITLY_DISABLED` | low-confidence 提示，不阻断、不声称功能一定开启 |

扫描达到文件数/字符上限时，除已经直接观察到的 release true 外，只输出 `SOURCE_WEBVIEW_DEBUGGING_AUDIT_INCOMPLETE`，不会误称“已关闭”。自定义 flavor source set、反射与运行时配置仍需人工核对；推荐在 `Application.onCreate` 且首个 WebView 创建前显式调用 `WebView.setWebContentsDebuggingEnabled(false)`。

#### opt-in 构建期反调试 stub（自研）

针对 `ANTI_DEBUG_NOT_OBSERVED` 覆盖提示，DroidSeal 附带一个**自研、可选**的构建期反调试 stub（`src/assets/antidebug-stub`）：JNI（`droidseal_antidebug.c` + `CMakeLists.txt`）读取 `/proc/self/status` 的 TracerPid、扫描 `/proc/self/maps` 的注入框架特征，配合 Kotlin 封装（`DroidSealAntiDebug.kt`）暴露检测结果，由应用自行决定命中后的处置。除启动期 `guard/inspect` 外，`guardOnActivityResumed` 可在 Activity `onResume` 以进程级默认两秒节流复查，覆盖启动后附加调试器的部分空窗；节流时返回 `null`，不会反复扫描 `/proc/maps`。

```shell
bun scripts/install-antidebug-stub.ts <app-module-dir> [--force]
```

它是**检测型**能力，由应用在源码集成、编译期经 NDK/CMake 链接（不是对成品 APK 事后注入），可被绕过、有误伤风险且不做处置；恢复态 API 也只返回/回调信号，不 kill、不退出、不改变应用行为。上线前必须覆盖设备、ROM、Android 版本与关键 Activity 恢复路径的真机矩阵，并与服务端风控/授权控制组合使用。详见写入的 `droidseal-antidebug/INTEGRATION.md`。

### 签名

可以选择：

- 使用现有签名库；
- 新建签名库；
- 暂不签名。

选择“暂不签名”时，DroidSeal 仍会在 `apksigner` 可用时验证输入 APK 的现有签名。若检测到有效签名，任何会重建 ZIP 的步骤都会自动跳过——Release 归一化不再剔除残留条目（`HARDEN_SKIPPED_TO_PRESERVE_SIGNATURE`），ZIP 对齐步骤也会跳过——避免改写 APK 后破坏已有签名；最终产物使用 `guarded-signed-preserved` 后缀并在报告中标记“已通过验证”。未安装 `apksigner` 时无法安全判断签名状态，因此同样保守地跳过这些步骤。

唯一的例外是 `android:debuggable=true`：这是必须修复的发布风险，因此归一化仍会改写 Manifest。此时原有签名会失效，报告以 `HARDEN_SIGNATURE_INVALIDATED`（medium）明确说明，最终产物按实际状态命名为 `guarded-unsigned`。

产物后缀始终反映**最终验证观察到的结果**，而不是配置意图：签名步骤未成功时，产物一定命名为 `guarded-unsigned`，不会出现名为“已签名”却无法安装的文件。

如果需要重新对齐、保护或修改一个已有签名的 APK，应选择现有或新建签名库，让流水线在所有内容变更完成后重新签名。

源码项目审计会额外检查 `keystore.properties`、`key.properties`、签名属性文件、项目内 JKS/keystore/P12/PFX，以及 Markdown/TXT 中的 `storePassword/keyPassword`。环境变量、Gradle 属性引用和明确占位符不会被当成真实密码；所有证据只保留项目相对路径、行号和字段名，密码值会在进入 finding 前丢弃。Git 可用时会区分当前 tracked、历史出现和未跟踪文件；对应修复包生成密钥轮换/事件响应清单及 `.gitignore` 示例，但不会自动删除密钥或改写 Git 历史。

对应用自身的签名校验，源码审计只有在“有效 SHA-256 允许列表 + Android 签名 API + SHA-256 摘要 + `onCreate/attachBaseContext` 启动调用 + 失败强制处置”形成完整交叉证据时才标记为 observed。占位指纹、BuildConfig/环境变量等静态不可解析值、未确认启动调用和未确认处置会分别报告，不会凭方法名猜测已生效。最终 APK 经 `apksigner` 验证后，DroidSeal 会将源码中的多指纹轮换允许列表与实际证书 SHA-256 比对；不一致是 confirmed critical 并阻断发布，报告只显示脱敏指纹。匹配仅证明本次构建配置一致，客户端校验仍可能被补丁或 Hook 绕过，不能代替服务端授权与完整性判定。

使用现有签名库时填写：

- JKS/PKCS12 路径；
- 私钥别名；
- 签名库密码；
- 私钥密码，留空时沿用签名库密码。

新建签名库还会填写：

- CN（必填）；
- OU、O、L、ST（可留空）；
- 两字母国家代码 C；
- 有效天数，默认 9125；
- RSA 4096 或 EC P-256。

密码输入由专用键盘处理器捕获，只显示圆点。密码不会写入：

- DroidSeal JSON/Markdown 报告；
- 外部工具命令参数；
- 应用配置文件；
- 终端聊天记录。

密码通过仅属于子进程的环境变量交给 `keytool`/`apksigner`，所有捕获输出再次进行字符串脱敏。

> 新发布签名库必须立即离线备份。丢失既有应用的发布密钥可能导致无法发布可更新版本。

## 14 步流水线

1. **环境诊断**：定位工具并标出所选流程的缺失项。
2. **准备工作区**：验证输入；复制已有 APK；绝不原地修改。
3. **签名库**：提前验证现有别名，或用 keytool 新建，尽早暴露密码/别名问题。
4. **源码安全审计**：检查 release/R8/资源优化/Manifest/明文签名密码与源码启发式。
5. **构建 Release APK**：执行项目自己的 Gradle Wrapper 并复制生成 APK。
6. **APK 安全审计**：解析 ZIP、DEX、ELF、资源表与 AXML；`aapt` 仅补充元数据并作为回退。
7. **本地安全防护**：按严格证据核验 R8、标准 DEX、反调试与完整性覆盖；证据不足只作低置信度提示。
8. **Release 归一化**：确保 `debuggable=false`，修改后验证，否则中止并回退。
9. **Web JS 发布处理**：显式可选；Terser 处理严格白名单内的混合应用脚本、移除 source map，全部成功并复核 ZIP 后才原子写出。
10. **资源名混淆**：可选解析 `resources.arsc`；`getIdentifier` 命中时保留全部键名，DEX 明文引用路径也保留。
11. **ZIP 对齐**：`zipalign -p -f 4`；保留有效现有签名时自动跳过。
12. **APK 签名**：apksigner 输出新的签名 APK。
13. **最终验证**：验证对齐、签名方案、签名证书并计算 SHA-256。
14. **生成报告**：复制最终 APK，生成 JSON/Markdown、发布证据 manifest、CycloneDX SBOM、许可证待核验清单、发布门禁、控制覆盖矩阵以及可审阅修复模板/计划。

## 防护检查如何对应常见威胁

### 静态分析与反编译

- 检查 release 是否启用 R8/代码优化。
- 检查是否启用资源优化。
- 检查是否使用优化版默认规则。
- 仅审计 app 模块 release 明确引用的规则、模块 `proguard-rules.pro` 与 `src/main/keepRules/`，忽略注释、debug/build 目录和非 app 模块。
- 对 `-dontobfuscate`、`-dontshrink`、`-dontoptimize`、全局/整包宽泛 keep 及缺失规则文件给出稳定 finding code、相对路径和行号；注解/继承约束与 `allowobfuscation` 按真实语义降误报。
- 报告明文签名密码。
- 建议敏感凭据不进入客户端，核心授权由服务端完成。

R8 能缩减、优化和混淆代码，但不能把客户端秘密变成不可提取的秘密。

源码项目成功选出 APK 后，报告目录下的 `release-evidence/manifest.json` 会从该 APK 的 `build/outputs/apk/<variant>` 路径反推模块与变体，只归档同一变体的 `mapping.txt`、`configuration.txt`、`seeds.txt`、`usage.txt`、可选 `missing_rules.txt` 以及实际使用的 DroidSeal R8 覆盖脚本。每个文件记录 SHA-256、大小和项目相对路径；缺失文件保留原因。现成 APK 输入明确标记为“不适用”，无法解析布局时不会模糊搜索其他历史 mapping。

每次报告还会生成 `supply-chain/droidseal-sbom.cdx.json`（CycloneDX 1.5）与 `supply-chain/license-review.json`。只有 Gradle 中固定字面量版本生成 Maven version/purl；动态版本、变量和 version catalog 的 `version.ref` 标为 unresolved，DEX 包前缀标为 observed，Native `.so` 按库名合并并保留 ABI/路径证据。DroidSeal 不从包名联网猜版本或许可证，所有未核验许可证保持 `NOASSERTION`，需用解析后的依赖锁、随包 LICENSE/NOTICE 和法务审核确认。

报告 schema 7 包含 `releaseDecision` 与 `controlCoverage`，并对签名自检证据执行指纹脱敏。门禁规则版本为 `droidseal-release-policy/1`：失败步骤、明确无效/缺失发布签名及 confirmed/high 的 critical 发现进入 `block`；签名未验证、较低置信度 critical 及 confirmed/high 的 high 发现进入 `review`；低置信度“未观察到”和其余提示不阻断。Play Integrity、Key Attestation、Challenge/防重放、服务端风控、JNI/O-MVLL 与真机矩阵始终需要业务侧外部验证；即使制品中有精确静态信号，也只标为 `observed`，不会冒充服务端闭环完成。

### 动态调试与 Hook

反调试、Frida/Xposed 特征检测和时间检测都可能被绕过，也容易误伤设备。DroidSeal 不自动向未知 APK 注入此类代码。报告建议：

- 把支付、积分、授权等关键决策放到服务端；
- 使用应用/设备完整性信号作为风险输入，而不是唯一访问控制；
- 对本地完整性检测做分层、可观测和兼容性回归；
- 避免扫描用户设备上的无关应用或进程。

### 网络抓包

- 检查 `usesCleartextTraffic`。
- 检查是否声明 Network Security Config，并在 APK 模式直接解析编译后的 NSC AXML 内容。
- 检查明文流量、用户 CA、debug-overrides、弱/过期 pinning，并建议默认 TLS、最小化自定义信任锚。
- 若业务确需证书固定，必须准备备份公钥和轮换/失效策略。

证书固定不是通用默认答案；错误的固定策略会让合法证书轮换导致应用断网。

### 内存修改

- 报告建议关键状态由服务端校验。
- 密钥优先使用 Android Keystore/硬件支持的密钥能力。
- 本地 CRC、异或数值和 `mprotect` 只能增加成本，不能代替服务端授权。

### 脱壳与加固

- 默认不做伪“DEX 加密”，也不内置或调用加壳/VMP 工具。
- 主动加固请在源码接入有授权的商业/自研方案后再构建。
- 源码加固后仍需在 DroidSeal 中重新对齐、签名并在真机矩阵回归。
- 报告明确说明 VMP、类抽取、自定义加载器和 Native 保护的兼容性成本。

### 二次打包

- 发布密钥和签名证书验证是基础。
- Java 层自签名校验容易被修改或 Hook，不能作为唯一控制。
- 推荐把签名/渠道/完整性信号与服务端风险校验结合。
- 资源哈希、自校验和渠道信息应有升级与密钥轮换机制。

## 输出结构

```text
<output>/
├── <input>-guarded-signed.apk              # 本次重新签名并验证通过
│   或 <input>-guarded-signed-preserved.apk # 保留并验证了原签名
│   或 <input>-guarded-unsigned.apk         # 最终未验证到有效签名
└── .droidseal/
    └── runs/
        └── <run-id>/
            ├── artifacts/
            │   ├── 01-input.apk                 # APK 输入时
            │   ├── 02-built.apk                 # 项目输入构建成功时
            │   ├── 03b-hardened.apk             # Manifest 被改写时
            │   ├── 03c-stripped.apk             # 调试残留被移除时
            │   ├── 03d-web-assets.apk           # Web JS 处理启用且适用时
            │   ├── 03e-arsc-obfuscated.apk      # ARSC 混淆启用且适用时
            │   ├── 04-aligned.apk               # 执行对齐时
            │   ├── 05-signed.apk                # 执行重新签名时
            │   └── droidseal-force-r8.init.gradle # 需要强制 R8 时
            └── reports/
                ├── droidseal-report.json
                ├── droidseal-report.md
                ├── release-evidence/
                │   ├── manifest.json
                │   └── <同一 Gradle 变体的 R8 证据文件>
                ├── supply-chain/
                │   ├── droidseal-sbom.cdx.json
                │   └── license-review.json
                └── remediation/                 # 有可模板化发现时
                    ├── README.md
                    ├── droidseal-remediation.json
                    └── <修复模板>
```

最终 APK 后缀反映验证结果，而不是用户的签名意图。中间制品、R8 证据和修复目录只在对应步骤实际适用时出现；报告目录即使没有最终 APK 也会尽量生成失败诊断。

## 常见错误

| 错误码 | 含义 | 典型处理 |
| --- | --- | --- |
| `INPUT_NOT_FOUND` | 输入路径不存在 | 检查绝对路径、网络盘和权限 |
| `TOOLCHAIN_INCOMPLETE` | 所选流程缺少必需工具 | 下载并继续，或手动安装后重新检测 |
| `REQUIRED_TOOL_MISSING` | 当前步骤缺少工具 | 安装 JDK/Build Tools，重新诊断 |
| `GRADLE_TASK_NOT_FOUND` | Gradle 任务不存在 | 运行 `gradlew tasks`，选择真实变体 |
| `ANDROID_SDK_NOT_FOUND` | Gradle 找不到 SDK | 配置 `local.properties` 或 SDK 环境变量 |
| `BUILD_APK_NOT_FOUND` | 构建后未找到 APK | 填写自定义输出路径，确认不是 AAB/库模块 |
| `INVALID_APK_ARCHIVE` | APK ZIP 损坏 | 重新获取或构建，核对 SHA-256 |
| `KEYSTORE_PASSWORD_INVALID` | 签名库密码或格式错误 | 用 keytool 单独验证 |
| `KEY_ALIAS_NOT_FOUND` | 别名不存在/不是私钥 | `keytool -list -v` 查看 PrivateKeyEntry |
| `PKCS12_PASSWORD_MISMATCH` | 新 PKCS12 使用了不同 key password | 沿用 store password，或改用 JKS |
| `SIGNATURE_OPERATION_FAILED` | 签名操作失败 | 检查现有签名、顺序、minSdk 和算法 |
| `SIGNATURE_MISSING_AFTER_FAILED_SIGNING` | 配置了重新签名，但签名步骤未成功，最终产物未签名 | 先修复“签名库”或“APK 签名”步骤报告的根因 |
| `PROCESS_TIMEOUT` | 外部工具超时 | 检查隐藏交互、Gradle 下载或文件锁 |

每个错误都会在 TUI 中给出说明、建议、脱敏后的工具输出和回退结果。

## 开发与验证

```powershell
bun run check
bun test
bun run build
bun run release:check
```

完整发布前验证：

```bash
bun run verify
```

测试覆盖：

- 每一步引导文字和跳过分类；
- 向导中安全审计基线、zipalign 和签名选择的说明；
- 用户主动跳过与自动“不适用”的状态传播；
- 开源发布前的签名材料、APK/AAB、secret 和本机路径检查。

## 项目文档与参与方式

README 是用户入口和当前实现说明；以下文档承担不同职责，避免把历史、治理和研究规格混在同一文件中：

| 文档 | 职责 | 是否并入 README |
| --- | --- | --- |
| [CHANGELOG.md](CHANGELOG.md) | 已发布和待发布的用户可见变化 | 保留独立；README 只写当前状态 |
| [Android 开源加固组合技术路线](android-open-source-hardening-technical-roadmap.md) | 应用团队在 DroidSeal 之外可采用的 R8、Native、运行时、证明和服务端纵深防御路线 | 保留独立；它是战略参考，不是 DroidSeal 已实现功能清单 |
| [开源与商业化实施路线](docs/open-source-commercialization-roadmap.md) | 从干净仓库、许可证、供应链发布到 Community/Pro/Enterprise 隔离的逐项实施和验收路线 | 保留独立；只保存未完成项，完成结果转入变更或发布证据 |
| [DEX 写引擎与 ARSC 设计](docs/dex-write-engine.md) | 自研二进制写回、实验模块、失败关闭子集和真机门禁的深度设计/实现状态 | 保留独立；README 只说明受支持边界 |
| [反调试 stub 集成说明](src/assets/antidebug-stub/INTEGRATION.md) | 安装到目标 Android 模块后的源码接线和真机验证 | 保留在资产目录并随 stub 一起复制 |
| [第三方许可证说明](THIRD_PARTY_NOTICES.md) | 实际依赖、可选外部工具和许可证边界 | 保留独立，作为分发合规材料 |
| [贡献指南与 DCO](CONTRIBUTING.md) | 开发、测试、提交和签署要求 | 保留独立 |
| [安全政策](SECURITY.md) | 漏洞报告范围与私密披露方式 | 保留独立 |
| [项目治理](GOVERNANCE.md) | 维护者职责与决策方式 | 保留独立 |
| [社区行为准则](CODE_OF_CONDUCT.md) | 社区行为规范 | 保留独立 |
| [商标与品牌政策](TRADEMARKS.md) | 名称、Logo 和背书边界 | 保留独立 |

`.github/PULL_REQUEST_TEMPLATE.md` 是 GitHub 工作流模板，不属于用户文档；`dependencies/`、`node_modules/` 与 `dist/` 内的 Markdown 属于第三方或生成内容，不参与项目文档合并。

DroidSeal 采用 Maintainer-led 治理并通过 Developer Certificate of Origin 1.1 接受贡献。任何真实 APK、AAB、JKS/PKCS12、私钥、密码或未脱敏日志都不得提交到仓库。

## 技术路线与路线评价

### 定位与实现纪律

DroidSeal 采用 **local-first、local-safe、证据优先** 路线：商业加固前默认完成可验证的源码审计、强制 release R8/资源裁剪、Manifest/调试残留归一化、可选资源混淆、对齐、签名与最终验证；不重写既有 DEX 业务方法，也不向未知 APK 劫持式注入启动代码。构建、发布检查和打包脚本均由 TypeScript/Bun 驱动；Windows 上出现的 `gradlew.bat`、`apksigner.bat` 仅是用户项目或 Android SDK 的平台入口，不是 DroidSeal 自有批处理脚本。

这条路线由五个支柱组成：

1. **纯 TypeScript 二进制能力**：ZIP 中央目录、DEX 字符串池、AXML、ARSC、ELF 均由内置解析器处理，保持离线和低供应链依赖。
2. **严格证据与置信度**：源码调用点可确认参数，DEX 字符串必须有 API/动作交叉信号；报告区分已确认、高、中、低置信度，缺少字符串从不直接证明能力不存在。
3. **可验证的安全后处理**：剔除调试条目、归一化 `debuggable`、经预检的可选资源名混淆、对齐、签名和验证均产生独立制品，失败可回退。
4. **工具链编排与降级**：统一调度 Gradle、aapt、zipalign、apksigner、keytool；Manifest 深审优先直读 AXML，缺失外部工具不会阻断可由内置解析器完成的检查。
5. **TUI、报告与修复闭环**：分步/一键流程共享同一状态机；报告阶段把可模板化建议自动沉淀为 NSC、备份规则、Manifest 片段和机器可读修复计划，但不静默覆盖源码。

### 双输入审计覆盖

| 能力 | 项目/源码输入 | APK 输入 |
| --- | --- | --- |
| Manifest、权限、组件与深链 | 文本 Manifest + 源码规则 | 直接解析 `AndroidManifest.xml` AXML；`aapt xmltree` 回退 |
| Network Security Config | 读取明文 `res/xml`，使用共享 NSC 规则 | 解析 Manifest 引用，经 `resources.arsc` 定位并还原编译 AXML，复用同一规则 |
| `fullBackupContent` / `dataExtractionRules` | 读取明文规则并检查敏感路径排除 | 经 ARSC 定位编译 XML，解析 `<exclude>` 与敏感路径；异常时安全降级 |
| 代码启发式 | 扫描 Kotlin/Java（有文件数/字符上限） | 扫描 DEX 字符串池（不反编译/改写指令） |
| Native 与供应链清单 | Gradle 依赖坐标清单 | ELF NX/RELRO/Canary/FORTIFY/TEXTREL、JNI/SDK 特征清单 |

### 路线评价

优势是**可审计、可验证、默认无运行时代码注入、可离线**，适合作为 CI/发布前的第一道安全关卡；直接 AXML + ARSC 解析已把组件、NSC 和备份规则的主要源码侧深度迁移到 APK 模式。它与 MobSF/Quark、SCA/CVE 数据库、动态沙箱和商业加壳/VMP 是互补关系，不替代真实 CVE 比对、运行时行为分析或强对抗保护。

后续优先级是继续减少源码/APK 规则差异、扩展更多编译资源语义，并把更多低风险且确定性的建议转成可审阅模板；涉及业务授权、组件语义、证书轮换或数据分类的修复仍必须由开发者确认，不能安全地“一键猜测”。

## 项目架构

DroidSeal 是单进程、本地优先的 TypeScript/Bun CLI。TUI 只负责收集配置和展示事件，所有分步与一键操作都进入同一个 `Pipeline`；每个可能改写 APK 的步骤生成新制品，成功后才推进 `currentArtifact`，失败则删除失败输出并回退。报告层最后汇总步骤、发现、供应链、签名和发布门禁证据。

```text
src/index.tsx
└─ src/ui/                 TUI、向导、主题、缩放与输入状态
   └─ src/core/pipeline.ts 14 步事务式状态机
      ├─ 源码审计          Gradle/R8/Manifest/签名材料/WebView/规则
      ├─ APK 审计          ZIP/AXML/ARSC/DEX/ELF/签名/秘密/SDK
      ├─ 安全后处理        Manifest、残留条目、Web JS、ARSC、对齐、签名
      ├─ 工具编排          Gradle/JDK/Android Build Tools/Capacitor
      └─ 证据与报告        R8 归档、SBOM、门禁、覆盖矩阵、修复包
```

### 目录与模块分工

| 层 | 主要文件 | 实际职责 |
| --- | --- | --- |
| 入口与交互 | `src/index.tsx`、`src/ui/app.tsx`、`wizard.ts`、`button.tsx`、`theme.ts`、`zoom.ts` | CLI 参数、分步/一键向导、输入与按钮状态、进度/聊天面板、深冰蓝主题与步骤状态展示；UI 由 OpenTUI/Solid 渲染，交互逻辑由 DroidSeal 实现。 |
| 编排与共享模型 | `pipeline.ts`、`types.ts`、`process.ts`、`errors.ts` | 14 步状态机、独立制品、失败回退、跳过分类、参数数组启动、超时、输出脱敏和稳定错误码。 |
| 工具链与构建 | `toolchain.ts`、`tool-installer.ts`、`bundle.ts`、`capacitor-build.ts` | 发现项目内/系统/托管工具；校验下载；调用项目 Gradle Wrapper；检测 Capacitor 并同步 Web 层；不会猜测生成不匹配的 Wrapper。 |
| 源码审计 | `project-audit.ts`、`r8-rules-audit.ts`、`signing-material-audit.ts`、`signature-self-check.ts`、`webview-debug-audit.ts`、`backup-rules-audit.ts`、`gradle-components.ts`、`code-heuristics.ts` | Manifest、权限、NSC/备份、R8 开关与 keep 规则、签名材料/Git 暴露、自签名校验闭环、WebView release 调试状态、Gradle 组件和 Java/Kotlin 启发式。 |
| APK 审计 | `apk-audit.ts`、`dex-scan.ts`、`elf-scan.ts`、`axml-nsc.ts`、`signing-audit.ts`、`secret-scan.ts`、`permissions-catalog.ts` | ZIP 安全、二进制 Manifest/XML、资源引用、DEX 字符串交叉证据、Native 加固、签名方案/证书、秘密、权限和 SDK 家族；`aapt` 只是补充/回退。 |
| 二进制格式与后处理 | `harden-manifest.ts`、`apk-strip.ts`、`arsc-model.ts`、`arsc-obfuscate.ts`、`lossy-harden.ts`、`web-asset-minify.ts` | 自研 ZIP/AXML/ARSC 读写；强制 `debuggable=false`、清理调试残留、原子处理白名单 Web JS、经预检的可选资源名/路径混淆。DEFLATE 只调用内置 `node:zlib`。 |
| 签名与发布证据 | `release-evidence.ts`、`sbom.ts`、`release-policy.ts`、`remediation.ts`、`report.ts` | 精确归档同一 Gradle 变体的 R8 文件，生成 CycloneDX 1.5、许可证复核清单、`pass/review/block`、纵深覆盖矩阵、修复模板以及 JSON/Markdown 报告。 |
| 可选源码资产 | `src/assets/antidebug-stub/`、`antidebug-stub.ts` | 把自研 Kotlin/JNI/CMake 检测 stub 复制到用户选择的 Android 模块；由用户显式接线和构建，不事后注入 APK。 |
| 构建与质量门禁 | `scripts/build.ts`、`release-check.ts`、`collect-local-dependencies.ts`、`bundle-toolchain.ts`、`device-smoke.ts` | 生成并压缩分发 bundle、校验 source map/哈希、收集便携依赖、预取官方工具链，以及有设备时执行签名/DEX/Manifest/安装冒烟。 |

### 自研格式能力与失败边界

ZIP 容器、AXML、ARSC、DEX/ELF 审计及流水线没有引入 `apktool`、`androguard`、`jadx` 或第三方 ZIP/AXML/ARSC 改包库。核心写出器复用未修改条目的原始压缩数据，只重建必要目录；不认识的结构会显式失败并回到步骤前制品。

| 自研能力 | 当前主线状态 | 边界 |
| --- | --- | --- |
| ZIP/Manifest 归一化与条目清理 | 默认主线 | 可验证、失败回退；改写后需重新签名。 |
| AXML/ARSC 深审 | 默认主线 | 覆盖 Manifest、NSC、备份规则和资源引用；异常时降级，不猜测。 |
| Web JS Terser 处理 | 显式可选主线 | 严格限定 `assets/public` / `assets/www`；普通脚本不做顶层 mangle；不承诺保密。 |
| ARSC 名称/路径混淆 | 显式可选主线 | `getIdentifier` 或 DEX 路径字面量触发保留；需要重新对齐、签名和真机回归。 |
| DEX 编解码、模型和受限写回 | 已实现研究模块：`dex-codec.ts`、`dex-model.ts`、`dex-writer.ts` | 对未知 opcode、try/catch、debug info、注解等失败关闭；未接入 14 步主线。 |
| DEX 字符串安全子集与密码计划 | 已实现研究模块：`dex-string-crypto.ts` | 只生成非破坏性计划；运行时解密器、指令扩展和寄存器重分配未接入。 |
| 新增 DEX 的反调试实验 | 已实现研究模块：`axml-writer.ts`、`lossy-inject.ts` | 仅覆盖受限 Application 场景和合成测试，尚缺完整真机 Stage-B 矩阵；未接入 UI/流水线，不属于受支持发布功能。 |

详细格式规格、已完成里程碑和仍需人工执行的 `dexdump`/真机门禁见 [DEX 写引擎与 ARSC 设计](docs/dex-write-engine.md)。这里的“已实现研究模块”表示仓库有代码和单元测试，不表示对任意真实 APK 的兼容性承诺。

## 实际依赖与第三方边界

依赖以 `package.json` 和锁文件为准。DroidSeal 的第三方 JavaScript 包数量很小，但不是“完全零依赖”：

| 包 | 锁定版本 | 安装层级 | 实际用途 |
| --- | --- | --- | --- |
| `@opentui/core` | `0.4.5` | dev dependency，构建时打入 exe | 终端渲染器、键盘/鼠标事件和原生终端运行时。 |
| `@opentui/solid` | `0.4.5` | dev dependency，构建时打入 exe | OpenTUI 的 Solid 适配、preload 与 Bun 构建插件。 |
| `solid-js` | `1.9.12` | dev dependency，构建时打入 exe | TUI 响应式状态。 |
| `terser` | `5.49.0` | dev dependency，构建后打入 exe | 压缩 DroidSeal 中间 bundle；在用户显式开启时处理混合应用 Web JavaScript。禁用 unsafe 变换和 source map。 |
| `typescript` | `5.9.3` | dev dependency | `tsc --noEmit` 类型检查，不进入运行功能。 |
| `@types/bun` | `1.3.14` | dev dependency | Bun API 类型定义。 |
| `brace-expansion` | `2.1.3` | 传递依赖 override | 安全固定传递依赖版本；DroidSeal 源码不直接导入。 |

Bun API 与 `node:fs`、`node:path`、`node:crypto`、`node:zlib`、`node:os` 属于构建后嵌入 exe 的运行时能力，不是 npm 第三方包。OpenTUI、Solid 和 Terser 均只在源码开发/构建阶段安装；它们的实际运行代码会进入 `dist/droidseal.exe`，因此发布后的 npm 安装没有 runtime dependencies，但这些第三方实现仍属于产品运行边界。

正式构建会使用 Bun metafile 逐一反查实际进入可执行文件的 npm 模块，并在 `dist/third-party/` 生成精确组件清单、CycloneDX SBOM、第三方通知和逐包许可证原文；`droidseal-build.json` 记录这些材料的大小与 SHA-256。Bun 运行时固定为 `1.3.14`，其 JavaScriptCore/WebKit LGPL-2.0-only 与 TinyCC LGPL-2.1-only 对应源码、固定提交和重新链接步骤见 [Bun LGPL 重新链接说明](licenses/Bun-LGPL-RELINKING.md)。发布检查会在 Bun 版本、官方许可证原文、清单或任一许可证证据漂移时失败。

DroidSeal 还会按所选流程调用外部工具：

| 工具/平台 | 何时实际使用 | 是否由 DroidSeal 实现或捆绑 |
| --- | --- | --- |
| Bun | 始终 | 第三方运行时；便携目录可复制本机版本。 |
| 项目 Gradle Wrapper + 匹配的 Gradle/AGP | 从源码构建时 | 由目标 Android 项目提供，DroidSeal 只编排。 |
| Java/JDK、`keytool` | Gradle 构建、签名库检查/创建 | 外部工具；可发现、受校验下载或收集进 `dependencies/`。 |
| Android Build Tools：`aapt`、`zipalign`、`apksigner` | 元数据补充、对齐、签名和验证 | Google 官方工具；可通过 `sdkmanager` 安装或收集进便携目录。 |
| Node.js、npm、npx | 检测到 Capacitor 项目时同步/完整构建 Web 层 | 外部工具；纯 Gradle/APK 输入不需要。 |
| `dexdump`、`aapt2`/`aapt`、`adb` | `bun run smoke:device` 的可选 Stage-B 门禁 | Android SDK/Platform Tools；缺失或无设备时明确跳过。 |
| Android NDK、CMake | 用户安装并在源码接入反调试 stub 时 | 目标项目构建依赖；不属于默认 APK 流水线。 |

`dependencies/` 是本机生成的便携运行目录，包含锁定 npm 包、Bun/Node、完整 JDK 和 Android Build Tools，并由 `bundle-manifest.json` 记录工具路径与 SHA-256；它不是新的源码依赖清单，也不能替代目标项目自己的 Gradle Wrapper。具体许可证、下载来源和分发责任见 [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md)。

### 为什么核心 APK 格式处理保持自研

- **字节级控制**：未修改 ZIP 条目复用原始压缩字节，减少重排、重压缩和签名摘要的意外变化。
- **供应链收敛**：直接处理用户 APK 和签名流程的核心路径没有庞大的解析器传递依赖。
- **失败语义明确**：解析上限、未知结构、签名保护和改写后复核均可在同一状态机中失败关闭并回退。

自研不等于自造商业壳。DEX 加密、VMP、类抽取、自定义加载器和高对抗运行时保护仍应在有源码、授权和设备矩阵的工程中集成；DroidSeal 的默认职责是审计、确定性后处理、签名验证和证据留档。

## 技术与规范

终端界面由 OpenTUI 的 Solid 渲染器绘制。交互层、流水线状态、工具调用、错误解释和事务回退均在 DroidSeal 内部实现。

APK 构建、优化、签名和安全检查遵循 Android 官方规范：

- [从命令行构建应用](https://developer.android.com/build/building-cmdline)
- [apksigner](https://developer.android.com/tools/apksigner)
- [启用 R8 应用优化](https://developer.android.com/topic/performance/app-optimization/enable-app-optimization)
- [Network Security Configuration](https://developer.android.com/privacy-and-security/security-config)
- [Android 安全最佳实践](https://developer.android.com/privacy-and-security/security-best-practices)

## 许可证

除非另有说明，DroidSeal 的源代码、项目文档和示例均采用 [MIT License](LICENSE)。

MIT License 不授予以暗示官方身份、赞助或背书的方式使用 DroidSeal 名称或 Logo 的权利，具体参见 [TRADEMARKS.md](TRADEMARKS.md)。第三方工具和依赖项继续受各自许可证及条款约束，具体参见 [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md)。

项目通过 Developer Certificate of Origin 1.1 接受外部贡献，具体参见 [CONTRIBUTING.md](CONTRIBUTING.md)。
