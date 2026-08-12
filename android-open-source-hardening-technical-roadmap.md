# Android 开源加固组合技术路线

> 文档版本：1.1  
> 基准日期：2026-08-02  
> 适用范围：Android 原生应用（Kotlin/Java + 可选 C/C++/JNI），APK/AAB 发布  
> 目标：使用可审计的开源组件与平台能力，构建“静态混淆 + Native 保护 + 运行时检测 + 设备/应用证明 + 服务端风控”的纵深防御体系。  
> 注意：本文不构成法律意见；许可证义务应由组织法务或开源合规负责人最终确认。

---

## 文档定位

本文是 Android 应用团队的纵深防御参考，描述 R8、Native、运行时风险信号、设备/应用证明和服务端控制如何组合；它不是 DroidSeal 当前功能清单，也不表示所列第三方项目已被 DroidSeal 集成。

DroidSeal 的当前实现、14 步主线、自研/第三方边界以 [README](README.md) 为准，已完成的用户可见变化以 [CHANGELOG](CHANGELOG.md) 为准。此前用于逐条实施 DSR-001～DSR-009 的待办队列、旧差距快照和完成日志已经全部验收，其结论已并入上述文档，因此从本路线图移除，避免继续显示已经补齐的缺口和过期测试计数。

涉及 Play Integrity、Key Attestation、Challenge/防重放、服务端风控、JNI/O-MVLL、商业壳或第三方混淆器的条目仍属于应用/服务端工程选型，必须独立完成许可证、供应链、兼容性和真机矩阵评审。

---
## 1. 结论与推荐栈

### 1.1 推荐生产路线

```text
业务去敏感化与资产分级
        ↓
R8：全量代码裁剪、优化、名称混淆
        ↓
LSParanoid：仅对选定 Java/Kotlin 字符串做补充混淆（可选）
        ↓
security-core JNI：承载少量高价值算法与校验逻辑
        ↓
O-MVLL：对关键 Native 函数做局部增强混淆
        ↓
自研运行时风险信号：签名、代码完整性、调试、Hook、Root 等
        ↓
Play Integrity（Google Play）或 Android Key Attestation（多渠道）
        ↓
服务端 Challenge、重放保护、风险评分与分级处置
        ↓
dpt-shell：仅在完成兼容性验证后，对核心 DEX 做可选后处理
```

### 1.2 默认组件选择

| 安全层 | 默认选择 | 备选 | 默认结论 |
|---|---|---|---|
| Java/Kotlin 基础优化与混淆 | **R8** | dProtect | 生产默认使用 R8 |
| Java/Kotlin 增强混淆 | LSParanoid（字符串，可选） | dProtect、BlackObfuscator | 按包/按类局部启用 |
| Native 核心保护 | **O-MVLL** | 自研 LLVM Pass | 只保护关键函数 |
| DEX 壳/方法抽空 | dpt-shell（可选） | 不加壳 | 稳定性优先，后置引入 |
| 运行时风险检测 | **自研 security-runtime** | freeRASP、dpt-shell 内置检测 | 服务端只信任组合证据 |
| Google Play 应用/设备证明 | **Play Integrity API** | 无 | 专有服务，不是开源组件 |
| 多渠道设备密钥证明 | **Android Keystore + Key Attestation** | 厂商证明服务 | 平台能力，不是单独 SDK |
| 安全验收 | **OWASP MASVS/MASTG** | 自建测试规范 | 作为标准，不进入 APK |

### 1.3 不建议的组合

1. **不建议对整个 App 串联 R8 → dProtect。**  
   dProtect 官方 Android 集成要求关闭 R8；两者应视为全应用主处理器的二选一。

2. **不建议全量启用控制流平坦化。**  
   只保护高价值、非性能热点的方法。

3. **不建议把 dpt-shell 当作唯一防护。**  
   壳可被脱除，核心授权必须由服务端完成。

4. **不建议使用 freeRASP 时把它标记为“纯开源方案”。**  
   其仓库明确说明 SDK 由 MIT 开源部分和 Talsec 闭源二进制部分构成，并受免费使用政策约束。

---

## 2. 功能—项目—开源政策总表

### 2.1 核心项目矩阵

| 功能 | 项目/能力 | 集成位置 | 开源状态 | 许可证/政策 | 商业应用要点 | 本路线定位 |
|---|---|---|---|---|---|---|
| 代码裁剪、优化、类/方法/字段重命名 | [R8](https://r8.googlesource.com/r8/) | Android Gradle Plugin 构建阶段 | **纯开源** | BSD-3-Clause | 可商用、可修改、可再分发；再分发需保留版权、许可条件和免责声明，不得未经许可用项目/贡献者名称背书 | **默认主混淆器** |
| Java/Kotlin 算术、字符串、常量、控制流增强混淆 | [dProtect](https://github.com/open-obfuscator/dProtect) | Java 字节码处理阶段 | **纯开源、强 copyleft** | GPL-2.0 | 作为构建工具处理自有代码，输出通常不因工具本身自动变成 GPL；但分发修改版工具、组合 GPL 代码或注入 GPL 运行时代码时可能产生源码提供义务，需法务复核 | **R8 的替代路线或隔离 SDK 路线** |
| Native LLVM 混淆 | [O-MVLL](https://github.com/open-obfuscator/o-mvll) | NDK/Clang 编译阶段 | **纯开源** | Apache-2.0 | 可商用、修改、再分发；保留 LICENSE/NOTICE、标记修改，并关注专利条款 | **Native 主保护组件** |
| DEX 方法抽空、运行时重建、基础反调试/Frida/CRC/签名检测 | [dpt-shell](https://github.com/luoyesiqiu/dpt-shell) | APK/AAB 后处理阶段 | **纯开源** | MIT | 可商用；保留版权和许可声明。项目会引入多个第三方依赖，必须审计最终产物中实际包含的依赖许可证 | **可选壳，不作为基线** |
| DEX 控制流混淆 | [BlackObfuscator](https://github.com/CodingGay/BlackObfuscator) | DEX 后处理阶段 | **纯开源** | Apache-2.0 | 可商用；保留许可证/NOTICE；基于 dex2jar，需检查组合依赖 | **可选单点增强** |
| Java/Kotlin 字符串混淆 | [LSParanoid](https://github.com/LSPosed/LSParanoid) | Gradle/字节码处理阶段 | **纯开源** | Apache-2.0 | 可商用；保留许可证/NOTICE；应确认插件注入的运行时代码及第三方依赖清单 | **R8 主线的轻量补充** |
| APK/Smali 黑盒混淆 | [Obfuscapk](https://github.com/ClaudiuGeorgiu/Obfuscapk) | APK 后处理阶段 | **纯开源但已归档** | MIT | 可商用；仓库自 2024-07-27 起归档、只读，不再维护 | **仅研究/遗留项目，不用于新生产线** |
| Root、Hook、篡改、模拟器等 RASP 检测 | [freeRASP Android](https://github.com/talsec/Free-RASP-Android) | App 运行时 SDK | **混合开源/闭源，Freemium** | 开源部分 MIT；闭源二进制归 Talsec；受 Fair Usage Policy 约束 | 不是纯开源 SDK；需评估用量政策、闭源供应链、遥测/隐私、升级和商业版边界 | **可选供应商 SDK，不纳入纯开源基线** |
| 应用、设备、账号和环境完整性判定 | [Play Integrity API](https://developer.android.com/google/play/integrity) | 客户端 + Google Play + 服务端 | **专有服务** | Google Play 条款、API 使用政策及数据处理规则 | 不是开源；存在平台依赖、配额、联网和数据合规要求；令牌必须在服务端解密验证 | **Google Play 渠道关键证明能力** |
| 硬件设备密钥及证明 | [Android Keystore / Key Attestation](https://developer.android.com/privacy-and-security/security-key-attestation) | Android 系统 + TEE/StrongBox + 服务端 | **平台开源与专有实现混合** | AOSP 大部分用户空间代码偏好 Apache-2.0；设备 TEE、StrongBox、厂商实现及 Google 证明基础设施不保证开源 | 不是可打包的独立开源库；服务端必须验证证书链、可信根、Security Level 和吊销状态 | **多渠道设备身份与请求签名** |
| 安全需求和测试方法 | [OWASP MASVS](https://github.com/OWASP/masvs)、[MASTG](https://github.com/OWASP/mastg) | 研发规范、测试和审计 | **开放标准/文档** | GitHub 仓库标示 CC-BY-SA-4.0；官网页面可能标示 CC-BY-4.0，转载具体内容时以对应制品 LICENSE 为准 | 可用于内部标准；对外复制、修改文档需保留署名并遵守相同方式共享等条款（以具体制品为准） | **安全验收基线** |

### 2.2 开源政策分类说明

| 分类 | 含义 | 本路线项目 |
|---|---|---|
| 纯开源、宽松许可证 | 源码可获得，允许商业使用、修改和再分发，主要义务是保留版权、许可和 NOTICE | R8、O-MVLL、dpt-shell、BlackObfuscator、LSParanoid、Obfuscapk |
| 纯开源、Copyleft | 源码可获得；修改或分发项目本体及其衍生组合时可能要求按相同许可证提供源码 | dProtect |
| 混合开源/闭源 | 仓库或封装层开源，但核心二进制、后台能力或高级功能闭源，并可能附带使用政策 | freeRASP |
| 专有服务/API | 客户端接口可公开使用，但服务实现、判定算法和基础设施闭源 | Play Integrity |
| 平台开源 + 硬件/厂商闭源 | Android API/AOSP 部分开源，但设备安全硬件和厂商实现不一定开源 | Android Keystore / Key Attestation |
| 开放标准/文档 | 不是运行时代码，主要用于需求和验收；采用 Creative Commons 文档许可 | OWASP MASVS/MASTG |

---

## 3. 目标、非目标与威胁模型

### 3.1 防护目标

本路线用于提高以下攻击的成本：

- JADX、apktool、JEB 等静态反编译和代码阅读；
- 业务代码复制、接口协议复制和二次打包；
- 修改本地布尔值、授权状态或金额参数；
- Frida/Xposed 类 Hook、调试器附加和运行时方法替换；
- DEX/Native 库替换、重签名和资源篡改；
- 请求重放、批量自动化和非官方客户端调用；
- 从客户端提取长期秘密或完整风控规则。

### 3.2 非目标

本路线不能承诺：

- 客户端代码“不可逆”；
- 单个检测点永远不可绕过；
- 在完全受攻击者控制的设备上建立绝对可信执行环境；
- 使用字符串混淆保存服务端主密钥；
- 仅依赖壳或 Root 检测完成支付、授权或封号决策。

### 3.3 资产分级

| 等级 | 示例 | 技术处置 |
|---|---|---|
| S0：不得进入客户端 | 服务端私钥、支付主密钥、永久授权生成逻辑、完整风控规则 | 只放服务端 |
| S1：客户端必须存在且高价值 | 协议签名、许可证挑战响应、核心算法、本地模型解密控制 | JNI + O-MVLL + 服务端 Challenge |
| S2：一般业务逻辑 | ViewModel、Repository、普通数据处理 | R8；必要时局部 LSParanoid |
| S3：低价值/公开逻辑 | UI、公共数据模型、开源组件调用 | 常规优化，不做重度保护 |

---

## 4. 总体架构

```text
┌─────────────────────────────────────────────────────────────┐
│ 服务端安全决策层                                             │
│ Challenge / Token / 重放保护 / 风险评分 / 限流 / 二次认证     │
└──────────────────────────────┬──────────────────────────────┘
                               │
┌──────────────────────────────▼──────────────────────────────┐
│ 应用与设备证明层                                             │
│ Play Integrity（Play 渠道）                                  │
│ Android Key Attestation + 设备密钥（多渠道）                  │
└──────────────────────────────┬──────────────────────────────┘
                               │
┌──────────────────────────────▼──────────────────────────────┐
│ 运行时风险信号层                                             │
│ 签名 / 安装来源 / 代码完整性 / 调试 / Hook / Root / 模拟器     │
│ 项目：自研 security-runtime；可选 dpt-shell/freeRASP          │
└──────────────────────────────┬──────────────────────────────┘
                               │
┌──────────────────────────────▼──────────────────────────────┐
│ Native 核心保护层                                            │
│ security-core JNI + O-MVLL                                   │
└──────────────────────────────┬──────────────────────────────┘
                               │
┌──────────────────────────────▼──────────────────────────────┐
│ Java/Kotlin 基础保护层                                       │
│ R8；可选 LSParanoid；dProtect 作为替代路线                    │
└─────────────────────────────────────────────────────────────┘
```

### 4.1 信任原则

1. 客户端只生成和上报证据，**服务端做最终决策**。
2. 任何单一信号均可能误报或被绕过。
3. 高价值请求必须绑定用户、会话、设备、业务参数、时间窗口和一次性 Challenge。
4. 拒绝策略应分级，避免因 Root、辅助功能、模拟器等单一信号误伤合法用户。
5. 客户端不得持有可离线生成永久授权的秘密。

---

## 5. 阶段一：R8 基线

### 5.1 功能对应

| 功能 | 项目 |
|---|---|
| 无用代码裁剪 | R8 |
| 逻辑优化、方法内联、类合并 | R8 |
| 类/方法/字段名称缩短 | R8 |
| 无用资源优化 | R8/AGP |
| 崩溃堆栈还原 | R8 mapping + retrace |

Android 官方建议发布构建启用 R8 优化。AGP 9.3 及以上使用新的 `optimization {}` DSL；旧版 AGP 使用 `minifyEnabled`/`shrinkResources`。

### 5.2 AGP 9.3 及以上

```kotlin
android {
    buildTypes {
        release {
            optimization {
                enable = true
            }
        }
    }
}
```

Keep 规则放入：

```text
app/src/main/keepRules/
├── reflection.keep
├── serialization.keep
├── jni.keep
├── webview.keep
└── sdk.keep
```

### 5.3 AGP 9.2 及以下

```kotlin
android {
    buildTypes {
        release {
            isMinifyEnabled = true
            isShrinkResources = true

            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro"
            )
        }
    }
}
```

### 5.4 Keep 规则原则

禁止全包保留：

```proguard
# 不推荐
-keep class com.company.** {
    *;
}
```

按动态访问点精确保留：

```proguard
# JNI：只保留 native 方法名称
-keepclasseswithmembernames class * {
    native <methods>;
}

# WebView JavaScript 接口
-keepclassmembers class * {
    @android.webkit.JavascriptInterface <methods>;
}

# 业务自定义反射注解
-keep @interface com.company.security.KeepForReflection

-keep,allowoptimization,allowshrinking class * {
    @com.company.security.KeepForReflection <fields>;
    @com.company.security.KeepForReflection <methods>;
}
```

### 5.5 R8 许可证落地

- 在组织的 `THIRD_PARTY_NOTICES.md` 中记录 R8 和 BSD-3-Clause；
- 自行再分发 R8 二进制或修改版时，保留版权、许可条件和免责声明；
- 不使用 Google 或贡献者名称为产品背书；
- R8 仅作为构建工具时，通常不会把其许可证施加到应用业务代码上；
- 固定 AGP/R8 版本并归档 `mapping.txt`、`configuration.txt`、`seeds.txt`、`usage.txt`。

---

## 6. 阶段二：Java/Kotlin 增强保护

### 6.1 路线 A：R8 + LSParanoid（推荐轻量方案）

#### 功能对应

| 功能 | 项目 |
|---|---|
| 名称混淆、裁剪、优化 | R8 |
| 选定类的字符串混淆 | LSParanoid |

示例：

```kotlin
plugins {
    id("org.lsposed.lsparanoid")
}

lsparanoid {
    includeDependencies = false
    variantFilter = { variant ->
        variant.buildType == "release"
    }
}
```

```kotlin
@Obfuscate
internal object EndpointConstants {
    const val PATH_LICENSE = "/v1/license/challenge"
}
```

使用边界：

- 只处理 API 路径、内部标识、提示语和低敏感常量；
- 不存放主密钥、永久 Token 或完整风控规则；
- 不对第三方依赖全量处理；
- 评估生成代码对启动、崩溃栈和增量构建的影响。

开源政策：

- Apache-2.0；
- 可商业使用和修改；
- 保留许可证、NOTICE 和版权信息；
- 审核插件注入到 APK 中的 helper/runtime 代码及其依赖。

### 6.2 路线 B：dProtect 替换全应用 R8

```text
Java/Kotlin 编译
        ↓
dProtect/ProGuard 管线
        ↓
DEX
```

dProtect 能力：

- 算术混淆；
- 字符串混淆；
- 常量混淆；
- 控制流混淆；
- ProGuard 风格裁剪、优化和名称混淆。

关键约束：

- dProtect 官方 Android 示例明确要求 `minifyEnabled false`，防止 R8 同时运行；
- 必须验证当前 AGP、Kotlin、Compose、协程、Hilt/Dagger、Room、KSP/KAPT、AAB 和多模块兼容性；
- dProtect 文档也说明部分 Pass 存在公开去混淆攻击，不应视为不可破解。

许可证政策：

- GPL-2.0；
- 内部使用和修改允许；
- 若向外分发修改后的 dProtect 工具，应按 GPL-2.0 提供对应源码和许可证；
- GNU GPL FAQ 说明，GPL 程序的输出一般不因工具许可证自动受 GPL 约束，除非输出复制了程序本身受保护的实质内容；
- 必须检查 dProtect 是否把注解、运行时 helper 或其他 GPL 组件打入最终 APK；
- 在闭源商业应用采用前，完成一次正式开源合规评审。

### 6.3 路线 C：隔离安全 SDK 使用 dProtect，App 继续使用 R8

```text
security-sdk 源码
        ↓
dProtect Standalone
        ↓
预混淆 AAR/JAR
        ↓
主 App 引用
        ↓
R8 处理其余代码
```

适用条件：

- 安全逻辑能拆为窄接口 SDK；
- 团队能维护 dProtect mapping 和 R8 mapping 两套映射；
- JNI、反射和序列化边界清晰；
- CI 能对预混淆 SDK 和最终 App 分别测试。

主 App 需要避免再次破坏 SDK 接口，例如：

```proguard
-keep class x.y.z.publicapi.** {
    public *;
}
```

风险：

- 双重处理链增加构建、崩溃还原和许可证审计复杂度；
- dProtect 混淆后的包名、JNI 符号和序列化字段需稳定；
- 只建议有专门构建安全人员的团队采用。

### 6.4 BlackObfuscator 的位置

BlackObfuscator 只解决 DEX 控制流可读性问题，不负责完整性、反调试或设备证明。

```text
R8 输出 DEX
       ↓
BlackObfuscator 仅处理业务核心包
       ↓
重新打包和签名
```

适用场景：

- 无法迁移到 Native；
- 某些 Java/Kotlin 核心方法需要额外提高阅读成本；
- 已有充分的 DEX 回归测试。

不建议同时叠加 dProtect 控制流混淆、BlackObfuscator 和 dpt-shell 到全部 DEX。

---

## 7. 阶段三：Native 安全核心与 O-MVLL

### 7.1 模块结构

```text
security-core/
├── CMakeLists.txt
├── include/
│   └── security_api.h
├── src/
│   ├── jni_bridge.cpp
│   ├── request_signer.cpp
│   ├── challenge_response.cpp
│   ├── integrity_checker.cpp
│   ├── runtime_signal_encoder.cpp
│   └── crypto_wrapper.cpp
└── omvll/
    └── omvll_config.py
```

### 7.2 功能对应

| 功能 | 项目 |
|---|---|
| Kotlin/Java 与 Native 桥接 | Android NDK/JNI |
| Native 控制流、字符串、常量、间接调用等混淆 | O-MVLL |
| 密钥生成与硬件持有 | Android Keystore |
| 服务端 Challenge 响应 | 自研 security-core + 服务端 |
| Native 符号裁剪 | Clang/LLD/strip |

### 7.3 JNI 接口设计

不推荐：

```kotlin
external fun isSafe(): Boolean
```

攻击者只需把返回值固定为 `true`。

推荐：

```kotlin
internal object SecurityBridge {
    init {
        System.loadLibrary("security_core")
    }

    external fun signRequest(
        canonicalPayload: ByteArray,
        serverChallenge: ByteArray,
        timestampMillis: Long
    ): ByteArray

    external fun collectRuntimeSignals(
        sessionNonce: ByteArray
    ): ByteArray
}
```

设计要求：

- 接口数量少、参数明确；
- 不返回单一安全布尔值；
- 输出绑定服务端 nonce、用户会话和请求摘要；
- Native 不保存服务端主密钥；
- 使用 Keystore 设备密钥签名时，私钥不可导出。

### 7.4 O-MVLL 配置策略

O-MVLL 通过 Clang `-fpass-plugin` 集成，规则由 Python API 控制。官方文档当前主要支持 AArch64/AArch32；Windows 交叉编译支持需要单独验证。

示例：

```python
import omvll

class AppSecurityConfig(omvll.ObfuscationConfig):
    def flatten_cfg(self, module, function):
        protected = {
            "sign_critical_request",
            "verify_license_challenge",
            "encode_runtime_signals",
        }
        return function.name in protected

    def obfuscate_string(self, module, function, value):
        return function.name.startswith("security_")
```

推荐强度：

| 等级 | 保护对象 | Pass 建议 |
|---|---|---|
| 低 | security-core 一般函数 | 字符串、常量、少量间接调用 |
| 中 | 请求签名、许可证响应 | 算术、常量、间接调用、局部控制流 |
| 高 | 3～10 个关键函数 | 多 Pass 组合、自定义选择条件、每版本变化 |

不要重度保护：

- 音视频实时循环；
- 图像处理热路径；
- 大量内存复制；
- 高频 JSON/Protobuf 解析；
- 第三方大型 Native 库；
- 启动早期的全部 JNI 初始化逻辑。

### 7.5 O-MVLL 许可证落地

- Apache-2.0；
- 工具可内部使用、修改和商业部署；
- 如果分发修改后的 O-MVLL，保留 LICENSE/NOTICE 并标记修改；
- 归档 O-MVLL 源码版本、构建产物、LLVM/NDK 版本和 Python 配置；
- 最终 APK 通常只包含混淆后的业务机器码，不包含 O-MVLL 工具本体；仍应在内部 SBOM/构建工具清单记录该工具。

---

## 8. 阶段四：运行时风险信号

### 8.1 推荐实现方式

默认使用自研 `security-runtime`，将检测拆散在多个业务路径，不集中为一个 `checkEverything()`。

```text
security-runtime/
├── AppSignatureSignal
├── InstallSourceSignal
├── DebuggerSignal
├── RuntimeMapSignal
├── NativeCodeIntegritySignal
├── RootEnvironmentSignal
├── EmulatorSignal
└── RiskEnvelopeEncoder
```

### 8.2 功能对应

| 风险信号 | 推荐实现/项目 |
|---|---|
| 当前签名证书摘要 | Android PackageManager + 自研 |
| 安装来源 | Android InstallSourceInfo + Play Integrity |
| Debuggable/调试器状态 | Android API + Native 自研；dpt-shell 可提供补充 |
| 关键 Native `.text` 完整性 | 自研 hash/CRC；dpt-shell 可提供基础 CRC |
| Hook/注入异常 | 自研多信号；dpt-shell/freeRASP 可补充 |
| Root/系统修改 | 自研多信号、Play Integrity/freeRASP |
| 模拟器 | 自研启发式、freeRASP |
| App/Device 绑定 | Keystore 设备密钥；freeRASP 提供供应商方案 |
| 环境风险上报 | 自研风险信封 + 服务端 |

### 8.3 风险信封

```json
{
  "schema": 1,
  "sessionId": "server-issued",
  "nonceHash": "base64url-sha256",
  "appVersion": 123,
  "signals": {
    "signature": 0,
    "debugger": 1,
    "nativeIntegrity": 0,
    "hookRisk": 2,
    "rootRisk": 1
  },
  "monotonicCounter": 51,
  "timestampMillis": 0,
  "deviceKeySignature": "base64url"
}
```

要求：

- 信封必须绑定服务端 Challenge；
- 使用设备密钥签名，而不是客户端硬编码 HMAC 密钥；
- 服务端校验时效、计数器、会话和重放；
- 不把单个信号直接映射为永久封禁；
- 关键检测在 Java 和 Native 多点交叉产生。

### 8.4 分级处置

| 风险等级 | 服务端动作 |
|---|---|
| 0 | 正常执行 |
| 1 | 缩短 Token、增加审计、降低频率 |
| 2 | 触发重新登录、生物认证或短信二次验证 |
| 3 | 拒绝支付、提现、兑换、授权等高价值操作 |
| 4 | 拒绝会话并提示安装官方版本或修复环境 |

### 8.5 freeRASP 的使用边界

freeRASP 可以快速补充 Root、Hook、篡改、模拟器和安装来源检测，但必须明确：

- SDK 不是纯开源；
- 开源部分使用 MIT，闭源二进制属于 Talsec；
- 受 Freemium/Fair Usage Policy 约束；
- 商业高级能力、支持和维护属于商业版；
- 应评估其遥测、隐私披露、离线行为、供应链和退出迁移成本；
- 不把 freeRASP 回调直接作为服务端唯一可信证据。

---

## 9. 阶段五：应用与设备证明

## 9.1 Google Play 渠道：Play Integrity

### 功能对应

| 功能 | 项目/服务 |
|---|---|
| 应用是否为 Google Play 认可版本 | Play Integrity `appIntegrity` |
| 设备完整性判定 | Play Integrity `deviceIntegrity` |
| 账号/许可状态 | Play Integrity `accountDetails` 等判定 |
| 请求内容绑定 | Standard Request `requestHash` |
| 标准请求重放缓解 | Play Integrity 自动保护 + 服务端业务 nonce |

标准请求流程：

```text
服务端生成 challenge/sessionId/expireAt
        ↓
客户端稳定序列化业务请求
        ↓
requestHash = SHA-256(canonicalRequest)
        ↓
客户端请求 Play Integrity Token
        ↓
客户端发送业务请求 + Token + runtime risk envelope
        ↓
服务端调用 Google 解码并验证 Token
        ↓
服务端重算 requestHash、检查时效和判定
        ↓
服务端执行风险策略
```

稳定序列化示例：

```text
v1
operation=license_activate
userId=123456
targetId=product_001
amountMinor=0
timestampMillis=...
challenge=...
```

不要直接对普通 JSON 字符串哈希，除非已定义：

- 字段排序；
- 字符编码；
- 数值格式；
- 空值规则；
- 转义规则；
- 版本号。

### 开源政策

- Play Integrity 是 Google 专有服务，不是开源项目；
- 客户端库和文档公开不代表判定引擎开源；
- 受 Google Play/API 条款、配额和数据处理政策约束；
- 需要在隐私和数据安全申报中评估所收集的应用、设备和环境信息；
- 设计降级路径，避免 Google 服务临时不可用时整个 App 不可用。

## 9.2 多渠道：Android Keystore + Key Attestation

流程：

```text
首次注册
  1. 客户端在 Android Keystore 生成不可导出 EC 密钥
  2. 使用服务端 challenge 请求 Key Attestation
  3. 上传证书链和公钥
  4. 服务端验证链、根、Security Level、应用信息和吊销状态
  5. 服务端注册 deviceKeyId

每次敏感请求
  1. 服务端下发一次性 challenge
  2. 客户端设备私钥签名 canonicalRequest
  3. 服务端验证签名、会话、时效和重放
```

服务端必须检查：

- X.509 证书链签名；
- 可信 attestation root；
- `attestationSecurityLevel` 为 `TrustedEnvironment` 或 `StrongBox`；
- 证书吊销状态；
- challenge 与服务端原始值一致；
- 应用包名和签名摘要（若证明扩展提供且策略需要）；
- 密钥用途、算法、生成时间和设备注册状态。

### 开源政策

- Android Keystore/Key Attestation 是平台能力，不是独立第三方库；
- AOSP 大部分用户空间软件采用 Apache-2.0，但具体设备 TEE、StrongBox、KeyMint 和厂商实现可能包含闭源部分；
- Google attestation 根、远程密钥配置和验证基础设施不是由应用团队控制的纯开源服务；
- 不能把“使用 AOSP API”描述为“整条设备证明链完全开源”。

---

## 10. 阶段六：可选 DEX 壳 dpt-shell

### 10.1 放置位置

```text
Java/Kotlin 编译
        ↓
R8（或 dProtect）
        ↓
O-MVLL Native 编译
        ↓
生成待发布 APK/AAB
        ↓
基础功能测试
        ↓
dpt-shell 后处理
        ↓
签名/对齐
        ↓
完整回归与安全测试
```

### 10.2 功能对应

dpt-shell 当前公开能力包括：

- 抽空 DEX 方法实现；
- 运行时重建方法代码；
- APK/AAB 输入；
- 运行时反调试；
- Frida 检测；
- Native `libc .text` CRC 检测；
- 可选运行时签名校验；
- 按规则排除类和 ABI。

### 10.3 推荐范围

第一阶段只保护：

```text
com.company.auth
com.company.license
com.company.payment
com.company.security
```

优先排除：

```text
androidx.**
kotlin.**
kotlinx.**
com.google.**
第三方支付/推送 SDK
Application 和 AppComponentFactory 初始化链路
ContentProvider 启动入口
Dynamic Feature 入口
Compose/协程大量生成代码
```

### 10.4 Play App Signing 注意事项

dpt-shell `--verify-sign` 从用于签名的 keystore 计算证书 SHA-256。Play App Signing 下：

- 上传 AAB 的上传密钥；
- Google 最终分发 APK 使用的应用签名密钥；

通常不是同一把密钥。因此：

- Google Play AAB 不应默认启用 dpt-shell 内置 `--verify-sign`；
- 应使用 Play Console 的应用签名证书摘要实现自有校验；
- 支持签名密钥轮换和证书 lineage；
- 以 Play Integrity `appIntegrity` 作为主要服务端判定；
- 国内渠道/自有 APK 使用固定最终签名密钥时，再评估 `--verify-sign`。

### 10.5 开源与供应链政策

- dpt-shell 本体为 MIT；
- 项目引用多个第三方库和子模块；
- 由于部分 shell/runtime 代码会进入最终 APK，必须对最终产物做实际依赖扫描，而不能只记录 dpt-shell 顶层 MIT；
- 建立 `THIRD_PARTY_NOTICES.md` 和 CycloneDX/SPDX SBOM；
- 固定 commit/tag，并在内部制品仓库保存源码快照；
- 项目 README 明确提醒测试数量不多，生产使用风险自担，因此必须保留一键关闭和回滚能力。

---

## 11. 服务端安全路线

客户端加固只能提高逆向成本，最终安全边界应位于服务端。

### 11.1 必须实现

| 功能 | 实现 |
|---|---|
| 一次性 Challenge | 服务端生成，高熵，短时有效，使用后失效 |
| 请求内容绑定 | canonical request + SHA-256/requestHash |
| Token 时效 | 高风险环境缩短 Token 生命周期 |
| 设备绑定 | Key Attestation 注册的设备公钥 |
| 重放保护 | Challenge、计数器、幂等键和时间窗口 |
| 风险评分 | Play Integrity + runtime signals + 行为信号 |
| 速率限制 | 用户、设备、IP、操作四维限流 |
| 二次认证 | 生物认证、短信、密码或人工复核 |
| 密钥轮换 | 服务端签名密钥、证书根和客户端允许列表可轮换 |
| 审计 | 记录判定依据、版本、设备键和请求摘要 |

### 11.2 服务端判定伪代码

```text
verify(request):
    validate_session(request.session)
    reject_if_expired(request.timestamp)

    challenge = consume_challenge(
        request.sessionId,
        request.challengeId
    )

    expected_hash = sha256(canonicalize(request.businessPayload))

    play_result = verify_play_integrity(request.integrityToken)
    require(play_result.requestHash == expected_hash)
    require(play_result.packageName == EXPECTED_PACKAGE)

    device_key = load_registered_device_key(request.deviceKeyId)
    verify_signature(
        device_key,
        expected_hash || challenge,
        request.deviceSignature
    )

    runtime_risk = verify_runtime_envelope(
        request.runtimeSignals,
        challenge
    )

    score = risk_engine(
        play_result,
        runtime_risk,
        account_history,
        device_history,
        request_behavior
    )

    return policy_decision(score, request.operation)
```

### 11.3 不允许

- 客户端上传 `isSafe=true`，服务端直接信任；
- 客户端自己决定支付、授权或许可证永久有效；
- 使用客户端硬编码对称密钥给风险信号做 HMAC；
- 只依赖 Root 检测拒绝所有用户；
- Integrity Token 未绑定具体请求；
- Challenge 可重复使用或长期有效。

---

## 12. 工程目录建议

```text
root/
├── app/
│   ├── src/main/
│   ├── src/main/keepRules/
│   └── proguard-rules.pro
├── security-api/
│   └── Kotlin 公共窄接口
├── security-runtime/
│   └── Java/Kotlin 运行时风险采集
├── security-core/
│   ├── src/main/cpp/
│   ├── CMakeLists.txt
│   └── omvll/omvll_config.py
├── security-protocol/
│   └── canonical request、risk envelope schema
├── security-server/
│   └── Challenge、Integrity、设备键和风险策略
├── security-tests/
│   ├── static/
│   ├── dynamic/
│   └── compatibility/
├── compliance/
│   ├── THIRD_PARTY_NOTICES.md
│   ├── licenses/
│   └── sbom/
└── build-logic/
    └── protectedRelease 构建逻辑
```

---

## 13. 构建变体与 CI/CD

### 13.1 构建变体

```text
debug
├── 无混淆或最小混淆
├── 无壳
└── 完整调试能力

release
├── R8
├── 正常 NDK 优化
└── 普通功能回归

protectedRelease
├── R8 或 dProtect（二选一）
├── LSParanoid（可选）
├── O-MVLL
├── 自研 runtime signals
├── Play Integrity/Key Attestation
├── dpt-shell（可选）
└── 安全、性能、兼容性全量回归
```

### 13.2 Pipeline

```text
1. 许可证/SBOM 扫描
2. 单元测试
3. Kotlin/Java 编译
4. R8 或 dProtect
5. O-MVLL Native 编译
6. 生成 APK/AAB
7. 基础 UI 自动化
8. 可选 dpt-shell 后处理
9. 最终签名和 zipalign
10. 全量 UI/设备兼容测试
11. 静态反编译验收
12. 动态 Hook/调试验收
13. 性能基线对比
14. 归档 mapping、符号、配置和许可证
15. 内部测试轨道
16. 灰度发布
17. 崩溃/ANR/风控误报监控
```

### 13.3 每个发布版本归档

```text
mapping.txt
configuration.txt
seeds.txt
usage.txt
Native 未剥离符号
Native Build ID
R8/dProtect 规则
O-MVLL Python 配置
dpt-shell 规则和源码版本
AGP、R8、JDK、NDK、LLVM 版本
最终签名证书 SHA-256
APK/AAB SHA-256
SBOM
THIRD_PARTY_NOTICES.md
Git commit
CI build number
```

---

## 14. 工具兼容关系

| 组合 | 结论 | 原因 |
|---|---|---|
| R8 + O-MVLL | **推荐** | 分别处理 Java/Kotlin 和 Native，职责清晰 |
| R8 + LSParanoid | **可用** | 字符串处理与 R8 基础优化互补；需测试任务顺序 |
| R8 + dpt-shell | **可选** | R8 先处理，dpt-shell 后处理；需做启动和 AAB 测试 |
| R8 + BlackObfuscator | **谨慎使用** | 只对少量业务 DEX；增加后处理风险 |
| dProtect + O-MVLL | **可用** | Java/Native 分层，但 dProtect 兼容性和 GPL 合规需验证 |
| R8 + dProtect 全应用串联 | **不推荐** | 两者都是全应用字节码优化/混淆主处理器，官方 dProtect 路线要求关闭 R8 |
| dProtect + LSParanoid | **一般不需要** | dProtect 已提供字符串混淆，重复处理收益低 |
| dProtect + BlackObfuscator | **不推荐默认叠加** | 多重控制流处理增加崩溃、体积和调试成本 |
| dpt-shell + BlackObfuscator 全量 | **不推荐** | 多重 DEX 后处理，兼容性和回滚复杂 |
| dpt-shell `--verify-sign` + Play App Signing AAB | **需自定义验证** | 上传证书与最终应用签名证书可能不同 |
| freeRASP + 自研检测 | **可选** | 能补充信号，但避免重复检测和误报；仍需服务端评分 |

---

## 15. 开源合规实施

### 15.1 建立组件台账

建议记录：

```yaml
name: o-mvll
version: pinned-tag-or-commit
source: https://github.com/open-obfuscator/o-mvll
license: Apache-2.0
usage: build-time-native-obfuscator
distributed_in_apk: false
modified: true
source_archive: internal-artifact-uri
notice_required: true
owner: mobile-security
```

### 15.2 判断是否进入最终 APK

| 项目 | 工具本体是否通常进入 APK | 需要重点审计 |
|---|---:|---|
| R8 | 否 | 构建工具许可证、嵌入依赖 |
| dProtect | 通常否 | 是否注入 annotation/helper/runtime；修改版工具分发 |
| O-MVLL | 否 | 是否复制 runtime/helper；LLVM 相关 NOTICE |
| LSParanoid | 可能注入 helper | 最终 DEX 中 helper 及依赖 |
| BlackObfuscator | 工具本体通常否 | DEX 转换依赖和注入代码 |
| dpt-shell | **是，shell/runtime 会进入 APK** | 所有打包 Native/Java 第三方依赖 |
| freeRASP | **是，闭源 SDK 二进制进入 APK** | 商业/免费政策、隐私、供应链 |
| Play Integrity 客户端库 | 是 | Google Play 服务条款和依赖许可 |
| Keystore API | 系统提供 | 设备实现和服务依赖，不随 APK 分发 |

### 15.3 发布制品要求

- `THIRD_PARTY_NOTICES.md`；
- 完整许可证副本；
- NOTICE 文件；
- CycloneDX 或 SPDX SBOM；
- 修改过的 Apache-2.0 组件标记修改；
- 修改/分发 GPL-2.0 工具时提供对应源码与构建说明；
- 保存下载来源、tag、commit 和 hash；
- 禁止从不明网盘或二次打包渠道引入安全工具；
- 定期检查项目归档、许可证变更和依赖漏洞。

### 15.4 GPL-2.0 特别说明

采用 dProtect 时应区分三种情况：

1. **内部 CI 使用未修改 dProtect，不向外分发工具**  
   通常只是在使用 GPL 工具，不自动要求业务 App 开源。

2. **向客户/合作方分发修改后的 dProtect 或其二进制**  
   需要按 GPL-2.0 提供对应源码、许可证和修改说明。

3. **最终 APK 包含来自 GPL 项目的实质代码或与 GPL 代码形成衍生组合**  
   可能触发更广泛义务，必须由法务和开源合规团队具体分析。

---

## 16. 验收标准

### 16.1 功能回归

必须覆盖：

- 冷启动、热启动；
- 登录、退出、Token 刷新；
- 支付、提现、授权、许可证；
- 推送、分享、Deep Link；
- WebView `JavascriptInterface`；
- 相机、相册、文件上传；
- Room/数据库迁移；
- Gson/Moshi/Jackson/Protobuf 序列化；
- JNI；
- WorkManager/后台任务；
- Dynamic Feature；
- 32 位/64 位 ABI；
- Play 内测安装和非 Play 渠道安装。

### 16.2 性能门槛

| 指标 | 建议门槛 |
|---|---:|
| 冷启动 P95 增幅 | ≤ 10% |
| 热启动 P95 增幅 | ≤ 5% |
| 高价值接口 CPU 增幅 | ≤ 10% |
| APK/AAB 体积增幅 | ≤ 15% |
| Java 崩溃率 | 不得显著上升 |
| Native 崩溃率 | 不得显著上升 |
| ANR | 不得显著上升 |
| Integrity 请求关键路径 | 按业务 SLA 单独定义 |

### 16.3 安全验收

使用 OWASP MASVS-RESILIENCE/MASTG 建立测试：

- JADX/apktool 静态分析；
- 关键字符串和类名检索；
- 修改关键条件分支；
- 重签名和非官方安装；
- 替换 DEX/Native 库；
- 调试器附加；
- Frida Hook Java/JNI 入口；
- 运行时内存字符串检索；
- 抓取并重放敏感请求；
- 伪造客户端风险字段；
- 绕过单个检测点；
- 模拟 Play Integrity 失败、超时或无服务；
- 模拟设备证明链无效或被吊销；
- 验证服务端能拒绝被篡改的高价值请求。

验收目标：

- 修改一个本地布尔值不能获得授权；
- 单次响应不能无限重放；
- 绕过一个检测点不能关闭全部保护；
- 客户端不存在长期主密钥；
- 服务端能识别请求、应用、设备和会话不一致；
- 崩溃堆栈能够用 mapping/Native 符号还原。

---

## 17. 分阶段实施计划

### 阶段 0：威胁建模与资产分级

交付：

- S0～S3 资产清单；
- 高价值业务请求清单；
- 当前密钥、Token 和授权逻辑审计；
- 攻击者能力模型；
- 开源组件准入清单。

### 阶段 1：R8 稳定基线

交付：

- 精确 Keep 规则；
- Release 全量回归；
- mapping 归档和线上 retrace；
- R8 前后包体积/启动性能对比；
- 无大范围 `-keep class **`。

### 阶段 2：Native 安全核心

交付：

- `security-core`；
- 3～10 个高价值函数迁移；
- JNI 窄接口；
- 服务端 Challenge 协议；
- 无永久秘密进入 Native。

### 阶段 3：O-MVLL

交付：

- 固定工具版本和源码快照；
- 按函数选择 Pass；
- 性能基线；
- arm64-v8a/armeabi-v7a 兼容测试；
- Native 崩溃符号链路。

### 阶段 4：运行时信号与服务端评分

交付：

- 风险信封 schema；
- 设备密钥签名；
- 多信号风险评分；
- 分级处置；
- 误报监控与策略回滚。

### 阶段 5：Integrity/Attestation

交付：

- Google Play：Standard Play Integrity + `requestHash`；
- 多渠道：Keystore + Key Attestation；
- 服务端证书链/吊销检查；
- 失败和降级策略；
- 数据合规说明。

### 阶段 6：可选增强

按风险收益依次评估：

1. LSParanoid；
2. dpt-shell；
3. BlackObfuscator；
4. 隔离 SDK dProtect；
5. 全应用 dProtect 替换 R8。

每次只增加一个变量，完成兼容性、性能和安全对比后再进入下一项。

---

## 18. 最终推荐方案

### 18.1 普通商业应用

```text
R8
+ 精确 Keep 规则
+ 少量 JNI
+ O-MVLL 局部混淆
+ 自研签名/调试/完整性风险信号
+ Play Integrity 或设备密钥
+ 服务端 Challenge 与风险评分
```

全部核心构建工具可选纯开源组件；Play Integrity 属于专有服务。

### 18.2 会员、版权内容、软件授权、一般游戏

```text
普通商业应用方案
+ LSParanoid
+ Native 代码段完整性
+ 更短 Token
+ dpt-shell 核心包试点
```

dpt-shell 仍需独立灰度和一键回滚。

### 18.3 金融、支付、强反作弊、高价值授权

```text
R8 或 dProtect（二选一）
+ 独立 security SDK
+ O-MVLL 自定义策略
+ 分布式运行时检测
+ Play Integrity
+ Key Attestation
+ 服务端设备绑定、Challenge、行为风控
+ 可选 dpt-shell
+ 定期人工逆向与红队测试
```

即使采用最高档组合，也不应声称完全替代商业加固的代码虚拟化、持续设备情报、规则更新和专业对抗服务。

---

## 19. 决策清单

上线前逐项确认：

- [ ] 服务端主密钥和完整风控规则未进入客户端；
- [ ] R8 与 dProtect 已明确二选一；
- [ ] Keep 规则按反射/JNI/序列化入口精确配置；
- [ ] O-MVLL 只作用于关键非热点函数；
- [ ] 客户端风险信号绑定服务端 Challenge；
- [ ] 服务端不信任单一 `isSafe` 布尔值；
- [ ] Play Integrity 使用 `requestHash` 绑定稳定序列化请求；
- [ ] Key Attestation 在服务端验证证书链、根和吊销；
- [ ] dpt-shell 已完成 AAB、启动、签名和低端机测试；
- [ ] Play App Signing 下未错误使用上传证书做最终签名校验；
- [ ] freeRASP 被标记为混合开源/闭源供应商 SDK；
- [ ] Obfuscapk 未进入新生产构建链；
- [ ] `THIRD_PARTY_NOTICES.md`、LICENSE、NOTICE 和 SBOM 完整；
- [ ] mapping、Native 符号和工具配置已归档；
- [ ] 已完成 OWASP MASVS/MASTG 静态和动态测试；
- [ ] 所有防护均有远程策略开关、灰度和回滚能力。

---

## 20. 官方参考资料

### Android 与 Google

- [R8 官方源码仓库](https://r8.googlesource.com/r8/)
- [R8 BSD-3-Clause LICENSE](https://r8.googlesource.com/r8/+/refs/heads/main/LICENSE)
- [Android：使用 R8 启用应用优化](https://developer.android.com/topic/performance/app-optimization/enable-app-optimization)
- [Android：R8 Keep 规则概览](https://developer.android.com/topic/performance/app-optimization/keep-rules-overview)
- [Play Integrity API](https://developer.android.com/google/play/integrity)
- [Play Integrity Standard Request](https://developer.android.com/google/play/integrity/standard)
- [Play Integrity 判定](https://developer.android.com/google/play/integrity/verdicts)
- [Play Integrity 条款与数据安全](https://developer.android.com/google/play/integrity/terms)
- [Android Key Attestation](https://developer.android.com/privacy-and-security/security-key-attestation)
- [AOSP 许可证说明](https://source.android.com/docs/setup/contribute/licenses)

### 开源加固项目

- [dProtect](https://github.com/open-obfuscator/dProtect)
- [dProtect 官方文档](https://obfuscator.re/dprotect/)
- [dProtect Android 集成](https://obfuscator.re/dprotect/introduction/getting-started/)
- [O-MVLL](https://github.com/open-obfuscator/o-mvll)
- [O-MVLL 官方文档](https://obfuscator.re/omvll/introduction/)
- [dpt-shell](https://github.com/luoyesiqiu/dpt-shell)
- [BlackObfuscator](https://github.com/CodingGay/BlackObfuscator)
- [LSParanoid](https://github.com/LSPosed/LSParanoid)
- [Obfuscapk](https://github.com/ClaudiuGeorgiu/Obfuscapk)
- [freeRASP Android](https://github.com/talsec/Free-RASP-Android)

### 标准与许可证

- [OWASP MASVS-RESILIENCE](https://mas.owasp.org/MASVS/11-MASVS-RESILIENCE/)
- [OWASP MASTG](https://github.com/OWASP/mastg)
- [GNU GPL FAQ：GPL 工具输出的许可证边界](https://www.gnu.org/licenses/gpl-faq.en.html)
- [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0.html)
- [MIT License](https://opensource.org/license/mit)

---

## 附录 A：推荐落地组合摘要

```text
【必须】
R8（BSD-3-Clause）
O-MVLL（Apache-2.0）
自研 security-runtime（组织自有许可证）
服务端 Challenge/风险评分（组织自有）
Play Integrity（专有服务）或 Key Attestation（平台能力）
OWASP MASVS/MASTG 验收

【可选】
LSParanoid（Apache-2.0）
dpt-shell（MIT）
BlackObfuscator（Apache-2.0）

【替代路线】
dProtect（GPL-2.0）替换全应用 R8
或只处理隔离 security SDK

【不作为纯开源组件】
freeRASP：MIT 开源部分 + 闭源二进制 + Freemium 政策
Play Integrity：Google 专有服务
Android Key Attestation：AOSP/平台 API + 设备硬件/厂商/Google 基础设施

【不推荐新生产项目】
Obfuscapk：MIT，但已于 2024-07-27 归档
```
