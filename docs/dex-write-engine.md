# DroidSeal 有损加固设计文档（DEX 写引擎 + ARSC 资源混淆）

> 状态：**研究实现已分阶段交付，默认产品主线仅接入 ARSC**。本文既保存格式设计，也记录真实接线边界：
> - **#2 ARSC 资源混淆**：N0～N4 已完成，并作为 14 步流水线中的显式可选步骤接入；仍要求重新对齐、签名和真机资源回归。
> - **#1 DEX 注入反调试**：M0～M4 的编解码、受限写回、变长 AXML 和新增 `classesN.dex` 实验模块已有代码与合成测试，但 `lossy-inject.ts` 未被 `pipeline.ts` 导入，尚缺真实 APK/多版本设备的 Stage-B 兼容矩阵，因此不是当前受支持的 UI/发布能力。
> - **#3 DEX 字符串加密**：已完成标识符排除、安全子集选择、密码和非破坏性计划；运行时解密器注入、指令扩展、分支修正和寄存器重分配刻意未实现，不会改写用户 DEX。
>
> README 是当前用户能力的事实入口；本文件用于解释实现原理、失败关闭子集和尚未满足的接入门禁。里程碑状态见 §12 与 §14.8。
---

## 1. 背景与目标

### 1.1 为什么需要写引擎

DroidSeal 默认主线仍只把 DEX 字符串池读取用于启发式审计；仓库中的研究模块已扩展到受限写回，但两项有损能力若要成为面向任意真实 APK 的正式功能，仍必须**重写 DEX 字节并证明 ART 能稳定装载**：

- **#1 DEX 注入反调试**：把反调试检测（native + Java 侧）注入成品 APK，并让它在应用启动时自动运行。需要新增类、改写方法字节码或改写 AndroidManifest 入口。
- **#3 DEX 字符串加密**：加密敏感字符串常量，运行时解密。需要新增解密方法、改写每处 `const-string` 引用。

两者都无法靠"就地改几个字节"完成——DEX 是强交叉引用、带全局校验和的紧凑二进制格式，任何增删都会牵动全局偏移、索引排序、`map_list` 与 header 校验和。因此必须实现一个完整的**解析 → 内存模型 → 重排序列化**引擎，本质上等价于纯 TypeScript 重造 dexlib2/baksmali 的 DEX writer。

### 1.2 明确的非目标

- **不做 VMP / 控制流虚拟化**：不把 DVM 字节码翻译成自定义 VM。
- **不做运行时加壳/解壳加载器**：不实现 DEX 加密壳 + 自定义 ClassLoader 的整包加壳。
- **#2 arsc 资源混淆是独立子工程**：不依赖本 DEX 写引擎，走 ARSC 解析/重写 + ZIP 条目改名路线，完整设计见 §14。
- **不追求对抗性强度上限**：注入/加密是"提高逆向成本"的纵深防御，不是不可破解的屏障。

### 1.3 关键发现：读→写的鸿沟与当前结果

本设计最初从“只有读取和等长就地改写”的基线出发；此后已交付受限 DEX/AXML 写回与完整 ARSC 主线，但“受限合成测试通过”仍不等于“能够任意重写真实 APK”。这个鸿沟继续决定三项能力的产品接入级别。

**当前基础设施**

- **ZIP 读写**：`parseRawZip` + `buildZip`（`src/core/harden-manifest.ts`）已支持 STORED(0)/DEFLATE(8) 的解包与重打包，`crc32Of` 算条目 CRC，node:zlib `deflateRawSync/inflateRawSync` 做压缩。条目增删改名完全可用。
- **AXML 编辑**：`flipDebuggableInAxml` 负责等长布尔翻转；`axml-writer.ts` 已能重建字符串池并把既有 `<application android:name>` 重指向更长类名，但仍不能在缺少该属性时安全新增属性。
- **DEX 读取与受限写回**：`extractDexStrings` 用于默认审计；`dex-codec.ts`、`dex-model.ts`、`dex-writer.ts` 已实现编解码、校验和、表重排和受限类/指令写回，对 try/debug/注解/未知 opcode 等结构失败关闭。

**三项能力的成本与接线结果**

| 能力 | 固有复杂度 | 技术路线 | 当前仓库状态 |
|---|---|---|---|
| **#2 ARSC 资源混淆** | 中等、边界清晰 | 自研 ARSC 解析/重写 + ZIP 条目改名；不碰 DEX | **已接入主线**：显式可选、严格白名单、失败回退 |
| **#1 DEX 注入反调试** | 研究级 | 受限新 DEX + 变长 AXML + Adler-32/SHA-1 | **仅研究模块**：合成测试已完成，真实设备 Stage-B 和兼容子集不足，未接入主线 |
| **#3 DEX 字符串加密** | 研究级 | 安全子集 + 解密器 + 指令/寄存器/偏移重写 | **只完成非破坏性计划**：没有运行时解密改写，不修改用户 APK |

**#1/#3 的产品边界**

#1/#3 仍接近用纯 TypeScript 重建 dexlib2/baksmali 的高风险子集，最危险的失败不是立即报错，而是安装后在特定 ART/ROM/代码路径崩溃。仓库保留这些实现用于格式研究和逐步验证，但默认产品坚持失败关闭：只有 ARSC 路线进入正式流水线；反调试优先使用 `src/assets/antidebug-stub/` 的源码构建期集成；字符串保护只保留安全子集/密码计划，不伪装成已经完成运行时加密。
---

## 2. 定位冲突与前置条件

### 2.1 与现有定位的冲突（须由用户显式接受）

| 现有定位 | 冲突点 |
|---|---|
| 核心零运行时依赖 | 市面无成熟纯 JS DEX 汇编器，只能自研；实现体量巨大（见 §11） |
| 无损后处理（绝不改业务字节） | 注入/加密**主动改写 DEX 业务字节**，是有损操作 |
| 可复现 / 可审计 / 可回退 | 改写引入随机密钥、注入代码，产物不再逐字节可复现；需靠备份保证可回退 |
| 失败即安全回退 | DEX 写错的失败模式是"装得上但运行崩"或"ART 拒装"，比构建失败更隐蔽 |

### 2.2 强制前置条件（正式接入时必须落实）

1. **opt-in**：默认关闭，用户在向导中显式勾选"有损加固"。
2. **处理前明确提示**：列明将改写哪些内容、可能的运行时风险、可能被 Play Protect 标记。
3. **自动备份原包**：改写前把原始 APK 完整复制到独立备份路径，并在报告中记录备份位置与原始 SHA-256。
4. **报告标注"已有损改写"**：新增 finding（如 `LOSSY_DEX_REWRITTEN`），如实记录改写范围、注入类名、加密字符串数量、随包密钥指纹。
5. **改写后强制重签名**：DEX 变更使原签名失效，必须走 sign + verify，且 verify 里 ART 侧校验（若有工具）应通过。

### 2.3 外部约束

- **Play Protect / 上架审核**：注入 native、动态特征、加密字符串是常见"加固/恶意"信号，可能影响信任与上架。
- **ART 版本演进脆弱性**：ART 对 DEX 校验逐版本收紧；今天能装的产物未必在新版本稳定。
- **无源码 keep 信息**：post-hoc 改写缺少语义信息（反射、序列化、JNI 绑定），注入/改写易在运行时崩。
- **与 app 自带完整性校验冲突**：若应用本身做签名指纹/资源哈希自检，改写会触发其自毁逻辑。

---

## 3. DEX 格式完整参考（写引擎必须覆盖的全部结构）

> 全部小端序（`endian_tag = 0x12345678`）。偏移量为字节。多数结构要求 **4 字节对齐**。

### 3.1 `header_item`（默认 `header_size = 0x70` = 112 字节）

| 偏移 | 字段 | 大小 | 说明 |
|---|---|---|---|
| 0x00 | `magic` | 8 | `"dex\n035\0"`（或 037/038/039/03A 视版本） |
| 0x08 | `checksum` | 4 | **Adler-32**，覆盖 0x0c 之后到文件尾 |
| 0x0c | `signature` | 20 | **SHA-1**，覆盖 0x20 之后到文件尾 |
| 0x20 | `file_size` | 4 | 整个 DEX 字节数 |
| 0x24 | `header_size` | 4 | 恒为 0x70 |
| 0x28 | `endian_tag` | 4 | 0x12345678 |
| 0x2c | `link_size` / `link_off` | 8 | 通常 0 |
| 0x34 | `map_off` | 4 | `map_list` 偏移 |
| 0x38 | `string_ids_size` / `string_ids_off` | 8 | 字符串索引区 |
| 0x40 | `type_ids_size` / `type_ids_off` | 8 | 类型索引区 |
| 0x48 | `proto_ids_size` / `proto_ids_off` | 8 | 原型索引区 |
| 0x50 | `field_ids_size` / `field_ids_off` | 8 | 字段索引区 |
| 0x58 | `method_ids_size` / `method_ids_off` | 8 | 方法索引区 |
| 0x60 | `class_defs_size` / `class_defs_off` | 8 | 类定义区 |
| 0x68 | `data_size` / `data_off` | 8 | 数据区 |

> 现有 `dex-scan.ts` 仅用到 0x38/0x3c（string_ids size/off）。写引擎必须解析并重写以上**全部** size/off 对。

### 3.2 索引区（定长项，均在 data 区之前，需维护排序不变量）

- `string_id_item`：`{ string_data_off: u32 }`。**string_ids 必须按其指向字符串的 UTF-16 码点序升序排列**（modified UTF-16 比较）。
- `type_id_item`：`{ descriptor_idx: u32 }`（指向 string_ids）。**按 descriptor 的 string_idx 升序**。
- `proto_id_item`：`{ shorty_idx: u32, return_type_idx: u32, parameters_off: u32 }`。**按 (return_type, parameters) 升序**。
- `field_id_item`：`{ class_idx: u16, type_idx: u16, name_idx: u32 }`。**按 (class, name, type) 升序**。
- `method_id_item`：`{ class_idx: u16, proto_idx: u16, name_idx: u32 }`。**按 (class, name, proto) 升序**。
- `class_def_item`：`{ class_idx, access_flags, superclass_idx, interfaces_off, source_file_idx, annotations_off, class_data_off, static_values_off }`（8×u32）。**约束：父类/接口若在同 DEX 内定义，须先于子类出现（拓扑序）**。

> **关键**：任何增删字符串/类型/方法都会打乱索引顺序，导致所有引用这些索引的地方（type_ids、method_ids、code_item 操作数……）需要**重新映射**。写引擎必须在 mutate 后统一"重排 + 重映射"。

### 3.3 数据区结构

- `string_data_item`：`ULEB128(utf16_length)` + `MUTF-8 字节` + `0x00` 终止符。
- `type_list`：`{ size: u32, list: type_item[size] }`，`type_item = { type_idx: u16 }`。4 字节对齐。
- `code_item`：`{ registers_size: u16, ins_size: u16, outs_size: u16, tries_size: u16, debug_info_off: u32, insns_size: u32, insns: u16[insns_size], (padding), try_item[tries_size], encoded_catch_handler_list }`。4 字节对齐。
- `try_item`：`{ start_addr: u32, insn_count: u16, handler_off: u16 }`（handler_off 指向 handler list 内偏移）。
- `encoded_catch_handler` / `encoded_catch_handler_list`：SLEB128/ULEB128 变长编码的异常处理表。
- `debug_info_item`：变长状态机字节码（行号/局部变量），含对 string/type 索引的引用（改索引时需同步修正，或直接丢弃 debug 信息作为简化）。
- `class_data_item`：`{ static_fields_size, instance_fields_size, direct_methods_size, virtual_methods_size }`（均 ULEB128），后跟 `encoded_field[]` 与 `encoded_method[]`，**用 ULEB128 增量(delta)编码 field_idx/method_idx**，且 encoded_method 含 `code_off`。
- `encoded_value` / `encoded_array` / `annotation_item` / `annotations_directory_item`：注解与静态初值编码（改索引时也需修正）。

### 3.4 `map_list`

- 结构：`{ size: u32, map_item[size] }`，`map_item = { type: u16, unused: u16, size: u32, offset: u32 }`。
- `type` 枚举（部分）：`HEADER_ITEM=0x0000`、`STRING_ID_ITEM=0x0001`、`TYPE_ID_ITEM=0x0002`、`PROTO_ID_ITEM=0x0003`、`FIELD_ID_ITEM=0x0004`、`METHOD_ID_ITEM=0x0005`、`CLASS_DEF_ITEM=0x0006`、`MAP_LIST=0x1000`、`TYPE_LIST=0x1001`、`ANNOTATION_SET_REF_LIST=0x1002`、`ANNOTATION_SET_ITEM=0x1003`、`CLASS_DATA_ITEM=0x2000`、`CODE_ITEM=0x2001`、`STRING_DATA_ITEM=0x2002`、`DEBUG_INFO_ITEM=0x2003`、`ANNOTATION_ITEM=0x2004`、`ENCODED_ARRAY_ITEM=0x2005`、`ANNOTATIONS_DIRECTORY_ITEM=0x2006`。
- **规则**：map_item 按 offset 升序；header 必在最前；每类 section 只出现一次；size/offset 必须与实际布局精确一致。ART 用 map_list 校验各 section 位置。

---

## 4. 校验和与签名重算

改写后必须按**固定顺序**重算，否则 ART 装载失败：

1. **先算 SHA-1 签名**：对 `[0x20, file_end)` 区间做 SHA-1，写入 0x0c..0x1f。用 `Bun.CryptoHasher("sha1")`（已在 `apk-audit.ts` 用 `Bun.CryptoHasher("sha256")` 验证可用）。
2. **再算 Adler-32 校验和**：对 `[0x0c, file_end)` 区间（**包含刚写入的 signature**）算 Adler-32，写入 0x08..0x0b。
3. 顺序不可颠倒：checksum 覆盖 signature，故 signature 必须先定稿。

Adler-32 参考实现（纯 TS，`MOD = 65521`）：
```
a=1, b=0; for byte in data: a=(a+byte)%65521; b=(b+a)%65521; return (b<<16)|a
```
> 建议每 ~5552 字节做一次取模以避免溢出（或用 BigInt 累加后取模）。JS number 精度足够按块处理。

**ART 校验点**：install/verify 时校验 checksum 与 map_list 一致性；signature 主要供工具与去重使用。checksum 错 → 直接拒装。

---

## 5. 编解码原语（读写均已实现）

现有 `dex-scan.ts:readUleb128` 只读。写引擎需补齐：

- **`writeUleb128(value): bytes`**：无符号 LEB128。
- **`writeUleb128p1(value): bytes`**：ULEB128 of (value+1)，用于可为 -1 的索引（如 debug_info 的 name_idx）。
- **`writeSleb128(value): bytes`**：有符号 LEB128（encoded_value、catch handler 用）。
- **`readSleb128` / `readUleb128p1`**：读方向补齐（现只有 `readUleb128`）。
- **MUTF-8 编码器**：
  - ASCII (U+0001..U+007F) → 单字节。
  - **U+0000 → 双字节 `0xC0 0x80`**（绝不能是裸 0x00，那是终止符）。
  - U+0080..U+07FF → 2 字节；U+0800..U+FFFF → 3 字节。
  - **补充平面 (U+10000+) → 编码为一对代理，每个代理各 3 字节（共 6 字节）**，非标准 UTF-8 的 4 字节。JS 字符串本就是 UTF-16，遍历 char code 即可。
- **MUTF-8 解码器**：现用 `TextDecoder("utf-8")` 是近似（对 0xC0 0x80 与 6 字节代理不完全正确），写引擎的 round-trip 需要精确 MUTF-8 解码以保证等价。

---

## 6. 引擎架构：解析 → 内存模型 → 重排序列化

### 6.1 三段式

```
parse(bytes) -> DexModel        // 全量解析进对象模型（不保留原始偏移，只保留语义）
mutate(DexModel) -> DexModel    // 增类 / 改字节码 / 加密字符串
serialize(DexModel) -> bytes    // 布局规划器：重排 + 重映射 + 对齐 + map_list + 校验和
```

### 6.2 内存模型（`DexModel`）

以**语义引用**替代原始 u32 偏移/索引：
- `strings: string[]`（去偏移，纯值）。
- `types: { descriptor: string }[]`（引用 string 值而非 idx）。
- `protos`, `fields`, `methods`：引用 type/string 语义对象。
- `classes: ClassDef[]`，每个含 `ClassData`（字段/方法）、每个方法含 `CodeItem`（指令、寄存器、try/handler、可选 debug）。
- 指令中的 string/type/field/method 操作数存**语义引用**，序列化时再解析为最终索引。

这样 mutate 阶段无需关心偏移；serialize 阶段统一分配。

### 6.3 布局规划器（serialize 核心）

1. **重建索引区并排序**：对 strings/types/protos/fields/methods 去重、按 §3.2 排序不变量排序，生成"语义对象 → 最终索引"映射表。
2. **分配数据区偏移**：按 map_list 推荐顺序布局 string_data、type_list、code_item、class_data、debug_info、annotations…，逐项 4 字节对齐，记录每项 offset。
3. **回填所有引用**：用映射表把指令操作数、class_def、method_id 等的语义引用解析成最终 u32/u16 索引与偏移。
4. **写 header 的全部 size/off 对** + **写 map_list**（各 section 的 type/size/offset）。
5. **算 signature，再算 checksum**（§4）。

### 6.4 正确性铁律

- 索引区排序不变量**必须**满足，否则 ART 二分查找失败 → 拒装。
- 交叉引用一致性：删除一个 string 必须确保无任何 type/field/method/指令仍引用它。
- code_item 的 `registers_size/ins_size/outs_size` 必须覆盖实际使用；`insns_size` 与指令字节数一致；try/handler 的地址以**指令单元(u16)**计数，改指令后必须修正。
- 对齐：code_item、type_list 等按 4 字节对齐并补零；对齐字节数也计入 offset。

### 6.5 黄金门禁（M0）

> 对**未修改**的真实/合成 DEX 执行 `parse → serialize`，输出必须与输入**逐字节等价**（或退一步：语义等价且通过 `dexdump` + ART `verify`）。

逐字节等价是最强保证，但因原 DEX 的 section 排列/对齐/debug 信息可能有实现差异，务实策略是：
- 阶段 A：对"由本引擎自己 serialize 出的 DEX"做 `parse→serialize` 幂等（自洽）。
- 阶段 B：对 d8 产出的真实 DEX 做语义等价（`dexdump -d` 前后一致）+ 真机 `pm install` 冒烟。

未过 M0 前，禁止进入任何 mutate 能力开发。

---

## 7. #1 DEX 注入反调试 — 详细设计

### 7.1 注入内容

注入一个新类 `Lcom/droidseal/inj/AntiDebug;`，含静态方法 `check()`：
- 纯 Java 侧：调用 `Landroid/os/Debug;->isDebuggerConnected()Z`、`waitingForDebugger()Z`。
- native 侧（可选）：`System.loadLibrary("droidseal_antidebug")` + `nativeTracerPid()` / `nativeHasInjectionArtifacts()`——复用现有源码 stub 的 C/JNI 实现（`src/assets/antidebug-stub/droidseal_antidebug.c`）。
- 处置策略：默认只上报（写 log / 供 app 决策），不主动崩溃（与 stub 一致）。

注入需新增：string_ids（类名、方法名、描述符）、type_ids、proto_ids、method_ids、一个 class_def + class_data + 至少一个 code_item（`check()` 的字节码）。

### 7.2 触发点（让注入代码真正运行）——两条路径

**路径 (a)：应用已有自定义 Application**
- 在其 `<init>` 或 `onCreate` 的 code_item 首部注入 `invoke-static {}, Lcom/droidseal/inj/AntiDebug;->check()V`。
- 影响：`insns_size` 增大、可能需要提升 `registers_size`/`outs_size`；其后所有指令地址位移，须修正 try_item.start_addr、handler 地址、debug_info 行号映射。
- 这是**最外科手术式**的字节码改写，风险最高。

**路径 (b)：无自定义 Application（或选择更稳方案）**
- 生成注入类继承原 application（若原为默认 `android.app.Application`，直接继承它），在注入类 `onCreate` 里 `super.onCreate()` + `check()`。
- 改 `AndroidManifest` 的 `application android:name` 指向注入类。
- **代价**：这是**变长 AXML 改写**——要往 AXML 字符串池加入新类名字符串，重建字符串池偏移表、resource map、各 chunk 的 size，与全量偏移修正。现有 `flipDebuggableInAxml` 只做**等长**就地改，**不够用**，需另写 `axml-writer.ts`（见 §13）。

> 建议优先实现 (b)：字节码改动小（只新增一个完整类，不改既有方法），但需 AXML 变长写引擎；(a) 反之。两者都需 DEX 写引擎。

### 7.3 打包 native 库

把 `libdroidseal_antidebug.so` 按 ABI 写入 `lib/arm64-v8a/`、`lib/armeabi-v7a/` 等，复用 `buildZip`（ZIP 条目名自由）。需预先交叉编译好各 ABI 的 .so 并作为资源随 DroidSeal 分发。

### 7.4 顺序

改 DEX（+可选改 AXML）→ 重新 zipalign → **必须重签名** → verify（含 ART 侧校验若可用）。

---

## 8. #3 DEX 字符串加密 — 详细设计

### 8.1 致命陷阱：string_ids 池被"字面量"和"标识符"共用

string_ids 池同时存放：
- **字符串字面量**（`const-string` 的操作数，可加密）。
- **标识符**：类描述符（`Lcom/...;`）、方法名、字段名、proto shorty、源文件名等（**加密即破坏类加载/反射，绝对不能碰**）。

### 8.2 安全子集构建算法

1. 解析 type_ids/proto_ids/field_ids/method_ids/class_defs/annotations/debug_info，收集所有**被当作标识符引用的 string_idx** → `identifierStrings` 集合。
2. 遍历所有 code_item，找 `const-string vAA, string@BBBB`(op=0x1a) 与 `const-string/jumbo vAA, string@BBBBBBBB`(op=0x1b) 的操作数 string_idx → `literalStrings` 集合。
3. **可加密集 = literalStrings − identifierStrings**（差集；任何同时作标识符的串排除）。
4. 可加选：只加密"疑似敏感"子集（复用 `secret-scan.ts` / `dex-scan.ts` 的启发式），减少改动面与误伤。

### 8.3 改写方案

- 新增解密方法 `Lcom/droidseal/inj/Crypto;->d(I)Ljava/lang/String;`（入参：密文表索引；返回：明文）。
- 加密后的密文存为：注入类的静态 `byte[]`/`String[]` 常量数组（`encoded_array_item` / static_values），或 assets 里的 blob（则解密方法读 assets）。
- 把每处 `const-string vX, @str` 改写为：`const vX, #index` + `invoke-static {vX}, Crypto->d(I)Ljava/lang/String;` + `move-result-object vX`。
- **影响**：单条指令 → 多条指令，`insns_size` 增大，可能需要更多寄存器（`registers_size` 提升，甚至触发 `const/16`→`const` 或 `move`→`move/16` 的寄存器编号扩展问题）；try/handler/debug 偏移全量修正。属 code_item 深度重写。

### 8.4 密钥方案

- 每次改写生成**随包随机对称密钥**（如 XOR + 位旋转的轻量方案，或 AES；注意解密方法本身在明文 DEX 中可被逆向——这是纯客户端加密的固有上限，须在报告中说明）。
- 随机源需可注入（避免 `Math.random`，用 `crypto.getRandomValues`）；把密钥指纹（非密钥本身）与加密字符串数量记入报告与备份元数据。

> 现实提醒：无 DEX 加壳配套时，解密逻辑与密文同处明文 DEX，逆向者可直接调用解密方法批量还原。字符串加密只抬高自动化扫描/静态搜索的成本，不是强保护。

---

## 9. 风险与失败模式清单

- **ART verify 拒装**：索引未排序、map_list 不一致、校验和错、offset 越界、对齐错。
- **装得上但运行崩**：寄存器分配不足、指令地址/try-handler 错位、debug_info 与代码不符、反射/JNI 依赖被改索引打断。
- **multidex**：`classes.dex` + `classes2.dex`…；注入类应放主 dex，跨 dex 引用需在正确 dex 内建 method_id。
- **D8 vs DX 差异**：新旧编译器产物的 section 排列/对齐差异，影响 M0 等价策略。
- **jumbo string**：字符串数 > 65535 时 `const-string` 需升级 `const-string/jumbo`；改写可能跨越该阈值。
- **code_item 4 字节对齐** 与 try_item 存在性（tries_size=0 时无 padding 规则差异）。
- **app 自带完整性校验**：签名指纹/资源哈希自检会因改写触发自毁。
- **Play Protect / 上架**：注入 native、加密串、动态加载特征可能被判可疑。
- **版本漂移**：ART 逐版本收紧，产物需在多版本回归。

---

## 10. 测试策略

- **合成 DEX 构造器**：扩展 `tests/tier2-audit.test.ts` 的 `buildDex()`，从"仅 string 池"升级到含 type_ids/method_ids/class_defs/class_data/code_item 的**可装载最小 DEX**。
- **M0 幂等/等价门禁**：`parse→serialize` 自洽幂等；对 d8 真实 DEX 做 `dexdump -d` 语义等价。
- **单元**：ULEB128/SLEB128/ULEB128p1 读写对拍；MUTF-8 编解码 round-trip（含 U+0000、补充平面）；Adler-32/SHA-1 对已知向量。
- **变异测试**：仅注入一个空类后仍通过 verify；加密安全子集后 `dexdump` 中标识符不变、字面量变为密文引用。
- **端到端**：合成/真实 APK → 注入/加密 → zipalign → 重签名 → apksigner verify；有条件时 `pm install` 冒烟矩阵（多 Android 版本 × 多 ABI）。
- **回归**：保持 `bun run check` / `bun test` / `bun run release:check` 全绿；新原语避免触发 release-check 密钥扫描（测试内密钥用运行时拼接，见现有 tier1/tier2 测试范式）。

---

## 11. 依赖决策

- **纯 TS vs 放宽零依赖**：主流 DEX 汇编器（smali/baksmali、dexlib2）均为 Java，无成熟、可信、活跃的纯 JS/TS DEX writer 可直接依赖。这反而**印证工作量之大**。
- **建议**：坚持纯 TS 自研（与项目定位一致），但**明确这是多周、研究级子工程**，按 §12 里程碑分期交付，每期有独立可装载验收，不追求一次做完。若未来评估引入 WASM 版 dex 工具，需单独评审其可信度与体积代价。

---

## 12. 分阶段里程碑

> ✅ **M0（Stage A）已完成**：DEX 写引擎的编解码原语、校验和层与「未修改 DEX 逐字节 round-trip」已交付并测试。
> - 编解码原语：`src/core/dex-codec.ts`（`writeUleb128`/`readUleb128`、`writeUleb128p1`/`readUleb128p1`、`writeSleb128`/`readSleb128`、精确 MUTF-8 `encodeMutf8`/`decodeMutf8`（U+0000→`C0 80`、补充平面→6 字节代理对）、`adler32` 分块取模），`tests/dex-codec.test.ts` 用规范向量与 round-trip 校验。
> - 解析/序列化/校验和：`src/core/dex-model.ts` 的 `parseDex`（全量 header size/off 对 + `map_list` + string_ids，校验 magic/endian/file_size/map 一致性）、`serializeDex`（raw+dirty，未修改即逐字节等价；dirty 时明确抛错，重排布局规划器归入 M1）、`recomputeDexChecksums`（先 SHA-1 signature 再 Adler-32 checksum，顺序固定）。`tests/dex-model.test.ts` 覆盖解析、Stage A 幂等、校验和一致性与拒绝非法输入。
>
> ⚠️ **仍需人工执行**：Stage B（对 d8 真实产物做 `dexdump -d` 语义等价 + 真机 `pm install` 冒烟）见 `scripts/device-smoke.ts`（`bun run smoke:device <apk>`，工具/设备齐备时自动执行，缺失则安全跳过）。

> ✅ **M1（自动化核心）已完成**：§6.2/§6.3 的「语义重排 + 重映射布局规划器」与「新增一个空类」能力已交付并测试。
> - 布局规划器：`src/core/dex-writer.ts` 的 `parseDexTables`（全量索引区 + `class_data` + `code_item` 的扁平语义解析）、`serializeDexTables`（对 strings/types/protos/fields/methods 按 §3.2 排序不变量重排，生成 old→new 映射，回填全部交叉引用——含用完整 Dalvik 宽度/引用表遍历 `code_item` 指令、重映射 `const-string`/`const-string/jumbo`/类型/字段/方法操作数与内联 switch/array 载荷；重排后写 header 全量 size/off 对 + `map_list`，再算 signature/checksum）。
> - mutate 能力：`addEmptyClass` 及 `internString/internType/internProto/internMethod`（后续 M3/M4 复用），`tests/dex-writer.test.ts` 覆盖空类注入、排序不变量、Stage A 逐字节幂等、跨索引洗牌后的操作数重映射、校验和一致性与 fail-closed。
> - **fail-closed 子集**：`try/catch`、`debug_info`、注解、静态初始值、未知/新版 opcode 一律在解析/序列化时报错安全回退（符合 §2.2「失败即安全回退」），不产出"装得上但运行崩"的 DEX。这些结构的支持与真机验收（Stage B）随 M2+ 与人工冒烟推进。

> ✅ **M2（自动化核心）已完成**：变长 AXML 写引擎已交付并测试。
> - `src/core/axml-writer.ts`：`parseAxml`（解析 XML 头 + ResStringPool 的 UTF-8/UTF-16 编码 + 偏移表 + 样式区，其余"资源映射表 + XML 树"整段按索引引用故原样保留）、`internAxmlString`（追加式插入——AXML 字符串池无排序要求，故新串一律追加、既有索引全部保持有效）、`setApplicationName`（把 `<application android:name>` 重指向注入类名，长度不变的 4 字节回填）、`readApplicationName`、`serializeAxml`（重建字符串池 + 重算池 chunk `size` 与 XML 总 `size`）。`tests/axml-writer.test.ts` 覆盖池解析/读取、无修改 round-trip、变长重指向到更长类名、索引去重、`android:name` 缺失时 fail-closed。
> - **fail-closed 子集**：`<application>` 缺少 `android:name` 时（默认 Application 情形需新增属性）明确报错回退，不误写；新增属性（含按 res-id 排序插入 + 节点/树 size 重算）仍未实现；M4 因此只接受宿主已声明 `android:name` 的受限场景。
> - ⚠️ **仍需人工执行**：真机 `aapt dump badging` 校验与 `pm install` 冒烟见 `scripts/device-smoke.ts`（Stage-B 门禁，工具/设备齐备时自动执行）。

> ✅ **M3（自动化核心）已完成**：DEX 字符串加密的「安全子集选择 + 分组密码 + 非破坏性方案」已交付并测试。
> - `src/core/dex-string-crypto.ts`：`computeIdentifierStrings`（汇总全部 `types`/`protos.shorty`/`fields.name`/`methods.name`/`class.sourceFile` 索引——标识符**永不加密**）、`computeLiteralStrings`（经 `dex-writer.ts` 新增导出的 `collectStringOperands` 从 `const-string`/`const-string/jumbo` 操作数回收字面量）、`computeEncryptableStrings`（字面量 − 标识符，升序）；密码 `generateKey`（`crypto.getRandomValues`，非 `Math.random`）+ `encryptBytes`/`decryptBytes`（XOR + 逐字节位旋转）+ `keyFingerprint`（SHA-256 前 16 位，非机密指纹）；`planStringEncryption`（**非破坏性**，产出 `{key, keyFingerprint, entries[], literalCount, identifierCount, encryptableCount, findings}`）。`tests/dex-string-crypto.test.ts` 覆盖密码 round-trip（空/Unicode/300 字符）、密文≠明文、错误密钥失败、标识符/字面量集合、`encryptable` 排除与方法名冲突的字符串、方案可 round-trip、零变更与 filter 收窄。
> - **fail-closed 子集**：§8.3 的运行时解密改写（`const-string` → `const #idx` + `invoke-static` 解密器 + `move-result`，需插指令 + 寄存器再分配 + 分支/switch 偏移修正）属研究级高风险改造，**刻意不自动应用**——只交付可自动化的安全内核（子集选择 + 密码 + 非破坏性方案）并以 round-trip 证明，避免产出"装得上但运行崩"的 DEX。

> ✅ **M4（自动化核心）已完成**：反调试注入端到端（§7.2 路径 b：新增 `classesN.dex`）已交付并测试。
> - `src/core/lossy-inject.ts`：`buildAntiDebugDex`（用 `dex-writer.ts` 的 `internMethod`/`internType` 生成一支全新 DEX——`AntiDebug.check()V` 调 `Debug.isDebuggerConnected`；`Bootstrap` 继承宿主原 Application，`<init>` 调 `super.<init>`、`onCreate` 调 `super.onCreate` 后触发反调试检测；标准 Dalvik 字节码 `invoke-super`/`invoke-static`/`return-void`）、`nextDexName`（扫描既有 `classes*.dex` 取下一序号）、`injectAntiDebug`（读包 → SHA-256 → `parseRawZip` → 定位清单 → `parseAxml`/`readApplicationName` → 构 DEX → `setApplicationName` 重指向 Bootstrap → 重打包：清单 STORED 替换、其余原样拷贝、末尾追加注入 DEX、可选备份、finding `LOSSY_DEX_REWRITTEN`）。跨 DEX 引用在加载期解析，全程停留在写引擎支持子集内（无 try/debug/注解）。`tests/lossy-inject.test.ts` 覆盖 DEX 构建的类+引用、Stage A `file_size` 合法、端到端注入 `classes2.dex` + 重指向 `android:name` + 备份等于原包、`android:name` 缺失时 fail-closed。
> - **fail-closed 子集**：宿主无自定义 Application（清单缺 `android:name`）时明确报错回退——因 M2 的 AXML 写引擎尚不能插入新属性，故不臆造默认 Application 类名，避免误写。
> - ⚠️ **仍需人工执行**：`dexdump -f`/`apksigner verify`/`aapt dump badging` 与真机 `adb install` 运行冒烟见 `scripts/device-smoke.ts`（Stage-B 门禁；缺工具/设备时安全跳过并退出 0，齐备时自动执行）。

> ⚠️ **Stage-B 真机验收（全里程碑通用，仍需人工）**：`scripts/device-smoke.ts`（`bun run smoke:device <path-to.apk>`）自动探测 `apksigner`/`dexdump`/`aapt(2)`/`adb`（PATH + `ANDROID_SDK_ROOT`/`ANDROID_HOME`），逐项运行可执行的门禁（签名校验 → DEX 结构解析 → 清单 badging → 设备安装冒烟）；缺工具或无设备则给出指引并安全跳过（退出 0），仅当"可运行门禁失败"时退出 1。本仓库/CI 环境通常无 SDK/设备，故需在具备工具链与真机的环境重跑以完成 Stage-B。



---

## 13. 与现有代码的接线点

### 13.1 可复用的现有能力

| 能力 | 位置 | 用途 |
|---|---|---|
| `parseRawZip` / `buildZip` / `OutEntry` | `src/core/harden-manifest.ts` | 解包/重打包 APK，增删 `classes*.dex`、`lib/*/*.so` 条目 |
| `crc32Of` | `src/core/harden-manifest.ts:170` | ZIP 条目 CRC |
| `inflateEntry` + node:zlib `deflateRawSync/inflateRawSync` | `harden-manifest.ts` | DEX 条目通常 STORED，但打包/压缩通用 |
| `extractDexStrings` / `readUleb128` | `src/core/dex-scan.ts` | 读引擎起点，扩展为全量解析 |
| `extractApkEntryBytes` / `stripApkEntries` | `src/core/apk-strip.ts` | 取/删条目字节的范例 |
| `Bun.CryptoHasher("sha1")` | 见 `apk-audit.ts` sha256 用法 | DEX signature |
| `flipDebuggableInAxml` | `harden-manifest.ts:121` | AXML 结构解析范例（但仅等长，需扩展为变长） |
| stub C/JNI 检测 | `src/assets/antidebug-stub/` | #1 被注入的 native 侧 |
| 测试范式 `buildDex/buildElf/storedEntry/writeApk/emptyToolchain` | `tests/tier2-audit.test.ts` | 合成产物与集成测试 |

### 13.2 当前模块与主线接线状态

| 模块 | 已实现内容 | 产品接线 |
|---|---|---|
| `dex-codec.ts` / `dex-model.ts` | LEB/MUTF-8、校验和、header/map/string 解析与未修改 round-trip | 研究基础，不参与默认审计路径 |
| `dex-writer.ts` | 受限索引重排、交叉引用回填、空类/方法构造、指令引用重映射 | 研究基础；未知或高风险结构失败关闭 |
| `axml-writer.ts` | 字符串池重建、既有 Application 名称重指向 | 仅供实验注入；缺属性时拒绝 |
| `dex-string-crypto.ts` | 标识符排除、可加密字面量集合、随机密钥/指纹和非破坏性计划 | 没有运行时改写，不接入流水线 |
| `lossy-inject.ts` | 新增 `classesN.dex`、受限 Bootstrap/Application 重指向、备份与 finding | 未被 `pipeline.ts` 导入，无 UI 开关，不属于当前发布功能 |
| `lossy-harden.ts` | ARSC 端到端改写 | 已由 `pipeline.ts` 的 `arsc-obfuscate` 步骤显式可选接入 |

DEX 注入若未来进入主线，仍需补齐：受支持结构矩阵、真实 APK `dexdump`/安装/启动回归、多 Android/ROM/ABI 设备矩阵、签名与自完整性冲突测试，以及和现有 `PipelineConfig`、报告及发布门禁的显式 opt-in 接线。未满足这些条件前，不应只因为模块和单元测试存在就对用户开放。
---

## 14. #2 ARSC 资源混淆（独立子工程，不依赖 DEX 写引擎）

> 与 #1/#3 不同：资源在运行时**按整数 ID（如 `0x7f0a0001`）引用，而非按名字**。因此重命名资源条目名、扁平化资源文件路径**都不需要改动任何 DEX 字节码**——这是 #2 远比 #1/#3 简单、可单轮交付的根本原因。技术路线对标 AndResGuard。

### 14.1 为什么安全（整数 ID 引用，而非名字）

- 编译期 aapt/aapt2 已把所有 `R.xxx.yyy` 解析成 `0x7f……` 常量，烧进 DEX 与二进制 XML 的 `Res_value`。运行时 `Resources.getXxx(int id)` 用的是这个整数。
- 二进制 XML（AndroidManifest.xml、layout、drawable xml 等）里对其他资源的引用也是 `Res_value{ dataType=REFERENCE, data=0x7f…… }`，即 ID 而非名字。
- 因此：**改 `resources.arsc` 里的条目名（key）与文件路径，不影响 ID→值 的映射，DEX/XML 无需同步改**。唯一必须同步的是"文件类资源"的**路径字符串**与它对应的 **ZIP 条目名**（见 §14.4 模式 B）。

### 14.2 `resources.arsc` 二进制格式参考（写引擎必须覆盖）

全部小端序。所有 chunk 以通用头开始：

- `ResChunk_header`：`{ type: u16, headerSize: u16, size: u32 }`。`size` 覆盖整个 chunk（含子 chunk）。

顶层与嵌套结构：

1. **`RES_TABLE_TYPE`（0x0002）= ResTable_header**：`ResChunk_header` + `packageCount: u32`。其后依次是 1 个全局字符串池 + N 个 package。
2. **`RES_STRING_POOL_TYPE`（0x0001）= ResStringPool**（全局池，位于 ResTable_header 之后）：
   - `{ stringCount: u32, styleCount: u32, flags: u32, stringsStart: u32, stylesStart: u32 }`，随后是 `stringCount` 个 u32 偏移数组、可选 style 偏移数组，然后是字符串数据区。
   - **`flags` 的 `UTF8_FLAG=0x0100`**：置位则字符串为 UTF-8（长度前缀是"u16 长度 + u8 长度"的变体，且以 `0x00` 结尾）；否则 UTF-16LE（长度前缀 u16，以 `0x0000` 结尾）。长度 ≥ 0x80/0x8000 时用双字节扩展编码。写引擎必须**精确复现所选编码**。
   - 全局池存放：**文件类资源的路径**（如 `res/drawable-hdpi/ic_launcher.png`）、以及字符串型资源值（`<string>` 内容等）。
3. **`RES_TABLE_PACKAGE_TYPE`（0x0200）= ResTable_package**：`{ id: u32, name: u16[128](UTF-16 包名), typeStrings: u32(偏移), lastPublicType: u32, keyStrings: u32(偏移), lastPublicKey: u32, (可能有 typeIdOffset) }`。内部再嵌两个字符串池：
   - **type 字符串池**：类型名（`drawable`/`string`/`layout`/`id`…），一般不混淆（数量少、无收益）。
   - **key 字符串池**：**条目名**（`app_name`/`ic_launcher`/`activity_main`…）——**这是模式 A 重命名的目标**。
4. **`RES_TABLE_TYPE_SPEC_TYPE`（0x0202）= ResTable_typeSpec**：`{ id: u8, res0, res1, entryCount: u32 }` + `entryCount` 个 u32 配置标志（记录哪些资源随配置变化）。
5. **`RES_TABLE_TYPE_TYPE`（0x0201）= ResTable_type**：`{ id: u8, flags: u8, reserved: u16, entryCount: u32, entriesStart: u32, config: ResTable_config }`，随后是 `entryCount` 个 u32 **入口偏移数组**（`NO_ENTRY=0xffffffff` 表示该配置下无此资源），再是紧凑排列的入口：
   - `ResTable_entry`：`{ size: u16, flags: u16, key: ResStringPool_ref(u32，指向 key 池的条目名索引) }`。
   - 其后是值：简单值为 `Res_value{ size: u16, res0: u8, dataType: u8, data: u32 }`；复合值（`FLAG_COMPLEX`）为 `ResTable_map_entry` + 若干 `ResTable_map`。
   - **`Res_value.dataType == TYPE_STRING(0x03)` 时，`data` 是全局字符串池索引**——文件类资源正是走这里指向 `res/...` 路径（模式 B 的核心）。
6. **资源 ID 组成**：`0xPPTTEEEE`（PP=package id，TT=type id 从 1 起，EEEE=entry 序号）。**混淆不改这三者，只改名字/路径字符串**，故 ID 稳定、DEX/XML 不受影响。

> 复杂度显著低于 DEX：无跨区排序不变量、无 Adler-32/SHA-1、无 code_item。核心难点只有两点——**字符串池的精确重建（含 UTF-8/UTF-16 与偏移表）** 与 **所有 chunk `size` 的自底向上重算**。

### 14.3 混淆模式 A：条目名（key）缩短/重命名

1. 解析 package 的 key 字符串池，得到全部条目名。
2. 生成映射 `原名 → 短名`（如 `app_name → a`、`ic_launcher → b`；按 §14.5 白名单排除不可改项）。
3. **重建 key 字符串池**：用短名替换，重算 `stringCount`（通常不变）、偏移数组、`stringsStart`、chunk `size`。若 1:1 保持顺序，`ResTable_entry.key` 索引可不变，仅池内字节变短——最省事。
4. 自底向上重算 package `size`、ResTable_header `size`。
5. **收益**：显著缩小 arsc 体积、抹掉语义化名字（一定逆向增本）。**不触碰 ID、不改 DEX/XML**。

### 14.4 混淆模式 B：资源文件路径扁平化（需同步改 ZIP 条目名）

1. 遍历所有 `ResTable_type` 的入口，找 `Res_value.dataType==TYPE_STRING` 且其全局池字符串形如 `res/…` 的**文件类资源**。
2. 生成映射 `res/drawable-hdpi/ic_launcher.png → r/a.png`（扁平化目录、缩短文件名；保留扩展名以稳妥）。
3. **两处必须同步更新，否则运行时找不到文件**：
   - **全局字符串池**中该路径字符串 → 改为新短路径（触发全局池重建与 chunk size 重算）。
   - **ZIP 条目名** → 用 `buildZip` 以新名写回（`buildZip` 条目名自由，可直接改名，字节与 crc 不变）。
4. 注意**同一路径可能被多个配置/入口引用**：按"池中唯一字符串"建映射，保证一次改名、多处引用同步生效。
5. **收益**：抹掉 `res/layout/activity_main.xml` 之类的语义路径，压缩目录树。

### 14.5 白名单与必须保留项（正确性关键）

- **`getIdentifier("name","type",pkg)` 反射按名查找**：模式 A 会使其失效。无法静态完全判定，故：
  - 扫描 DEX 字符串池（复用 `extractDexStrings`）；一旦命中 `getIdentifier`，严格预检会**保留全部资源条目名**，避免动态拼接名称绕过字面量白名单。
  - 提供用户可配置的 `keepResourceNames` / `keepPaths` 白名单。
- **AndroidManifest 引用的资源**：清单里是按 **ID** 引用（`android:icon="@0x7f……"` 编译后为 ID），改名安全；但**包名、`android:name`（组件类名）等不是资源名**，本就不在 arsc 混淆范围。
- **对外公开的库资源（public.xml / lastPublicKey）**：作为 AAR/库被其他工程按名引用的 public 资源，改名会破坏下游——库工程默认**排除 public 段**。
- **代码里按路径字符串访问**：如 WebView 加载 `file:///android_asset/...`、`file:///android_res/...`，或 `AssetManager.open("path")`——模式 B 会破坏。`assets/` 目录**不属于 arsc 管辖**（无 ID 映射），默认**不改 assets 路径**；只扁平化 `res/` 下、且被 arsc 以 ID 引用的文件。
- **对齐与压缩要求**：`resources.arsc` 必须以 **STORED(不压缩) 且 4 字节对齐**存放，Android 才能 mmap。改写后**必须走 zipalign 步骤**（现有 `align`）确保对齐；`buildZip` 写 STORED 没问题，但对齐由 align 步骤保证。
- **Split APK / App Bundle**：每个 split 各有自己的 arsc，需分别处理；动态特性模块的 ID 空间需留意。

### 14.6 重写流水线（步骤）

1. `parseRawZip` 解包，`extractApkEntryBytes(apk, "resources.arsc")` 取 arsc 字节。
2. 解析 arsc → 内存模型（ResTable_header / 全局池 / packages / type&key 池 / typeSpec / types+entries+values）。
3. 依据模式 A/B + 白名单构建 `原名→短名`、`原路径→短路径` 两张映射表。
4. 应用映射：重命名 key 条目、改写文件路径字符串。
5. **序列化 arsc**：重建受影响字符串池（偏移表 + UTF-8/UTF-16 编码 + stringsStart）→ 自底向上重算所有 chunk `size`（entry/type/typeSpec/package/全局池/ResTable_header）→ 保持入口偏移数组与 `entriesStart` 一致。
6. `buildZip` 写回：替换 `resources.arsc` 条目（STORED），并按路径映射**重命名对应文件条目**，其余条目逐字节复制。
7. 走 `align`（4 字节对齐 arsc）→ **重签名** → `apksigner verify`。
8. 报告新增 finding（如 `LOSSY_ARSC_OBFUSCATED`）：记录重命名条目数、路径映射数、备份位置与原始 SHA-256、白名单命中项与 `getIdentifier` 告警。

### 14.7 风险与失败模式

- **反射按名查找失效**（getIdentifier / 资源名字面量）——严格模式已在命中 API 时禁用全部 key 重命名；仍需真机覆盖动态皮肤与插件资源。
- **字符串池编码写错**（UTF-8 双长度前缀 / UTF-16 结尾符 / 偏移表错位）→ 资源解析异常。
- **chunk size 未自底向上重算一致** → aapt/ART 解析越界。
- **arsc 未对齐或被压缩** → 运行时 mmap 失败、启动崩。
- **模式 B 路径改了但 ZIP 条目没改（或反之）** → 资源缺失。
- **public 库资源被改** → 下游按名引用断裂。
- **Play Protect / 上架**：资源混淆特征相对常见、风险低于注入 native，但仍应在报告中如实标注。

### 14.8 分阶段里程碑（#2）

> ✅ **N0/N1/N2/N3/N4 全部完成**：#2 ARSC 资源混淆已作为可选有损步骤端到端交付。
> - N0：`src/core/arsc-model.ts`（`parseArsc`/`serializeArsc` + UTF-8/UTF-16 字符串池编解码 + 脏标记重建），`tests/arsc-model.test.ts` 验证 round-trip 逐字节等价与重命名后重建。
> - N1（模式 A）：`src/core/arsc-obfuscate.ts` 的 `shortenKeyNames`（1:1 保序缩短 key 条目名 + 白名单 + 映射表），`tests/arsc-obfuscate.test.ts` 验证缩短后 serialize/parse 往返、ID 不变、白名单保留。
> - N2（模式 B）：`arsc-obfuscate.ts` 的 `flattenFilePaths`（在全局池原索引处就地改写 `res/…` 路径为 `r/…`、保留扩展名、返回供 ZIP 改名的映射）。因索引不变，所有 `Res_value` 引用保持有效。
> - N3（严格保留）：`arsc-obfuscate.ts` 的 `analyzeResourceReflection`（扫描 DEX 字符串池中的 `getIdentifier`，命中则把全部资源条目名并入 keep 集，并产出 `ARSC_RESOURCE_NAME_REFLECTION` finding）。
> - N4（端到端）：`src/core/lossy-harden.ts` 的 `obfuscateArscInApk`（提取 `resources.arsc` → 模式 A/B + 反射/字面路径安全保留 → `serializeArsc` → 用 `buildZip` 重打包：`resources.arsc` 以 STORED 替换、按映射同步重命名文件条目 → 产出 `LOSSY_ARSC_OBFUSCATED` finding）。流水线在 `harden` 之后、`align` 之前新增 opt-in `arsc-obfuscate` 步骤；对齐与签名在其后照常执行。`tests/lossy-harden.test.ts` 覆盖合成 APK 的端到端改写、路径保留、`getIdentifier` 全键保留、无 arsc 空操作与模式开关。
>
> ⚠️ **仍需人工执行**：真机冒烟（多机型/多密度回归、安装运行）无法在本仓库自动化，需在集成时由人工完成；`apksigner verify` 由既有 `verify` 步骤在重签名后自动校验。

每个里程碑独立验收，未过不得进入下一阶段。

### 14.9 与现有代码的接线点（#2）

| 能力 | 位置 | 用途 |
|---|---|---|
| `parseRawZip` / `buildZip` / `OutEntry` | `src/core/harden-manifest.ts` | 解包/重打包、替换 `resources.arsc`、**重命名文件条目** |
| `extractApkEntryBytes` | `src/core/apk-strip.ts` | 取 `resources.arsc` 与资源文件字节 |
| `crc32Of` | `src/core/harden-manifest.ts:170` | 条目 CRC（改名不改内容时可沿用原 crc） |
| 字符串池解析范式 | `harden-manifest.ts`（AXML `CHUNK_STRING_POOL=0x0001`） | ResStringPool 与 AXML 池同构，解析/编码可互相借鉴 |
| `extractDexStrings` | `src/core/dex-scan.ts` | 扫描 DEX 中 `getIdentifier`/资源名字面量以生成白名单告警 |
| `align` 步骤 | 流水线 | 保证改写后 `resources.arsc` 4 字节对齐（STORED） |
| 测试范式 `writeApk/storedEntry` | `tests/tier2-audit.test.ts` | 合成含 arsc 的最小 APK 做集成测试 |

当前实现：

- `src/core/arsc-model.ts` 同时承担 ResTable/字符串池/package 的解析、脏池重建和序列化，没有再拆出原计划中的 `arsc-writer.ts`。
- `src/core/arsc-obfuscate.ts` 负责键名缩短、路径扁平化、白名单和 `getIdentifier` 分析。
- `src/core/lossy-harden.ts` 负责 APK 提取/写回、ZIP 条目同步改名和 finding；这是已接入默认产品的 ARSC 路径，不等同于未接线的 `lossy-inject.ts`。
- `PipelineConfig.enableArscObfuscation`、向导、报告和 `arsc-obfuscate` 步骤已经完成显式 opt-in 接线，位置在 Web JS 处理之后、zipalign/签名之前。

> **交付独立性**：#2 只依赖已有的 ZIP 读写与字符串池解析范式，**完全不需要 DEX 写引擎（§3–§13）**，可先于 #1/#3 单独立项交付。

---

## 附：正式接入前检查清单

- [ ] 用户已显式接受 §2.1 的定位冲突与 §2.2 前置条件。
- [x] M0 黄金门禁方案（逐字节 vs 语义等价 + 真机）已定（Stage A 逐字节自动化；Stage B 语义/真机由 `scripts/device-smoke.ts` 承载）。
- [ ] 各 ABI 的 `libdroidseal_antidebug.so` 交叉编译产物已就绪（#1）。（M4 采用 §7.2 路径 b 纯 DEX 注入，未走 native `.so`；如需 native 反调试仍待交叉编译。）
- [x] MUTF-8 精确编解码（含 U+0000 / 补充平面）已单测覆盖（`tests/dex-codec.test.ts`）。
- [x] Adler-32/SHA-1 计算顺序（先 sig 后 checksum）已单测覆盖（`tests/dex-codec.test.ts` / `tests/dex-model.test.ts`）。
- [x] 字符串加密安全子集算法（排除标识符）已单测覆盖（`tests/dex-string-crypto.test.ts`）。
- [x] 真机安装冒烟矩阵（多 Android 版本 × 多 ABI）已规划（`scripts/device-smoke.ts` 提供统一入口；矩阵执行需人工在具备设备的环境运行）。
- [x] （#2）arsc N0 round-trip 等价门禁已定（逐字节，`tests/arsc-model.test.ts`；`aapt2 dump` 语义等价归 Stage-B 人工）。
- [x] （#2）字符串池 UTF-8/UTF-16 双编码精确重建已单测覆盖（`tests/arsc-model.test.ts`）。
- [x] （#2）`getIdentifier`/资源名反射白名单与告警启发式已就绪（`arsc-obfuscate.ts` 的 `analyzeResourceReflection`）。
- [x] （#2）模式 B 路径映射与 ZIP 条目改名的同步机制已验证（`tests/lossy-harden.test.ts`）；`resources.arsc` 对齐(STORED+4字节)由 `align` 步骤保证。
