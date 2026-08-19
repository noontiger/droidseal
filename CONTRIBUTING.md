# 为 DroidSeal 贡献

感谢你帮助改进 DroidSeal。项目接受缺陷修复、文案与可访问性改进、测试、平台兼容修复，以及面向合法 Android 应用安全发布的功能。

参与社区即表示同意遵守 [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md)。安全漏洞不要提交公开 Issue，请遵循 [SECURITY.md](SECURITY.md)。

## 项目治理

DroidSeal 采用 Maintainer-led 治理。维护者负责项目方向、安全边界、兼容性承诺、发布质量和最终合并决定，具体参见 [GOVERNANCE.md](GOVERNANCE.md)。大型架构变化、新下载源或新安全控制应先讨论再实现。

## Developer Certificate of Origin

DroidSeal 使用 Developer Certificate of Origin 1.1（DCO）接受外部贡献。每个提交都必须包含有效的 `Signed-off-by` 行，以确认提交者有权按照项目许可证提供该贡献。

创建已签署提交：

```bash
git commit -s
```

生成的提交信息应包含：

```text
Signed-off-by: Your Name <your.email@example.com>
```

请使用真实姓名或你依法可以使用的身份，不要代替他人签署。DCO 1.1 全文见 <https://developercertificate.org/>。

## 开发环境

要求：

- Bun 1.3 或更高版本；
- 受支持的交互式终端；
- 与所测试流程对应的 JDK、Android SDK 和 Build Tools。

```bash
bun install --frozen-lockfile
bun run dev
```

提交前运行：

```bash
bun run verify
```

`verify` 会依次执行 TypeScript 严格检查、测试、构建和开源发布检查。

## 贡献范围

欢迎：

- APK、Manifest、ZIP、DEX 和 SO 的防御性审计；
- Gradle、R8、zipalign、keytool 和 apksigner 工作流；
- 自研 opt-in 构建期反调试 stub 与安全审计基线的改进；
- 事务回退、脱敏、错误解释和 TUI 可访问性；
- Windows、macOS 和 Linux 兼容性；
- 文档、测试、报告格式和发布工程改进。

不接受：

- 未授权脱壳、Hook、证书校验绕过或安全检测规避；
- 窃取签名密钥、凭据或受保护代码；
- 将真实 APK、AAB、JKS、PKCS12、私钥或密码提交到仓库；
- 静默下载、执行或上传用户文件的行为。

## Pull Request 要求

1. 每个 PR 只处理一个清晰问题。
2. 每个提交包含有效的 DCO `Signed-off-by` 行。
3. 行为变化必须包含测试；文案变化应覆盖关键分支。
4. 不要提交 `node_modules`、`dist`、`.droidseal`、APK 或签名材料。
5. 新依赖必须说明用途、许可证、维护状态和无法使用现有依赖实现的原因。
6. 外部命令必须用参数数组启动，不能拼接 shell 字符串。
7. 所有密码必须通过子进程环境传递，并加入输出脱敏列表。
8. 失败分支必须保留或恢复上一个有效 APK。
9. 用户可见变化应更新 README 和 CHANGELOG。
10. 提交前运行 `bun run verify`。

## 安全敏感改动

涉及进程执行、参数解析、路径规范化、归档处理、自动下载、校验和、签名凭据、密钥库、输出脱敏、网络访问或权限变化时，PR 必须说明安全影响、威胁边界和验证方式，并由 CODEOWNERS 审核。

## 报告普通缺陷

使用 Bug Report 模板，并提供：

- DroidSeal 版本；
- 操作系统、终端、Bun、JDK 和 Android Build Tools 版本；
- 输入类型（APK 或项目），不要上传真实应用；
- 步骤名称、错误码和已脱敏输出；
- 最小复现方式。

## 贡献许可

除非另有明确约定，源代码、测试、文档和示例贡献按照 MIT License 分发。DCO 签署证明你有权提交贡献，不会把贡献的版权转让给维护者。