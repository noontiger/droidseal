# DroidSeal

> 商业加固前你能做的大多数内容。一键式端到端管线，超越初级安全水平。

DroidSeal 是面向 Android 发布流程的**加固前处理 / 端到端管线工具**：在把 APK 交给商业加固服务之前，先用一套可复现的本地化步骤完成代码混淆、资源清理、签名一致性校验与发布包校验，减少加固后回滚与兼容性问题。

## 特性

- **九步端到端管线**：解包 → 资源清理 → 清单收敛 → R8 / ProGuard → 原生库处理 → zipalign → apksigner → 完整性校验 → 产物归档，覆盖从 APK 到可发布包的全过程。
- **三种运行模式**：分步处理（可控、可断点续跑）、一键处理（端到端自动）、环境诊断（只检查工具链与配置，不改产物）。
- **能力网格**：混淆策略、资源瘦身、签名管理、清单裁剪、原生库处理、发布校验。
- **安全与隐私**：全部在本地完成，不对外上传源码或签名密钥；密钥仅用于本地签名，绝不离开本机。

## 目录结构（GitHub Pages）

```
.
├── index.html        # 站点主页（交互式深色终端风）
├── screenshot.png    # Hero 区产品截图
├── LICENSE           # MIT
└── README.md
```

## 本地预览

```bash
# 任选其一
python -m http.server 8000
# 或
npx serve .
```

然后打开 http://localhost:8000

## 部署到 GitHub Pages

1. 在 GitHub 新建仓库（如 `droidseal` 或 `droidseal.github.io`）。
2. 推送本目录到 `main` 分支：
   ```bash
   git remote add origin git@github.com:<you>/droidseal.git
   git push -u origin main
   ```
3. 仓库 **Settings → Pages → Build and deployment → Source: Deploy from a branch → Branch: main → /(root)**，保存后等待数分钟即可访问。

## 许可证

[MIT](./LICENSE) © 2026 DroidSeal Contributors
