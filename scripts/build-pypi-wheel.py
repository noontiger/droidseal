"""构建 PyPI wheel：把 dist/* 同步到 droidseal/_bin/，再构建 win_amd64 wheel。

用法（在项目根目录执行）：
    python scripts/build-pypi-wheel.py

前置条件：
    - 已执行 `bun run build` 生成 dist/droidseal.exe 与 droidseal-build.json；
    - 已有可用的 Python 环境（脚本会自动选择 `python -m build`，否则退回
      `pip wheel --no-build-isolation`，两者均只需本地已装的 setuptools/wheel）。
"""

import importlib.util
import shutil
import subprocess
import sys
from pathlib import Path

project_root = Path(__file__).resolve().parent.parent
dist_dir = project_root / "dist"
package_dir = project_root / "droidseal"
bin_dir = package_dir / "_bin"
wheelhouse = project_root / "wheelhouse"


def main() -> int:
    if not (dist_dir / "droidseal.exe").is_file() or not (dist_dir / "droidseal-build.json").is_file():
        print(
            "[DroidSeal] 缺少 dist/droidseal.exe 或 dist/droidseal-build.json，请先执行 `bun run build`。",
            file=sys.stderr,
        )
        return 1

    # 1. 同步二进制产物到 Python 包内（_bin 已被 .gitignore 排除）
    if bin_dir.exists():
        shutil.rmtree(bin_dir)
    shutil.copytree(dist_dir, bin_dir)

    # 2. 清空旧 wheel 并构建（平台标签 win_amd64 由 setup.cfg [bdist_wheel] 决定）
    for old in wheelhouse.glob("droidseal-*.whl"):
        old.unlink()
    wheelhouse.mkdir(exist_ok=True)

    if importlib.util.find_spec("build"):
        cmd = [sys.executable, "-m", "build", "--wheel", "--outdir", str(wheelhouse)]
    else:
        cmd = [sys.executable, "-m", "pip", "wheel", ".", "--no-deps", "--no-build-isolation", "-w", str(wheelhouse)]
    result = subprocess.run(cmd, cwd=project_root)
    if result.returncode != 0:
        print("[DroidSeal] wheel 构建失败，请查看上方错误。", file=sys.stderr)
        return result.returncode

    # 3. 校验平台标签
    wheel = next(wheelhouse.glob("droidseal-*.whl"), None)
    if wheel is None or not wheel.name.endswith("-win_amd64.whl"):
        print(f"[DroidSeal] wheel 平台标签异常：{wheel.name if wheel else '无产物'}", file=sys.stderr)
        return 1

    # 4. 清理 setuptools 在项目根目录留下的 build/ 构建产物
    build_dir = project_root / "build"
    if build_dir.exists():
        shutil.rmtree(build_dir, ignore_errors=True)

    print(f"[DroidSeal] 已生成 {wheel.name}（{wheel.stat().st_size / 1024 / 1024:.1f} MB）")
    print(f"[DroidSeal] 上传：python -m twine upload {wheel}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
