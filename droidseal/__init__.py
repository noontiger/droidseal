"""DroidSeal — Python 启动器（仅封装 Windows x64 / Linux x64 原生二进制）。

业务实现位于编译后的 `_bin/` 目录下的平台二进制中；本模块只负责校验
SHA-256、设置 OpenTUI 资源目录并透传命令行参数，逻辑与
`bin/droidseal.cjs` 一一对应。
"""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path

__version__ = "0.2.1"  # 与 package.json / pyproject.toml 保持一致


def _fail(message: str) -> int:
    print(f"[DroidSeal] {message}", file=sys.stderr)
    return 1


def main(argv: list[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)

    is_windows = sys.platform == "win32"
    if sys.platform not in ("win32", "linux") or sys.maxsize <= 2**32:
        arch = "x86" if sys.maxsize <= 2**32 else "x64"
        return _fail(f"当前 PyPI 二进制包支持 Windows x64 / Linux x64，检测到 {sys.platform}-{arch}。")

    executable_name = "droidseal.exe" if is_windows else "droidseal"
    metadata_name = "droidseal-build.json" if is_windows else "droidseal-build.linux.json"
    expected_target = "windows-x64" if is_windows else "linux-x64"

    bin_dir = Path(__file__).resolve().parent / "_bin"
    executable = bin_dir / executable_name
    metadata_path = bin_dir / metadata_name

    if not executable.is_file() or not metadata_path.is_file():
        return _fail(f"安装不完整：缺少 {executable_name} 或构建元数据，请重新安装 pip 包。")

    try:
        metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
    except Exception as exc:  # noqa: BLE001 - 统一转为用户可读错误
        return _fail(f"无法读取构建元数据：{exc}")

    artifact = metadata.get("artifact") or {}
    sha256 = artifact.get("sha256")
    if (
        metadata.get("schemaVersion") != 2
        or artifact.get("path") != executable_name
        or artifact.get("target") != expected_target
        or not isinstance(sha256, str)
        or not (len(sha256) == 64 and all(c in "0123456789abcdef" for c in sha256))
    ):
        return _fail("构建元数据格式无效，拒绝启动未经确认的二进制文件。")

    if hashlib.sha256(executable.read_bytes()).hexdigest() != sha256:
        return _fail("droidseal.exe 完整性校验失败；文件可能损坏或被修改，请重新安装。")

    env = dict(os.environ)
    env.setdefault("OTUI_ASSET_ROOT", str(bin_dir))

    try:
        result = subprocess.run([str(executable), *args], cwd=os.getcwd(), env=env)
    except KeyboardInterrupt:
        return 130
    except OSError as exc:
        return _fail(f"无法启动二进制文件：{exc}")
    return result.returncode
