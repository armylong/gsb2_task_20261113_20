"""全局配置与路径管理。

所有运行期数据（上传的原始包、任务元数据、释放目录）都放在 DATA_DIR 下，
数据目录与代码目录分离，可用环境变量 SAFEARCH_DATA_DIR 覆盖，
方便测试时使用独立的临时数据目录，避免多批次互相串数据。
"""
from __future__ import annotations

import os
from pathlib import Path

# 服务监听地址：只绑定本机回环，不对局域网暴露。
HOST = os.environ.get("SAFEARCH_HOST", "127.0.0.1")
PORT = int(os.environ.get("SAFEARCH_PORT", "8765"))

# 数据目录（上传原件 / 任务元数据 / 释放结果）。
DATA_DIR = Path(os.environ.get("SAFEARCH_DATA_DIR", Path(__file__).resolve().parent.parent / "data"))
UPLOAD_DIR = DATA_DIR / "uploads"
JOBS_DIR = DATA_DIR / "jobs"
RELEASES_DIR = DATA_DIR / "releases"
DEMO_DIR = DATA_DIR / "demos"

# 静态页面目录。
STATIC_DIR = Path(__file__).resolve().parent.parent / "static"

# 上传体积硬上限（防止一次请求吃光磁盘），默认 2GB。
MAX_UPLOAD_BYTES = int(os.environ.get("SAFEARCH_MAX_UPLOAD", str(2 * 1024 ** 3)))

# 限制参数的服务端硬边界：无论前端传什么都不能超过这些值。
HARD_LIMITS = {
    "max_entries": (1, 200_000),
    "max_file_size": (1, 100 * 1024 ** 3),       # 单文件 1B ~ 100GiB
    "max_total_size": (1, 1024 * 1024 ** 3),     # 总量 1B ~ 1TiB
    "max_ratio": (1.0, 100_000.0),
}

# 页面上展示的默认限制。
DEFAULT_LIMITS = {
    "max_entries": 10_000,
    "max_file_size": 100 * 1024 ** 2,   # 单文件 100MiB
    "max_total_size": 500 * 1024 ** 2,  # 总量 500MiB
    "max_ratio": 100.0,                # 压缩比例 100:1
}

# 读取包内成员内容时的分块大小。
READ_CHUNK = 64 * 1024


def ensure_dirs() -> None:
    """启动时建立数据目录（幂等）。"""
    for d in (DATA_DIR, UPLOAD_DIR, JOBS_DIR, RELEASES_DIR, DEMO_DIR):
        d.mkdir(parents=True, exist_ok=True)
