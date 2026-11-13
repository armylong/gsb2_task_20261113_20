"""本地演示包生成器。

所有演示包在服务启动时于数据目录内现建（幂等），页面可直接加载，
无需用户自备附件。危险内容只是具有危险*名称/结构*的文本条目，
不含任何可执行脚本，也不访问网络。

覆盖场景：正常中文文件、目录穿越、绝对路径、反斜杠绕过、重名冲突、
符号链接后跟文件、超限、损坏内容。
"""
from __future__ import annotations

import io
import os
import tarfile
import zipfile
from pathlib import Path

from . import config

DEMOS: list[dict] = [
    {"key": "normal", "title": "正常素材包（中文文件名）",
     "format": "zip", "desc": "目录结构与中文文件名均正常，可安全释放。"},
    {"key": "traversal", "title": "目录穿越包", "format": "zip",
     "desc": "含 ../../ 穿越条目，试图写到释放目录之外。"},
    {"key": "absolute", "title": "绝对路径包", "format": "tar",
     "desc": "条目以 / 开头，试图绕过目标目录写入系统位置。"},
    {"key": "backslash", "title": "反斜杠绕过包", "format": "zip",
     "desc": "用反斜杠伪装文件名，绕过只查正斜杠的检查。"},
    {"key": "duplicate", "title": "重名/大小写冲突包", "format": "zip",
     "desc": "规范化重名、仅大小写不同、文件与目录冲突同时存在。"},
    {"key": "symlink", "title": "符号链接逃逸包（链接+后续文件）", "format": "tar",
     "desc": "先放看似正常的链接，后续文件借链接写到释放目录外。"},
    {"key": "bomb", "title": "超限演示包（高压缩比）", "format": "zip",
     "desc": "高度可压缩内容，默认比例/大小限制下扫描会被中止。"},
    {"key": "corrupt", "title": "损坏包", "format": "zip",
     "desc": "魔数正确但内容被截断，扫描应报告损坏且服务不退出。"},
]


def _zip_bytes(entries: list[tuple]) -> bytes:
    """entries: (名称, 数据 bytes 或 None(目录), 可选 zipinfo 外部属性)。"""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for item in entries:
            name, data = item[0], item[1]
            if data is None:
                zi = zipfile.ZipInfo(name + "/")
                zi.external_attr = (0o040755 << 16) | 0x10
                zf.writestr(zi, b"")
            else:
                zf.writestr(name, data)
    return buf.getvalue()


def _zip_symlink_bytes(entries: list[tuple]) -> bytes:
    """构造含 unix 符号链接条目的 zip（本地演示用）。"""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for name, kind, payload in entries:
            zi = zipfile.ZipInfo(name)
            if kind == "link":
                zi.external_attr = (0o120777 << 16)
                zf.writestr(zi, payload)
            elif kind == "dir":
                zi.external_attr = (0o040755 << 16) | 0x10
                zf.writestr(zi, b"")
            else:
                zf.writestr(zi, payload)
    return buf.getvalue()


def _tar_bytes(entries: list[tuple], gzip: bool = True) -> bytes:
    """entries: (名称, 类型, 数据/链接目标)。"""
    mode = "w:gz" if gzip else "w"
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode=mode) as tf:
        for name, kind, payload in entries:
            ti = tarfile.TarInfo(name)
            if kind == "dir":
                ti.type = tarfile.DIRTYPE
                ti.mode = 0o755
                tf.addfile(ti)
            elif kind == "symlink":
                ti.type = tarfile.SYMTYPE
                ti.linkname = payload
                ti.mode = 0o777
                tf.addfile(ti)
            else:
                data = payload if isinstance(payload, bytes) else payload.encode()
                ti.size = len(data)
                ti.mode = 0o644
                tf.addfile(ti, io.BytesIO(data))
    return buf.getvalue()


def build_demo(key: str) -> bytes:
    if key == "normal":
        return _zip_bytes([
            ("素材/", None),
            ("素材/说明.txt", "这是正常的中文说明文件。\n".encode()),
            ("素材/images/", None),
            ("素材/images/封面.txt", "封面占位内容".encode()),
            ("readme.md", b"# demo\nnormal package\n"),
        ])

    if key == "traversal":
        return _zip_bytes([
            ("safe/正常文件.txt", "保留在释放目录内".encode()),
            ("../../../../tmp/safearch_evil.txt", "穿越内容".encode()),
            ("docs/../报告.txt", "片段穿越但规范化后仍在内部".encode()),
        ])

    if key == "absolute":
        return _tar_bytes([
            ("etc/配置.conf", "file", "内部配置\n"),
            ("/tmp/safearch_absolute_evil.txt", "file", "绝对路径内容\n"),
        ], gzip=True)

    if key == "backslash":
        # zip 里反斜杠只是普通字符；检查器必须识别其分隔符语义
        return _zip_bytes([
            ("正常目录/文件.txt", b"ok"),
            ("..\\..\\tmp\\safearch_backslash_evil.txt", b"backslash traversal"),
            ("子目录\\..\\evil.txt", b"mixed slash"),
        ])

    if key == "duplicate":
        return _zip_bytes([
            ("data/log.txt", "第一份".encode()),
            ("data/log.txt", "第二份，释放会覆盖第一份".encode()),
            ("README.txt", "大写".encode()),
            ("readme.txt", "小写，大小写不敏感系统上冲突".encode()),
            ("conflict", "我是文件".encode()),
            ("conflict/inside.txt", "同名路径下却还有子条目".encode()),
        ])

    if key == "symlink":
        return _tar_bytes([
            ("work/", "dir", None),
            ("work/link", "symlink", "/tmp"),
            ("work/link/safearch_link_evil.txt", "file", "借链接写到 /tmp\n"),
            ("inside/", "dir", None),
            ("inside/loop", "symlink", "../inside"),
            ("inside/loop/note.txt", "file", "链接目标仍在目录内，但链接本身不释放\n"),
        ], gzip=True)

    if key == "bomb":
        # 10MiB 全零数据，DEFLATED 后只有约 10KB，压缩比约 1000:1
        big = b"\x00" * (10 * 1024 * 1024)
        return _zip_bytes([("zero.bin", big)])

    if key == "corrupt":
        good = _zip_bytes([("a.txt", b"hello"), ("b.txt", b"world")])
        # 保留 zip 魔数与开头，截断中央目录
        return good[: len(good) // 2]

    raise KeyError(f"未知演示包：{key}")


def ensure_demos() -> dict[str, Path]:
    """启动时生成全部演示包（已存在则跳过），返回 key -> 路径。"""
    config.DEMO_DIR.mkdir(parents=True, exist_ok=True)
    paths: dict[str, Path] = {}
    for demo in DEMOS:
        suffix = ".tar.gz" if demo["format"] == "tar" else ".zip"
        path = config.DEMO_DIR / f"{demo['key']}{suffix}"
        if not path.exists():
            path.write_bytes(build_demo(demo["key"]))
        paths[demo["key"]] = path
    return paths
