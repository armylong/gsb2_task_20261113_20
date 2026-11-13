"""压缩包统一只读访问层（zip / tar / tar.gz）。

设计原则：
* 只读取、不落地——扫描阶段不会把任何成员内容写到释放目录或其他位置；
* 对外暴露统一的 :class:`ArchiveEntry` 与 :class:`ArchiveReader`，
  扫描器和释放器共用同一套遍历逻辑；
* tar 采用流式遍历（``r|*``），不依赖成员可随机定位；
* 损坏包抛出 :class:`ArchiveError`，格式无法识别抛出
  :class:`UnsupportedArchiveError`，由上层转成任务失败而不是让服务退出。
"""
from __future__ import annotations

import io
import os
import tarfile
import zipfile
from dataclasses import dataclass, field

ZIP_MAGICS = (b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08")
GZIP_MAGIC = b"\x1f\x8b"

# 条目类型常量（同时用于前后端展示与释放判定）。
TYPE_FILE = "file"
TYPE_DIR = "dir"
TYPE_SYMLINK = "symlink"
TYPE_HARDLINK = "hardlink"
TYPE_SPECIAL = "special"          # 字符设备/块设备/FIFO 等特殊文件
TYPE_OTHER = "other"

TYPE_LABELS = {
    TYPE_FILE: "普通文件",
    TYPE_DIR: "目录",
    TYPE_SYMLINK: "符号链接",
    TYPE_HARDLINK: "硬链接",
    TYPE_SPECIAL: "特殊文件",
    TYPE_OTHER: "其他",
}


class ArchiveError(Exception):
    """压缩包损坏或读取失败。"""


class UnsupportedArchiveError(Exception):
    """不是本工具支持的压缩包格式。"""


@dataclass
class ArchiveEntry:
    index: int
    raw_name: str
    entry_type: str
    declared_size: int          # 包内声明的未压缩大小（不可信，仅作展示与预判）
    compressed_size: int        # 压缩后占用字节（tar 流式读取时在读完后回填）
    mode: int = 0
    link_target: str | None = None
    # tar 内部对象 / zip 信息对象，供读取器内部使用，不对外序列化。
    _native: object = field(default=None, repr=False, compare=False)


def _pretty_zip_name(info: zipfile.ZipInfo) -> str:
    """zip 文件名解码：优先 UTF-8 标志，其次尝试 GBK，保证中文正常展示。"""
    if info.flag_bits & 0x800:
        return info.filename
    try:
        raw = info.filename.encode("cp437")
    except (UnicodeEncodeError, AttributeError):
        return info.filename
    for enc in ("gbk", "gb18030", "big5"):
        try:
            return raw.decode(enc)
        except UnicodeDecodeError:
            continue
    return raw.decode("utf-8", errors="replace")


def _pretty_tar_name(name: str) -> str:
    """tar 名在 surrogateescape 下可能含代理字符，按常见中文编码再试一次。"""
    try:
        name.encode("utf-8")
        return name
    except UnicodeEncodeError:
        raw = name.encode("utf-8", errors="surrogateescape")
        for enc in ("gbk", "gb18030", "big5"):
            try:
                return raw.decode(enc)
            except UnicodeDecodeError:
                continue
        return raw.decode("utf-8", errors="replace")


class _CountingReader:
    """记录已读取压缩字节数的文件代理，用于 tar 的真实压缩比例计算。"""

    def __init__(self, f):
        self._f = f
        self.position = 0

    def read(self, n=-1):
        data = self._f.read(n)
        self.position += len(data)
        return data

    def tell(self):
        return self.position

    def seek(self, *args):
        raise io.UnsupportedOperation("流式 tar 不支持 seek")

    def close(self):
        self._f.close()


class ZipReader:
    def __init__(self, path: str):
        try:
            self.zf = zipfile.ZipFile(path, "r")
        except zipfile.BadZipFile as e:
            raise ArchiveError(f"zip 文件已损坏：{e}") from e
        self.entries: list[ArchiveEntry] = []
        unix_mode = self.zf.infolist and True
        for i, info in enumerate(self.zf.infolist()):
            posix_mode = (info.external_attr >> 16) & 0xFFFF
            if info.is_dir():
                etype = TYPE_DIR
            elif unix_mode and (posix_mode & 0o170000) == 0o120000:
                etype = TYPE_SYMLINK
            else:
                etype = TYPE_FILE
            target = None
            if etype == TYPE_SYMLINK:
                try:
                    target = self.zf.read(info).decode("utf-8", errors="replace")
                except (zipfile.BadZipFile, OSError) as e:
                    raise ArchiveError(f"读取链接成员 {info.filename!r} 失败：{e}") from e
            self.entries.append(
                ArchiveEntry(
                    index=i,
                    raw_name=_pretty_zip_name(info),
                    entry_type=etype,
                    declared_size=info.file_size,
                    compressed_size=info.compress_size,
                    mode=posix_mode,
                    link_target=target,
                    _native=info,
                )
            )

    def __iter__(self):
        return iter(self.entries)

    def open_member(self, entry: ArchiveEntry):
        try:
            return self.zf.open(entry._native, "r")
        except (zipfile.BadZipFile, OSError, RuntimeError) as e:
            raise ArchiveError(f"读取成员 {entry.raw_name!r} 失败：{e}") from e

    def compressed_position(self, current: ArchiveEntry) -> int:
        """截至当前成员已消费的压缩字节（仅累计成员数据，不含格式元数据）。"""
        return sum(e.compressed_size for e in self.entries
                   if e.index <= current.index)

    def position_before(self, current: ArchiveEntry) -> int:
        """当前成员开始之前，前面成员累计的压缩字节。"""
        return sum(e.compressed_size for e in self.entries
                   if e.index < current.index)

    def close(self):
        self.zf.close()


class TarReader:
    def __init__(self, path: str):
        self._raw = open(path, "rb")
        self._counter = _CountingReader(self._raw)
        try:
            # r|* 流式自动识别 gzip/bzip2/xz/普通 tar；本工具只保证 gzip。
            self.tar = tarfile.open(fileobj=self._counter, mode="r|*")
        except (tarfile.TarError, EOFError, OSError) as e:
            self._raw.close()
            raise ArchiveError(f"tar 文件已损坏或格式无法识别：{e}") from e
        self._current: ArchiveEntry | None = None
        self._member_start = 0

    def __iter__(self):
        return self

    def __next__(self) -> ArchiveEntry:
        try:
            member = self.tar.next()  # 流式模式必须用 next()，不能直接迭代
        except StopIteration:
            raise
        except (tarfile.TarError, EOFError, OSError) as e:
            raise ArchiveError(f"tar 读取成员时出错：{e}") from e
        if member is None:
            raise StopIteration
        tmap = {
            tarfile.REGTYPE: TYPE_FILE,
            tarfile.AREGTYPE: TYPE_FILE,
            tarfile.DIRTYPE: TYPE_DIR,
            tarfile.SYMTYPE: TYPE_SYMLINK,
            tarfile.LNKTYPE: TYPE_HARDLINK,
            tarfile.CHRTYPE: TYPE_SPECIAL,
            tarfile.BLKTYPE: TYPE_SPECIAL,
            tarfile.FIFOTYPE: TYPE_SPECIAL,
            tarfile.CONTTYPE: TYPE_FILE,
        }
        etype = tmap.get(member.type, TYPE_OTHER)
        self._member_start = self._counter.position
        self._done = getattr(self, "_done", [])
        self._current = ArchiveEntry(
            index=member.offset if isinstance(member.offset, int) else 0,
            raw_name=_pretty_tar_name(member.name),
            entry_type=etype,
            declared_size=member.size,
            compressed_size=0,
            mode=member.mode,
            link_target=member.linkname or None,
            _native=member,
        )
        # 用遍历序号作为稳定索引（offset 在流式模式下不适合做下标）。
        self._current.index = self._count = getattr(self, "_count", -1) + 1
        return self._current

    def open_member(self, entry: ArchiveEntry):
        if entry is not self._current:
            raise ArchiveError("tar 为流式读取，只能按遍历顺序读取当前成员")
        try:
            stream = self.tar.extractfile(entry._native)
        except (tarfile.TarError, OSError) as e:
            raise ArchiveError(f"读取成员 {entry.raw_name!r} 失败：{e}") from e
        if stream is None:
            # 目录/链接等没有数据流，用空流统一接口。
            stream = io.BytesIO(b"")
        reader = self
        member_start = self._member_start

        class _MemberStream(io.RawIOBase):
            def readable(self):
                return True

            def readinto(self, b):
                n = stream.readinto(b)
                return n

            def close(self):
                try:
                    stream.close()
                finally:
                    entry.compressed_size = reader._counter.position - member_start
                    if entry not in reader._done:
                        reader._done.append(entry)
                super().close()

        return io.BufferedReader(_MemberStream())

    def compressed_position(self, current: ArchiveEntry) -> int:
        # 已完成成员（回填过 compressed_size）的压缩量 + 当前成员已读量
        done = sum(e.compressed_size for e in self._done)
        if current is self._current:
            done += self._counter.position - self._member_start
        return done

    def position_before(self, current: ArchiveEntry) -> int:
        # tar 成员按顺序遍历，当前成员开始前的压缩流位置即入口位置
        return self._member_start if current is self._current else 0

    def close(self):
        try:
            self.tar.close()
        finally:
            self._raw.close()


def detect_format(path: str) -> str:
    """按魔数判断格式，返回 zip / tar / tgz。"""
    with open(path, "rb") as f:
        head = f.read(262 + 512)
    if head[:4] in ZIP_MAGICS:
        return "zip"
    if head[:2] == GZIP_MAGIC:
        return "tgz"
    # tar 的 ustar 魔数位于第 257 字节
    if len(head) >= 263 and head[257:262] in (b"ustar",):
        return "tar"
    # 老式无 ustar 魔数的 tar：至少两个 512 字节块且全零填充，交给 tarfile 兜底
    if len(head) >= 1024 and head[512:1024].count(b"\x00") >= 500:
        return "tar"
    return "unknown"


def open_archive(path: str) -> ZipReader | TarReader:
    """打开压缩包；识别不了或已损坏时抛出明确异常，绝不落到服务进程退出。"""
    fmt = detect_format(path)
    if fmt == "zip":
        return ZipReader(path)
    if fmt in ("tar", "tgz"):
        return TarReader(path)

    # 魔数缺失时做一次保守的兜底尝试。
    try:
        return ZipReader(path)
    except ArchiveError:
        pass
    try:
        return TarReader(path)
    except ArchiveError:
        pass
    raise UnsupportedArchiveError(
        "无法识别的文件格式，仅支持 zip、tar 与 gzip 压缩的 tar（.tar.gz/.tgz）"
    )
