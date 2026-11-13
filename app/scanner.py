"""安全扫描器：遍历压缩包条目、做静态分析、有界读取真实内容。

扫描全程只读取上传的原始包，不创建任何释放目录、不落地成员内容。
声明大小不可信，普通文件会按分块真实读取并计算 SHA-256，
读取过程中由 :class:`~app.limits.SizeTracker` 按实际字节复核限制。
"""
from __future__ import annotations

import hashlib

from . import config, risks
from .analyzer import EntryFinding, PathAnalyzer, make_risk
from .archiveio import open_archive, ArchiveError, UnsupportedArchiveError, TYPE_FILE
from .limits import LimitExceeded, Limits, SizeTracker


class ScanResult:
    def __init__(self):
        self.analyzer = PathAnalyzer()
        self.tracker: SizeTracker | None = None
        self.errors: list[dict] = []       # 任务级错误（整包损坏、整批中止）
        self.aborted = False
        self.format = ""

    @property
    def entries(self) -> list[EntryFinding]:
        return self.analyzer.findings

    def to_dict(self) -> dict:
        return {
            "format": self.format,
            "aborted": self.aborted,
            "errors": list(self.errors),
            "totals": {
                "entries": len(self.analyzer.findings),
                "declared_size": sum(f.declared_size for f in self.analyzer.findings),
                "actual_size": self.tracker.total_uncompressed if self.tracker else 0,
                "compressed_size": self.tracker.total_compressed if self.tracker else 0,
                "ratio": (
                    round(self.tracker.total_uncompressed / self.tracker.total_compressed, 2)
                    if self.tracker and self.tracker.total_compressed else None
                ),
            },
        }


def scan_archive(path: str, limits: Limits) -> ScanResult:
    """扫描一个压缩包，返回完整分析结果；任何异常都收敛为结果里的错误。"""
    result = ScanResult()
    result.tracker = SizeTracker(limits)

    try:
        reader = open_archive(path)
    except UnsupportedArchiveError as e:
        result.errors.append({"code": "UNSUPPORTED", "message": str(e)})
        result.aborted = True
        return result
    except ArchiveError as e:
        result.errors.append({"code": "ARCHIVE_CORRUPT", "message": str(e)})
        result.aborted = True
        return result
    except OSError as e:
        result.errors.append({"code": "READ_FAILED", "message": f"文件读取失败：{e}"})
        result.aborted = True
        return result

    result.format = type(reader).__name__

    try:
        entry_count = 0
        for entry in reader:
            entry_count += 1
            if entry_count > limits.max_entries:
                result.aborted = True
                result.errors.append({
                    "code": "TOO_MANY_ENTRIES",
                    "message": (f"条目数达到上限 {limits.max_entries}，"
                                "已中止扫描，后续条目未检查"),
                    "limit": limits.max_entries,
                })
                break

            finding = result.analyzer.add(
                index=entry.index,
                raw_name=entry.raw_name,
                entry_type=entry.entry_type,
                declared_size=entry.declared_size,
                link_target=entry.link_target,
            )

            # 声明大小预判（不可信，但能在读取前拦下明显超限）
            try:
                result.tracker.check_entry_declared(entry.declared_size)
            except LimitExceeded as e:
                code = "DECLARED_TOO_BIG" if e.kind == "max_file_size" else "TOTAL_DECLARED"
                finding.risks.append(make_risk(
                    code, declared=entry.declared_size,
                    limit=e.threshold, note=e.message,
                ))
                if e.kind == "max_total_size":
                    result.aborted = True
                    result.errors.append({
                        "code": e.kind, "message": e.message,
                        "current": e.current, "limit": e.threshold,
                    })
                    break
                finding.safe = False
                continue

            # 只有普通文件才读取真实内容；链接/目录/特殊文件一律不读内容
            if entry.entry_type != TYPE_FILE:
                continue
            # 已知危险（穿越/绝对路径/链接逃逸等）的文件也不必再读
            if any(r.level == risks.DANGER for r in finding.risks):
                finding.safe = False
                continue

            _read_member(reader, entry, finding, result, limits)
            if result.aborted:
                break
    except ArchiveError as e:
        result.aborted = True
        result.errors.append({"code": "ARCHIVE_CORRUPT", "message": str(e)})
    except OSError as e:
        result.aborted = True
        result.errors.append({"code": "READ_FAILED", "message": f"读取过程出错：{e}"})
    finally:
        reader.close()

    result.analyzer.finalize()
    return result


def _read_member(reader, entry, finding: EntryFinding, result: ScanResult,
                 limits: Limits) -> None:
    """分块读取一个普通文件的全部内容：算摘要、按真实字节强制限制。"""
    hasher = hashlib.sha256()
    actual = 0
    # 用“成员压缩量”计算真实压缩比例，避免把 zip 头尾元数据算进分母，
    # 导致高压缩比炸弹在小包上被稀释。
    pos_before = reader.position_before(entry)
    try:
        stream = reader.open_member(entry)
    except ArchiveError as e:
        finding.risks.append(make_risk("READ_ERROR", note=str(e)))
        finding.safe = False
        return

    try:
        while True:
            chunk = stream.read(config.READ_CHUNK)
            if not chunk:
                break
            hasher.update(chunk)
            n = len(chunk)
            actual += n
            compressed_delta = reader.compressed_position(entry) - pos_before
            pos_before = reader.compressed_position(entry)
            try:
                result.tracker.feed(n, compressed_delta, actual)
            except LimitExceeded as e:
                code = {
                    "max_file_size": "READ_TOO_BIG",
                    "max_total_size": "READ_TOTAL",
                    "max_ratio": "RATIO_EXCEEDED",
                }[e.kind]
                finding.risks.append(make_risk(
                    code, actual=actual, limit=e.threshold, note=e.message,
                ))
                finding.safe = False
                result.aborted = True
                result.errors.append({
                    "code": e.kind, "message": e.message,
                    "current": e.current, "limit": e.threshold,
                    "entry": finding.raw_name,
                })
                return
    except (ArchiveError, OSError, EOFError) as e:
        finding.risks.append(make_risk(
            "READ_ERROR", note=f"成员内容损坏或读取中断：{e}",
        ))
        finding.safe = False
        return
    finally:
        try:
            stream.close()
        except (ArchiveError, OSError):
            finding.risks.append(make_risk("READ_ERROR", note="成员流关闭时校验失败"))
            finding.safe = False

    finding.actual_size = actual
    finding.sha256 = hasher.hexdigest()
    if actual != entry.declared_size:
        # 声明与实际不符本身记录在报告数据里（两个字段都有），不单独算风险
        pass
