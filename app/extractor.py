"""事务化安全释放器。

安全边界（不依赖前端按钮状态，全部在服务端强制执行）：
* 只有扫描结论 ``safe=True`` 的**普通文件**可以释放；风险条目、符号链接、
  硬链接、特殊文件即使被直接写进请求也一律拒绝；
* 每次释放使用独立批次目录，先写入同目录下的临时暂存区，全部成功后才整体
  切换为正式目录；中途任何损坏、超限、写入失败都会整批回滚，不留半成品；
* 每个目标路径在真正写盘前再做一次规范化 + 根目录包含校验（纵深防御）。
"""
from __future__ import annotations

import hashlib
import os
import shutil
from dataclasses import dataclass
from pathlib import Path

from . import config
from .archiveio import open_archive, ArchiveError, TYPE_FILE
from .analyzer import analyze_raw_name
from .limits import LimitExceeded, Limits, SizeTracker


class ExtractionError(Exception):
    """释放过程中的致命错误，触发整批回滚。"""


@dataclass
class ExtractionOutcome:
    release_id: str
    release_dir: str
    selected: list[int]
    succeeded: list[dict]
    rejected: list[dict]
    failed: dict | None
    status: str                       # succeeded / failed
    total_written: int


def _safe_join(root: Path, rel: str) -> Path:
    """写盘前最后一道路径防线：目标必须严格位于 root 之内。"""
    target = (root / rel).resolve()
    root_resolved = root.resolve()
    if target != root_resolved and root_resolved not in target.parents:
        raise ExtractionError(f"目标路径越界，已拒绝写入：{rel}")
    return target


def extract(job, requested_indexes: list[int]) -> ExtractionOutcome:
    """执行一次释放。``job`` 为 jobs.Job 对象（含扫描结论与原始包路径）。"""
    release_id = _new_id()
    batch_root = config.RELEASES_DIR / job.job_id / release_id
    staging = batch_root.with_name(release_id + ".staging")
    if staging.exists():
        shutil.rmtree(staging, ignore_errors=True)
    staging.mkdir(parents=True, exist_ok=False)

    findings = {f.index: f for f in job.scan_entries}
    limits: Limits = job.limits_obj
    tracker = SizeTracker(limits)

    selected: list[int] = []
    rejected: list[dict] = []
    succeeded: list[dict] = []
    total_written = 0
    failed: dict | None = None

    # 1. 服务端逐项复核请求：只认扫描结论，前端传什么都不能越权
    for idx in requested_indexes:
        finding = findings.get(idx)
        if finding is None:
            rejected.append({"index": idx, "reason": "条目不存在于本包"})
            continue
        if finding.entry_type != TYPE_FILE:
            rejected.append({"index": idx, "raw_name": finding.raw_name,
                             "reason": f"非普通文件（{finding.entry_type}），禁止释放"})
            continue
        if not finding.safe:
            rejected.append({"index": idx, "raw_name": finding.raw_name,
                             "reason": "扫描存在风险，禁止释放"})
            continue
        selected.append(idx)

    # 先把每个选中条目的释放结果初始化为 pending（报告能如实呈现过程）
    for idx in selected:
        findings[idx].extraction = {
            "release_id": release_id, "status": "pending", "target": None,
        }

    # 没有任何条目通过服务端安全复核：整批失败并回滚暂存区
    if not selected:
        _rollback(staging)
        return ExtractionOutcome(
            release_id=release_id, release_dir="", selected=selected,
            succeeded=succeeded, rejected=rejected,
            failed={"message": "没有可安全释放的条目，整批未执行（已全部拦截）"},
            status="failed", total_written=0,
        )

    try:
        reader = open_archive(job.archive_path)
    except (ArchiveError, OSError) as e:
        _rollback(staging)
        raise ExtractionError(f"重新打开压缩包失败：{e}") from e

    try:
        wanted = set(selected)
        seen: set[int] = set()
        for entry in reader:
            if entry.index not in wanted:
                continue
            seen.add(entry.index)
            finding = findings[entry.index]

            # 2. 写盘前再次独立校验路径（不信任扫描阶段缓存的字符串）
            codes, clean, _ = analyze_raw_name(entry.raw_name)
            if clean is None or any(c in codes for c in
                                    ("ABS_PATH", "DRIVE_PATH", "TRAVERSAL")):
                raise ExtractionError(f"条目 {entry.raw_name!r} 路径复核未通过")
            target = _safe_join(staging, clean)

            # 3. 必要目录自动建立（目录条目本身不释放，只按需建父目录）
            target.parent.mkdir(parents=True, exist_ok=True)

            # 4. 有界流式写入，真实字节再次执行全部限制
            hasher = hashlib.sha256()
            written = 0
            pos_before = reader.position_before(entry)
            try:
                stream = reader.open_member(entry)
            except ArchiveError as e:
                raise ExtractionError(f"成员 {entry.raw_name!r} 无法读取：{e}") from e
            try:
                # xb：绝不覆盖已存在文件
                with open(target, "xb") as out:
                    while True:
                        chunk = stream.read(config.READ_CHUNK)
                        if not chunk:
                            break
                        out.write(chunk)
                        hasher.update(chunk)
                        written += len(chunk)
                        cdelta = reader.compressed_position(entry) - pos_before
                        pos_before = reader.compressed_position(entry)
                        try:
                            tracker.feed(len(chunk), cdelta, written)
                        except LimitExceeded as e:
                            raise ExtractionError(
                                f"释放中止：{e.message}（条目 {entry.raw_name!r}）"
                            ) from e
            except FileExistsError as e:
                raise ExtractionError(
                    f"目标文件已存在，拒绝覆盖：{clean}"
                ) from e
            except OSError as e:
                raise ExtractionError(
                    f"写入失败（条目 {entry.raw_name!r}）：{e}"
                ) from e
            finally:
                stream.close()

            # 5. 内容摘要与扫描记录一致才允许成功
            if finding.sha256 and hasher.hexdigest() != finding.sha256:
                raise ExtractionError(
                    f"条目 {entry.raw_name!r} 内容摘要与扫描结果不一致，已中止"
                )
            total_written += written
            succeeded.append({
                "index": entry.index, "raw_name": entry.raw_name,
                "target": clean, "size": written,
                "sha256": hasher.hexdigest(),
            })
            finding.extraction = {
                "release_id": release_id, "status": "succeeded",
                "target": clean, "size": written,
                "sha256": hasher.hexdigest(),
            }

        missing = wanted - seen
        if missing:
            raise ExtractionError(
                f"压缩包中找不到选中条目：{sorted(missing)}，包结构可能已损坏"
            )
    except ExtractionError:
        for idx in selected:
            if findings[idx].extraction.get("status") != "succeeded":
                findings[idx].extraction = {
                    "release_id": release_id, "status": "failed",
                    "target": None,
                }
        _rollback(staging)
        reader.close()
        failed = {"message": _last_error_message(selected, findings)}
        return ExtractionOutcome(
            release_id=release_id, release_dir="", selected=selected,
            succeeded=succeeded, rejected=rejected, failed=failed,
            status="failed", total_written=0,
        )
    except (ArchiveError, OSError, EOFError) as e:
        for idx in selected:
            if findings[idx].extraction.get("status") != "succeeded":
                findings[idx].extraction = {
                    "release_id": release_id, "status": "failed",
                    "target": None, "error": str(e),
                }
        _rollback(staging)
        reader.close()
        return ExtractionOutcome(
            release_id=release_id, release_dir="", selected=selected,
            succeeded=succeeded, rejected=rejected,
            failed={"message": f"压缩包读取失败，整批回滚：{e}"},
            status="failed", total_written=0,
        )
    else:
        reader.close()

    # 6. 全部成功：暂存目录整体原子改名为正式批次目录
    try:
        batch_root.parent.mkdir(parents=True, exist_ok=True)
        os.rename(staging, batch_root)
    except OSError as e:
        _rollback(staging)
        raise ExtractionError(f"批次目录切换失败：{e}") from e

    return ExtractionOutcome(
        release_id=release_id, release_dir=str(batch_root),
        selected=selected, succeeded=succeeded, rejected=rejected,
        failed=None, status="succeeded", total_written=total_written,
    )


def _rollback(staging: Path) -> None:
    """整批失败：删除本批暂存区，正式目录与其他批次不受影响。"""
    shutil.rmtree(staging, ignore_errors=True)


def _last_error_message(selected: list[int], findings) -> str:
    for idx in reversed(selected):
        err = findings[idx].extraction.get("error")
        if err:
            return err
    return "释放失败，本批已回滚"


def _new_id() -> str:
    import uuid
    return uuid.uuid4().hex[:12]


def iter_release_files(release_dir: str):
    """枚举一个成功批次内实际释放的普通文件（供打包下载）。"""
    root = Path(release_dir).resolve()
    for path in sorted(root.rglob("*")):
        if path.is_file() and not path.is_symlink():
            yield path, path.relative_to(root).as_posix()


def resolve_download_path(release_dir: str, rel_name: str) -> Path | None:
    """单文件下载的路径解析：任何越界/链接尝试都返回 None。"""
    root = Path(release_dir).resolve()
    candidate = (root / rel_name)
    try:
        resolved = candidate.resolve(strict=False)
    except OSError:
        return None
    if root not in resolved.parents and resolved != root:
        return None
    if not resolved.is_file() or resolved.is_symlink():
        return None
    return resolved
