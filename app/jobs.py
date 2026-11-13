"""任务（压缩包检查/释放批次）的状态机、持久化与并发隔离。

每个任务独立目录、独立锁；状态以 JSON 落盘，服务重启后仍可在页面查看
历史检查记录与释放结果。释放采用同步串行 + 任务级互斥锁，
保证“扫描结束前不能释放”以及多个包同时操作不会串结果。
"""
from __future__ import annotations

import json
import threading
import uuid
from datetime import datetime
from pathlib import Path

from . import config
from .analyzer import EntryFinding, RiskRecord
from .extractor import extract, ExtractionError
from .limits import Limits
from .scanner import scan_archive

# 任务状态机
ST_UPLOADED = "uploaded"        # 已上传，等待/正在扫描
ST_SCANNING = "scanning"
ST_SCANNED = "scanned"          # 扫描完成，可选择释放
ST_SCAN_FAILED = "scan_failed"  # 整包损坏/不支持等
ST_EXTRACTING = "extracting"
ST_COMPLETED = "completed"      # 至少有一次成功释放
ST_FAILED = "failed"            # 最近一次释放失败（可重试）

STATE_LABELS = {
    ST_UPLOADED: "已上传",
    ST_SCANNING: "检查中",
    ST_SCANNED: "检查完成",
    ST_SCAN_FAILED: "检查失败",
    ST_EXTRACTING: "释放中",
    ST_COMPLETED: "释放完成",
    ST_FAILED: "释放失败",
}


class Job:
    def __init__(self, job_id: str, original_name: str, archive_path: str):
        self.job_id = job_id
        self.original_name = original_name
        self.archive_path = archive_path
        self.state = ST_UPLOADED
        self.created_at = _now()
        self.updated_at = self.created_at
        self.limits: dict = dict(config.DEFAULT_LIMITS)
        self.limits_obj: Limits | None = None
        self.scan_entries: list[EntryFinding] = []
        self.scan_meta: dict = {}
        self.releases: list[dict] = []
        self.lock = threading.Lock()
        self.error: str | None = None

    # ------------------------------------------------------------------ #
    def run_scan(self, limits: Limits) -> None:
        with self.lock:
            if self.state in (ST_SCANNED, ST_SCAN_FAILED, ST_EXTRACTING,
                              ST_COMPLETED, ST_FAILED):
                raise InvalidState("该任务已扫描，不能重复扫描")
            self.state = ST_SCANNING
            self.limits = limits.to_dict()
            self.limits_obj = limits
            self._persist()

            result = scan_archive(self.archive_path, limits)
            self.scan_entries = result.entries
            self.scan_meta = result.to_dict()
            self.updated_at = _now()
            fatal = any(e["code"] in ("UNSUPPORTED", "ARCHIVE_CORRUPT",
                                      "READ_FAILED") for e in result.errors)
            # 整包无法解析，或中止时一个条目都没分析出来：扫描失败；
            # 仅因条目/大小/比例超限中止但已有结论的，仍允许查看与释放安全条目。
            if fatal or (result.aborted and not result.entries):
                self.state = ST_SCAN_FAILED
                self.error = "；".join(e["message"] for e in result.errors) \
                    or "扫描在产生任何结论前已中止"
            else:
                self.state = ST_SCANNED
            self._persist()

    def run_extract(self, indexes: list[int]) -> dict:
        with self.lock:
            if self.state not in (ST_SCANNED, ST_COMPLETED, ST_FAILED):
                raise InvalidState("扫描尚未完成或任务状态不允许释放")
            self.state = ST_EXTRACTING
            self._persist()
            try:
                outcome = extract(self, list(indexes))
            except ExtractionError as e:
                self.state = ST_FAILED
                self.error = str(e)
                self._persist()
                raise
            record = {
                "release_id": outcome.release_id,
                "status": outcome.status,
                "selected": outcome.selected,
                "succeeded": outcome.succeeded,
                "rejected": outcome.rejected,
                "failed": outcome.failed,
                "total_written": outcome.total_written,
                "release_dir": outcome.release_dir,
                "at": _now(),
            }
            self.releases.append(record)
            self.state = ST_COMPLETED if outcome.status == "succeeded" else ST_FAILED
            self.error = outcome.failed["message"] if outcome.failed else None
            self.updated_at = _now()
            self._persist()
            return record

    # ------------------------------------------------------------------ #
    def to_dict(self) -> dict:
        safe_count = sum(1 for f in self.scan_entries if f.safe)
        risk_count = sum(1 for f in self.scan_entries
                         if any(r.level in ("danger", "warn") for r in f.risks))
        return {
            "job_id": self.job_id,
            "original_name": self.original_name,
            "state": self.state,
            "state_label": STATE_LABELS.get(self.state, self.state),
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "limits": self.limits,
            "scan_meta": self.scan_meta,
            "safe_count": safe_count,
            "risk_count": risk_count,
            "entries": [f.to_dict() for f in self.scan_entries],
            "releases": self.releases,
            "error": self.error,
            "report_url": f"/api/jobs/{self.job_id}/report",
        }

    def report(self) -> dict:
        """完整 JSON 检查报告（含每次释放的真实结果，失败也如实记录）。"""
        return {
            "报告版本": 1,
            "文件摘要": {
                "原始文件名": self.original_name,
                "任务编号": self.job_id,
                "创建时间": self.created_at,
                "最近更新": self.updated_at,
                "当前状态": STATE_LABELS.get(self.state, self.state),
                "扫描汇总": self.scan_meta.get("totals", {}),
                "格式": self.scan_meta.get("format", ""),
                "扫描级错误": self.scan_meta.get("errors", []),
            },
            "实际使用的限制": self.limits,
            "条目检查结果": [
                {
                    "序号": f.index,
                    "原始名称": f.raw_name,
                    "目标相对路径": f.target_rel,
                    "类型": f.entry_type,
                    "声明大小": f.declared_size,
                    "实际大小": f.actual_size,
                    "SHA256": f.sha256,
                    "可释放": f.safe,
                    "风险": [{"代码": r.code, "级别": r.level,
                             "说明": r.message, "详情": r.detail}
                            for r in f.risks],
                    "释放结果": f.extraction or None,
                }
                for f in self.scan_entries
            ],
            "释放记录": self.releases,
        }

    # ------------------------------------------------------------------ #
    def _persist(self) -> None:
        path = _job_path(self.job_id)
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_suffix(".json.tmp")
        tmp.write_text(json.dumps(self._serializable(), ensure_ascii=False, indent=2),
                       encoding="utf-8")
        tmp.replace(path)

    def _serializable(self) -> dict:
        d = self.to_dict()
        d["archive_path"] = self.archive_path
        return d


class InvalidState(Exception):
    pass


class JobManager:
    def __init__(self):
        self._jobs: dict[str, Job] = {}
        self._lock = threading.Lock()

    def create(self, original_name: str, archive_path: str) -> Job:
        job_id = uuid.uuid4().hex
        job = Job(job_id, original_name, archive_path)
        with self._lock:
            self._jobs[job_id] = job
        job._persist()
        return job

    def get(self, job_id: str) -> Job | None:
        return self._jobs.get(job_id)

    def list(self) -> list[dict]:
        with self._lock:
            jobs = sorted(self._jobs.values(),
                          key=lambda j: j.created_at, reverse=True)
        return [{k: v for k, v in j.to_dict().items() if k != "entries"}
                for j in jobs]

    def load_from_disk(self) -> int:
        """服务启动时恢复历史任务（元数据；原始包仍在 uploads 中）。"""
        n = 0
        if not config.JOBS_DIR.exists():
            return 0
        for path in config.JOBS_DIR.glob("*/job.json"):
            try:
                data = json.loads(path.read_text(encoding="utf-8"))
                job = Job(data["job_id"], data["original_name"],
                          data.get("archive_path", ""))
                job.state = data["state"]
                job.created_at = data["created_at"]
                job.updated_at = data["updated_at"]
                job.limits = data["limits"]
                job.scan_meta = data["scan_meta"]
                job.releases = data.get("releases", [])
                job.error = data.get("error")
                job.scan_entries = [_restore_entry(e) for e in data.get("entries", [])]
                # 重启时若卡在中间态，按失败收敛，避免永久挂起
                if job.state in (ST_SCANNING, ST_EXTRACTING):
                    job.state = ST_FAILED
                    job.error = "服务重启前任务未完成，已标记为失败，可重新操作"
                with self._lock:
                    self._jobs[job.job_id] = job
                n += 1
            except (KeyError, json.JSONDecodeError, OSError):
                continue
        return n


def _restore_entry(d: dict) -> EntryFinding:
    f = EntryFinding(
        index=d["index"], raw_name=d["raw_name"], entry_type=d["entry_type"],
        declared_size=d["declared_size"], target_rel=d.get("target_rel"),
        safe=d.get("safe", False), actual_size=d.get("actual_size"),
        sha256=d.get("sha256"), extraction=d.get("extraction") or {},
    )
    f.risks = [RiskRecord(code=r["code"], level=r["level"],
                          message=r["message"], detail=r.get("detail", {}))
               for r in d.get("risks", [])]
    return f


def _job_path(job_id: str) -> Path:
    return config.JOBS_DIR / job_id / "job.json"


def _now() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


# 进程级单例
manager = JobManager()
