"""用户可配置的释放限制及其强制逻辑。

声明大小来自压缩包自身的元数据，不可信；真正读取成员内容时
通过 :class:`SizeTracker` 同步累计实际消耗，任何一项超限都会
抛出 :class:`LimitExceeded`，由上层及时中止并记录是哪一项超限。
"""
from __future__ import annotations

from dataclasses import dataclass

from . import config


class LimitExceeded(Exception):
    """读取/扫描过程中突破了某项限制。

    ``kind`` 取值：max_entries / max_file_size / max_total_size / max_ratio。
    """

    def __init__(self, kind: str, message: str, current: int | float, threshold: int | float):
        super().__init__(message)
        self.kind = kind
        self.message = message
        self.current = current
        self.threshold = threshold


@dataclass
class Limits:
    """一次扫描实际生效的限制（已做服务端钳制，结果会写进报告）。"""

    max_entries: int
    max_file_size: int
    max_total_size: int
    max_ratio: float

    @classmethod
    def from_request(cls, raw: dict | None) -> "Limits":
        """从请求参数构造限制；缺失用默认值，越界用服务端硬边界钳制。"""
        raw = raw or {}
        values = dict(config.DEFAULT_LIMITS)
        for key in config.HARD_LIMITS:
            if key not in raw or raw[key] in (None, ""):
                continue
            try:
                num = float(raw[key])
            except (TypeError, ValueError):
                raise LimitExceeded(key, f"限制参数 {key} 不是有效数字", 0, 0)
            low, high = config.HARD_LIMITS[key]
            values[key] = max(low, min(high, num))
        return cls(
            max_entries=int(values["max_entries"]),
            max_file_size=int(values["max_file_size"]),
            max_total_size=int(values["max_total_size"]),
            max_ratio=float(values["max_ratio"]),
        )

    def to_dict(self) -> dict:
        return {
            "max_entries": self.max_entries,
            "max_file_size": self.max_file_size,
            "max_total_size": self.max_total_size,
            "max_ratio": self.max_ratio,
        }


class SizeTracker:
    """扫描/释放时累计实际读取字节与压缩字节，执行单文件、总量与比例限制。"""

    def __init__(self, limits: Limits):
        self.limits = limits
        self.total_uncompressed = 0
        self.total_compressed = 0

    def check_entry_declared(self, declared_size: int) -> None:
        """读取成员前先按声明大小做预判（声明不可信，但能尽早拦下明显超限）。"""
        if declared_size > self.limits.max_file_size:
            raise LimitExceeded(
                "max_file_size",
                f"成员声明大小 {declared_size} 字节超过单文件上限 "
                f"{self.limits.max_file_size} 字节",
                declared_size,
                self.limits.max_file_size,
            )
        if self.total_uncompressed + declared_size > self.limits.max_total_size:
            raise LimitExceeded(
                "max_total_size",
                f"按声明大小累计将达到 {self.total_uncompressed + declared_size} 字节，"
                f"超过总释放大小上限 {self.limits.max_total_size} 字节",
                self.total_uncompressed + declared_size,
                self.limits.max_total_size,
            )

    def feed(self, uncompressed_delta: int, compressed_delta: int, entry_uncompressed: int) -> None:
        """每读到一个分块后调用，基于真实字节数复核全部限制。"""
        self.total_uncompressed += uncompressed_delta
        self.total_compressed += compressed_delta

        if entry_uncompressed > self.limits.max_file_size:
            raise LimitExceeded(
                "max_file_size",
                f"成员实际大小已达 {entry_uncompressed} 字节，"
                f"超过单文件上限 {self.limits.max_file_size} 字节",
                entry_uncompressed,
                self.limits.max_file_size,
            )
        if self.total_uncompressed > self.limits.max_total_size:
            raise LimitExceeded(
                "max_total_size",
                f"实际累计大小 {self.total_uncompressed} 字节，"
                f"超过总释放大小上限 {self.limits.max_total_size} 字节",
                self.total_uncompressed,
                self.limits.max_total_size,
            )
        # 比例 = 实际未压缩字节 / 压缩后字节；tar（无压缩）天然接近 1:1。
        if self.total_compressed > 0:
            ratio = self.total_uncompressed / self.total_compressed
            if ratio > self.limits.max_ratio:
                raise LimitExceeded(
                    "max_ratio",
                    f"实际压缩比例已达 {ratio:.1f}:1，"
                    f"超过上限 {self.limits.max_ratio:.1f}:1（疑似压缩炸弹）",
                    round(ratio, 2),
                    self.limits.max_ratio,
                )
