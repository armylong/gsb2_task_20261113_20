"""路径与条目结构安全分析。

分析器只依赖压缩包内自报的名称/链接信息做静态分析，全程不落地任何文件。
检查维度：
1. 绝对路径、盘符路径、反斜杠绕过、目录穿越（``..``）；
2. 规范化后重名、文件/目录冲突、仅大小写差异的落点冲突——记录冲突双方；
3. 符号链接/硬链接指向目录外，以及后续普通文件借道链接写到外面的组合攻击；
4. 特殊文件与嵌套压缩包标记。
"""
from __future__ import annotations

import posixpath
from dataclasses import dataclass, field

from . import risks
from .risks import DANGER, WARN, RISK_CATALOG


@dataclass
class RiskRecord:
    code: str
    level: str
    message: str
    detail: dict = field(default_factory=dict)


@dataclass
class EntryFinding:
    """单个条目的分析结果，会序列化进任务状态与 JSON 报告。"""

    index: int
    raw_name: str
    entry_type: str
    declared_size: int
    target_rel: str | None = None          # 规范化后的目标相对路径（危险条目可能为 None）
    risks: list[RiskRecord] = field(default_factory=list)
    safe: bool = False                     # 是否允许释放（仅无风险普通文件为 True）
    actual_size: int | None = None         # 扫描时实际读到的字节数
    sha256: str | None = None              # 实际内容摘要（成功读取后才有）
    extraction: dict = field(default_factory=dict)  # 释放结果，见 extractor

    def to_dict(self) -> dict:
        return {
            "index": self.index,
            "raw_name": self.raw_name,
            "entry_type": self.entry_type,
            "type_label": risks_label(self.entry_type),
            "declared_size": self.declared_size,
            "target_rel": self.target_rel,
            "risks": [{"code": r.code, "level": r.level, "message": r.message,
                       "detail": r.detail} for r in self.risks],
            "safe": self.safe,
            "actual_size": self.actual_size,
            "sha256": self.sha256,
            "extraction": self.extraction,
        }


def risks_label(entry_type: str) -> str:
    from .archiveio import TYPE_LABELS
    return TYPE_LABELS.get(entry_type, "其他")


def make_risk(code: str, **detail) -> RiskRecord:
    level, message = RISK_CATALOG[code]
    return RiskRecord(code=code, level=level, message=message, detail=detail)


def analyze_raw_name(raw_name: str) -> tuple[list[str], str | None, bool]:
    """分析条目的原始名称。

    返回 (风险代码列表, 规范化相对路径或 None, 是否含反斜杠)。
    规范化只做字符串运算，不接触文件系统。
    """
    codes: list[str] = []
    name = raw_name
    has_backslash = "\\" in name

    # 1. Windows 盘符：C:foo、C:\foo、//server/share 等
    drive = _detect_drive(name)
    if drive:
        codes.append("DRIVE_PATH")

    # 2. 反斜杠统一视作分隔符再分析（Windows 语义下 \ 与 / 等价）
    normalized_input = name.replace("\\", "/")

    # 3. 绝对路径（POSIX 风格 / 开头，或反斜杠开头 \\foo）
    if normalized_input.startswith("/"):
        codes.append("ABS_PATH")

    # 4. 拆分片段，识别 .. 穿越（含 ....// 这类伪装：连续点段也是异常名称）
    segments = [seg for seg in normalized_input.split("/") if seg not in ("", ".")]
    if any(seg == ".." for seg in segments):
        codes.append("TRAVERSAL")
    # 名称中出现纯多点片段（...、.... 等）在正常素材里不合法，按穿越保守处理
    if any(set(seg) == {"."} and len(seg) >= 3 for seg in segments):
        if "TRAVERSAL" not in codes:
            codes.append("TRAVERSAL")

    # 5. 规范化（纯字符串），判断最终是否逃出根
    clean = posixpath.normpath(posixpath.join(*segments)) if segments else ""
    if clean.startswith("../") or clean == ".." or clean.startswith("/"):
        if "TRAVERSAL" not in codes:
            codes.append("TRAVERSAL")

    if has_backslash:
        codes.append("BACKSLASH_PATH")

    # 危险名称无法给出安全落点
    if any(c in codes for c in ("ABS_PATH", "DRIVE_PATH", "TRAVERSAL")):
        return codes, None, has_backslash
    return codes, clean, has_backslash


def _detect_drive(name: str) -> str | None:
    if len(name) >= 2 and name[1] == ":" and name[0].isalpha():
        return name[:2]
    # UNC 路径 \\server\share
    if name.startswith("\\\\"):
        return "UNC"
    return None


class _TrieNode:
    """落点前缀树：每个规范化路径片段一个节点，记录占用该路径的条目。"""

    __slots__ = ("entry_index", "entry_type", "exact_key", "children", "case_index")

    def __init__(self):
        self.entry_index: int | None = None
        self.entry_type: str | None = None
        self.exact_key: str | None = None
        self.children: dict[str, "_TrieNode"] = {}
        # 小写片段 -> 已注册的原始片段，用于仅大小写差异检测
        self.case_index: dict[str, str] = {}


class PathAnalyzer:
    def __init__(self):
        self.findings: list[EntryFinding] = []
        self._root = _TrieNode()
        # 规范化相对路径（小写） -> 该路径上所有条目索引
        self._case_map: dict[str, list[int]] = {}
        # 已确认的包内符号链接：规范化路径 -> (原始目标, 条目索引)
        self._symlinks: dict[str, tuple[str, int]] = {}
        self._by_index: dict[int, EntryFinding] = {}

    # ------------------------------------------------------------------ #
    # 主入口
    # ------------------------------------------------------------------ #
    def add(self, index: int, raw_name: str, entry_type: str, declared_size: int,
            link_target: str | None) -> EntryFinding:
        finding = EntryFinding(
            index=index, raw_name=raw_name, entry_type=entry_type,
            declared_size=declared_size,
        )
        name_codes, clean, _ = analyze_raw_name(raw_name)
        for code in name_codes:
            finding.risks.append(make_risk(code, raw_name=raw_name))
        finding.target_rel = clean

        # 嵌套压缩包（仅提示，不递归）
        lower = (clean or raw_name).lower()
        if entry_type == "file" and any(lower.endswith(s) for s in risks.NESTED_ARCHIVE_SUFFIXES):
            finding.risks.append(make_risk("NESTED_ARCHIVE"))

        # 结构冲突分析（仅对名称本身可规范化的条目做）
        if clean:
            self._check_collisions(finding, clean)
            self._check_links(finding, clean, link_target)

        # 类型类风险
        if entry_type == "special":
            finding.risks.append(make_risk("SPECIAL_FILE"))
        elif entry_type == "other":
            finding.risks.append(make_risk("UNSUPPORTED_TYPE"))
        elif entry_type == "hardlink":
            self._check_hardlink(finding, link_target)

        finding.safe = (
            entry_type == "file"
            and not any(r.level in (DANGER, WARN) for r in finding.risks)
        )
        self.findings.append(finding)
        self._by_index[index] = finding
        return finding

    # ------------------------------------------------------------------ #
    # 冲突：重名 / 大小写 / 文件目录
    # ------------------------------------------------------------------ #
    def _check_collisions(self, finding: EntryFinding, clean: str) -> None:
        segments = clean.split("/")
        node = self._root
        for depth, seg in enumerate(segments, start=1):
            low = seg.lower()
            # 大小写冲突：同级已有仅大小写不同的片段
            if low in node.case_index and node.case_index[low] != seg:
                other = self._find_index_by_prefix(node, seg, segments, depth)
                self._append_pair_risk(
                    finding, "CASE_COLLISION",
                    other_index=other,
                    path=clean,
                    note=f"路径片段 {node.case_index[low]!r} 与 {seg!r} 仅大小写不同",
                )
            node.case_index.setdefault(low, seg)
            node = node.children.setdefault(seg, _TrieNode())

            # 祖先被条目占用：已有文件挡在当前路径的中间
            if node.entry_index is not None and depth < len(segments):
                other = self._by_index[node.entry_index]
                if node.entry_type == "file":
                    self._append_pair_risk(
                        finding, "TYPE_CONFLICT",
                        other_index=node.entry_index,
                        path=clean,
                        note=f"祖先路径 {other.target_rel!r} 已被普通文件占用",
                    )

        # 终点已被占用
        if node.entry_index is not None:
            other = self._by_index[node.entry_index]
            if other.raw_name == finding.raw_name:
                code = "EXACT_DUPLICATE"
                note = "原始名称完全相同"
            elif node.exact_key and node.exact_key.lower() == clean.lower():
                code = "CASE_COLLISION"
                note = "规范化后仅大小写不同"
            else:
                code = "EXACT_DUPLICATE"
                note = "规范化后落到同一路径"
            self._append_pair_risk(finding, code, other_index=node.entry_index,
                                   path=clean, note=note)
        else:
            node.entry_index = finding.index
            node.entry_type = finding.entry_type
            node.exact_key = clean

        # 反向：当前是目录/文件，挡住了后续条目时由后续条目在祖先检查里报告；
        # 当前是文件而其路径下已注册过子条目（目录在前的场景）
        if node.children and finding.entry_type == "file":
            child_idx = self._first_child_index(node)
            if child_idx is not None:
                self._append_pair_risk(
                    finding, "TYPE_CONFLICT", other_index=child_idx, path=clean,
                    note="该文件路径下已存在子条目，文件与目录冲突",
                )

        self._case_map.setdefault(clean.lower(), []).append(finding.index)

    def _find_index_by_prefix(self, node: _TrieNode, seg: str,
                              segments: list[str], depth: int) -> int | None:
        """大小写冲突时定位对端条目索引。"""
        low = seg.lower()
        for key, child in node.children.items():
            if key.lower() == low and child.entry_index is not None:
                return child.entry_index
        return None

    @staticmethod
    def _first_child_index(node: _TrieNode) -> int | None:
        for child in node.children.values():
            if child.entry_index is not None:
                return child.entry_index
            found = PathAnalyzer._first_child_index(child)
            if found is not None:
                return found
        return None

    def _append_pair_risk(self, finding: EntryFinding, code: str,
                          other_index: int | None, path: str, note: str) -> None:
        other_name = self._by_index[other_index].raw_name if other_index in self._by_index else None
        finding.risks.append(make_risk(
            code, path=path, other_index=other_index,
            other_name=other_name, note=note,
        ))
        if other_index in self._by_index:
            other = self._by_index[other_index]
            if not any(r.code == code and r.detail.get("other_index") == finding.index
                       for r in other.risks):
                other.risks.append(make_risk(
                    code, path=path, other_index=finding.index,
                    other_name=finding.raw_name, note=note,
                ))
                other.safe = False

    # ------------------------------------------------------------------ #
    # 链接：符号链接逃逸与“链接 + 后续文件”组合
    # ------------------------------------------------------------------ #
    def _check_links(self, finding: EntryFinding, clean: str,
                     link_target: str | None) -> None:
        if finding.entry_type == "symlink":
            escaped, resolved, chain = self._resolve_link(clean, link_target or "")
            if escaped:
                finding.risks.append(make_risk(
                    "SYMLINK_ESCAPE", link_target=link_target,
                    resolved=resolved, chain=chain,
                ))
            else:
                finding.risks.append(make_risk(
                    "SYMLINK_INSIDE", link_target=link_target,
                    resolved=resolved, chain=chain,
                ))
            self._symlinks[clean] = (link_target or "", finding.index)
            return

        if finding.entry_type == "file":
            # 逐级检查路径上是否存在包内符号链接
            parts = clean.split("/")
            for i in range(1, len(parts)):
                ancestor = "/".join(parts[:i])
                if ancestor in self._symlinks:
                    target, link_idx = self._symlinks[ancestor]
                    escaped, resolved, chain = self._resolve_link(ancestor, target)
                    # 链接之后剩余的相对片段继续拼接
                    remainder = "/".join(parts[i:])
                    final_posix = posixpath.normpath(posixpath.join(resolved, remainder))
                    final_escape = final_posix.startswith("../") or final_posix == ".."
                    code = "LINK_FOLLOW_ESCAPE" if (escaped or final_escape) else "LINK_FOLLOW_INSIDE"
                    finding.risks.append(make_risk(
                        code, link_entry=link_idx,
                        link_path=ancestor, link_target=target,
                        resolved=final_posix,
                        note=f"借道符号链接 {ancestor!r}（{self._by_index[link_idx].raw_name!r}）写入",
                    ))

    def _resolve_link(self, link_clean_path: str, target: str) -> tuple[bool, str, list[str]]:
        """解析链接目标，跟随包内其他链接，判断是否逃出释放根。

        返回 (是否逃逸, 规范化后的目标相对路径, 经过的链接链)。
        """
        chain: list[str] = []
        seen: set[str] = set()
        current_link = link_clean_path
        current_target = target

        while True:
            chain.append(current_link)
            if current_link in seen:
                return True, "链接循环", chain
            seen.add(current_link)

            if current_target.startswith("/") or current_target.startswith("\\"):
                return True, current_target, chain
            if _detect_drive(current_target):
                return True, current_target, chain

            base = posixpath.dirname(current_link)
            resolved = posixpath.normpath(posixpath.join(base, current_target.replace("\\", "/")))
            if resolved.startswith("../") or resolved == "..":
                return True, resolved, chain
            # 解析结果回到链接链上已出现的位置（含指向自身）：链接循环
            if resolved in seen:
                return True, "链接循环: " + " -> ".join(chain + [resolved]), chain

            if resolved in self._symlinks:
                current_link, current_target = resolved, self._symlinks[resolved][0]
                continue
            return False, resolved, chain

    # ------------------------------------------------------------------ #
    # 硬链接
    # ------------------------------------------------------------------ #
    def _check_hardlink(self, finding: EntryFinding, link_target: str | None) -> None:
        target = link_target or ""
        if target.startswith("/") or _detect_drive(target) or ".." in target.split("/"):
            finding.risks.append(make_risk(
                "HARDLINK_ESCAPE", link_target=target,
                note="硬链接指向释放目录之外的绝对路径或上级路径",
            ))
            return
        finding.risks.append(make_risk("HARDLINK", link_target=target))

    # ------------------------------------------------------------------ #
    def finalize(self) -> list[EntryFinding]:
        """全部条目分析完后复核 safe 标记（冲突风险可能在后续条目上回填）。"""
        for f in self.findings:
            if f.entry_type != "file":
                f.safe = False
                continue
            f.safe = not any(r.level in (DANGER, WARN) for r in f.risks)
        return self.findings
