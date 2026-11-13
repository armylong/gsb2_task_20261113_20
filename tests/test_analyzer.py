"""路径分析器纯逻辑单元测试（不起 HTTP 服务，覆盖边界组合）。"""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.analyzer import PathAnalyzer, analyze_raw_name
from app.risks import DANGER


def analyze(entries: list[tuple]):
    """entries: (index, 原始名, 类型, 声明大小, 链接目标)。"""
    a = PathAnalyzer()
    for item in entries:
        idx, name, etype = item[0], item[1], item[2]
        size = item[3] if len(item) > 3 else 10
        target = item[4] if len(item) > 4 else None
        a.add(idx, name, etype, size, target)
    a.finalize()
    return {f.index: f for f in a.findings}


class AnalyzerTests(unittest.TestCase):
    def test_traversal_variants(self):
        f = analyze([
            (0, "../a.txt", "file", 1, None),
            (1, "a/../../b.txt", "file", 1, None),
            (2, "/etc/passwd", "file", 1, None),
            (3, "C:\\Windows\\x", "file", 1, None),
            (4, "..\\..\\evil", "file", 1, None),
        ])
        self.assertTrue(any(r.code == "TRAVERSAL" for r in f[0].risks))
        self.assertTrue(any(r.code == "TRAVERSAL" for r in f[1].risks))
        self.assertTrue(any(r.code == "ABS_PATH" for r in f[2].risks))
        self.assertTrue(any(r.code == "DRIVE_PATH" for r in f[3].risks))
        self.assertTrue(any(r.code == "BACKSLASH_PATH" for r in f[4].risks))
        for item in f.values():
            self.assertFalse(item.safe)

    def test_exact_duplicate_records_both(self):
        f = analyze([(0, "dir/a.txt", "file"), (1, "dir/a.txt", "file")])
        for idx in (0, 1):
            risk = next(r for r in f[idx].risks if r.code == "EXACT_DUPLICATE")
            self.assertEqual(risk.detail["other_index"], 1 - idx)
            self.assertFalse(f[idx].safe)

    def test_case_collision(self):
        f = analyze([(0, "ReadMe.txt", "file"), (1, "README.TXT", "file")])
        self.assertTrue(any(r.code == "CASE_COLLISION" for r in f[0].risks))
        self.assertTrue(any(r.code == "CASE_COLLISION" for r in f[1].risks))

    def test_file_dir_type_conflict(self):
        f = analyze([
            (0, "conflict", "file"),
            (1, "conflict/child.txt", "file"),
        ])
        codes = {r.code for r in f[0].risks} | {r.code for r in f[1].risks}
        self.assertIn("TYPE_CONFLICT", codes)

    def test_symlink_escape_and_follow(self):
        f = analyze([
            (0, "work", "dir", 0, None),
            (1, "work/link", "symlink", 0, "/tmp"),
            (2, "work/link/evil.txt", "file", 5, None),
            (3, "work/link/../inner.txt", "file", 5, None),
        ])
        self.assertTrue(any(r.code == "SYMLINK_ESCAPE" for r in f[1].risks))
        self.assertTrue(any(r.code == "LINK_FOLLOW_ESCAPE" for r in f[2].risks))
        self.assertFalse(f[1].safe)
        self.assertFalse(f[2].safe)

    def test_inside_symlink_chain(self):
        # 链接指向包内目录，后续文件仍被标记借道风险
        f = analyze([
            (0, "a", "dir", 0, None),
            (1, "a/real", "dir", 0, None),
            (2, "a/real/data.txt", "file", 3, None),
            (3, "a/alias", "symlink", 0, "real"),
            (4, "a/alias/data2.txt", "file", 3, None),
        ])
        self.assertTrue(any(r.code == "SYMLINK_INSIDE" for r in f[3].risks))
        self.assertTrue(any(r.code == "LINK_FOLLOW_INSIDE" for r in f[4].risks))

    def test_symlink_loop(self):
        f = analyze([
            (0, "x", "symlink", 0, "x"),
        ])
        risk = next(r for r in f[0].risks if r.code == "SYMLINK_ESCAPE")
        self.assertIn("循环", str(risk.detail))

    def test_safe_files_remain_extractable(self):
        f = analyze([
            (0, "docs/", "dir", 0, None),
            (1, "docs/a.txt", "file", 10, None),
            (2, "docs/sub/b.txt", "file", 20, None),
        ])
        self.assertFalse(f[0].safe)  # 目录不参与释放
        self.assertTrue(f[1].safe)
        self.assertTrue(f[2].safe)

    def test_special_and_hardlink_blocked(self):
        f = analyze([
            (0, "dev/null", "special", 0, None),
            (1, "hl", "hardlink", 0, "/etc/hosts"),
            (2, "hl2", "hardlink", 0, "docs/a.txt"),
        ])
        self.assertTrue(any(r.code == "SPECIAL_FILE" for r in f[0].risks))
        self.assertTrue(any(r.code == "HARDLINK_ESCAPE" for r in f[1].risks))
        self.assertTrue(any(r.code == "HARDLINK" for r in f[2].risks))
        for item in f.values():
            self.assertFalse(item.safe)

    def test_normalized_target_path(self):
        f = analyze([(0, "a/b/../c.txt", "file")])
        # 含 .. 片段即视为穿越风险（保守策略）
        self.assertTrue(any(r.code == "TRAVERSAL" for r in f[0].risks))

    def test_nested_archive_info_only(self):
        f = analyze([
            (0, "inner.zip", "file", 100, None),
            (1, "inner.tar.gz", "file", 100, None),
            (2, "plain.txt", "file", 10, None),
        ])
        self.assertTrue(any(r.code == "NESTED_ARCHIVE" for r in f[0].risks))
        self.assertTrue(any(r.code == "NESTED_ARCHIVE" for r in f[1].risks))
        # info 级别不影响可释放性
        self.assertTrue(f[0].safe)
        self.assertTrue(f[2].safe)

    def test_disguised_dots_segment(self):
        for name in ("....//evil", ".../x", "...."):
            codes, clean, _ = analyze_raw_name(name)
            self.assertIn("TRAVERSAL", codes, name)
            self.assertIsNone(clean)


if __name__ == "__main__":
    unittest.main(verbosity=2)
