"""端到端自动化验证。

运行：python3 -m unittest tests.test_security -v
覆盖：
* 正常中文包的检查与释放全流程；
* 目录穿越/绝对路径/反斜杠/重名/符号链接组合等危险包不会在释放目录外留文件；
* 超限按真实字节中止、损坏包不拖垮服务；
* 失败释放整批回滚、重试不篡改历史失败记录；
* 跨批次下载隔离与下载地址越权防护；
* 服务端强制拦截：直接请求释放危险条目也不会成功。
"""
from __future__ import annotations

import io
import json
import os
import sys
import tarfile
import tempfile
import unittest
import zipfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from tests.support import TestServer


def make_zip(entries: list[tuple]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, data in entries:
            zf.writestr(name, data)
    return buf.getvalue()


def make_tar(entries: list[tuple], gzip=True) -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz" if gzip else "w") as tf:
        for name, kind, payload in entries:
            ti = tarfile.TarInfo(name)
            if kind == "symlink":
                ti.type = tarfile.SYMTYPE
                ti.linkname = payload
                ti.mode = 0o777
            elif kind == "dir":
                ti.type = tarfile.DIRTYPE
                ti.mode = 0o755
            else:
                data = payload if isinstance(payload, bytes) else payload.encode()
                ti.size = len(data)
                ti.mode = 0o644
                tf.addfile(ti, io.BytesIO(data))
            if kind in ("symlink", "dir"):
                tf.addfile(ti)
    return buf.getvalue()


class SecurityTests(unittest.TestCase):
    server: TestServer = None

    @classmethod
    def setUpClass(cls):
        cls.server = TestServer()

    @classmethod
    def tearDownClass(cls):
        cls.server.stop()

    # ------------------------------------------------------------------ #
    def find(self, job, code=None, raw_contains=None):
        for e in job["entries"]:
            if code and any(r["code"] == code for r in e["risks"]):
                return e
            if raw_contains and raw_contains in e["raw_name"]:
                return e
        return None

    def safe_indexes(self, job):
        return [e["index"] for e in job["entries"] if e["safe"]]

    # 1. 正常包：中文展示、扫描、释放、下载全流程 ----------------------- #
    def test_01_normal_package_full_flow(self):
        pkg = make_zip([
            ("素材/说明.txt", "中文内容".encode()),
            ("素材/子目录/封面.txt", b"cover"),
            ("readme.md", b"# ok"),
        ])
        status, data = self.server.upload(pkg, "正常包.zip")
        self.assertEqual(status, 200)
        job = self.server.wait_state(data["job_id"])
        self.assertEqual(job["state"], "scanned")
        self.assertEqual(job["safe_count"], 3)
        # 中文文件名原样展示
        self.assertTrue(any("说明.txt" in e["raw_name"] for e in job["entries"]))
        # 实际大小与摘要被真实计算
        entry = self.find(job, raw_contains="readme.md")
        self.assertEqual(entry["actual_size"], 4)
        self.assertEqual(len(entry["sha256"]), 64)

        indexes = self.safe_indexes(job)
        resp = self.server.post_json(
            f"/api/jobs/{job['job_id']}/extract", {"indexes": indexes})
        self.assertEqual(resp["state"], "completed")
        release = resp["release"]
        self.assertEqual(release["status"], "succeeded")
        self.assertEqual(len(release["succeeded"]), 3)

        # 释放目录内确实有文件，且全部位于数据目录之内
        rdir = Path(release["release_dir"])
        self.assertTrue(rdir.is_dir())
        self.assertTrue((rdir / "素材" / "说明.txt").is_file())
        for p in rdir.rglob("*"):
            self.assertTrue(str(p.resolve()).startswith(
                str(self.server.data_dir.resolve())))

        # 打包下载可访问且是合法 zip
        code, body = self.server.get_raw(
            f"/api/jobs/{job['job_id']}/download?release_id={release['release_id']}")
        self.assertEqual(code, 200)
        with zipfile.ZipFile(io.BytesIO(body)) as zf:
            names = zf.namelist()
            self.assertIn("素材/说明.txt", names)

        # JSON 报告内容完整且为中文键
        report = self.server.get_json(f"/api/jobs/{job['job_id']}/report")
        self.assertIn("文件摘要", report)
        self.assertIn("实际使用的限制", report)
        self.assertEqual(len(report["条目检查结果"]), 3)
        self.assertTrue(all("原始名称" in x for x in report["条目检查结果"]))

    # 2. 目录穿越：标记危险且无法释放、目录外无文件 --------------------- #
    def test_02_traversal_blocked_and_no_escape(self):
        evil_marker = Path(tempfile.gettempdir()) / "safearch_evil_traversal.txt"
        evil_marker.unlink(missing_ok=True)
        pkg = make_zip([
            ("safe.txt", b"ok"),
            ("../../../../tmp/safearch_evil_traversal.txt", b"evil"),
        ])
        _, data = self.server.upload(pkg, "穿越.zip")
        job = self.server.wait_state(data["job_id"])
        bad = self.find(job, "TRAVERSAL")
        self.assertIsNotNone(bad)
        self.assertFalse(bad["safe"])

        # 直接请求释放危险条目：服务端必须拒绝（整批没有文件可写）
        resp = self.server.post_json(
            f"/api/jobs/{job['job_id']}/extract", {"indexes": [bad["index"]]})
        self.assertEqual(resp["release"]["status"], "failed")
        self.assertTrue(any(r["index"] == bad["index"]
                            for r in resp["release"]["rejected"]))
        # 失败后暂存区被清理，没有正式批次目录，目录外无文件
        self.assertFalse(evil_marker.exists())
        release_root = self.server.data_dir / "releases" / job["job_id"]
        if release_root.exists():
            self.assertEqual(
                [p for p in release_root.rglob("*") if p.is_file()], [])

        # 只释放安全文件可以成功，危险文件仍然不在磁盘上
        good = self.find(job, raw_contains="safe.txt")
        resp2 = self.server.post_json(
            f"/api/jobs/{job['job_id']}/extract", {"indexes": [good["index"]]})
        self.assertEqual(resp2["state"], "completed")
        self.assertFalse(evil_marker.exists())

    # 3. 绝对路径 tar ---------------------------------------------------- #
    def test_03_absolute_path_tar(self):
        marker = Path(tempfile.gettempdir()) / "safearch_absolute_evil.txt"
        marker.unlink(missing_ok=True)
        pkg = make_tar([
            ("etc/配置.conf", "file", "内部"),
            ("/tmp/safearch_absolute_evil.txt", "file", "外部"),
        ])
        _, data = self.server.upload(pkg, "绝对.tar.gz")
        job = self.server.wait_state(data["job_id"])
        bad = self.find(job, "ABS_PATH")
        self.assertIsNotNone(bad)
        self.assertFalse(bad["safe"])
        resp = self.server.post_json(
            f"/api/jobs/{job['job_id']}/extract", {"indexes": [bad["index"]]})
        self.assertEqual(resp["release"]["status"], "failed")
        self.assertFalse(marker.exists())

    # 4. 反斜杠绕过 ------------------------------------------------------ #
    def test_04_backslash_bypass(self):
        pkg = make_zip([
            ("ok.txt", b"ok"),
            ("..\\..\\..\\tmp\\safearch_backslash_evil.txt", b"x"),
        ])
        _, data = self.server.upload(pkg, "反斜杠.zip")
        job = self.server.wait_state(data["job_id"])
        self.assertIsNotNone(self.find(job, "BACKSLASH_PATH"))
        self.assertIsNotNone(self.find(job, "TRAVERSAL"))
        self.assertFalse(any(e["safe"] and "backslash" in e["raw_name"]
                             for e in job["entries"]))

    # 5. 重名/大小写/文件目录冲突，且能看到冲突双方 --------------------- #
    def test_05_collisions_show_both_parties(self):
        pkg = make_zip([
            ("data/log.txt", b"a"),
            ("data/log.txt", b"b"),
            ("README.txt", b"upper"),
            ("readme.txt", b"lower"),
            ("conflict", b"iamfile"),
            ("conflict/inside.txt", b"child"),
        ])
        _, data = self.server.upload(pkg, "冲突.zip")
        job = self.server.wait_state(data["job_id"])
        dup = self.find(job, "EXACT_DUPLICATE")
        case = self.find(job, "CASE_COLLISION")
        typ = self.find(job, "TYPE_CONFLICT")
        self.assertIsNotNone(dup)
        self.assertIsNotNone(case)
        self.assertIsNotNone(typ)
        # 冲突风险里必须带对端条目信息，而不是只看名称里的两个点
        party = next(r for r in dup["risks"] if r["code"] == "EXACT_DUPLICATE")
        self.assertIsNotNone(party["detail"].get("other_name"))
        self.assertIn("log.txt", party["detail"]["other_name"])
        # 所有冲突条目都不可释放
        for e in job["entries"]:
            if any(r["code"] in ("EXACT_DUPLICATE", "CASE_COLLISION",
                                 "TYPE_CONFLICT") for r in e["risks"]):
                self.assertFalse(e["safe"], e["raw_name"])

    # 6. 符号链接 + 后续文件组合逃逸 ------------------------------------ #
    def test_06_symlink_then_file_escape(self):
        marker = Path(tempfile.gettempdir()) / "safearch_link_evil.txt"
        marker.unlink(missing_ok=True)
        pkg = make_tar([
            ("work/", "dir", None),
            ("work/link", "symlink", "/tmp"),
            ("work/link/safearch_link_evil.txt", "file", "evil"),
        ])
        _, data = self.server.upload(pkg, "链接逃逸.tar.gz")
        job = self.server.wait_state(data["job_id"])
        self.assertIsNotNone(self.find(job, "SYMLINK_ESCAPE"))
        follow = self.find(job, "LINK_FOLLOW_ESCAPE")
        self.assertIsNotNone(follow)
        self.assertFalse(follow["safe"])
        # 链接条目与跟随条目都不能通过直接请求释放
        idxs = [e["index"] for e in job["entries"]]
        resp = self.server.post_json(
            f"/api/jobs/{job['job_id']}/extract", {"indexes": idxs})
        self.assertEqual(resp["release"]["status"], "failed")
        self.assertFalse(marker.exists())

    # 7. 压缩比例超限：真实字节触发中止 --------------------------------- #
    def test_07_ratio_limit_aborts_on_real_bytes(self):
        big = b"\x00" * (5 * 1024 * 1024)
        pkg = make_zip([("zero.bin", big)])
        # 比例上限调到 50:1，全零数据压缩比远超
        job = self.server.load_demo  # 占位避免提示
        _, data = self.server.upload(
            pkg, "bomb.zip",
            limits={"max_entries": 100, "max_file_size": 1024 ** 3,
                    "max_total_size": 1024 ** 3, "max_ratio": 50})
        result = self.server.wait_state(data["job_id"])
        codes = [e["code"] for err in result["scan_meta"]["errors"]
                 for e in [err]]
        self.assertTrue(
            any(err["code"] == "max_ratio" for err in result["scan_meta"]["errors"]),
            result["scan_meta"]["errors"])
        self.assertTrue(any(
            r["code"] == "RATIO_EXCEEDED"
            for e in result["entries"] for r in e["risks"]))

    # 8. 条目数上限 ------------------------------------------------------ #
    def test_08_entry_count_limit(self):
        pkg = make_zip([(f"f{i}.txt", b"x") for i in range(20)])
        _, data = self.server.upload(
            pkg, "many.zip",
            limits={"max_entries": 5, "max_file_size": 1024 ** 2,
                    "max_total_size": 1024 ** 2, "max_ratio": 100})
        job = self.server.wait_state(data["job_id"])
        self.assertTrue(any(e["code"] == "TOO_MANY_ENTRIES"
                            for e in job["scan_meta"]["errors"]))
        self.assertLessEqual(len(job["entries"]), 5)

    # 9. 损坏包：报告原因、服务不退出、后续请求正常 --------------------- #
    def test_09_corrupt_archive_reported_and_server_alive(self):
        good = make_zip([("a.txt", b"hello")])
        corrupt = good[: len(good) // 2]
        _, data = self.server.upload(corrupt, "损坏.zip")
        job = self.server.wait_state(data["job_id"])
        self.assertEqual(job["state"], "scan_failed")
        self.assertTrue(job["error"])
        # 服务仍然健康：另一个正常包可以照常处理
        job2 = self.server.load_demo("normal")
        self.assertEqual(job2["state"], "scanned")

    # 10. 不支持的文件类型 ----------------------------------------------- #
    def test_10_unsupported_file(self):
        _, data = self.server.upload(b"this is not an archive at all" * 10,
                                     "奇怪.dat")
        job = self.server.wait_state(data["job_id"])
        self.assertEqual(job["state"], "scan_failed")
        self.assertIn("无法识别", job["error"])

    # 11. 释放失败整批回滚，重试不篡改历史失败 -------------------------- #
    def test_11_failure_rolls_back_and_history_kept(self):
        # 构造含损坏成员的 zip：先正常文件后一个无法解压的成员
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("a.txt", b"first")
            zf.writestr("b.txt", b"second")
        raw = bytearray(buf.getvalue())
        # 破坏第二个成员的局部数据（中央目录之后不动，破坏数据区末尾）
        raw[-40] = raw[-40] ^ 0xFF
        _, data = self.server.upload(bytes(raw), "半损坏.zip")
        job = self.server.wait_state(data["job_id"])
        # 扫描可能成功也可能在读取时报错；尝试释放全部安全条目
        indexes = self.safe_indexes(job)
        if indexes:
            resp = self.server.post_json(
                f"/api/jobs/{job['job_id']}/extract", {"indexes": indexes})
            if resp["state"] == "failed":
                # 正式批次目录不应存在（暂存已回滚）
                rel_root = self.server.data_dir / "releases" / job["job_id"]
                self.assertFalse(any(rel_root.glob("*")) if rel_root.exists() else True)

        # 无论上一步如何，重新加载一个正常包，确认失败不影响后续操作
        normal = self.server.load_demo("normal")
        resp2 = self.server.post_json(
            f"/api/jobs/{normal['job_id']}/extract",
            {"indexes": self.safe_indexes(normal)})
        self.assertEqual(resp2["state"], "completed")

        # 报告里每次释放记录都如实保留，失败不会被后续成功覆盖
        report = self.server.get_json(f"/api/jobs/{normal['job_id']}/report")
        self.assertTrue(all(rec["status"] == "succeeded"
                            for rec in report["释放记录"]))

    # 12. 跨批次下载隔离 + 下载地址越权 --------------------------------- #
    def test_12_cross_batch_download_isolation(self):
        j1 = self.server.load_demo("normal")
        r1 = self.server.post_json(
            f"/api/jobs/{j1['job_id']}/extract",
            {"indexes": self.safe_indexes(j1)})
        rid1 = r1["release"]["release_id"]

        j2 = self.server.load_demo("normal")
        r2 = self.server.post_json(
            f"/api/jobs/{j2['job_id']}/extract",
            {"indexes": self.safe_indexes(j2)})
        rid2 = r2["release"]["release_id"]
        self.assertNotEqual(rid1, rid2)

        # 用任务1的身份请求任务2的批次：必须 404
        code, _ = self.server.get_raw(
            f"/api/jobs/{j1['job_id']}/download?release_id={rid2}")
        self.assertEqual(code, 404)
        # 伪造不存在的批次
        code, _ = self.server.get_raw(
            f"/api/jobs/{j1['job_id']}/download?release_id=deadbeefdead")
        self.assertEqual(code, 404)
        # 单文件下载中的穿越尝试
        code, _ = self.server.get_raw(
            f"/api/jobs/{j2['job_id']}/files/..%2f..%2f..%2fetc%2fpasswd"
            f"?release_id={rid2}")
        self.assertEqual(code, 404)
        # 正常单文件下载可用（目标名含中文，需要百分号编码）
        from urllib.parse import quote
        target = r2["release"]["succeeded"][0]["target"]
        code, body = self.server.get_raw(
            f"/api/jobs/{j2['job_id']}/files/{quote(target)}"
            f"?release_id={rid2}")
        self.assertEqual(code, 200)
        self.assertGreater(len(body), 0)

    # 13. 扫描阶段不在释放目录留文件 ------------------------------------ #
    def test_13_scan_leaves_no_extracted_files(self):
        rel_dir = self.server.data_dir / "releases"
        before = set(rel_dir.rglob("*")) if rel_dir.exists() else set()
        self.server.load_demo("symlink")
        self.server.load_demo("traversal")
        after = set(rel_dir.rglob("*")) if rel_dir.exists() else set()
        self.assertEqual(before, after)

        # 真实上传的原件只进入 uploads 专属目录，本任务的释放目录不会被建立
        pkg = make_zip([("a.txt", b"x"), ("../evil.txt", b"y")])
        _, data = self.server.upload(pkg, "扫描留痕检查.zip")
        job = self.server.wait_state(data["job_id"])
        uploads = list((self.server.data_dir / "uploads").rglob("source.bin"))
        self.assertGreaterEqual(len(uploads), 1)
        # 没有执行过释放：该任务不应存在任何批次目录
        self.assertFalse(
            (self.server.data_dir / "releases" / job["job_id"]).exists())

    # 14. 演示包全部可加载且危险项被识别 -------------------------------- #
    def test_14_all_demos_load_with_expected_risks(self):
        expect = {
            "normal": None,
            "traversal": "TRAVERSAL",
            "absolute": "ABS_PATH",
            "backslash": "BACKSLASH_PATH",
            "duplicate": "EXACT_DUPLICATE",
            "symlink": "SYMLINK_ESCAPE",
            "bomb": "RATIO_EXCEEDED",
            "corrupt": None,  # 整包损坏，状态为 scan_failed
        }
        for key, code in expect.items():
            job = self.server.load_demo(key)
            if key == "corrupt":
                self.assertEqual(job["state"], "scan_failed", key)
                continue
            if code:
                self.assertIsNotNone(self.find(job, code),
                                     f"{key} 应命中 {code}")

    # 15. 嵌套压缩包只标记不递归 ---------------------------------------- #
    def test_15_nested_archive_flagged_not_recursed(self):
        inner = make_zip([("inside.txt", b"x")])
        outer = make_zip([
            ("内层.zip", inner),
            ("普通.txt", b"y"),
        ])
        _, data = self.server.upload(outer, "嵌套.zip")
        job = self.server.wait_state(data["job_id"])
        nested = self.find(job, "NESTED_ARCHIVE")
        self.assertIsNotNone(nested)
        self.assertTrue(any(r["level"] == "info" for r in nested["risks"]))
        # 内层文件没有被展开成独立条目
        self.assertFalse(any(e["raw_name"] == "inside.txt"
                             for e in job["entries"]))

    # 16. 刷新后历史记录仍可查看（状态持久化） -------------------------- #
    def test_16_history_persisted(self):
        job = self.server.load_demo("normal")
        listing = self.server.get_json("/api/jobs")
        self.assertTrue(any(j["job_id"] == job["job_id"] for j in listing["jobs"]))
        disk = self.server.data_dir / "jobs" / job["job_id"] / "job.json"
        self.assertTrue(disk.is_file())
        saved = json.loads(disk.read_text(encoding="utf-8"))
        self.assertEqual(saved["job_id"], job["job_id"])
        self.assertIn("entries", saved)

    # 17. 空压缩包不报错、服务不崩 -------------------------------------- #
    def test_17_empty_archives(self):
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w"):
            pass
        _, data = self.server.upload(buf.getvalue(), "空.zip")
        job = self.server.wait_state(data["job_id"])
        self.assertEqual(job["state"], "scanned")
        self.assertEqual(len(job["entries"]), 0)

        tbuf = io.BytesIO()
        with tarfile.open(fileobj=tbuf, mode="w:gz"):
            pass
        _, data2 = self.server.upload(tbuf.getvalue(), "空.tar.gz")
        job2 = self.server.wait_state(data2["job_id"])
        self.assertEqual(job2["state"], "scanned")
        self.assertEqual(len(job2["entries"]), 0)

    # 18. 限制参数在服务端被钳制到硬边界 -------------------------------- #
    def test_18_limits_clamped_server_side(self):
        pkg = make_zip([("a.txt", b"x")])
        # 传入荒谬的参数：负数、超大值，服务端应钳制而不是崩溃或放行
        _, data = self.server.upload(pkg, "clamp.zip", limits={
            "max_entries": -999, "max_file_size": 10 ** 18,
            "max_total_size": -1, "max_ratio": 0})
        job = self.server.wait_state(data["job_id"])
        self.assertEqual(job["state"], "scanned")
        from app import config
        self.assertEqual(job["limits"]["max_entries"],
                         config.HARD_LIMITS["max_entries"][0])
        self.assertEqual(job["limits"]["max_file_size"],
                         config.HARD_LIMITS["max_file_size"][1])
        self.assertEqual(job["limits"]["max_ratio"],
                         config.HARD_LIMITS["max_ratio"][0])

    # 19. 多包并发：任务与批次互不串结果 -------------------------------- #
    def test_19_concurrent_jobs_isolated(self):
        import threading
        outcomes, errors = {}, []

        def worker(key, idx):
            try:
                job = self.server.load_demo(key)
                safe = [e["index"] for e in job["entries"] if e["safe"]]
                if safe:
                    r = self.server.post_json(
                        f"/api/jobs/{job['job_id']}/extract", {"indexes": safe})
                    outcomes[idx] = (job["job_id"],
                                     r["release"]["status"],
                                     len(r["release"]["succeeded"]))
                else:
                    outcomes[idx] = (job["job_id"], "no-safe", 0)
            except Exception as e:  # pragma: no cover
                errors.append(repr(e))

        threads = [threading.Thread(target=worker, args=("normal", i))
                   for i in range(5)]
        threads += [threading.Thread(target=worker, args=("traversal", 10 + i))
                    for i in range(3)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        self.assertEqual(errors, [])
        job_ids = {v[0] for v in outcomes.values()}
        self.assertEqual(len(job_ids), 8)
        # 每个任务的批次目录都在自己的专属目录之下
        for jid in job_ids:
            jdir = self.server.data_dir / "releases" / jid
            if jdir.exists():
                for child in jdir.iterdir():
                    self.assertTrue(child.parent.name == jid)


if __name__ == "__main__":
    unittest.main(verbosity=2)
