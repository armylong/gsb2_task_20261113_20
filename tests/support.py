"""测试公共工具：独立数据目录启动服务、multipart 上传、轮询等待。"""
from __future__ import annotations

import json
import os
import sys
import tempfile
import threading
import time
import urllib.request
import uuid
from http.client import HTTPConnection
from pathlib import Path

# 确保从仓库根目录导入 app 包
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))


class TestServer:
    """在临时数据目录上启动真实 HTTP 服务（监听 127.0.0.1 随机端口）。"""

    def __init__(self):
        self.tmpdir = tempfile.mkdtemp(prefix="safearch_test_")
        os.environ["SAFEARCH_DATA_DIR"] = self.tmpdir
        os.environ["SAFEARCH_PORT"] = "0"  # 由系统分配端口
        # 延迟导入，确保环境变量先生效
        from app import config
        config.DATA_DIR = Path(self.tmpdir)
        config.UPLOAD_DIR = config.DATA_DIR / "uploads"
        config.JOBS_DIR = config.DATA_DIR / "jobs"
        config.RELEASES_DIR = config.DATA_DIR / "releases"
        config.DEMO_DIR = config.DATA_DIR / "demos"
        config.ensure_dirs()

        from app.server import Handler
        from http.server import ThreadingHTTPServer

        class _Server(ThreadingHTTPServer):
            request_queue_size = 128
            allow_reuse_address = True
            daemon_threads = True

        self.httpd = _Server(("127.0.0.1", 0), Handler)
        from app.demo_builder import ensure_demos
        ensure_demos()
        self.port = self.httpd.server_address[1]
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()

    def stop(self):
        self.httpd.shutdown()
        self.httpd.server_close()

    # ------------------------------------------------------------------ #
    def url(self, path: str) -> str:
        return f"http://127.0.0.1:{self.port}{path}"

    def get_json(self, path: str, retries: int = 3):
        last = None
        for attempt in range(retries):
            try:
                with urllib.request.urlopen(self.url(path), timeout=15) as r:
                    return json.loads(r.read().decode("utf-8"))
            except (ConnectionResetError, ConnectionRefusedError) as e:
                last = e
                time.sleep(0.1 * (attempt + 1))
        raise last

    def post_json(self, path: str, payload: dict, retries: int = 3):
        last = None
        for attempt in range(retries):
            req = urllib.request.Request(
                self.url(path),
                data=json.dumps(payload).encode("utf-8"),
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            try:
                with urllib.request.urlopen(req, timeout=15) as r:
                    return json.loads(r.read().decode("utf-8"))
            except urllib.error.HTTPError as e:
                # 业务错误响应（4xx/5xx）是确定结果，不重试
                return json.loads(e.read().decode("utf-8")), e.code
            except (ConnectionResetError, ConnectionRefusedError) as e:
                last = e
                time.sleep(0.1 * (attempt + 1))
        raise last

    def get_raw(self, path: str):
        try:
            with urllib.request.urlopen(self.url(path), timeout=15) as r:
                return r.status, r.read()
        except urllib.error.HTTPError as e:
            return e.code, e.read()

    def upload(self, archive_bytes: bytes, filename: str,
               limits: dict | None = None):
        """手写 multipart/form-data 上传。"""
        boundary = "----safearchtest" + uuid.uuid4().hex
        body = bytearray()
        fields = limits or {}
        for k, v in fields.items():
            body.extend(f"--{boundary}\r\n".encode())
            body.extend(f'Content-Disposition: form-data; name="{k}"\r\n\r\n'.encode())
            body.extend(str(v).encode())
            body.extend(b"\r\n")
        body.extend(f"--{boundary}\r\n".encode())
        body.extend(
            f'Content-Disposition: form-data; name="file"; filename="{filename}"\r\n'
            .encode())
        body.extend(b"Content-Type: application/octet-stream\r\n\r\n")
        body.extend(archive_bytes)
        body.extend(f"\r\n--{boundary}--\r\n".encode())

        conn = HTTPConnection("127.0.0.1", self.port, timeout=15)
        conn.request("POST", "/api/jobs", bytes(body),
                     {"Content-Type": f"multipart/form-data; boundary={boundary}"})
        resp = conn.getresponse()
        data = json.loads(resp.read().decode("utf-8"))
        conn.close()
        return resp.status, data

    def wait_state(self, job_id: str, timeout: float = 20.0) -> dict:
        """轮询直到任务离开扫描/释放中间态。"""
        deadline = time.time() + timeout
        while time.time() < deadline:
            job = self.get_json(f"/api/jobs/{job_id}")
            if job["state"] not in ("uploaded", "scanning", "extracting"):
                return job
            time.sleep(0.15)
        raise AssertionError(f"任务 {job_id} 超时未结束")

    def load_demo(self, key: str, limits: dict | None = None) -> dict:
        qs = ""
        if limits:
            qs = "?limits=" + urllib.parse.quote(json.dumps(limits))
        data = self.post_json(f"/api/demos/{key}/load{qs}", {})
        if isinstance(data, tuple):
            raise AssertionError(f"演示包加载失败：{data}")
        return self.wait_state(data["job_id"])

    # ------------------------------------------------------------------ #
    @property
    def data_dir(self) -> Path:
        return Path(self.tmpdir)
