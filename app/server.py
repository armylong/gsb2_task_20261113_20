"""基于标准库 http.server 的本地 HTTP 服务。

只绑定 127.0.0.1；上传采用流式 multipart 解析直接落盘到任务专属目录；
下载接口对批次归属与相对路径做双重校验，无法借此读取批次外文件。
"""
from __future__ import annotations

import json
import shutil
import threading
import zipfile
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse, parse_qs

from . import config
from .demo_builder import DEMOS, ensure_demos
from .extractor import iter_release_files, resolve_download_path, ExtractionError
from .jobs import InvalidState, manager
from .limits import LimitExceeded, Limits


class UploadError(Exception):
    pass


class _BodyReader:
    """对请求体做定长、分块读取，并支持跨块的分隔符扫描。"""

    def __init__(self, stream, length: int, chunk: int = 64 * 1024):
        self.stream = stream
        self.remaining = length
        self.chunk = chunk
        self.pending = b""

    def read_until(self, marker: bytes, max_bytes: int | None = None):
        """读到 marker 为止；返回 (marker 之前的数据, 是否命中 marker)。

        命中时 marker 本身被消费，不包含在返回数据里。
        """
        out = bytearray()
        while True:
            if not self.pending:
                self._fill()
            if not self.pending:
                return bytes(out), False
            idx = self.pending.find(marker)
            if idx >= 0:
                out.extend(self.pending[:idx])
                self.pending = self.pending[idx + len(marker):]
                return bytes(out), True
            # 保留 marker 长度-1 的尾部防止 marker 跨块
            keep = len(marker) - 1
            head, self.pending = self.pending[:-keep], self.pending[-keep:]
            out.extend(head)
            if max_bytes is not None and len(out) > max_bytes:
                raise UploadError("数据超过允许长度")
            if not self._fill() and not self.pending:
                return bytes(out), False

    def read_exact(self, n: int) -> bytes:
        """精确消费 n 个字节（先取 pending，再从底层流补齐）。"""
        out = bytearray()
        while len(out) < n:
            if not self.pending:
                if not self._fill():
                    break
            take = min(len(self.pending), n - len(out))
            out.extend(self.pending[:take])
            self.pending = self.pending[take:]
        return bytes(out)

    def _fill(self) -> bool:
        if self.remaining <= 0:
            return False
        n = min(self.chunk, self.remaining)
        data = self.stream.read(n)
        if not data:
            return False
        self.remaining -= len(data)
        self.pending += data
        return True


def parse_multipart(stream, content_length: int, boundary: bytes,
                    max_size: int, dest_path):
    """流式解析单文件 multipart 表单，文件内容直接写入 dest_path。

    返回普通字段字典；超过 max_size 立即中止，避免大包吃光磁盘。
    """
    reader = _BodyReader(stream, content_length)
    delim = b"--" + boundary
    fields: dict[str, str] = {}
    file_seen = False

    # 首个边界
    preamble, ok = reader.read_until(delim, max_bytes=1024)
    if not ok:
        raise UploadError("multipart 起始边界不正确")
    # 边界后应紧跟 \r\n
    tail, ok = reader.read_until(b"\r\n", max_bytes=4)
    if not ok:
        raise UploadError("multipart 边界后缺少换行")

    while True:
        # 读 part 头
        header_blob, ok = reader.read_until(b"\r\n\r\n", max_bytes=64 * 1024)
        if not ok:
            raise UploadError("multipart 部件头不完整")
        headers = {}
        for line in header_blob.decode("utf-8", errors="replace").split("\r\n"):
            if ":" in line:
                k, v = line.split(":", 1)
                headers[k.strip().lower()] = v.strip()
        name, filename = _parse_disposition(
            headers.get("content-disposition", ""))

        part_marker = b"\r\n" + delim
        if filename is not None:
            safe_name = filename.replace("\\", "/").split("/")[-1] or "upload.bin"
            written = 0
            with open(dest_path, "wb") as out:
                while True:
                    data, hit = reader.read_until(part_marker, max_bytes=max_size + 1)
                    out.write(data)
                    written += len(data)
                    if written > max_size:
                        raise UploadError(
                            f"上传体积超过服务端硬上限 {max_size} 字节")
                    if hit:
                        break
            fields["filename"] = safe_name
            file_seen = True
        else:
            data, hit = reader.read_until(part_marker, max_bytes=64 * 1024)
            if not hit:
                raise UploadError("multipart 字段数据不完整")
            if name:
                fields[name] = data.decode("utf-8", errors="replace")

        # 边界已被消费，下一段只有两种可能："--\r\n"(结束) 或 "\r\n"(下一部件)
        two = reader.read_exact(2)
        if two == b"--":
            break
        if two != b"\r\n":
            raise UploadError("multipart 边界后缀不正确")

    if not file_seen:
        try:
            dest_path.unlink(missing_ok=True)
        except OSError:
            pass
        raise UploadError("请求中没有文件字段")
    return fields


def _parse_disposition(header: str) -> tuple[str | None, str | None]:
    name = None
    filename = None
    for part in header.split(";"):
        part = part.strip()
        if part.startswith("name="):
            name = part[5:].strip('"')
        elif part.startswith("filename="):
            filename = part[9:].strip('"')
    return name, filename


class Handler(BaseHTTPRequestHandler):
    server_version = "SafeArchiveCheck/1.0"

    # ------------------------------------------------------------------ #
    def log_message(self, fmt, *args):
        # 安静模式：错误仍由异常处理记录到响应
        pass

    def _json(self, obj, status=HTTPStatus.OK):
        body = json.dumps(obj, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(body)

    def _error(self, message: str, status=HTTPStatus.BAD_REQUEST):
        self._json({"error": message}, status=status)

    # ------------------------------------------------------------------ #
    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path
        try:
            if path == "/" or path == "/index.html":
                return self._serve_static("index.html", "text/html; charset=utf-8")
            if path == "/app.js":
                return self._serve_static("app.js", "application/javascript; charset=utf-8")
            if path == "/styles.css":
                return self._serve_static("styles.css", "text/css; charset=utf-8")
            if path == "/api/demos":
                return self._json({"demos": DEMOS})
            if path == "/api/jobs":
                return self._json({"jobs": manager.list()})
            if path.startswith("/api/jobs/"):
                return self._job_get(path.split("/")[3], path)
            self._error("接口不存在", HTTPStatus.NOT_FOUND)
        except (BrokenPipeError, ConnectionResetError):
            pass
        except Exception as e:  # 最后防线：任何异常都不能让服务退出
            self._json({"error": f"服务器内部错误：{e}"}, HTTPStatus.INTERNAL_SERVER_ERROR)

    def do_POST(self):
        parsed = urlparse(self.path)
        path = parsed.path
        try:
            if path == "/api/jobs":
                return self._create_job()
            if path.startswith("/api/demos/") and path.endswith("/load"):
                return self._load_demo(path.split("/")[3])
            if path.startswith("/api/jobs/") and path.endswith("/extract"):
                return self._extract(path.split("/")[3])
            self._error("接口不存在", HTTPStatus.NOT_FOUND)
        except (BrokenPipeError, ConnectionResetError):
            pass
        except Exception as e:
            self._json({"error": f"服务器内部错误：{e}"}, HTTPStatus.INTERNAL_SERVER_ERROR)

    # ------------------------------------------------------------------ #
    def _serve_static(self, name: str, ctype: str):
        target = config.STATIC_DIR / name
        if not target.is_file():
            return self._error("页面资源缺失", HTTPStatus.NOT_FOUND)
        body = target.read_bytes()
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _create_job(self):
        ctype = self.headers.get("Content-Type", "")
        if not ctype.startswith("multipart/form-data"):
            return self._error("需要 multipart/form-data 上传")
        if "boundary=" not in ctype:
            return self._error("multipart 缺少 boundary")
        boundary = ctype.split("boundary=", 1)[1].strip().encode()
        length = int(self.headers.get("Content-Length", "0") or 0)
        if length <= 0:
            return self._error("请求体为空")
        if length > config.MAX_UPLOAD_BYTES + 1024 * 1024:
            return self._error("上传体积超过服务端硬上限",
                               HTTPStatus.REQUEST_ENTITY_TOO_LARGE)

        job = manager.create("unknown", "")
        job_dir = config.UPLOAD_DIR / job.job_id
        job_dir.mkdir(parents=True, exist_ok=True)
        dest = job_dir / "source.bin"
        try:
            fields = parse_multipart(
                self.rfile, length, boundary, config.MAX_UPLOAD_BYTES, dest)
        except UploadError as e:
            shutil.rmtree(job_dir, ignore_errors=True)
            return self._error(f"上传失败：{e}", HTTPStatus.BAD_REQUEST)

        original = fields.get("filename") or fields.get("name") or "upload.bin"
        job.original_name = original
        job.archive_path = str(dest)
        job._persist()

        # 限制参数随上传一起提交
        try:
            limits = Limits.from_request(fields)
        except LimitExceeded as e:
            return self._error(f"限制参数无效：{e.message}")

        def work():
            try:
                job.run_scan(limits)
            except LimitExceeded as e:
                job.state = "scan_failed"
                job.error = e.message
                job._persist()
            except Exception as e:
                job.state = "scan_failed"
                job.error = f"扫描异常：{e}"
                job._persist()

        threading.Thread(target=work, daemon=True).start()
        self._json({"job_id": job.job_id, "state": job.state})

    def _load_demo(self, key: str):
        paths = ensure_demos()
        if key not in paths:
            return self._error("演示包不存在", HTTPStatus.NOT_FOUND)
        demo_meta = next((d for d in DEMOS if d["key"] == key), None)
        job = manager.create(demo_meta["title"] + self._suffix(demo_meta["format"]),
                             str(paths[key]))
        raw_limits = parse_qs(urlparse(self.path).query).get("limits", [None])[0]
        try:
            limits = Limits.from_request(
                json.loads(raw_limits) if raw_limits else None)
        except (json.JSONDecodeError, LimitExceeded):
            limits = Limits.from_request(None)

        def work():
            try:
                job.run_scan(limits)
            except Exception as e:
                job.state = "scan_failed"
                job.error = f"扫描异常：{e}"
                job._persist()

        threading.Thread(target=work, daemon=True).start()
        self._json({"job_id": job.job_id, "state": job.state,
                    "demo": demo_meta})

    @staticmethod
    def _suffix(fmt: str) -> str:
        return ".tar.gz" if fmt == "tar" else ".zip"

    def _job_get(self, job_id: str, path: str):
        job = manager.get(job_id)
        if job is None:
            return self._error("任务不存在", HTTPStatus.NOT_FOUND)
        if path == f"/api/jobs/{job_id}":
            return self._json(job.to_dict())
        if path == f"/api/jobs/{job_id}/report":
            return self._json(job.report())
        if path == f"/api/jobs/{job_id}/download":
            return self._download_zip(job)
        if path.startswith(f"/api/jobs/{job_id}/files/"):
            rel = path[len(f"/api/jobs/{job_id}/files/"):]
            return self._download_file(job, rel)
        self._error("接口不存在", HTTPStatus.NOT_FOUND)

    def _extract(self, job_id: str):
        job = manager.get(job_id)
        if job is None:
            return self._error("任务不存在", HTTPStatus.NOT_FOUND)
        try:
            length = int(self.headers.get("Content-Length", "0"))
            payload = json.loads(self.rfile.read(length).decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            return self._error("请求体不是有效 JSON")
        indexes = payload.get("indexes", [])
        if not isinstance(indexes, list) or not all(isinstance(i, int) for i in indexes):
            return self._error("indexes 必须是整数数组")
        try:
            record = job.run_extract(indexes)
        except InvalidState as e:
            return self._error(str(e), HTTPStatus.CONFLICT)
        except ExtractionError as e:
            return self._json({"error": str(e), "state": job.state},
                              HTTPStatus.CONFLICT)
        self._json({"release": record, "state": job.state})

    # ------------------------------------------------------------------ #
    def _release_dir_for(self, job, release_id: str):
        for rec in reversed(job.releases):
            if rec["release_id"] == release_id and rec["status"] == "succeeded":
                rd = Path(rec["release_dir"])
                if not rd.is_dir():
                    return None
                # 批次目录必须位于本任务专属目录之下
                if config.RELEASES_DIR.resolve() not in rd.resolve().parents:
                    return None
                return rd
        return None

    def _download_zip(self, job):
        qs = parse_qs(urlparse(self.path).query)
        release_id = (qs.get("release_id") or [""])[0]
        release_dir = self._release_dir_for(job, release_id)
        if release_dir is None:
            return self._error("批次不存在或未成功释放", HTTPStatus.NOT_FOUND)

        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", "application/zip")
        self.send_header("Content-Disposition",
                         f'attachment; filename="{job.job_id}_{release_id}.zip"')
        self.end_headers()
        try:
            with zipfile.ZipFile(self.wfile, "w", zipfile.ZIP_DEFLATED) as zf:
                for abs_path, rel in iter_release_files(str(release_dir)):
                    zf.write(abs_path, arcname=rel)
        except (BrokenPipeError, ConnectionResetError):
            pass

    def _download_file(self, job, rel_name: str):
        from urllib.parse import unquote
        qs = parse_qs(urlparse(self.path).query)
        release_id = (qs.get("release_id") or [""])[0]
        release_dir = self._release_dir_for(job, release_id)
        if release_dir is None:
            return self._error("批次不存在或未成功释放", HTTPStatus.NOT_FOUND)
        rel_name = unquote(rel_name)
        target = resolve_download_path(str(release_dir), rel_name)
        if target is None:
            return self._error("文件不存在或路径非法", HTTPStatus.NOT_FOUND)
        body = target.read_bytes()
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", "application/octet-stream")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Content-Disposition",
                         f'attachment; filename="{target.name}"')
        self.end_headers()
        self.wfile.write(body)


def make_server() -> ThreadingHTTPServer:
    config.ensure_dirs()
    ensure_demos()
    restored = manager.load_from_disk()
    if restored:
        print(f"[启动] 已恢复 {restored} 个历史任务")

    class _Server(ThreadingHTTPServer):
        # 并发突发时加大连接队列，允许端口快速复用，请求线程随主进程退出
        request_queue_size = 128
        allow_reuse_address = True
        daemon_threads = True

    server = _Server((config.HOST, config.PORT), Handler)
    return server


def main():  # pragma: no cover
    server = make_server()
    print(f"压缩包安全检查工具已启动：http://{config.HOST}:{config.PORT}")
    print("仅监听本机回环地址；按 Ctrl+C 停止。")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n正在停止……")
        server.shutdown()
