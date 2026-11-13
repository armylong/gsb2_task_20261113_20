#!/usr/bin/env python3
"""本地压缩包安全检查工具启动入口。

用法：
    python3 run.py
可选环境变量：
    SAFEARCH_PORT=9000      端口（默认 8765）
    SAFEARCH_DATA_DIR=路径  数据目录（默认 ./data）
"""
import os
import sys

# -I 隔离模式下脚本目录不会自动加入 sys.path，这里显式补上，
# 同时避免从当前工作目录加载任何同名模块。
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from app.server import main

if __name__ == "__main__":
    main()
