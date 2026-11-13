"""风险代码、中文说明与严重级别定义。"""
from __future__ import annotations

# 严重级别
DANGER = "danger"   # 危险：绝对不能释放
WARN = "warn"       # 风险：默认不可释放
INFO = "info"       # 提示：不影响安全性（如嵌套压缩包）

# 风险代码 -> (严重级别, 中文模板)
RISK_CATALOG: dict[str, tuple[str, str]] = {
    "ABS_PATH":          (DANGER, "绝对路径条目，解压会绕过目标目录直接写入系统位置"),
    "DRIVE_PATH":        (DANGER, "Windows 盘符路径（如 C:），无法安全映射到释放目录"),
    "BACKSLASH_PATH":    (WARN,   "名称含反斜杠，可能用于绕过正斜杠写法的路径检查"),
    "TRAVERSAL":         (DANGER, "目录穿越：名称包含上级目录跳转（..），规范化后会写到目标目录之外"),
    "EXACT_DUPLICATE":   (DANGER, "规范化后与其他条目重名，释放会发生覆盖"),
    "CASE_COLLISION":    (DANGER, "仅大小写不同但落到同一位置，在不区分大小写的文件系统上会互相覆盖"),
    "TYPE_CONFLICT":     (DANGER, "文件与目录在同一路径上冲突，释放顺序不同会得到不同结果"),
    "SYMLINK_ESCAPE":    (DANGER, "符号链接指向释放目录之外，配合后续文件可写到任意位置"),
    "SYMLINK_INSIDE":    (WARN,   "符号链接条目本身不会被释放，链接会改变后续文件的真实落点"),
    "LINK_FOLLOW_ESCAPE": (DANGER, "该条目借道符号链接写入，解析后落到释放目录之外"),
    "LINK_FOLLOW_INSIDE": (WARN,  "该条目借道包内符号链接写入，链接不释放时其落点无法保证"),
    "HARDLINK_ESCAPE":   (DANGER, "硬链接目标指向释放目录之外"),
    "HARDLINK":          (WARN,   "硬链接条目不会被释放"),
    "SPECIAL_FILE":      (DANGER, "字符设备/块设备/FIFO 等特殊文件，不允许在释放目录创建"),
    "UNSUPPORTED_TYPE":  (WARN,   "不支持的条目类型，不会被释放"),
    "NESTED_ARCHIVE":    (INFO,   "嵌套压缩包：仅展示，不会自动递归解包，需单独检查后再决定"),
    "DECLARED_TOO_BIG":  (DANGER, "声明大小超过单文件释放大小上限"),
    "TOTAL_DECLARED":    (DANGER, "按声明大小累计超过总释放大小上限"),
    "READ_TOO_BIG":      (DANGER, "实际读取超过单文件释放大小上限，已中止读取"),
    "READ_TOTAL":        (DANGER, "实际累计读取超过总释放大小上限，已中止扫描"),
    "RATIO_EXCEEDED":    (DANGER, "实际压缩比例超过上限（疑似压缩炸弹），已中止扫描"),
    "READ_ERROR":        (DANGER, "成员内容读取失败，压缩包可能已损坏"),
    "TOO_MANY_ENTRIES":  (DANGER, "条目数超过上限，已中止扫描，后续条目未检查"),
}

# 即使没有显式风险，也一律禁止释放的条目类型
BLOCKED_TYPES = {"symlink", "hardlink", "special", "other"}

NESTED_ARCHIVE_SUFFIXES = (".zip", ".tar", ".tar.gz", ".tgz", ".tar.bz2", ".tar.xz")
