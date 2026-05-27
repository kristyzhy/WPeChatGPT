"""
WPeGPT — 配置文件
配置AI模型和WPeServer参数。
"""

# ── AI模型 ──
MODEL = ""

# ── API KEY ──
API_KEY = ""

# ── API URL ──
API_BASE_URL = ""

# ── Language ──
# True = 中文, False = English
ZH_CN = True

# ── 正向代理 ──
# 例如: "http://127.0.0.1:7890"，不需要则留空
FORWARD_PROXY = ""

# 并发工作线程数
MAX_WORKERS = 5

# ── 默认自动分析模式 ──
# "full"  = 全量功能分析
# "light" = 轻量功能分析（仅关键路径）
# "vuln"  = 漏洞分析（仅关键路径）
ANALYSIS_MODE = "light"

# ── 关键路径分析数量 ──
# Phase 2从调用树可达函数中选取Top N进行深度分析
# 按函数分值排序后选取，值越大覆盖越广但耗时越长
MAX_CRITICAL_LIGHT = 50
MAX_CRITICAL_FULL = 30
MAX_CRITICAL_VULN = 30

# ── 全量扫描数量 ──
# Phase 3对未被关键路径覆盖的函数进行快速扫描
# 按可疑度排序后选取，0表示不限制
MAX_FULL_SCAN = 200