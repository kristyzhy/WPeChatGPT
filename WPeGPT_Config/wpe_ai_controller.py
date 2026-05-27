#!/usr/bin/env python3
"""
WPeGPT AI Controller — 外部AI控制器，通过TCP驱动IDA自动化分析

用法:
    python wpe_ai_controller.py [--mode full|light|vuln] [--output DIR] [--log-file PATH]
"""

import argparse
import json
import os
import re
import tempfile
import socket
import sys
import time
import threading
import traceback
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed


# Windows: FreeConsole + AllocConsole 创建独立窗口
# Linux/macOS: 父进程已通过终端模拟器启动，无需额外操作
if __name__ == "__main__":
    if sys.platform == "win32":
        try:
            import ctypes
            from ctypes import wintypes
            ctypes.windll.kernel32.FreeConsole()
            ctypes.windll.kernel32.AllocConsole()
            h = ctypes.windll.kernel32.GetStdHandle(-11)  # STD_OUTPUT_HANDLE
            ctypes.windll.kernel32.SetConsoleScreenBufferSize(h, wintypes._COORD(120, 9999))
            _conout = open("CONOUT$", "w", encoding="utf-8")
            _conin = open("CONIN$", "r", encoding="utf-8")
            sys.stdout = _conout
            sys.stderr = _conout
            sys.stdin = _conin
            ctypes.windll.kernel32.SetConsoleTitleW("WPeGPT AI Controller")
        except Exception:
            pass


# 端口发现文件（包含host、port、plugin_dir）
# 多实例隔离：文件名包含PID，控制器扫描所有匹配文件并尝试连接
_PORT_FILE_PATTERN = os.path.join(tempfile.gettempdir(), ".wpe_server_port_*")


def _discover_port_files():
    """扫描所有端口文件，返回按修改时间排序的(文件路径, 数据)列表"""
    import glob
    files = glob.glob(_PORT_FILE_PATTERN)
    results = []
    for f in files:
        try:
            with open(f, "r") as fp:
                data = json.load(fp)
                results.append((f, data))
        except Exception:
            pass
    # 按修改时间降序排列，优先连接最新的实例
    results.sort(key=lambda x: os.path.getmtime(x[0]), reverse=True)
    return results


def discover_server_port():
    """从端口文件发现服务器端口，优先连接最新的实例"""
    for _, data in _discover_port_files():
        host = data.get("host", "127.0.0.1")
        port = data.get("port", 18478)
        # 验证进程是否存活
        pid = data.get("pid")
        if pid is not None:
            try:
                if sys.platform == "win32":
                    import ctypes
                    result = ctypes.windll.kernel32.OpenProcess(0x100000, 0, pid)
                    if result:
                        ctypes.windll.kernel32.CloseHandle(result)
                        return host, port
                else:
                    os.kill(pid, 0)  # 信号0 = 检查进程是否存在
                    return host, port
            except (OSError, AttributeError):
                continue
        else:
            return host, port
    return DEFAULT_HOST, 18478


# 从config.py加载配置
_config_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "WPeGPT_Config")
if _config_dir not in sys.path:
    sys.path.insert(0, _config_dir)
import config

# 从config读取的默认值，可通过CLI参数覆盖
DEFAULT_HOST = "127.0.0.1"
DEFAULT_MODEL = config.MODEL
DEFAULT_BASE_URL = config.API_BASE_URL
DEFAULT_API_KEY = config.API_KEY
DEFAULT_ANALYSIS_MODE = config.ANALYSIS_MODE
DEFAULT_MAX_WORKERS = config.MAX_WORKERS
DEFAULT_MAX_CRITICAL = {
    "light": getattr(config, "MAX_CRITICAL_LIGHT", 50),
    "full": getattr(config, "MAX_CRITICAL_FULL", 30),
    "vuln": getattr(config, "MAX_CRITICAL_VULN", 20),
}
DEFAULT_MAX_FULL_SCAN = getattr(config, "MAX_FULL_SCAN", 200)
ZH_CN = getattr(config, "ZH_CN", True)


class TeeWriter:
    """同时写入stdout和文件的输出流，用于实时日志转发"""
    def __init__(self, filepath):
        self.file = open(filepath, "w", encoding="utf-8")
        self.stdout = sys.stdout

    def write(self, text):
        self.stdout.write(text)
        self.stdout.flush()
        self.file.write(text)
        self.file.flush()

    def flush(self):
        self.stdout.flush()
        self.file.flush()

    def close(self):
        self.file.close()


# ── 双语标签 ──
_LABELS = {
    "zh": {
        "report_title": "WPeGPT AI Controller — 二进制分析报告",
        "phase0": "阶段0: 连接IDA",
        "phase1": "阶段1: 全局扫描",
        "phase2_explain": "阶段2: 关键路径功能分析 (并发)",
        "phase2_vuln": "阶段2: 关键路径漏洞分析 (并发)",
        "phase3": "阶段3: 全量函数扫描 (并发)",
        "getting_funcs": "[*] 获取函数列表...",
        "getting_strings": "[*] 获取字符串...",
        "getting_calltree": "[*] 获取调用树...",
        "found_funcs": "找到 {count} 个函数",
        "found_strings": "找到 {count} 条字符串",
        "found_calls": "找到 {count} 个调用关系",
        "ai_unavail": "[AI不可用: 代理返回错误]",
        "cannot_decompile": "[!] 无法反编译 {name}",
        "cannot_connect": "[{wid}] 无法连接IDA",
        "critical_path_info": "关键路径上 {total} 个用户函数（跳过 {skip} 个系统函数），将分析 {max} 个",
        "remaining_info": "剩余 {count} 个用户函数待快速扫描（跳过 {skip} 个系统函数）",
        "empty_analysis": "[{wid}] [!] {name} 分析返回空，数据键: {keys}",
        "analysis_fail_msg": "[{wid}] [!] {name} 分析失败: {err}",
        "no_taskid": "[{wid}] [!] {name} 未返回task_id",
        "phase3_done": "阶段3完成，耗时 {time:.1f}s",
        "generating_report": "生成分析报告",
        "json_report": "JSON报告: {path}",
        "md_report": "Markdown报告: {path}",
        "func_analysis": "**功能分析:**",
        "phase1_label": "阶段1 (全局扫描)",
        "phase2_label": "阶段2 (关键路径)",
        "phase3_label": "阶段3 (全量扫描)",
        "phase3_skip": "跳过",
        "total_analyzed": "分析函数总数",
        "suspicious_label": "可疑函数",
        "suspicious_label_vuln": "漏洞风险函数",
        "stdlib_skip": "跳过 {count} 个系统函数",
        "report_footer": "*由 WPeGPT AI Controller 生成*",
        "suspicious_section": "## 可疑函数",
        "suspicious_section_vuln": "## 漏洞风险函数",
        "purpose_section": "## 程序目的分析",
        "critical_section": "## 关键路径分析详情",
        "stats_section": "## 统计信息",
        "no_api_key": "[!] config.py中未找到API密钥，AI引擎将不可用。",
        "discovery": "[*] 发现IDA服务器端口: {host}:{port}",
        "connect_fail": "[!] 无法连接IDA，请确认WPeChatGPT插件已加载。",
        "connect_ok": "[+] IDA连接成功!",
        "shutdown": "[*] 正在关闭IDA服务器...",
        "user_interrupt": "\n[!] 用户中断。",
        "analysis_fail": "\n[!] 分析失败: {err}",
    },
    "en": {
        "report_title": "WPeGPT AI Controller — Binary Analysis Report",
        "phase0": "Phase 0: Connecting to IDA",
        "phase1": "Phase 1: Global Scan",
        "phase2_explain": "Phase 2: Critical Path Analysis (concurrent)",
        "phase2_vuln": "Phase 2: Critical Path Vuln Analysis (concurrent)",
        "phase3": "Phase 3: Full Function Scan (concurrent)",
        "getting_funcs": "[*] Fetching function list...",
        "getting_strings": "[*] Fetching strings...",
        "getting_calltree": "[*] Fetching call tree...",
        "found_funcs": "Found {count} functions",
        "found_strings": "Found {count} strings",
        "found_calls": "Found {count} call relationships",
        "ai_unavail": "[AI unavailable: proxy returned error]",
        "cannot_decompile": "[!] Cannot decompile {name}",
        "cannot_connect": "[{wid}] Cannot connect to IDA",
        "critical_path_info": "{total} user functions on critical path ({skip} stdlib skipped), will analyze {max}",
        "remaining_info": "{count} remaining user functions for quick scan ({skip} stdlib skipped)",
        "empty_analysis": "[{wid}] [!] {name} returned empty analysis, data keys: {keys}",
        "analysis_fail_msg": "[{wid}] [!] {name} analysis failed: {err}",
        "no_taskid": "[{wid}] [!] {name} did not return task_id",
        "phase3_done": "Phase 3 completed, elapsed {time:.1f}s",
        "generating_report": "Generating analysis report",
        "json_report": "JSON report: {path}",
        "md_report": "Markdown report: {path}",
        "func_analysis": "**Function Analysis:**",
        "phase1_label": "Phase 1 (Global Scan)",
        "phase2_label": "Phase 2 (Critical Path)",
        "phase3_label": "Phase 3 (Full Scan)",
        "phase3_skip": "skipped",
        "total_analyzed": "Total functions analyzed",
        "suspicious_label": "Suspicious functions",
        "suspicious_label_vuln": "Vulnerability-risk functions",
        "stdlib_skip": "{count} stdlib functions skipped",
        "report_footer": "*Generated by WPeGPT AI Controller*",
        "suspicious_section": "## Suspicious Functions",
        "suspicious_section_vuln": "## Vulnerability-Risk Functions",
        "purpose_section": "## Binary Purpose Analysis",
        "critical_section": "## Critical Path Analysis Details",
        "stats_section": "## Statistics",
        "no_api_key": "[!] No API key found in config.py, AI engine will be unavailable.",
        "discovery": "[*] Discovered IDA server port: {host}:{port}",
        "connect_fail": "[!] Cannot connect to IDA, please ensure WPeChatGPT plugin is loaded.",
        "connect_ok": "[+] IDA connected successfully!",
        "shutdown": "[*] Shutting down IDA server...",
        "user_interrupt": "\n[!] User interrupted.",
        "analysis_fail": "\n[!] Analysis failed: {err}",
    },
}

def _L(key, **kwargs):
    lang = "zh" if ZH_CN else "en"
    text = _LABELS[lang].get(key, key)
    if kwargs:
        try:
            text = text.format(**kwargs)
        except KeyError:
            pass
    return text


class IDAConnection:
    """TCP客户端，与IDA内的WPeServer通信"""

    def __init__(self, host=DEFAULT_HOST, port=18478):
        self.host = host
        self.port = port
        self.sock = None
        self._lock = threading.Lock()
        self._id_counter = 0
        self._buffer = ""

    def connect(self, timeout=10):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.settimeout(timeout)
        try:
            self.sock.connect((self.host, self.port))
            self.sock.settimeout(None)
            self._buffer = ""
            return True
        except Exception as e:
            print(f"[!] Failed to connect to IDA at {self.host}:{self.port}: {e}")
            return False

    def close(self):
        if self.sock:
            try:
                self.sock.close()
            except:
                pass
            self.sock = None

    def _reconnect(self, timeout=5):
        """尝试重新连接，用于处理连接断开"""
        print(f"[*] 尝试重新连接 {self.host}:{self.port}...")
        self.close()
        return self.connect(timeout=timeout)

    def _recv_until_newline(self):
        while "\n" not in self._buffer:
            try:
                data = self.sock.recv(8192)
                if not data:
                    return None
                self._buffer += data.decode("utf-8")
            except socket.timeout:
                return None
            except Exception as e:
                return None

        line, self._buffer = self._buffer.split("\n", 1)
        return line.strip()

    def send_command(self, command, params=None, timeout=None, reconnect=True):
        with self._lock:
            self._id_counter += 1
            msg_id = self._id_counter
            msg = json.dumps({"id": msg_id, "command": command, "params": params or {}}) + "\n"
            try:
                self.sock.sendall(msg.encode("utf-8"))
            except Exception:
                # 发送失败，尝试重连
                if reconnect:
                    print(f"[!] 发送失败，尝试重连 {self.host}:{self.port}")
                    if self._reconnect():
                        return self.send_command(command, params, timeout, reconnect=False)
                return {"status": "error", "data": {"message": "Connection lost"}}

            # Wait for response with matching ID
            deadline = time.time() + (timeout or 120)
            while time.time() < deadline:
                line = self._recv_until_newline()
                if line is None:
                    # 接收失败，尝试重连
                    if reconnect:
                        print(f"[!] 接收超时/失败，尝试重连 {self.host}:{self.port}")
                        if self._reconnect():
                            return self.send_command(command, params, timeout, reconnect=False)
                    return {"status": "error", "data": {"message": "Connection lost"}}
                try:
                    resp = json.loads(line)
                    if resp.get("_id") == msg_id:
                        return resp
                except json.JSONDecodeError:
                    continue

            return {"status": "error", "data": {"message": f"Command '{command}' timed out"}}


class AIEngine:
    """AI分析引擎"""

    def __init__(self, api_key, model=DEFAULT_MODEL, base_url=DEFAULT_BASE_URL):
        self.model = model
        try:
            import openai
            import httpx
            if base_url:
                self.client = openai.OpenAI(base_url=base_url, api_key=api_key)
            else:
                self.client = openai.OpenAI(api_key=api_key)
            self.available = True
        except ImportError:
            print("[!] openai package not installed. AI orchestration disabled.")
            print("    Install with: pip install openai httpx")
            self.available = False
            self.client = None

    def query(self, prompt, max_tokens=4096):
        if not self.available:
            return "AI engine not available."
        try:
            response = self.client.chat.completions.create(
                model=self.model,
                messages=[{"role": "user", "content": prompt}],
                max_tokens=max_tokens,
                timeout=180,
            )
            return response.choices[0].message.content or ""
        except Exception as e:
            print(f"[!] AI query failed: {e}")
            return f"[AI error: {e}]"


# ── 标准库/系统函数过滤集 ──
_STDLIB_FUNCTIONS = {
    # Memory management
    "malloc", "free", "calloc", "realloc", "memalign", "aligned_alloc",
    "memset", "memcpy", "memmove", "memcmp", "mmap", "munmap", "mprotect",
    # String operations
    "strlen", "strcat", "strncat", "strncpy", "strncmp", "strchr", "strrchr",
    "strstr", "strtok", "strtok_r", "strdup", "strndup", "strcpy", "strcmp",
    "strerror", "strerror_r", "strtol", "strtoul", "strtoll", "strtoull",
    "strtod", "strtof", "strspn", "strcspn", "strpbrk",
    "strnlen", "strcoll", "strxfrm",
    "strncpy", "strrchr",
    "wcscpy", "wcsncpy", "wcslen", "wcscmp", "wcsnrtombs", "mbsrtowcs",
    "wcscat", "wcsncmp", "wcsncpy", "wcstol", "wcstoul", "wcschr", "wcsrchr",
    "wcsnlen", "wmemcpy", "wmemmove", "wmemcmp", "wmemchr",
    "wcscpy_s", "wmemcpy_s", "wcsncpy_s", "wcscat_s", "wcsncat_s",
    # File I/O
    "fopen", "fclose", "fread", "fwrite", "fgets", "fputs", "fseek",
    "fseeko", "ftell", "rewind", "fflush", "feof", "ferror", "clearerr",
    "fgetc", "getc", "getchar", "putc", "putchar", "puts", "gets",
    "popen", "pclose", "tmpfile", "tmpnam", "tmpnam_r", "setvbuf",
    "setbuf", "fileno", "fdopen", "freopen", "fgetpos", "fsetpos",
    "fprintf", "fscanf", "printf", "scanf", "sprintf", "sscanf",
    "snprintf", "vprintf", "vfprintf", "vsprintf", "vsnprintf",
    "fread_unlocked", "fwrite_unlocked", "getc_unlocked", "getchar_unlocked",
    "fflush_unlocked", "flockfile", "funlockfile", "ftrylockfile",
    "fread_s", "fwrite_s", "fopen_s", "fclose_s",
    # Low-level I/O
    "open", "close", "read", "write", "lseek", "creat", "dup", "dup2",
    "access", "unlink", "link", "symlink", "chmod", "chown", "fchown",
    "fchmod", "stat", "fstat", "lstat", "mkdir", "rmdir", "readlink",
    "fsync", "ftruncate", "truncate", "pipe", "isatty", "tcgetattr", "tcsetattr",
    # Network
    "socket", "bind", "listen", "accept", "connect", "send", "recv",
    "sendto", "recvfrom", "sendmsg", "recvmsg", "setsockopt", "getsockopt",
    "shutdown", "getsockname", "getpeername",
    "inet_addr", "inet_ntoa", "inet_ntop", "inet_pton", "inet_aton",
    "htonl", "htons", "ntohl", "ntohs",
    "gethostbyname", "gethostbyaddr", "getaddrinfo", "freeaddrinfo",
    "gethostname", "gethostbyname_r", "gai_strerror",
    # Process / system
    "fork", "execve", "execvp", "execv", "execl", "execlp", "system",
    "wait", "waitpid", "wait4", "exit", "_exit", "abort", "atexit",
    "getpid", "getppid", "getuid", "geteuid", "getgid", "getegid",
    "setsid", "setuid", "setgid", "chroot", "alarm", "sleep", "usleep",
    "gettimeofday", "time", "clock", "clock_gettime", "nanosleep",
    "getenv", "setenv", "unsetenv", "putenv",
    # Signals
    "signal", "sigaction", "sigprocmask", "sigemptyset", "sigaddset",
    "sigdelset", "sigfillset", "sigismember", "sigpending", "sigsuspend",
    "raise", "kill", "tkill", "rt_sigaction", "rt_sigprocmask",
    # Threading
    "pthread_create", "pthread_join", "pthread_exit", "pthread_cancel",
    "pthread_mutex_init", "pthread_mutex_destroy", "pthread_mutex_lock",
    "pthread_mutex_unlock", "pthread_mutex_trylock",
    "pthread_cond_init", "pthread_cond_destroy", "pthread_cond_wait",
    "pthread_cond_signal", "pthread_cond_broadcast",
    "pthread_attr_init", "pthread_attr_destroy", "pthread_attr_setdetachstate",
    "pthread_detach", "pthread_self", "pthread_equal",
    "pthread_rwlock_init", "pthread_rwlock_destroy", "pthread_rwlock_rdlock",
    "pthread_rwlock_wrlock", "pthread_rwlock_unlock",
    "pthread_once", "pthread_atfork",
    "pthread_return_0", "pthread_dummy",
    # Ctype / locale
    "isalnum", "isalpha", "iscntrl", "isdigit", "isgraph", "islower",
    "isprint", "ispunct", "isspace", "isupper", "isxdigit",
    "tolower", "toupper", "toascii",
    "setlocale", "localeconv", "call_wsetlocale",
    # Math
    "sqrt", "pow", "exp", "log", "log10", "sin", "cos", "tan",
    "asin", "acos", "atan", "atan2", "ceil", "floor", "round", "fabs",
    "fmod", "ldexp", "frexp", "modf", "hypot", "erf", "tgamma", "lgamma",
    "powf", "sqrtf", "sinf", "cosf", "tanf", "logf", "expf", "ceilf", "floorf",
    "fegetenv", "fesetenv", "feholdexcept", "fegetround", "fesetround",
    "feclearexcept", "fetestexcept", "feupdateenv",
    # Random
    "rand", "srand", "random", "srandom", "rand_cmwc", "drand48",
    "initstate", "initstate_r", "setstate", "setstate_r", "init_rand",
    # Time
    "asctime", "ctime", "gmtime", "localtime", "mktime", "strftime",
    "strptime", "difftime", "tzset",
    # Misc libc internals
    "__libc_start_main", "__libc_csu_init", "__libc_csu_fini",
    "__ctype_b_loc", "__ctype_tolower_loc", "__ctype_toupper_loc",
    "__stack_chk_fail", "__gmon_start__", "_ITM_deregisterTMCloneTable",
    "_ITM_registerTMCloneTable", "__cxa_finalize", "__cxa_atexit",
    "_Jv_RegisterClasses", "_fini", "_init", "__do_global_dtors_aux",
    "_fp_hw", "_fp_out_narrow", "_fp_hw_probe",
    "_init_proc", "_term_proc", "_stdio_init", "_stdio_term", "_fpinit",
    "__uClibc_main",
    # MSVC CRT startup / process lifecycle
    "StartAddress", "MainAddress", "WinMain", "wWinMain",
    "tidy_global", "cleanup", "initialize_c", "init_c",
    "TopLevelExceptionFilter", "UnhandledExceptionFilter",
    "_CxxThrowException", "__CxxExceptionFilter",
    "_errno", "__errno", "_GetErrno",
    "terminate", "_onexit", "_cexit",
    "memmove_s", "memcpy_s", "memcpy_repmovs", "memset_repmovs",
    # C++ demangled helpers
    "__gxx_personality_v0", "__cxa_begin_catch", "__cxa_end_catch",
    "__cxa_throw", "__cxa_rethrow", "__cxa_call_unexpected",
    # MSVC CRT (单下划线前缀)
    "_memset", "_memcpy", "_memmove", "_memcmp",
    "_strlen", "_strcmp", "_strncmp", "_strcpy", "_strncpy",
    "_strcat", "_strncat", "_strchr", "_strrchr", "_strstr",
    "_wcslen", "_wcscpy", "_wcsncpy", "_wcscmp",
    "_mbslen", "_mbscpy", "_mbscmp",
    "_fopen", "_fclose", "_fread", "_fwrite", "_fgets", "_fputs",
    "_fprintf", "_fscanf", "_printf", "_scanf", "_sprintf", "_sscanf",
    "_snprintf", "_vsnprintf", "_vprintf", "_vfprintf",
    "_malloc", "_free", "_calloc", "_realloc",
    "_exit", "_getenv", "_setenv", "_putenv",
    "_system", "_popen", "_pclose",
    "_open", "_close", "_read", "_write", "_lseek",
    "_creat", "_access", "_unlink", "_mkdir", "_rmdir",
    "_stat", "_fstat", "_lstat",
    "_getcwd", "_chdir",
    "_atoi", "_atof", "_atol", "_atoll",
    "_strtod", "_strtol", "_strtoul", "_strtoll", "_strtoull",
    "_tolower", "_toupper", "_isalpha", "_isdigit", "_isalnum",
    "_isupper", "_islower", "_isspace", "_ispunct", "_isprint",
    "_iscntrl", "_isxdigit", "_isgraph",
    "_towlower", "_towupper",
    "_abs", "_labs", "_llabs",
    "_ftime", "_time", "_clock",
    "_beginthread", "_beginthreadex", "_endthread", "_endthreadex",
    "_lock", "_unlock",
    "_CrtDumpMemoryLeaks", "_CrtSetReportMode",
    # Other common
    "getopt", "getopt_long", "getopt_long_only",
    "basename", "dirname", "realpath",
    "qsort", "bsearch", "abs", "labs", "llabs",
    "atof", "atoi", "atol", "atoll",
    "perror", "__errno_location",
    "dlerror", "dlopen", "dlsym", "dlclose",
    "ioctl", "fcntl", "poll", "select",
    "chdir", "getcwd", "umask",
    "sbrk", "brk",
    "longjmp", "setjmp", "sigsetjmp", "siglongjmp",
    "bzero", "bcopy", "index", "rindex",
}

# ── Windows API ──
_WIN_API_FUNCTIONS = {
    # ── Kernel32 ──
    "CreateFileW", "CreateFileA", "CloseHandle",
    "ReadFile", "WriteFile", "GetFileSize", "SetFilePointer",
    "GetTempPathW", "GetTempPathA", "GetTempFileNameW", "GetTempFileNameA",
    "GetModuleHandleW", "GetModuleHandleA", "GetModuleHandleExW", "GetModuleHandleExA",
    "GetProcAddress", "LoadLibraryW", "LoadLibraryA", "LoadLibraryExW", "LoadLibraryExA",
    "FreeLibrary", "GetModuleFileNameW", "GetModuleFileNameA",
    "CreateProcessW", "CreateProcessA", "ExitProcess", "TerminateProcess",
    "GetCurrentProcess", "GetCurrentProcessId", "GetCurrentThread", "GetCurrentThreadId",
    "GetStartupInfoW", "GetStartupInfoA", "GetCommandLineW", "GetCommandLineA",
    "GetSystemInfo", "GetVersion", "GetVersionExW", "GetVersionExA",
    "GetTickCount", "GetTickCount64", "QueryPerformanceCounter", "QueryPerformanceFrequency",
    "Sleep", "SleepEx", "GetSystemTime", "GetLocalTime", "SystemTimeToFileTime",
    "GetLastError", "SetLastError",
    "HeapAlloc", "HeapFree", "HeapCreate", "HeapDestroy", "HeapReAlloc",
    "VirtualAlloc", "VirtualFree", "VirtualProtect", "VirtualQuery",
    "VirtualAllocEx", "VirtualFreeEx", "VirtualProtectEx",
    "SetDefaultDllDirectories", "SetDllDirectoryW", "SetDllDirectoryA",
    "OutputDebugStringW", "OutputDebugStringA",
    "IsDebuggerPresent", "CheckRemoteDebuggerPresent",
    "CreateMutexW", "CreateMutexA", "OpenMutexW", "ReleaseMutex",
    "CreateEventW", "CreateEventA", "SetEvent", "ResetEvent",
    "CreateThread", "CreateRemoteThread", "ExitThread",
    "WaitForSingleObject", "WaitForMultipleObjects",
    "GetThreadContext", "SetThreadContext", "ResumeThread", "SuspendThread",
    "OpenProcess", "ReadProcessMemory", "WriteProcessMemory",
    "CreateToolhelp32Snapshot", "Process32FirstW", "Process32NextW",
    "Thread32First", "Thread32Next", "Module32FirstW", "Module32NextW",
    "NtUnmapViewOfSection", "QueueUserAPC",
    # ── Advapi32 (Registry/Crypto/Security) ──
    "RegOpenKeyExW", "RegOpenKeyExA", "RegOpenKeyW", "RegOpenKeyA",
    "RegCreateKeyExW", "RegCreateKeyExA", "RegSetValueExW", "RegSetValueExA",
    "RegQueryValueExW", "RegQueryValueExA", "RegDeleteKeyW", "RegDeleteKeyA",
    "RegDeleteValueW", "RegDeleteValueA", "RegCloseKey",
    "RegEnumKeyExW", "RegEnumKeyExA", "RegEnumValueW", "RegEnumValueA",
    # Crypto
    "CryptAcquireContextW", "CryptAcquireContextA",
    "CryptCreateHash", "CryptHashData", "CryptGetHashParam",
    "CryptEncrypt", "CryptDecrypt", "CryptDestroyHash",
    "CryptGenKey", "CryptImportKey", "CryptExportKey", "CryptDestroyKey",
    "CryptReleaseContext",
    # ── User32 (UI/Hooking) ──
    "MessageBoxW", "MessageBoxA", "DialogBoxParamW", "DialogBoxParamA",
    "CreateWindowExW", "CreateWindowExA", "DestroyWindow",
    "RegisterClassW", "RegisterClassExW", "UnregisterClassW",
    "DefWindowProcW", "DefWindowProcA", "DispatchMessageW", "DispatchMessageA",
    "TranslateMessage", "PeekMessageW", "PeekMessageA", "GetMessageW", "GetMessageA",
    "PostMessageW", "PostMessageA", "SendMessageW", "SendMessageA",
    "ShowWindow", "UpdateWindow", "SetWindowPos", "MoveWindow",
    "FindWindowW", "FindWindowA", "FindWindowExW", "FindWindowExA",
    "SetWindowTextW", "SetWindowTextA", "GetWindowTextW", "GetWindowTextA",
    "GetDlgItem", "SetDlgItemTextW", "GetDlgItemTextW",
    "GetAsyncKeyState", "GetKeyState", "GetKeyboardState",
    "SetWindowsHookExW", "SetWindowsHookExA", "UnhookWindowsHookEx",
    "CallNextHookEx", "SetWinEventHook", "UnhookWinEvent",
    "AttachThreadInput",
    # ── GDI32 ──
    "CreateFontW", "CreateFontA", "CreateFontIndirectW", "CreateFontIndirectA",
    "CreateBitmap", "CreateCompatibleBitmap", "CreateDCW", "CreateDCA",
    "DeleteObject", "SelectObject", "BitBlt", "StretchBlt",
    "TextOutW", "TextOutA", "DrawTextW", "DrawTextA",
    "GetDeviceCaps", "GetStockObject",
    # ── Comctl32 / Comdlg32 ──
    "InitCommonControls", "InitCommonControlsEx",
    "ImageList_Create", "ImageList_Add", "ImageList_Draw",
    "GetOpenFileNameW", "GetOpenFileNameA",
    "GetSaveFileNameW", "GetSaveFileNameA",
    # ── Shell32 ──
    "ShellExecuteW", "ShellExecuteA", "ShellExecuteExW", "ShellExecuteExA",
    "Shell_NotifyIconW", "Shell_NotifyIconA",
    "SHGetFolderPathW", "SHGetFolderPathA", "SHGetSpecialFolderPathW",
    "CommandLineToArgvW",
    # ── Ws2_32 (Networking) ──
    "WSAStartup", "WSACleanup", "WSAGetLastError", "WSASetLastError",
    "socket", "closesocket",
    "connect", "bind", "listen", "accept",
    "send", "recv", "sendto", "recvfrom",
    "setsockopt", "getsockopt",
    "htons", "htonl", "ntohs", "ntohl",
    "inet_addr", "inet_ntoa", "inet_pton", "inet_ntop",
    "gethostbyname", "gethostbyaddr", "getaddrinfo", "freeaddrinfo",
    "gethostname", "getpeername", "getsockname",
    "WSASocketW", "WSASocketA", "WSARecv", "WSASend",
    "select", "WSAAsyncSelect",
    # ── Wininet / Winhttp ──
    "InternetOpenW", "InternetOpenA", "InternetOpenUrlW", "InternetOpenUrlA",
    "InternetConnectW", "InternetConnectA",
    "HttpOpenRequestW", "HttpOpenRequestA", "HttpSendRequestW", "HttpSendRequestA",
    "InternetReadFile", "InternetWriteFile", "InternetCloseHandle",
    "HttpQueryInfoW", "HttpQueryInfoA",
    # ── Ole32 / OleAut32 ──
    "CoInitialize", "CoInitializeEx", "CoUninitialize",
    "CoCreateInstance", "CoGetClassObject",
    "SysAllocString", "SysFreeString",
    "VariantInit", "VariantClear",
    # ── Ntdll ──
    "NtQueryInformationProcess", "NtSetInformationThread",
    "NtCreateThreadEx", "RtlCreateUserThread",
    "RtlMoveMemory", "RtlCopyMemory", "RtlZeroMemory",
    "DbgPrint",
}

# ── MSVC 编译器生成的函数名前缀 ──
_MSVC_PREFIXES = [
    "__imp_",           # DLL import thunk
    "??",               # MSVC name-mangled C++ (e.g., ??0CDialog@@QAE@XZ)
    "__std_",           # MSVC internal stdlib helpers
    "__scrt_",          # MSVC CRT startup
    "__vcrt_",          # MSVC VCRT
    "__acrt_",          # MSVC ACRT
    "__CxxFrameHandler", # C++ exception handling
    "__security_check_cookie",
    "__report_gsfailure",
    "_except_handler",
    "__EH_prolog", "__EH_epilog",
    "_RTC_",            # Runtime checks
    "__RTC_",
    "__ArrayUnwind",
    "_vsnprintf", "__vsnprintf",
    "__ascii_",         # ASCII locale helpers
    "_wfsopen", "__wfsopen",
    "j_",               # IDA jump thunk (e.g., j_j__free_base)
]

# ── 前缀匹配（GCC/Clang + MSVC） ──
_STDLIB_PREFIXES = [
    # GCC/Clang
    "__printf_", "__fprintf_", "__sprintf_", "__snprintf_", "__vfprintf_",
    "__memcpy_", "__memmove_", "__memset_", "__strcpy_", "__strncpy_",
    "__strcat_", "__strncat_", "__gets_", "__readlinkat_",
    "__stack_chk_", "__gmon_", "__cxa_", "__libc_",
    "_pthread_", "pthread_",
    "__isoc99_", "__isoc23_",
    "__fdelt_", "__longjmp_",
    # MSVC CRT
    "_invoke_watson",
    "_invalid_parameter",
    "_onexit",
    "_cexit",
    "_initterm", "_initterm_e",
    "_configure_narrow_argv",
    "_initialize_narrow_environment",
    "_get_initial_narrow_environment",
    "_wassert",
    # MSVC 编译器内部 stdlib 辅助函数（常见于安装程序/白软件）
    "_stdio_",        # _stdio_fopen, _stdio_init 等
    "_fp",            # _fpmaxtostr, _fpinit, _fp_hw 等浮点辅助函数
    "_wcs",           # wcsrtombs, wcrtomb 等宽字符函数
    "_mbs",           # mbsrtowcs 等多字节字符串函数
    "_mbc",           # mbc* 多字节字符辅助
    "_wctomb",        # wctomb_s 等转换函数
    "_mem",           # _memcpy, _memccpy 等（无 __ 前缀的 MSVC 版本）
    "_str",           # _strdup, _strlwr 等（无 __ 前缀的 MSVC 版本）
    "_fget",          # _fgetchar, _fgetwc 等
    "_fput",          # _fputchar, _fputwc 等
    "_getw", "_putw", # _getwchar, _putwchar
    "_heap",          # _heap_alloc, _heap_free 等
    "_malloc",        # _malloc_base, _malloc_array 等
    "_free",          # _free_base 等
    "_realloc",       # _realloc_base 等
    "_crt",           # _crt* CRT 内部函数
    "_seh",           # 结构化异常处理
    "_xcpt",          # 异常处理
    "_callnewh",      # new handler
    "_getdrive",      # 驱动器相关
    "_seterrormode",  # 错误模式
    "_initterm",      # MSVC CRT initialization
    "_cexit",         # CRT exit
    "_onexit",        # MSVC onexit
    "_errno",         # errno accessor
    "_except",        # exception handling
    "_terminate",     # process termination
    "_cxxthrow",      # C++ exception throw
    "_top",           # TopLevelExceptionFilter etc
    "_tidy",          # tidy_global etc
    "_initialize",    # initialize_c etc
    "_start",         # StartAddress etc
]

# 函数名后缀匹配
_STDLIB_SUFFIXES = [
    "_chk", "_unlocked", "_r", "_l",
]


def is_stdlib_function(func_name):
    if not func_name:
        return True
    if func_name in _STDLIB_FUNCTIONS:
        return True
    # Check Windows API
    if func_name in _WIN_API_FUNCTIONS:
        return True
    # Check MSVC compiler-generated prefixes
    for prefix in _MSVC_PREFIXES:
        if func_name.startswith(prefix):
            return True
    # Check stdlib prefixes
    lower = func_name.lower()
    for prefix in _STDLIB_PREFIXES:
        if lower.startswith(prefix):
            return True
    # Check suffixes: only match if the base is also a known stdlib function
    for suffix in _STDLIB_SUFFIXES:
        if func_name.endswith(suffix):
            base = func_name[: -len(suffix)]
            if base in _STDLIB_FUNCTIONS:
                return True
    # Underscore-prefixed singletons (like _exit, _start) are usually system
    if func_name.startswith("_") and not func_name.startswith("__"):
        if func_name.lower() in ("_start", "_exit", "_init", "_fini",
                                  "_init_proc", "_term_proc", "_fpinit",
                                  "_stdio_init", "_fp_out_narrow", "_fp_hw",
                                  "_fp_hw_probe", "_jmp_buf"):
            return True
        # 单下划线+常见libc函数名 = MSVC CRT 版本（如 _memset, _memcpy, _fopen）
        # 检查去掉下划线后是否为已知stdlib函数
        bare = func_name[1:].lower()
        if bare in _STDLIB_FUNCTIONS:
            return True
        # 也检查是否匹配前缀
        for prefix in _STDLIB_PREFIXES:
            if func_name.lower().startswith(prefix):
                return True
    # ── Go语言标准库/运行时函数 ──
    # Go编译的二进制包含大量 runtime/net/crypto 等包函数
    if _is_go_stdlib(func_name):
        return True
    return False


_GO_STDLIB_PACKAGES = [
    # Go 运行时核心
    "runtime.",
    "runtime/internal/",
    "runtime/debug.",
    "runtime/pprof.",
    "runtime/trace.",
    # Go 编译器生成的辅助类型/符号
    "go.shape.",
    "go.itab.",
    "type..eq.",
    "type..hash.",
    "type..eqfunc.",
    "type..hashfunc.",
    # Go 标准库
    "fmt.",
    "os.",
    "io.",
    "bytes.",
    "strings.",
    "strconv.",
    "sync.",
    "sync/atomic.",
    "math.",
    "math/big.",
    "math/bits.",
    "math/rand.",
    "sort.",
    "time.",
    "errors.",
    "context.",
    "log.",
    "flag.",
    "unicode.",
    "unicode/utf8.",
    "unicode/utf16.",
    "encoding/",
    "encoding/base64.",
    "encoding/binary.",
    "encoding/json.",
    "encoding/hex.",
    "encoding/xml.",
    "encoding/pem.",
    "encoding/asn1.",
    "encoding/gob.",
    "compress/",
    "compress/flate.",
    "compress/gzip.",
    "compress/zlib.",
    "compress/bzip2.",
    "compress/lzw.",
    "hash/",
    "hash/crc32.",
    "hash/crc64.",
    "hash/fnv.",
    "hash/adler32.",
    "hash/maphash.",
    "crypto/",
    "crypto/aes.",
    "crypto/cipher.",
    "crypto/des.",
    "crypto/dsa.",
    "crypto/ecdsa.",
    "crypto/ed25519.",
    "crypto/elliptic.",
    "crypto/hmac.",
    "crypto/md5.",
    "crypto/rand.",
    "crypto/rc4.",
    "crypto/rsa.",
    "crypto/sha1.",
    "crypto/sha256.",
    "crypto/sha512.",
    "crypto/subtle.",
    "crypto/tls.",
    "crypto/x509.",
    "crypto/x509/pkix.",
    "crypto/internal/",
    "internal/",
    "reflect.",
    "unsafe.",
    "debug/",
    "debug/dwarf.",
    "debug/elf.",
    "debug/pe.",
    "debug/macho.",
    "debug/gosym.",
    "plugin.",
    "syscall.",
    "syscall/js.",
    # Go 网络库（包含大量可能被误判的关键词）
    "net.",
    "net/http.",
    "net/url.",
    "net/textproto.",
    "net/mail.",
    "net/smtp.",
    "net/textproto.",
    "net/http/internal/",
    "net/http/httptrace.",
    # Go 容器
    "container/list.",
    "container/heap.",
    "container/ring.",
]

def _is_go_stdlib(func_name):
    """检查是否为Go语言标准库/运行时函数"""
    for pkg in _GO_STDLIB_PACKAGES:
        if func_name.startswith(pkg):
            return True
    # Go函数名匹配：package.FunctionName 格式
    # 也匹配 go: 前缀的编译器生成的符号
    if func_name.startswith("go:"):
        return True
    # 匹配 Go abi 后缀
    if ".abi0" in func_name or ".abi1" in func_name:
        return True
    return False
    return False


# ── 函数可疑度打分 ──
_SUSPICIOUS_KW = [
    # 网络/C2 (通用)
    "socket", "connect", "send", "recv", "accept", "listen", "bind",
    # 网络/C2 (Windows)
    "wsa", "internet", "http", "ftp", "winsock",
    # 网络/C2 (Linux)
    "curl", "wget", "ncat", "netcat", "socat", "mkfifo", "reverse",
    # 钩子/键盘记录
    "hook", "keylog", "keystate", "keyboard", "mouse", "input",
    # 加密
    "crypt", "bcrypt", "encrypt", "decrypt", "hash", "aes", "rsa",
    # 进程注入 (Windows)
    "remotethread", "writeprocessmemory", "virtualalloc", "openprocess",
    "ntunmap", "queueuserapc", "threadcontext", "resumethread",
    # 进程注入 (Linux)
    "ptrace", "memfd", "execveat", "usermodehelper", "ldpreload",
    # 持久化 (Windows)
    "regset", "regcreate", "regopen", "createservice", "schtasks",
    "runonce", "startup",
    # 持久化 (Linux)
    "crontab", "bashrc", "profile", "systemd", "initd",
    # 反分析
    "debugger", "isdebugger", "vmware", "virtualbox", "sandbox",
    "wireshark", "ollydbg", "x64dbg",
    # 进程执行
    "createprocess", "shellexecute", "winexec", "system(",
    # 资源/投放
    "findresource", "loadresource", "lockresource", "sizeofresource",
    "dropper", "extract", "decompress",
    # 隐藏
    "hide", "sw_hide", "showwindow", "setwindowpos",
    # 权限 (Windows)
    "impersonate", "adjusttoken", "logonuser", "uac",
    # 权限 (Linux)
    "setuid", "setgid", "chmod+s", "capset", "prctl", "seccomp",
    # 数据窃取 (Linux)
    "shadow", "passwd", "authorized_keys", "ssh_key",
]


def _build_called_by_index(call_tree):
    """预计算被调用次数索引，O(n*m) → O(n+m)"""
    called_by = {}
    for caller, callees in call_tree.items():
        for callee in callees:
            called_by[callee] = called_by.get(callee, 0) + 1
    return called_by


def _score_function(name, func_addr, call_tree, func_size_map, called_by_index):
    """对函数按可疑度打分，返回 (name, addr, score) 元组"""
    score = 0
    name_lower = name.lower()

    # 1. 函数名是否匹配可疑关键词
    for kw in _SUSPICIOUS_KW:
        if kw in name_lower:
            score += 10

    # 2. 非stdlib函数
    if not is_stdlib_function(name):
        score += 1

    # 3. 作为caller调用其他人的次数（调用链中的上游）
    call_count = len(call_tree.get(name, []))
    score += call_count

    # 4. 被多少调用（核心枢纽函数）— 预计算索引，O(1)查询
    called_by_count = called_by_index.get(name, 0)
    score += called_by_count * 2

    # 5. 函数大小（大函数通常逻辑更复杂）
    func_size = func_size_map.get(name, 0)
    if func_size > 500:
        score += 5
    if func_size > 2000:
        score += 10

    return (name, func_addr, score)


def _rank_functions(func_list, call_tree, all_functions):
    """对函数列表按可疑度排序，返回 (name, addr, score) 元组列表"""
    # 构建函数名→大小的映射
    func_size_map = {}
    for f in all_functions:
        size = f.get("size", 0)
        func_size_map[f["name"]] = size

    # 预计算被调用次数索引（O(n+m)，替代每次O(n*m)遍历）
    called_by_index = _build_called_by_index(call_tree)

    scored = []
    for f in func_list:
        scored.append(_score_function(f["name"], f["address"], call_tree, func_size_map, called_by_index))

    # 按分数降序排列
    scored.sort(key=lambda x: x[2], reverse=True)
    return scored


# ── 漏洞模式打分：寻找容易出漏洞的函数 ──
_VULN_KW = [
    # 危险函数相关（C标准库危险函数、Windows危险API）
    "strcpy", "strcat", "sprintf", "vsprintf", "gets", "scanf",
    "memcpy", "memmove", "wcscpy", "wcscat", "swprintf",
    # 解析/反序列化
    "parse", "decode", "unpack", "deserialize", "unmarshal",
    "readheader", "readpacket", "readframe", "parseurl", "parseheader",
    # 网络/协议
    "recv", "readfile", "readsocket", "tcp_", "udp_", "http_", "ftp_",
    "ssl", "tls", "cipher",
    # 压缩/编码
    "decompress", "inflate", "unzip", "decodebase64", "urldecode",
    # 文件/输入
    "fread", "fgets", "getline", "readinput", "prompt",
    # 内存操作
    "alloc", "free", "resize", "realloc", "malloc",
    # 加密/哈希
    "crypt", "hash", "encrypt", "decrypt", "sign", "verify",
]

def _score_vuln_function(name, func_addr, call_tree, func_size_map, called_by_index):
    """漏洞模式专用打分：寻找容易存在漏洞的函数"""
    score = 0
    name_lower = name.lower()

    # 1. 函数名匹配漏洞相关关键词
    for kw in _VULN_KW:
        if kw in name_lower:
            score += 15

    # 2. 非stdlib函数（用户自定义函数更容易有漏洞）
    if not is_stdlib_function(name):
        score += 2

    # 3. 函数大小（大函数更可能有复杂逻辑导致漏洞）
    func_size = func_size_map.get(name, 0)
    if func_size > 200:
        score += 3
    if func_size > 500:
        score += 5
    if func_size > 2000:
        score += 10
    if func_size > 5000:
        score += 15

    # 4. 调用子函数数量多 = 逻辑复杂 = 更容易出错
    call_count = len(call_tree.get(name, []))
    if call_count > 5:
        score += 3
    if call_count > 15:
        score += 5
    if call_count > 30:
        score += 10

    # 5. 被调用次数（核心枢纽函数）— 预计算索引
    called_by_count = called_by_index.get(name, 0)
    score += called_by_count

    return (name, func_addr, score)


def _rank_vuln_functions(func_list, call_tree, all_functions):
    """漏洞模式专用排序"""
    func_size_map = {}
    for f in all_functions:
        size = f.get("size", 0)
        func_size_map[f["name"]] = size

    # 预计算被调用次数索引
    called_by_index = _build_called_by_index(call_tree)

    scored = []
    for f in func_list:
        scored.append(_score_vuln_function(f["name"], f["address"], call_tree, func_size_map, called_by_index))

    scored.sort(key=lambda x: x[2], reverse=True)
    return scored


class WPeAIController:
    """主控制器：执行三阶段分析流水线"""

    MODES = {
        "full":  ["phase1", "phase2_explain", "phase3_explain"],
        "light": ["phase1", "phase2_explain"],
        "vuln":  ["phase2_vuln"],
    }

    def __init__(self, ida_conn, ai_engine, output_dir=None, mode="full"):
        self.ida = ida_conn
        self.ai = ai_engine
        self.mode = mode if mode in self.MODES else DEFAULT_ANALYSIS_MODE
        self.max_workers = DEFAULT_MAX_WORKERS
        self.max_critical = DEFAULT_MAX_CRITICAL.get(self.mode, 50)
        self.max_full_scan = DEFAULT_MAX_FULL_SCAN
        self.results = {
            "metadata": {
                "version": "3.0",
                "timestamp": datetime.now().isoformat(),
                "phases": {},
            },
            "binary_info": {},
            "phase1_global_scan": {},
            "phase2_critical_path": {},
            "phase3_full_scan": {},
            "summary": {},
        }
        self.analyzed_funcs = set()
        self.suspicious_funcs = set()
        self.output_dir = output_dir

    def _s(self, base_key):
        """Mode-aware label: if mode is vuln, try {key}_vuln first."""
        if self.mode == "vuln":
            v = _LABELS.get("zh" if ZH_CN else "en", {}).get(base_key + "_vuln")
            if v:
                return v
        return _L(base_key)

    def run(self):
        active_phases = self.MODES[self.mode]
        phase_labels = {
            "phase1": "Global Scan",
            "phase2_explain": "Critical Path Explain",
            "phase3_explain": "Full Function Explain",
            "phase2_vuln": "Critical Path Vuln",
        }
        active_labels = [phase_labels.get(p, p) for p in active_phases]

        self._print_header("WPeGPT AI Controller — Mode: %s" % self.mode.upper())
        print(f"    Active phases: {', '.join(active_labels)}")

        # Phase 0: Connect and gather basic info
        if not self._phase0_connect():
            return False

        # vuln模式：只获取函数和调用树，跳过字符串扫描
        if self.mode == "vuln" and "phase2_vuln" in active_phases:
            self._fetch_call_tree()

        if "phase1" in active_phases:
            self._phase1_global_scan()

        # 网络地址解密（在Phase1之后、Phase2之前，仅当有网络能力但无硬编码地址时触发）
        if self.mode != "vuln":
            self._decrypt_network_addresses()

        if "phase2_explain" in active_phases:
            self._phase2_critical_path(analysis_type="explain")

        if "phase2_vuln" in active_phases:
            self._phase2_critical_path(analysis_type="vuln")

        if "phase3_explain" in active_phases:
            self._phase3_full_scan()

        # 综合判定：vuln模式跳过综合判定，专注漏洞分析
        if self.mode != "vuln":
            self._generate_conclusion()

        self._generate_report()

        self._print_header("Analysis Complete!" if not ZH_CN else "分析完成!")
        print(f"    {_L('total_analyzed')}: {len(self.analyzed_funcs)}")
        if self.suspicious_funcs:
            print(f"    {self._s('suspicious_label')}: {len(self.suspicious_funcs)} — {', '.join(sorted(self.suspicious_funcs)[:10])}{'...' if len(self.suspicious_funcs) > 10 else ''}")
        return True

    def _phase0_connect(self):
        self._print_header(_L("phase0"))
        info = self.ida.send_command("get_info")
        if info.get("status") != "ok":
            print(f"[!] Failed to get binary info: {info}")
            return False

        self.results["binary_info"] = info["data"]
        bi = info["data"]
        # 根据分析文件名设置输出目录
        if self.output_dir is None:
            idb_name = bi.get("idb_name", "binary")
            base_name = os.path.splitext(idb_name)[0]
            self.output_dir = os.path.join(os.getcwd(), "%s_WPeAI_Results" % base_name)
        os.makedirs(self.output_dir, exist_ok=True)
        print(f"    IDB: {bi.get('idb_name', 'unknown')}")
        print(f"    Architecture: {bi.get('arch', 'unknown')}")
        print(f"    Entry point: {bi.get('entry_point', 'unknown')}")
        print(f"    Functions: {bi.get('func_count', 0)}")
        print(f"    Segments: {len(bi.get('segments', []))}")
        return True

    def _fetch_call_tree(self):
        """轻量级数据获取：仅函数列表+调用树，用于vuln模式"""
        print(_L("getting_funcs"))
        func_result = self.ida.send_command("get_functions", timeout=30)
        functions = func_result.get("data", {}).get("functions", [])
        print(f"    {_L('found_funcs', count=len(functions))}")

        print(_L("getting_calltree"))
        tree_result = self.ida.send_command("get_call_tree", timeout=60)
        call_tree = tree_result.get("data", {}).get("call_tree", {})
        print(f"    {_L('found_calls', count=len(call_tree))}")

        self._all_functions = functions
        self._call_tree = call_tree

    def _phase1_global_scan(self):
        self._print_header(_L("phase1"))
        t0 = time.time()

        print(_L("getting_funcs"))
        func_result = self.ida.send_command("get_functions", timeout=30)
        functions = func_result.get("data", {}).get("functions", [])
        print(f"    {_L('found_funcs', count=len(functions))}")

        print(_L("getting_strings"))
        str_result = self.ida.send_command("get_strings", {"max_length": 80, "min_length": 3}, timeout=30)
        strings = str_result.get("data", {}).get("strings", [])
        print(f"    {_L('found_strings', count=len(strings))}")

        print(_L("getting_calltree"))
        tree_result = self.ida.send_command("get_call_tree", timeout=60)
        call_tree = tree_result.get("data", {}).get("call_tree", {})
        print(f"    {_L('found_calls', count=len(call_tree))}")

        # ── 智能字符串分类：提取所有可疑指标 ──
        _MALICIOUS_INDICATORS = [
            # 网络/C2通信
            'WS2_32', 'winhttp', 'wininet', 'InternetOpen', 'InternetConnect',
            'HttpSendRequest', 'URLDownload', 'socket', 'connect', 'recv', 'send',
            'WSAStartup', 'gethostbyname', 'getaddrinfo', 'htons', 'htonl',
            'sendto', 'recvfrom', 'WSASocket', 'inet_addr', 'inet_pton',
            # 键盘记录/输入钩子
            'SetWindowsHookEx', 'UnhookWindowsHookEx', 'GetKeyState', 'GetAsyncKeyState',
            'GetKeyboardState', 'keylog', 'DirectInput', 'WH_KEYBOARD', 'WH_MOUSE',
            'CallNextHookEx', 'SetWinEventHook', 'AttachThreadInput',
            # 加密/解密/编码
            'BCrypt', 'CryptAcquire', 'CryptEncrypt', 'CryptDecrypt', 'CryptGenKey',
            'CryptImportKey', 'CryptExportKey', 'CryptHashData', 'aes', 'rsa',
            'base64', 'RtlEncrypt', 'RtlDecrypt',
            # 进程/线程注入
            'CreateRemoteThread', 'WriteProcessMemory', 'VirtualAllocEx',
            'OpenProcess', 'NtUnmapViewOfSection', 'QueueUserAPC',
            'SetThreadContext', 'GetThreadContext', 'ResumeThread',
            'NtCreateThreadEx', 'RtlCreateUserThread',
            # 持久化/自启动
            'RunOnce', 'CurrentVersion\\Run', 'schtasks', 'ScheduledTask',
            'CreateService', 'ChangeServiceConfig', 'StartupApproved',
            'RegSetValue', 'RegCreateKey',
            # 环境检测/反分析
            'IsDebuggerPresent', 'CheckRemoteDebuggerPresent', 'NtQueryInformationProcess',
            'GetTickCount', 'QueryPerformanceCounter', 'vmware', 'virtualbox',
            'sandbox', 'wireshark', 'procmon', 'ollydbg', 'x64dbg', 'ida pro',
            'NtSetInformationThread', 'ThreadHideFromDebugger',
            # 文件投放/Dropper
            'ShellExecute', 'CreateProcess', 'WinExec',
            'WriteFile', 'CreateFile', 'GetTempPath', 'GetTempFileName',
            'DropFile', 'extract', 'decompress', 'resource', 'FindResource',
            'LoadResource', 'LockResource', 'SizeofResource',
            # 隐藏/反检测
            'SetWindowPos', 'ShowWindow', 'SW_HIDE', 'FindWindow',
            'Inject', 'Reflective', 'GetProcAddress', 'LoadLibrary',
            # 权限提升
            'AdjustTokenPrivileges', 'Impersonate', 'LogonUser',
            'IsNTAdmin', 'Elevate', 'UAC',
            # ── Shellcode加载/代码执行（仅最明确的指标）──
            # 注意：不要包含 VirtualAlloc/CreateThread/WriteProcessMemory 等
            # 这些在合法安装程序/解压程序中也很常见，仅靠字符串存在不足以标记
            'CallWindowProcA', 'CallWindowProcW',  # 回调执行（极少被正常程序使用）
            'EnumCalendarInfo', 'EnumDateFormats',  # 枚举回调执行
            'EnumSystemLocales', 'EnumUILanguages',
            'EnumObjects', 'EnumMetaFile', 'EnumEnhMetaFile',
            'EnumFontFamilies',  # 回调执行模式（shellcode执行技巧）
            # ── 内存/文件操作（shellcode loader核心API，单独存在不标记，需组合判断）──
            'VirtualAlloc', 'VirtualAllocEx',  # 分配内存（需结合后续操作判断）
            'ReadFile', 'CreateFileW', 'CreateFileA',  # 读取外部数据
            # ── InstallShield/MSI 安装程序框架识别（用于降低误报）──
            'MsiExecute', 'MsiSetProperty', 'MsiGetProperty',
            'MsiSetInternalUI', 'MsiGetProductInfo',
            'InstallShield', 'ISExternalUI', 'ISScript',
            'SetupPrereq', 'ISSetup', 'IsSuite',
            'Windows Installer', 'MSI installer',
            # ── Linux ELF 特有指标 ──
            '/etc/passwd', '/etc/shadow', '/etc/sudoers', '/etc/crontab',
            '/proc/self/', '/proc/meminfo', '/proc/version',
            '/dev/tcp/', '/dev/udp/',
            'ssh_key', 'authorized_keys', '.bash_history', '.ssh/id_rsa',
            'netcat', 'nc -e', 'ncat', 'bash -i', '/bin/bash -i',
            'reverse shell', '/bin/sh -i', 'socat', 'mkfifo',
            'LD_PRELOAD', 'ptrace', 'seccomp', 'prctl',
            '/tmp/.X', '/var/spool/cron', 'crontab -e',
            'chmod +s', 'setuid', 'setgid', 'cap_set',
            'memfd_create', 'execveat', 'usermodehelper',
            '/etc/ld.so.preload', '/etc/ld.so.conf',
            'iptables', 'ufw', 'nftables', 'selinux',
            'modprobe', 'insmod', 'rmmod', 'kmod',
            'curl ', 'wget ', '/dev/null 2>&1', 'nohup',
            # ── macOS 特有指标 ──
            'launchd', 'launchctl', 'launchagent', 'launchdaemon',
            '/Library/LaunchAgents', '/Library/LaunchDaemons',
            '/System/Library/LaunchAgents', 'osascript',
            'SecurityAgent', 'kextload', 'kextutil',
            'SPCDownload', 'Gatekeeper', 'XProtect',
        ]
        suspicious_strings = []
        dll_strings = []
        ui_strings = []
        other_strings = []
        for s in strings:
            content = s['content']
            content_lower = content.lower()
            matched = False
            # 匹配可疑指标
            for indicator in _MALICIOUS_INDICATORS:
                if indicator.lower() in content_lower:
                    suspicious_strings.append(content)
                    matched = True
                    break
            if not matched:
                # DLL名称
                if content.endswith('.dll') and len(content) < 30:
                    dll_strings.append(content)
                # MFC/UI框架字符串（限制数量避免淹没可疑指标）
                elif any(kw in content_lower for kw in ['cwin', 'cframe', 'cdialog', 'cbutton', 'clist', 'cmfc', 'cdock', 'ctoolbar', 'cmenu', 'cview', 'cpane', 'cribbon']):
                    if len(ui_strings) < 40:
                        ui_strings.append(content)
                # 其他有趣字符串
                else:
                    if len(other_strings) < 80:
                        other_strings.append(content)

        # 去重
        suspicious_strings = list(dict.fromkeys(suspicious_strings))
        dll_strings = list(dict.fromkeys(dll_strings))

        call_tree_summary = {}
        for caller, callees in list(call_tree.items())[:100]:
            call_tree_summary[caller] = callees

        # ── 提取网络地址（IP、域名、URL、端口）──
        network_addresses = self._extract_network_addresses(strings)

        # ── Phase 1只做数据收集，不做结论 ──
        # 可疑字符串分类结果存入 results，供最终综合判定使用
        elapsed = time.time() - t0
        self.results["phase1_global_scan"] = {
            "duration_seconds": round(elapsed, 1),
            "function_count": len(functions),
            "string_count": len(strings),
            "call_tree_size": len(call_tree),
            "strings": strings,
            "call_tree": call_tree,
            # 字符串分类（供最终结论阶段使用）
            "suspicious_strings": suspicious_strings[:100],
            "dll_strings": dll_strings[:50],
            "ui_strings": ui_strings,
            "other_strings": other_strings,
            "suspicious_string_categories": {
                "networking": [s for s in suspicious_strings if any(kw in s.lower() for kw in ['ws2_32', 'winhttp', 'wininet', 'internet', 'socket', 'connect', 'recv', 'send', 'wsa', 'gethost', 'getaddr', 'htons', 'curl ', 'wget ', 'ncat', 'netcat', 'socat', 'mkfifo', '/dev/tcp', '/dev/udp'])],
                "keylogging": [s for s in suspicious_strings if any(kw in s.lower() for kw in ['setwindowshook', 'unhook', 'getkeystate', 'getasynckeystate', 'keylog', 'directinput', 'wh_keyboard', 'wh_mouse', 'callnexthook', 'xinput', 'evdev', '/dev/input']) and "crypto/tls" not in s.lower()],
                "crypto": [s for s in suspicious_strings if any(kw in s.lower() for kw in ['bcrypt', 'cryptacq', 'cryptenc', 'cryptdec', 'cryptgen', 'cryptimport', 'cryptexport', 'crypthash', 'aes', 'rsa', 'base64', 'rtlen', 'rtldc', 'libssl', 'libcrypto', 'openssl', 'ssh_key', 'id_rsa'])],
                "injection": [s for s in suspicious_strings if any(kw in s.lower() for kw in ['createremotethread', 'writeprocessmemory', 'virtualallocex', 'openprocess', 'ntunmap', 'queueuserapc', 'setthreadcontext', 'getthreadcontext', 'resumethread', 'ptrace', 'memfd_create', 'execveat', 'ld_preload', 'usermodehelper']) and "httptrace" not in s.lower()],
                "persistence": [s for s in suspicious_strings if any(kw in s.lower() for kw in ['runonce', 'currentversion\\run', 'schtasks', 'scheduledtask', 'createservice', 'changeservice', 'startupapproved', 'regsetvalue', 'regcreatekey', 'launchd', 'launchctl', 'launchagent', 'launchdaemon', 'crontab', 'bashrc', 'systemd', '/etc/init.d'])],
                "antianalysis": [s for s in suspicious_strings if any(kw in s.lower() for kw in ['isdebugger', 'checkremote', 'ntqueryinfo', 'gettickcount', 'queryperformance', 'vmware', 'virtualbox', 'sandbox', 'wireshark', 'procmon', 'ollydbg', 'x64dbg', 'seccomp', 'selinux', 'gatekeeper', 'xprotect', 'ptrace']) and "httptrace" not in s.lower() and "pTrace" not in s],
                "dropper": [s for s in suspicious_strings if any(kw in s.lower() for kw in ['shellexecute', 'createprocess', 'winexec', 'writefile', 'createfile', 'gettemppath', 'gettempfilename', 'dropfile', 'extract', 'decompress', 'findresource', 'loadresource', 'lockresource', 'sizeofresource', '/tmp/.', 'nohup', '/dev/null'])],
                "code_execution": [s for s in suspicious_strings if any(kw in s.lower() for kw in ['callwindowproc', 'enumcalendar', 'enumdate', 'enumsystem', 'enumui', 'enumobject', 'enumfont', 'enummeta', 'enumenhmeta', 'bash -i', '/bin/sh', 'reverse shell'])],
                # 内存+文件操作组合（shellcode loader核心模式：VirtualAlloc + ReadFile + 间接调用）
                "memory_file_ops": [s for s in suspicious_strings if any(kw in s.lower() for kw in ['virtualalloc', 'readfile', 'createfilew', 'createfilea'])],
                # 安装程序框架识别（InstallShield/MSI，用于降低误报）
                "installer_framework": [s for s in suspicious_strings if any(kw in s.lower() for kw in ['msiexecute', 'msisetproperty', 'msigetproperty', 'msisetinternalui', 'msigetproductinfo', 'installshield', 'isexternalui', 'isscript', 'setupprereq', 'issetup', 'issuite', 'windows installer', 'msi installer'])],
            },
            "all_functions": [{"name": f["name"], "address": f["address"]} for f in functions],
            # 网络地址提取（供报告和网络分析使用）
            "network_addresses": network_addresses,
        }

        # 打印可疑字符串统计
        if suspicious_strings:
            print(f"    发现 {len(suspicious_strings)} 条可疑安全指标字符串:")
            cats = self.results["phase1_global_scan"]["suspicious_string_categories"]
            for cat_name, cat_items in cats.items():
                if cat_items:
                    label_map = {
                        "networking": "网络通信",
                        "keylogging": "键盘记录/钩子",
                        "crypto": "加密/解密",
                        "injection": "进程注入",
                        "persistence": "持久化",
                        "antianalysis": "反分析/反调试",
                        "dropper": "文件投放/Dropper",
                        "code_execution": "代码执行/Shellcode",
                        "memory_file_ops": "内存/文件操作",
                        "installer_framework": "安装程序框架",
                    }
                    print(f"      {label_map.get(cat_name, cat_name)}: {len(cat_items)} 条")
        else:
            print("    未发现明显可疑安全指标字符串")

        # 保存函数列表供后续阶段使用
        self._all_functions = functions
        self._call_tree = call_tree

        print(f"    Phase 1 completed in {elapsed:.1f}s")

    def _decrypt_network_addresses(self):
        """
        当检测到网络连接但未发现硬编码地址时，
        尝试识别解密函数并提交给AI进行字符串解密。
        """
        p1 = self.results.get("phase1_global_scan", {})
        cats = p1.get("suspicious_string_categories", {})
        net_addr = p1.get("network_addresses", {})

        # 条件：有网络能力但没有提取到域名/URL/IP
        has_network = bool(cats.get("networking"))
        has_addresses = bool(net_addr.get("domains") or net_addr.get("urls") or net_addr.get("ips"))

        if not has_network or has_addresses:
            return

        self._print_header("网络地址解密")
        print("    [*] 检测到网络能力但无硬编码地址，尝试解密...")

        # 步骤1：从函数名中找出可能的解密函数
        _DECRYPT_KW = [
            "decrypt", "decode", "xor", "unobfusc", "deobfusc",
            "base64decode", "rot13", "rc4", "aes", "des",
            "crypt", "strdecrypt", "stringdec", "stringdecode",
            "getstring", "getapi", "resolveapi", "loadstring",
            "unpack", "decompress", "decodestr", "decode_string",
            "decryptstr", "decrypt_string", "decode_url",
            "get_c2", "get_config", "load_config", "readconfig",
            "getdomain", "geturl", "getserver", "gethost",
            "getpeer", "getendpoint",
        ]

        func_name_to_addr = {}
        for f in self._all_functions:
            func_name_to_addr[f["name"]] = f["address"]

        # 按可疑度打分找出解密候选
        decrypt_candidates = []
        for name, addr in func_name_to_addr.items():
            if is_stdlib_function(name):
                continue
            score = 0
            name_lower = name.lower()
            for kw in _DECRYPT_KW:
                if kw in name_lower:
                    score += 10

            # 被多个函数调用的中间函数（可能是解密核心）
            called_by_count = sum(1 for callees in self._call_tree.values() if name in callees)
            if called_by_count >= 2:
                score += called_by_count * 2

            # 网络相关函数调用的子函数
            if any(kw in name_lower for kw in ["socket", "connect", "http", "wininet", "wsa", "internet", "send", "recv"]):
                score += 5

            if score > 0:
                decrypt_candidates.append({"name": name, "address": addr, "score": score})

        decrypt_candidates.sort(key=lambda x: x["score"], reverse=True)
        top_candidates = decrypt_candidates[:8]

        if not top_candidates:
            print("    [*] 未找到解密函数候选")
            return

        print(f"    找到 {len(top_candidates)} 个解密候选函数:")
        for c in top_candidates[:5]:
            print(f"      {c['name']} (score={c['score']})")
        if len(top_candidates) > 5:
            print(f"      ... 及 {len(top_candidates) - 5} 个")

        # 步骤2：获取候选函数的伪代码并发送给AI解密
        if not self.ai.available:
            print("    [!] AI不可用，跳过解密")
            return

        # 批量获取伪代码
        pseudocodes = []
        for candidate in top_candidates:
            detail = self.ida.send_command("get_function_detail", {"address": candidate["address"]}, timeout=30)
            pc = detail.get("data", {}).get("pseudocode", "")
            if pc:
                pseudocodes.append({
                    "name": candidate["name"],
                    "address": candidate["address"],
                    "score": candidate["score"],
                    "pseudocode": pc,
                })

        if not pseudocodes:
            print("    [!] 无法获取候选函数伪代码")
            return

        print(f"    成功获取 {len(pseudocodes)} 个函数伪代码，提交AI分析...")

        # 构建解密提示词
        pc_text = ""
        for i, pc in enumerate(pseudocodes):
            pc_text += f"\n--- Function {i+1}: {pc['name']} ({pc['address']}) [score={pc['score']}] ---\n"
            # 截断过长的伪代码（AI token限制）
            code = pc["pseudocode"]
            if len(code) > 3000:
                code = code[:3000] + "\n... [truncated]"
            pc_text += code

        decrypt_prompt = f"""You are analyzing a binary that has network communication capabilities (socket, connect, WSA, WinINet APIs detected). However, NO hardcoded server addresses, domains, or IPs were found in the string table. This suggests the addresses are encrypted/obfuscated and decrypted at runtime.

Analyze the following function(s) pseudocode to identify any decryption/decoding logic and extract the decrypted server addresses.

{pc_text}

TASK:
1. Identify which encryption/obfuscation method is used (XOR, base64, custom algorithm, string concatenation, etc.)
2. Extract the encrypted data (byte arrays, encoded strings) and any keys/IVs used
3. Decrypt/decode the data to reveal the actual server addresses, domains, or URLs
4. If the function constructs addresses from string parts (e.g., splitting a domain into segments), reconstruct the full address
5. If the data cannot be fully decrypted (requires runtime execution), describe the algorithm and provide the best approximation of what the decrypted values might look like

RESPONSE FORMAT:
- Decryption method: (XOR/Base64/custom/string concatenation/etc.)
- Key/parameters: (if applicable)
- Decrypted addresses:
  - Address 1: [decrypted value] — purpose: [C2/update/login/etc.] — from function: [function name]
  - Address 2: ...
- Confidence: high/medium/low
- Notes: any additional observations about the encryption scheme"""

        result = self.ai.query(decrypt_prompt, max_tokens=4096)

        # 存储解密结果
        decrypted_addresses = {
            "status": "success" if "[AI error:" not in result else "error",
            "ai_response": result,
            "functions_analyzed": [pc["name"] for pc in pseudocodes],
        }

        # 尝试从 AI 响应中提取提取地址
        addr_pattern = re.compile(r'(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]*[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}')
        ip_pattern = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
        found = set(addr_pattern.findall(result)) | set(ip_pattern.findall(result))
        # 过滤常见假阳性
        found = {a for a in found if a.lower() not in (
            "example.com", "test.com", "yourdomain.com",
            "your.server.com", "decrypted.value", "c2.server.com",
            "malware.example.com",
        )}
        decrypted_addresses["extracted_domains"] = sorted(found)

        self.results["phase1_global_scan"]["decrypted_addresses"] = decrypted_addresses

        if found:
            print(f"    [+] 解密发现 {len(found)} 个地址: {', '.join(sorted(found)[:10])}")
        else:
            print("    [*] 未从AI响应中提取到具体地址（查看报告获取AI分析详情）")
        print(f"    网络地址解密完成 (AI响应长度: {len(result)} 字符)")

    def _poll_task(self, conn, task_id, timeout=180):
        deadline = time.time() + timeout
        while time.time() < deadline:
            resp = conn.send_command("get_task_result", {"task_id": task_id}, timeout=10)
            status = resp.get("status")
            if status == "done":
                data = resp.get("data", {})
                return data
            elif status == "error":
                err_msg = resp.get("data", {}).get("message", "Task errored")
                return {"error": err_msg}
            time.sleep(1)
        return {"error": "Task timed out after %ds" % timeout}

    def _phase2_critical_path(self, analysis_type="explain"):
        label = _L("phase2_vuln") if analysis_type == "vuln" else _L("phase2_explain")
        self._print_header(label)
        t0 = time.time()

        # 查找入口/根函数
        all_callees = set()
        for callees in self._call_tree.values():
            all_callees.update(callees)
        root_funcs = []
        for caller in self._call_tree:
            if caller not in all_callees or caller.lower() in ("main", "winmain", "start", "_start", "entry"):
                root_funcs.append(caller)
        if not root_funcs:
            root_funcs = list(self._call_tree.keys())[:10]

        # 通过BFS构建可达函数集
        reachable = set()
        queue = list(root_funcs)
        while queue:
            func = queue.pop(0)
            if func in reachable:
                continue
            reachable.add(func)
            for callee in self._call_tree.get(func, []):
                if callee not in reachable:
                    queue.append(callee)

        # 函数名到地址的映射
        func_name_to_addr = {}
        for f in self._all_functions:
            func_name_to_addr[f["name"]] = f["address"]

        critical_funcs = []
        stdlib_skipped = 0
        for name in reachable:
            if is_stdlib_function(name):
                stdlib_skipped += 1
                continue
            if name in func_name_to_addr:
                critical_funcs.append({"name": name, "address": func_name_to_addr[name]})

        # ── 按可疑度排序后选取 Top N ──
        rank_fn = _rank_vuln_functions if analysis_type == "vuln" else _rank_functions
        max_deep = min(len(critical_funcs), self.max_critical)
        if critical_funcs:
            # ── 优先保证根函数及其直接子函数被分析（避免入口点被遗漏）──
            root_and_direct = set()
            for root in root_funcs:
                if root in func_name_to_addr and not is_stdlib_function(root):
                    root_and_direct.add(root)
                for callee in self._call_tree.get(root, []):
                    if callee in func_name_to_addr and not is_stdlib_function(callee):
                        root_and_direct.add(callee)
            # 对所有函数打分排序
            all_scored = rank_fn(critical_funcs, self._call_tree, self._all_functions)
            score_label = "漏洞风险分" if analysis_type == "vuln" else "可疑分"
            top3 = all_scored[:3]
            print(f"    最高{score_label}函数: {', '.join(f'{n}({sc})' for n, _, sc in top3)}")
            # forced 数量较少时，强制纳入根函数+直接子函数，剩余名额按分数补齐
            if len(root_and_direct) <= self.max_critical // 2:
                forced_names = root_and_direct
                remaining_funcs = [f for f in critical_funcs if f["name"] not in forced_names]
                scored_remaining = rank_fn(remaining_funcs, self._call_tree, self._all_functions)
                remaining_slots = max(0, max_deep - len(forced_names))
                top_remaining = [{"name": s[0], "address": s[1]} for s in scored_remaining[:remaining_slots]]
                critical_funcs = [{"name": n, "address": func_name_to_addr[n]} for n in forced_names] + top_remaining
                print(f"    根函数及直接子函数强制纳入: {len(forced_names)} 个（{', '.join(sorted(root_and_direct)[:5])}{'...' if len(root_and_direct) > 5 else ''}）")
            else:
                # forced 超过一半名额，直接按分数取 Top N
                sort_label = "漏洞风险度" if analysis_type == "vuln" else "可疑度"
                critical_funcs = [{"name": s[0], "address": s[1]} for s in all_scored[:max_deep]]
                if len(root_and_direct) >= max_deep:
                    print(f"    根函数及直接子函数共 {len(root_and_direct)} 个（已达或超过分析名额 {max_deep}），按{sort_label}排序选取 Top {max_deep}")
                else:
                    print(f"    根函数及直接子函数共 {len(root_and_direct)} 个（超过一半名额），按{sort_label}排序选取 Top {max_deep}")
        print(f"    {_L('critical_path_info', total=len(critical_funcs), skip=stdlib_skipped, max=max_deep)}")
        print(f"    {'使用' if ZH_CN else 'Using'} %d {'个并发工作线程' if ZH_CN else 'concurrent workers'}" % self.max_workers)

        # 并发分析：每个工作线程使用独立连接
        critical_results = [None] * max_deep
        progress_lock = threading.Lock()
        completed = [0]
        is_vuln = (analysis_type == "vuln")

        def analyze_worker(func_list):
            worker_id = threading.current_thread().name
            conn = IDAConnection(self.ida.host, self.ida.port)
            if not conn.connect(timeout=10):
                print(f"[{worker_id}] {_L('cannot_connect')}")
                return
            try:
                for func in func_list:
                    addr = func["address"]
                    name = func["name"]

                    # 获取函数详情
                    detail = conn.send_command("get_function_detail", {"address": addr}, timeout=30)
                    pseudocode = detail.get("data", {}).get("pseudocode", "")
                    if not pseudocode:
                        print(f"[{worker_id}] {_L('cannot_decompile', name=name)}")
                        continue

                    # 根据分析类型启动AI任务
                    if is_vuln:
                        resp = conn.send_command("find_vulnerabilities", {"address": addr}, timeout=10)
                        cmd_name = "vuln"
                    else:
                        resp = conn.send_command("explain_function", {"address": addr}, timeout=10)
                        cmd_name = "explain"
                    task_id = resp.get("data", {}).get("task_id")

                    # 等待任务完成
                    task_result = self._poll_task(conn, task_id, timeout=180) if task_id else {"error": "No task_id"}

                    # 处理结果
                    text = ""
                    is_suspicious = False
                    if task_result and "error" not in task_result:
                        text = task_result.get("analysis", "")
                        if not text:
                            print(f"[{worker_id}] [!] {cmd_name} returned empty for {name}, raw data keys: {list(task_result.keys())}")
                        if text and not is_vuln:
                            conn.send_command("set_comment", {"address": addr, "comment": text, "is_function": True})
                            # ── explain模式的可疑函数检测：基于AI响应关键词 ──
                            _EXPLAIN_SUSPICIOUS_KW = [
                                "C2", "c2", "命令控制", "远控", "远程控制", "键盘记录", "keylog",
                                "进程注入", "process injection", "持久化", "persistence",
                                "数据外泄", "data exfil", "数据窃取", "盗取",
                                "反调试", "anti-debug", "反分析", "环境检测",
                                "C2通信", "回连", "后门", "backdoor",
                                "Hook", "钩子", "SetWindowsHookEx",
                                "加密通信", "encrypted communication", "隐秘",
                                "提权", "privilege escalation", "权限提升",
                                "自启动", "auto-start", "开机启动",
                                "ptrace", "memfd", "LD_PRELOAD", "seccomp",
                                "reverse shell", "crontab", "bashrc",
                                "ssh_key", "authorized_keys", "setuid",
                            ]
                            # ── 否定/免责模式：AI明确排除恶意意图的表述 ──
                            _NEGATION_PATTERNS = [
                                "无可疑", "无明显可疑", "没有可疑", "未发现可疑",
                                "not suspicious", "no suspicious", "not malicious",
                                "no malicious", "无明显恶意", "无恶意", "未发现恶意",
                                "无明显恶意行为", "没有发现恶意", "正常软件", "legitimate",
                                "正常功能", "normal behavior", "常见行为", "common pattern",
                                "无明显问题", "no obvious issue", "未发现明显问题",
                                "属于正常", "是常见的", "is a common", "typical for",
                                "合法程序", "正规软件", "benign",
                            ]
                            text_lower = text.lower()
                            # ── 基于危险API组合的模式检测（shellcode loader检测）──
                            # shellcode loader核心模式：分配可执行内存 + 从外部加载数据 + 间接调用执行
                            _SHELLCODE_PATTERNS = [
                                # 明确的shellcode执行：分配+读取+执行
                                ("virtualalloc", "page_execute", "readfile", "call"),
                                ("virtualalloc", "page_execute", "lpaddress", "call"),
                                # 资源释放执行
                                ("loadresource", "virtualalloc", "page_execute"),
                                # 明确的"执行分配的内存"描述
                                ("allocated memory", "execute", "shellcode"),
                                ("allocated memory", "execute", "payload"),
                                # 可执行内存页
                                ("executable memory", "virtualalloc"),
                                ("可执行内存", "分配"),
                                # 回调执行技巧
                                ("enumcalendar", "shellcode"),
                                ("callwindowproc", "shellcode"),
                                # 简化模式：分配+读取文件+直接调用（无需page_execute关键词）
                                ("virtualalloc", "readfile", "call", "lpaddress"),
                                ("virtualalloc", "readfile", "function pointer", "call"),
                                ("virtualalloc", "readfile", "indirect call"),
                                ("virtualalloc", "loadresource", "call"),
                                # 中文模式
                                ("virtualalloc", "读取文件", "调用"),
                                ("分配内存", "readfile", "函数指针"),
                                ("可执行", "读文件", "执行"),
                            ]
                            for pattern in _SHELLCODE_PATTERNS:
                                if all(kw in text_lower for kw in pattern):
                                    is_suspicious = True
                                    with progress_lock:
                                        self.suspicious_funcs.add(name)
                                    break
                            # 再检查是否为否定/免责场景
                            if not is_suspicious and any(neg in text_lower for neg in _NEGATION_PATTERNS):
                                is_suspicious = False
                            elif not is_suspicious:
                                # 只在非否定场景下做关键词匹配
                                kw_matches = sum(1 for kw in _EXPLAIN_SUSPICIOUS_KW if kw.lower() in text_lower)
                                if kw_matches >= 3:  # 至少3个关键词才标记（提高到3减少误报）
                                    is_suspicious = True
                                    with progress_lock:
                                        self.suspicious_funcs.add(name)
                        if text and is_vuln:
                            conn.send_command("set_comment", {
                                "address": addr,
                                "comment": f"[Vuln Analysis]\n{text}",
                                "is_function": False,
                            })
                            if "未发现" not in text and "未发现明显漏洞" not in text and "no vulnerability" not in text.lower() and "no obvious vulnerabilit" not in text.lower():
                                is_suspicious = True
                                with progress_lock:
                                    self.suspicious_funcs.add(name)
                    elif task_result and "error" in task_result:
                        print(f"[{worker_id}] [×] {cmd_name} task failed for {name}: {task_result.get('error')}")
                    else:
                        print(f"[{worker_id}] [×] {cmd_name} result is None for {name}")

                    result = {
                        "name": name,
                        "address": addr,
                        "explanation": text if not is_vuln else "",
                        "vulnerability_analysis": text if is_vuln else "",
                        "is_suspicious": is_suspicious,
                    }
                    with progress_lock:
                        critical_results[func["_idx"]] = result
                        self.analyzed_funcs.add(name)
                        completed[0] += 1
                    status = "[√]" if text else "[×]"
                    print(f"[{worker_id}] [{completed[0]}/{max_deep}] {status} {name}")
            finally:
                conn.close()

        # 分发任务到工作线程
        tasks = critical_funcs[:max_deep]
        for i, func in enumerate(tasks):
            func["_idx"] = i

        with ThreadPoolExecutor(max_workers=self.max_workers, thread_name_prefix="Worker") as executor:
            batches = [[] for _ in range(self.max_workers)]
            for i, func in enumerate(tasks):
                batches[i % self.max_workers].append(func)
            futures = [executor.submit(analyze_worker, batch) for batch in batches if batch]
            for f in as_completed(futures):
                try:
                    f.result()
                except Exception as e:
                    print(f"[!] Worker error: {e}")

        critical_results = [r for r in critical_results if r is not None]

        elapsed = time.time() - t0
        self.results["phase2_critical_path"] = {
            "duration_seconds": round(elapsed, 1),
            "root_functions": root_funcs,
            "reachable_count": len(reachable),
            "stdlib_functions_skipped": stdlib_skipped,
            "analyzed_count": len(critical_results),
            "functions": critical_results,
            "suspicious_functions": list(self.suspicious_funcs),
        }

        print(f"    Phase 2 completed in {elapsed:.1f}s")
        print(f"    {self._s('suspicious_label')}: {list(self.suspicious_funcs)}")

    def _phase3_full_scan(self):
        self._print_header(_L("phase3"))
        t0 = time.time()

        analyzed_names = {f["name"] for f in self.results.get("phase2_critical_path", {}).get("functions", [])}
        stdlib_skipped = 0
        remaining = []
        for f in self._all_functions:
            if f["name"] in analyzed_names:
                continue
            if is_stdlib_function(f["name"]):
                stdlib_skipped += 1
                continue
            remaining.append(f)

        # ── 按可疑度排序后选取 Top N ──
        if remaining and self.max_full_scan > 0:
            scored = _rank_functions(remaining, self._call_tree, self._all_functions)
            original_count = len(remaining)
            remaining = [{"name": s[0], "address": s[1]} for s in scored]
            if len(remaining) > self.max_full_scan:
                remaining = remaining[:self.max_full_scan]
                print(f"    剩余 {original_count} 个用户函数，按可疑度排序后选取 Top {self.max_full_scan}")
            else:
                print(f"    {_L('remaining_info', count=len(remaining), skip=stdlib_skipped)}")
        else:
            print(f"    {_L('remaining_info', count=len(remaining), skip=stdlib_skipped)}")
        print(f"    {'使用' if ZH_CN else 'Using'} %d {'个并发工作线程' if ZH_CN else 'concurrent workers'}" % self.max_workers)

        remaining_results = [None] * len(remaining)
        progress_lock = threading.Lock()
        completed = [0]

        def scan_worker(func_list):
            worker_id = threading.current_thread().name
            conn = IDAConnection(self.ida.host, self.ida.port)
            if not conn.connect(timeout=10):
                return
            try:
                for func in func_list:
                    addr = func["address"]
                    name = func["name"]

                    # 启动explain任务
                    explain_resp = conn.send_command("explain_function", {"address": addr}, timeout=10)
                    explain_task_id = explain_resp.get("data", {}).get("task_id")
                    explain_text = ""
                    if explain_task_id:
                        explain_data = self._poll_task(conn, explain_task_id, timeout=180)
                        if "error" not in explain_data:
                            explain_text = explain_data.get("analysis", "")
                            if not explain_text:
                                print(f"[{worker_id}] {_L('empty_analysis', wid=worker_id, name=name, keys=list(explain_data.keys()) if explain_data else 'none')}")
                            if explain_text:
                                conn.send_command("set_comment", {"address": addr, "comment": explain_text, "is_function": True})
                        else:
                            print(f"[{worker_id}] {_L('analysis_fail_msg', wid=worker_id, name=name, err=explain_data.get('error'))}")
                    else:
                        print(f"[{worker_id}] {_L('no_taskid', wid=worker_id, name=name)}")

                    # 无论成功失败都计数
                    with progress_lock:
                        self.analyzed_funcs.add(name)

                    idx = func["_idx"]
                    remaining_results[idx] = {
                        "name": name,
                        "address": addr,
                        "explanation": explain_text[:200] if explain_text else "",
                        "full_explanation": explain_text,
                    }
                    with progress_lock:
                        completed[0] += 1
                        if completed[0] % 10 == 0 or completed[0] == len(remaining):
                            print(f"[{worker_id}] [{completed[0]}/{len(remaining)}] done")
            finally:
                conn.close()

        for i, func in enumerate(remaining):
            func["_idx"] = i

        with ThreadPoolExecutor(max_workers=self.max_workers, thread_name_prefix="ScanWorker") as executor:
            batches = [[] for _ in range(self.max_workers)]
            for i, func in enumerate(remaining):
                batches[i % self.max_workers].append(func)
            futures = [executor.submit(scan_worker, batch) for batch in batches if batch]
            for f in as_completed(futures):
                try:
                    f.result()
                except Exception as e:
                    print(f"[!] Scan worker error: {e}")

        remaining_results = [r for r in remaining_results if r is not None]

        elapsed = time.time() - t0
        self.results["phase3_full_scan"] = {
            "duration_seconds": round(elapsed, 1),
            "stdlib_functions_skipped": stdlib_skipped,
            "scanned_count": len(remaining_results),
            "functions": remaining_results,
        }

        print(f"    {_L('phase3_done', time=elapsed)}")

    def _generate_conclusion(self):
        """综合分析所有阶段的数据，让AI做出最终判定"""
        self._print_header("综合判定程序目的")

        if not self.ai.available:
            print("    AI引擎不可用，跳过综合判定。")
            self.results["final_conclusion"] = "AI引擎不可用，无法进行综合判定。"
            return

        p1 = self.results.get("phase1_global_scan", {})
        p2 = self.results.get("phase2_critical_path", {})
        p3 = self.results.get("phase3_full_scan", {})
        bi = self.results.get("binary_info", {})

        # ── 构建综合证据 ──
        cats = p1.get("suspicious_string_categories", {})
        categories_summary = {}
        for cat_name, cat_items in cats.items():
            if cat_items:
                label_map = {
                    "networking": "网络通信/C2",
                    "keylogging": "键盘记录/输入钩子",
                    "crypto": "加密/解密",
                    "injection": "进程/线程注入",
                    "persistence": "持久化/自启动",
                    "antianalysis": "反分析/反调试",
                    "dropper": "文件投放/Dropper",
                    "code_execution": "代码执行/Shellcode加载",
                    "memory_file_ops": "内存/文件操作",
                    "installer_framework": "安装程序框架",
                }
                categories_summary[label_map.get(cat_name, cat_name)] = cat_items[:10]

        # 关键路径分析摘要（取可疑函数）
        suspicious_phase2 = []
        for f in p2.get("functions", []):
            if f.get("is_suspicious"):
                suspicious_phase2.append({
                    "name": f["name"],
                    "address": f["address"],
                    "summary": f.get("explanation", f.get("vulnerability_analysis", ""))[:300],
                })

        # 全量扫描摘要（取前20个函数的简要说明）
        phase3_summaries = []
        for f in p3.get("functions", [])[:20]:
            if f.get("explanation"):
                phase3_summaries.append({
                    "name": f["name"],
                    "address": f["address"],
                    "summary": f["explanation"][:200],
                })

        # 调用树摘要
        call_tree = p1.get("call_tree", {})
        call_tree_sample = dict(list(call_tree.items())[:50])

        # 网络地址提取
        net_addr = p1.get("network_addresses", {})
        has_network = bool(categories_summary.get("networking")) or bool(net_addr.get("domains")) or bool(net_addr.get("urls")) or bool(net_addr.get("ips"))
        net_addr_context = ""
        if has_network:
            net_parts = []
            if net_addr.get("domains"):
                net_parts.append(f"Domains found: {json.dumps(net_addr['domains'], ensure_ascii=False)}")
            if net_addr.get("ips"):
                net_parts.append(f"IP addresses found: {json.dumps(net_addr['ips'])}")
            if net_addr.get("urls"):
                net_parts.append(f"URLs found: {json.dumps(net_addr['urls'][:15], ensure_ascii=False)}")
            if net_addr.get("ports"):
                net_parts.append(f"Non-standard ports found: {sorted(net_addr['ports'])}")
            net_addr_context = "\n".join(net_parts)
        else:
            net_addr_context = "(no network addresses found)"

        lang_instruction = "用简体中文回答" if ZH_CN else "Respond in English"

        context = f"""=== Binary Info ===
File: {bi.get('idb_name', 'unknown')}
Architecture: {bi.get('arch', 'unknown')}
Total functions: {bi.get('func_count', 0)}
Analysis mode: {self.mode}

=== Phase 1: Static String Analysis ===
Total strings found: {p1.get('string_count', 0)}
Suspicious indicator categories found: {len(categories_summary)}

{chr(10).join(f'--- {cat_name} ({len(items)} items) ---{chr(10)}' + chr(10).join(items[:8]) for cat_name, items in categories_summary.items()) if categories_summary else "(no suspicious string categories found)"}

=== Phase 2: Critical Path Analysis ({p2.get('analyzed_count', 0)} functions analyzed) ===
Suspicious functions flagged by AI ({len(suspicious_phase2)}):
{json.dumps(suspicious_phase2[:15], ensure_ascii=False, indent=2) if suspicious_phase2 else "(no functions flagged as suspicious)"}

=== Phase 3: Full Scan ({p3.get('scanned_count', 0)} functions scanned) ===
Sample analysis results:
{json.dumps(phase3_summaries[:10], ensure_ascii=False, indent=2) if phase3_summaries else "(no phase 3 data)"}

=== Call Tree (partial, 50 entries) ===
{json.dumps(call_tree_sample, indent=2, ensure_ascii=False)}

=== Network Addresses ===
{net_addr_context}

You are a senior malware analyst and reverse engineer. Based on ALL the evidence above from multiple analysis phases, provide a comprehensive and objective conclusion about this binary's purpose.

GUIDELINES:
1. Synthesize evidence across ALL phases — do NOT rely on any single indicator.
2. SHELLCODE LOADER DETECTION — the definitive pattern is: allocate executable memory (VirtualAlloc/Mmap) + load external data into it (ReadFile/LoadResource/recv/WriteProcessMemory) + INDIRECT CALL to the buffer (e.g., `(lpAddress)()`, `CreateThread`, `ShellExecute`). This pattern ALONE is sufficient to classify as a shellcode loader. The presence of a GUI, installer UI, or decoy content does NOT negate this — many loaders use a decoy.
3. EXECUTABLE MEMORY + EXTERNAL DATA = SHELLCODE LOADER: If the code allocates memory (especially with execute permissions like PAGE_EXECUTE or 0x40) and fills it from an EXTERNAL FILE or NETWORK SOURCE (not embedded resources), then executes that buffer, this IS a shellcode loader. Do not dismiss it as "normal" even if a GUI or installer is present.
4. GUI-AS-DECOY is common in shellcode loaders: A legitimate-looking GUI (image viewer, installer, updater) that opens a decoy file while loading and executing shellcode in the background. If the binary allocates executable memory and calls it as code, the GUI is a decoy — period.
5. Installers and legitimate software DO use VirtualAlloc/ReadFile, but they DO NOT cast a file-read buffer to a function pointer and call it. If the pseudocode shows `((void (*)(void))buffer)()` or equivalent, it is NOT a legitimate installer — it is a shellcode loader.
6. Many legitimate applications use security-sensitive Windows APIs. This alone is not suspicious. However, the specific combination of: (a) allocating executable memory + (b) loading unverified external data into it + (c) directly executing that buffer = shellcode loader, NOT normal behavior.
7. Suspicious API combinations that indicate loader behavior: VirtualAlloc/VirtualAllocEx + PAGE_EXECUTE + ReadFile/CreateFile + function pointer cast to buffer + CreateThread. Also watch for callback-based execution (EnumCalendarInfo, CallWindowProc) used to execute shellcode.
8. Distinguish between: (a) executable memory + external data + indirect CALL = confirmed shellcode loader, (b) executable memory for JIT/decompression + NO indirect call = needs further investigation, (c) normal API usage without executable memory = not suspicious.
9. If evidence is inconclusive but there are strong indicators (e.g., executable memory allocation with obscure data loading patterns), classify as "potentially unwanted" or "suspicious" rather than "legitimate" — err on the side of caution.
10. Only classify as "legitimate application" if there is NO executable memory allocation followed by indirect execution, AND the observed API usage is consistent with the claimed application type.
11. INSTALLER FRAMEWORK DETECTION: If the "安装程序框架" (installer_framework) category contains strings like MsiExecute, MsiSetProperty, InstallShield, ISExternalUI, ISScript, Windows Installer — the binary is almost certainly a legitimate installer package. In this case, APIs that appear in injection/persistence/antianalysis categories (WriteProcessMemory, RegSetValue, IsDebuggerPresent, NtQueryInformationProcess, CreateRemoteThread) are NORMAL for InstallShield/MSI installers and should NOT be treated as malicious indicators unless combined with executable-memory+indirect-call patterns. InstallShield uses WriteProcessMemory for file extraction, RegSetValue for registry configuration, and IsDebuggerPresent for setup debugging — all benign in an installer context.
12. When installer_framework strings are present: the primary conclusion should be "legitimate installer" unless there is independent evidence of shellcode loading (VirtualAlloc + ReadFile + indirect call) that cannot be explained by the installer framework itself.
13. MEMORY+FILE without indirect call: If Phase 1 finds VirtualAlloc + ReadFile strings but NO analyzed function shows the pattern of casting a buffer to a function pointer and calling it, classify as "needs further investigation" rather than "confirmed malicious" — but do NOT dismiss it as "legitimate" either.
14. NETWORK ADDRESS EXTRACTION: If the binary has network communication capabilities (socket, connect, WSA, WinINet APIs), examine the Phase 2/3 function analyses for any code that constructs, decrypts, or obfuscates server addresses. Common techniques include: (a) XOR-decoded strings (e.g., buffer XOR with key producing a domain name), (b) string concatenation (e.g., building URLs from split parts like "http://" + "svchosta" + ".com"), (c) Base64-encoded addresses decoded at runtime, (d) addresses loaded from config files at known paths (e.g., .ini, .cfg, registry keys). When you see these patterns in the analyzed functions, describe them in the NETWORK ADDRESSES section — include the function name, the method of obfuscation, and the likely resolved address.

{lang_instruction}. Structure your response:
1. **Overall classification**: (legitimate application / potentially unwanted / dual-purpose / likely malicious / inconclusive) — confidence: high/medium/low
2. **Evidence summary**: list the strongest indicators for AND against maliciousness
3. **Confirmed capabilities**: list each with evidence from which phase(s)
4. **Normal behavior explanation**: if classified as legitimate, explain why the observed API usage is normal for this type of software (e.g., installer uses VirtualAlloc for decompression, FTP client uses WinHTTP)
5. **Shellcode/Loader check**: explicitly state whether the binary allocates executable memory and DIRECTLY CALLS it as code (the definitive shellcode indicator) — OR if it only allocates memory for normal purposes (decompression, extraction, threading)
6. **Risk assessment**: if any concerns exist, specify what they are and how a user could verify safety
7. **NETWORK ADDRESSES**: If the binary has network communication capabilities, list ALL discovered server addresses. Include: (a) hardcoded IPs and domains from strings, (b) URLs and endpoints, (c) ports used, (d) if addresses appear encrypted or obfuscated, describe which function(s) handle decryption and what the decrypted values likely are based on the code analysis, (e) any configuration file paths where addresses are stored (e.g., .ini files, registry keys). Format each address with its context and purpose (e.g., "C2 server: svchosta.com:28001 (from sub_1001DA70, loaded from C:\ProgramData\%d.ini)", "QQ login: ssl.ptlogin2.qq.com (credential phishing target)").
8. **Final conclusion**: what is the most likely true purpose of this binary — this should be your definitive summary, synthesizing all evidence above into a clear statement of the binary's true purpose and threat level.
"""

        print(f"    综合 {p1.get('string_count', 0)} 条字符串 + {p2.get('analyzed_count', 0)} 个关键函数分析 + {p3.get('scanned_count', 0)} 个全量扫描结果...")
        conclusion = self.ai.query(context, max_tokens=4096)
        if "[AI error:" in conclusion:
            print("[!] 综合判定AI失败。")
            conclusion = _L("ai_unavail")

        self.results["final_conclusion"] = conclusion

        # 打印综合判定结果到控制台
        print(f"\n{'='*60}")
        print(f"  综合判定结果")
        print(f"{'='*60}")
        print(conclusion)
        print(f"{'='*60}\n")
        print(f"    综合判定完成 (响应长度: {len(conclusion)} 字符)")

    def _generate_report(self):
        self._print_header(_L("generating_report"))

        # ── 报告完整性校验：确保有实质性内容 ──
        p2_funcs = self.results.get("phase2_critical_path", {}).get("functions", [])
        p3_funcs = self.results.get("phase3_full_scan", {}).get("functions", [])
        empty_phase2 = sum(1 for f in p2_funcs if not f.get("explanation") and not f.get("vulnerability_analysis"))
        if p2_funcs and empty_phase2 == len(p2_funcs):
            print("    [!] 警告: Phase 2所有函数分析返回空，报告内容可能不完整。")
        if not self.analyzed_funcs:
            print("    [!] 警告: 没有分析任何函数，报告仅包含静态扫描数据。")

        total_duration = (
            self.results["phase1_global_scan"].get("duration_seconds", 0)
            + self.results["phase2_critical_path"].get("duration_seconds", 0)
            + self.results["phase3_full_scan"].get("duration_seconds", 0)
        )

        self.results["summary"] = {
            "mode": self.mode,
            "total_duration_seconds": round(total_duration, 1),
            "total_functions_analyzed": len(self.analyzed_funcs),
            "stdlib_functions_skipped": (
                self.results["phase2_critical_path"].get("stdlib_functions_skipped", 0)
                + self.results["phase3_full_scan"].get("stdlib_functions_skipped", 0)
            ),
            "suspicious_function_count": len(self.suspicious_funcs),
            "suspicious_functions": list(self.suspicious_funcs),
            "binary_purpose": self.results.get("final_conclusion", "") if self.mode != "vuln" else "",
        }

        # 保存JSON报告
        suffix = f"-{self.mode}"
        json_path = os.path.join(self.output_dir, f"analysis_report{suffix}.json")
        with open(json_path, "w", encoding="utf-8") as f:
            json.dump(self.results, f, ensure_ascii=False, indent=2, default=str)
        print(f"    {_L('json_report', path=json_path)}")

        # 保存Markdown报告
        md_path = os.path.join(self.output_dir, f"analysis_report{suffix}.md")
        self._write_markdown_report(md_path)
        print(f"    {_L('md_report', path=md_path)}")

    def _extract_network_addresses(self, strings):
        """Extract network addresses from strings (IP, domain, URL, port)"""
        addresses = {"ips": [], "domains": [], "urls": [], "ports": []}
        seen_ips = set()
        seen_domains = set()
        seen_urls = set()
        seen_ports = set()

        # 白名单：排除常见合法域名/URL前缀
        _BENIGN_PREFIXES = [
            "microsoft.com/pki", "microsoft.com/pkistamps",
            "verisign.com", "verisign.net", "thawte.com",
            "digicert.com", "globalsign.com", "comodo.com",
            "google.com/pki", "amazontrust.com",
            "entrust.net", "geotrust.com", "rapidssl.com",
            "pki.goog", "letsencrypt.org", "isrg.org",
            "ocsp.", "crl.", "crl.",
            "www.w3.org", "schemas.xmlsoap.org",
            "t1.gstatic.com", "crl.usertrust.com",
            # Go 语言基础设施
            "go.dev/issue", "golang.org",
        ]

        # 常见软件/系统 benign 域名
        _BENIGN_DOMAINS = [
            "schemas.microsoft.com", "ns.adobe.com",
            "www.w3.org", "xml.apache.org",
            "java.sun.com", "xmlns.jcp.org",
            # Go 语言基础设施
            "go.dev", "golang.org",
        ]

        # Go 语言包名白名单：防止 fmt.pp、net.ip 等被误识别为域名
        _GO_PKG_TLDS = {
            "pp", "ip", "fmt", "shape", "file", "url", "ret", "fd", "nih",
            "ctr", "gcm", "int", "nat", "conn", "aead", "addr", "kind",
            "type", "name", "itab", "oid", "kem", "kdf", "word", "tag",
            "state", "writer", "reader", "closer", "body", "zone", "time",
            "abbr", "pool", "cond", "once", "alert", "error", "netfd",
            "flags", "scope", "rand", "list", "tflag", "hash", "block",
            "stack", "form", "iter", "flag", "hmac", "sha3", "buffer",
            "discard", "timer", "dirinfo", "rawconn", "timeout", "mutex",
            "eface", "config", "values", "ipmask", "ipaddr", "ipconn",
            "ipattr", "result", "byname", "dialer", "node", "funcid",
            "table", "opt", "cache", "client", "server", "request",
            "response", "header", "cookie", "proxy", "trace", "tracefns",
            "tlsrecord", "record", "cipher", "key", "cert", "chain",
            "chainkey", "hashkey", "enc", "dec", "keylog", "log",
            "cipher_suites", "sni", "ext", "version", "curve", "group",
            "ecdsa", "ed25519", "rsa", "dh", "x25519", "nist", "p256",
            "p384", "p521", "curves", "curveid",
            # ABI / 编译器相关
            "abi", "ret", "jmp", "call", "args", "frame", "stack",
        }

        def _is_benign(s):
            sl = s.lower().strip()
            for prefix in _BENIGN_PREFIXES:
                if sl.startswith("http://" + prefix) or sl.startswith("https://" + prefix) or sl.startswith(prefix):
                    return True
            for domain in _BENIGN_DOMAINS:
                if sl == domain or sl.endswith("." + domain):
                    return True
            return False

        for s in strings:
            content = s['content']

            # IPv4 地址（排除纯localhost/127.0.0.1等）
            # Go 运行时版本号/IP段常量（如 2.5.4.x 是 Go net 包的测试/示例IP）
            _BENIGN_IP_PREFIXES = ("2.5.4.",)
            # 已知公共 DNS/公共 IP
            _BENIGN_IPS = {
                "1.1.1.1", "1.0.0.1",        # Cloudflare DNS
                "8.8.8.8", "8.8.4.4",        # Google DNS
                "9.9.9.9",                    # Quad9 DNS
                "208.67.222.222", "208.67.220.220",  # OpenDNS
                "114.114.114.114",            # 114 DNS (China)
                "223.5.5.5", "223.6.6.6",    # AliDNS (China)
            }
            for ip_match in re.finditer(r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(?::(\d+))?\b', content):
                ip = ip_match.group(1)
                port = ip_match.group(2)
                octets = ip.split('.')
                if not all(0 <= int(o) <= 255 for o in octets):
                    continue
                if ip in ("0.0.0.0", "255.255.255.255"):
                    continue
                # 排除 Go 运行时版本号/IP段常量
                if ip.startswith(_BENIGN_IP_PREFIXES):
                    continue
                # 排除已知公共 DNS
                if ip in _BENIGN_IPS:
                    continue
                if ip not in seen_ips:
                    seen_ips.add(ip)
                    addresses["ips"].append(ip)
                if port and port not in seen_ports:
                    seen_ports.add(port)
                    addresses["ports"].append(int(port))

            # URL
            for url_match in re.finditer(r'(https?://[^\s<>"\'\)\}\]]+)', content):
                url = url_match.group(1).rstrip('.,;:')
                # 清理URL末尾可能混入的证书DER数据
                # 如 vslogo.gif04 → vslogo.gif, crl0D → crl, cps0* → cps
                url = re.sub(r'[0-9]+[A-Za-z*]*$', '', url)
                if not url or len(url) < 10:
                    continue
                if not _is_benign(url) and url not in seen_urls:
                    seen_urls.add(url)
                    addresses["urls"].append(url)
                    # 从URL中提取域名
                    domain_match = re.search(r'https?://([^/:]+)', url)
                    if domain_match:
                        domain = domain_match.group(1).lower()
                        if not _is_benign(domain) and domain not in seen_domains:
                            seen_domains.add(domain)
                            addresses["domains"].append(domain)

            # 域名（排除已知的常见 benign 域名模式）
            # 文件扩展名黑名单：排除 dll/exe/sys 等文件后缀误匹配为域名
            _FILE_EXTENSIONS = {
                "dll", "exe", "sys", "ini", "txt", "cfg", "conf", "dat",
                "log", "bat", "cmd", "tmp", "temp",
                "drv", "ocx", "tlb", "lib", "pdb", "map", "idx",
                "res", "rc", "hpp", "cpp", "cs",
                "xml", "json", "yaml", "yml", "toml", "env",
                "html", "htm", "css", "js", "py", "rb", "go",
                "reg", "inf", "ps1", "vbs", "wsf",
                # 图片/证书/资源文件后缀（URL路径中常见）
                "gif", "png", "jpg", "jpeg", "ico", "bmp", "svg",
                "cer", "crt", "pem", "der", "pfx", "p12",
                "html", "htm", "css", "js",
            }
            for domain_match in re.finditer(r'\b([a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?)+)\b', content):
                domain = domain_match.group(1).lower()
                parts = domain.split('.')
                # 排除纯数字（IP地址）
                if all(p.isdigit() for p in parts):
                    continue
                # 排除短的单标签/双标签和常见TLD
                if len(parts) < 2:
                    continue
                tld = parts[-1]
                # 排除TLD中包含数字的（如 gif04、cr0d → 非合法TLD，通常是证书DER字节混入）
                if re.search(r'\d', tld):
                    continue
                # 排除文件扩展名（如 kernel32.dll → tld="dll"）
                if tld in _FILE_EXTENSIONS:
                    continue
                # 排除 Go 语言包名（如 fmt.pp → tld="pp"）
                if tld in _GO_PKG_TLDS:
                    continue
                # 排除过短的后缀（<2字符的TLD基本不存在）
                if len(tld) < 2:
                    continue
                if _is_benign(domain):
                    continue
                # 排除太短的（可能是缩写/变量名）
                if len(domain) < 5:
                    continue
                if domain in seen_domains:
                    continue
                seen_domains.add(domain)
                addresses["domains"].append(domain)

        # 端口号：匹配常见的端口模式字符串
        for s in strings:
            content = s['content']
            # 匹配 "Port" / "port" 后面的数字
            for port_match in re.finditer(r'(?i)(?:port|端口)[\s:=]*?(\d{2,5})\b', content):
                port = int(port_match.group(1))
                if 1 <= port <= 65535 and port not in (80, 443) and str(port) not in seen_ports:
                    seen_ports.add(str(port))
                    addresses["ports"].append(port)

        return addresses

    def _write_markdown_report(self, path):
        lines = []
        lines.append(f"# {_L('report_title')}")
        lines.append("")
        lines.append(f"**Generated:** {self.results['metadata']['timestamp']}")
        lines.append(f"**Binary:** {self.results['binary_info'].get('idb_name', 'unknown')}")
        lines.append(f"**Architecture:** {self.results['binary_info'].get('arch', 'unknown')}")
        lines.append(f"**Functions:** {self.results['binary_info'].get('func_count', 0)}")
        lines.append(f"**Mode:** {self.mode.upper()}")
        lines.append(f"**Total Duration:** {self.results['summary'].get('total_duration_seconds', 0):.1f}s")
        lines.append("")

        # ── vuln 模式专用报告结构 ──
        if self.mode == "vuln":
            self._write_vuln_report(lines)
        else:
            self._write_normal_report(lines)

        p1 = self.results.get("phase1_global_scan", {})
        p2 = self.results["phase2_critical_path"]
        p3 = self.results.get("phase3_full_scan", {})

        lines.append(_L("stats_section"))
        lines.append("")
        if p1.get("duration_seconds", 0) > 0:
            lines.append(f"- {_L('phase1_label')}: {p1['duration_seconds']:.1f}s")
        lines.append(f"- {_L('phase2_label')}: {p2.get('duration_seconds', 0):.1f}s ({_L('stdlib_skip', count=p2.get('stdlib_functions_skipped', 0))})")
        if p3.get("scanned_count") is not None or p3.get("stdlib_functions_skipped") is not None:
            lines.append(f"- {_L('phase3_label')}: {p3.get('duration_seconds', 0):.1f}s ({_L('stdlib_skip', count=p3.get('stdlib_functions_skipped', 0))})")
        else:
            lines.append(f"- {_L('phase3_label')}: {_L('phase3_skip')}")
        lines.append(f"- {_L('total_analyzed')}: {len(self.analyzed_funcs)}")
        lines.append(f"- {self._s('suspicious_label')}: {len(self.suspicious_funcs)}")
        lines.append("")
        lines.append("---")
        lines.append(_L("report_footer"))

        with open(path, "w", encoding="utf-8") as f:
            f.write("\n".join(lines))

    def _extract_vuln_types(self, text):
        """从漏洞分析文本中提取漏洞类型"""
        vuln_types = []
        type_patterns = {
            "缓冲区溢出": ["缓冲区溢出", "buffer overflow", "buffer overrun", "栈溢出", "stack overflow", "stack buffer"],
            "格式化字符串": ["格式化字符串", "format string", "format str"],
            "释放后重用": ["use[- ]after[- ]free", "释放后重", "dangling pointer", "悬空指针"],
            "堆溢出": ["heap overflow", "堆溢出", "heap corruption", "堆损坏"],
            "空指针解引用": ["null pointer", "空指针", "null dereference", "NULL dereference"],
            "整数溢出": ["integer overflow", "整数溢出", "int overflow", "integer wrap"],
            "竞态条件": ["race condition", "竞态条件", "concurrency", "线程竞争"],
            "类型混淆": ["type confusion", "类型混淆", "type mismatch"],
            "双重释放": ["double free", "双重释放"],
            "越界读写": ["out-of-bounds", "越界", "out of bounds", "OOB", "off-by-one", "off-by-"],
            "命令注入": ["command injection", "命令注入", "os command injection"],
            "SQL注入": ["sql injection", "SQL 注入", "sql注入"],
            "路径遍历": ["path traversal", "路径遍历", "directory traversal", "目录遍历"],
            "内存泄漏": ["memory leak", "内存泄漏", "resource leak"],
        }
        for vuln_type, patterns in type_patterns.items():
            for pattern in patterns:
                if re.search(pattern, text, re.IGNORECASE):
                    if vuln_type not in vuln_types:
                        vuln_types.append(vuln_type)
                    break
        return vuln_types

    def _extract_network_section(self, conclusion):
        """从 AI 结论中提取 NETWORK ADDRESSES 部分"""
        if not conclusion:
            return ""

        # 匹配多种可能的标题格式（现在网络地址在第7项，最终结论在第8项）
        # 需要停在"最终结论"之前
        patterns = [
            r'(?m)^#{1,3}\s*\*\*NETWORK ADDRESSES\*\*(.*?)(?=^#{1,3}\s+\*?\*|^\d+\.\s*\*\*Final conclusion|^\*\*Final conclusion|---\s*$|$)',
            r'(?m)^#{1,3}\s*\*\*网络地址\*\*(.*?)(?=^#{1,3}\s+\*?\*|^\d+\.\s*\*\*最终结论|^\*\*最终结论|---\s*$|$)',
            r'(?m)^#{1,3}\s*NETWORK ADDRESSES(.*?)(?=^#{1,3}\s+\*?\*|^\d+\.\s*\*\*Final conclusion|---\s*$|$)',
            r'(?m)^#{1,3}\s*网络地址(.*?)(?=^#{1,3}\s+\*?\*|^\d+\.\s*\*\*最终结论|---\s*$|$)',
            r'(?m)^\d+\.\s*\*\*NETWORK ADDRESSES\*\*(.*?)(?=\n\d+\.\s+\*\*|^\d+\.\s*\*\*Final conclusion|---\s*$|$)',
            r'(?m)^\d+\.\s*\*\*网络地址\*\*(.*?)(?=\n\d+\.\s+\*\*|^\d+\.\s*\*\*最终结论|---\s*$|$)',
            r'(?m)^\*\*NETWORK ADDRESSES\*\*\s*[:：]?(.*?)(?=\n\d+\.\s+\*\*|^\*\*Final conclusion|^\*\*最终结论|^\d+\.\s*\*\*Final conclusion|---\s*$|$)',
            r'(?m)^\*\*网络地址\*\*\s*[:：]?(.*?)(?=\n\d+\.\s+\*\*|^\*\*Final conclusion|^\*\*最终结论|^\d+\.\s*\*\*Final conclusion|---\s*$|$)',
        ]

        for pattern in patterns:
            match = re.search(pattern, conclusion, re.DOTALL)
            if match:
                text = match.group(0).strip()
                # 清理末尾的分隔符
                text = re.sub(r'\s*---+\s*$', '', text)
                return text
        return ""

    def _clean_vuln_text(self, text):
        """清理漏洞分析文本，去除标记和提示词"""
        # 去除 WPeChat 标记
        text = re.sub(r'---WPeChat_VulnFinder_START---\s*', '', text)
        text = re.sub(r'\s*---WPeChat_VulnFinder_END---\s*', '', text)
        # 去除重复的prompt部分（如果有）
        return text.strip()

    def _write_vuln_report(self, lines):
        """漏洞模式专用报告：高危漏洞总结 + 高危函数及漏洞成因"""
        phase2_funcs = self.results["phase2_critical_path"].get("functions", [])

        # 收集高危函数
        vuln_funcs = []
        for func in phase2_funcs:
            if not func.get("is_suspicious"):
                continue
            raw_text = func.get("vulnerability_analysis", "")
            if not raw_text:
                continue
            vuln_types = self._extract_vuln_types(raw_text)
            clean_text = self._clean_vuln_text(raw_text)
            vuln_funcs.append({
                "name": func["name"],
                "address": func["address"],
                "vuln_types": vuln_types,
                "analysis": clean_text,
            })

        # 统计漏洞类型
        vuln_type_counts = {}
        for vf in vuln_funcs:
            for vt in vf["vuln_types"]:
                vuln_type_counts[vt] = vuln_type_counts.get(vt, 0) + 1

        # ── 第一部分：高危漏洞总结 ──
        lines.append("## 高危漏洞总结")
        lines.append("")
        lines.append("")

        if vuln_funcs:
            # 概述
            lines.append(f"**高危函数数量：{len(vuln_funcs)}**")
            lines.append("")
            lines.append(f"**漏洞类型数量：{len(vuln_type_counts)}**")
            lines.append("")

            if vuln_type_counts:
                lines.append("**漏洞类型分布：**")
                lines.append("")
                # 按出现次数降序排列
                sorted_types = sorted(vuln_type_counts.items(), key=lambda x: x[1], reverse=True)
                for vtype, count in sorted_types:
                    lines.append(f"- {vtype}：{count} 个函数")
                lines.append("")
        else:
            lines.append("**未发现高危漏洞。**")
            lines.append("")
            lines.append(f"共分析 {len(phase2_funcs)} 个关键路径函数，均未发现明显漏洞。")
            lines.append("")

        # ── 第二部分：高危函数及其漏洞成因 ──
        if vuln_funcs:
            lines.append("")
            lines.append("## 高危函数及其漏洞成因")
            lines.append("")
            for vf in vuln_funcs:
                lines.append(f"### {vf['name']} (`{vf['address']}`)")
                lines.append("")
                if vf["vuln_types"]:
                    lines.append(f"**漏洞类型：**{'、'.join(vf['vuln_types'])}")
                    lines.append("")
                lines.append("**漏洞成因：**")
                lines.append("")
                lines.append(vf["analysis"])
                lines.append("")

    def _write_normal_report(self, lines):
        """非漏洞模式报告（full / light）"""
        # 程序目的分析
        lines.append(_L("purpose_section"))
        lines.append("")
        purpose = self.results["summary"].get("binary_purpose", "N/A")
        lines.append(purpose)
        lines.append("")

        # ── 网络地址提取（仅在有网络连接时显示）──
        p1 = self.results.get("phase1_global_scan", {})
        net_addr = p1.get("network_addresses", {})
        decrypted = p1.get("decrypted_addresses", {})
        has_network = bool(p1.get("suspicious_string_categories", {}).get("networking"))

        if has_network and (net_addr.get("domains") or net_addr.get("ips") or net_addr.get("urls") or net_addr.get("ports") or decrypted):
            lines.append("## 网络地址提取")
            lines.append("")

            # ── 解密提取的地址 ──
            if decrypted and decrypted.get("status") == "success":
                lines.append("### AI 解密分析")
                lines.append("")
                if decrypted.get("extracted_domains"):
                    lines.append(f"**解密发现 {len(decrypted['extracted_domains'])} 个地址：**")
                    lines.append("")
                    for domain in sorted(decrypted["extracted_domains"]):
                        lines.append(f"- `{domain}`")
                    lines.append("")
                # 完整的AI解密分析
                if decrypted.get("ai_response"):
                    lines.append("**完整解密分析：**")
                    lines.append("")
                    lines.append(decrypted["ai_response"])
                    lines.append("")
                if decrypted.get("functions_analyzed"):
                    lines.append(f"**分析的函数：**{'、'.join(decrypted['functions_analyzed'][:8])}")
                    lines.append("")

            # 从 AI 结论中提取 NETWORK ADDRESSES 部分
            conclusion = self.results.get("final_conclusion", "")
            net_section = self._extract_network_section(conclusion)
            if net_section:
                lines.append("### 地址汇总")
                lines.append("")
                lines.append(net_section)
                lines.append("")

            # 静态字符串中提取的地址
            if net_addr.get("domains") or net_addr.get("ips") or net_addr.get("urls") or net_addr.get("ports"):
                lines.append("**静态字符串提取：**")
                lines.append("")
                if net_addr.get("domains"):
                    lines.append(f"- 域名 ({len(net_addr['domains'])} 个)：{'、'.join(net_addr['domains'][:20])}{'...' if len(net_addr['domains']) > 20 else ''}")
                if net_addr.get("ips"):
                    lines.append(f"- IP 地址 ({len(net_addr['ips'])} 个)：{'、'.join(net_addr['ips'][:20])}{'...' if len(net_addr['ips']) > 20 else ''}")
                if net_addr.get("urls"):
                    lines.append(f"- URL ({len(net_addr['urls'])} 个)：")
                    for url in net_addr['urls'][:15]:
                        lines.append(f"  - `{url}`")
                    if len(net_addr['urls']) > 15:
                        lines.append(f"  - ... 及其他 {len(net_addr['urls']) - 15} 个")
                if net_addr.get("ports"):
                    sorted_ports = sorted(net_addr['ports'])
                    lines.append(f"- 非标准端口：{', '.join(str(p) for p in sorted_ports[:20])}{'...' if len(sorted_ports) > 20 else ''}")
                lines.append("")

        suspicious = self.results["summary"].get("suspicious_functions", [])
        if suspicious:
            lines.append(self._s("suspicious_section"))
            lines.append("")
            for func_name in suspicious:
                lines.append(f"- **{func_name}**")
            lines.append("")

        lines.append(_L("critical_section"))
        lines.append("")
        for func in self.results["phase2_critical_path"].get("functions", []):
            lines.append(f"### {func['name']} ({func['address']})")
            lines.append("")
            if func.get("is_suspicious"):
                lines.append("**[SUSPICIOUS]**")
                lines.append("")
            if func.get("explanation"):
                lines.append(_L("func_analysis"))
                lines.append("")
                lines.append(func["explanation"])
                lines.append("")

    def _print_header(self, title):
        print(f"\n{'='*60}")
        print(f"  {title}")
        print(f"{'='*60}")


def main():
    mode_help = "Analysis mode: full, light, vuln" if not ZH_CN else "分析模式: full(全量), light(轻量), vuln(漏洞)"
    parser = argparse.ArgumentParser(description="WPeGPT AI Controller — Automated IDA Analysis")
    parser.add_argument("--mode", choices=["full", "light", "vuln"], default=None,
                        help=mode_help)
    parser.add_argument("--output", default=None, help="Report output directory")
    parser.add_argument("--log-file", default=None, help="Log file path for real-time progress display")
    keep_help = "Keep IDA server running after analysis (default: auto-shutdown)" if not ZH_CN else "分析后保持IDA服务器运行（默认自动关闭）"
    parser.add_argument("--keep-alive", action="store_true", default=False,
                        help=keep_help)
    args = parser.parse_args()

    # 设置日志转发
    tee_writer = None
    if args.log_file:
        tee_writer = TeeWriter(args.log_file)
        sys.stdout = tee_writer
        sys.stderr = tee_writer

    api_key = DEFAULT_API_KEY
    model = DEFAULT_MODEL
    base_url = DEFAULT_BASE_URL

    if not api_key:
        print(_L("no_api_key"))

    host, port = discover_server_port()
    print(_L("discovery", host=host, port=port))
    ida = IDAConnection(host, port)
    if not ida.connect():
        print(_L("connect_fail"))
        sys.exit(1)
    print(_L("connect_ok"))

    ai = AIEngine(api_key=api_key, model=model, base_url=base_url)

    controller = WPeAIController(ida, ai, output_dir=args.output, mode=args.mode)
    success = False
    try:
        try:
            success = controller.run()
        except KeyboardInterrupt:
            print(_L("user_interrupt"))
        except Exception as e:
            print(_L("analysis_fail", err=e))
            traceback.print_exc()
    finally:
        # 分析完成后关闭IDA服务器
        if not args.keep_alive:
            print(_L("shutdown"))
            try:
                print("[*] Sending quit_ida command to IDA...")
                result = ida.send_command("quit_ida", timeout=5)
                print("[*] quit_ida response: %s" % result)
                # 给IDA主线程一点时间处理退出回调
                time.sleep(1)
            except Exception as e:
                print("[*] quit_ida failed: %s" % e)
        ida.close()
        # 关闭日志转发
        if tee_writer:
            tee_writer.close()

    # 独立窗口模式下暂停，保留完整分析输出供用户查看
    if sys.platform == "win32":
        sys.stdout.write("\n分析完成，按任意键关闭窗口...\n")
        sys.stdout.flush()
        try:
            import msvcrt
            msvcrt.getch()
        except Exception:
            try:
                input("Press Enter to close...")
            except Exception:
                pass
    else:
        # Linux/macOS: 终端已保持打开，无需额外暂停
        sys.stdout.write("\n分析完成。\n")
        sys.stdout.flush()

    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
