import functools
import shlex
import socket
import idaapi
import ida_hexrays
import ida_kernwin
import idautils
import idc
import re
import threading
import json
import sys, os
import subprocess
import time
import tempfile

# 延迟导入 openai/httpx（IDA 自带 Python 通常不包含这两个包）
try:
    import openai
    import httpx
    _ai_deps_available = True
except ImportError:
    _ai_deps_available = False
    print("[WPeGPT] Warning: openai/httpx 未安装，AI功能不可用。")
    print("[WPeGPT] 请在IDA的Python环境中安装: pip install openai httpx")
    openai = None
    httpx = None
config_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "WPeGPT_Config")
sys.path.append(config_dir)

# 从config.py加载配置
config_path = os.path.join(config_dir, "config.py")
sys.path.insert(0, os.path.dirname(config_path))
import config

# ── 全局配置 ──
ZH_CN = config.ZH_CN
_wpe_clients = []
_wpe_clients_lock = threading.Lock()
wpe_server = None
_wpe_tasks = {}    # task_id -> {"status": "pending|done|error", "result": ...}
_wpe_tasks_lock = threading.Lock()
_wpe_task_counter = 0
_wpe_task_counter_lock = threading.Lock()  # 保护 task_id 计数器


class WPeCommandHandler:
    def __init__(self):
        pass

    def dispatch(self, command, params):
        handler = getattr(self, "cmd_" + command, None)
        if handler is None:
            return {"status": "error", "data": {"message": "Unknown command: " + command}}
        try:
            return handler(params)
        except Exception as e:
            return {"status": "error", "data": {"message": str(e)}}

    def cmd_get_info(self, params):
        entry = idc.get_inf_attr(idc.INF_START_EA)
        arch = "unknown"
        info = idaapi.get_inf_structure()
        proc = info.procname
        if info.is_64bit():
            if "arm" in proc.lower():
                arch = "ARM64"
            else:
                arch = "x64"
        elif info.is_32bit():
            if "arm" in proc.lower():
                arch = "ARM"
            elif "mips" in proc.lower():
                arch = "MIPS"
            elif "ppc" in proc.lower():
                arch = "PowerPC"
            else:
                arch = "x86"
        segs = []
        for seg_ea in idautils.Segments():
            segs.append({"name": idc.get_segm_name(seg_ea), "start": hex(seg_ea), "end": hex(idc.get_segm_end(seg_ea))})
        idb_path = idc.get_idb_path()
        return {"status": "ok", "data": {"idb_path": idb_path, "idb_name": os.path.basename(idb_path), "arch": arch, "entry_point": hex(entry), "func_count": idaapi.get_func_qty(), "segments": segs}}

    def cmd_get_functions(self, params):
        funcs = []
        for seg_ea in idautils.Segments():
            for func_ea in idautils.Functions(seg_ea, idc.get_segm_end(seg_ea)):
                func_name = idc.get_func_name(func_ea)
                func_end = idc.get_func_attr(func_ea, idc.FUNCATTR_END)
                funcs.append({"name": func_name, "address": hex(func_ea), "address_int": func_ea, "size": func_end - func_ea if func_end != idaapi.BADADDR else 0})
        return {"status": "ok", "data": {"functions": funcs, "count": len(funcs)}}

    def cmd_get_function_detail(self, params):
        addr = params.get("address")
        if addr is None:
            return {"status": "error", "data": {"message": "Missing 'address' parameter"}}
        if isinstance(addr, str):
            addr = int(addr, 0)
        try:
            decompiled = ida_hexrays.decompile(addr)
            func_start = idaapi.get_func(addr).start_ea if idaapi.get_func(addr) else addr
            func_end = idc.get_func_attr(addr, idc.FUNCATTR_END)
            func_cmt = idc.get_func_cmt(addr, 0) or ""
            return {"status": "ok", "data": {"name": idc.get_func_name(addr), "address": hex(func_start), "end": hex(func_end), "pseudocode": str(decompiled), "comment": func_cmt}}
        except Exception as e:
            return {"status": "error", "data": {"message": "Decompile failed: " + str(e)}}

    def cmd_get_strings(self, params):
        max_len = params.get("max_length", 50)
        min_len = params.get("min_length", 1)
        strings = []
        for s in idautils.Strings():
            content = str(s)
            if min_len <= len(content) <= max_len:
                strings.append({"address": hex(s.ea), "content": content.replace('\n', '').replace('\r', ''), "length": len(content)})
        return {"status": "ok", "data": {"strings": strings, "count": len(strings)}}

    def cmd_get_call_tree(self, params):
        from collections import defaultdict
        # 尝试多种入口点（Windows PE + Linux ELF + macOS Mach-O）
        entry_names = [
            "_start", "__start", "start", "main", "WinMain",
            "_main", "__libc_start_main", "entry", "start_address",
        ]
        start_addr = idaapi.BADADDR
        for name in entry_names:
            addr = idc.get_name_ea_simple(name)
            if addr != idaapi.BADADDR:
                start_addr = addr
                break
        if start_addr in (idaapi.BADADDR, idaapi.BADADDR & 0xFFFFFFFF):
            try:
                start_addr = idc.get_segm_by_sel(idc.selector_by_name(".text"))
            except Exception:
                try:
                    start_addr = idc.get_segm_by_sel(idc.selector_by_name("__text"))
                except Exception:
                    return {"status": "error", "data": {"message": "Cannot find .text/__text segment"}}
        text_start = idc.get_segm_start(start_addr)
        text_end = idc.get_segm_end(start_addr)
        func_dict = defaultdict(list)
        # 检测是否为 MSVC 名字修饰（用于过滤装饰函数）
        info = idaapi.get_inf_structure()
        is_msvc = info.procname == "metapc"
        for func_ea in idautils.Functions(text_start, text_end):
            func_name = idc.get_func_name(func_ea)
            # 跳过内部辅助函数和系统函数
            if func_name.startswith("__") or func_name == "syscall" or func_name == "start":
                if "WinMain" not in func_name and "main" not in func_name:
                    continue
            # MSVC 名字修饰过滤（@ 装饰调用约定, ? C++ mangled）
            # ELF 文件通常没有这些，但 MSVC 编译的 Windows 目标有
            if is_msvc and ('@' in func_name or '?' in func_name) and "WinMain" not in func_name:
                continue
            for ref_ea in idautils.CodeRefsTo(func_ea, 0):
                caller = idc.get_func_name(ref_ea)
                if caller and not caller.startswith("__"):
                    if is_msvc and '@' not in caller and '?' not in caller:
                        func_dict[caller].append(func_name)
                    elif "WinMain" in caller:
                        func_dict[caller].append(func_name)
                    elif not is_msvc:
                        # ELF/Mach-O: 不做名字修饰过滤
                        func_dict[caller].append(func_name)
        for caller in func_dict:
            func_dict[caller] = list(set(func_dict[caller]))
        return {"status": "ok", "data": {"call_tree": dict(func_dict), "func_count": len(func_dict)}}

    def cmd_get_task_result(self, params):
        task_id = params.get("task_id")
        if task_id is None:
            return {"status": "error", "data": {"message": "Missing 'task_id' parameter"}}
        with _wpe_tasks_lock:
            task = _wpe_tasks.get(str(task_id))
            if task is None:
                return {"status": "error", "data": {"message": "Task not found"}}
            return {"status": task["status"], "data": task.get("result", {}), "task_id": task_id}

    def _start_async_ai_task(self, analysis_type, addr):
        global _wpe_task_counter
        with _wpe_task_counter_lock:
            _wpe_task_counter += 1
            task_id = str(_wpe_task_counter)
            _wpe_tasks[task_id] = {"status": "pending", "result": {}}

        def run_task():
            ida_data = {"func_name": None, "addr_hex": None}
            def _get_info():
                ida_data["func_name"] = idc.get_func_name(addr)
                ida_data["addr_hex"] = hex(addr)
                return 0
            ida_kernwin.execute_sync(functools.partial(_get_info), ida_kernwin.MFF_READ)
            func_name = ida_data["func_name"] or "unknown"
            addr_hex = ida_data["addr_hex"]
            print("[WPeGPT_Server] Task %s START: %s at %s, type=%s" % (task_id, func_name, addr_hex, analysis_type))
            prompts = _get_prompts()
            prompt_template = prompts.get(analysis_type)
            if prompt_template is None:
                with _wpe_tasks_lock:
                    _wpe_tasks[task_id] = {"status": "error", "result": {"message": "Unknown analysis type"}}
                return

            # 反编译（主线程）
            decompile_result = {"pseudocode": None, "error": None}
            def do_decompile():
                try:
                    decompiled = ida_hexrays.decompile(addr)
                    decompile_result["pseudocode"] = str(decompiled)
                    decompile_result["func_name"] = idc.get_func_name(addr)
                except Exception as e:
                    decompile_result["error"] = str(e)
                return 0
            ida_kernwin.execute_sync(functools.partial(do_decompile), ida_kernwin.MFF_WRITE)
            if decompile_result["error"]:
                print("[WPeGPT_Server] Error：Task %s DECOMPILE FAILED: %s" % (task_id, decompile_result["error"]))
                with _wpe_tasks_lock:
                    _wpe_tasks[task_id] = {"status": "error", "result": {"message": "Decompile failed: " + decompile_result["error"]}}
                return
            print("[WPeGPT_Server] Task %s: decompiled %d chars from %s" % (task_id, len(decompile_result["pseudocode"]), func_name))

            # 调用AI
            analysis = None
            prompt = prompt_template.format(code=decompile_result["pseudocode"])
            print("[WPeGPT_Server] Task %s: calling AI for %s..." % (task_id, analysis_type))
            if client is None:
                print("[WPeGPT_Server] Error：Task %s: AI client not initialized!" % task_id)
                with _wpe_tasks_lock:
                    _wpe_tasks[task_id] = {"status": "error", "result": {"message": "AI client not initialized"}}
                return
            for attempt in range(3):
                try:
                    response = client.chat.completions.create(
                        model=MODEL,
                        messages=[{"role": "user", "content": prompt}],
                    )
                    msg = response.choices[0].message
                    analysis = msg.content or ""
                    if not analysis and hasattr(msg, 'reasoning_content') and msg.reasoning_content:
                        analysis = msg.reasoning_content
                    print("[WPeGPT_Server] Task %s: AI call succeeded on attempt %d, got %d chars" % (task_id, attempt + 1, len(analysis)))
                    break
                except Exception as e:
                    err_str = str(e).lower()
                    if ("refused" in err_str or "rate" in err_str or "limit" in err_str) and attempt < 2:
                        wait = 30 * (attempt + 1)
                        print("[WPeGPT_Server] Error：Task %s: Rate limited, retrying in %ds..." % (task_id, wait))
                        time.sleep(wait)
                    else:
                        print("[WPeGPT_Server] Error：Task %s: AI call FAILED: %s" % (task_id, str(e)))
                        with _wpe_tasks_lock:
                            _wpe_tasks[task_id] = {"status": "error", "result": {"message": "AI call failed: " + str(e)}}
                        return
            if not analysis:
                print("[WPeGPT_Server] Error：Task %s: Empty AI response" % task_id)
                with _wpe_tasks_lock:
                    _wpe_tasks[task_id] = {"status": "error", "result": {"message": "Empty AI response"}}
                return

            # 写入IDA注释并保存结果
            def set_comment():
                idc.set_func_cmt(addr, analysis, 0)
                ida_data["final_name"] = idc.get_func_name(addr)
                return 0
            ida_kernwin.execute_sync(functools.partial(set_comment), ida_kernwin.MFF_WRITE)

            with _wpe_tasks_lock:
                _wpe_tasks[task_id] = {
                    "status": "done",
                    "result": {"function": ida_data.get("final_name", func_name), "address": addr_hex, "analysis": analysis},
                }
            print("[WPeGPT_Server] Task %s completed: %s (%d chars stored)" % (task_id, ida_data.get("final_name", func_name), len(analysis)))

        t = threading.Thread(target=run_task, daemon=True, name="AITask-%s" % task_id)
        t.start()
        return task_id

    def cmd_explain_function(self, params):
        return self._start_ai_task("explain", params)

    def cmd_rename_function(self, params):
        return self._start_ai_task("rename", params)

    def cmd_find_vulnerabilities(self, params):
        return self._start_ai_task("vuln", params)

    def cmd_generate_exploit(self, params):
        return self._start_ai_task("exploit", params)

    def cmd_python_restore(self, params):
        return self._start_ai_task("python", params)

    def cmd_full_analysis(self, params):
        return self._start_full_analysis(params)

    def _start_ai_task(self, analysis_type, params):
        addr = params.get("address")
        if addr is None:
            return {"status": "error", "data": {"message": "Missing 'address' parameter"}}
        if isinstance(addr, str):
            addr = int(addr, 0)
        task_id = self._start_async_ai_task(analysis_type, addr)
        return {"status": "ok", "data": {"task_id": task_id, "address": hex(addr)}}

    def _start_full_analysis(self, params):
        addr = params.get("address")
        if addr is None:
            return {"status": "error", "data": {"message": "Missing 'address' parameter"}}
        if isinstance(addr, str):
            addr = int(addr, 0)
        task_ids = {}
        for name in ["explain", "vuln", "python", "exploit"]:
            task_ids[name + "_function"] = self._start_async_ai_task(name, addr)
        return {"status": "ok", "data": {"task_ids": task_ids, "address": hex(addr)}}

    def cmd_set_comment(self, params):
        addr = params.get("address")
        comment = params.get("comment", "")
        is_func = params.get("is_function", True)
        if addr is None:
            return {"status": "error", "data": {"message": "Missing 'address' parameter"}}
        if isinstance(addr, str):
            addr = int(addr, 0)
        result = {"error": None}
        def do_set():
            try:
                if is_func:
                    idc.set_func_cmt(addr, comment, 0)
                else:
                    idc.set_cmt(addr, comment, 0)
            except Exception as e:
                result["error"] = str(e)
            return 0
        ida_kernwin.execute_sync(functools.partial(do_set), ida_kernwin.MFF_WRITE)
        if result["error"]:
            return {"status": "error", "data": {"message": result["error"]}}
        return {"status": "ok", "data": {"address": hex(addr)}}

    def cmd_rename_function_addr(self, params):
        addr = params.get("address")
        new_name = params.get("new_name")
        if addr is None or new_name is None:
            return {"status": "error", "data": {"message": "Missing 'address' or 'new_name' parameter"}}
        if isinstance(addr, str):
            addr = int(addr, 0)
        new_name = re.sub(r'[^a-zA-Z0-9_]', '_', new_name)
        if not new_name[0].isalpha() and new_name[0] != '_':
            new_name = '_' + new_name
        result_holder = {"ok": False}
        def do_rename():
            result_holder["ok"] = idc.set_name(addr, new_name, idc.SN_CHECK)
            return 0
        ida_kernwin.execute_sync(functools.partial(do_rename), ida_kernwin.MFF_WRITE)
        if result_holder["ok"]:
            return {"status": "ok", "data": {"address": hex(addr), "new_name": new_name}}
        return {"status": "error", "data": {"message": "Failed to rename function"}}


def _wpe_handle_client(conn, addr, handler):
    global _wpe_clients
    buffer = ""
    try:
        while True:
            data = conn.recv(4096)
            if not data:
                break
            buffer += data.decode("utf-8")
            while "\n" in buffer:
                line, buffer = buffer.split("\n", 1)
                line = line.strip()
                if not line:
                    continue
                try:
                    msg = json.loads(line)
                    command = msg.get("command", "")
                    params = msg.get("params", {})
                    resp_id = msg.get("id", 0)

                    # shutdown命令直接处理，无需IDA同步
                    if command == "shutdown":
                        conn.send((json.dumps({"status": "ok", "data": {"message": "Shutting down"}, "_id": resp_id}) + "\n").encode("utf-8"))
                        conn.close()
                        print("[WPeGPT_Server] Shutdown requested by client, stopping server...")
                        if wpe_server:
                            wpe_server.shutdown()
                        return

                    # 自动退出IDA
                    if command == "quit_ida":
                        try:
                            conn.send((json.dumps({"status": "ok", "data": {"message": "Exiting IDA"}, "_id": resp_id}) + "\n").encode("utf-8"))
                        except:
                            pass
                        # 先关闭服务器（释放端口文件、关闭所有连接），
                        # 然后通过execute_ui_requests在IDA主线程调用qexit
                        # execute_ui_requests是异步的，不会阻塞当前线程
                        if wpe_server:
                            wpe_server.running = False
                            try:
                                wpe_server.server_socket.close()
                            except:
                                pass
                        def _do_exit():
                            idc.qexit(0)
                            return False
                        ida_kernwin.execute_ui_requests([_do_exit])
                        return

                    # 等待执行结果
                    result_event = threading.Event()
                    result_holder = {"result": None}

                    def execute_command():
                        result_holder["result"] = handler.dispatch(command, params)
                        result_event.set()
                        return 0

                    ida_kernwin.execute_sync(functools.partial(execute_command), ida_kernwin.MFF_WRITE)
                    # 超时等待，防止死锁
                    if not result_event.wait(timeout=10):
                        response = {"status": "error", "data": {"message": "execute_sync timed out"}, "_id": resp_id}
                    else:
                        response = result_holder.get("result", {"status": "error", "data": {"message": "Execution failed"}})
                        response["_id"] = resp_id

                    conn.send((json.dumps(response) + "\n").encode("utf-8"))
                except json.JSONDecodeError:
                    conn.send((json.dumps({"status": "error", "data": {"message": "Invalid JSON"}, "_id": resp_id}) + "\n").encode("utf-8"))
                except Exception as e:
                    conn.send((json.dumps({"status": "error", "data": {"message": str(e)}, "_id": resp_id}) + "\n").encode("utf-8"))
    except Exception as e:
        print("[WPeGPT_Server] Error：Client error: %s" % str(e))
    finally:
        with _wpe_clients_lock:
            _wpe_clients = [(c, a) for (c, a) in _wpe_clients if c != conn]
        try:
            conn.close()
        except:
            pass


class WPeServer:
    def __init__(self, host="127.0.0.1"):
        self.host = host
        self.port = 0
        self.server_socket = None
        self.server_thread = None
        self.handler = WPeCommandHandler()
        self.running = False
        self._port_file = None

    def start(self):
        if self.running:
            return False
        try:
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server_socket.bind((self.host, 0))
            # 获取OS分配的端口
            self.port = self.server_socket.getsockname()[1]
            self.server_socket.listen(1)
            self.running = True
            self.server_thread = threading.Thread(target=self._accept_loop, daemon=True)
            self.server_thread.start()
            # 写入临时端口文件供控制器发现（含PID隔离，支持多实例）
            port_file = os.path.join(tempfile.gettempdir(), ".wpe_server_port_%d" % os.getpid())
            plugin_dir = os.path.dirname(os.path.abspath(__file__))
            with open(port_file, "w") as f:
                json.dump({
                    "host": self.host, "port": self.port,
                    "plugin_dir": plugin_dir, "pid": os.getpid(),
                }, f)
            self._port_file = port_file
            print("[WPeGPT_Server] Started on %s:%d (port file: %s)" % (self.host, self.port, self._port_file))
            return True
        except Exception as e:
            print("[WPeGPT_Server] Error：Failed to start server: %s" % str(e))
            return False

    def _accept_loop(self):
        global _wpe_clients
        while self.running:
            try:
                self.server_socket.settimeout(1.0)
                try:
                    conn, addr = self.server_socket.accept()
                except socket.timeout:
                    continue
                with _wpe_clients_lock:
                    _wpe_clients.append((conn, addr))
                client_thread = threading.Thread(target=_wpe_handle_client, args=(conn, addr, self.handler), daemon=True)
                client_thread.start()
            except Exception as e:
                if self.running:
                    print("[WPeGPT_Server] Error：Accept error: %s" % str(e))

    def shutdown(self):
        global _wpe_clients
        self.running = False
        with _wpe_clients_lock:
            for conn, addr in _wpe_clients:
                try:
                    conn.close()
                except:
                    pass
            _wpe_clients = []
        if self.server_socket:
            try:
                self.server_socket.close()
            except:
                pass
        if self.server_thread:
            self.server_thread.join(timeout=3)
        if self._port_file:
            try:
                os.remove(self._port_file)
            except:
                pass
            self._port_file = None
        print("[WPeGPT_Server] Server stopped")


# 插件名：从模型名派生
PLUGIN_NAME = 'WPeGPT-' + config.MODEL.upper()

# API密钥：优先从config读取，回退环境变量
model_api_key = config.API_KEY or os.getenv("model_api_key")
MODEL = config.MODEL or os.getenv("model_name")
AI_TIMEOUT = 120

def _build_client():
    if not _ai_deps_available:
        return None
    if not model_api_key:
        return None
    kwargs = {"api_key": model_api_key, "timeout": AI_TIMEOUT}
    if config.FORWARD_PROXY:
        kwargs["http_client"] = httpx.Client(
            proxies=config.FORWARD_PROXY, transport=httpx.HTTPTransport(local_address="0.0.0.0"),
        )
    if config.API_BASE_URL:
        kwargs["base_url"] = config.API_BASE_URL
    return openai.OpenAI(**kwargs)

# 防止IDA重复加载脚本导致重复初始化（但每次加载都需要重建client）
if "_wpe_client" not in sys.modules:
    sys.modules["_wpe_client"] = True
    if not model_api_key:
        print("[WPeGPT] Warning: API_KEY 未配置，AI功能不可用。")
        print("[WPeGPT] 请在 WPeGPT_Config/config.py 中设置 API_KEY。")
    if MODEL:
        print("\n[WPeGPT] is using %s." % MODEL)
    else:
        print("\n[WPeGPT] Warning: No AI model has been configured.")
        print("[WPeGPT] Please set MODEL in WPeGPT_Config/config.py.")
    client = _build_client()
    if client is None:
        if _ai_deps_available and not model_api_key:
            print("[WPeGPT] AI功能不可用（缺少 API_KEY），WPeServer仍可用。")
        elif not MODEL:
            print("[WPeGPT] AI功能不可用（未配置模型），WPeServer仍可用。")
        else:
            print("[WPeGPT] AI功能不可用（缺少 openai/httpx 依赖），WPeServer仍可用。")
    if config.FORWARD_PROXY:
        print("[WPeGPT] has appointed the forward-proxy.")
    if config.API_BASE_URL:
        print("[WPeGPT] BASE URL: %s" % config.API_BASE_URL)
else:
    # IDA重新加载脚本（打开新二进制），重建client
    client = _build_client()


# ── 双语提示词 ──
_PROMPTS_CN = {
    "explain": "你是一名二进制分析专家。以下是一个反编译伪代码函数，请客观分析：\n1. 该函数的核心功能和预期目的\n2. 调用的关键API及其作用（网络通信、文件操作、注册表、加密、进程/线程、内存管理等）\n3. 参数的作用\n4. 是否存在可疑或危险行为（如C2通信、持久化、环境检测、数据外泄、进程注入等），如有请指出，如无请说明'无明显可疑行为'\n5. 建议的新函数名\n（用简体中文回答，回答开始前加上'---WPeChat_START---'字符串结束后加上'---WPeChat_END---'字符串）\n{code}",
    "rename": "以下是一个C语言函数，请分析并建议更合适的变量名。回复一个JSON对象，键为原名，值为建议的新名。不要解释，只输出JSON字典。\n{code}",
    "vuln": "你是一名安全研究员。请分析以下伪代码函数的安全性：\n1. 是否存在缓冲区溢出、格式化字符串、整数溢出、UAF、竞争条件、输入校验缺失等漏洞\n2. 攻击者可能如何利用\n3. 如果未发现漏洞，请明确说明'未发现明显漏洞'\n（用简体中文回答，回答开始前加上'---WPeChat_VulnFinder_START---'字符串结束后加上'---WPeChat_VulnFinder_END---'字符串）\n{code}",
    "exploit": "使用Python构造代码来利用下面函数中的漏洞。（用简体中文回答我，并且回答开始前加上'---WPeChat_VulnPython_START---'字符串结束后加上'---WPeChat_VulnPython_END---'字符串）\n{code}",
    "python": "分析下面的C语言伪代码并用python3代码进行还原。（回答开始前加上'---WPeChat_Python_START---'字符串结束后加上'---WPeChat_Python_END---'字符串）\n{code}",
}

_PROMPTS_EN = {
    "explain": "You are a binary analysis expert. Below is a decompiled pseudocode function, please objectively analyze:\n1. The core functionality and intended purpose\n2. Key APIs called and their roles (network communication, file operations, registry, encryption, process/thread, memory management, etc.)\n3. The purpose of parameters\n4. Whether there are any suspicious or dangerous behaviors (such as C2 communication, persistence, environment detection, data exfiltration, process injection, etc.) — point them out if present, or state 'no suspicious behavior detected' if not\n5. Suggested new function name\n(Reply in English, prefix your answer with '---WPeChat_START---' and suffix with '---WPeChat_END---')\n{code}",
    "rename": "Analyze the following C function:\n{code}\nSuggest better variable names, reply with a JSON array where keys are the original names and values are the proposed names. Do not explain anything, only print the JSON dictionary.",
    "vuln": "You are a security researcher. Please analyze the security of the following pseudocode function:\n1. Whether there are buffer overflows, format strings, integer overflows, UAF, race conditions, input validation missing, etc.\n2. How an attacker might exploit them\n3. If no vulnerabilities are found, clearly state 'no obvious vulnerabilities found'\n(Reply in English, prefix your answer with '---WPeChat_VulnFinder_START---' and suffix with '---WPeChat_VulnFinder_END---')\n{code}",
    "exploit": "Use Python to construct exploit code leveraging the vulnerability in the following function. (Reply in English, prefix your answer with '---WPeChat_VulnPython_START---' and suffix with '---WPeChat_VulnPython_END---')\n{code}",
    "python": "Analyze the following C pseudocode and restore it using Python 3 code. (Prefix your answer with '---WPeChat_Python_START---' and suffix with '---WPeChat_Python_END---')\n{code}",
}

_PROMPTS_HANDLER_CN = {
    "explain": "下面是一个C语言伪代码函数，请客观分析该函数的核心功能、参数的作用、详细实现逻辑，是否存在可疑行为（如有请指出，如无请说明'无明显可疑行为'），最后取一个新的函数名字。（用简体中文回答我，并且回答开始前加上'---WPeChat_START---'字符串结束后加上'---WPeChat_END---'字符串）\n{code}",
    "vuln": "请客观分析下面这个C语言伪代码函数的安全性，查找是否存在缓冲区溢出、格式化字符串、整数溢出、UAF、竞争条件、输入校验缺失等漏洞。如未发现漏洞，请明确说明'未发现明显漏洞'。（用简体中文回答我，并且回答开始前加上'---WPeChat_VulnFinder_START---'字符串结束后加上'---WPeChat_VulnFinder_END---'字符串）\n{code}",
    "exploit": "使用Python构造代码来利用下面函数中的漏洞。（用简体中文回答我，并且回答开始前加上'---WPeChat_VulnPython_START---'字符串结束后加上'---WPeChat_VulnPython_END---'字符串）\n{code}",
    "python": "分析下面的C语言伪代码并用python3代码进行还原。（回答开始前加上'---WPeChat_Python_START---'字符串结束后加上'---WPeChat_Python_END---'字符串）\n{code}",
}

_PROMPTS_HANDLER_EN = {
    "explain": "Below is a C pseudocode function. Please objectively analyze its core functionality, parameter purposes, detailed implementation logic, and whether there are any suspicious behaviors (point them out if present, or state 'no suspicious behavior detected' if not), then suggest a new function name. (Reply in English, prefix with '---WPeChat_START---' and suffix with '---WPeChat_END---')\n{code}",
    "vuln": "Please objectively analyze the security of the following C pseudocode function, checking for buffer overflows, format strings, integer overflows, UAF, race conditions, input validation missing, etc. If no vulnerabilities are found, clearly state 'no obvious vulnerabilities found'. (Reply in English, prefix with '---WPeChat_VulnFinder_START---' and suffix with '---WPeChat_VulnFinder_END---')\n{code}",
    "exploit": "Use Python to construct exploit code leveraging the vulnerability in the following function. (Reply in English, prefix with '---WPeChat_VulnPython_START---' and suffix with '---WPeChat_VulnPython_END---')\n{code}",
    "python": "Analyze the following C pseudocode and restore it using Python 3 code. (Prefix with '---WPeChat_Python_START---' and suffix with '---WPeChat_Python_END---')\n{code}",
}

def _get_prompts():
    return _PROMPTS_CN if ZH_CN else _PROMPTS_EN

def _get_handler_prompt(analysis_type):
    prompts = _PROMPTS_HANDLER_CN if ZH_CN else _PROMPTS_HANDLER_EN
    return prompts.get(analysis_type, "").format(code="{code}")


# AI启动外部控制器 — 自动化分析二进制（独立控制台窗口运行）
# 用户可在新弹出的命令行窗口中实时查看完整分析进度


class AutoHandler(idaapi.action_handler_t):
    """自动化分析处理器的基类，子类指定分析模式"""
    _mode = "light"  # 由子类覆盖

    def __init__(self):
        idaapi.action_handler_t.__init__(self)

    def _find_python(self):
        """寻找系统Python解释器（IDA内置的sys.executable不可用）"""
        import shutil
        import platform

        # Unix-like (Linux/macOS)
        if platform.system() != "Windows":
            for name in ("python3", "python"):
                path = shutil.which(name)
                if path:
                    return path
            # 常见Unix路径回退
            for p in ("/usr/bin/python3", "/usr/local/bin/python3",
                      "/opt/homebrew/bin/python3", "/usr/bin/python"):
                if os.path.isfile(p):
                    return p
            return None

        # Windows
        # 优先使用 python.exe（控制台程序），而非 pythonw.exe（无窗口程序）
        # pythonw.exe 可能忽略 CREATE_NEW_CONSOLE 标志，导致窗口不弹出
        for name in ("python.exe", "pythonw.exe"):
            path = shutil.which(name)
            if path:
                return path
        # Windows 应用商店版 Python（App Execution Alias）
        localappdata = os.environ.get("LOCALAPPDATA", "")
        if localappdata:
            alias_path = os.path.join(localappdata, "Microsoft", "WindowsApps", "python.exe")
            if os.path.isfile(alias_path):
                return alias_path
        return None

    def activate(self, ctx):
        plugin_dir = os.path.dirname(os.path.abspath(__file__))
        config_dir = os.path.join(plugin_dir, "WPeGPT_Config")
        controller_path = os.path.join(config_dir, "wpe_ai_controller.py")
        if not os.path.isfile(controller_path):
            print("[WPeGPT] Error：未找到自动化分析脚本 wpe_ai_controller.py！ @WPeace")
            return 0
        python_exe = self._find_python()
        if python_exe is None:
            print("[WPeGPT] Error：未找到系统Python解释器！ @WPeace")
            return 0

        mode_labels = {"light": "轻量", "full": "全量", "vuln": "漏洞"}
        mode_label = mode_labels.get(self._mode, self._mode)
        print("[WPeGPT] 启动自动化分析（%s模式），独立进度窗口... @WPeace" % mode_label)

        # 直接在新控制台窗口中启动 Python 控制器
        cmd = [python_exe, controller_path, "--mode", self._mode, "--keep-alive"]
        if sys.platform == "win32":
            # Windows: 新控制台窗口
            subprocess.Popen(cmd, creationflags=subprocess.CREATE_NEW_CONSOLE)
        elif sys.platform == "darwin":
            # macOS: 通过 Terminal.app 打开，路径含空格时需用引号包裹
            shell_cmd = " ".join(shlex.quote(p) for p in cmd)
            subprocess.Popen([
                "osascript", "-e",
                'tell application "Terminal" to do script "%s"' % shell_cmd,
            ])
        else:
            # Linux: 尝试常见终端模拟器，shlex.quote 处理含空格路径
            terminals = [
                ["gnome-terminal", "--"],
                ["konsole", "-e"],
                ["xfce4-terminal", "-e"],
                ["xterm", "-e"],
                ["x-terminal-emulator", "-e"],
            ]
            shell_cmd = " ".join(shlex.quote(p) for p in cmd)
            launched = False
            for term in terminals:
                try:
                    subprocess.Popen(term + [shell_cmd])
                    launched = True
                    break
                except OSError:
                    continue
            if not launched:
                # 回退：后台运行（无实时输出）
                print("[WPeGPT] 未找到终端模拟器，后台运行（无实时输出）。")
                subprocess.Popen(cmd)

        return 1

    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS


class AutoLightHandler(AutoHandler):
    _mode = "light"

class AutoFullHandler(AutoHandler):
    _mode = "full"

class AutoVulnHandler(AutoHandler):
    _mode = "vuln"


# AI分析解释函数
class ExplainHandler(idaapi.action_handler_t):
    def __init__(self):
        idaapi.action_handler_t.__init__(self)

    def activate(self, ctx):
        funcComment = getFuncComment(idaapi.get_screen_ea())
        if "---WPeChat_START---" in funcComment:
            print("当前函数已经完成过 %s:Explain 分析，请查看注释或删除注释重新分析。@WPeace"%(PLUGIN_NAME))
            return 0
        decompiler_output = ida_hexrays.decompile(idaapi.get_screen_ea())
        v = ida_hexrays.get_widget_vdui(ctx.widget)
        prompt = _get_handler_prompt("explain").replace("{code}", str(decompiler_output))
        query_model_async(prompt,
            functools.partial(comment_callback, address=idaapi.get_screen_ea(), view=v, cmtFlag=0, printFlag=0), 0)
        return 1

    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS


# AI重命名函数变量
class RenameHandler(idaapi.action_handler_t):
    def __init__(self):
        idaapi.action_handler_t.__init__(self)

    def activate(self, ctx):
        decompiler_output = ida_hexrays.decompile(idaapi.get_screen_ea())
        v = ida_hexrays.get_widget_vdui(ctx.widget)
        query_model_async("Analyze the following C function:\n" + str(decompiler_output) +
                            "\nSuggest better variable names, reply with a JSON array where keys are the original names"
                            "and values are the proposed names. Do not explain anything, only print the JSON "
                            "dictionary.",
                          functools.partial(rename_callback, address=idaapi.get_screen_ea(), view=v),
                          0)
        return 1

    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS


# 使用Python3还原函数
class PythonHandler(idaapi.action_handler_t):
    def __init__(self):
        idaapi.action_handler_t.__init__(self)

    def activate(self, ctx):
        lastAddr = idc.prev_head(idc.get_func_attr(idaapi.get_screen_ea(), idc.FUNCATTR_END))
        addrComment = getAddrComment(lastAddr)
        if "---WPeChat_Python_START---" in str(addrComment):
            print("当前函数已经完成过 %s:Python 分析，请查看注释或删除注释重新分析。@WPeace"%(PLUGIN_NAME))
            return 0
        decompiler_output = ida_hexrays.decompile(idaapi.get_screen_ea())
        v = ida_hexrays.get_widget_vdui(ctx.widget)
        prompt = _get_handler_prompt("python").replace("{code}", str(decompiler_output))
        query_model_async(prompt,
            functools.partial(comment_callback, address=lastAddr, view=v, cmtFlag=1, printFlag=1), 0)
        return 1

    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS


# AI查找函数漏洞
class FindVulnHandler(idaapi.action_handler_t):
    def __init__(self):
        idaapi.action_handler_t.__init__(self)

    def activate(self, ctx):
        funcComment = getFuncComment(idaapi.get_screen_ea())
        if "---WPeChat_VulnFinder_START---" in funcComment:
            print("当前函数已经完成过 %s:VulnFinder 分析，请查看注释或删除注释重新分析。@WPeace"%(PLUGIN_NAME))
            return 0
        decompiler_output = ida_hexrays.decompile(idaapi.get_screen_ea())
        v = ida_hexrays.get_widget_vdui(ctx.widget)
        prompt = _get_handler_prompt("vuln").replace("{code}", str(decompiler_output))
        query_model_async(prompt,
            functools.partial(comment_callback, address=idaapi.get_screen_ea(), view=v, cmtFlag=0, printFlag=2), 0)
        return 1

    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS


# AI生成漏洞EXP
class expCreateHandler(idaapi.action_handler_t):
    def __init__(self):
        idaapi.action_handler_t.__init__(self)

    def activate(self, ctx):
        funcComment = getFuncComment(idaapi.get_screen_ea())
        if "---WPeChat_VulnPython_START---" in funcComment:
            print("当前函数已经完成过 %s:ExpCreater 分析，请查看注释或删除注释重新分析。@WPeace"%(PLUGIN_NAME))
            return 0
        decompiler_output = ida_hexrays.decompile(idaapi.get_screen_ea())
        v = ida_hexrays.get_widget_vdui(ctx.widget)
        prompt = _get_handler_prompt("exploit").replace("{code}", str(decompiler_output))
        query_model_async(prompt,
            functools.partial(comment_callback, address=idaapi.get_screen_ea(), view=v, cmtFlag=0, printFlag=3), 0)
        return 1

    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS




# AI查询主函数
def query_model(query, cb, max_tokens=2500):
    if client is None:
        print(f"{MODEL} AI client not available, install with: pip install openai httpx")
        return
    try:
        response = client.chat.completions.create(
            model=MODEL,
            messages=[{"role": "user", "content": query}]
        )
        ida_kernwin.execute_sync(functools.partial(cb, response=response.choices[0].message.content), ida_kernwin.MFF_WRITE)
    except openai.BadRequestError as e:
        print(f"{MODEL} 请求失败: {e}")
    except openai.OpenAIError as e:
        if "overloaded" in str(e).lower() or "timeout" in str(e).lower():
            print(f"{MODEL} API 繁忙，请稍后重试。@WPeace")
        elif "Cannot connect to proxy" in str(e):
            print("代理出现问题，请稍后重试或检查代理。@WPeace")
        else:
            print(f"OpenAI 服务器请求失败: {e}")
    except Exception as e:
        print(f"查询时遇到异常: {e}")


# 异步发起AI查询
def query_model_async(query, cb, retry=0):
    if retry == 0:
        print(f"正在发送 {PLUGIN_NAME}:{MODEL} API 请求。@WPeace")
    else:
        print(f"正在重发 {PLUGIN_NAME}-{MODEL} API 请求。@WPeace")
    t = threading.Thread(target=query_model, args=[query, cb])
    t.start()


# AI回调：设置注释并打印状态
def comment_callback(address, view, response, cmtFlag, printFlag):
    if cmtFlag == 0:
        idc.set_func_cmt(address, response, 0)
    elif cmtFlag == 1:
        idc.set_cmt(address, response, 1)
    if view:
        view.refresh_view(False)
    labels = {
        0: ("Explain", f"{PLUGIN_NAME}:Explain 完成分析，已对函数 {idc.get_func_name(address)} 进行注释。@WPeace"),
        1: ("Python", f"{PLUGIN_NAME}:Python 完成分析，已在函数末尾地址 {hex(address)} 汇编处进行注释。@WPeace"),
        2: ("VulnFinder", f"{PLUGIN_NAME}:VulnFinder 完成分析，已对函数 {idc.get_func_name(address)} 进行注释。@WPeace"),
        3: ("ExpCreater", f"{PLUGIN_NAME}:ExpCreater 完成分析，已对函数 {idc.get_func_name(address)} 进行注释。@WPeace"),
    }
    print("%s query finished!" % MODEL)
    _, msg = labels.get(printFlag, ("?", "Unknown callback"))
    print(msg)


# AI回调：从JSON提取变量名并重命名
def rename_callback(address, view, response, retries=0):
    j = re.search(r"\{[^}]*?\}", response)
    if not j:
        if retries >= 3:
            print(f"{PLUGIN_NAME}-{MODEL} API 无有效响应，请稍后重试。@WPeace")
            return
        print("响应中无法提取JSON，正在请求模型修复...")
        query_model_async("The JSON document provided in this response is invalid. Can you fix it?\n" + response,
                          functools.partial(rename_callback, address=address, view=view, retries=retries + 1), 1)
        return
    try:
        names = json.loads(j.group(0))
    except json.decoder.JSONDecodeError:
        if retries >= 3:
            print(f"{PLUGIN_NAME}-{MODEL} API 无有效响应，请稍后重试。@WPeace")
            return
        print("返回的JSON格式无效，正在请求模型修复...")
        query_model_async("Please fix the following JSON document:\n" + j.group(0),
                          functools.partial(rename_callback, address=address, view=view, retries=retries + 1), 1)
        return
    function_addr = idaapi.get_func(address).start_ea
    replaced = []
    for n in names:
        if ida_hexrays.rename_lvar(function_addr, n, names[n]):
            replaced.append(n)
    comment = idc.get_func_cmt(address, 0)
    if comment and replaced:
        for n in replaced:
            comment = re.sub(r'\b%s\b' % n, names[n], comment)
        idc.set_func_cmt(address, comment, 0)
    if view:
        view.refresh_view(True)
    print("%s query finished!" % MODEL)
    print(f"{PLUGIN_NAME}:RenameVariable 完成分析，已重命名{len(replaced)}个变量。@WPeace")


# 获取函数/地址注释
def getFuncComment(address):
    cmt = idc.get_func_cmt(address, 0) or idc.get_func_cmt(address, 1)
    return cmt

def getAddrComment(address):
    cmt = idc.get_cmt(address, 0) or idc.get_cmt(address, 1)
    return cmt


# 右键菜单钩子
class ContextMenuHooks(idaapi.UI_Hooks):
    def finish_populating_widget_popup(self, form, popup):
        idaapi.attach_action_to_popup(form, popup, myplugin_WPeChatGPT.explain_action_name, "%s/"%(PLUGIN_NAME))
        idaapi.attach_action_to_popup(form, popup, myplugin_WPeChatGPT.rename_action_name, "%s/"%(PLUGIN_NAME))
        idaapi.attach_action_to_popup(form, popup, myplugin_WPeChatGPT.python_action_name, "%s/"%(PLUGIN_NAME))
        idaapi.attach_action_to_popup(form, popup, myplugin_WPeChatGPT.vulnFinder_action_name, "%s/"%(PLUGIN_NAME))
        idaapi.attach_action_to_popup(form, popup, myplugin_WPeChatGPT.expPython_action_name, "%s/"%(PLUGIN_NAME))


class myplugin_WPeChatGPT(idaapi.plugin_t):
    autoWPeGPT_base_path = None
    autoWPeGPT_action_light = "%s:Auto_Analysis_Light"%(PLUGIN_NAME)
    autoWPeGPT_action_full  = "%s:Auto_Analysis_Full"%(PLUGIN_NAME)
    autoWPeGPT_action_vuln  = "%s:Auto_Analysis_Vuln"%(PLUGIN_NAME)
    explain_action_name = "%s:Explain_Function"%(PLUGIN_NAME)
    explain_menu_path = None
    rename_action_name = "%s:Rename_Function"%(PLUGIN_NAME)
    rename_menu_path = None
    python_action_name = "%s:Python_Function"%(PLUGIN_NAME)
    python_menu_path = None
    vulnFinder_action_name = "%s:VulnFinder_Function"%(PLUGIN_NAME)
    vulnFinder_menu_path = None
    expPython_action_name = "%s:VulnPython_Function"%(PLUGIN_NAME)
    expPython_menu_path = None
    wanted_name = PLUGIN_NAME
    wanted_hotkey = ''
    comment = "%s Plugin for IDA"%(PLUGIN_NAME)
    help = "Find more information at https://github.com/wpeace-hch"
    menu = None
    flags = 0
    def init(self):
        global wpe_server
        try:
            # 检查反编译插件是否可用
            if not ida_hexrays.init_hexrays_plugin():
                # 反编译不可用，启动服务器并退出
                try:
                    wpe_server = WPeServer()
                    wpe_server.start()
                except:
                    pass
                print("%s: Hex-Rays反编译插件不可用，菜单功能已禁用。@WPeace" % PLUGIN_NAME)
                print("%s v3.0 已启动，但存在错误，请检查报错信息。@WPeace\n" % PLUGIN_NAME)
                return idaapi.PLUGIN_KEEP

            # 根据语言设置菜单路径（实例属性，覆盖类级占位）
            self.autoWPeGPT_base_path = "Edit/%s/Auto-WPeGPT/"%(PLUGIN_NAME) if not ZH_CN else "Edit/%s/自动化分析/"%(PLUGIN_NAME)
            self.explain_menu_path     = "Edit/%s/Function analysis"%(PLUGIN_NAME) if not ZH_CN else "Edit/%s/函数分析"%(PLUGIN_NAME)
            self.rename_menu_path      = "Edit/%s/Rename function variables"%(PLUGIN_NAME) if not ZH_CN else "Edit/%s/重命名函数变量"%(PLUGIN_NAME)
            self.python_menu_path      = "Edit/%s/Python restore"%(PLUGIN_NAME) if not ZH_CN else "Edit/%s/Python还原此函数"%(PLUGIN_NAME)
            self.vulnFinder_menu_path  = "Edit/%s/Vulnerability finding"%(PLUGIN_NAME) if not ZH_CN else "Edit/%s/二进制漏洞查找"%(PLUGIN_NAME)
            self.expPython_menu_path   = "Edit/%s/Try to generate Exploit"%(PLUGIN_NAME) if not ZH_CN else "Edit/%s/尝试生成Exploit"%(PLUGIN_NAME)

            # 根据语言配置选择标签
            labels = {
                "explain": ("函数分析", "Function analysis"),
                "rename": ("重命名函数变量", "Rename function variables"),
                "python": ("Python还原此函数", "Python restores this function"),
                "vuln": ("二进制漏洞查找", "Vulnerability finding"),
                "exploit": ("尝试生成Exploit", "Try to generate Exploit"),
            }
            k = 0 if ZH_CN else 1
            L = {key: val[k] for key, val in labels.items()}

            tooltips = {
                "explain": ("使用 %s 分析当前函数" % MODEL, "Analyze current function with %s" % MODEL),
                "rename": ("使用 %s 重命名当前函数的变量" % MODEL, "Rename current function variables with %s" % MODEL),
                "python": ("使用 %s 分析当前函数并用python3还原" % MODEL, "Analyze current function with %s and restore in python3" % MODEL),
                "vuln": ("使用 %s 在当前函数中查找漏洞" % MODEL, "Find vulnerabilities in current function with %s" % MODEL),
                "exploit": ("使用 %s 尝试对漏洞函数生成EXP" % MODEL, "Try to generate exploit for vulnerable function with %s" % MODEL),
            }
            tooltips = {key: val[k] for key, val in tooltips.items()}

            # 注册菜单动作
            auto_menu_light = "自动化分析 / 轻量分析" if ZH_CN else "Auto-WPeGPT / Light Mode"
            auto_menu_full  = "自动化分析 / 全量分析" if ZH_CN else "Auto-WPeGPT / Full Mode"
            auto_menu_vuln  = "自动化分析 / 漏洞分析" if ZH_CN else "Auto-WPeGPT / Vuln Mode"
            auto_tooltip_l  = "轻量模式：全局扫描 + 关键路径分析" if ZH_CN else "Light: Global scan + Critical path analysis"
            auto_tooltip_f  = "全量模式：全局扫描 + 关键路径分析 + 全量函数扫描" if ZH_CN else "Full: Global scan + Critical path + Full function scan"
            auto_tooltip_v  = "漏洞模式：全局扫描 + 关键路径漏洞分析" if ZH_CN else "Vuln: Global scan + Critical path vuln analysis"
            action_specs = [
                (self.autoWPeGPT_action_light, auto_menu_light, AutoLightHandler(), "Ctrl+Alt+W", auto_tooltip_l, self.autoWPeGPT_base_path),
                (self.autoWPeGPT_action_full,  auto_menu_full,  AutoFullHandler(),  "",           auto_tooltip_f,  self.autoWPeGPT_base_path),
                (self.autoWPeGPT_action_vuln,  auto_menu_vuln,  AutoVulnHandler(),  "",           auto_tooltip_v,  self.autoWPeGPT_base_path),
                (self.explain_action_name,   L["explain"],   ExplainHandler(),  "Ctrl+Alt+G", tooltips["explain"],    self.explain_menu_path),
                (self.rename_action_name,    L["rename"],    RenameHandler(),   "Ctrl+Alt+R", tooltips["rename"],     self.rename_menu_path),
                (self.python_action_name,    L["python"],    PythonHandler(),   "",           tooltips["python"],     self.python_menu_path),
                (self.vulnFinder_action_name, L["vuln"],     FindVulnHandler(), "Ctrl+Alt+E", tooltips["vuln"],       self.vulnFinder_menu_path),
                (self.expPython_action_name, L["exploit"],   expCreateHandler(), "",         tooltips["exploit"],    self.expPython_menu_path),
            ]
            for action_name, label, handler, hotkey, tooltip, menu_path in action_specs:
                idaapi.register_action(idaapi.action_desc_t(action_name, label, handler, hotkey, tooltip, 199))
                idaapi.attach_action_to_menu(menu_path, action_name, idaapi.SETMENU_APP)

            # 注册右键菜单
            self.menu = ContextMenuHooks()
            self.menu.hook()

            # 启动WPeServer
            wpe_server = WPeServer()
            if not wpe_server.start():
                print("[WPeGPT_Server] Error：服务器启动失败！")
                wpe_server = None

            print("[WPeGPT] %s v3.0 正常工作 :)@WPeace\n" % PLUGIN_NAME)
            return idaapi.PLUGIN_KEEP
        except Exception as e:
            print("[WPeGPT_Server] Error：插件初始化异常 — %s" % str(e))
            print("[WPeGPT] %s v3.0 已启动，但存在错误，请检查报错信息。@WPeace\n" % PLUGIN_NAME)
            return idaapi.PLUGIN_KEEP

    def run(self, arg):
        pass

    def term(self):
        idaapi.detach_action_from_menu(self.autoWPeGPT_base_path, self.autoWPeGPT_action_light)
        idaapi.detach_action_from_menu(self.autoWPeGPT_base_path, self.autoWPeGPT_action_full)
        idaapi.detach_action_from_menu(self.autoWPeGPT_base_path, self.autoWPeGPT_action_vuln)
        idaapi.detach_action_from_menu(self.explain_menu_path, self.explain_action_name)
        idaapi.detach_action_from_menu(self.rename_menu_path, self.rename_action_name)
        idaapi.detach_action_from_menu(self.python_menu_path, self.python_action_name)
        idaapi.detach_action_from_menu(self.vulnFinder_menu_path, self.vulnFinder_action_name)
        idaapi.detach_action_from_menu(self.expPython_menu_path, self.expPython_action_name)
        if self.menu:
            self.menu.unhook()
        global wpe_server
        if wpe_server:
            wpe_server.shutdown()
            wpe_server = None
        return


def PLUGIN_ENTRY():
    return type(f"myplugin_{PLUGIN_NAME}", (myplugin_WPeChatGPT, ), dict())()