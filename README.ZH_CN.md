> [!NOTE]
> WPeChatGPT 从 v3.0 起更名为 **WPeGPT**，进行了完整的架构重构。现有版本不受影响。

# WPeGPT

一个将 AI 集成到 IDA 的二进制分析工作流**插件**。WPeGPT 通过将 IDA 中的反编译伪代码发送给 AI 模型进行分析，实现代码分析变量重命名等功能。

受 [Gepetto](https://github.com/JusticeRage/Gepetto) 启发。

> AI 的分析结果**仅供参考**，不然我们这些分析师就当场失业了。XD

## 功能

### 交互式分析（IDA 插件）

| 功能 | 说明 |
|------|------|
| 函数分析 | 分析函数的用途、使用环境和行为 |
| 变量重命名 | 函数变量重命名 |
| Python 还原 | 使用 Python 重构实现伪代码的功能复现 |
| 漏洞查找 | 识别当前函数中的潜在漏洞 |
| Exploit 生成 | 尝试为有漏洞的函数生成利用代码 |

### 自动化分析（WPeServer + Controller）

v3.0 引入了基于 **TCP 的架构**，实现全自动二进制文件分析：

- **WPeServer** — 嵌入 IDA 的 TCP 服务器，接受外部控制器的命令。支持多个 IDA 实例并发运行。
- **三阶段分析流水线** — 有针对性的分段智能分析。
- **三种分析模式：**

  | 模式 | 说明 | 耗时 |
  |------|------|------|
  | `light` | 全局扫描 + 关键路径函数分析 | ~2-5 分钟 |
  | `full` | 全局扫描 + 关键路径 + 全量函数分析 | ~10-30 分钟 |
  | `vuln` | 关键路径函数漏洞分析 | ~5-20 分钟 |

- **智能字符串分类** — 自动将字符串分为 10 类：网络、键盘记录、加密、注入、持久化、反分析、投放器、代码执行、内存/文件操作、安装框架。
- **网络 IoC 提取** — 提取 IP、域名、URL 和端口。自动检测并尝试解密加密的 C2 地址。
- **函数可疑度评分** — 通过关键词匹配、调用者/被调用者关系、函数大小和标准库过滤对函数排名，优先分析高风险函数。
- **Shellcode 加载器检测** — 基于模式检测 shellcode 执行技术。
- **结构化报告** — 同时输出 JSON 和 Markdown 报告到 `<binary_name>_WPeAI_Results/`。

## 更新历史
|版本|日期|说明|
|----|----|----|
|1.0|2023-02-28|Based on Gepetto.|
|1.1|2023-03-02|1. 删除分析加解密的功能。<br>2. 增加 python 还原函数的功能。<br>3. 修改了一些细节。|
|1.2|2023-03-03|1. 增加查找函数中二进制漏洞的功能。<br>2. 增加尝试自动生成对应 EXP 的功能。<br>3. 修改了一些细节。<br>（由于OpenAI服务器卡顿原因未测试上传）|
|2.0|2023-03-06|1. 完成测试 *v1.2* 版本漏洞相关功能。<br>2. 改用 OpenAI 最新发布的 **gpt-3.5-turbo** 模型。|
|2.1|2023-03-07|修复 OpenAI-API 的 timed out 问题。（详见节***关于 OpenAI-API 报错***）|
|2.3|2023-04-23|添加 **Auto-WPeGPT v0.1**，支持对二进制文件的自动分析功能。<br>（从此版本需要添加包 *anytree*，使用 *requirements.txt* 或 *pip install anytree*）|
|2.4|2023-11-10|1. 修改了一些显示细节。<br>2. 更新 **Auto-WPeGPT v0.2**。|
|2.5|2024-08-07|1. 添加了对其他模型的支持。@tpsnt<br> - 通过修改 *MODEL* 变量，可以支持其他模型<br> - 设置环境变量 *OPENAI_API_BASE* 为 "https://dashscope.aliyuncs.com/compatible-mode/v1" ，将 *MODEL* 设置为 qwen-max、qwen-long、qwen-plus 等，可以使用灵积API<br> - 将插件进行复制并修改 *PLUGIN_NAME*，可以允许多个模型同时存在<br>2. 修改代码适配最新的 python openai 包。（需要使用pip更新你的openai包）|
|2.6|2025-02-17|添加对DeepSeek的支持，你需要将变量*PLUGIN_NAME*设置为"WPeChat-DeepSeek"，同时将你的API KEY填入*model_api_key*变量。<br>（默认为DeepSeek-V3模型，如果希望调用R1模型，修改变量 **MODEL** = *'deepseek-reasoner'* 即可）|
| **3.0** | **2026-05-27** | **更名为 WPeGPT，完整架构重构：**<br>1. 模块化架构（`WPeGPT.py` + `config.py` + `wpe_ai_controller.py`）。<br>2. 引入 **WPeServer**（TCP 命令服务器）实现外部 AI 驱动自动化分析。<br>3. **三阶段分析流水线**（全局扫描 → 关键路径 → 全量扫描）。<br>4. **三种分析模式**（轻量 / 全量 / 漏洞）。<br>5. 智能字符串分类（10 类）和网络 IoC 提取。<br>6. 函数可疑度评分系统 + 标准库过滤。<br>7. Shellcode 加载器检测。<br>8. 结构化 JSON + Markdown 报告生成。 |

## 安装

### 1. 安装依赖

```bash
pip install -r ./requirements.txt
```

### 2. 配置

编辑 `WPeGPT_Config/config.py`：

- 设置你的 `API_KEY`
- 设置 `API_BASE_URL`
- 设置 `MODEL`
- 设置 `ZH_CN = True` 使用中文（默认），`False` 使用英文
- 可选配置 `ANALYSIS_MODE`、`MAX_WORKERS` 等

### 3. 安装插件

将 `WPeGPT.py` 和 `WPeGPT_Config/` 文件夹复制到 IDA 的 `plugins/` 目录，重启 IDA 后即可使用。

> **`! NOTE`**：IDA 环境必须配置为 **Python 3**。

## 使用方法

### 交互模式（IDA 插件）

- **快捷键：**

  | 快捷键 | 功能 |
  |--------|------|
  | `Ctrl+Alt+G` | 函数分析 |
  | `Ctrl+Alt+R` | 重命名函数变量 |
  | `Ctrl+Alt+E` | 二进制漏洞查找 |
  | `Ctrl+Alt+W` | 轻量自动化分析 |

- **伪代码窗口右键菜单**

&emsp;&emsp;<img src="https://github.com/WPeace-HcH/WPeGPT/blob/main/IMG/menuInPseudocode.png" width="788"/>

- **菜单栏**：Edit → WPeGPT

&emsp;&emsp;<img src="https://github.com/WPeace-HcH/WPeGPT/blob/main/IMG/menuInEdit.png" width="360"/>

### 自动模式（无头分析）

使用 [wpegpt-analyzer](https://github.com/WPeace-HcH/wpegpt-analyzer) 技能，或通过菜单栏：Edit → WPeGPT → 自动化分析

报告将保存到 `<binary_name>_WPeAI_Results/`。

## 示例

使用方式：

&emsp;&emsp;<img src="https://github.com/WPeace-HcH/WPeGPT/blob/main/IMG/useExample.gif" width="790"/>

函数分析效果展示：

&emsp;&emsp;<img src="https://github.com/WPeace-HcH/WPeGPT/blob/main/IMG/resultExample.gif" width="790"/>

二进制漏洞查找效果展示：

&emsp;&emsp;<img src="https://github.com/WPeace-HcH/WPeGPT/blob/main/IMG/vulnExample.gif" width="790"/>

## 关于 OpenAI-API 报错

在科学上网条件下仍遇到连接问题：

- 检查 `urllib3` 版本 — v1.26 存在代理问题。修复方法：
  ```bash
  pip uninstall urllib3
  pip install urllib3==1.25.11
  ```
- 在 `config.py` 中配置 `FORWARD_PROXY`（例如 `http://127.0.0.1:7890`）。
- 或通过设置 `API_BASE_URL` 使用反向代理。

## 联系我

如果使用插件时遇到问题或有任何疑问，欢迎提交 Issue 或发送邮件。
