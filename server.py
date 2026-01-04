"""
Gemini OpenAI 兼容 API 服务

启动: python server.py
后台: http://localhost:23456/admin
API:  http://localhost:23456/v1
"""

from fastapi import FastAPI, HTTPException, Header, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, RedirectResponse, StreamingResponse, JSONResponse
from pydantic import BaseModel
from typing import List, Dict, Any, Optional, Union
import uvicorn
import time
import uuid
import json
import os
import re
import httpx
import hashlib
import secrets

# ============ 配置 ============
API_KEY = "sk-geminixxxxx"
HOST = "0.0.0.0"
PORT = 23456
CONFIG_FILE = "config_data.json"
# 后台登录账号密码
ADMIN_USERNAME = "admin"
ADMIN_PASSWORD = "admin123"
# ==============================

app = FastAPI(title="Gemini OpenAI API", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# 静态文件路由 (CSS, JS, 图片等)
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

# 挂载静态文件目录
if os.path.exists("static"):
    app.mount("/static", StaticFiles(directory="static"), name="static")

# 提供根目录的 image.png 文件（兼容旧路径）
@app.get("/static/image.png")
async def serve_image():
    """提供示例图片"""
    # 优先从 static 目录查找
    static_path = os.path.join(os.path.dirname(__file__), "static", "image.png")
    root_path = os.path.join(os.path.dirname(__file__), "image.png")
    
    if os.path.exists(static_path):
        return FileResponse(static_path)
    elif os.path.exists(root_path):
        return FileResponse(root_path)
    else:
        raise HTTPException(status_code=404, detail="示例图片不存在")

# 存储有效的 session token
_admin_sessions = set()

def generate_session_token():
    """生成随机 session token"""
    return secrets.token_hex(32)

def verify_admin_session(request: Request):
    """验证管理员 session"""
    token = request.cookies.get("admin_session")
    if not token or token not in _admin_sessions:
        return False
    return True

# 默认可用模型列表 (Gemini 3 官网三个模型: 快速/思考/Pro)
DEFAULT_MODELS = ["gemini-3.0-flash", "gemini-3.0-flash-thinking", "gemini-3.0-pro"]

# 默认模型 ID (用于请求头选择模型)
DEFAULT_MODEL_IDS = {
    "flash": "56fdd199312815e2",
    "pro": "e6fa609c3fa255c0", 
    "thinking": "e051ce1aa80aa576",
}

# 配置存储
_config = {
    "SNLM0E": "",
    "SECURE_1PSID": "",
    "SECURE_1PSIDTS": "",
    "SAPISID": "",
    "SID": "",
    "HSID": "",
    "SSID": "",
    "APISID": "",
    "PUSH_ID": "",
    "FULL_COOKIE": "",  # 存储完整cookie字符串
    "MANUAL_SNLM0E": "",  # 手动输入的 AT Token（用于保存用户输入）
    "MANUAL_PUSH_ID": "",  # 手动输入的 PUSH_ID（用于保存用户输入）
    "MODELS": DEFAULT_MODELS.copy(),  # 可用模型列表
    "MODEL_IDS": DEFAULT_MODEL_IDS.copy(),  # 模型 ID 映射
}

# Cookie 字段映射 (浏览器cookie名 -> 配置字段名)
COOKIE_FIELD_MAP = {
    "__Secure-1PSID": "SECURE_1PSID",
    "__Secure-1PSIDTS": "SECURE_1PSIDTS",
    "SAPISID": "SAPISID",
    "__Secure-1PAPISID": "SAPISID",  # 也映射到 SAPISID
    "SID": "SID",
    "HSID": "HSID",
    "SSID": "SSID",
    "APISID": "APISID",
}


def parse_cookie_string(cookie_str: str) -> dict:
    """解析完整cookie字符串，提取所需字段"""
    result = {}
    if not cookie_str:
        return result
    
    for item in cookie_str.split(";"):
        item = item.strip()
        if "=" in item:
            eq_index = item.index("=")
            key = item[:eq_index].strip()
            value = item[eq_index + 1:].strip()
            if key in COOKIE_FIELD_MAP:
                result[COOKIE_FIELD_MAP[key]] = value
    
    return result


def fetch_tokens_from_page(cookies_str: str) -> dict:
    """从 Gemini 页面自动获取 SNLM0E、PUSH_ID 和可用模型列表"""
    result = {"snlm0e": "", "push_id": "", "models": [], "error": ""}
    try:
        import os
        import ssl
        
        # 配置 SSL，与 client.py 保持一致
        verify_ssl = True
        if os.environ.get("DISABLE_SSL_VERIFY") == "1":
            verify_ssl = False
        
        # 如果代理有问题，可以通过设置环境变量 DISABLE_PROXY=1 来临时清除代理环境变量
        if os.environ.get("DISABLE_PROXY") == "1":
            os.environ.pop("HTTP_PROXY", None)
            os.environ.pop("HTTPS_PROXY", None)
            os.environ.pop("http_proxy", None)
            os.environ.pop("https_proxy", None)
        
        session = httpx.Client(
            timeout=30.0,
            follow_redirects=True,
            verify=verify_ssl,
            headers={
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
                "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8",
            }
        )
        
        # 设置 cookies
        cookie_count = 0
        for item in cookies_str.split(";"):
            item = item.strip()
            if "=" in item:
                key, value = item.split("=", 1)
                key = key.strip()
                value = value.strip()
                if key and value:
                    session.cookies.set(key, value, domain=".google.com")
                    cookie_count += 1
        
        if cookie_count == 0:
            result["error"] = "Cookie 格式错误：未找到有效的 Cookie 键值对"
            return result
        
        resp = session.get("https://gemini.google.com")
        if resp.status_code != 200:
            result["error"] = f"请求失败：HTTP {resp.status_code}，可能是 Cookie 无效或网络问题"
            return result
        
        html = resp.text
        
        # 检查是否是登录页面（Cookie 可能已过期）
        if "signin" in html.lower() or "login" in html.lower() or len(html) < 10000:
            result["error"] = "检测到登录页面，Cookie 可能已过期，请重新获取最新的 Cookie"
            return result
        
        # 获取 SNLM0E (AT Token) - 增加更多匹配模式
        snlm0e_patterns = [
            r'"SNlM0e"\s*:\s*"([^"]+)"',  # 标准格式
            r'"SNlM0e":\s*"([^"]+)"',     # 无空格
            r'SNlM0e["\s:]+["\']([^"\']+)["\']',  # 灵活格式
            r'"at"\s*:\s*"([^"]+)"',      # at 字段
            r'var\s+SNlM0e\s*=\s*["\']([^"\']+)["\']',  # JavaScript 变量
            r'window\.SNlM0e\s*=\s*["\']([^"\']+)["\']',  # window 对象
            r'SNlM0e\s*=\s*["\']([^"\']+)["\']',  # 直接赋值
            r'["\']SNlM0e["\']\s*:\s*["\']([^"\']+)["\']',  # 字符串键
        ]
        
        for pattern in snlm0e_patterns:
            match = re.search(pattern, html, re.IGNORECASE)
            if match:
                token = match.group(1)
                # 验证 token 长度（通常 AT Token 是较长的字符串）
                if len(token) > 10:
                    result["snlm0e"] = token
                    break
        
        # 如果还是没找到，尝试在 JavaScript 代码块中搜索
        if not result["snlm0e"]:
            # 搜索 script 标签中的内容
            script_pattern = r'<script[^>]*>(.*?)</script>'
            scripts = re.findall(script_pattern, html, re.DOTALL | re.IGNORECASE)
            for script in scripts:
                for pattern in snlm0e_patterns:
                    match = re.search(pattern, script, re.IGNORECASE)
                    if match:
                        token = match.group(1)
                        if len(token) > 10:
                            result["snlm0e"] = token
                            break
                if result["snlm0e"]:
                    break
        
        # 获取 PUSH_ID - 增加更多匹配模式
        push_id_patterns = [
            r'"push[_-]?id["\s:]+["\'](feeds/[a-z0-9]+)["\']',  # "push_id": "feeds/xxx"
            r'push[_-]?id["\s:=]+["\'](feeds/[a-z0-9]+)["\']',  # push_id="feeds/xxx"
            r'feedName["\s:]+["\'](feeds/[a-z0-9]+)["\']',      # "feedName": "feeds/xxx"
            r'clientId["\s:]+["\'](feeds/[a-z0-9]+)["\']',      # "clientId": "feeds/xxx"
            r'["\']push[_-]?id["\']\s*:\s*["\'](feeds/[a-z0-9]+)["\']',  # 'push_id': 'feeds/xxx'
            r'push[_-]?id\s*=\s*["\'](feeds/[a-z0-9]+)["\']',   # push_id = "feeds/xxx"
            r'(feeds/[a-z0-9]{14,})',                            # 直接匹配 feeds/xxx 格式（14位以上）
        ]
        
        # 先尝试精确匹配
        for pattern in push_id_patterns:
            matches = re.findall(pattern, html, re.IGNORECASE)
            if matches:
                # 验证格式（应该是 feeds/ 开头，后面跟着字母数字）
                for match in matches:
                    if match.startswith("feeds/") and len(match) > 15:
                        result["push_id"] = match
                        break
                if result["push_id"]:
                    break
        
        # 如果精确匹配失败，尝试在 JavaScript 代码块中搜索
        if not result["push_id"]:
            script_pattern = r'<script[^>]*>(.*?)</script>'
            scripts = re.findall(script_pattern, html, re.DOTALL | re.IGNORECASE)
            for script in scripts:
                for pattern in push_id_patterns:
                    matches = re.findall(pattern, script, re.IGNORECASE)
                    if matches:
                        for match in matches:
                            if match.startswith("feeds/") and len(match) > 15:
                                result["push_id"] = match
                                break
                        if result["push_id"]:
                            break
                if result["push_id"]:
                    break
        
        # 获取可用模型列表 (从页面中提取 gemini 模型 ID)
        model_patterns = [
            r'"(gemini-[a-z0-9\.\-]+)"',  # 匹配 "gemini-xxx" 格式
            r"'(gemini-[a-z0-9\.\-]+)'",  # 匹配 'gemini-xxx' 格式
        ]
        models_found = set()
        for pattern in model_patterns:
            matches = re.findall(pattern, html, re.IGNORECASE)
            for m in matches:
                # 过滤有效的模型名称
                if any(x in m.lower() for x in ['flash', 'pro', 'ultra', 'nano']):
                    models_found.add(m)
        
        if models_found:
            result["models"] = sorted(list(models_found))
        
        # 获取模型 ID (用于 x-goog-ext-525001261-jspb 请求头)
        # 这些 ID 用于选择不同的模型版本
        model_id_pattern = r'\["([a-f0-9]{16})","gemini[^"]*(?:flash|pro|thinking)[^"]*"\]'
        model_ids = re.findall(model_id_pattern, html, re.IGNORECASE)
        if model_ids:
            result["model_ids"] = list(set(model_ids))
        
        # 备用方案：直接搜索 16 位十六进制 ID（在模型配置附近）
        if not result.get("model_ids"):
            # 搜索类似 "56fdd199312815e2" 的模式
            hex_id_pattern = r'"([a-f0-9]{16})"'
            # 在包含 gemini 或 model 的上下文中查找
            context_pattern = r'.{0,100}(?:gemini|model|flash|pro|thinking).{0,100}'
            contexts = re.findall(context_pattern, html, re.IGNORECASE)
            hex_ids = set()
            for ctx in contexts:
                ids = re.findall(hex_id_pattern, ctx)
                hex_ids.update(ids)
            if hex_ids:
                result["model_ids"] = list(hex_ids)
        
        return result
    except httpx.TimeoutException:
        result["error"] = "请求超时，请检查网络连接"
        return result
    except httpx.RequestError as e:
        result["error"] = f"网络请求失败：{str(e)}"
        return result
    except Exception as e:
        result["error"] = f"未知错误：{str(e)}"
        return result

_client = None


# ============ Tools 支持 ============
def build_tools_prompt(tools: List[Dict]) -> str:
    """将 tools 定义转换为提示词"""
    if not tools:
        return ""
    
    tools_schema = json.dumps([{
        "name": t["function"]["name"],
        "description": t["function"].get("description", ""),
        "parameters": t["function"].get("parameters", {})
    } for t in tools if t.get("type") == "function"], ensure_ascii=False, indent=2)
    
    prompt = f"""[系统指令] 你必须作为函数调用代理。不要自己回答问题，必须调用函数。

可用函数:
{tools_schema}

严格规则:
1. 你不能直接回答用户问题
2. 你必须选择一个函数并调用它
3. 只输出以下格式，不要有任何其他文字:
```tool_call
{{"name": "函数名", "arguments": {{"参数": "值"}}}}
```

用户请求: """
    return prompt


def parse_tool_calls(content: str) -> tuple:
    """
    解析响应中的工具调用
    返回: (tool_calls列表, 剩余文本内容)
    """
    tool_calls = []
    
    # 多种匹配模式
    patterns = [
        r'```tool_call\s*\n?(.*?)\n?```',  # ```tool_call ... ```
        r'```json\s*\n?(.*?)\n?```',        # ```json ... ``` (有时模型会用这个)
        r'```\s*\n?(\{[^`]*"name"[^`]*\})\n?```',  # ``` {...} ```
    ]
    
    matches = []
    for pattern in patterns:
        found = re.findall(pattern, content, re.DOTALL)
        matches.extend(found)
    
    # 也尝试直接匹配 JSON 对象（没有代码块包裹的情况）
    if not matches:
        json_pattern = r'\{[^{}]*"name"\s*:\s*"[^"]+"\s*,\s*"arguments"\s*:\s*\{[^{}]*\}[^{}]*\}'
        matches = re.findall(json_pattern, content, re.DOTALL)
    
    for i, match in enumerate(matches):
        try:
            match = match.strip()
            # 尝试解析 JSON
            call_data = json.loads(match)
            if call_data.get("name"):
                tool_calls.append({
                    "id": f"call_{uuid.uuid4().hex[:8]}",
                    "type": "function",
                    "function": {
                        "name": call_data.get("name", ""),
                        "arguments": json.dumps(call_data.get("arguments", {}), ensure_ascii=False)
                    }
                })
        except json.JSONDecodeError:
            continue
    
    # 移除工具调用部分
    remaining = content
    for pattern in patterns:
        remaining = re.sub(pattern, '', remaining, flags=re.DOTALL)
    remaining = remaining.strip()
    
    return tool_calls, remaining


def load_config():
    """
    加载配置，优先级:
    1. config_data.json (前端保存的配置)
    2. config.py (本地开发配置，仅作为备用)
    """
    global _config
    loaded_from_json = False
    
    # 优先从 JSON 文件加载
    if os.path.exists(CONFIG_FILE):
        try:
            with open(CONFIG_FILE, "r", encoding="utf-8") as f:
                saved = json.load(f)
                if saved.get("SNLM0E") and saved.get("SECURE_1PSID"):
                    _config.update(saved)
                    loaded_from_json = True
        except:
            pass
    
    # 如果 JSON 没有有效配置，尝试从 config.py 加载
    if not loaded_from_json:
        try:
            import config
            for key in _config:
                if hasattr(config, key) and getattr(config, key):
                    _config[key] = getattr(config, key)
        except:
            pass


def save_config():
    with open(CONFIG_FILE, "w", encoding="utf-8") as f:
        json.dump(_config, f, indent=2, ensure_ascii=False)


def get_client():
    global _client
    
    if not _config.get("SNLM0E") or not _config.get("SECURE_1PSID"):
        raise HTTPException(status_code=500, detail="请先在后台配置 Token 和 Cookie")
    
    # 如果 client 已存在，直接复用，保持会话上下文
    if _client is not None:
        return _client
    
    cookies = f"__Secure-1PSID={_config['SECURE_1PSID']}"
    if _config.get("SECURE_1PSIDTS"):
        cookies += f"; __Secure-1PSIDTS={_config['SECURE_1PSIDTS']}"
    if _config.get("SAPISID"):
        cookies += f"; SAPISID={_config['SAPISID']}; __Secure-1PAPISID={_config['SAPISID']}"
    if _config.get("SID"):
        cookies += f"; SID={_config['SID']}"
    if _config.get("HSID"):
        cookies += f"; HSID={_config['HSID']}"
    if _config.get("SSID"):
        cookies += f"; SSID={_config['SSID']}"
    if _config.get("APISID"):
        cookies += f"; APISID={_config['APISID']}"
    
    from client import GeminiClient
    _client = GeminiClient(
        secure_1psid=_config["SECURE_1PSID"],
        snlm0e=_config["SNLM0E"],
        cookies_str=cookies,
        push_id=_config.get("PUSH_ID") or None,
        model_ids=_config.get("MODEL_IDS") or DEFAULT_MODEL_IDS,
        debug=False,
    )
    return _client


def get_login_html():
    """读取登录页面模板"""
    template_path = os.path.join(os.path.dirname(__file__), "templates", "login.html")
    if os.path.exists(template_path):
        with open(template_path, "r", encoding="utf-8") as f:
            return f.read()
    else:
        # 降级方案：返回简单的HTML
        return '''<!DOCTYPE html>
<html><head><title>登录</title></head>
<body><h1>模板文件未找到，请确保 templates/login.html 存在</h1></body>
</html>'''


def get_admin_html():
    """读取管理后台页面模板并替换变量"""
    template_path = os.path.join(os.path.dirname(__file__), "templates", "admin.html")
    if os.path.exists(template_path):
        with open(template_path, "r", encoding="utf-8") as f:
            html = f.read()
            # 替换模板变量
            html = html.replace("{{ API_KEY }}", API_KEY)
            html = html.replace("{{ PORT }}", str(PORT))
            return html
    else:
        # 降级方案：返回简单的HTML
        return f'''<!DOCTYPE html>
<html><head><title>配置</title></head>
<body><h1>模板文件未找到，请确保 templates/admin.html 存在</h1>
<p>API Key: {API_KEY}</p>
<p>Port: {PORT}</p>
</body>
</html>'''


@app.get("/admin/login", response_class=HTMLResponse)
async def admin_login_page():
    return get_login_html()


@app.post("/admin/login")
async def admin_login(request: Request):
    data = await request.json()
    username = data.get("username", "")
    password = data.get("password", "")
    
    if username == ADMIN_USERNAME and password == ADMIN_PASSWORD:
        token = generate_session_token()
        _admin_sessions.add(token)
        response = JSONResponse({"success": True, "message": "登录成功"})
        response.set_cookie(key="admin_session", value=token, httponly=True, max_age=86400)
        return response
    else:
        return {"success": False, "message": "用户名或密码错误"}


@app.get("/admin/logout")
async def admin_logout(request: Request):
    token = request.cookies.get("admin_session")
    if token and token in _admin_sessions:
        _admin_sessions.discard(token)
    response = RedirectResponse(url="/admin/login", status_code=302)
    response.delete_cookie("admin_session")
    return response


@app.get("/admin", response_class=HTMLResponse)
async def admin_page(request: Request):
    if not verify_admin_session(request):
        return RedirectResponse(url="/admin/login", status_code=302)
    return get_admin_html()


@app.post("/admin/save")
async def admin_save(request: Request):
    if not verify_admin_session(request):
        raise HTTPException(status_code=401, detail="未登录")
    
    global _client
    data = await request.json()
    
    # 处理完整 Cookie 字符串，去除前后空格
    full_cookie = data.get("FULL_COOKIE", "").strip()
    if not full_cookie:
        return {"success": False, "message": "Cookie 是必填项"}
    
    # 解析 Cookie 字符串
    parsed = parse_cookie_string(full_cookie)
    
    if not parsed.get("SECURE_1PSID"):
        return {"success": False, "message": "Cookie 中未找到 __Secure-1PSID 字段，请确保复制了完整的 Cookie"}
    
    # 从页面自动获取 SNLM0E 和 PUSH_ID
    tokens = fetch_tokens_from_page(full_cookie)
    
    # 检查是否有手动输入的 AT Token
    manual_snlm0e = data.get("MANUAL_SNLM0E", "").strip()
    token_source = ""  # 初始化变量
    
    # 确定使用哪个 AT Token
    if manual_snlm0e:
        # 优先使用手动输入的 Token
        snlm0e_to_use = manual_snlm0e
        token_source = "手动输入"
    elif tokens.get("snlm0e"):
        # 使用自动获取的 Token
        snlm0e_to_use = tokens["snlm0e"]
        token_source = "自动获取"
    else:
        # 两者都没有，返回错误
        error_msg = tokens.get("error", "未知错误")
        if error_msg:
            return {
                "success": False, 
                "message": f"无法自动获取 AT Token：{error_msg}\n\n提示：如果自动获取失败，可以在上方手动填写 AT Token。获取方法：打开 gemini.google.com → F12 → 查看页面源代码 (Ctrl+U) → 搜索 'SNlM0e' → 复制引号内的值"
            }
        else:
            return {
                "success": False, 
                "message": "无法自动获取 AT Token，请检查 Cookie 是否有效或已过期。\n\n提示：\n1. 请确保 Cookie 是从已登录的浏览器中完整复制的，包含所有字段\n2. 如果自动获取失败，可以在上方手动填写 AT Token"
            }
    
    # 检查是否有手动输入的 PUSH_ID
    manual_push_id = data.get("MANUAL_PUSH_ID", "").strip()
    
    # 确定使用哪个 PUSH_ID
    if manual_push_id:
        # 优先使用手动输入的 PUSH_ID
        push_id_to_use = manual_push_id
        # 确保格式正确（应该是 feeds/xxxxx）
        if not push_id_to_use.startswith("feeds/"):
            if "/" not in push_id_to_use:
                push_id_to_use = f"feeds/{push_id_to_use}"
            else:
                # 如果用户输入了完整路径，直接使用
                pass
    elif tokens.get("push_id"):
        # 使用自动获取的 PUSH_ID
        push_id_to_use = tokens["push_id"]
    else:
        # 两者都没有，保持为空（图片功能不可用）
        push_id_to_use = ""
    
    # 更新配置
    _config["FULL_COOKIE"] = full_cookie
    _config["SNLM0E"] = snlm0e_to_use
    _config["PUSH_ID"] = push_id_to_use
    
    # 保存手动输入的值（无论是否为空，都保存，这样用户可以清空）
    # 如果字段在表单中存在，就保存它（包括空字符串）
    if "MANUAL_SNLM0E" in data:
        _config["MANUAL_SNLM0E"] = manual_snlm0e
    
    if "MANUAL_PUSH_ID" in data:
        _config["MANUAL_PUSH_ID"] = manual_push_id
    
    # 从解析结果更新各字段
    for field in ["SECURE_1PSID", "SECURE_1PSIDTS", "SAPISID", "SID", "HSID", "SSID", "APISID"]:
        _config[field] = parsed.get(field, "")
    
    # 使用自动获取的模型列表，如果获取失败则使用默认值
    if tokens.get("models"):
        _config["MODELS"] = tokens["models"]
    else:
        _config["MODELS"] = DEFAULT_MODELS.copy()
    
    # 处理模型 ID 配置
    model_ids = data.get("MODEL_IDS", {})
    if model_ids:
        # 只更新非空的值
        if model_ids.get("flash"):
            _config["MODEL_IDS"]["flash"] = model_ids["flash"]
        if model_ids.get("pro"):
            _config["MODEL_IDS"]["pro"] = model_ids["pro"]
        if model_ids.get("thinking"):
            _config["MODEL_IDS"]["thinking"] = model_ids["thinking"]
    
    save_config()
    _client = None
    
    # 构建结果信息
    parsed_fields = [k for k in ["SECURE_1PSID", "SECURE_1PSIDTS", "SAPISID", "SID", "HSID", "SSID", "APISID"] if parsed.get(k)]
    push_id_source = ""
    if manual_push_id:
        push_id_source = "（手动输入）"
    elif tokens.get("push_id"):
        push_id_source = "（自动获取）"
    push_id_msg = f"，PUSH_ID ✓ {push_id_source}" if _config.get("PUSH_ID") else "，PUSH_ID ✗ (图片功能不可用)"
    models_msg = f"，{len(_config['MODELS'])} 个模型" if _config.get("MODELS") else ""
    token_source_msg = f"（{token_source}）" if token_source else ""
    
    try:
        get_client()
        return {
            "success": True, 
            "message": f"配置已保存并验证成功！AT Token ✓ {token_source_msg}{push_id_msg}{models_msg}",
            "need_restart": False
        }
    except Exception as e:
        return {
            "success": True, 
            "message": f"配置已保存，但连接测试失败: {str(e)[:50]}",
            "need_restart": False
        }


@app.get("/admin/config")
async def admin_get_config(request: Request):
    if not verify_admin_session(request):
        raise HTTPException(status_code=401, detail="未登录")
    return _config


# ============ API 路由 ============

class ChatMessage(BaseModel):
    role: str
    content: Union[str, List[Dict[str, Any]]]
    name: Optional[str] = None
    
    class Config:
        extra = "ignore"


class FunctionDefinition(BaseModel):
    name: str
    description: Optional[str] = None
    parameters: Optional[Dict[str, Any]] = None

class ToolDefinition(BaseModel):
    type: str = "function"
    function: FunctionDefinition

class ChatCompletionRequest(BaseModel):
    model: str = "gemini"
    messages: List[ChatMessage]
    stream: Optional[bool] = False
    # Tools 支持
    tools: Optional[List[ToolDefinition]] = None
    tool_choice: Optional[Union[str, Dict[str, Any]]] = None
    # OpenAI SDK 可能发送的额外字段
    temperature: Optional[float] = None
    max_tokens: Optional[int] = None
    top_p: Optional[float] = None
    frequency_penalty: Optional[float] = None
    presence_penalty: Optional[float] = None
    stop: Optional[Union[str, List[str]]] = None
    n: Optional[int] = None
    user: Optional[str] = None
    
    class Config:
        extra = "ignore"  # 忽略未定义的额外字段


class ChatCompletionChoice(BaseModel):
    index: int
    message: Dict[str, Any]
    finish_reason: str


class Usage(BaseModel):
    prompt_tokens: int
    completion_tokens: int
    total_tokens: int


class ChatCompletionResponse(BaseModel):
    id: str
    object: str = "chat.completion"
    created: int
    model: str
    choices: List[ChatCompletionChoice]
    usage: Usage


def verify_api_key(authorization: str = Header(None)):
    if not API_KEY:
        return True
    if not authorization or not authorization.startswith("Bearer ") or authorization[7:] != API_KEY:
        raise HTTPException(status_code=401, detail="Invalid API key")
    return True


@app.get("/")
async def root():
    return RedirectResponse(url="/admin")


@app.get("/v1/models")
async def list_models(authorization: str = Header(None)):
    verify_api_key(authorization)
    models = _config.get("MODELS", DEFAULT_MODELS)
    created = int(time.time())
    return {
        "object": "list",
        "data": [{"id": m, "object": "model", "created": created, "owned_by": "google"} for m in models]
    }


def log_api_call(request_data: dict, response_data: dict, error: str = None):
    """记录 API 调用日志到文件"""
    import datetime
    log_entry = {
        "timestamp": datetime.datetime.now().isoformat(),
        "request": request_data,
        "response": response_data,
        "error": error
    }
    try:
        with open("api_logs.json", "a", encoding="utf-8") as f:
            f.write(json.dumps(log_entry, ensure_ascii=False, indent=2) + "\n---\n")
    except Exception as e:
        print(f"[LOG ERROR] 写入日志失败: {e}")


# 用于追踪会话：保存上次请求的所有用户消息内容
_last_user_messages_hash = ""


def get_user_messages_hash(messages: list) -> str:
    """计算所有用户消息的 hash，用于判断是否是同一会话"""
    content_str = ""
    for m in messages:
        role = m.role if hasattr(m, 'role') else m.get('role', '')
        if role != "user":
            continue
        content = m.content if hasattr(m, 'content') else m.get('content', '')
        if isinstance(content, list):
            # 对于包含图片的消息，只取文本部分
            text_parts = [item.get('text', '') for item in content if item.get('type') == 'text']
            content_str += f"{' '.join(text_parts)}|"
        else:
            content_str += f"{content}|"
    return hashlib.md5(content_str.encode()).hexdigest()


def is_continuation(current_messages: list, last_hash: str) -> bool:
    """
    判断当前请求是否是上一次对话的延续
    
    逻辑：如果当前消息去掉最后一条用户消息后的 hash 等于上次的 hash，
    说明是同一对话的延续
    """
    if not last_hash:
        return False
    
    # 找到所有用户消息
    user_indices = [i for i, m in enumerate(current_messages) 
                    if (m.role if hasattr(m, 'role') else m.get('role', '')) == "user"]
    
    if len(user_indices) <= 1:
        # 只有一条用户消息，无法判断是否延续，视为新对话
        return False
    
    # 去掉最后一条用户消息，计算剩余消息的 hash
    last_user_idx = user_indices[-1]
    prev_messages = current_messages[:last_user_idx]
    prev_hash = get_user_messages_hash(prev_messages)
    
    return prev_hash == last_hash


@app.post("/v1/chat/completions")
async def chat_completions(request: ChatCompletionRequest, authorization: str = Header(None)):
    global _last_user_messages_hash
    verify_api_key(authorization)
    
    # 记录请求入参 (图片内容截断显示)
    request_log = {
        "model": request.model,
        "stream": request.stream,
        "messages": [],
        "tools": [t.model_dump() for t in request.tools] if request.tools else None
    }
    for m in request.messages:
        msg_log = {"role": m.role}
        if isinstance(m.content, list):
            content_log = []
            for item in m.content:
                if item.get("type") == "image_url":
                    img_url = item.get("image_url", {})
                    if isinstance(img_url, dict):
                        url = img_url.get("url", "")
                    else:
                        url = str(img_url)
                    content_log.append({"type": "image_url", "url_preview": url[:100] + "..." if len(url) > 100 else url})
                else:
                    content_log.append(item)
            msg_log["content"] = content_log
        else:
            msg_log["content"] = m.content
        request_log["messages"].append(msg_log)
    
    try:
        client = get_client()
        
        if not is_continuation(request.messages, _last_user_messages_hash):
            client.reset()
        
        # 处理消息
        messages = []
        for m in request.messages:
            content = m.content
            if isinstance(content, list):
                messages.append({"role": m.role, "content": content})
            else:
                messages.append({"role": m.role, "content": content})
        
        # 如果有 tools，把工具提示词直接加到用户消息前面
        if request.tools and len(messages) > 0:
            tools_prompt = build_tools_prompt([t.model_dump() for t in request.tools])
            for i in range(len(messages) - 1, -1, -1):
                if messages[i]["role"] == "user":
                    original = messages[i]["content"]
                    if isinstance(original, str):
                        messages[i]["content"] = tools_prompt + original
                    break
        
        response = client.chat(messages=messages, model=request.model)
        _last_user_messages_hash = get_user_messages_hash(request.messages)
        
        reply_content = response.choices[0].message.content
        completion_id = f"chatcmpl-{uuid.uuid4().hex[:8]}"
        created_time = int(time.time())
        
        # 解析工具调用
        tool_calls = []
        final_content = reply_content
        if request.tools:
            tool_calls, final_content = parse_tool_calls(reply_content)
        
        # 处理流式响应
        if request.stream:
            async def generate_stream():
                chunk_data = {
                    "id": completion_id,
                    "object": "chat.completion.chunk",
                    "created": created_time,
                    "model": request.model,
                    "choices": [{
                        "index": 0,
                        "delta": {"role": "assistant"},
                        "finish_reason": None
                    }]
                }
                yield f"data: {json.dumps(chunk_data)}\n\n"
                
                if tool_calls:
                    # 流式返回工具调用
                    for tc in tool_calls:
                        chunk_data = {
                            "id": completion_id,
                            "object": "chat.completion.chunk",
                            "created": created_time,
                            "model": request.model,
                            "choices": [{
                                "index": 0,
                                "delta": {"tool_calls": [tc]},
                                "finish_reason": None
                            }]
                        }
                        yield f"data: {json.dumps(chunk_data)}\n\n"
                else:
                    chunk_data = {
                        "id": completion_id,
                        "object": "chat.completion.chunk",
                        "created": created_time,
                        "model": request.model,
                        "choices": [{
                            "index": 0,
                            "delta": {"content": final_content},
                            "finish_reason": None
                        }]
                    }
                    yield f"data: {json.dumps(chunk_data)}\n\n"
                
                chunk_data = {
                    "id": completion_id,
                    "object": "chat.completion.chunk",
                    "created": created_time,
                    "model": request.model,
                    "choices": [{
                        "index": 0,
                        "delta": {},
                        "finish_reason": "tool_calls" if tool_calls else "stop"
                    }]
                }
                yield f"data: {json.dumps(chunk_data)}\n\n"
                yield "data: [DONE]\n\n"
            
            return StreamingResponse(
                generate_stream(), 
                media_type="text/event-stream",
                headers={
                    "Cache-Control": "no-cache",
                    "Connection": "keep-alive",
                    "X-Accel-Buffering": "no",
                }
            )
        
        # 构建响应消息
        response_message = {"role": "assistant"}
        if tool_calls:
            response_message["content"] = final_content if final_content else None
            response_message["tool_calls"] = tool_calls
            finish_reason = "tool_calls"
        else:
            response_message["content"] = final_content
            finish_reason = "stop"
        
        response_data = ChatCompletionResponse(
            id=completion_id,
            created=created_time,
            model=request.model,
            choices=[ChatCompletionChoice(index=0, message=response_message, finish_reason=finish_reason)],
            usage=Usage(prompt_tokens=response.usage.prompt_tokens, completion_tokens=response.usage.completion_tokens, total_tokens=response.usage.total_tokens)
        )
        
        log_api_call(request_log, response_data.model_dump())
        
        return JSONResponse(
            content=response_data.model_dump(),
            headers={
                "Cache-Control": "no-cache",
                "X-Request-Id": completion_id,
            }
        )
    except HTTPException:
        raise
    except Exception as e:
        import traceback
        error_msg = str(e)
        print(f"[ERROR] Chat error: {error_msg}")
        traceback.print_exc()
        log_api_call(request_log, None, error=error_msg)
        raise HTTPException(status_code=500, detail=error_msg)


@app.post("/v1/chat/completions/reset")
async def reset_context(authorization: str = Header(None)):
    verify_api_key(authorization)
    global _client
    if _client:
        _client.reset()
    return {"status": "ok"}


load_config()

if __name__ == "__main__":
    print(f"""
╔══════════════════════════════════════════════════════════╗
║           Gemini OpenAI Compatible API Server            ║
╠══════════════════════════════════════════════════════════╣
║  后台配置: http://localhost:{PORT}/admin                   ║
║  API 地址: http://localhost:{PORT}/v1                      ║
║  API Key:  {API_KEY}                                     ║
╚══════════════════════════════════════════════════════════╝
""")
    uvicorn.run(app, host=HOST, port=PORT)
