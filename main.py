import string
import threading
import json
import os
import shutil
import atexit
import re
import time
import base64
import asyncio
import requests
import ddddocr as ocr_module
from http.server import HTTPServer, BaseHTTPRequestHandler
from mitmproxy import http, options
from mitmproxy.tools import dump

SETTINGS_PATH = 'config.json'
WEBUI_BIND = ('0.0.0.0', 8899)
PROXY_LISTEN_PORT = 8081
MAX_HISTORY = 20

recognition_history: list = []
logging_active = True

# 代理生命周期管理
proxy_thread = None
proxy_master = None
proxy_loop = None
proxy_alive = False

# OCR 引擎初始化
OcrClass = getattr(ocr_module, "DdddOcr", None)
print("Loading OCR engine …")
ocr_engine = OcrClass(show_ad=False)

CHARSET_MAP = {
    0: string.digits,
    1: string.ascii_lowercase,
    2: string.ascii_uppercase,
    3: string.ascii_letters,
    4: string.ascii_lowercase + string.digits,
    5: string.ascii_uppercase + string.digits,
    6: string.ascii_letters + string.digits,
    7: None,
}


def get_allowed_chars(code):
    """根据字符集编码返回允许的字符集合，None 表示不限制。"""
    try:
        code = int(code)
    except (ValueError, TypeError):
        code = 6
    raw = CHARSET_MAP.get(code, CHARSET_MAP[6])
    return set(raw) if raw is not None else None


def append_log(msg):
    if not logging_active:
        return
    try:
        os.makedirs('temp', exist_ok=True)
        stamp = time.strftime('%Y-%m-%d %H:%M:%S')
        with open('temp/log.txt', 'a', encoding='utf-8') as fh:
            fh.write(f"[{stamp}] {msg}\n")
    except Exception:
        pass


DEFAULT_SETTINGS = {
    "switchs": 1,
    "whitelist_switch": 0,
    "whitelist_hosts": [],
    "profiles": {
        "1": ["", "1", "6", "", "0", "\"uuid\":\"(.*?)\"", "false"]
    }
}


def read_settings():
    if os.path.exists(SETTINGS_PATH):
        try:
            with open(SETTINGS_PATH, 'r', encoding='utf-8') as fh:
                return json.load(fh)
        except Exception:
            return dict(DEFAULT_SETTINGS)
    return dict(DEFAULT_SETTINGS)


def write_settings(data):
    with open(SETTINGS_PATH, 'w', encoding='utf-8') as fh:
        json.dump(data, fh, indent=4)


def dispatch_raw_http(url, raw_packet):
    """解析原始 HTTP 请求模板并通过 requests.Session 发送。"""
    lines = raw_packet.replace('\r\n', '\n').split('\n')
    request_line = lines[0].strip() if lines else ''
    method = request_line.split()[0].upper() if request_line else 'GET'

    hdrs = {}
    payload = None
    separator = None
    for idx, ln in enumerate(lines[1:], start=1):
        if ln.strip() == '':
            separator = idx
            break
        colon = ln.find(':')
        if colon > 0:
            hdrs[ln[:colon].strip()] = ln[colon + 1:].strip()

    if separator is not None and separator + 1 < len(lines):
        payload = '\n'.join(lines[separator + 1:]).strip() or None

    with requests.Session() as sess:
        req = requests.Request(method, url, headers=hdrs, data=payload)
        return sess.send(sess.prepare_request(req), timeout=5, verify=False)


def deep_find_base64(node):
    """递归搜索 JSON 结构中的 base64 编码图片值。"""
    if isinstance(node, dict):
        for v in node.values():
            hit = deep_find_base64(v)
            if hit:
                return hit
    elif isinstance(node, list):
        for v in node:
            hit = deep_find_base64(v)
            if hit:
                return hit
    elif isinstance(node, str):
        if 'base64,' in node:
            return node.split('base64,', 1)[1]
        if re.fullmatch(r'[A-Za-z0-9+/=]{100,}', node or ''):
            return node
    return None


def extract_image_bytes(resp):
    """从多种响应格式中提取验证码图片字节。返回 (bytes, 来源标签)。"""
    ct = resp.headers.get('content-type', '')
    if any(t in ct for t in ('image/', 'octet-stream')):
        return resp.content, 'content-type'

    body = resp.text

    # JSON 深层扫描
    try:
        tree = resp.json()
        b64_hit = deep_find_base64(tree)
        if b64_hit:
            clean = re.split(r'["\'\s<]', b64_hit)[0]
            return base64.b64decode(clean), 'json-deep-scan'
    except (ValueError, json.JSONDecodeError):
        pass

    # Data-URI 模式
    uri_m = re.search(r'data:image/[^;]+;base64,([A-Za-z0-9+/=]+)', body)
    if uri_m:
        return base64.b64decode(uri_m.group(1)), 'data-uri'

    # 最长独立 base64 字符串
    candidates = re.findall(r'[A-Za-z0-9+/]{80,}={0,2}', body)
    if candidates:
        best = max(candidates, key=len)
        try:
            return base64.b64decode(best), 'standalone-b64'
        except Exception:
            pass

    return resp.content, 'raw-fallback'


def apply_regex_extraction(resp, extract_from, pattern):
    """从响应体或响应头中通过正则提取数据。返回提取的字符串或空字符串。"""
    try:
        if extract_from == '0':
            source = resp.text
        else:
            sep = pattern.index('|')
            header_name = pattern[:sep]
            pattern = pattern[sep + 1:]
            source = resp.headers.get(header_name, '')

        m = re.search(pattern, source)
        if m:
            return m.group(1) if m.lastindex else m.group(0)
        return ''
    except Exception:
        return 'regex_error'


def run_ocr(img_data, charset_code):
    """通过 OCR 引擎识别图片并按字符集过滤结果。"""
    try:
        if hasattr(ocr_engine, 'set_ranges') and charset_code not in ('8', '', None):
            try:
                ocr_engine.set_ranges(int(charset_code))
            except Exception:
                pass
        raw = ocr_engine.classification(img_data)
    except Exception as exc:
        append_log(f"OCR error: {exc}")
        return '0000'

    if isinstance(raw, dict) and 'text' in raw:
        text = str(raw.get('text', '0000'))
    elif isinstance(raw, str):
        text = raw
    else:
        text = '0000'

    allowed = get_allowed_chars(charset_code)
    if allowed:
        filtered = ''.join(ch for ch in text if ch in allowed)
        if filtered:
            text = filtered

    return text


def unpack_profile(data):
    """将配置列表解包为语义化字典。"""
    return {
        'target_url':   data[0],
        'fetch_mode':   data[1],
        'charset_code': data[2],
        'raw_request':  data[3],
        'extract_from': data[4],
        'pattern':      data[5],
        'advanced_on':  data[6],
    }


def recognize_and_extract(profile_data):
    """获取验证码、运行 OCR、可选提取正则数据。返回 (ocr_text, regex_result)。"""
    cfg = unpack_profile(profile_data)
    ocr_text = '0000'
    regex_result = ''

    try:
        t0 = time.time()
        append_log(
            f"Begin  mode={cfg['fetch_mode']}  charset={cfg['charset_code']}  url={cfg['target_url']}")

        # 获取验证码
        resp = None
        if cfg['fetch_mode'] == '1':
            resp = requests.get(
                cfg['target_url'],
                headers={
                    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
                    'Referer': 'https://www.google.com',
                },
                timeout=5, verify=False,
            )
        elif cfg['fetch_mode'] == '2':
            resp = dispatch_raw_http(cfg['target_url'], cfg['raw_request'])

        if resp is None:
            return ocr_text, regex_result

        append_log(
            f"Fetched  status={resp.status_code}  bytes={len(resp.content)}")

        # 高级正则提取
        if cfg['advanced_on'] == 'true':
            regex_result = apply_regex_extraction(
                resp, cfg['extract_from'], cfg['pattern'])
            append_log(
                f"Regex  from={'body' if cfg['extract_from']=='0' else 'header'}  result={regex_result}")

        # 跳过 OCR 模式
        if cfg['charset_code'] == '8':
            append_log("Skip-OCR mode")
            return '0000', regex_result

        # 图片提取
        img_bytes, src_label = extract_image_bytes(resp)
        append_log(f"Image source: {src_label}")

        # OCR 识别
        ocr_text = run_ocr(img_bytes, cfg['charset_code'])
        elapsed = int((time.time() - t0) * 1000)
        append_log(f"OCR  result={ocr_text}  ms={elapsed}")

        # 保存到历史记录
        try:
            if img_bytes and logging_active:
                recognition_history.insert(0, {
                    'time': time.strftime('%H:%M:%S'),
                    'url': cfg['target_url'],
                    'image': base64.b64encode(img_bytes).decode(),
                    'result': ocr_text,
                    'result_regex': regex_result or '',
                })
                while len(recognition_history) > MAX_HISTORY:
                    recognition_history.pop()
        except Exception as exc:
            append_log(f"History save error: {exc}")

    except Exception as exc:
        print(f"Recognition pipeline error: {exc}")
        append_log(f"Error: {exc}")

    return ocr_text, regex_result

class DashboardHandler(BaseHTTPRequestHandler):

    def do_GET(self):
        if self.path == '/':
            self.serve_dashboard()
        elif self.path == '/get_config':
            self.json_response(read_settings())
        elif self.path == '/get_logs':
            self.serve_logs()
        else:
            self.send_error(404)

    def serve_logs(self):
        logs = []
        if os.path.exists('temp/log.txt'):
            with open('temp/log.txt', 'r', encoding='utf-8') as fh:
                logs = fh.readlines()[-100:]
                logs.reverse()

        self.json_response({
            'logs': logs,
            'records': recognition_history,
            'logging_enabled': logging_active,
            'proxy_running': proxy_alive,
        })

    def serve_dashboard(self):
        settings = read_settings()
        tpl_path = os.path.join(os.path.dirname(
            __file__), 'templates', 'index.html')
        try:
            with open(tpl_path, 'r', encoding='utf-8') as fh:
                html = fh.read()
        except FileNotFoundError:
            self.send_error(500, 'Template missing')
            return
        html = html.replace('CONFIG_JSON_PLACEHOLDER', json.dumps(settings))
        self.html_response(html)

    def do_POST(self):
        global logging_active
        body = self.read_body()

        if self.path == '/save_config':
            write_settings(json.loads(body))
            self.ok_response()
        elif self.path == '/toggle_logging':
            logging_active = json.loads(body).get('enabled', True)
            self.ok_response()
        elif self.path == '/clear_logs':
            self.handle_clear(json.loads(body))
        elif self.path == '/toggle_proxy':
            self.handle_proxy_toggle(json.loads(body))
        else:
            self.send_error(404)

    def handle_clear(self, req):
        kind = req.get('type', 'all')
        if kind in ('text', 'all'):
            try:
                open('temp/log.txt', 'w').close()
            except Exception:
                pass
        if kind in ('image', 'all'):
            recognition_history.clear()
        self.ok_response()

    def handle_proxy_toggle(self, req):
        action = req.get('action', 'toggle')
        if action == 'start' or (action == 'toggle' and not proxy_alive):
            ok = launch_proxy()
            msg = '代理已启动' if ok else '代理已在运行'
        else:
            ok = shutdown_proxy()
            msg = '代理已停止' if ok else '代理未在运行'
        self.json_response(
            {'success': ok, 'running': proxy_alive, 'message': msg})

    def read_body(self):
        length = int(self.headers.get('Content-Length', 0))
        return self.rfile.read(length).decode('utf-8')

    def ok_response(self):
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b'OK')

    def json_response(self, obj):
        data = json.dumps(obj).encode('utf-8')
        self.send_response(200)
        self.send_header('Content-Type', 'application/json; charset=utf-8')
        self.end_headers()
        self.wfile.write(data)

    def html_response(self, html):
        data = html.encode('utf-8')
        self.send_response(200)
        self.send_header('Content-Type', 'text/html; charset=utf-8')
        self.end_headers()
        self.wfile.write(data)


class InterceptAddon:
    """mitmproxy 插件：拦截包含 @cap@N@ 标记的请求并替换为识别结果。"""

    SKIP_EXTENSIONS = frozenset((
        '.js', '.css', '.png', '.jpg', '.jpeg', '.gif', '.ico',
        '.svg', '.woff', '.woff2', '.ttf', '.eot', '.map',
        '.mp3', '.mp4', '.avi', '.pdf', '.zip', '.rar', '.exe',
        '.apk', '.ipa', '.swf', '.flv',
    ))

    def request(self, flow: http.HTTPFlow):
        TAG_REGEX = re.compile(r'@cap@(\d+)@')
        settings = read_settings()

        # 白名单过滤
        if settings.get('whitelist_switch') == 1:
            if not self.host_allowed(flow, settings.get('whitelist_hosts', [])):
                return

        # 跳过静态资源
        resource = flow.request.path.split('?')[0].lower()
        if any(resource.endswith(ext) for ext in self.SKIP_EXTENSIONS):
            return

        body_text = flow.request.content.decode('utf-8', errors='ignore')
        tag_match = TAG_REGEX.search(body_text)

        # 如果 body 中没有找到标记，也检查请求头
        if not tag_match:
            for hk, hv in flow.request.headers.items():
                tag_match = TAG_REGEX.search(hv)
                if tag_match:
                    break

        if not tag_match:
            return

        slot = int(tag_match.group(1))
        print(f"Intercepted tag @cap@{slot}@")
        append_log(
            f"Intercept @cap@{slot}@  {flow.request.method} {flow.request.url}")

        profile = settings.get('profiles', {}).get(str(slot))
        if not profile:
            return

        ocr_text, regex_res = recognize_and_extract(profile)
        advanced = len(profile) > 6 and str(profile[6]) == 'true'

        # 直接构造标记字符串用于替换
        tag_main = f'@cap@{slot}@'
        tag_ext = f'@cap@x{slot}@'

        # 替换请求体中的标记
        if flow.request.content:
            new_body = flow.request.content.decode('utf-8', errors='ignore')
            new_body = new_body.replace(tag_main, ocr_text)
            if advanced:
                new_body = new_body.replace(tag_ext, regex_res)
            flow.request.content = new_body.encode('utf-8')

        # 替换请求头中的标记
        for hk, hv in list(flow.request.headers.items()):
            updated = hv.replace(tag_main, ocr_text)
            if advanced:
                updated = updated.replace(tag_ext, regex_res)
            if updated != hv:
                flow.request.headers[hk] = updated

        log_line = f"Replaced @cap@{slot}@ -> {ocr_text}"
        if advanced:
            log_line += f" | @cap@x{slot}@ -> {regex_res}"
        print(log_line)
        append_log(log_line)

    @staticmethod
    def host_allowed(flow, patterns):
        """检查请求目标是否在白名单中。"""
        host = flow.request.host
        host_port = f"{host}:{flow.request.port}"
        for pat in patterns:
            try:
                if re.search(pat, host_port) or re.search(pat, host):
                    return True
            except Exception:
                if pat in (host_port, host):
                    return True
        return False

async def proxy_main():
    global proxy_master, proxy_loop, proxy_alive
    proxy_loop = asyncio.get_running_loop()
    opts = options.Options(listen_host='0.0.0.0',
                           listen_port=PROXY_LISTEN_PORT)
    proxy_master = dump.DumpMaster(opts, with_termlog=False, with_dumper=False)
    proxy_master.addons.add(InterceptAddon())
    proxy_alive = True
    print(f"Proxy listening on :{PROXY_LISTEN_PORT}")
    append_log(f"Proxy listening on :{PROXY_LISTEN_PORT}")
    await proxy_master.run()


def proxy_thread_target():
    global proxy_alive, proxy_master, proxy_loop
    try:
        asyncio.run(proxy_main())
    except Exception as exc:
        print(f"Proxy error: {exc}")
        append_log(f"Proxy error: {exc}")
    finally:
        proxy_alive = False
        proxy_master = None
        proxy_loop = None
        print("Proxy stopped")
        append_log("Proxy stopped")


def launch_proxy():
    global proxy_thread
    if proxy_alive and proxy_thread and proxy_thread.is_alive():
        return False
    proxy_thread = threading.Thread(target=proxy_thread_target, daemon=True)
    proxy_thread.start()
    time.sleep(0.5)
    return True


def shutdown_proxy():
    if not proxy_alive or not proxy_master or not proxy_loop:
        return False
    try:
        proxy_loop.call_soon_threadsafe(proxy_master.shutdown)
        return True
    except Exception as exc:
        print(f"Shutdown error: {exc}")
        append_log(f"Shutdown error: {exc}")
        return False


def run_webui():
    os.makedirs('temp', exist_ok=True)
    srv = HTTPServer(WEBUI_BIND, DashboardHandler)
    print(f"Dashboard: http://127.0.0.1:{WEBUI_BIND[1]}/")
    srv.serve_forever()


def cleanup():
    if os.path.exists('temp'):
        try:
            shutil.rmtree('temp')
            print("Temp cleaned.")
        except Exception as exc:
            print(f"Cleanup error: {exc}")

if __name__ == '__main__':
    atexit.register(cleanup)
    launch_proxy()
    run_webui()
