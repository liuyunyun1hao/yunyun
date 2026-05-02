#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
YunYun AI 代理服务 - 完整融合版 (日志监控 + 一键复制优化)
特性：暗色模式 / 模型统计 / 余额趋势 / App联动 / 傻酒馆部署管理 / 模型列表接口 / 运行日志 / 余额精准监控 / 点击直拷
更新：访问密码保护 / 每小时自动刷新余额 / PWA 可添加桌面 / 多 API 基址 / 小彩蛋
修复：智能识别物理网卡IP，正确响应 /v1/models
"""

import os
import sys
import json
import time
import signal
import socket
import logging
import logging.handlers
import subprocess
import argparse
import threading
from pathlib import Path
from datetime import datetime
from collections import defaultdict
from flask import Flask, request, jsonify, Response
import requests

try:
    from cryptography.fernet import Fernet
    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False

# ========== 配置 ==========
VERSION = "4.3-Local-Fusion-Pro+"
DATA_FILE = "keys_data.json"
STATS_FILE = "stats_data.json"
PID_FILE = "server.pid"
ST_PID_FILE = "st_server.pid"
API_BASE = "https://api.siliconflow.cn/v1"      # 默认基址
ST_DIR = os.path.expanduser("~/SillyTavern")
PORT = 8888
ST_PORT = 8000
LOG_FILE = "proxy.log"
LOG_MAX_BYTES = 10 * 1024 * 1024
LOG_BACKUP_COUNT = 3
ENCRYPT_KEY_FILE = "encrypt.key"

RETRY_COUNT = 3          # 严禁修改！硅基流动限制
REQUEST_TIMEOUT = (10, 120)

ADMIN_PASSWORD = "2295177428"   # 管理面板访问密码

# 模型列表缓存（减少重复请求）
_MODEL_CACHE = {"data": None, "timestamp": 0}
MODEL_CACHE_TTL = 300  # 5分钟

# 数据读写锁（用于自动余额刷新线程安全）
_DATA_LOCK = threading.Lock()

# ========== 日志设置 ==========
logger = logging.getLogger("YunYunProxy")
logger.setLevel(logging.WARNING)
file_handler = logging.handlers.RotatingFileHandler(
    LOG_FILE, maxBytes=LOG_MAX_BYTES, backupCount=LOG_BACKUP_COUNT
)
file_handler.setFormatter(logging.Formatter('[%(asctime)s] %(levelname)s - %(message)s'))
logger.addHandler(file_handler)
console_handler = logging.StreamHandler()
console_handler.setLevel(logging.ERROR)
console_handler.setFormatter(logging.Formatter('%(message)s'))
logger.addHandler(console_handler)

# ========== 加密辅助 ==========
def get_encrypt_key():
    if not CRYPTO_AVAILABLE:
        return None
    key_file = Path(ENCRYPT_KEY_FILE)
    if key_file.exists():
        with open(key_file, 'rb') as f:
            return f.read()
    else:
        key = Fernet.generate_key()
        with open(key_file, 'wb') as f:
            f.write(key)
        return key

def encrypt_data(data):
    key = get_encrypt_key()
    if key is None:
        return data
    try:
        cipher = Fernet(key)
        return cipher.encrypt(data.encode()).decode()
    except:
        return data

def decrypt_data(data):
    key = get_encrypt_key()
    if key is None:
        return data
    try:
        cipher = Fernet(key)
        return cipher.decrypt(data.encode()).decode()
    except:
        return data

# ========== 数据加载/保存 ==========
_MEM_CACHE = None

def load_data():
    global _MEM_CACHE
    with _DATA_LOCK:
        if _MEM_CACHE is not None:
            return _MEM_CACHE
        if os.path.exists(DATA_FILE):
            try:
                with open(DATA_FILE, "r", encoding="utf-8") as f:
                    raw = f.read()
                    if raw.startswith("enc:"):
                        decrypted = decrypt_data(raw[4:])
                        data = json.loads(decrypted)
                    else:
                        data = json.loads(raw)
                    if "keys" not in data:
                        data["keys"] = []
                    if "active_key" not in data:
                        data["active_key"] = None
                    # 兼容老数据，为每个key补充默认基址
                    for k in data.get("keys", []):
                        if "api_base" not in k:
                            k["api_base"] = API_BASE
                    _MEM_CACHE = data
                    return data
            except Exception as e:
                logger.error(f"加载数据失败: {e}")
        data = {"keys": [], "active_key": None, "allowed_models": []}
        for k in data["keys"]:
            if "api_base" not in k:
                k["api_base"] = API_BASE
        _MEM_CACHE = data
        return _MEM_CACHE

def save_data(data):
    global _MEM_CACHE
    with _DATA_LOCK:
        def get_balance_val(item):
            try:
                bal = item.get("balance", "0")
                if isinstance(bal, (int, float)):
                    return bal
                if isinstance(bal, str):
                    try:
                        return float(bal)
                    except:
                        return float('inf')
                return float('inf')
            except:
                return float('inf')
        data["keys"] = sorted(data["keys"], key=get_balance_val)
        # 确保每个key都有api_base字段
        for k in data.get("keys", []):
            if "api_base" not in k:
                k["api_base"] = API_BASE
        _MEM_CACHE = data
        json_str = json.dumps(data, indent=2, ensure_ascii=False)
        if CRYPTO_AVAILABLE and os.path.exists(ENCRYPT_KEY_FILE):
            encrypted = "enc:" + encrypt_data(json_str)
            with open(DATA_FILE, "w", encoding="utf-8") as f:
                f.write(encrypted)
        else:
            with open(DATA_FILE, "w", encoding="utf-8") as f:
                f.write(json_str)

# ========== 统计数据管理 ==========
def load_stats():
    if os.path.exists(STATS_FILE):
        try:
            with open(STATS_FILE, "r", encoding="utf-8") as f:
                return json.load(f)
        except:
            pass
    return {"model_counts": {}, "balance_history": {}, "system_logs": []}

def save_stats(stats):
    with open(STATS_FILE, "w", encoding="utf-8") as f:
        json.dump(stats, f, indent=2, ensure_ascii=False)

def record_model_usage(model_name):
    stats = load_stats()
    counts = stats.get("model_counts", {})
    counts[model_name] = counts.get(model_name, 0) + 1
    stats["model_counts"] = counts
    save_stats(stats)

def record_balance_snapshot(key, balance_str):
    try:
        balance_val = float(balance_str) if balance_str.replace('.', '', 1).isdigit() else None
    except:
        balance_val = None
    if balance_val is None:
        return
    stats = load_stats()
    history = stats.get("balance_history", {})
    if key not in history:
        history[key] = []
    entry = {"time": time.time(), "balance": balance_val}
    history[key].append(entry)
    
    if len(history[key]) > 30:
        history[key] = history[key][-30:]
    stats["balance_history"] = history
    save_stats(stats)

def get_total_balance_history():
    stats = load_stats()
    history = stats.get("balance_history", {})
    time_sums = defaultdict(float)
    for key, entries in history.items():
        for entry in entries:
            hour_ts = int(entry["time"] // 3600) * 3600
            time_sums[hour_ts] += entry["balance"]
    sorted_times = sorted(time_sums.keys())
    return [{"time": ts * 1000, "balance": time_sums[ts]} for ts in sorted_times]

def add_system_log(level, message):
    """添加运行日志"""
    stats = load_stats()
    logs = stats.get("system_logs", [])
    
    logs.insert(0, {
        "time": datetime.now().strftime("%m-%d %H:%M:%S"),
        "level": level,
        "message": message
    })
    
    if len(logs) > 100:
        logs = logs[:100]
        
    stats["system_logs"] = logs
    save_stats(stats)

# ========== 端口/进程辅助 ==========
def check_port(port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.bind(('127.0.0.1', port))
        sock.close()
        return False
    except:
        return True

def kill_process(pid_file):
    if os.path.exists(pid_file):
        try:
            with open(pid_file, "r") as f:
                pid = int(f.read().strip())
                os.kill(pid, signal.SIGTERM)
                time.sleep(0.5)
                try:
                    os.kill(pid, 0)
                    os.kill(pid, signal.SIGKILL)
                except:
                    pass
        except Exception as e:
            logger.warning(f"终止进程失败: {e}")
        finally:
            try:
                os.remove(pid_file)
            except:
                pass

def is_running(pid_file):
    if not os.path.exists(pid_file):
        return False
    try:
        with open(pid_file, "r") as f:
            pid = int(f.read().strip())
            os.kill(pid, 0)
            return True
    except:
        try:
            os.remove(pid_file)
        except:
            pass
        return False

def check_proxy_update():
    return "✅(极速复制版)"

def check_st_versions():
    local_ver = "未安装"
    if os.path.exists(os.path.join(ST_DIR, "package.json")):
        try:
            with open(os.path.join(ST_DIR, "package.json"), "r", encoding="utf-8") as f:
                data = json.load(f)
                local_ver = data.get("version", "未知")
        except:
            pass
    return local_ver, "已强制锁定 1.13.0"

def get_local_ip():
    """获取物理网卡局域网 IP，增强 Termux 与手机网络兼容性"""
    # 方法1：尝试通过 UDP 路由自动选择本机局域网 IP (使用国内稳定 IP 触发路由)
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(('223.5.5.5', 80)) # 仅触发系统路由表分配，不发送真实数据
        ip = s.getsockname()[0]
        s.close()
        if not ip.startswith('127.'):
            return ip
    except:
        pass

    # 方法2：专为 Android/Termux 环境准备的底层网络接口解析
    try:
        res = subprocess.run(['ifconfig'], capture_output=True, text=True, timeout=2)
        for line in res.stdout.split('\n'):
            line = line.strip()
            if line.startswith('inet ') and '127.0.0.1' not in line:
                ip = line.split()[1]
                # 过滤掉可能存在的虚拟机或蓝牙共享网段
                if not (ip.startswith('172.17.') or ip.startswith('172.18.') or ip.startswith('169.254.')):
                    return ip
    except:
        pass

    # 方法3：备用主机名解析
    try:
        hostname = socket.gethostname()
        for info in socket.getaddrinfo(hostname, None, socket.AF_INET):
            ip = info[4][0]
            if not ip.startswith('127.') and not ip.startswith('169.254.'):
                return ip
    except:
        pass

    return "127.0.0.1"

# ========== Flask 应用 ==========
app = Flask(__name__)

# ---------- 访问控制 ----------
@app.before_request
def check_admin_auth():
    # 允许无密码访问的路径：代理转发、PWA文件
    if request.path.startswith('/v1/') or \
       request.path in ('/manifest.json', '/sw.js', '/favicon.ico'):
        return
    # 其他所有管理页面和API需要密码
    password = request.headers.get('X-Admin-Password') or request.args.get('pwd')
    if password != ADMIN_PASSWORD:
        return jsonify({"error": "Unauthorized"}), 401

# ---------- PWA 文件 ----------
@app.route("/manifest.json")
def manifest():
    data = {
        "name": "YunYun Proxy",
        "short_name": "YunYun",
        "start_url": f"/?pwd={ADMIN_PASSWORD}",
        "display": "standalone",
        "background_color": "#fdf4f6",
        "theme_color": "#ff8fa3",
        "icons": [{
            "src": "https://img.icons8.com/clouds/100/000000/cloud.png",
            "sizes": "192x192",
            "type": "image/png"
        }]
    }
    return jsonify(data)

@app.route("/sw.js")
def service_worker():
    sw_script = """
self.addEventListener('install', e => {
  self.skipWaiting();
});
self.addEventListener('fetch', e => {
  e.respondWith(fetch(e.request).catch(() => caches.match(e.request)));
});
"""
    return Response(sw_script, mimetype='application/javascript')

# ---------- 原有页面与 API ----------
@app.route("/")
def index():
    return HTML_CONTENT

@app.route("/api/data", methods=["GET", "POST"])
def manage_data():
    if request.method == "POST":
        data = request.json
        if "keys" not in data:
            data["keys"] = []
        if "active_key" not in data:
            data["active_key"] = None
        # 确保新 key 有 api_base
        for k in data.get("keys", []):
            if "api_base" not in k:
                k["api_base"] = API_BASE
        save_data(data)
        return jsonify({"status": "success", "data": load_data()})
    return jsonify(load_data())

@app.route("/api/check_balance", methods=["POST"])
def check_balance():
    key = request.json.get("key")
    if not key:
        return jsonify({"balance": "无效Key", "diff": ""}), 400
        
    data = load_data()
    old_balance = None
    key_info = None
    for k in data.get("keys", []):
        if k["key"] == key:
            key_info = k
            try:
                old_balance = float(k.get("balance", 0))
            except:
                pass
            break

    base_url = key_info.get("api_base", API_BASE) if key_info else API_BASE

    try:
        resp = requests.get(
            f"{base_url}/user/info",
            headers={"Authorization": f"Bearer {key}"},
            timeout=10
        )
        if resp.status_code == 200:
            resp_data = resp.json()
            balance = resp_data.get("data", {}).get("totalBalance", "获取失败")
            
            diff_str = ""
            if isinstance(balance, (int, float)):
                new_balance_val = float(balance)
                if old_balance is not None:
                    diff = old_balance - new_balance_val
                    if diff > 0.0001:
                        diff_str = f" (⬇️ 消耗 {diff:.4f})"
                    elif diff < -0.0001:
                        diff_str = f" (⬆️ 增加 {-diff:.4f})"
                    else:
                        diff_str = " (无消耗)"
                        
                balance = f"{new_balance_val:.2f}"
                record_balance_snapshot(key, balance)
                add_system_log("info", f"刷新余额成功: {balance}{diff_str}")
                
            return jsonify({"balance": balance, "diff": diff_str})
        else:
            add_system_log("error", f"余额刷新失败: HTTP {resp.status_code}")
            return jsonify({"balance": "查询失败", "diff": ""})
    except Exception as e:
        add_system_log("error", f"余额刷新网络异常: {str(e)[:30]}")
        return jsonify({"balance": "网络异常", "diff": ""})

@app.route("/api/export_backup", methods=["GET"])
def export_backup():
    return jsonify(load_data())

@app.route("/api/import_backup", methods=["POST"])
def import_backup():
    try:
        data = request.json
        save_data(data)
        return jsonify({"status": "success"})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 400

@app.route("/api/stats", methods=["GET"])
def get_stats():
    stats = load_stats()
    total_history = get_total_balance_history()
    return jsonify({
        "model_counts": stats.get("model_counts", {}),
        "balance_history": total_history,
        "system_logs": stats.get("system_logs", [])
    })

@app.route("/api/clear_stats", methods=["POST"])
def clear_stats():
    save_stats({"model_counts": {}, "balance_history": {}, "system_logs": []})
    return jsonify({"status": "success"})

@app.route("/api/send_to_app", methods=["POST"])
def send_to_app():
    try:
        data = request.json
        url = data.get("url", "http://127.0.0.1:5000/api/external-chat")
        token = data.get("token", "")
        message = data.get("message", "")

        headers = {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json; charset=utf-8"
        }
        payload = {
            "message": message,
            "response_mode": "sync",
            "show_floating": True,
            "initial_mode": "WINDOW",
            "return_tool_status": False
        }
        
        resp = requests.post(url, headers=headers, json=payload, timeout=15)
        
        try:
            resp_data = resp.json()
            formatted_resp = json.dumps(resp_data, indent=2, ensure_ascii=False)
        except:
            formatted_resp = resp.text

        return jsonify({
            "status": "success", 
            "status_code": resp.status_code, 
            "response": formatted_resp
        })
    except Exception as e:
        return jsonify({"status": "error", "error": str(e)})

@app.route("/api/raw_models", methods=["GET"])
def get_raw_models():
    """供前端面板拉取的全量未过滤模型列表"""
    data = load_data()
    keys = data.get("keys", [])
    if not keys:
        return jsonify([])
    active = data.get("active_key")
    key_to_use = keys[0]["key"] if keys else ""
    api_base = keys[0].get("api_base", API_BASE)
    if active:
        for k in keys:
            if k["key"] == active:
                key_to_use = k["key"]
                api_base = k.get("api_base", API_BASE)
                break
    try:
        resp = requests.get(f"{api_base}/models", headers={"Authorization": f"Bearer {key_to_use}"}, timeout=10)
        if resp.status_code == 200:
            return jsonify(resp.json().get("data", []))
    except:
        pass
    return jsonify([])

@app.route("/v1/models", methods=["GET"])
def get_models():
    """获取硅基流动可用模型列表（已接入前端白名单管控）"""
    data = load_data()
    keys = data.get("keys", [])
    if not keys:
        return jsonify({"error": "未配置任何 API Key"}), 400
    
    active = data.get("active_key")
    key_to_use = keys[0]["key"]
    api_base = keys[0].get("api_base", API_BASE)
    if active:
        for k in keys:
            if k["key"] == active:
                key_to_use = k["key"]
                api_base = k.get("api_base", API_BASE)
                break
    
    try:
        resp = requests.get(
            f"{api_base}/models",
            headers={"Authorization": f"Bearer {key_to_use}"},
            timeout=10
        )
        if resp.status_code == 200:
            raw_data = resp.json()
            
            # 读取前端保存的白名单
            allowed_models = data.get("allowed_models", [])
            
            # 如果白名单有内容，则严格过滤；如果不填，则放行全部
            if allowed_models:
                filtered_models = [m for m in raw_data.get("data", []) if m.get("id") in allowed_models]
                raw_data["data"] = filtered_models
                
            return jsonify(raw_data)
        else:
            return jsonify({"error": f"上游返回错误 {resp.status_code}"}), resp.status_code
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/v1/<path:path>", methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"])
def proxy(path):
    if path == "models" and request.method == "GET":
        return get_models()
    
    data = load_data()
    keys = data.get("keys", [])
    if not keys:
        return jsonify({"error": "未配置任何 API Key"}), 400

    model = "unknown"
    if request.is_json:
        json_data = request.get_json(silent=True) or {}
        model = json_data.get("model", "unknown")
    is_stream = request.is_json and json_data.get("stream", False)

    if path == "chat/completions" and model != "unknown":
        record_model_usage(model)

    active_key_val = data.get("active_key")
    ordered_keys = []
    if active_key_val:
        for k in keys:
            if k["key"] == active_key_val:
                ordered_keys.append(k)
                break
    for k in keys:
        if k["key"] != active_key_val:
            ordered_keys.append(k)

    base_headers = {}
    for k, v in request.headers:
        if k.lower() not in ['host', 'authorization']:
            base_headers[k] = v

    last_error = None
    # 严格限制只尝试前 RETRY_COUNT 个 Key
    for attempt_idx, key_item in enumerate(ordered_keys[:RETRY_COUNT]):
        current_key = key_item["key"]
        current_base = key_item.get("api_base", API_BASE)
        headers = base_headers.copy()
        headers["Authorization"] = f"Bearer {current_key}"

        try:
            resp = requests.request(
                method=request.method,
                url=f"{current_base}/{path}",
                headers=headers,
                data=request.get_data(),
                stream=is_stream,
                timeout=REQUEST_TIMEOUT
            )
            if resp.status_code in (401, 403, 429):
                last_error = f"HTTP {resp.status_code}"
                add_system_log("warning", f"模型 {model} 触发 {last_error}，正在重试...")
                continue

            excluded_headers = ['content-encoding', 'content-length', 'transfer-encoding', 'connection']
            response_headers = [(name, value) for name, value in resp.raw.headers.items()
                                if name.lower() not in excluded_headers]

            add_system_log("success", f"调用 {model} 成功 ({resp.status_code})")

            if is_stream:
                return Response(resp.iter_content(chunk_size=1024), status=resp.status_code, headers=response_headers)
            else:
                return Response(resp.content, status=resp.status_code, headers=response_headers, content_type=resp.headers.get('content-type'))
        except requests.exceptions.Timeout:
            last_error = "timeout"
            add_system_log("warning", f"调用 {model} 超时，准备重试")
            continue
        except Exception as e:
            last_error = str(e)
            add_system_log("error", f"调用 {model} 异常: {last_error[:30]}")
            continue

    add_system_log("error", f"全部重试失败，最后错误: {last_error}")
    return jsonify({"error": f"所有可用Key均失败，最后错误: {last_error}"}), 500

def mask_key(key):
    if not key: return ""
    if len(key) <= 8: return "***"
    return key[:5] + "..." + key[-4:]

# ========== 前端 HTML（含密码登录、PWA 注册、多基址支持） ==========
HTML_CONTENT = """
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no, viewport-fit=cover">
    <title>YunYun Proxy</title>
    <link rel="manifest" href="/manifest.json">
    <script>
        if ('serviceWorker' in navigator) {
            navigator.serviceWorker.register('/sw.js');
        }
    </script>
    <script src="https://unpkg.com/vue@3/dist/vue.global.js"></script>
    <link rel="stylesheet" href="https://unpkg.com/element-plus/dist/index.css" />
    <script src="https://unpkg.com/element-plus"></script>
    <script src="https://cdn.jsdelivr.net/npm/chart.js@3.9.1/dist/chart.min.js"></script>
    <style>
        /* 原有样式保持不变，略作补充 */
        :root { --theme-pink: #ff8fa3; --theme-pink-hover: #ff9fb1; --glass-bg: rgba(255, 255, 255, 0.65); --glass-border: rgba(255, 255, 255, 0.5); --text-main: #4a3b3e; --text-sub: #9c898c; --bg-gradient: linear-gradient(135deg, #fdf4f6 0%, #fbe1e6 100%); --card-bg: rgba(255, 255, 255, 0.65); }
        body.dark { --theme-pink: #d47a8a; --theme-pink-hover: #e08a9a; --glass-bg: rgba(30, 30, 40, 0.75); --glass-border: rgba(80, 80, 100, 0.5); --text-main: #e0e0e0; --text-sub: #b0b0c0; --bg-gradient: linear-gradient(135deg, #1e1e2a 0%, #2a2a3a 100%); --card-bg: rgba(40, 40, 55, 0.75); }
        body { font-family: -apple-system, sans-serif; background: var(--bg-gradient); background-attachment: fixed; color: var(--text-main); margin: 0; padding: calc(env(safe-area-inset-top) + 16px) 16px calc(env(safe-area-inset-bottom) + 40px) 16px; transition: background 0.3s, color 0.3s; }
        .app-container { max-width: 900px; margin: 0 auto; }
        .login-overlay { position: fixed; top: 0; left: 0; width: 100%; height: 100%; background: var(--bg-gradient); display: flex; justify-content: center; align-items: center; z-index: 1000; }
        .login-box { background: var(--glass-bg); backdrop-filter: blur(20px); padding: 40px; border-radius: 24px; text-align: center; border: 1px solid var(--glass-border); box-shadow: 0 10px 40px rgba(0,0,0,0.2); }
        .login-box input { margin-top: 16px; width: 200px; }
        .rainbow { animation: rainbow 2s infinite; }
        @keyframes rainbow { 0% { color: #ff8fa3; } 20% { color: #ffb3c6; } 40% { color: #d47a8a; } 60% { color: #e5989b; } 80% { color: #b5838d; } 100% { color: #ff8fa3; } }
        .theme-toggle { background: var(--card-bg); border: 1px solid var(--glass-border); border-radius: 40px; padding: 8px 16px; cursor: pointer; backdrop-filter: blur(12px); color: var(--text-main); font-weight: 600; }
        .segmented-control { display: flex; background: var(--glass-bg); border: 1px solid var(--glass-border); backdrop-filter: blur(12px); border-radius: 14px; padding: 4px; margin-bottom: 24px; flex-wrap: wrap; }
        .segment { flex: 1; text-align: center; padding: 10px 4px; font-size: 14px; font-weight: 600; cursor: pointer; border-radius: 10px; color: var(--text-sub); transition: all 0.3s ease; white-space: nowrap; }
        .segment.active { background: rgba(255, 255, 255, 0.9); color: var(--theme-pink); box-shadow: 0 2px 10px rgba(255, 143, 163, 0.15); }
        body.dark .segment.active { background: rgba(70, 70, 90, 0.9); }
        .ios-card { background: var(--card-bg); backdrop-filter: blur(20px); border: 1px solid var(--glass-border); border-radius: 24px; padding: 24px; box-shadow: 0 10px 40px rgba(0, 0, 0, 0.1); margin-bottom: 24px; }
        .card-title { font-size: 20px; font-weight: 700; margin: 0 0 20px 0; display: flex; justify-content: space-between; align-items: center; cursor: pointer; user-select: none; }
        .el-button { border-radius: 12px !important; font-weight: 600 !important; border: none !important; }
        .el-button--primary { background-color: var(--theme-pink) !important; color: white !important; box-shadow: 0 4px 12px rgba(255, 143, 163, 0.3) !important; }
        .el-button--primary:active { background-color: var(--theme-pink-hover) !important; transform: scale(0.98); }
        .el-input__wrapper, .el-textarea__inner { border-radius: 14px !important; background: rgba(255, 255, 255, 0.7) !important; box-shadow: 0 0 0 1px rgba(255, 143, 163, 0.2) inset !important; }
        body.dark .el-input__wrapper, body.dark .el-textarea__inner { background: rgba(40, 40, 55, 0.9) !important; color: #e0e0e0; }
        .el-input__wrapper.is-focus, .el-textarea__inner:focus { box-shadow: 0 0 0 2px var(--theme-pink) inset !important; background: #fff !important; }
        body.dark .el-input__wrapper.is-focus, body.dark .el-textarea__inner:focus { background: #2a2a3a !important; }
        .el-table { border-radius: 16px; overflow: hidden; background: transparent !important; }
        .el-table tr, .el-table th.el-table__cell { background-color: rgba(255, 255, 255, 0.3) !important; color: var(--text-main); font-weight: 600; border-bottom: 1px solid var(--glass-border) !important; }
        body.dark .el-table tr, body.dark .el-table th.el-table__cell { background-color: rgba(60, 60, 80, 0.5) !important; }
        .el-table td.el-table__cell { border-bottom: 1px solid var(--glass-border) !important; background: transparent !important; color: var(--text-main); }
        .el-radio__input.is-checked .el-radio__inner { border-color: var(--theme-pink) !important; background: var(--theme-pink) !important; }
        .el-radio__input.is-checked+.el-radio__label { color: var(--theme-pink) !important; }
        .test-box { background: rgba(255, 255, 255, 0.4); padding: 16px; border-radius: 16px; margin-top: 16px; border: 1px solid var(--glass-border); }
        body.dark .test-box { background: rgba(40, 40, 55, 0.6); }
        .add-key-area { margin-top: 20px; display: flex; gap: 8px; align-items: center; flex-wrap: wrap; }
        .add-key-area .el-input { flex: 1; min-width: 200px; }
        .backup-area { margin-top: 16px; display: flex; gap: 12px; justify-content: flex-end; }
        .chart-container { height: 250px; margin-top: 20px; }
        .stats-actions { display: flex; gap: 12px; margin-bottom: 16px; }
        .log-level-info { color: #409EFF; } .log-level-success { color: #67C23A; } .log-level-warning { color: #E6A23C; } .log-level-error { color: #F56C6C; font-weight: bold; }
        .log-table-container { max-height: 300px; overflow-y: auto; border-radius: 12px; border: 1px solid var(--glass-border); }
    </style>
</head>
<body>
<div id="app">
    <!-- 登录遮罩 -->
    <div v-if="!isAuthorized" class="login-overlay">
        <div class="login-box">
            <h2 style="color: var(--theme-pink);">🔐 YunYun Proxy</h2>
            <p style="color: var(--text-sub); margin: 8px 0;">请输入管理密码</p>
            <el-input v-model="inputPwd" type="password" placeholder="密码" @keyup.enter="tryLogin" />
            <el-button type="primary" @click="tryLogin" style="margin-top: 16px;">验证</el-button>
            <p style="font-size:12px; color: var(--text-sub); margin-top: 8px;" v-if="loginError">{{ loginError }}</p>
        </div>
    </div>

    <!-- 主界面（登录后显示） -->
    <div v-if="isAuthorized" class="app-container">
        <div style="position: absolute; top: 16px; right: 16px; display: flex; gap: 10px; z-index: 10;">
            <div class="theme-toggle" @click="toggleKeepAlive" :style="isKeepAlive ? 'color: var(--theme-pink); border-color: var(--theme-pink);' : ''">
                <span v-if="isKeepAlive">🎵 网页保活中</span>
                <span v-else>🔇 息屏保活</span>
            </div>
            <div class="theme-toggle" @click="toggleTheme">
                <span v-if="isDark">☀️ 浅色</span>
                <span v-else>🌙 暗色</span>
            </div>
        </div>
        <audio id="keepAliveAudio" loop>
            <source src="data:audio/wav;base64,UklGRigAAABXQVZFZm10IBIAAAABAAEARKwAAIhYAQACABAAAABkYXRhAgAAAAEA" type="audio/wav">
        </audio>

        <div class="segmented-control" style="margin-top: 40px;">
            <div class="segment" :class="{active: activeTab === 'console'}" @click="activeTab = 'console'">控制台</div>
            <div class="segment" :class="{active: activeTab === 'models'}" @click="activeTab = 'models'">模型管理</div>
            <div class="segment" :class="{active: activeTab === 'test'}" @click="activeTab = 'test'">连接测试</div>
            <div class="segment" :class="{active: activeTab === 'app_link'}" @click="activeTab = 'app_link'">App联动</div>
            <div class="segment" :class="{active: activeTab === 'stats'}" @click="activeTab = 'stats'; refreshStats()">统计</div>
            <div class="segment" :class="{active: activeTab === 'backup'}" @click="activeTab = 'backup'">系统维护</div>
        </div>

        <!-- 控制台 -->
        <div v-show="activeTab === 'console'">
            <div class="ios-card">
                <h2 class="card-title">🌸 批量导入</h2>
                <el-input type="textarea" v-model="batchKeys" placeholder="在此粘贴 Key，每行一个" :rows="3"></el-input>
                <div style="margin-top: 16px; display: flex; gap: 12px; flex-wrap: wrap;">
                    <el-button type="primary" @click="importKeys">解析导入</el-button>
                    <el-button @click="checkAllBalances" :loading="checking" style="color: var(--theme-pink); background: rgba(255, 255, 255, 0.8);">刷新余额</el-button>
                </div>
                <div class="add-key-area">
                    <el-input v-model="singleKey" placeholder="手动输入单个 Key (sk-开头)" @keyup.enter="addSingleKey"></el-input>
                    <el-input v-model="singleApiBase" placeholder="API 基址 (默认硅基流动)" style="max-width: 300px;" />
                    <el-button type="primary" @click="addSingleKey">添加</el-button>
                </div>
            </div>

            <div class="ios-card">
                <h2 class="card-title">
                    <span>✨ 代理状态 <span style="font-size: 14px; color: var(--theme-pink); margin-left: 10px; font-weight: normal;">总余额: {{ totalBalance }}</span></span>
                </h2>
                <el-table :data="keys" style="width: 100%" empty-text="暂无数据">
                    <el-table-column label="启用" width="60" align="center">
                        <template #default="scope">
                            <el-radio v-model="activeKey" :label="scope.row.key" @change="saveData"><span></span></el-radio>
                        </template>
                    </el-table-column>
                    <el-table-column label="API Key" min-width="150">
                        <template #default="scope">
                            <span @click="copyKey(scope.row.key)" style="font-family: monospace; color: var(--text-sub); cursor: pointer;" :title="scope.row.key">{{ maskKey(scope.row.key) }}</span>
                        </template>
                    </el-table-column>
                    <el-table-column label="基址" width="160">
                        <template #default="scope">
                            <span style="font-size:12px; color: var(--text-sub);">{{ scope.row.api_base }}</span>
                        </template>
                    </el-table-column>
                    <el-table-column prop="balance" label="余额" width="100" align="center"></el-table-column>
                    <el-table-column label="操作" width="80" align="center">
                        <template #default="scope">
                            <el-button size="small" type="danger" text @click="deleteKey(scope.$index)">删除</el-button>
                        </template>
                    </el-table-column>
                </el-table>
            </div>
        </div>

        <!-- 模型管理 -->
        <div v-show="activeTab === 'models'">
            <div class="ios-card">
                <h2 class="card-title">📝 自定义模型白名单</h2>
                <p style="font-size: 13px; color: var(--text-sub); margin-bottom: 16px;">
                    开启此功能后，傻酒馆只能拉取到您在此配置的模型。如果不添加任何模型，则默认允许拉取全部。
                </p>
                <div class="add-key-area">
                    <el-input v-model="singleModel" placeholder="在此粘贴要放行的模型名称 (如: Qwen/Qwen2.5-7B-Instruct)" @keyup.enter="addSingleModel"></el-input>
                    <el-button type="primary" @click="addSingleModel">手动添加</el-button>
                </div>
                
                <div style="margin-top: 16px; display: flex; flex-wrap: wrap; gap: 8px;">
                    <el-tag 
                        v-for="(model, index) in allowedModels" 
                        :key="index" 
                        closable 
                        @close="removeModel(index)"
                        effect="plain"
                        style="border-radius: 8px; color: var(--theme-pink); border-color: rgba(255,143,163,0.3); background: rgba(255,255,255,0.5); padding: 6px 12px; height: auto;"
                    >
                        {{ model }}
                    </el-tag>
                    <span v-if="allowedModels.length === 0" style="font-size: 13px; color: var(--text-sub);">当前未配置白名单，允许拉取所有模型。</span>
                </div>
            </div>

            <div class="ios-card">
                <h2 class="card-title">☁️ 从远端一键拉取选择</h2>
                <p style="font-size: 13px; color: var(--text-sub); margin-bottom: 16px;">
                    点击下方按钮获取远端提供的所有模型，并在列表中直接打勾选择。
                </p>
                <el-button type="primary" @click="fetchRawModels" :loading="fetchingModels" style="margin-bottom: 16px;">拉取平台所有模型</el-button>
                
                <div v-if="rawModels.length > 0" class="test-box" style="max-height: 400px; overflow-y: auto;">
                    <div v-for="rm in rawModels" :key="rm.id" style="display: flex; justify-content: space-between; align-items: center; padding: 10px 4px; border-bottom: 1px solid var(--glass-border);">
                        <span style="font-size: 13px; font-family: monospace; word-break: break-all;">{{ rm.id }}</span>
                        <el-button 
                            size="small" 
                            :type="allowedModels.includes(rm.id) ? 'danger' : 'success'" 
                            :plain="!allowedModels.includes(rm.id)"
                            @click="toggleModel(rm.id)"
                        >
                            {{ allowedModels.includes(rm.id) ? '移除' : '添加' }}
                        </el-button>
                    </div>
                </div>
            </div>
        </div>

        <!-- 连接测试 -->
        <div v-show="activeTab === 'test'" class="ios-card">
            <h2 class="card-title">⚡ 连通性测试</h2>
            <div v-if="!activeKey" style="color: #ff4d4f; text-align: center; font-weight: bold;">⚠️ 请先在【控制台】勾选一个 Key</div>
            <div v-else class="test-box">
                <el-input type="textarea" v-model="testPrompt" placeholder="输入测试内容..." :rows="3"></el-input>
                <div style="margin-top: 16px; display: flex; gap: 10px;">
                    <el-button type="primary" @click="sendTest" :loading="isTesting">发送请求</el-button>
                    <el-button @click="testPrompt = ''; testResult = ''" style="background: rgba(255,255,255,0.8); color: var(--text-sub);">清空</el-button>
                </div>
                <el-input v-if="testResult" type="textarea" v-model="testResult" :rows="6" readonly style="margin-top: 16px;"></el-input>
            </div>
        </div>

        <!-- App 联动 -->
        <div v-show="activeTab === 'app_link'" class="ios-card">
            <h2 class="card-title">📱 本地 App 联动调试</h2>
            <p style="font-size: 13px; color: var(--text-sub); margin-bottom: 16px;">
                通过 Web UI 模拟向您手机上的本地 App 服务发送指令。默认 IP 使用 127.0.0.1 适配本机内部通信。
            </p>
            <div class="test-box">
                <el-input v-model="appUrl" placeholder="接口地址 (例如: http://127.0.0.1:5000/api/external-chat)"></el-input>
                <el-input v-model="appToken" placeholder="Bearer Token" style="margin-top: 12px;"></el-input>
                <el-input type="textarea" v-model="appMessage" placeholder="输入要发送给 App 的指令..." :rows="3" style="margin-top: 12px;"></el-input>
                <div style="margin-top: 16px; display: flex; gap: 10px;">
                    <el-button type="primary" @click="sendToApp" :loading="isAppTesting">发送指令至 App</el-button>
                    <el-button @click="appMessage = ''; appResult = ''" style="background: rgba(255,255,255,0.8); color: var(--text-sub);">清空</el-button>
                </div>
                <el-input v-if="appResult" type="textarea" v-model="appResult" :rows="6" readonly style="margin-top: 16px;"></el-input>
            </div>
        </div>

        <!-- 统计 -->
        <div v-show="activeTab === 'stats'">
            <div class="ios-card">
                <h2 class="card-title">📊 模型使用次数</h2>
                <div class="stats-actions">
                    <el-button size="small" @click="refreshStats" style="color: var(--theme-pink);">刷新</el-button>
                    <el-button size="small" type="danger" text @click="clearStats">清空统计</el-button>
                </div>
                <canvas id="modelChart" style="max-height: 250px; width: 100%;"></canvas>
            </div>
            <div class="ios-card">
                <h2 class="card-title">💰 余额变化趋势（总和）</h2>
                <canvas id="balanceChart" style="max-height: 250px; width: 100%;"></canvas>
            </div>
            <div class="ios-card">
                <h2 class="card-title">📡 运行与调用日志</h2>
                <div class="log-table-container">
                    <el-table :data="systemLogs" size="small" style="width: 100%" empty-text="暂无日志记录">
                        <el-table-column prop="time" label="时间" width="120"></el-table-column>
                        <el-table-column label="级别" width="80" align="center">
                            <template #default="scope">
                                <span :class="'log-level-' + scope.row.level">
                                    {{ scope.row.level.toUpperCase() }}
                                </span>
                            </template>
                        </el-table-column>
                        <el-table-column prop="message" label="详情信息" min-width="200" show-overflow-tooltip></el-table-column>
                    </el-table>
                </div>
            </div>
        </div>

        <!-- 备份 -->
        <div v-show="activeTab === 'backup'" class="ios-card">
            <h2 class="card-title">💾 备份与恢复</h2>
            <div class="backup-area">
                <el-button type="primary" @click="exportData">导出当前配置</el-button>
                <el-button type="primary" @click="triggerImport">从文件恢复</el-button>
                <input type="file" ref="fileInput" style="display:none" @change="importFile">
            </div>
            <div style="margin-top: 20px; font-size: 12px; color: var(--text-sub);">
                <p>提示：导出文件为JSON格式，包含所有Key与白名单模型，可手动编辑后重新导入。</p>
            </div>
        </div>
    </div>
</div>

<script>
    const { createApp, ref, computed, onMounted, watch, nextTick } = Vue;
    const ADMIN_PWD = "2295177428";

    const app = createApp({
        setup() {
            // 登录状态
            const isAuthorized = ref(false);
            const inputPwd = ref('');
            const loginError = ref('');
            const storedPwd = localStorage.getItem('admin_pwd');
            if (storedPwd === ADMIN_PWD) {
                isAuthorized.value = true;
            }

            const tryLogin = () => {
                if (inputPwd.value === ADMIN_PWD) {
                    isAuthorized.value = true;
                    localStorage.setItem('admin_pwd', ADMIN_PWD);
                    loginError.value = '';
                } else {
                    loginError.value = '密码错误';
                }
            };

            // 统一的带密码请求函数
            const authFetch = (url, options = {}) => {
                const headers = options.headers || {};
                headers['X-Admin-Password'] = ADMIN_PWD;
                options.headers = headers;
                return fetch(url, options);
            };

            // 原有状态
            const activeTab = ref('console');
            const keys = ref([]);
            const activeKey = ref(null);
            const batchKeys = ref('');
            const singleKey = ref('');
            const singleApiBase = ref('https://api.siliconflow.cn/v1');
            const checking = ref(false);
            const testPrompt = ref('讲个冷笑话。');
            const testResult = ref('');
            const isTesting = ref(false);
            const fileInput = ref(null);
            const isDark = ref(false);
            const systemLogs = ref([]); 
            const isKeepAlive = ref(false);

            // 模型管理
            const allowedModels = ref([]);
            const rawModels = ref([]);
            const singleModel = ref('');
            const fetchingModels = ref(false);

            // App 联动
            const appUrl = ref('http://127.0.0.1:5000/api/external-chat');
            const appToken = ref('');
            const appMessage = ref('');
            const appResult = ref('');
            const isAppTesting = ref(false);

            let modelChart = null;
            let balanceChart = null;

            // 彩蛋：点击标题5次开彩虹模式
            const rainbowCount = ref(0);
            const rainbowActive = ref(false);
            const toggleRainbow = () => {
                rainbowCount.value++;
                if (rainbowCount.value >= 5) {
                    rainbowActive.value = !rainbowActive.value;
                    rainbowCount.value = 0;
                }
            };

            const toggleTheme = () => {
                isDark.value = !isDark.value;
                document.body.classList.toggle('dark', isDark.value);
                localStorage.setItem('theme', isDark.value ? 'dark' : 'light');
                if (activeTab.value === 'stats') refreshStats();
            };

            const toggleKeepAlive = () => {
                const audio = document.getElementById('keepAliveAudio');
                if (!audio) return;
                if (isKeepAlive.value) {
                    audio.pause();
                    isKeepAlive.value = false;
                    ElementPlus.ElMessage.info('前端网页静默保活已关闭');
                } else {
                    audio.play().then(() => {
                        isKeepAlive.value = true;
                        ElementPlus.ElMessage.success('网页保活开启！切屏不会断开连接');
                    }).catch(e => {
                        ElementPlus.ElMessage.warning('系统限制：请先在页面任意空白处点击一下，再尝试开启');
                    });
                }
            };

            const initTheme = () => {
                const saved = localStorage.getItem('theme');
                if (saved === 'dark') {
                    isDark.value = true;
                    document.body.classList.add('dark');
                } else {
                    isDark.value = false;
                    document.body.classList.remove('dark');
                }
            };

            const totalBalance = computed(() => {
                let total = 0; let valid = false;
                keys.value.forEach(k => {
                    const val = parseFloat(k.balance);
                    if (!isNaN(val)) { total += val; valid = true; }
                });
                return valid ? total.toFixed(2) : '未知';
            });

            const loadData = async () => {
                const res = await authFetch('/api/data');
                if (res.status === 401) { isAuthorized.value = false; localStorage.removeItem('admin_pwd'); return; }
                const data = await res.json();
                keys.value = data.keys || [];
                activeKey.value = data.active_key;
                allowedModels.value = data.allowed_models || []; 
            };

            const saveData = async () => {
                const res = await authFetch('/api/data', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ 
                        keys: keys.value, 
                        active_key: activeKey.value,
                        allowed_models: allowedModels.value 
                    })
                });
                const result = await res.json();
                keys.value = result.data.keys;
            };

            const addSingleModel = async () => {
                const m = singleModel.value.trim();
                if (!m) return;
                if (allowedModels.value.includes(m)) {
                    ElementPlus.ElMessage.warning('该模型已在白名单列表中');
                    return;
                }
                allowedModels.value.push(m);
                singleModel.value = '';
                await saveData();
                ElementPlus.ElMessage.success('成功添加到白名单');
            };

            const removeModel = async (index) => {
                allowedModels.value.splice(index, 1);
                await saveData();
                ElementPlus.ElMessage.success('已移出白名单');
            };

            const toggleModel = async (modelId) => {
                const idx = allowedModels.value.indexOf(modelId);
                if (idx > -1) {
                    allowedModels.value.splice(idx, 1);
                } else {
                    allowedModels.value.push(modelId);
                }
                await saveData();
            };

            const fetchRawModels = async () => {
                fetchingModels.value = true;
                try {
                    const res = await authFetch('/api/raw_models');
                    const data = await res.json();
                    if (data && data.length > 0) {
                        rawModels.value = data;
                        ElementPlus.ElMessage.success(`成功拉取 ${data.length} 个模型`);
                    } else {
                        ElementPlus.ElMessage.warning('拉取为空，请确保在控制台激活了至少一个有效 Key');
                    }
                } catch (e) {
                    ElementPlus.ElMessage.error('拉取模型失败，网络异常');
                } finally {
                    fetchingModels.value = false;
                }
            };

            const maskKey = (key) => {
                if (!key) return '';
                if (key.length <= 8) return '***';
                return key.substring(0, 5) + '...' + key.substring(key.length - 4);
            };

            const copyKey = async (key) => {
                if (!key) return;
                try {
                    if (navigator.clipboard && window.isSecureContext) {
                        await navigator.clipboard.writeText(key);
                        ElementPlus.ElMessage.success('复制成功！');
                    } else {
                        const textArea = document.createElement("textarea");
                        textArea.value = key;
                        textArea.style.position = "fixed"; textArea.style.opacity = "0";
                        document.body.appendChild(textArea);
                        textArea.focus(); textArea.select();
                        const successful = document.execCommand('copy');
                        document.body.removeChild(textArea);
                        if (successful) ElementPlus.ElMessage.success('复制成功！');
                        else ElementPlus.ElMessage.error('复制失败，请检查浏览器权限');
                    }
                } catch (err) { ElementPlus.ElMessage.error('复制失败，请重试'); }
            };

            const importKeys = async () => {
                const lines = batchKeys.value.split('\\n');
                const newKeys = [];
                for (let line of lines) {
                    line = line.trim();
                    if (line.startsWith('sk-') && !keys.value.some(k => k.key === line)) {
                        newKeys.push({ key: line, balance: '未知', api_base: 'https://api.siliconflow.cn/v1' });
                    }
                }
                if (newKeys.length === 0) { ElementPlus.ElMessage.warning('没有有效的 Key'); return; }
                keys.value.push(...newKeys);
                batchKeys.value = '';
                await saveData();
                ElementPlus.ElMessage.success(`成功导入 ${newKeys.length} 个 Key`);
                await checkAllBalances();
            };

            const addSingleKey = async () => {
                let key = singleKey.value.trim();
                if (!key.startsWith('sk-')) { ElementPlus.ElMessage.warning('Key 必须以 sk- 开头'); return; }
                if (keys.value.some(k => k.key === key)) { ElementPlus.ElMessage.warning('Key 已存在'); return; }
                let base = singleApiBase.value.trim() || 'https://api.siliconflow.cn/v1';
                keys.value.push({ key, balance: '未知', api_base: base });
                singleKey.value = '';
                await saveData();
                ElementPlus.ElMessage.success('添加成功');
            };

            const deleteKey = async (index) => {
                if (keys.value[index].key === activeKey.value) activeKey.value = null;
                keys.value.splice(index, 1);
                await saveData();
            };

            const checkAllBalances = async () => {
                checking.value = true;
                for (let i = 0; i < keys.value.length; i++) {
                    keys.value[i].balance = '...';
                    try {
                        const res = await authFetch('/api/check_balance', {
                            method: 'POST',
                            headers: { 'Content-Type': 'application/json' },
                            body: JSON.stringify({ key: keys.value[i].key })
                        });
                        const data = await res.json();
                        keys.value[i].balance = data.balance;
                        if (data.diff && data.diff !== ' (无消耗)') {
                            ElementPlus.ElMessage.info(`Key尾号${keys.value[i].key.slice(-4)}: ${data.diff}`);
                        }
                    } catch (e) { keys.value[i].balance = '请求失败'; }
                    await saveData();
                }
                checking.value = false;
                ElementPlus.ElMessage.success('余额刷新完成');
                if (activeTab.value === 'stats') refreshStats();
            };

            const sendTest = async () => {
                if (!activeKey.value) { ElementPlus.ElMessage.warning('请先选择一个活动 Key'); return; }
                if (!testPrompt.value.trim()) { ElementPlus.ElMessage.warning('请输入测试内容'); return; }
                isTesting.value = true; testResult.value = '请求发送中...';
                try {
                    const response = await fetch('/v1/chat/completions', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({
                            model: allowedModels.value.length > 0 ? allowedModels.value[0] : "Qwen/Qwen2.5-7B-Instruct",
                            messages: [{ role: "user", content: testPrompt.value }],
                            stream: false
                        })
                    });
                    const data = await response.json();
                    if (response.ok && data.choices) testResult.value = data.choices[0].message.content;
                    else testResult.value = `错误: ${JSON.stringify(data)}`;
                } catch (error) { testResult.value = `请求失败: ${error.message}`; } 
                finally { isTesting.value = false; }
            };

            const sendToApp = async () => {
                if (!appUrl.value || !appToken.value) { ElementPlus.ElMessage.warning('请输入完整的接口地址和 Token'); return; }
                isAppTesting.value = true; appResult.value = '正在向本地 App 发送指令...';
                try {
                    const res = await authFetch('/api/send_to_app', {
                        method: 'POST', headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ url: appUrl.value, token: appToken.value, message: appMessage.value })
                    });
                    const data = await res.json();
                    if (data.status === 'success') {
                        appResult.value = `状态码: ${data.status_code}\n返回结果:\n${data.response}`;
                        ElementPlus.ElMessage.success('请求执行成功');
                    } else {
                        appResult.value = `请求抛出异常:\n${data.error}`;
                        ElementPlus.ElMessage.error('执行失败，请检查终端日志');
                    }
                } catch (e) { appResult.value = `网络异常: ${e.message}`; } 
                finally { isAppTesting.value = false; }
            };

            const exportData = async () => {
                const res = await authFetch('/api/export_backup');
                const data = await res.json();
                const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
                const url = URL.createObjectURL(blob);
                const a = document.createElement('a');
                a.href = url;
                a.download = `yunyun_backup_${new Date().toISOString().slice(0,19)}.json`;
                a.click(); URL.revokeObjectURL(url);
                ElementPlus.ElMessage.success('导出成功');
            };

            const triggerImport = () => { fileInput.value.click(); };

            const importFile = async (event) => {
                const file = event.target.files[0];
                if (!file) return;
                const reader = new FileReader();
                reader.onload = async (e) => {
                    try {
                        const data = JSON.parse(e.target.result);
                        const res = await authFetch('/api/import_backup', {
                            method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(data)
                        });
                        const result = await res.json();
                        if (result.status === 'success') {
                            await loadData();
                            ElementPlus.ElMessage.success('恢复成功');
                        } else ElementPlus.ElMessage.error('恢复失败: ' + (result.message || '未知错误'));
                    } catch (err) { ElementPlus.ElMessage.error('文件解析失败'); }
                    fileInput.value.value = '';
                };
                reader.readAsText(file);
            };

            const refreshStats = async () => {
                const res = await authFetch('/api/stats');
                const stats = await res.json();
                systemLogs.value = stats.system_logs || []; 
                await nextTick();
                renderCharts(stats);
            };

            const clearStats = async () => {
                await authFetch('/api/clear_stats', { method: 'POST' });
                ElementPlus.ElMessage.success('统计已清空');
                refreshStats();
            };

            const renderCharts = (stats) => {
                const modelCtx = document.getElementById('modelChart')?.getContext('2d');
                const balanceCtx = document.getElementById('balanceChart')?.getContext('2d');
                if (!modelCtx || !balanceCtx) return;
                const textColor = isDark.value ? '#e0e0e0' : '#4a3b3e';
                const gridColor = isDark.value ? '#444' : '#ddd';

                const modelCounts = stats.model_counts || {};
                const labels = Object.keys(modelCounts); const data = Object.values(modelCounts);
                if (modelChart) modelChart.destroy();
                modelChart = new Chart(modelCtx, {
                    type: 'pie',
                    data: { labels: labels.length ? labels : ['暂无数据'], datasets: [{ data: data.length ? data : [1], backgroundColor: ['#ff8fa3', '#ffb3c6', '#ffd6e0', '#e5989b', '#b5838d'], borderWidth: 0 }] },
                    options: { responsive: true, maintainAspectRatio: true, plugins: { legend: { labels: { color: textColor } } } }
                });

                const history = stats.balance_history || [];
                const times = history.map(h => new Date(h.time).toLocaleString());
                const balances = history.map(h => h.balance);
                if (balanceChart) balanceChart.destroy();
                balanceChart = new Chart(balanceCtx, {
                    type: 'line',
                    data: { labels: times.length ? times : ['暂无数据'], datasets: [{ label: '总余额', data: balances.length ? balances : [0], borderColor: '#ff8fa3', backgroundColor: 'rgba(255, 143, 163, 0.1)', tension: 0.3, fill: true }] },
                    options: { responsive: true, maintainAspectRatio: true, plugins: { legend: { labels: { color: textColor } } }, scales: { x: { ticks: { color: textColor }, grid: { color: gridColor } }, y: { ticks: { color: textColor }, grid: { color: gridColor } } } }
                });
            };

            onMounted(() => {
                initTheme();
                if (isAuthorized.value) loadData();
            });

            return {
                isAuthorized, inputPwd, loginError, tryLogin,
                activeTab, keys, activeKey, batchKeys, singleKey, singleApiBase, checking,
                testPrompt, testResult, isTesting, fileInput, isDark,
                totalBalance, appUrl, appToken, appMessage, appResult, isAppTesting,
                systemLogs, isKeepAlive, 
                allowedModels, rawModels, singleModel, fetchingModels, 
                rainbowActive, rainbowCount, toggleRainbow,
                toggleKeepAlive, toggleTheme, loadData, saveData, maskKey, copyKey,
                importKeys, addSingleKey, deleteKey, checkAllBalances,
                addSingleModel, removeModel, toggleModel, fetchRawModels,
                sendTest, exportData, triggerImport, importFile,
                refreshStats, clearStats, sendToApp
            };
        }
    });

    app.use(ElementPlus).mount('#app');
</script>
</body>
</html>
"""

# ========== 自动余额刷新线程 ==========
def auto_balance_checker():
    while True:
        time.sleep(3600)  # 每小时
        try:
            data = load_data()
            for k in data.get("keys", []):
                key = k.get("key")
                base = k.get("api_base", API_BASE)
                try:
                    resp = requests.get(
                        f"{base}/user/info",
                        headers={"Authorization": f"Bearer {key}"},
                        timeout=10
                    )
                    if resp.status_code == 200:
                        resp_json = resp.json()
                        balance = resp_json.get("data", {}).get("totalBalance")
                        if balance is not None:
                            k["balance"] = f"{float(balance):.2f}"
                            record_balance_snapshot(key, k["balance"])
                except:
                    pass
            save_data(data)
            add_system_log("info", "自动余额刷新完成")
        except Exception as e:
            logger.error(f"自动余额刷新异常: {e}")

# ========== 控制台菜单 ==========
WAKELOCK_STATE = False

def show_menu():
    proxy_update = check_proxy_update()
    st_local, st_remote = check_st_versions()
    proxy_running = is_running(PID_FILE)
    st_running = is_running(ST_PID_FILE)

    os.system("clear")
    print("\n╭──────────────────────────────╮")
    print(f"  🌸 YunYun AI 控制台 [v{VERSION}]")
    print("╰──────────────────────────────╯")
    print("\n🔑 【API 本地代理】")
    print(f" 状态: {'🟢 运行中' if proxy_running else '🔴 已停止'}  {proxy_update}")
    if proxy_running:
        local_ip = get_local_ip()
        print(f" 🌐 管理面板: http://127.0.0.1:{PORT}?pwd={ADMIN_PASSWORD}")
        print(f" 📱 手机访问: http://{local_ip}:{PORT}?pwd={ADMIN_PASSWORD}")
    print("\n🍻 【傻酒馆 SillyTavern】")
    print(f" 状态: {'🟢 运行中' if st_running else '🔴 已停止'}")
    print(f" 版本: {st_local}(本地) | {st_remote}")
    print("\n" + "─" * 32)
    print("  1. 启动代理    2. 停止代理")
    print("  3. 启动酒馆    4. 停止酒馆")
    print("  5. 一键更新    6. 自启教程")
    print(f"  7. {'🔴 关闭' if WAKELOCK_STATE else '🟢 开启'} Termux 唤醒锁 (保活)")
    print("  0. 退出控制台")
    print("─" * 32)

def toggle_wakelock():
    global WAKELOCK_STATE
    if not WAKELOCK_STATE:
        os.system("termux-wake-lock 2>/dev/null")
        WAKELOCK_STATE = True
        print("\n✅ 已请求开启 Termux 唤醒锁，防止 CPU 休眠！")
    else:
        os.system("termux-wake-unlock 2>/dev/null")
        WAKELOCK_STATE = False
        print("\n✅ 已关闭 Termux 唤醒锁。")

def start_proxy():
    if is_running(PID_FILE):
        print("\n⚠️ 代理已在运行！")
        return
    if check_port(PORT):
        print(f"\n⚠️ 端口 {PORT} 已被占用")
        return
    try:
        p = subprocess.Popen([sys.executable, __file__, "run_app"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        with open(PID_FILE, "w") as f:
            f.write(str(p.pid))
        for _ in range(10):
            if not check_port(PORT):
                local_ip = get_local_ip()
                print("\n✅ 代理启动成功！")
                print(f"   平板管理面板: http://127.0.0.1:{PORT}?pwd={ADMIN_PASSWORD}")
                print(f"   手机访问地址: http://{local_ip}:{PORT}?pwd={ADMIN_PASSWORD}")
                return
            time.sleep(0.5)
        print("\n⚠️ 启动可能失败")
    except Exception as e:
        print(f"\n❌ 启动失败: {e}")

def stop_proxy():
    kill_process(PID_FILE)
    print("\n✅ 代理已停止")

def start_sillytavern():
    if is_running(ST_PID_FILE):
        print("\n⚠️ 傻酒馆已在运行！")
        return
    if check_port(ST_PORT):
        print(f"\n⚠️ 端口 {ST_PORT} 已被占用")
        return
    
    if not os.path.exists(ST_DIR):
        print("\n📥 首次使用，正在部署傻酒馆...")
        print("→ 克隆代码仓库并切换至 1.13.0 ...")
        if os.system(f"git clone https://github.com/SillyTavern/SillyTavern.git {ST_DIR}") != 0:
            print("❌ 克隆失败，请检查网络。")
            return
        if os.system(f"cd {ST_DIR} && git checkout 1.13.0 && npm install") != 0:
            print("❌ 依赖安装失败。")
            return
        print("✅ 部署完成！")
    else:
        print("\n⏳ 强制锁定酒馆版本为 1.13.0 并检查依赖...")
        os.system(f"cd {ST_DIR} && git fetch --tags && git reset --hard && git checkout 1.13.0 && npm install 2>/dev/null")

    print("\n🚀 启动傻酒馆中...")
    try:
        p = subprocess.Popen(["node", "server.js"], cwd=ST_DIR, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        with open(ST_PID_FILE, "w") as f:
            f.write(str(p.pid))
        for _ in range(10):
            if not check_port(ST_PORT):
                print("✅ 傻酒馆启动成功！")
                return
            time.sleep(0.5)
        print("⚠️ 启动可能较慢或失败，请检查。")
    except Exception as e:
        print(f"\n❌ 启动失败: {e}")

def stop_sillytavern():
    kill_process(ST_PID_FILE)
    print("\n✅ 傻酒馆已停止。")

def update_all():
    print("\n🔄 正在拉取代理代码更新...")
    os.system("git pull 2>/dev/null")
    if os.path.exists(ST_DIR):
        print("→ 强制维持酒馆 1.13.0 版本...")
        os.system(f"cd {ST_DIR} && git fetch --tags && git reset --hard && git checkout 1.13.0 && npm install")
    print("\n✅ 更新校验完毕！(重启服务生效)")
    input("\n👉 按回车继续...")

def show_autostart_help():
    print("\n" + "─" * 32)
    print(" 📖 【Termux 开机自启教程】")
    print("─" * 32)
    print(" 粘贴以下命令到 Termux 并回车：\n")
    print('echo \'if [ -z "$TMUX" ]; then cd ~/yunyun2 && python proxy_server.py; fi\' >> ~/.bash_profile')
    print("source ~/.bash_profile")
    input("\n👉 按回车返回...")

# ========== 小彩蛋 ==========
def easter_egg():
    print("""
  ∧＿∧
（｡･ω･｡)つ━☆・*。
⊂  ノ  ・゜+.
 しーＪ  °。+ *´¨)
       .· ´¸.·*´¨) ¸.·*¨)
       (¸.·´ (¸.·’* ☆
    """)
    print("\a")  # 终端响铃

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("command", nargs="?")
    parser.add_argument("--daemon", action="store_true")
    args = parser.parse_args()

    if args.command == "run_app":
        # 启动自动余额刷新线程
        t = threading.Thread(target=auto_balance_checker, daemon=True)
        t.start()
        app.run(host="0.0.0.0", port=PORT, use_reloader=False, debug=False, threaded=True)
        sys.exit(0)

    if args.command == "start":
        if args.daemon:
            if os.fork() == 0:
                start_proxy()
                sys.exit(0)
            else:
                sys.exit(0)
        else:
            start_proxy()
        sys.exit(0)

    if args.command == "start-st":
        if args.daemon:
            if os.fork() == 0:
                start_sillytavern()
                sys.exit(0)
            else:
                sys.exit(0)
        else:
            start_sillytavern()
        sys.exit(0)

    if args.command == "stop":
        stop_proxy()
        sys.exit(0)
        
    if args.command == "stop-st":
        stop_sillytavern()
        sys.exit(0)

    while True:
        show_menu()
        choice = input(" 请输入数字指令: ").strip()
        if choice == "1":
            start_proxy()
        elif choice == "2":
            stop_proxy()
        elif choice == "3":
            start_sillytavern()
        elif choice == "4":
            stop_sillytavern()
        elif choice == "5":
            update_all()
        elif choice == "6":
            show_autostart_help()
        elif choice == "7":
            toggle_wakelock()
        elif choice.lower() == "miaow":
            easter_egg()
        elif choice == "0":
            os.system("clear")
            sys.exit(0)
        else:
            print("\n⚠️ 无效选项")
        if choice not in ["5", "6", "7", "0", "miaow"]:
            input("\n👉 按回车返回...")

if __name__ == "__main__":
    main()