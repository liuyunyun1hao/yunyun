#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
YunYun AI 代理服务 - 云端安全增强版
适配 Render / 环境变量持久化 / UI 密码保护 / 代理鉴权
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
from pathlib import Path
from datetime import datetime
from collections import defaultdict
from functools import wraps
from flask import Flask, request, jsonify, Response
import requests

try:
    from cryptography.fernet import Fernet
    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False

# ========== 云端环境变量配置 ==========
PORT = int(os.environ.get("PORT", 8888))               # 适配 Render 自动分配的端口
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "")  # Web 控制台登录密码
PROXY_TOKEN = os.environ.get("PROXY_TOKEN", "")        # API 鉴权密钥 (保护真实 Key)
ENV_API_KEYS = os.environ.get("API_KEYS", "")          # 逗号分隔的 sk-xxx，解决免费层文件丢失问题

# ========== 基础配置 ==========
VERSION = "4.0-Cloud-Secured"
DATA_FILE = "keys_data.json"
STATS_FILE = "stats_data.json"
PID_FILE = "server.pid"
API_BASE = "https://api.siliconflow.cn/v1"
LOG_FILE = "proxy.log"
LOG_MAX_BYTES = 10 * 1024 * 1024
LOG_BACKUP_COUNT = 3
ENCRYPT_KEY_FILE = "encrypt.key"

RETRY_COUNT = 3
REQUEST_TIMEOUT = (10, 120)

# ========== 日志 ==========
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
    if not CRYPTO_AVAILABLE: return None
    key_file = Path(ENCRYPT_KEY_FILE)
    if key_file.exists():
        with open(key_file, 'rb') as f: return f.read()
    else:
        key = Fernet.generate_key()
        with open(key_file, 'wb') as f: f.write(key)
        return key

def encrypt_data(data):
    key = get_encrypt_key()
    if key is None: return data
    try:
        return Fernet(key).encrypt(data.encode()).decode()
    except:
        return data

def decrypt_data(data):
    key = get_encrypt_key()
    if key is None: return data
    try:
        return Fernet(key).decrypt(data.encode()).decode()
    except:
        return data

# ========== 数据加载/保存 (融合环境变量) ==========
_MEM_CACHE = None

def load_data():
    global _MEM_CACHE
    if _MEM_CACHE is not None:
        return _MEM_CACHE
    
    _MEM_CACHE = {"keys": [], "active_key": None}
    if os.path.exists(DATA_FILE):
        try:
            with open(DATA_FILE, "r", encoding="utf-8") as f:
                raw = f.read()
                if raw.startswith("enc:"):
                    data = json.loads(decrypt_data(raw[4:]))
                else:
                    data = json.loads(raw)
                _MEM_CACHE.update(data)
        except Exception as e:
            logger.error(f"加载数据失败: {e}")
            
    # 核心：每次加载时注入环境变量中的 Keys，确保即使文件丢失 Key 仍在
    if ENV_API_KEYS:
        env_keys = [k.strip() for k in ENV_API_KEYS.split(",") if k.strip().startswith("sk-")]
        existing_keys = {k["key"] for k in _MEM_CACHE.get("keys", [])}
        for ek in env_keys:
            if ek not in existing_keys:
                _MEM_CACHE["keys"].append({"key": ek, "balance": "未知"})
                # 默认激活第一个配置的 Key
                if not _MEM_CACHE.get("active_key"):
                    _MEM_CACHE["active_key"] = ek
                    
    return _MEM_CACHE

def save_data(data):
    global _MEM_CACHE
    def get_balance_val(item):
        try:
            bal = item.get("balance", "0")
            return float(bal) if isinstance(bal, (int, float)) or (isinstance(bal, str) and bal.replace('.', '', 1).isdigit()) else float('inf')
        except: return float('inf')
        
    data["keys"] = sorted(data["keys"], key=get_balance_val)
    _MEM_CACHE = data
    json_str = json.dumps(data, indent=2, ensure_ascii=False)
    
    try:
        if CRYPTO_AVAILABLE and os.path.exists(ENCRYPT_KEY_FILE):
            with open(DATA_FILE, "w", encoding="utf-8") as f:
                f.write("enc:" + encrypt_data(json_str))
        else:
            with open(DATA_FILE, "w", encoding="utf-8") as f:
                f.write(json_str)
    except Exception as e:
        logger.error(f"写入文件失败 (可能在云端只读环境中): {e}")

# ========== 统计数据管理 ==========
def load_stats():
    if os.path.exists(STATS_FILE):
        try:
            with open(STATS_FILE, "r", encoding="utf-8") as f: return json.load(f)
        except: pass
    return {"model_counts": {}, "balance_history": {}}

def save_stats(stats):
    try:
        with open(STATS_FILE, "w", encoding="utf-8") as f:
            json.dump(stats, f, indent=2, ensure_ascii=False)
    except: pass

def record_model_usage(model_name):
    stats = load_stats()
    stats.setdefault("model_counts", {})[model_name] = stats.get("model_counts", {}).get(model_name, 0) + 1
    save_stats(stats)

def record_balance_snapshot(key, balance_str):
    try:
        balance_val = float(balance_str) if balance_str.replace('.', '', 1).isdigit() else None
        if balance_val is None: return
        stats = load_stats()
        history = stats.setdefault("balance_history", {})
        history.setdefault(key, []).append({"time": time.time(), "balance": balance_val})
        history[key] = history[key][-30:]
        save_stats(stats)
    except: pass

def get_total_balance_history():
    stats = load_stats()
    time_sums = defaultdict(float)
    for entries in stats.get("balance_history", {}).values():
        for entry in entries:
            time_sums[int(entry["time"] // 3600) * 3600] += entry["balance"]
    return [{"time": ts * 1000, "balance": time_sums[ts]} for ts in sorted(time_sums.keys())]

# ========== 安全鉴权中间件 ==========
def check_auth(username, password):
    return password == ADMIN_PASSWORD and username == "admin"

def authenticate():
    return Response(
    '🚫 访问受限：请输入管理员凭据 (用户名为 admin)。\n', 401,
    {'WWW-Authenticate': 'Basic realm="YunYun Proxy Admin"'})

def requires_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not ADMIN_PASSWORD:
            return f(*args, **kwargs)
        auth = request.authorization
        if not auth or not check_auth(auth.username, auth.password):
            return authenticate()
        return f(*args, **kwargs)
    return decorated

# ========== Flask 应用 ==========
app = Flask(__name__)

# Web UI 及 API 接口全面保护
@app.route("/")
@requires_auth
def index(): return HTML_CONTENT

@app.route("/api/data", methods=["GET", "POST"])
@requires_auth
def manage_data():
    if request.method == "POST":
        data = request.json
        data.setdefault("keys", [])
        data.setdefault("active_key", None)
        save_data(data)
        return jsonify({"status": "success", "data": load_data()})
    return jsonify(load_data())

@app.route("/api/check_balance", methods=["POST"])
@requires_auth
def check_balance():
    key = request.json.get("key")
    if not key: return jsonify({"balance": "无效Key"}), 400
    try:
        resp = requests.get(f"{API_BASE}/user/info", headers={"Authorization": f"Bearer {key}"}, timeout=10)
        if resp.status_code == 200:
            balance = resp.json().get("data", {}).get("totalBalance", "获取失败")
            if isinstance(balance, (int, float)): balance = f"{balance:.2f}"
            record_balance_snapshot(key, balance)
            return jsonify({"balance": balance})
        return jsonify({"balance": "查询失败"})
    except: return jsonify({"balance": "网络异常"})

@app.route("/api/stats", methods=["GET"])
@requires_auth
def get_stats():
    return jsonify({"model_counts": load_stats().get("model_counts", {}), "balance_history": get_total_balance_history()})

@app.route("/api/export_backup", methods=["GET"])
@requires_auth
def export_backup(): return jsonify(load_data())

@app.route("/api/import_backup", methods=["POST"])
@requires_auth
def import_backup():
    try:
        save_data(request.json)
        return jsonify({"status": "success"})
    except Exception as e: return jsonify({"status": "error", "message": str(e)}), 400

@app.route("/api/clear_stats", methods=["POST"])
@requires_auth
def clear_stats():
    save_stats({"model_counts": {}, "balance_history": {}})
    return jsonify({"status": "success"})

# ========== 代理核心路由 (Proxy Token 保护) ==========
@app.route("/v1/<path:path>", methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"])
def proxy(path):
    # 如果配置了代理鉴权，拦截非法请求
    if PROXY_TOKEN:
        auth_header = request.headers.get("Authorization", "")
        if auth_header != f"Bearer {PROXY_TOKEN}":
            return jsonify({"error": "Unauthorized: 代理鉴权 Token 无效或未提供"}), 401

    data = load_data()
    keys = data.get("keys", [])
    if not keys: return jsonify({"error": "云端未配置任何后端 API Key"}), 400

    model = request.get_json(silent=True).get("model", "unknown") if request.is_json else "unknown"
    is_stream = request.is_json and request.get_json(silent=True).get("stream", False)

    if path == "chat/completions" and model != "unknown":
        record_model_usage(model)

    active_key_val = data.get("active_key")
    ordered_keys = [k for k in keys if k["key"] == active_key_val] + [k for k in keys if k["key"] != active_key_val]

    base_headers = {k: v for k, v in request.headers if k.lower() not in ['host', 'authorization']}
    last_error = None

    for key_item in ordered_keys[:RETRY_COUNT]:
        headers = base_headers.copy()
        headers["Authorization"] = f"Bearer {key_item['key']}"

        try:
            resp = requests.request(
                method=request.method, url=f"{API_BASE}/{path}", headers=headers,
                data=request.get_data(), stream=is_stream, timeout=REQUEST_TIMEOUT
            )
            if resp.status_code in (401, 403, 429):
                last_error = resp.status_code
                continue

            excluded = ['content-encoding', 'content-length', 'transfer-encoding', 'connection']
            resp_headers = [(name, value) for name, value in resp.raw.headers.items() if name.lower() not in excluded]

            if is_stream:
                return Response(resp.iter_content(chunk_size=1024), status=resp.status_code, headers=resp_headers)
            else:
                return Response(resp.content, status=resp.status_code, headers=resp_headers, content_type=resp.headers.get('content-type'))
        except Exception as e:
            last_error = str(e)
            continue

    return jsonify({"error": f"所有后端Key均失败，最后错误: {last_error}"}), 500

# ========== 保持原有的精致前端 (截取以省略，实际保留你原版全部 HTML_CONTENT) ==========
HTML_CONTENT = """
"""

# ========== 本地启动入口 ==========
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=PORT, debug=False, threaded=True)
