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

# ========== 前端 HTML ==========
HTML_CONTENT = """
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no, viewport-fit=cover">
    <title>YunYun Proxy</title>
    <script src="https://unpkg.com/vue@3/dist/vue.global.js"></script>
    <link rel="stylesheet" href="https://unpkg.com/element-plus/dist/index.css" />
    <script src="https://unpkg.com/element-plus"></script>
    <script src="https://cdn.jsdelivr.net/npm/chart.js@3.9.1/dist/chart.min.js"></script>
    <style>
        :root {
            --theme-pink: #ff8fa3;
            --theme-pink-hover: #ff9fb1;
            --glass-bg: rgba(255, 255, 255, 0.65);
            --glass-border: rgba(255, 255, 255, 0.5);
            --text-main: #4a3b3e;
            --text-sub: #9c898c;
            --bg-gradient: linear-gradient(135deg, #fdf4f6 0%, #fbe1e6 100%);
            --card-bg: rgba(255, 255, 255, 0.65);
        }
        body.dark {
            --theme-pink: #d47a8a;
            --theme-pink-hover: #e08a9a;
            --glass-bg: rgba(30, 30, 40, 0.75);
            --glass-border: rgba(80, 80, 100, 0.5);
            --text-main: #e0e0e0;
            --text-sub: #b0b0c0;
            --bg-gradient: linear-gradient(135deg, #1e1e2a 0%, #2a2a3a 100%);
            --card-bg: rgba(40, 40, 55, 0.75);
        }
        body {
            font-family: -apple-system, sans-serif;
            background: var(--bg-gradient);
            background-attachment: fixed;
            color: var(--text-main);
            margin: 0;
            padding: calc(env(safe-area-inset-top) + 16px) 16px calc(env(safe-area-inset-bottom) + 40px) 16px;
            transition: background 0.3s, color 0.3s;
        }
        .app-container { max-width: 900px; margin: 0 auto; }
        .theme-toggle {
            position: absolute;
            top: 16px;
            right: 16px;
            background: var(--card-bg);
            border: 1px solid var(--glass-border);
            border-radius: 40px;
            padding: 8px 16px;
            cursor: pointer;
            backdrop-filter: blur(12px);
            color: var(--text-main);
            font-weight: 600;
            z-index: 10;
        }
        .segmented-control {
            display: flex;
            background: var(--glass-bg);
            border: 1px solid var(--glass-border);
            backdrop-filter: blur(12px);
            border-radius: 14px;
            padding: 4px;
            margin-bottom: 24px;
        }
        .segment {
            flex: 1;
            text-align: center;
            padding: 10px 0;
            font-size: 14px;
            font-weight: 600;
            cursor: pointer;
            border-radius: 10px;
            color: var(--text-sub);
            transition: all 0.3s ease;
        }
        .segment.active {
            background: rgba(255, 255, 255, 0.9);
            color: var(--theme-pink);
            box-shadow: 0 2px 10px rgba(255, 143, 163, 0.15);
        }
        body.dark .segment.active {
            background: rgba(70, 70, 90, 0.9);
        }
        .ios-card {
            background: var(--card-bg);
            backdrop-filter: blur(20px);
            border: 1px solid var(--glass-border);
            border-radius: 24px;
            padding: 24px;
            box-shadow: 0 10px 40px rgba(0, 0, 0, 0.1);
            margin-bottom: 24px;
        }
        .card-title {
            font-size: 20px;
            font-weight: 700;
            margin: 0 0 20px 0;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        .el-button { border-radius: 12px !important; font-weight: 600 !important; border: none !important; }
        .el-button--primary { background-color: var(--theme-pink) !important; color: white !important; box-shadow: 0 4px 12px rgba(255, 143, 163, 0.3) !important; }
        .el-button--primary:active { background-color: var(--theme-pink-hover) !important; transform: scale(0.98); }
        .el-input__wrapper, .el-textarea__inner {
            border-radius: 14px !important;
            background: rgba(255, 255, 255, 0.7) !important;
            box-shadow: 0 0 0 1px rgba(255, 143, 163, 0.2) inset !important;
        }
        body.dark .el-input__wrapper, body.dark .el-textarea__inner {
            background: rgba(40, 40, 55, 0.9) !important;
            color: #e0e0e0;
        }
        .el-input__wrapper.is-focus, .el-textarea__inner:focus {
            box-shadow: 0 0 0 2px var(--theme-pink) inset !important;
            background: #fff !important;
        }
        body.dark .el-input__wrapper.is-focus, body.dark .el-textarea__inner:focus {
            background: #2a2a3a !important;
        }
        .el-table {
            border-radius: 16px;
            overflow: hidden;
            background: transparent !important;
        }
        .el-table tr, .el-table th.el-table__cell {
            background-color: rgba(255, 255, 255, 0.3) !important;
            color: var(--text-main);
            font-weight: 600;
            border-bottom: 1px solid var(--glass-border) !important;
        }
        body.dark .el-table tr, body.dark .el-table th.el-table__cell {
            background-color: rgba(60, 60, 80, 0.5) !important;
        }
        .el-table td.el-table__cell {
            border-bottom: 1px solid var(--glass-border) !important;
            background: transparent !important;
            color: var(--text-main);
        }
        .el-radio__input.is-checked .el-radio__inner {
            border-color: var(--theme-pink) !important;
            background: var(--theme-pink) !important;
        }
        .el-radio__input.is-checked+.el-radio__label { color: var(--theme-pink) !important; }
        .test-box {
            background: rgba(255, 255, 255, 0.4);
            padding: 16px;
            border-radius: 16px;
            margin-top: 16px;
            border: 1px solid var(--glass-border);
        }
        body.dark .test-box { background: rgba(40, 40, 55, 0.6); }
        .add-key-area { margin-top: 20px; display: flex; gap: 8px; align-items: center; flex-wrap: wrap; }
        .add-key-area .el-input { flex: 1; min-width: 200px; }
        .backup-area { margin-top: 16px; display: flex; gap: 12px; justify-content: flex-end; }
        .chart-container { height: 250px; margin-top: 20px; }
        .stats-actions { display: flex; gap: 12px; margin-bottom: 16px; }
    </style>
</head>
<body>
<div id="app" class="app-container">
    <div class="theme-toggle" @click="toggleTheme">
        <span v-if="isDark">☀️ 浅色</span>
        <span v-else>🌙 暗色</span>
    </div>

    <div class="segmented-control" style="margin-top: 40px;">
        <div class="segment" :class="{active: activeTab === 'console'}" @click="activeTab = 'console'">控制台</div>
        <div class="segment" :class="{active: activeTab === 'test'}" @click="activeTab = 'test'">连接测试</div>
        <div class="segment" :class="{active: activeTab === 'stats'}" @click="activeTab = 'stats'; refreshStats()">统计</div>
        <div class="segment" :class="{active: activeTab === 'backup'}" @click="activeTab = 'backup'">备份/恢复</div>
    </div>

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
                <el-table-column label="API Key" min-width="180">
                    <template #default="scope">
                        <span style="font-family: monospace; color: var(--text-sub);">{{ maskKey(scope.row.key) }}</span>
                        <el-button link size="small" @click="copyKey(scope.row.key)" style="margin-left: 6px; padding: 0;">
                            <svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="color: var(--theme-pink);"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path></svg>
                        </el-button>
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
    </div>

    <div v-show="activeTab === 'backup'" class="ios-card">
        <h2 class="card-title">💾 备份与恢复</h2>
        <div class="backup-area">
            <el-button type="primary" @click="exportData">导出当前配置</el-button>
            <el-button type="primary" @click="triggerImport">从文件恢复</el-button>
            <input type="file" ref="fileInput" style="display:none" @change="importFile">
        </div>
        <div style="margin-top: 20px; font-size: 12px; color: var(--text-sub);">
            <p>提示：导出文件为JSON格式，可手动编辑后重新导入。</p>
        </div>
    </div>
</div>

<script>
    const { createApp, ref, computed, onMounted, watch, nextTick } = Vue;

    const app = createApp({
        setup() {
            // 状态
            const activeTab = ref('console');
            const keys = ref([]);
            const activeKey = ref(null);
            const batchKeys = ref('');
            const singleKey = ref('');
            const checking = ref(false);
            const testPrompt = ref('讲个冷笑话。');
            const testResult = ref('');
            const isTesting = ref(false);
            const fileInput = ref(null);
            const isDark = ref(false);

            // 图表实例
            let modelChart = null;
            let balanceChart = null;

            // 暗色模式
            const toggleTheme = () => {
                isDark.value = !isDark.value;
                document.body.classList.toggle('dark', isDark.value);
                localStorage.setItem('theme', isDark.value ? 'dark' : 'light');
                // 图表需要重新渲染以适应主题颜色（简单起见，刷新时重新绘制）
                if (activeTab.value === 'stats') refreshStats();
            };

            // 初始化主题
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

            // 总余额
            const totalBalance = computed(() => {
                let total = 0;
                let valid = false;
                keys.value.forEach(k => {
                    const val = parseFloat(k.balance);
                    if (!isNaN(val)) { total += val; valid = true; }
                });
                return valid ? total.toFixed(2) : '未知';
            });

            // 数据操作
            const loadData = async () => {
                const res = await fetch('/api/data');
                const data = await res.json();
                keys.value = data.keys || [];
                activeKey.value = data.active_key;
            };

            const saveData = async () => {
                const res = await fetch('/api/data', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ keys: keys.value, active_key: activeKey.value })
                });
                const result = await res.json();
                keys.value = result.data.keys;
            };

            const maskKey = (key) => {
                if (!key) return '';
                if (key.length <= 8) return '***';
                return key.substring(0, 5) + '...' + key.substring(key.length - 4);
            };

            const copyKey = async (key) => {
                try {
                    await navigator.clipboard.writeText(key);
                    ElementPlus.ElMessage.success('已复制到剪贴板');
                } catch (err) {
                    ElementPlus.ElMessage.error('复制失败');
                }
            };

            const importKeys = async () => {
                const lines = batchKeys.value.split('\\n');
                const newKeys = [];
                for (let line of lines) {
                    line = line.trim();
                    if (line.startsWith('sk-') && !keys.value.some(k => k.key === line)) {
                        newKeys.push({ key: line, balance: '未知' });
                    }
                }
                if (newKeys.length === 0) {
                    ElementPlus.ElMessage.warning('没有有效的 Key');
                    return;
                }
                keys.value.push(...newKeys);
                batchKeys.value = '';
                await saveData();
                ElementPlus.ElMessage.success(`成功导入 ${newKeys.length} 个 Key`);
                await checkAllBalances();
            };

            const addSingleKey = async () => {
                let key = singleKey.value.trim();
                if (!key.startsWith('sk-')) {
                    ElementPlus.ElMessage.warning('Key 必须以 sk- 开头');
                    return;
                }
                if (keys.value.some(k => k.key === key)) {
                    ElementPlus.ElMessage.warning('Key 已存在');
                    return;
                }
                keys.value.push({ key, balance: '未知' });
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
                        const res = await fetch('/api/check_balance', {
                            method: 'POST',
                            headers: { 'Content-Type': 'application/json' },
                            body: JSON.stringify({ key: keys.value[i].key })
                        });
                        const data = await res.json();
                        keys.value[i].balance = data.balance;
                    } catch (e) {
                        keys.value[i].balance = '请求失败';
                    }
                    await saveData();
                }
                checking.value = false;
                ElementPlus.ElMessage.success('余额刷新完成');
                // 刷新统计页图表
                if (activeTab.value === 'stats') refreshStats();
            };

            const sendTest = async () => {
                if (!activeKey.value) {
                    ElementPlus.ElMessage.warning('请先选择一个活动 Key');
                    return;
                }
                if (!testPrompt.value.trim()) {
                    ElementPlus.ElMessage.warning('请输入测试内容');
                    return;
                }
                isTesting.value = true;
                testResult.value = '请求发送中...';
                try {
                    const response = await fetch('/v1/chat/completions', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({
                            model: "Qwen/Qwen2.5-7B-Instruct",
                            messages: [{ role: "user", content: testPrompt.value }],
                            stream: false
                        })
                    });
                    const data = await response.json();
                    if (response.ok && data.choices) {
                        testResult.value = data.choices[0].message.content;
                    } else {
                        testResult.value = `错误: ${JSON.stringify(data)}`;
                    }
                } catch (error) {
                    testResult.value = `请求失败: ${error.message}`;
                } finally {
                    isTesting.value = false;
                }
            };

            const exportData = async () => {
                const res = await fetch('/api/export_backup');
                const data = await res.json();
                const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
                const url = URL.createObjectURL(blob);
                const a = document.createElement('a');
                a.href = url;
                a.download = `yunyun_backup_${new Date().toISOString().slice(0,19)}.json`;
                a.click();
                URL.revokeObjectURL(url);
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
                        const res = await fetch('/api/import_backup', {
                            method: 'POST',
                            headers: { 'Content-Type': 'application/json' },
                            body: JSON.stringify(data)
                        });
                        const result = await res.json();
                        if (result.status === 'success') {
                            await loadData();
                            ElementPlus.ElMessage.success('恢复成功');
                        } else {
                            ElementPlus.ElMessage.error('恢复失败: ' + (result.message || '未知错误'));
                        }
                    } catch (err) {
                        ElementPlus.ElMessage.error('文件解析失败');
                    }
                    fileInput.value.value = '';
                };
                reader.readAsText(file);
            };

            // 统计功能
            const refreshStats = async () => {
                const res = await fetch('/api/stats');
                const stats = await res.json();
                await nextTick();
                renderCharts(stats);
            };

            const clearStats = async () => {
                await fetch('/api/clear_stats', { method: 'POST' });
                ElementPlus.ElMessage.success('统计已清空');
                refreshStats();
            };

            const renderCharts = (stats) => {
                const modelCtx = document.getElementById('modelChart')?.getContext('2d');
                const balanceCtx = document.getElementById('balanceChart')?.getContext('2d');
                if (!modelCtx || !balanceCtx) return;

                const textColor = isDark.value ? '#e0e0e0' : '#4a3b3e';
                const gridColor = isDark.value ? '#444' : '#ddd';

                // 模型饼图
                const modelCounts = stats.model_counts || {};
                const labels = Object.keys(modelCounts);
                const data = Object.values(modelCounts);
                if (modelChart) modelChart.destroy();
                modelChart = new Chart(modelCtx, {
                    type: 'pie',
                    data: {
                        labels: labels.length ? labels : ['暂无数据'],
                        datasets: [{
                            data: data.length ? data : [1],
                            backgroundColor: ['#ff8fa3', '#ffb3c6', '#ffd6e0', '#e5989b', '#b5838d'],
                            borderWidth: 0
                        }]
                    },
                    options: {
                        responsive: true,
                        maintainAspectRatio: true,
                        plugins: {
                            legend: { labels: { color: textColor } }
                        }
                    }
                });

                // 余额趋势折线图
                const history = stats.balance_history || [];
                const times = history.map(h => new Date(h.time).toLocaleString());
                const balances = history.map(h => h.balance);
                if (balanceChart) balanceChart.destroy();
                balanceChart = new Chart(balanceCtx, {
                    type: 'line',
                    data: {
                        labels: times.length ? times : ['暂无数据'],
                        datasets: [{
                            label: '总余额',
                            data: balances.length ? balances : [0],
                            borderColor: '#ff8fa3',
                            backgroundColor: 'rgba(255, 143, 163, 0.1)',
                            tension: 0.3,
                            fill: true
                        }]
                    },
                    options: {
                        responsive: true,
                        maintainAspectRatio: true,
                        plugins: {
                            legend: { labels: { color: textColor } }
                        },
                        scales: {
                            x: { ticks: { color: textColor }, grid: { color: gridColor } },
                            y: { ticks: { color: textColor }, grid: { color: gridColor } }
                        }
                    }
                });
            };

            onMounted(() => {
                initTheme();
                loadData();
            });

            return {
                activeTab, keys, activeKey, batchKeys, singleKey, checking,
                testPrompt, testResult, isTesting, fileInput, isDark,
                totalBalance,
                toggleTheme, loadData, saveData, maskKey, copyKey,
                importKeys, addSingleKey, deleteKey, checkAllBalances,
                sendTest, exportData, triggerImport, importFile,
                refreshStats, clearStats
            };
        }
    });

    app.use(ElementPlus).mount('#app');
</script>
</body>
</html>
"""

# ========== 本地启动入口 ==========
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=PORT, debug=False, threaded=True)
