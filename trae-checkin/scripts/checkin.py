#!/usr/bin/env python3
"""Trae 每日签到。

从本机 Trae 桌面端的 storage.json 中解密登录令牌（Chromium v10/v11，
AES-128-CBC），调用官方签到接口领取每日积分。脚本幂等，令牌不会写入
日志或标准输出。

用法:
  checkin.sh                # 正常签到
  checkin.sh --inspect      # 只解析存储结构，不发送请求
  checkin.sh --dry-run      # 完整走解密与提取，但不发请求

退出码:
  0  签到成功，或今日已签到
  2  登录态失效，需在桌面端重新登录
  3  其他错误（网络、接口返回异常、环境不支持等）
  4  未找到可用令牌

环境变量:
  TRAE_STORAGE         指定 storage.json 路径
  TRAE_DECRYPT_PASS    覆盖解密口令（默认 peanuts / macOS 走 Keychain）
  TRAE_DECRYPT_SALT    覆盖解密 salt（默认 saltysalt）
  TRAE_DECRYPT_ITER    覆盖 PBKDF2 迭代次数（Linux 默认 1，macOS 默认 1003）
  TRAE_EXTRA_HEADERS   额外请求头，格式 "K1: V1; K2: V2"
  TRAE_BODY            请求体 JSON，默认 {}
"""

from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import json
import os
import re
import subprocess
import sys
import urllib.error
import urllib.request
from datetime import datetime
from pathlib import Path

API_URL = "https://api.trae.cn/trae/api/v2/ug/checkin_credits/claim"
ENCRYPTED_PREFIXES = ("v10", "v11")
JWT_RE = re.compile(r"^eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}$")
TOKEN_KEY_RE = re.compile(r"token|jwt|auth|session|credential|login", re.I)
RELOGIN_PATTERNS = ("请先登录", "未登录", "登录已", "登录失效", "重新登录", "unauthorized", "invalid token", "token expired")
ALREADY_PATTERNS = ("已签到", "已经签到", "重复签到", "already", "repeat")


def log(message: str, level: str = "INFO") -> None:
    stamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    line = f"[{stamp}] [{level}] {message}"
    print(line, file=sys.stderr)
    try:
        path = log_path()
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("a", encoding="utf-8") as handle:
            handle.write(line + "\n")
    except OSError:
        pass


def state_dir() -> Path:
    base = os.environ.get("XDG_STATE_HOME")
    root = Path(base) if base else Path.home() / ".local" / "state"
    return root / "trae-checkin"


def log_path() -> Path:
    return state_dir() / "checkin.log"


def storage_candidates() -> list[Path]:
    override = os.environ.get("TRAE_STORAGE")
    if override:
        return [Path(override).expanduser()]

    home = Path.home()
    names = ("Trae", "Trae CN", "TraeCN", "trae")
    if sys.platform == "darwin":
        roots = [home / "Library" / "Application Support" / n for n in names]
    elif sys.platform.startswith("win"):
        appdata = Path(os.environ.get("APPDATA", home / "AppData" / "Roaming"))
        local = Path(os.environ.get("LOCALAPPDATA", home / "AppData" / "Local"))
        roots = [appdata / n for n in names] + [local / n for n in names]
    else:
        roots = [home / ".config" / n for n in names]

    return [root / "User" / "globalStorage" / "storage.json" for root in roots]


def iter_strings(node, prefix: str = ""):
    if isinstance(node, dict):
        for key, value in node.items():
            yield from iter_strings(value, f"{prefix}.{key}" if prefix else str(key))
    elif isinstance(node, list):
        for index, value in enumerate(node):
            yield from iter_strings(value, f"{prefix}[{index}]")
    elif isinstance(node, str):
        yield prefix, node


def decrypt_key() -> tuple[bytes, bytes]:
    passphrase = os.environ.get("TRAE_DECRYPT_PASS")
    salt = os.environ.get("TRAE_DECRYPT_SALT", "saltysalt")

    if passphrase is None:
        if sys.platform == "darwin":
            passphrase = keychain_password()
            default_iterations = 1003
        else:
            passphrase = "peanuts"
            default_iterations = 1
    else:
        default_iterations = 1

    iterations = int(os.environ.get("TRAE_DECRYPT_ITER", default_iterations))
    key = hashlib.pbkdf2_hmac("sha1", passphrase.encode(), salt.encode(), iterations, 16)
    return key, b" " * 16


def keychain_password() -> str:
    """从 macOS Keychain 读取 Chromium 系应用的 safeStorage 口令。"""
    for service in ("Trae Safe Storage", "Trae CN Safe Storage", "Chromium Safe Storage"):
        try:
            result = subprocess.run(
                ["security", "find-generic-password", "-s", service, "-w"],
                capture_output=True, text=True, timeout=10, check=False,
            )
            if result.returncode == 0 and result.stdout.strip():
                return result.stdout.strip()
        except (OSError, subprocess.SubprocessError):
            continue
    raise RuntimeError("无法从 Keychain 读取解密口令，请设置 TRAE_DECRYPT_PASS")


def aes_cbc_decrypt(payload: bytes, key: bytes, iv: bytes) -> bytes:
    result = subprocess.run(
        [
            "openssl", "enc", "-d", "-aes-128-cbc", "-K", key.hex(), "-iv", iv.hex(),
        ],
        input=payload, capture_output=True, check=False,
    )
    if result.returncode != 0:
        raise ValueError(result.stderr.decode("utf-8", "replace").strip() or "openssl 解密失败")
    return result.stdout


def decrypt_string(value: str, key: bytes, iv: bytes) -> str | None:
    prefix = next((p for p in ENCRYPTED_PREFIXES if value.startswith(p)), None)
    if prefix is None:
        return None
    encoded = value[len(prefix):].strip()
    try:
        raw = base64.b64decode(encoded + "=" * (-len(encoded) % 4), validate=False)
    except (binascii.Error, ValueError):
        return None
    try:
        plain = aes_cbc_decrypt(raw, key, iv)
    except (ValueError, OSError):
        return None
    text = plain.decode("utf-8", "ignore").strip("\x00").strip()
    return text or None


def collect_tokens(document, key: bytes, iv: bytes) -> list[tuple[str, str, str]]:
    """返回 (字段路径, 令牌, 来源) 列表；来源为 plain / v10 / v11。"""
    found: list[tuple[str, str, str]] = []
    for path, value in iter_strings(document):
        if JWT_RE.match(value):
            found.append((path, value, "plain"))
            continue
        decrypted = decrypt_string(value, key, iv)
        if decrypted and JWT_RE.match(decrypted):
            found.append((path, decrypted, value[:3]))
    return found


def score(candidate: tuple[str, str, str]) -> tuple[int, int]:
    path, token, _ = candidate
    keyword = 2 if TOKEN_KEY_RE.search(path) else 0
    return keyword, len(token)


def load_storage(path: Path):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        log(f"读取 {path} 失败: {exc}", "ERROR")
        return None


def inspect(document, tokens) -> None:
    encrypted = sum(1 for _, v in iter_strings(document) if v.startswith(ENCRYPTED_PREFIXES))
    print("存储结构解析结果：")
    print(f"  加密字段数量: {encrypted}")
    print(f"  可用令牌数量: {len(tokens)}")
    for path, token, source in sorted(tokens, key=score, reverse=True):
        print(f"  - 字段 {path} | 来源 {source} | 长度 {len(token)} 字符 | 前缀 {token[:3]}***")


def claim(token: str, dry_run: bool) -> tuple[int, str]:
    body = os.environ.get("TRAE_BODY", "{}")
    if dry_run:
        log("dry-run：已提取令牌，跳过网络请求")
        return 0, "dry-run"

    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
        "Accept": "application/json",
        "User-Agent": "trae-checkin/1.0",
    }
    raw_extra = os.environ.get("TRAE_EXTRA_HEADERS", "")
    for pair in raw_extra.split(";"):
        if ":" in pair:
            name, _, val = pair.partition(":")
            headers[name.strip()] = val.strip()

    request = urllib.request.Request(
        API_URL, data=body.encode("utf-8"), headers=headers, method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=20) as response:
            status = response.status
            payload = response.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as exc:
        status = exc.code
        payload = exc.read().decode("utf-8", "replace") if exc.fp else ""
    except urllib.error.URLError as exc:
        return 3, f"网络请求失败: {exc.reason}"
    except TimeoutError:
        return 3, "网络请求超时"

    return interpret(status, payload)


def interpret(status: int, payload: str) -> tuple[int, str]:
    if status in (401, 403):
        return 2, f"HTTP {status}，登录态已失效"

    try:
        data = json.loads(payload) if payload else {}
    except json.JSONDecodeError:
        return 3, f"HTTP {status}，响应非 JSON: {payload[:120]}"

    code = data.get("code", data.get("errno"))
    message = str(data.get("message") or data.get("msg") or "")
    haystack = f"{message} {payload}".lower()

    if code in (1001, "1001") or any(p in haystack for p in RELOGIN_PATTERNS):
        return 2, f"接口返回鉴权失败（code={code}）：{message or '未提供原因'}"

    if any(p in haystack for p in ALREADY_PATTERNS):
        amount = extract_amount(data)
        return 0, f"今日已签到，无需重复领取。（当前积分: {amount}）" if amount else "今日已签到，无需重复领取。"

    if status == 200 and code in (None, 0, "0"):
        amount = extract_amount(data)
        return 0, f"签到成功，本次领取 {amount} 积分。" if amount else "签到成功。"

    return 3, f"HTTP {status}，code={code}，message={message or payload[:120]}"


def extract_amount(data):
    for key, value in walk_pairs(data):
        if any(word in key.lower() for word in ("credit", "point", "amount", "gain", "reward")):
            if isinstance(value, (int, float)) and not isinstance(value, bool):
                return value
    return None


def walk_pairs(node, prefix=""):
    if isinstance(node, dict):
        for key, value in node.items():
            yield from walk_pairs(value, str(key))
    elif isinstance(node, list):
        for value in node:
            yield from walk_pairs(value, prefix)
    elif isinstance(node, (int, float, str)):
        yield prefix, node


def main() -> int:
    parser = argparse.ArgumentParser(description="Trae 每日签到")
    parser.add_argument("--storage", help="storage.json 路径")
    parser.add_argument("--inspect", action="store_true", help="只解析结构，不发送请求")
    parser.add_argument("--dry-run", action="store_true", help="解密提取但不发请求")
    args = parser.parse_args()

    if args.storage:
        os.environ["TRAE_STORAGE"] = args.storage

    path = next((p for p in storage_candidates() if p.exists()), None)
    if path is None:
        log("未找到 storage.json。请先在本机打开并登录 Trae 桌面端，或用 TRAE_STORAGE 指定路径。", "ERROR")
        log(f"已尝试: {', '.join(str(p) for p in storage_candidates())}", "ERROR")
        return 4

    if sys.platform.startswith("win") and os.environ.get("TRAE_DECRYPT_PASS") is None:
        log("Windows 下令牌由 DPAPI 保护，本脚本不支持；请改用 PowerShell 的 ProtectedData 解密，或设置 TRAE_DECRYPT_PASS。", "ERROR")
        return 3

    document = load_storage(path)
    if document is None:
        return 3

    try:
        key, iv = decrypt_key()
    except RuntimeError as exc:
        log(str(exc), "ERROR")
        return 3

    tokens = collect_tokens(document, key, iv)
    if args.inspect:
        inspect(document, tokens)
        return 0

    if not tokens:
        log("storage.json 中未找到可用登录令牌，可能登录态已过期。请重新登录 Trae 桌面端。", "ERROR")
        return 4

    best = max(tokens, key=score)
    log(f"已提取令牌（字段 {best[0]}，来源 {best[2]}，长度 {len(best[1])}）")

    code, message = claim(best[1], args.dry_run)
    log(message, "INFO" if code == 0 else "ERROR")
    return code


if __name__ == "__main__":
    sys.exit(main())