#!/usr/bin/env bash
# ============================================================
# TraeWork 每日积分签到（macOS / Linux / Git Bash 版）
#
# 流程：读取本地令牌 -> 查询签到状态 -> 未签到则领取 -> 写日志
# 用法：
#   bash scripts/checkin.sh
# 或（显式指定运行时）：
#   export TRAE_CHECKIN_NODE=/path/to/node
#   bash scripts/checkin.sh
# 定时（crontab 示例）：
#   0 9,12,15,18,21 * * * /path/to/checkin.sh >> /path/to/logs/checkin.log 2>&1
#
# 凭据安全提示：
#   - 本地令牌（token）等同 TraeWork 账号密码，仅在本脚本内存中使用，
#     通过管道立即消费，不写入日志、不落地、不回显。
#   - 日志（logs/checkin.log）只记录签到结果（积分/成功失败），不含令牌。
#   - 切勿将日志、脚本输出粘贴分享或提交到任何仓库。
# ============================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DECRYPT_JS="$SCRIPT_DIR/decrypt-token.js"
SKILL_ROOT="$(dirname "$SCRIPT_DIR")"
LOG_DIR="$SKILL_ROOT/logs"
mkdir -p "$LOG_DIR"
LOG_FILE="$LOG_DIR/checkin.log"

log() {
    local ts
    ts="$(date '+%Y-%m-%d %H:%M:%S')"
    echo "[$ts] $*"
    echo "[$ts] $*" >> "$LOG_FILE"
}

# ---------- 可选：随机错峰（避免整点风暴） ----------
if [ -n "${TRAE_CHECKIN_JITTER:-}" ]; then
    if [ "$TRAE_CHECKIN_JITTER" -gt 0 ] 2>/dev/null; then
        sleep $((RANDOM % TRAE_CHECKIN_JITTER))
    fi
fi

# ---------- 查找 Node.js ----------
find_node() {
    if [ -n "${TRAE_CHECKIN_NODE:-}" ] && [ -x "$TRAE_CHECKIN_NODE" ]; then
        echo "$TRAE_CHECKIN_NODE"
        return 0
    fi
    if command -v node >/dev/null 2>&1; then
        command -v node
        return 0
    fi
    # 常见安装路径
    for p in /usr/local/bin/node /opt/homebrew/bin/node /usr/bin/node; do
        if [ -x "$p" ]; then echo "$p"; return 0; fi
    done
    return 1
}

NODE_BIN="$(find_node)" || {
    log "未找到 Node.js 运行时。请安装 Node.js 或设置 TRAE_CHECKIN_NODE 环境变量。"
    exit 1
}

# ---------- 1. 读取令牌和设备 ID ----------
TOKEN=""
DEVICE_ID=""
USER_ID=""
EDITION=""

# 捕获解密脚本输出（stderr 不捕获，让安全提示正常显示）
while IFS= read -r line; do
    case "$line" in
        DECRYPT_RESULT:*) TOKEN="${line#DECRYPT_RESULT:}" ;;
        DEVICE_ID:*) DEVICE_ID="${line#DEVICE_ID:}" ;;
        USER_ID:*) USER_ID="${line#USER_ID:}" ;;
        EDITION:*) EDITION="${line#EDITION:}" ;;
    esac
done < <("$NODE_BIN" "$DECRYPT_JS")

if [ -z "$TOKEN" ]; then
    log "获取令牌失败，请确认已安装并登录 TraeWork / TraeCode 桌面端。"
    exit 1
fi
if [[ "$TOKEN" == ERR* ]]; then
    log "获取令牌失败（$TOKEN）。请确认已安装并登录 TraeWork / TraeCode 桌面端。"
    exit 1
fi

API_BASE="https://api.trae.cn"

# ---------- API 调用函数 ----------
trae_api() {
    local path="$1"
    local headers=(
        -H "Content-Type: application/json"
        -H "Accept: application/json"
        -H "Authorization: Cloud-IDE-JWT $TOKEN"
        -H "Origin: https://www.trae.cn"
        -H "Referer: https://www.trae.cn/"
    )
    if [ -n "$DEVICE_ID" ]; then
        headers+=(-H "x-device-id: $DEVICE_ID")
    fi
    # -w 输出 HTTP 状态码在最后一行
    curl -s -m 20 -w "\n%{http_code}" -X POST \
        "$API_BASE$path" \
        "${headers[@]}" \
        -d "{}" 2>/dev/null
}

# 从 curl 输出中分离响应体和状态码
parse_curl_output() {
    local output="$1"
    local lines
    mapfile -t lines <<< "$output"
    local count=${#lines[@]}
    if [ "$count" -eq 0 ]; then
        HTTP_CODE="000"
        RESP_BODY=""
        return
    fi
    HTTP_CODE="${lines[$((count - 1))]}"
    if [ "$count" -gt 1 ]; then
        RESP_BODY="$(printf '%s' "${lines[@]:0:$((count - 1))}")"
    else
        RESP_BODY=""
    fi
}

# ---------- 2. 查询签到状态 ----------
STATUS_OUTPUT="$(trae_api "/trae/api/v2/ug/checkin_credits/status")" || {
    log "查询签到状态失败（网络异常）"
    exit 1
}
parse_curl_output "$STATUS_OUTPUT"
STATUS_CODE="$HTTP_CODE"
STATUS_BODY="$RESP_BODY"

if [ "$STATUS_CODE" = "000" ]; then
    log "查询签到状态失败（网络异常）"
    exit 1
fi
if [ "$STATUS_CODE" = "401" ] || [ "$STATUS_CODE" = "403" ]; then
    log "令牌已过期或无权限（HTTP $STATUS_CODE），请打开 TraeWork 桌面端刷新登录态后重试"
    exit 1
fi
if [ "$STATUS_CODE" != "200" ]; then
    log "查询签到状态失败（HTTP $STATUS_CODE）"
    exit 1
fi
if [ -z "$STATUS_BODY" ]; then
    log "查询签到状态失败（响应为空，HTTP $STATUS_CODE）"
    exit 1
fi

# 解析状态（用 grep/sed 提取，不依赖 python）
CHECKED_IN=false
CREDITS=0
EXTRA_CREDITS=0
ENABLE=false

if echo "$STATUS_BODY" | grep -q '"checked_in"\s*:\s*true'; then
    CHECKED_IN=true
fi
if echo "$STATUS_BODY" | grep -q '"enable"\s*:\s*true'; then
    ENABLE=true
fi
if echo "$STATUS_BODY" | grep -qo '"credits"\s*:\s*[0-9]*'; then
    CREDITS="$(echo "$STATUS_BODY" | grep -o '"credits"\s*:\s*[0-9]*' | grep -o '[0-9]*$')"
fi
if echo "$STATUS_BODY" | grep -qo '"extra_credits"\s*:\s*[0-9]*'; then
    EXTRA_CREDITS="$(echo "$STATUS_BODY" | grep -o '"extra_credits"\s*:\s*[0-9]*' | grep -o '[0-9]*$')"
fi

if $CHECKED_IN; then
    total=$((CREDITS + EXTRA_CREDITS))
    log "今日已签到，积分 $CREDITS（额外 $EXTRA_CREDITS，总计 $total）。版本：$EDITION"
    exit 0
fi

# ---------- 3. 执行签到 ----------
if ! $ENABLE; then
    log "签到功能未启用，跳过。"
    exit 0
fi

CLAIM_OUTPUT="$(trae_api "/trae/api/v2/ug/checkin_credits/claim")" || {
    log "签到请求失败（网络异常）"
    exit 1
}
parse_curl_output "$CLAIM_OUTPUT"
CLAIM_CODE="$HTTP_CODE"
CLAIM_BODY="$RESP_BODY"

if [ "$CLAIM_CODE" = "000" ]; then
    log "签到请求失败（网络异常）"
    exit 1
fi
if [ "$CLAIM_CODE" = "401" ] || [ "$CLAIM_CODE" = "403" ]; then
    log "令牌已过期或无权限（HTTP $CLAIM_CODE），请打开 TraeWork 桌面端刷新登录态后重试"
    exit 1
fi
if [ -z "$CLAIM_BODY" ]; then
    log "签到请求失败（响应为空，HTTP $CLAIM_CODE）"
    exit 1
fi

# 解析签到结果
BODY_CODE=""
BODY_MSG=""
if echo "$CLAIM_BODY" | grep -qo '"code"\s*:\s*[0-9]*'; then
    BODY_CODE="$(echo "$CLAIM_BODY" | grep -o '"code"\s*:\s*[0-9]*' | grep -o '[0-9]*$')"
fi
if echo "$CLAIM_BODY" | grep -qo '"message"\s*:\s*"[^"]*"'; then
    BODY_MSG="$(echo "$CLAIM_BODY" | grep -o '"message"\s*:\s*"[^"]*"' | sed 's/.*"message"\s*:\s*"//' | sed 's/"$//')"
fi

if [ "$BODY_CODE" = "0" ]; then
    # 签到成功，重新查询积分
    STATUS2_OUTPUT="$(trae_api "/trae/api/v2/ug/checkin_credits/status")" || true
    parse_curl_output "$STATUS2_OUTPUT"
    if [ "$HTTP_CODE" = "200" ]; then
        c3=0; ec3=0
        if echo "$RESP_BODY" | grep -qo '"credits"\s*:\s*[0-9]*'; then
            c3="$(echo "$RESP_BODY" | grep -o '"credits"\s*:\s*[0-9]*' | grep -o '[0-9]*$')"
        fi
        if echo "$RESP_BODY" | grep -qo '"extra_credits"\s*:\s*[0-9]*'; then
            ec3="$(echo "$RESP_BODY" | grep -o '"extra_credits"\s*:\s*[0-9]*' | grep -o '[0-9]*$')"
        fi
        total=$((c3 + ec3))
        log "签到成功！领取积分 $c3（额外 $ec3，总计 $total）。版本：$EDITION"
        exit 0
    fi
    log "签到成功！版本：$EDITION（code=0, msg=$BODY_MSG）"
    exit 0
elif [ "$BODY_CODE" = "1001" ]; then
    log "认证失败（code=1001），请打开 TraeWork 桌面端刷新登录态后重试"
    exit 1
elif [ "$BODY_CODE" = "9004" ]; then
    log "签到失败（code=9004，缺少设备 ID），请确认桌面端已正常登录"
    exit 1
else
    log "签到未成功：code=$BODY_CODE msg=$BODY_MSG"
    exit 1
fi
