#!/usr/bin/env bash
# Trae 每日签到入口。真正的逻辑在同目录的 checkin.py。
#
#   ./checkin.sh              正常签到
#   ./checkin.sh --inspect    查看 storage.json 解析结果（不发送请求）
#   ./checkin.sh --dry-run    解密并提取令牌，但不发送请求
#
# 退出码：0 成功/已签到，2 需重新登录，3 其他错误，4 未找到令牌

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
exec python3 "${SCRIPT_DIR}/checkin.py" "$@"
