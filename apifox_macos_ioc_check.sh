#!/bin/bash

set -u
IFS=$'\n\t'

SCRIPT_VERSION="1.1"
COMPROMISE_START="2026-03-04"
COMPROMISE_END="2026-03-22"
LOG_LOOKBACK_DAYS="${LOG_LOOKBACK_DAYS:-30}"
LOG_TIMEOUT_SECONDS="${LOG_TIMEOUT_SECONDS:-20}"

FINDINGS=0
RISK_SCORE=0
TMP_DIR="${TMPDIR:-/tmp}/apifox-ioc-check-$$"
mkdir -p "$TMP_DIR"

cleanup() {
  rm -rf "$TMP_DIR"
}
trap cleanup EXIT

section() {
  printf '\n== %s ==\n' "$1"
}

info() {
  printf '[INFO] %s\n' "$1"
}

warn() {
  printf '[WARN] %s\n' "$1"
}

hit() {
  local score="$1"
  shift
  FINDINGS=$((FINDINGS + 1))
  RISK_SCORE=$((RISK_SCORE + score))
  printf '[HIT] %s\n' "$*"
}

show_block() {
  sed 's/^/    /'
}

command_exists() {
  command -v "$1" >/dev/null 2>&1
}

run_capture_with_timeout() {
  local timeout_seconds="$1"
  local out_file="$2"
  shift 2

  : >"$out_file"
  "$@" >"$out_file" 2>/dev/null &
  local cmd_pid=$!
  local waited=0

  while kill -0 "$cmd_pid" 2>/dev/null; do
    if [ "$waited" -ge "$timeout_seconds" ]; then
      kill "$cmd_pid" 2>/dev/null
      wait "$cmd_pid" 2>/dev/null
      return 124
    fi
    sleep 1
    waited=$((waited + 1))
  done

  wait "$cmd_pid"
}

IOC_REGEX='apifox\.it\.com|/public/apifox-event\.js|/event/[02]/log|af_uuid|af_os|af_user|af_name|af_apifox_user|af_apifox_name|_rl_headers|_rl_mc|MIIEvQIBADANBgkqh|collectPreInformations|collectAddInformations'

collect_candidate_paths() {
  {
    [ -e "/Applications/Apifox.app" ] && printf '%s\n' "/Applications/Apifox.app"
    [ -e "$HOME/Applications/Apifox.app" ] && printf '%s\n' "$HOME/Applications/Apifox.app"
    [ -e "$HOME/Library/Application Support/Apifox" ] && printf '%s\n' "$HOME/Library/Application Support/Apifox"
    [ -e "$HOME/Library/Caches/Apifox" ] && printf '%s\n' "$HOME/Library/Caches/Apifox"
    [ -e "$HOME/Library/Logs/Apifox" ] && printf '%s\n' "$HOME/Library/Logs/Apifox"
    [ -e "$HOME/Library/Saved Application State/com.apifox.desktop.savedState" ] && printf '%s\n' "$HOME/Library/Saved Application State/com.apifox.desktop.savedState"

    find \
      "$HOME/Library/Application Support" \
      "$HOME/Library/Caches" \
      "$HOME/Library/Logs" \
      "$HOME/Library/Preferences" \
      "$HOME/Library/Saved Application State" \
      -maxdepth 4 \
      \( -iname '*apifox*' -o -iname '*Apifox*' \) \
      2>/dev/null
  } | sort -u
}

print_path_list() {
  local file="$1"
  if [ -s "$file" ]; then
    sed 's/^/    /' "$file"
  else
    printf '    (none)\n'
  fi
}

scan_path_for_iocs() {
  local path="$1"
  local label="$2"
  local out="$TMP_DIR/scan.out"

  if [ -d "$path" ]; then
    grep -aR -n -E "$IOC_REGEX" "$path" 2>/dev/null | head -n 20 >"$out"
  elif [ -f "$path" ]; then
    grep -a -n -E "$IOC_REGEX" "$path" 2>/dev/null | head -n 20 >"$out"
  else
    : >"$out"
  fi

  if [ -s "$out" ]; then
    hit 3 "$label 命中已知 IOC"
    cat "$out" | show_block
  fi
}

scan_literal_in_file() {
  local file="$1"
  local regex="$2"
  local label="$3"
  local score="$4"
  local out="$TMP_DIR/literal.out"

  if [ ! -f "$file" ]; then
    return
  fi

  grep -a -n -E "$regex" "$file" 2>/dev/null | head -n 10 >"$out"
  if [ -s "$out" ]; then
    hit "$score" "$label"
    cat "$out" | show_block
  fi
}

check_system_info() {
  section "系统信息"
  info "脚本版本: $SCRIPT_VERSION"
  info "当前时间: $(date '+%Y-%m-%d %H:%M:%S %Z')"
  info "主机名: $(scutil --get ComputerName 2>/dev/null || hostname)"
  info "用户: $(id -un)"
  info "系统: $(sw_vers -productName 2>/dev/null) $(sw_vers -productVersion 2>/dev/null) ($(uname -m))"
  info "重点时间窗: $COMPROMISE_START 至 $COMPROMISE_END"
}

check_apifox_process() {
  section "Apifox 进程"
  if pgrep -ifl '[Aa]pifox' >"$TMP_DIR/proc.txt"; then
    warn "检测到 Apifox 相关进程仍在运行，建议先退出再继续处置"
    cat "$TMP_DIR/proc.txt" | show_block
  else
    info "当前未发现运行中的 Apifox 进程"
  fi
}

check_apifox_artifacts() {
  section "Apifox 本地痕迹"
  collect_candidate_paths >"$TMP_DIR/apifox_paths.txt"
  if [ -s "$TMP_DIR/apifox_paths.txt" ]; then
    info "发现以下 Apifox 相关路径:"
    print_path_list "$TMP_DIR/apifox_paths.txt"
  else
    warn "未发现明显的 Apifox 本地路径"
    return
  fi

  while IFS= read -r path; do
    scan_path_for_iocs "$path" "$path"
  done <"$TMP_DIR/apifox_paths.txt"
}

check_local_storage() {
  section "Electron Local Storage"
  find "$HOME/Library/Application Support" -path '*Apifox*' \( -iname 'leveldb' -o -iname 'Local Storage' \) 2>/dev/null | sort -u >"$TMP_DIR/local_storage_dirs.txt"

  if [ ! -s "$TMP_DIR/local_storage_dirs.txt" ]; then
    warn "未发现 Apifox 对应的 Local Storage/leveldb 目录"
    return
  fi

  info "发现可能的 Local Storage 目录:"
  print_path_list "$TMP_DIR/local_storage_dirs.txt"

  while IFS= read -r path; do
    scan_path_for_iocs "$path" "$path"
  done <"$TMP_DIR/local_storage_dirs.txt"
}

check_shell_histories() {
  section "Shell 历史"
  local any_history=0
  for hist in "$HOME/.zsh_history" "$HOME/.bash_history"; do
    if [ -f "$hist" ]; then
      any_history=1
      scan_literal_in_file "$hist" 'apifox\.it\.com|/public/apifox-event\.js|/event/[02]/log' "$hist 中出现 IOC 字符串" 1
    fi
  done

  if [ "$any_history" -eq 0 ]; then
    info "未发现 .zsh_history 或 .bash_history"
  fi
}

check_unified_logs() {
  section "统一日志"
  if ! command_exists log; then
    warn "系统缺少 log 命令，跳过统一日志检查"
    return
  fi

  local predicate='eventMessage CONTAINS[c] "apifox.it.com" OR eventMessage CONTAINS[c] "/public/apifox-event.js" OR eventMessage CONTAINS[c] "/event/0/log" OR eventMessage CONTAINS[c] "/event/2/log" OR eventMessage CONTAINS[c] "af_uuid"'

  if ! run_capture_with_timeout "$LOG_TIMEOUT_SECONDS" "$TMP_DIR/unified_logs_raw.txt" \
    log show --style compact --last "${LOG_LOOKBACK_DAYS}d" --predicate "$predicate"; then
    warn "统一日志扫描超过 ${LOG_TIMEOUT_SECONDS} 秒，已跳过。可通过 LOG_TIMEOUT_SECONDS 调大超时"
    return
  fi

  head -n 40 "$TMP_DIR/unified_logs_raw.txt" >"$TMP_DIR/unified_logs.txt"

  if [ -s "$TMP_DIR/unified_logs.txt" ]; then
    hit 2 "统一日志在最近 ${LOG_LOOKBACK_DAYS} 天内命中 IOC"
    cat "$TMP_DIR/unified_logs.txt" | show_block
  else
    info "最近 ${LOG_LOOKBACK_DAYS} 天的统一日志中未发现命中"
  fi
}

check_persistence() {
  section "持久化痕迹"
  {
    [ -d "$HOME/Library/LaunchAgents" ] && grep -aR -n -E "$IOC_REGEX" "$HOME/Library/LaunchAgents" 2>/dev/null
    [ -d "/Library/LaunchAgents" ] && grep -aR -n -E "$IOC_REGEX" "/Library/LaunchAgents" 2>/dev/null
    [ -d "/Library/LaunchDaemons" ] && grep -aR -n -E "$IOC_REGEX" "/Library/LaunchDaemons" 2>/dev/null
  } | head -n 20 >"$TMP_DIR/persistence.txt"

  if [ -s "$TMP_DIR/persistence.txt" ]; then
    hit 3 "LaunchAgents/LaunchDaemons 中出现 IOC，需优先人工核查"
    cat "$TMP_DIR/persistence.txt" | show_block
  else
    info "未在 LaunchAgents/LaunchDaemons 中发现 IOC 字符串"
  fi
}

print_summary() {
  section "结果汇总"
  info "命中项数量: $FINDINGS"
  info "风险分值: $RISK_SCORE"

  if [ "$RISK_SCORE" -ge 6 ]; then
    warn "结论: 高风险，建议视为已受影响主机进行处置"
  elif [ "$RISK_SCORE" -ge 3 ]; then
    warn "结论: 中风险，建议立即人工复核并按受影响主机处理凭证"
  elif [ "$RISK_SCORE" -ge 1 ]; then
    warn "结论: 低风险，但存在可疑痕迹，需要结合使用记录判断"
  else
    info "结论: 未发现直接 IOC"
  fi

  printf '\n'
  printf '%s\n' "处置建议:"
  printf '%s\n' "  1. 如果你在 2026-03-04 至 2026-03-22 期间启动过 Apifox 桌面端，即使脚本未命中，也建议轮换 SSH、Git、Kubernetes、npm 等凭证。"
  printf '%s\n' "  2. 如果命中 _rl_headers/_rl_mc、apifox.it.com 或 /event/0/log 等 IOC，优先停用该主机上的相关密钥并审计服务器登录日志。"
  printf '%s\n' "  3. 本脚本主要覆盖本地痕迹与日志痕迹；若攻击者已投放独立后门，仍需配合 EDR、网络日志和 LaunchAgent/守护进程审计。"
}

main() {
  if [ "$(uname -s)" != "Darwin" ]; then
    printf '%s\n' "该脚本仅支持 macOS。"
    exit 1
  fi

  check_system_info
  check_apifox_process
  check_apifox_artifacts
  check_local_storage
  check_shell_histories
  check_unified_logs
  check_persistence
  print_summary
}

main "$@"
