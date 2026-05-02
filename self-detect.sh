#!/usr/bin/env bash
set -u

VERSION="3.2.5"
SCAN_MODE="quick"
SKIP_UDP=0
STRICT_RULES=0
OUTPUT_DIR=""
PUBLIC_IP=""
PROBE_TRAFFIC=0
PROBE_ROUNDS=1

REPORT_ENABLED=1
REPORT_URL="http://netreport.leikwanhost.com/report"

DOWNLOAD_OPENGFW=1
OPENGFW_URL="http://10.10.10.10/OpenGFW-linux-amd64"
OPENGFW_BIN="$(pwd)/OpenGFW-linux-amd64"

RUN_OPENGFW_REPLAY=0
REPLAY_CAPTURE_SECONDS=45
REPLAY_WITH_PROBE=0
REPLAY_BPF_FILTER="tcp or udp"
REPLAY_CAPTURE_INTERFACE="any"
REPLAY_LOG_FILE=""
REPLAY_PCAP_FILE=""
REPLAY_LOG_CLEAN_FILE=""
OPENGFW_LOG_LEVEL="debug"
declare -a REPLAY_HITS=()

DAEMON_MODE=0
DAEMON_INTERVAL_SECONDS=300
INSTALL_SYSTEMD=0
SYSTEMD_SERVICE_NAME="opengfw-self-detect"

BLOCK_LIST=""
UNBLOCK_LIST=""
INTERACTIVE_FIREWALL=0
FIREWALL_ONLY=0
TRUSTED_PORTS=""
MENU_MODE=0
FIREWALL_IP_FAMILY="both"
BRAND_TITLE="利群主機 | LeiKwan Host"

RULES_FILE=""
REPORT_FILE=""
SCRIPT_PATH=""
SCRIPT_DIR=""
RESULT_DIR=""
JUDGEMENT_LATEST_FILE=""
JUDGEMENT_HISTORY_FILE=""
OVERVIEW_LATEST_FILE=""
OVERVIEW_HISTORY_FILE=""

declare -a TCP_PORTS=()
declare -a UDP_PORTS=()
declare -a ENDPOINTS=()
declare -a FINDINGS=()
declare -a WARNINGS=()
declare -a JUDGEMENT_ROWS=()
declare -a SELECTED_RESULT_ROWS=()
declare -A RULE_DEDUP=()
declare -A PROCESS_BY_ENDPOINT=()
declare -A REPLAY_TYPES_BY_ENDPOINT=()
declare -A REPLAY_HITS_BY_ENDPOINT=()
declare -A APP_PROTO_BY_ENDPOINT=()
declare -A ENDPOINT_INDEX_BY_KEY=()

COLOR=1
if [[ ! -t 1 ]]; then
  COLOR=0
fi
if [[ "${NO_COLOR:-0}" == "1" ]]; then
  COLOR=0
fi

if [[ "$COLOR" == "1" ]]; then
  C_RESET=$'\033[0m'
  C_BLUE=$'\033[1;34m'
  C_GREEN=$'\033[1;32m'
  C_YELLOW=$'\033[1;33m'
  C_RED=$'\033[1;31m'
  C_GRAY=$'\033[0;37m'
else
  C_RESET=""
  C_BLUE=""
  C_GREEN=""
  C_YELLOW=""
  C_RED=""
  C_GRAY=""
fi

log_ui()   { echo -e "\n${C_BLUE}== $1 ==${C_RESET}"; }
log_info() { echo -e "${C_GREEN}[INFO]${C_RESET} $1"; }
log_warn() { echo -e "${C_YELLOW}[WARN]${C_RESET} $1"; }
log_err()  { echo -e "${C_RED}[CRIT]${C_RESET} $1"; }

run_command_with_spinner() {
  local title="$1"
  local outfile="$2"
  shift 2

  if [[ -t 1 ]]; then
    local pid=0
    local start_ts now elapsed idx=0
    local frames='|/-\'

    "$@" >"$outfile" 2>&1 &
    pid=$!
    start_ts="$(date +%s)"

    while kill -0 "$pid" >/dev/null 2>&1; do
      now="$(date +%s)"
      elapsed=$((now - start_ts))
      printf "\r[INFO] %s... %s %ss" "$title" "${frames:idx:1}" "$elapsed"
      idx=$(((idx + 1) % 4))
      sleep 0.2
    done

    wait "$pid"
    local rc=$?
    printf "\r%100s\r" ""
    return $rc
  fi

  "$@" >"$outfile" 2>&1
  return $?
}

show_timed_spinner() {
  local title="$1"
  local duration="$2"
  local watch_pid="${3:-}"

  if [[ ! -t 1 ]]; then
    sleep "$duration"
    return 0
  fi

  local start_ts now elapsed idx=0 remain
  local frames='|/-\'
  start_ts="$(date +%s)"

  while :; do
    now="$(date +%s)"
    elapsed=$((now - start_ts))
    remain=$((duration - elapsed))
    if (( remain < 0 )); then
      remain=0
    fi

    printf "\r[INFO] %s... %s %ss/%ss (remaining %ss)" \
      "$title" "${frames:idx:1}" "$elapsed" "$duration" "$remain"
    idx=$(((idx + 1) % 4))

    if (( elapsed >= duration )); then
      break
    fi
    if [[ -n "$watch_pid" ]] && ! kill -0 "$watch_pid" >/dev/null 2>&1; then
      break
    fi
    sleep 0.2
  done

  printf "\r%100s\r" ""
  return 0
}

usage() {
  cat <<'EOF'
利群主機 | LeiKwan Host
OpenGFW + Nmap 自查工具 / Self-Audit Tool

Usage:
  bash self-detect-opengfw.sh [options]

Options:
  --quick                 Fast scan (optimized version detection)
  --full                  Complete scan (optimized deep detection, not version-all)
  --skip-udp              Skip UDP scan
  --strict-rules          Generate stronger OpenGFW suggestions (block high risk)
  --public-ip <IP>        Set public IP manually (for TLS/SNI mismatch check)
  --no-probe              Disable active probes (default behavior)
  --probe-rounds <N>      Active probe rounds per endpoint (default: 1)
  --probe                 Enable active probes
  --run-opengfw-replay    Capture traffic and replay via OpenGFW pcap mode
  --capture-seconds <N>   Capture duration for replay (default: 45)
  --replay-with-probe     Run probes during capture window
  --capture-interface <I> Capture interface for replay (default: any)
  --capture-filter <BPF>  tcpdump filter (default: "tcp or udp")
  --opengfw-log-level <L> OpenGFW log level for replay (default: debug)
  --disable-report        Disable curl report upload
  --report-url <URL>      Override report endpoint (default: netreport URL)
  --download-opengfw      Enable OpenGFW auto-download (default on)
  --skip-download-opengfw Skip OpenGFW auto-download
  --opengfw-url <URL>     OpenGFW binary URL
  --opengfw-bin <PATH>    Local path for OpenGFW binary
  --trusted-ports <LIST>  Suppress known ports/ranges, ex: tcp:32000-32999,tcp:443
  --fw-family <TYPE>      Firewall family: both|ipv4|ipv6 (default both)
  --block <LIST>          Block ports now, format: tcp:443,udp:51820
  --unblock <LIST>        Unblock ports now, format: tcp:443,udp:51820
  --interactive-firewall  Prompt whether to block/unblock findings
  --firewall-only         Only apply block/unblock, skip scan/replay
  --daemon                Run continuously
  --interval-seconds <N>  Loop interval in daemon mode (default: 300)
  --install-systemd       Install and start a systemd service
  --service-name <NAME>   systemd service name (default: opengfw-self-detect)
  --menu                  Launch interactive menu UI
  --output-dir <DIR>      Output directory (default: script-dir/logs)
  -h, --help              Show help

Outputs:
  1) Markdown report
  2) OpenGFW rule suggestion file (YAML)
  3) Optional JSON upload by curl
  4) Optional OpenGFW replay hit summary
EOF
}

have_cmd() {
  command -v "$1" >/dev/null 2>&1
}

need_cmd() {
  local cmd="$1"
  if ! have_cmd "$cmd"; then
    log_err "Missing dependency: $cmd"
    return 1
  fi
  return 0
}

preflight_check_core() {
  local miss=()
  local c
  for c in ss nmap awk grep sed curl openssl; do
    if ! have_cmd "$c"; then
      miss+=("$c")
    fi
  done
  if [[ "${#miss[@]}" -gt 0 ]]; then
    log_err "缺少核心依賴 | Missing core dependencies: ${miss[*]}"
    return 1
  fi
  return 0
}

preflight_check_replay() {
  if [[ "$RUN_OPENGFW_REPLAY" != "1" ]]; then
    return 0
  fi
  local miss=()
  if ! have_cmd tcpdump; then
    miss+=("tcpdump")
  fi
  if [[ ! -x "$OPENGFW_BIN" ]]; then
    miss+=("OpenGFW binary executable")
  fi
  if [[ "${#miss[@]}" -gt 0 ]]; then
    log_err "進階回放模式依賴缺失 | Replay dependencies missing: ${miss[*]}"
    return 1
  fi
  return 0
}

parse_args() {
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --quick)
        SCAN_MODE="quick"
        shift
        ;;
      --full)
        SCAN_MODE="full"
        shift
        ;;
      --skip-udp)
        SKIP_UDP=1
        shift
        ;;
      --strict-rules)
        STRICT_RULES=1
        shift
        ;;
      --public-ip)
        PUBLIC_IP="${2:-}"
        if [[ -z "$PUBLIC_IP" ]]; then
          log_err "--public-ip requires a value"
          exit 1
        fi
        shift 2
        ;;
      --no-probe)
        PROBE_TRAFFIC=0
        shift
        ;;
      --probe)
        PROBE_TRAFFIC=1
        shift
        ;;
      --probe-rounds)
        PROBE_ROUNDS="${2:-}"
        if [[ ! "$PROBE_ROUNDS" =~ ^[0-9]+$ ]] || [[ "$PROBE_ROUNDS" -lt 1 ]] || [[ "$PROBE_ROUNDS" -gt 20 ]]; then
          log_err "--probe-rounds must be an integer between 1 and 20"
          exit 1
        fi
        shift 2
        ;;
      --run-opengfw-replay)
        RUN_OPENGFW_REPLAY=1
        shift
        ;;
      --capture-seconds)
        REPLAY_CAPTURE_SECONDS="${2:-}"
        if [[ ! "$REPLAY_CAPTURE_SECONDS" =~ ^[0-9]+$ ]] || [[ "$REPLAY_CAPTURE_SECONDS" -lt 5 ]] || [[ "$REPLAY_CAPTURE_SECONDS" -gt 3600 ]]; then
          log_err "--capture-seconds must be an integer between 5 and 3600"
          exit 1
        fi
        shift 2
        ;;
      --capture-interface)
        REPLAY_CAPTURE_INTERFACE="${2:-}"
        if [[ -z "$REPLAY_CAPTURE_INTERFACE" ]]; then
          log_err "--capture-interface requires a value"
          exit 1
        fi
        shift 2
        ;;
      --replay-with-probe)
        REPLAY_WITH_PROBE=1
        RUN_OPENGFW_REPLAY=1
        shift
        ;;
      --capture-filter)
        REPLAY_BPF_FILTER="${2:-}"
        if [[ -z "$REPLAY_BPF_FILTER" ]]; then
          log_err "--capture-filter requires a value"
          exit 1
        fi
        shift 2
        ;;
      --opengfw-log-level)
        OPENGFW_LOG_LEVEL="$(tr '[:upper:]' '[:lower:]' <<<"${2:-}")"
        if [[ -z "$OPENGFW_LOG_LEVEL" ]]; then
          log_err "--opengfw-log-level requires a value"
          exit 1
        fi
        shift 2
        ;;
      --disable-report)
        REPORT_ENABLED=0
        shift
        ;;
      --report-url)
        REPORT_URL="${2:-}"
        if [[ -z "$REPORT_URL" ]]; then
          log_err "--report-url requires a value"
          exit 1
        fi
        shift 2
        ;;
      --download-opengfw)
        DOWNLOAD_OPENGFW=1
        shift
        ;;
      --skip-download-opengfw)
        DOWNLOAD_OPENGFW=0
        shift
        ;;
      --opengfw-url)
        OPENGFW_URL="${2:-}"
        if [[ -z "$OPENGFW_URL" ]]; then
          log_err "--opengfw-url requires a value"
          exit 1
        fi
        shift 2
        ;;
      --opengfw-bin)
        OPENGFW_BIN="${2:-}"
        if [[ -z "$OPENGFW_BIN" ]]; then
          log_err "--opengfw-bin requires a value"
          exit 1
        fi
        shift 2
        ;;
      --trusted-ports)
        TRUSTED_PORTS="${2:-}"
        if [[ -z "$TRUSTED_PORTS" ]]; then
          log_err "--trusted-ports requires a value"
          exit 1
        fi
        shift 2
        ;;
      --fw-family)
        FIREWALL_IP_FAMILY="$(tr '[:upper:]' '[:lower:]' <<<"${2:-}")"
        if [[ "$FIREWALL_IP_FAMILY" != "both" && "$FIREWALL_IP_FAMILY" != "ipv4" && "$FIREWALL_IP_FAMILY" != "ipv6" ]]; then
          log_err "--fw-family must be both|ipv4|ipv6"
          exit 1
        fi
        shift 2
        ;;
      --block)
        BLOCK_LIST="${2:-}"
        if [[ -z "$BLOCK_LIST" ]]; then
          log_err "--block requires a value"
          exit 1
        fi
        shift 2
        ;;
      --unblock)
        UNBLOCK_LIST="${2:-}"
        if [[ -z "$UNBLOCK_LIST" ]]; then
          log_err "--unblock requires a value"
          exit 1
        fi
        shift 2
        ;;
      --interactive-firewall)
        INTERACTIVE_FIREWALL=1
        shift
        ;;
      --firewall-only)
        FIREWALL_ONLY=1
        shift
        ;;
      --daemon)
        DAEMON_MODE=1
        shift
        ;;
      --interval-seconds)
        DAEMON_INTERVAL_SECONDS="${2:-}"
        if [[ ! "$DAEMON_INTERVAL_SECONDS" =~ ^[0-9]+$ ]] || [[ "$DAEMON_INTERVAL_SECONDS" -lt 10 ]] || [[ "$DAEMON_INTERVAL_SECONDS" -gt 86400 ]]; then
          log_err "--interval-seconds must be an integer between 10 and 86400"
          exit 1
        fi
        shift 2
        ;;
      --install-systemd)
        INSTALL_SYSTEMD=1
        shift
        ;;
      --service-name)
        SYSTEMD_SERVICE_NAME="${2:-}"
        if [[ -z "$SYSTEMD_SERVICE_NAME" ]]; then
          log_err "--service-name requires a value"
          exit 1
        fi
        shift 2
        ;;
      --menu)
        MENU_MODE=1
        shift
        ;;
      --output-dir)
        OUTPUT_DIR="${2:-}"
        if [[ -z "$OUTPUT_DIR" ]]; then
          log_err "--output-dir requires a value"
          exit 1
        fi
        shift 2
        ;;
      -h|--help)
        usage
        exit 0
        ;;
      *)
        log_err "Unknown argument: $1"
        usage
        exit 1
        ;;
    esac
  done
}

csv_from_array() {
  local -n arr="$1"
  local out=""
  local item
  for item in "${arr[@]}"; do
    if [[ -z "$out" ]]; then
      out="$item"
    else
      out="$out,$item"
    fi
  done
  echo "$out"
}

extract_process_name_from_ss_line() {
  local line="$1"
  local proc
  proc="$(sed -n 's/.*users:(("\([^"]\+\)".*/\1/p' <<<"$line")"
  if [[ -z "$proc" ]]; then
    proc="-"
  fi
  echo "$proc"
}

build_process_map() {
  unset PROCESS_BY_ENDPOINT
  declare -gA PROCESS_BY_ENDPOINT=()

  local line local_addr port proc
  while IFS= read -r line; do
    local_addr="$(awk '{print $4}' <<<"$line")"
    port="$(sed -E 's/.*:([0-9]+)$/\1/' <<<"$local_addr")"
    if [[ ! "$port" =~ ^[0-9]+$ ]]; then
      continue
    fi
    proc="$(extract_process_name_from_ss_line "$line")"
    PROCESS_BY_ENDPOINT["tcp:${port}"]="$proc"
  done < <(ss -H -ltnp 2>/dev/null || true)

  while IFS= read -r line; do
    local_addr="$(awk '{print $5}' <<<"$line")"
    port="$(sed -E 's/.*:([0-9]+)$/\1/' <<<"$local_addr")"
    if [[ ! "$port" =~ ^[0-9]+$ ]]; then
      continue
    fi
    proc="$(extract_process_name_from_ss_line "$line")"
    PROCESS_BY_ENDPOINT["udp:${port}"]="$proc"
  done < <(ss -H -lunp 2>/dev/null || true)
}

endpoint_in_trusted_list() {
  local proto="$1"
  local port="$2"
  if [[ -z "$TRUSTED_PORTS" ]]; then
    return 1
  fi

  local token clean t_proto spec start end
  local -a tokens=()
  IFS=',' read -r -a tokens <<<"$TRUSTED_PORTS"

  for token in "${tokens[@]}"; do
    clean="$(echo "$token" | tr -d '[:space:]')"
    [[ -z "$clean" ]] && continue

    if [[ "$clean" == *":"* ]]; then
      t_proto="${clean%%:*}"
      spec="${clean##*:}"
    else
      t_proto="any"
      spec="$clean"
    fi
    t_proto="$(tr '[:upper:]' '[:lower:]' <<<"$t_proto")"

    if [[ "$t_proto" != "any" && "$t_proto" != "$proto" ]]; then
      continue
    fi

    if [[ "$spec" == *"-"* ]]; then
      start="${spec%%-*}"
      end="${spec##*-}"
      if [[ "$start" =~ ^[0-9]+$ && "$end" =~ ^[0-9]+$ ]] && (( port >= start && port <= end )); then
        return 0
      fi
    else
      if [[ "$spec" =~ ^[0-9]+$ ]] && (( port == spec )); then
        return 0
      fi
    fi
  done
  return 1
}

collect_listening_ports() {
  log_ui "1) Collect listening ports"
  build_process_map

  mapfile -t TCP_PORTS < <(
    ss -H -ltn 2>/dev/null \
      | awk '{print $4}' \
      | sed -E 's/.*:([0-9]+)$/\1/' \
      | grep -E '^[0-9]+$' \
      | sort -nu
  )

  if [[ "$SKIP_UDP" == "0" ]]; then
    mapfile -t UDP_PORTS < <(
      ss -H -lun 2>/dev/null \
        | awk '{print $5}' \
        | sed -E 's/.*:([0-9]+)$/\1/' \
        | grep -E '^[0-9]+$' \
        | sort -nu
    )
  fi

  if [[ "${#TCP_PORTS[@]}" -eq 0 && "${#UDP_PORTS[@]}" -eq 0 ]]; then
    log_warn "No local listening ports found. Continue with passive steps."
    return 1
  fi

  if [[ "${#TCP_PORTS[@]}" -gt 0 ]]; then
    log_info "TCP ports: $(csv_from_array TCP_PORTS)"
  else
    log_info "TCP ports: none"
  fi

  if [[ "$SKIP_UDP" == "1" ]]; then
    log_info "UDP scan: skipped"
  elif [[ "${#UDP_PORTS[@]}" -gt 0 ]]; then
    log_info "UDP ports: $(csv_from_array UDP_PORTS)"
  else
    log_info "UDP ports: none"
  fi
  return 0
}

run_nmap_scan() {
  local proto="$1"
  local ports_csv="$2"
  local outfile="$3"
  local -a common_args
  local -a service_args

  if [[ "$SCAN_MODE" == "full" ]]; then
    service_args=(--version-intensity 3)
    common_args=(-Pn -n -T4 --max-retries 1 --initial-rtt-timeout 100ms --max-rtt-timeout 1000ms --host-timeout 180s)
  else
    service_args=(--version-light)
    common_args=(-Pn -n -T4 --max-retries 1 --initial-rtt-timeout 100ms --max-rtt-timeout 500ms --host-timeout 20s)
  fi

  if [[ "$proto" == "tcp" ]]; then
    log_info "Running Nmap TCP scan... please wait"
    run_command_with_spinner "Scanning TCP ports" "$outfile" nmap "${common_args[@]}" -sV "${service_args[@]}" --reason -p "$ports_csv" 127.0.0.1
    return $?
  fi

  if [[ "$proto" == "udp" ]]; then
    if [[ "$(id -u)" -ne 0 ]]; then
      WARNINGS+=("UDP detection is less reliable without root privileges.")
    fi
    log_info "Running Nmap UDP scan... please wait"
    run_command_with_spinner "Scanning UDP ports" "$outfile" nmap "${common_args[@]}" -sU -sV "${service_args[@]}" --reason -p "$ports_csv" 127.0.0.1
    return $?
  fi

  return 1
}

download_opengfw_binary_if_needed() {
  if [[ -f "$OPENGFW_BIN" ]]; then
    if have_cmd chmod; then
      chmod +x "$OPENGFW_BIN" >/dev/null 2>&1 || true
    fi
    log_info "OpenGFW binary already present: $OPENGFW_BIN"
    return
  fi

  if [[ "$DOWNLOAD_OPENGFW" != "1" ]]; then
    return
  fi

  log_ui "0) Download OpenGFW binary"
  local dir
  dir="$(dirname "$OPENGFW_BIN")"
  mkdir -p "$dir"

  if have_cmd curl; then
    if ! curl -fsSL --connect-timeout 5 --max-time 120 -o "$OPENGFW_BIN" "$OPENGFW_URL"; then
      log_err "Failed to download OpenGFW from: $OPENGFW_URL"
      WARNINGS+=("OpenGFW download failed from ${OPENGFW_URL}.")
      return
    fi
  elif have_cmd wget; then
    if ! wget -q -O "$OPENGFW_BIN" "$OPENGFW_URL"; then
      log_err "Failed to download OpenGFW from: $OPENGFW_URL"
      WARNINGS+=("OpenGFW download failed from ${OPENGFW_URL}.")
      return
    fi
  else
    log_warn "No curl/wget found; cannot download OpenGFW automatically."
    WARNINGS+=("No curl/wget in environment for OpenGFW download.")
    return
  fi

  if have_cmd chmod; then
    chmod +x "$OPENGFW_BIN" || WARNINGS+=("chmod +x failed for ${OPENGFW_BIN}.")
  else
    WARNINGS+=("chmod command not found; mark executable manually: chmod +x ${OPENGFW_BIN}")
  fi

  log_info "OpenGFW binary ready: $OPENGFW_BIN"
}

append_endpoints_from_nmap() {
  local nmap_file="$1"
  local line port_proto port proto state service version proc key idx

  while IFS= read -r line; do
    port_proto=$(awk '{print $1}' <<<"$line")
    state=$(awk '{print $2}' <<<"$line")
    if [[ ! "$state" =~ ^open ]]; then
      continue
    fi

    port="${port_proto%/*}"
    proto="${port_proto#*/}"
    service=$(awk '{print $3}' <<<"$line")
    version=$(cut -d' ' -f4- <<<"$line" | sed -E 's/^[[:space:]]+//')
    proc="${PROCESS_BY_ENDPOINT["${proto}:${port}"]:-"-"}"
    key="${proto}:${port}"

    if [[ -n "${ENDPOINT_INDEX_BY_KEY[$key]:-}" ]]; then
      idx="${ENDPOINT_INDEX_BY_KEY[$key]}"
      ENDPOINTS[$idx]="${port}"$'\t'"${proto}"$'\t'"${service}"$'\t'"${version}"$'\t'"${proc}"
    else
      ENDPOINTS+=("${port}"$'\t'"${proto}"$'\t'"${service}"$'\t'"${version}"$'\t'"${proc}")
      ENDPOINT_INDEX_BY_KEY["$key"]=$((${#ENDPOINTS[@]} - 1))
    fi
  done < <(grep -E '^[0-9]+/(tcp|udp)[[:space:]]+' "$nmap_file" || true)
}

detect_application_protocols() {
  if [[ "${#ENDPOINTS[@]}" -eq 0 ]]; then
    return
  fi

  log_ui "應用協議探測 | Application Protocol Probe"

  local ep port proto service version proc key http_code https_code
  for ep in "${ENDPOINTS[@]}"; do
    IFS=$'\t' read -r port proto service version proc <<<"$ep"
    if [[ "$proto" != "tcp" ]]; then
      continue
    fi
    key="${proto}:${port}"

    http_code="$(curl -sS -m 4 -o /dev/null -w "%{http_code}" "http://127.0.0.1:${port}" 2>/dev/null || echo "000")"
    if [[ "$http_code" =~ ^[1-5][0-9][0-9]$ ]]; then
      APP_PROTO_BY_ENDPOINT["$key"]="http"
      continue
    fi

    https_code="$(curl -k -sS -m 4 -o /dev/null -w "%{http_code}" "https://127.0.0.1:${port}" 2>/dev/null || echo "000")"
    if [[ "$https_code" =~ ^[1-5][0-9][0-9]$ ]]; then
      APP_PROTO_BY_ENDPOINT["$key"]="https"
      continue
    fi

    if echo | timeout 4 openssl s_client -brief -connect "127.0.0.1:${port}" >/dev/null 2>&1; then
      APP_PROTO_BY_ENDPOINT["$key"]="tls"
    fi
  done
}

seed_endpoints_from_listening_ports() {
  ENDPOINTS=()
  unset ENDPOINT_INDEX_BY_KEY
  declare -gA ENDPOINT_INDEX_BY_KEY=()

  local port proc key
  for port in "${TCP_PORTS[@]}"; do
    key="tcp:${port}"
    proc="${PROCESS_BY_ENDPOINT[$key]:-"-"}"
    ENDPOINTS+=("${port}"$'\t'"tcp"$'\t'"unknown"$'\t'"listener-from-ss"$'\t'"${proc}")
    ENDPOINT_INDEX_BY_KEY["$key"]=$((${#ENDPOINTS[@]} - 1))
  done

  for port in "${UDP_PORTS[@]}"; do
    key="udp:${port}"
    proc="${PROCESS_BY_ENDPOINT[$key]:-"-"}"
    ENDPOINTS+=("${port}"$'\t'"udp"$'\t'"unknown"$'\t'"listener-from-ss"$'\t'"${proc}")
    ENDPOINT_INDEX_BY_KEY["$key"]=$((${#ENDPOINTS[@]} - 1))
  done
}

apply_application_protocol_labels() {
  if [[ "${#ENDPOINTS[@]}" -eq 0 ]]; then
    return
  fi

  local updated=()
  local ep port proto service version proc key app_proto
  for ep in "${ENDPOINTS[@]}"; do
    IFS=$'\t' read -r port proto service version proc <<<"$ep"
    key="${proto}:${port}"
    app_proto="${APP_PROTO_BY_ENDPOINT[$key]:-}"
    case "$app_proto" in
      http)
        service="http"
        version="application-probe http"
        ;;
      https)
        service="https"
        version="application-probe https"
        ;;
      tls)
        if [[ "$service" == "unknown" || "$service" == "tcpwrapped" || "$service" == "ssl?" || "$service" == "https?" ]]; then
          service="tls"
          version="application-probe tls"
        fi
        ;;
    esac
    updated+=("${port}"$'\t'"${proto}"$'\t'"${service}"$'\t'"${version}"$'\t'"${proc}")
  done

  ENDPOINTS=("${updated[@]}")
}

trigger_active_probes() {
  if [[ "$PROBE_TRAFFIC" != "1" ]]; then
    return
  fi
  if [[ "${#ENDPOINTS[@]}" -eq 0 ]]; then
    return
  fi

  log_ui "1.5) Trigger active handshake probes"
  log_info "Probe rounds per endpoint: $PROBE_ROUNDS"

  local round ep port proto service version proc
  for ((round=1; round<=PROBE_ROUNDS; round++)); do
    for ep in "${ENDPOINTS[@]}"; do
      IFS=$'\t' read -r port proto service version proc <<<"$ep"
      if [[ "$proto" == "tcp" ]]; then
        timeout 2 bash -c "echo >/dev/tcp/127.0.0.1/${port}" >/dev/null 2>&1 || true
        if have_cmd curl; then
          curl -m 2 -k -L -s "http://127.0.0.1:${port}" >/dev/null 2>&1 || true
          curl -m 2 -k -L -s "https://127.0.0.1:${port}" >/dev/null 2>&1 || true
        fi
        if have_cmd openssl; then
          echo | timeout 3 openssl s_client -connect "127.0.0.1:${port}" -servername localhost >/dev/null 2>&1 || true
        fi
      elif [[ "$proto" == "udp" ]]; then
        timeout 1 bash -c "echo ping >/dev/udp/127.0.0.1/${port}" >/dev/null 2>&1 || true
      fi
    done
  done
}

reset_runtime_state() {
  TCP_PORTS=()
  UDP_PORTS=()
  ENDPOINTS=()
  FINDINGS=()
  WARNINGS=()
  JUDGEMENT_ROWS=()
  SELECTED_RESULT_ROWS=()
  unset RULE_DEDUP
  declare -gA RULE_DEDUP=()
  unset PROCESS_BY_ENDPOINT
  declare -gA PROCESS_BY_ENDPOINT=()
  unset REPLAY_TYPES_BY_ENDPOINT
  declare -gA REPLAY_TYPES_BY_ENDPOINT=()
  unset REPLAY_HITS_BY_ENDPOINT
  declare -gA REPLAY_HITS_BY_ENDPOINT=()
  unset APP_PROTO_BY_ENDPOINT
  declare -gA APP_PROTO_BY_ENDPOINT=()
  unset ENDPOINT_INDEX_BY_KEY
  declare -gA ENDPOINT_INDEX_BY_KEY=()
  REPLAY_HITS=()
  RULES_FILE=""
  REPORT_FILE=""
  REPLAY_LOG_FILE=""
  REPLAY_PCAP_FILE=""
  REPLAY_LOG_CLEAN_FILE=""
  OVERVIEW_LATEST_FILE=""
  OVERVIEW_HISTORY_FILE=""
}

parse_endpoint_token() {
  local token="$1"
  token="$(echo "$token" | tr -d '[:space:]')"
  local proto="${token%%:*}"
  local port="${token##*:}"

  if [[ "$proto" == "$token" ]] || [[ -z "$port" ]]; then
    return 1
  fi
  proto="$(tr '[:upper:]' '[:lower:]' <<<"$proto")"
  if [[ "$proto" != "tcp" && "$proto" != "udp" ]]; then
    return 1
  fi
  if [[ ! "$port" =~ ^[0-9]+$ ]] || (( port < 1 || port > 65535 )); then
    return 1
  fi
  echo "${proto}:${port}"
  return 0
}

apply_iptables_block() {
  local proto="$1"
  local port="$2"
  local family="${3:-both}"

  if [[ "$family" != "ipv6" ]] && ! have_cmd iptables; then
    WARNINGS+=("iptables not found; cannot block ${proto}:${port}.")
    return 1
  fi
  if [[ "$family" == "both" || "$family" == "ipv4" ]]; then
    if ! iptables -C INPUT -p "$proto" --dport "$port" -j REJECT >/dev/null 2>&1; then
      iptables -I INPUT 1 -p "$proto" --dport "$port" -j REJECT >/dev/null 2>&1 || return 1
    fi
  fi
  if [[ "$family" == "both" || "$family" == "ipv6" ]]; then
    if ! have_cmd ip6tables; then
      WARNINGS+=("ip6tables not found; ipv6 block skipped for ${proto}:${port}.")
    elif ! ip6tables -C INPUT -p "$proto" --dport "$port" -j REJECT >/dev/null 2>&1; then
      ip6tables -I INPUT 1 -p "$proto" --dport "$port" -j REJECT >/dev/null 2>&1 || true
    fi
  fi
  return 0
}

apply_iptables_unblock() {
  local proto="$1"
  local port="$2"
  local family="${3:-both}"

  if [[ "$family" != "ipv6" ]] && ! have_cmd iptables; then
    WARNINGS+=("iptables not found; cannot unblock ${proto}:${port}.")
    return 1
  fi
  if [[ "$family" == "both" || "$family" == "ipv4" ]]; then
    while iptables -C INPUT -p "$proto" --dport "$port" -j REJECT >/dev/null 2>&1; do
      iptables -D INPUT -p "$proto" --dport "$port" -j REJECT >/dev/null 2>&1 || break
    done
  fi
  if [[ "$family" == "both" || "$family" == "ipv6" ]]; then
    if have_cmd ip6tables; then
      while ip6tables -C INPUT -p "$proto" --dport "$port" -j REJECT >/dev/null 2>&1; do
        ip6tables -D INPUT -p "$proto" --dport "$port" -j REJECT >/dev/null 2>&1 || break
      done
    else
      WARNINGS+=("ip6tables not found; ipv6 unblock skipped for ${proto}:${port}.")
    fi
  fi
  return 0
}

iptables_cmd_for_family() {
  local family="$1"
  if [[ "$family" == "ipv6" ]]; then
    echo "ip6tables"
  else
    echo "iptables"
  fi
}

chain_name_for_port() {
  local family="$1"
  local proto="$2"
  local port="$3"
  local fam_prefix="4"
  local proto_prefix="T"
  if [[ "$family" == "ipv6" ]]; then
    fam_prefix="6"
  fi
  if [[ "$proto" == "udp" ]]; then
    proto_prefix="U"
  fi
  echo "LKH${fam_prefix}${proto_prefix}${port}"
}

entry_matches_family() {
  local entry="$1"
  local family="$2"
  if [[ "$family" == "ipv6" ]]; then
    [[ "$entry" == *:* ]]
    return
  fi
  [[ "$entry" != *:* ]]
}

remove_port_whitelist_rules() {
  local proto="$1"
  local port="$2"
  local family="$3"
  local cmd chain
  cmd="$(iptables_cmd_for_family "$family")"
  if ! have_cmd "$cmd"; then
    return 0
  fi
  chain="$(chain_name_for_port "$family" "$proto" "$port")"

  while "$cmd" -C INPUT -p "$proto" --dport "$port" -j "$chain" >/dev/null 2>&1; do
    "$cmd" -D INPUT -p "$proto" --dport "$port" -j "$chain" >/dev/null 2>&1 || break
  done
  "$cmd" -F "$chain" >/dev/null 2>&1 || true
  "$cmd" -X "$chain" >/dev/null 2>&1 || true
}

apply_port_whitelist_rules() {
  local proto="$1"
  local port="$2"
  local family="$3"
  local entries_csv="$4"
  local cmd chain count=0
  local -a entries=()
  local entry clean

  cmd="$(iptables_cmd_for_family "$family")"
  if ! have_cmd "$cmd"; then
    WARNINGS+=("${cmd} not found; cannot apply whitelist for ${proto}:${port}.")
    return 1
  fi

  chain="$(chain_name_for_port "$family" "$proto" "$port")"
  "$cmd" -N "$chain" >/dev/null 2>&1 || true
  "$cmd" -F "$chain" >/dev/null 2>&1 || true
  if ! "$cmd" -C INPUT -p "$proto" --dport "$port" -j "$chain" >/dev/null 2>&1; then
    "$cmd" -I INPUT 1 -p "$proto" --dport "$port" -j "$chain" >/dev/null 2>&1 || return 1
  fi

  IFS=',' read -r -a entries <<<"$entries_csv"
  for entry in "${entries[@]}"; do
    clean="$(echo "$entry" | tr -d '[:space:]')"
    [[ -z "$clean" ]] && continue
    if ! entry_matches_family "$clean" "$family"; then
      continue
    fi
    "$cmd" -A "$chain" -s "$clean" -j ACCEPT >/dev/null 2>&1 || return 1
    count=$((count + 1))
  done

  if (( count == 0 )); then
    remove_port_whitelist_rules "$proto" "$port" "$family"
    WARNINGS+=("No ${family} whitelist entries matched for ${proto}:${port}.")
    return 1
  fi

  "$cmd" -A "$chain" -j REJECT >/dev/null 2>&1 || return 1
  return 0
}

apply_block_unblock_lists() {
  local need_fw=0
  if [[ -n "$BLOCK_LIST" || -n "$UNBLOCK_LIST" || "$INTERACTIVE_FIREWALL" == "1" ]]; then
    need_fw=1
  fi
  if [[ "$need_fw" == "0" ]]; then
    return
  fi
  if [[ "$(id -u)" -ne 0 ]]; then
    WARNINGS+=("Firewall operations require root; block/unblock skipped.")
    return
  fi

  local token parsed proto port
  local -a _blocks=()
  local -a _unblocks=()

  if [[ -n "$BLOCK_LIST" ]]; then
    IFS=',' read -r -a _blocks <<<"$BLOCK_LIST"
    for token in "${_blocks[@]}"; do
      parsed="$(parse_endpoint_token "$token" || true)"
      if [[ -z "$parsed" ]]; then
        WARNINGS+=("Invalid --block token: ${token}")
        continue
      fi
      proto="${parsed%%:*}"
      port="${parsed##*:}"
      if apply_iptables_block "$proto" "$port" "$FIREWALL_IP_FAMILY"; then
        log_info "Blocked ${proto}:${port} (family=${FIREWALL_IP_FAMILY})"
      else
        WARNINGS+=("Failed to block ${proto}:${port}.")
      fi
    done
  fi

  if [[ -n "$UNBLOCK_LIST" ]]; then
    IFS=',' read -r -a _unblocks <<<"$UNBLOCK_LIST"
    for token in "${_unblocks[@]}"; do
      parsed="$(parse_endpoint_token "$token" || true)"
      if [[ -z "$parsed" ]]; then
        WARNINGS+=("Invalid --unblock token: ${token}")
        continue
      fi
      proto="${parsed%%:*}"
      port="${parsed##*:}"
      if apply_iptables_unblock "$proto" "$port" "$FIREWALL_IP_FAMILY"; then
        log_info "Unblocked ${proto}:${port} (family=${FIREWALL_IP_FAMILY})"
      else
        WARNINGS+=("Failed to unblock ${proto}:${port}.")
      fi
    done
  fi
}

interactive_firewall_actions() {
  if [[ "$INTERACTIVE_FIREWALL" != "1" ]]; then
    return
  fi
  if [[ "${#FINDINGS[@]}" -eq 0 ]]; then
    return
  fi
  if [[ "$(id -u)" -ne 0 ]]; then
    WARNINGS+=("Interactive firewall actions need root; skipped.")
    return
  fi
  if [[ ! -t 0 ]]; then
    WARNINGS+=("Interactive firewall mode requires TTY stdin; skipped.")
    return
  fi

  log_ui "5) Interactive firewall action"
  log_info "Choose per finding: [b]lock / [s]kip / [u]nblock"

  local finding sev port proto service version proc tags reasons choice
  for finding in "${FINDINGS[@]}"; do
    IFS=$'\t' read -r sev port proto service version proc tags reasons <<<"$finding"
    printf "%s/%s %s (proc=%s) severity=%s\n" "$port" "$proto" "$service" "$proc" "$(severity_text "$sev")"
    read -r -p "Action [b/s/u] (default s): " choice
    choice="${choice:-s}"
    case "$choice" in
      b|B)
        apply_iptables_block "$proto" "$port" "$FIREWALL_IP_FAMILY" && log_info "Blocked ${proto}:${port} (family=${FIREWALL_IP_FAMILY})" || WARNINGS+=("Failed to block ${proto}:${port}")
        ;;
      u|U)
        apply_iptables_unblock "$proto" "$port" "$FIREWALL_IP_FAMILY" && log_info "Unblocked ${proto}:${port} (family=${FIREWALL_IP_FAMILY})" || WARNINGS+=("Failed to unblock ${proto}:${port}")
        ;;
      *)
        ;;
    esac
  done
}

generate_opengfw_replay_config() {
  local config_file="$1"
  cat >"$config_file" <<'EOF'
io:
  queueSize: 1024
  queueNum: 100
  table: opengfw
  connMarkAccept: 1001
  connMarkDrop: 1002
  local: true
  rst: false

workers:
  count: 2
  queueSize: 64
  tcpMaxBufferedPagesTotal: 65536
  tcpMaxBufferedPagesPerConn: 16
  tcpTimeout: 10m
  udpMaxStreams: 4096

replay:
  realtime: false
EOF
}

summarize_opengfw_hits() {
  local replay_log="$1"
  local rule_name hit_count
  local any_hit=0
  local scan_log="$replay_log"

  REPLAY_LOG_CLEAN_FILE="${replay_log}.clean"
  sed -E 's/\x1b\[[0-9;]*m//g' "$replay_log" >"$REPLAY_LOG_CLEAN_FILE" 2>/dev/null || cp "$replay_log" "$REPLAY_LOG_CLEAN_FILE"
  scan_log="$REPLAY_LOG_CLEAN_FILE"

  mapfile -t _rule_names < <(grep -E '^- name:' "$RULES_FILE" | sed -E 's/^- name:[[:space:]]*//')
  for rule_name in "${_rule_names[@]}"; do
    hit_count="$(grep -Foc "$rule_name" "$scan_log" 2>/dev/null || echo "0")"
    if [[ "$hit_count" =~ ^[0-9]+$ ]] && (( hit_count > 0 )); then
      REPLAY_HITS+=("${rule_name}"$'\t'"${hit_count}")
      any_hit=1

      local analyzer port proto key old_types old_hits
      if [[ "$rule_name" =~ ^audit-(fet|socks|trojan|wireguard|openvpn|sni-mismatch)-port-([0-9]+)$ ]]; then
        analyzer="${BASH_REMATCH[1]}"
        port="${BASH_REMATCH[2]}"
        for key in "${!PROCESS_BY_ENDPOINT[@]}"; do
          proto="${key%%:*}"
          if [[ "${key##*:}" == "$port" ]]; then
            old_types="${REPLAY_TYPES_BY_ENDPOINT[$key]:-}"
            REPLAY_TYPES_BY_ENDPOINT["$key"]="$(csv_add_unique "$old_types" "$analyzer")"
            old_hits="${REPLAY_HITS_BY_ENDPOINT[$key]:-0}"
            REPLAY_HITS_BY_ENDPOINT["$key"]=$((old_hits + hit_count))
          fi
        done
      elif [[ "$rule_name" =~ ^audit-port-(tcp|udp)-([0-9]+)-(fet|socks|trojan|wireguard|openvpn|sni-mismatch)$ ]]; then
        proto="${BASH_REMATCH[1]}"
        port="${BASH_REMATCH[2]}"
        analyzer="${BASH_REMATCH[3]}"
        key="${proto}:${port}"
        old_types="${REPLAY_TYPES_BY_ENDPOINT[$key]:-}"
        REPLAY_TYPES_BY_ENDPOINT["$key"]="$(csv_add_unique "$old_types" "$analyzer")"
        old_hits="${REPLAY_HITS_BY_ENDPOINT[$key]:-0}"
        REPLAY_HITS_BY_ENDPOINT["$key"]=$((old_hits + hit_count))
      fi
    fi
  done

  if [[ "$any_hit" == "0" ]]; then
    log_info "OpenGFW 回放摘要：此輪無命中 | OpenGFW replay summary: no rule hits."
    if ! grep -Eq 'audit-|rule|matched|match' "$scan_log"; then
      WARNINGS+=("Replay log has no rule-level entries. Check OPENGFW_LOG_LEVEL and pcap link-type compatibility.")
    fi
  else
    log_ui "OpenGFW 回放命中摘要 | OpenGFW Replay Hit Summary"
    local item name count
    for item in "${REPLAY_HITS[@]}"; do
      IFS=$'\t' read -r name count <<<"$item"
      printf "  - %s : %s\n" "$name" "$count"
    done
  fi
}

run_opengfw_replay() {
  if [[ "$RUN_OPENGFW_REPLAY" != "1" ]]; then
    return
  fi

  if ! have_cmd tcpdump; then
    WARNINGS+=("tcpdump not found; OpenGFW replay skipped.")
    return
  fi
  if [[ ! -x "$OPENGFW_BIN" ]]; then
    WARNINGS+=("OpenGFW binary missing or not executable: ${OPENGFW_BIN}")
    return
  fi
  if [[ "$(id -u)" -ne 0 ]]; then
    WARNINGS+=("OpenGFW replay capture needs root (tcpdump); skipped.")
    return
  fi

  mkdir -p "$OUTPUT_DIR"
  local ts config_file capture_pid probe_pid
  ts="$(date +%Y%m%d-%H%M%S)"
  REPLAY_PCAP_FILE="${OUTPUT_DIR}/opengfw-capture-${ts}.pcap"
  REPLAY_LOG_FILE="${OUTPUT_DIR}/opengfw-replay-${ts}.log"
  config_file="${OUTPUT_DIR}/opengfw-replay-config-${ts}.yaml"

  generate_opengfw_replay_config "$config_file"

  log_ui "OpenGFW 回放 | OpenGFW Replay"
  log_info "正在抓包 ${REPLAY_CAPTURE_SECONDS}s（介面 ${REPLAY_CAPTURE_INTERFACE}）| Capturing traffic..."
  if [[ "$REPLAY_CAPTURE_INTERFACE" == "any" ]]; then
    # Force legacy LINUX_SLL (113) for broader parser compatibility.
    tcpdump -i any -y LINUX_SLL -nn -s 0 -w "$REPLAY_PCAP_FILE" "$REPLAY_BPF_FILTER" >/dev/null 2>&1 &
  else
    tcpdump -i "$REPLAY_CAPTURE_INTERFACE" -nn -s 0 -w "$REPLAY_PCAP_FILE" "$REPLAY_BPF_FILTER" >/dev/null 2>&1 &
  fi
  capture_pid=$!
  sleep 1
  if [[ "$REPLAY_WITH_PROBE" == "1" ]]; then
    log_info "Active probe traffic is enabled during capture."
    (
      PROBE_TRAFFIC=1
      trigger_active_probes >/dev/null 2>&1 || true
    ) &
    probe_pid=$!
  fi

  show_timed_spinner "Capturing traffic" "$REPLAY_CAPTURE_SECONDS" "$capture_pid"
  kill "$capture_pid" >/dev/null 2>&1 || true
  wait "$capture_pid" >/dev/null 2>&1 || true
  if [[ -n "${probe_pid:-}" ]]; then
    wait "$probe_pid" >/dev/null 2>&1 || true
  fi

  if [[ ! -s "$REPLAY_PCAP_FILE" ]]; then
    WARNINGS+=("Capture file empty; OpenGFW replay skipped.")
    return
  fi

  local link_type_line
  link_type_line="$(tcpdump -nr "$REPLAY_PCAP_FILE" -c 1 2>&1 | head -n1 || true)"
  log_info "pcap 資訊 | pcap info: ${link_type_line}"
  if grep -q "LINUX_SLL2" <<<"$link_type_line"; then
    WARNINGS+=("pcap link-type is LINUX_SLL2, which may reduce replay parser compatibility.")
  fi

  log_info "使用 OpenGFW 回放 pcap（log level=${OPENGFW_LOG_LEVEL}）| Replaying pcap with OpenGFW..."
  if ! run_command_with_spinner "Replaying pcap with OpenGFW" "$REPLAY_LOG_FILE" env OPENGFW_LOG_LEVEL="$OPENGFW_LOG_LEVEL" "$OPENGFW_BIN" -p "$REPLAY_PCAP_FILE" -c "$config_file" "$RULES_FILE"; then
    WARNINGS+=("OpenGFW replay failed. Check ${REPLAY_LOG_FILE}.")
    return
  fi

  summarize_opengfw_hits "$REPLAY_LOG_FILE"
}

install_systemd_service() {
  if [[ "$INSTALL_SYSTEMD" != "1" ]]; then
    return
  fi
  if [[ "$(id -u)" -ne 0 ]]; then
    log_err "--install-systemd requires root."
    exit 1
  fi
  if ! have_cmd systemctl; then
    log_err "systemctl not found; cannot install service."
    exit 1
  fi

  local unit_file="/etc/systemd/system/${SYSTEMD_SERVICE_NAME}.service"
  local script_abs
  local script_dir
  script_abs="$(readlink -f "$0" 2>/dev/null || echo "$0")"
  script_dir="$(cd "$(dirname "$script_abs")" && pwd)"

  cat >"$unit_file" <<EOF
[Unit]
Description=OpenGFW self-detect continuous monitor
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
WorkingDirectory=${script_dir}
ExecStart=/bin/bash "${script_abs}" --daemon --interval-seconds ${DAEMON_INTERVAL_SECONDS} --run-opengfw-replay --capture-seconds ${REPLAY_CAPTURE_SECONDS} --no-probe
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

  systemctl daemon-reload
  systemctl enable --now "${SYSTEMD_SERVICE_NAME}.service"
  log_info "Installed and started: ${SYSTEMD_SERVICE_NAME}.service"
  return 0
}

detect_public_ip_if_needed() {
  if [[ -n "$PUBLIC_IP" ]]; then
    return
  fi

  if have_cmd curl; then
    PUBLIC_IP="$(curl -4 -fsS --max-time 4 https://api.ipify.org 2>/dev/null || true)"
  fi

  if [[ -z "$PUBLIC_IP" ]] && have_cmd dig; then
    PUBLIC_IP="$(dig +short myip.opendns.com @resolver1.opendns.com 2>/dev/null | head -n1)"
  fi

  if [[ -z "$PUBLIC_IP" ]]; then
    WARNINGS+=("Could not detect public IP, TLS/SNI mismatch checks were skipped.")
  else
    log_info "Public IP detected: $PUBLIC_IP"
  fi
}

tls_sni_mismatch_check() {
  local port="$1"
  local cert_info dns_name resolved matched

  if [[ -z "$PUBLIC_IP" ]]; then
    return 1
  fi
  if ! have_cmd openssl || ! have_cmd dig || ! have_cmd timeout; then
    return 1
  fi

  cert_info="$(
    echo | timeout 5 openssl s_client -connect "127.0.0.1:${port}" -servername localhost 2>/dev/null \
      | openssl x509 -noout -ext subjectAltName -subject 2>/dev/null || true
  )"

  if [[ -z "$cert_info" ]]; then
    return 1
  fi

  matched=0
  while IFS= read -r dns_name; do
    [[ -z "$dns_name" ]] && continue
    resolved="$(dig +short A "$dns_name" 2>/dev/null; dig +short AAAA "$dns_name" 2>/dev/null)"
    if grep -Fxq "$PUBLIC_IP" <<<"$resolved"; then
      matched=1
      break
    fi
  done < <(grep -oE 'DNS:[^, ]+' <<<"$cert_info" | sed 's/^DNS://')

  if [[ "$matched" == "0" ]]; then
    return 0
  fi
  return 1
}

set_severity_if_higher() {
  local -n sev_ref="$1"
  local target="$2"
  if (( target > sev_ref )); then
    sev_ref="$target"
  fi
}

push_once() {
  local -n arr_ref="$1"
  local value="$2"
  local item
  for item in "${arr_ref[@]}"; do
    if [[ "$item" == "$value" ]]; then
      return
    fi
  done
  arr_ref+=("$value")
}

classify_endpoints() {
  log_ui "2) Classify risk using OpenGFW analyzer logic"
  detect_public_ip_if_needed

  local ep port proto service version proc lower lower_proc is_trusted app_proto key
  local severity reasons tags reason_text tag_text

  for ep in "${ENDPOINTS[@]}"; do
    IFS=$'\t' read -r port proto service version proc <<<"$ep"
    key="${proto}:${port}"
    lower="$(tr '[:upper:]' '[:lower:]' <<<"${service} ${version}")"
    lower_proc="$(tr '[:upper:]' '[:lower:]' <<<"${proc}")"
    app_proto="${APP_PROTO_BY_ENDPOINT[$key]:-}"
    severity=1
    reasons=()
    tags=()
    is_trusted=0

    if endpoint_in_trusted_list "$proto" "$port"; then
      is_trusted=1
      push_once tags "trusted"
      push_once reasons "Trusted port."
    fi

    if [[ "$lower_proc" =~ (ssserver|shadowsocks|xray|sing-box|singbox|v2ray|hysteria|tuic|brook) ]]; then
      set_severity_if_higher severity 4
      push_once tags "fet"
      push_once reasons "Proxy stack process."
    fi
    if [[ "$lower_proc" =~ (gost) ]]; then
      push_once tags "proxy-stack"
      push_once reasons "Forwarder process."
    fi

    case "$app_proto" in
      http)
        push_once tags "http-app"
        push_once reasons "HTTP service."
        if [[ ! "$port" =~ ^(80|8080|8000|8008|8888)$ ]]; then
          set_severity_if_higher severity 4
        fi
        ;;
      https)
        push_once tags "https-app"
        push_once reasons "HTTPS service."
        if [[ ! "$port" =~ ^(443|8443)$ ]]; then
          set_severity_if_higher severity 4
        fi
        ;;
      tls)
        push_once tags "tls-app"
        push_once reasons "TLS/SSL service."
        if [[ ! "$port" =~ ^(443|8443)$ ]]; then
          set_severity_if_higher severity 4
        fi
        ;;
    esac

    if [[ "$lower" =~ (trojan) ]]; then
      set_severity_if_higher severity 5
      push_once tags "trojan"
      push_once reasons "Trojan signature."
    fi

    if [[ "$lower" =~ (socks|socks4|socks5|dante|microsocks|proxy) ]]; then
      set_severity_if_higher severity 5
      push_once tags "socks"
      push_once reasons "SOCKS/proxy signature."
    fi

    if [[ "$lower" =~ (openvpn) ]] || [[ "$port" == "1194" ]]; then
      set_severity_if_higher severity 4
      push_once tags "openvpn"
      push_once reasons "OpenVPN signature."
    fi

    if [[ "$lower" =~ (pptp|l2tp|xl2tp|ppp) ]] || [[ "$port" == "1723" ]] || [[ "$port" == "1701" ]]; then
      set_severity_if_higher severity 5
      push_once tags "classic-vpn"
      push_once reasons "PPTP/L2TP signature."
    fi

    if [[ "$lower" =~ (wireguard) ]] || { [[ "$proto" == "udp" ]] && [[ "$port" == "51820" ]]; }; then
      set_severity_if_higher severity 4
      push_once tags "wireguard"
      push_once reasons "WireGuard signature."
    fi

    if [[ "$lower" =~ (vmess|vless|xray|hysteria|hy2|tuic|snell|shadowsocks|shadowtls) ]]; then
      set_severity_if_higher severity 5
      push_once tags "fet"
      push_once reasons "FET-like traffic."
    fi

    if [[ "$proto" == "udp" ]]; then
      if [[ ! "$port" =~ ^(53|67|68|69|123|161|500|4500|3478|443)$ ]]; then
        set_severity_if_higher severity 3
        push_once tags "quic-risk"
        push_once reasons "Non-standard UDP/QUIC."
      fi
    fi

    if [[ "$proto" == "tcp" ]] && [[ "$lower" =~ (ssl|tls|https) ]] && [[ ! "$port" =~ ^(443|8443)$ ]]; then
      set_severity_if_higher severity 3
      push_once tags "tls-nonstd"
      push_once reasons "TLS on non-standard port."
    fi

    if [[ "$proto" == "tcp" ]] && [[ "$service" == "unknown" ]] && [[ -z "$app_proto" ]] && (( port >= 10000 )) && [[ "$is_trusted" == "0" ]]; then
      set_severity_if_higher severity 3
      push_once tags "uncategorized"
      push_once reasons "Unable to Categorize."
    fi

    if { [[ "$proto" == "tcp" ]] && [[ "$lower" =~ (ssl|tls|https) ]]; } || [[ "$port" == "443" ]]; then
      if tls_sni_mismatch_check "$port"; then
        set_severity_if_higher severity 4
        push_once tags "sni-mismatch"
        push_once reasons "SNI mismatch."
      fi
    fi

    if (( severity >= 2 )); then
      reason_text="$(IFS='; '; echo "${reasons[*]}")"
      tag_text="$(IFS=','; echo "${tags[*]}")"
      FINDINGS+=("${severity}"$'\t'"${port}"$'\t'"${proto}"$'\t'"${service}"$'\t'"${version}"$'\t'"${proc}"$'\t'"${tag_text}"$'\t'"${reason_text}")
    fi
  done
}

severity_text() {
  case "$1" in
    5) echo "CRITICAL" ;;
    4) echo "HIGH" ;;
    3) echo "MEDIUM" ;;
    2) echo "LOW" ;;
    *) echo "INFO" ;;
  esac
}

severity_color() {
  case "$1" in
    5|4) echo "$C_RED" ;;
    3) echo "$C_YELLOW" ;;
    2) echo "$C_BLUE" ;;
    *) echo "$C_GRAY" ;;
  esac
}

judgement_type_from_tags() {
  local tags="$1"
  if contains_tag "$tags" "trojan"; then echo "Trojan"; return; fi
  if contains_tag "$tags" "socks"; then echo "SOCKS / Proxy"; return; fi
  if contains_tag "$tags" "wireguard"; then echo "WireGuard"; return; fi
  if contains_tag "$tags" "openvpn"; then echo "OpenVPN"; return; fi
  if contains_tag "$tags" "classic-vpn"; then echo "PPTP/L2TP"; return; fi
  if contains_tag "$tags" "sni-mismatch"; then echo "TLS SNI Mismatch"; return; fi
  if contains_tag "$tags" "http-app"; then echo "HTTP"; return; fi
  if contains_tag "$tags" "https-app"; then echo "HTTPS"; return; fi
  if contains_tag "$tags" "tls-app"; then echo "TLS/SSL"; return; fi
  if contains_tag "$tags" "proxy-stack"; then echo "Unable to Categorize"; return; fi
  if contains_tag "$tags" "quic-risk"; then echo "QUIC Non-Standard"; return; fi
  if contains_tag "$tags" "tls-nonstd"; then echo "TLS Non-Standard Port"; return; fi
  if contains_tag "$tags" "fet"; then echo "FET / Encrypted Proxy-like"; return; fi
  if contains_tag "$tags" "uncategorized"; then echo "Unable to Categorize"; return; fi
  if contains_tag "$tags" "trusted"; then echo "Trusted Port"; return; fi
  echo "Normal"
}

severity_rank() {
  case "$1" in
    CRITICAL) echo 5 ;;
    HIGH) echo 4 ;;
    MEDIUM) echo 3 ;;
    LOW) echo 2 ;;
    *) echo 1 ;;
  esac
}

severity_max_text() {
  local a="$1"
  local b="$2"
  if (( $(severity_rank "$a") >= $(severity_rank "$b") )); then
    echo "$a"
  else
    echo "$b"
  fi
}

csv_add_unique() {
  local old="$1"
  local item="$2"
  if [[ -z "$old" ]]; then
    echo "$item"
    return
  fi
  if grep -Eq "(^|,)$item(,|$)" <<<"$old"; then
    echo "$old"
    return
  fi
  echo "${old},${item}"
}

build_judgement_rows() {
  JUDGEMENT_ROWS=()
  local -A sev_map=()
  local -A type_map=()
  local -A reason_map=()

  local finding sev port proto service version proc tags reasons key
  for finding in "${FINDINGS[@]}"; do
    IFS=$'\t' read -r sev port proto service version proc tags reasons <<<"$finding"
    key="${proto}:${port}"
    sev_map["$key"]="$(severity_text "$sev")"
    type_map["$key"]="$(judgement_type_from_tags "$tags")"
    reason_map["$key"]="$reasons"
  done

  local ep risk jtype replay_types replay_hits reason
  for ep in "${ENDPOINTS[@]}"; do
    IFS=$'\t' read -r port proto service version proc <<<"$ep"
    key="${proto}:${port}"
    risk="${sev_map[$key]:-INFO}"
    jtype="${type_map[$key]:-Normal}"
    reason="${reason_map[$key]:-No high-risk indicators.}"

    replay_types="${REPLAY_TYPES_BY_ENDPOINT[$key]:-}"
    replay_hits="${REPLAY_HITS_BY_ENDPOINT[$key]:-0}"
    if [[ -n "$replay_types" && "$replay_types" != "-" && "$replay_hits" != "0" && "$replay_hits" != "-" ]]; then
      jtype="OpenGFW: ${replay_types}"
      risk="HIGH"
      reason="OpenGFW matched: ${replay_types} (${replay_hits})"
    elif [[ "$jtype" == "Unable to Categorize" ]]; then
      risk="$(severity_max_text "$risk" "MEDIUM")"
      reason="Unable to Categorize."
    elif [[ "$jtype" == "Normal" ]]; then
      risk="INFO"
      reason="No high-risk indicators."
    fi

    if [[ -z "$replay_types" ]]; then
      replay_types="-"
      replay_hits="-"
    fi

    JUDGEMENT_ROWS+=("${port}"$'\t'"${proto}"$'\t'"${service}"$'\t'"${proc}"$'\t'"${jtype}"$'\t'"${risk}"$'\t'"${reason}"$'\t'"${replay_types}"$'\t'"${replay_hits}")
  done
}

save_judgement_files() {
  if [[ -z "${RESULT_DIR:-}" ]]; then
    return
  fi
  mkdir -p "$RESULT_DIR"
  local ts
  ts="$(date +%Y%m%d-%H%M%S)"
  JUDGEMENT_HISTORY_FILE="${RESULT_DIR}/port-judgement-${ts}.tsv"
  JUDGEMENT_LATEST_FILE="${RESULT_DIR}/latest-port-judgement.tsv"

  {
    echo -e "timestamp\tport\tproto\tservice\tprocess\tjudgement_type\trisk\topengfw_types\topengfw_hits\treason"
    local row port proto service proc jtype risk reason replay_types replay_hits
    for row in "${JUDGEMENT_ROWS[@]}"; do
      IFS=$'\t' read -r port proto service proc jtype risk reason replay_types replay_hits <<<"$row"
      echo -e "$(date -u +%Y-%m-%dT%H:%M:%SZ)\t${port}\t${proto}\t${service}\t${proc}\t${jtype}\t${risk}\t${replay_types}\t${replay_hits}\t${reason}"
    done
  } >"$JUDGEMENT_HISTORY_FILE"

  cp -f "$JUDGEMENT_HISTORY_FILE" "$JUDGEMENT_LATEST_FILE" >/dev/null 2>&1 || true
}

save_overview_files() {
  if [[ -z "${SCRIPT_DIR:-}" ]]; then
    return
  fi
  mkdir -p "$RESULT_DIR" >/dev/null 2>&1 || true
  local ts
  ts="$(date +%Y%m%d-%H%M%S)"
  OVERVIEW_HISTORY_FILE="${RESULT_DIR}/port-risk-overview-${ts}.md"
  OVERVIEW_LATEST_FILE="${SCRIPT_DIR}/latest-port-risk-overview.md"

  {
    echo "# ${BRAND_TITLE}"
    echo "# 端口 + 信息 + 风险等级 总览 / Port + Info + Risk Overview"
    echo
    echo "- Generated: $(date '+%F %T %z')"
    echo "- Source: ${JUDGEMENT_HISTORY_FILE:-N/A}"
    echo
    echo "| Port | Proto | Service | Process | Type | Risk | OpenGFW |"
    echo "|---|---|---|---|---|---|---|"
    local row port proto service proc jtype risk reason replay_types replay_hits og
    for row in "${JUDGEMENT_ROWS[@]}"; do
      IFS=$'\t' read -r port proto service proc jtype risk reason replay_types replay_hits <<<"$row"
      if [[ -n "$replay_types" && "$replay_types" != "-" && "${replay_hits:-0}" != "0" && "${replay_hits:-0}" != "-" ]]; then
        og="${replay_types}(${replay_hits})"
      else
        og="-"
      fi
      echo "| ${port} | ${proto} | ${service} | ${proc} | ${jtype} | ${risk} | ${og} |"
    done
    echo
    echo "## Reason Details"
    echo
    for row in "${JUDGEMENT_ROWS[@]}"; do
      IFS=$'\t' read -r port proto service proc jtype risk reason replay_types replay_hits <<<"$row"
      echo "- ${port}/${proto} ${service} (${proc}) [${risk}] ${jtype}: ${reason}"
    done
  } >"$OVERVIEW_HISTORY_FILE"

  cp -f "$OVERVIEW_HISTORY_FILE" "$OVERVIEW_LATEST_FILE" >/dev/null 2>&1 || true
}

load_judgement_rows_from_file() {
  local file="$1"
  JUDGEMENT_ROWS=()
  if [[ ! -f "$file" ]]; then
    return 1
  fi
  local line port proto service proc jtype risk replay_types replay_hits reason ts
  while IFS=$'\t' read -r ts port proto service proc jtype risk replay_types replay_hits reason; do
    if [[ "$ts" == "timestamp" ]]; then
      continue
    fi
    JUDGEMENT_ROWS+=("${port}"$'\t'"${proto}"$'\t'"${service}"$'\t'"${proc}"$'\t'"${jtype}"$'\t'"${risk}"$'\t'"${reason}"$'\t'"${replay_types}"$'\t'"${replay_hits}")
  done <"$file"
  return 0
}

print_endpoint_judgement_table() {
  if [[ "${#JUDGEMENT_ROWS[@]}" -eq 0 ]]; then
    log_warn "無可用端口資料 | No endpoint data available."
    return
  fi

  log_ui "端口判斷主表 | Port + Judgement Main Table"
  printf "%-12s | %-14s | %-16s | %-26s | %-8s | %s\n" "Port" "Service" "Process" "Type" "Risk" "OpenGFW"
  echo "--------------------------------------------------------------------------------------------------------------------------"
  local row port proto service proc jtype risk reason replay_types replay_hits og
  for row in "${JUDGEMENT_ROWS[@]}"; do
    IFS=$'\t' read -r port proto service proc jtype risk reason replay_types replay_hits <<<"$row"
    if [[ -n "$replay_types" && "$replay_types" != "-" && "$replay_hits" != "0" && "$replay_hits" != "-" ]]; then
      og="${replay_types}(${replay_hits})"
    else
      og="-"
    fi
    printf "%-12s | %-14s | %-16s | %-26s | %-8s | %s\n" "${port}/${proto}" "$service" "$proc" "$jtype" "$risk" "$og"
  done
  echo "--------------------------------------------------------------------------------------------------------------------------"
  echo "說明: Type=判斷類型, Risk=風險等級, OpenGFW=回放命中類型與次數 | Type, Risk, replay hit classes/counts"
}

print_detection_notes() {
  echo
  printf "%b[註解 Notes]%b\n" "$C_YELLOW" "$C_RESET"
  printf "%b- FET%b: 在中國大陸特色防火牆語境裡，常被當作 Shadowsocks / 全加密代理流量。\n" "$C_BLUE" "$C_RESET"
  printf "%b- Trojan%b: 常被視為非標代理流量，容易招致通報。\n" "$C_BLUE" "$C_RESET"
  printf "%b- SOCKS4/SOCKS5%b: 屬於明顯代理握手流量，容易招致通報。\n" "$C_BLUE" "$C_RESET"
  printf "%b- SNI Mismatch%b: 常見於借殼域名/證書與目標 IP 不一致，容易招致通報。\n" "$C_BLUE" "$C_RESET"
  printf "%b- HTTP/HTTPS/TLS/SSL%b: 若跑在非常規端口，通常會被視為非標流量，可能招致通報。\n" "$C_BLUE" "$C_RESET"
  printf "%b- Unable to Categorize%b: 目前無法精準歸類，但不代表安全。\n" "$C_BLUE" "$C_RESET"
}

add_rule_once() {
  local key="$1"
  local name="$2"
  local expr="$3"
  local mode="${4:-log}"  # log or block

  if [[ -n "${RULE_DEDUP[$key]:-}" ]]; then
    return
  fi
  RULE_DEDUP["$key"]=1

  {
    echo "- name: ${name}"
    if [[ "$mode" == "block" ]]; then
      echo "  action: block"
      echo "  log: true"
    else
      echo "  log: true"
    fi
    echo "  expr: ${expr}"
    echo
  } >>"$RULES_FILE"
}

contains_tag() {
  local tags_csv="$1"
  local target="$2"
  grep -Eq "(^|,)${target}(,|$)" <<<"$tags_csv"
}

build_opengfw_rules() {
  log_ui "3) Generate OpenGFW rule suggestions"

  mkdir -p "$OUTPUT_DIR"
  local ts core_mode mode
  ts="$(date +%Y%m%d-%H%M%S)"
  RULES_FILE="${OUTPUT_DIR}/opengfw-rules-${ts}.yaml"

  {
    echo "# ${BRAND_TITLE}"
    echo "# Auto-generated by self-detect-opengfw.sh v${VERSION}"
    echo "# Scan mode: ${SCAN_MODE}"
    echo "# Generated: $(date '+%F %T %z')"
    echo "#"
    echo "# Guidance / 指南:"
    echo "# - Start with log rules."
    echo "# - Promote to block only after validating false positives."
    echo
  } >"$RULES_FILE"

  if [[ "$STRICT_RULES" == "1" ]]; then
    core_mode="block"
  else
    core_mode="log"
  fi

  add_rule_once "base-fet" "audit-fet" \
    "fet != nil && fet.yes" "$core_mode"
  add_rule_once "base-trojan" "audit-trojan" \
    "trojan != nil && trojan.yes" "$core_mode"
  add_rule_once "base-socks" "audit-socks" \
    "socks != nil" "$core_mode"
  add_rule_once "base-wireguard" "audit-wireguard" \
    "wireguard != nil" "$core_mode"
  add_rule_once "base-openvpn" "audit-openvpn" \
    "openvpn != nil && openvpn.rx_pkt_cnt + openvpn.tx_pkt_cnt > 50" "$core_mode"
  add_rule_once "base-classic-vpn-ports" "audit-classic-vpn-ports" \
    "(proto == \"tcp\" && port.dst == 1723) || (proto == \"udp\" && port.dst == 1701)" "$core_mode"
  add_rule_once "base-quic-nonstd" "audit-quic-non-standard-port" \
    "quic?.req != nil && !(port.dst in [443, 8443])" "log"
  add_rule_once "base-sni-mismatch" "audit-sni-mismatch" \
    "tls?.req?.sni != nil && ip.dst not in concat(lookup(tls.req.sni), lookup(tls.req.sni, \"1.1.1.1:53\"), lookup(tls.req.sni, \"8.8.8.8:53\"))" "log"

  # Always add per-endpoint OpenGFW analyzer rules so replay results can map to specific ports.
  local ep2 p2 proto2 service2 version2 proc2
  for ep2 in "${ENDPOINTS[@]}"; do
    IFS=$'\t' read -r p2 proto2 service2 version2 proc2 <<<"$ep2"
    add_rule_once "ep-fet-${proto2}-${p2}" "audit-port-${proto2}-${p2}-fet" \
      "proto == \"${proto2}\" && port.dst == ${p2} && fet != nil && fet.yes" "log"
    add_rule_once "ep-socks-${proto2}-${p2}" "audit-port-${proto2}-${p2}-socks" \
      "proto == \"${proto2}\" && port.dst == ${p2} && socks != nil" "log"
    add_rule_once "ep-trojan-${proto2}-${p2}" "audit-port-${proto2}-${p2}-trojan" \
      "proto == \"${proto2}\" && port.dst == ${p2} && trojan != nil && trojan.yes" "log"
    add_rule_once "ep-wireguard-${proto2}-${p2}" "audit-port-${proto2}-${p2}-wireguard" \
      "proto == \"${proto2}\" && port.dst == ${p2} && wireguard != nil" "log"
    add_rule_once "ep-openvpn-${proto2}-${p2}" "audit-port-${proto2}-${p2}-openvpn" \
      "proto == \"${proto2}\" && port.dst == ${p2} && openvpn != nil && openvpn.rx_pkt_cnt + openvpn.tx_pkt_cnt > 20" "log"
    add_rule_once "ep-sni-${proto2}-${p2}" "audit-port-${proto2}-${p2}-sni-mismatch" \
      "proto == \"${proto2}\" && port.dst == ${p2} && tls?.req?.sni != nil && ip.dst not in concat(lookup(tls.req.sni), lookup(tls.req.sni, \"1.1.1.1:53\"), lookup(tls.req.sni, \"8.8.8.8:53\"))" "log"
  done

  local finding sev port proto service version proc tags reasons
  for finding in "${FINDINGS[@]}"; do
    IFS=$'\t' read -r sev port proto service version proc tags reasons <<<"$finding"

    if (( sev >= 4 )) && [[ "$STRICT_RULES" == "1" ]]; then
      mode="block"
    else
      mode="log"
    fi

    if contains_tag "$tags" "trojan"; then
      add_rule_once "trojan-${proto}-${port}" "audit-trojan-port-${port}" \
        "proto == \"${proto}\" && port.dst == ${port} && trojan != nil && trojan.yes" "$mode"
    fi

    if contains_tag "$tags" "socks"; then
      add_rule_once "socks-${proto}-${port}" "audit-socks-port-${port}" \
        "proto == \"${proto}\" && port.dst == ${port} && socks != nil" "$mode"
    fi

    if contains_tag "$tags" "wireguard"; then
      add_rule_once "wireguard-${proto}-${port}" "audit-wireguard-port-${port}" \
        "proto == \"${proto}\" && port.dst == ${port} && wireguard != nil" "$mode"
    fi

    if contains_tag "$tags" "openvpn"; then
      add_rule_once "openvpn-${proto}-${port}" "audit-openvpn-port-${port}" \
        "proto == \"${proto}\" && port.dst == ${port} && openvpn != nil && openvpn.rx_pkt_cnt + openvpn.tx_pkt_cnt > 20" "$mode"
    fi

    if contains_tag "$tags" "classic-vpn"; then
      add_rule_once "classic-vpn-${proto}-${port}" "audit-classic-vpn-port-${port}" \
        "proto == \"${proto}\" && port.dst == ${port}" "$mode"
    fi

    if contains_tag "$tags" "fet"; then
      add_rule_once "fet-${proto}-${port}" "audit-fet-port-${port}" \
        "proto == \"${proto}\" && port.dst == ${port} && fet != nil && fet.yes" "$mode"
    fi

    if contains_tag "$tags" "quic-risk"; then
      add_rule_once "quic-${proto}-${port}" "audit-quic-port-${port}" \
        "proto == \"${proto}\" && port.dst == ${port} && quic?.req != nil" "log"
    fi

    if contains_tag "$tags" "sni-mismatch"; then
      add_rule_once "sni-mismatch-${proto}-${port}" "audit-sni-mismatch-port-${port}" \
        "proto == \"${proto}\" && port.dst == ${port} && tls?.req?.sni != nil && ip.dst not in concat(lookup(tls.req.sni), lookup(tls.req.sni, \"1.1.1.1:53\"), lookup(tls.req.sni, \"8.8.8.8:53\"))" "log"
    fi
  done

  log_info "Generated rules: $RULES_FILE"
}

print_console_summary() {
  log_ui "掃描摘要 | Scan Summary"
  if [[ "$RUN_OPENGFW_REPLAY" == "1" ]]; then
    log_info "OpenGFW 回放: 已啟用 | enabled"
  else
    log_info "OpenGFW 回放: 已停用（普通檢測）| disabled (normal detect)"
  fi

  local has_endpoints=1
  if [[ "${#ENDPOINTS[@]}" -eq 0 ]]; then
    log_warn "Nmap 未識別到開放端口 | Nmap did not identify open endpoints."
    has_endpoints=0
  fi

  if [[ "$has_endpoints" == "1" ]]; then
    print_endpoint_judgement_table
    print_detection_notes

    echo
    if [[ "${#JUDGEMENT_ROWS[@]}" -eq 0 ]]; then
      log_info "未發現明顯高風險協議指紋 | No obvious high-risk protocol fingerprints."
    else
      echo "風險原因明細 | Risk Findings Details:"
      local row port proto service proc jtype risk reason replay_types replay_hits color
      for row in "${JUDGEMENT_ROWS[@]}"; do
        IFS=$'\t' read -r port proto service proc jtype risk reason replay_types replay_hits <<<"$row"
        if [[ "$risk" == "INFO" ]]; then
          continue
        fi
        color="$(severity_color "$(severity_rank "$risk")")"
        printf "  - %b[%s]%b %s/%s %s (proc=%s, type=%s)\n    Reason: %s\n" "$color" "$risk" "$C_RESET" "$port" "$proto" "$service" "$proc" "$jtype" "$reason"
      done
    fi
  fi

  if [[ "${#WARNINGS[@]}" -gt 0 ]]; then
    echo
    echo "警告 | Warnings:"
    local w
    for w in "${WARNINGS[@]}"; do
      printf "  - %s\n" "$w"
    done
  fi

  if [[ "$RUN_OPENGFW_REPLAY" == "1" ]]; then
    echo
    if [[ "${#REPLAY_HITS[@]}" -eq 0 ]]; then
      echo "OpenGFW 回放命中: 無 | OpenGFW replay hits: none"
    else
      echo "OpenGFW 回放命中 | OpenGFW replay hits:"
      local hit_item hit_rule hit_count
      for hit_item in "${REPLAY_HITS[@]}"; do
        IFS=$'\t' read -r hit_rule hit_count <<<"$hit_item"
        printf "  - %s : %s\n" "$hit_rule" "$hit_count"
      done
    fi
  fi

  echo
  echo "產物檔案 | Artifacts:"
  echo "  - rules 規則: $RULES_FILE"
  echo "  - report 報告: $REPORT_FILE"
  if [[ -n "$JUDGEMENT_HISTORY_FILE" ]]; then
    echo "  - judgement-history: $JUDGEMENT_HISTORY_FILE"
  fi
  if [[ -n "$JUDGEMENT_LATEST_FILE" ]]; then
    echo "  - judgement-latest: $JUDGEMENT_LATEST_FILE"
  fi
  if [[ -n "$OVERVIEW_HISTORY_FILE" ]]; then
    echo "  - overview-history: $OVERVIEW_HISTORY_FILE"
  fi
  if [[ -n "$OVERVIEW_LATEST_FILE" ]]; then
    echo "  - overview-latest: $OVERVIEW_LATEST_FILE"
  fi
  if [[ -n "$REPLAY_PCAP_FILE" ]]; then
    echo "  - replay-pcap: $REPLAY_PCAP_FILE"
  fi
  if [[ -n "$REPLAY_LOG_FILE" ]]; then
    echo "  - replay-log: $REPLAY_LOG_FILE"
  fi
  if [[ -n "$REPLAY_LOG_CLEAN_FILE" ]]; then
    echo "  - replay-log-clean: $REPLAY_LOG_CLEAN_FILE"
  fi
}

build_markdown_report() {
  mkdir -p "$OUTPUT_DIR"
  local ts
  ts="$(date +%Y%m%d-%H%M%S)"
  REPORT_FILE="${OUTPUT_DIR}/self-detect-report-${ts}.md"

  {
    echo "# ${BRAND_TITLE}"
    echo "# OpenGFW + Nmap 自查報告 / Self-Audit Report"
    echo
    echo "- Version: \`${VERSION}\`"
    echo "- Scan mode: \`${SCAN_MODE}\`"
    echo "- Generated: \`$(date '+%F %T %z')\`"
    echo "- Public IP: \`${PUBLIC_IP:-N/A}\`"
    echo "- Trusted ports: \`${TRUSTED_PORTS:-N/A}\`"
    echo "- Replay interface: \`${REPLAY_CAPTURE_INTERFACE}\`"
    echo "- OpenGFW log level: \`${OPENGFW_LOG_LEVEL}\`"
    echo
    echo "## Port + Judgement Main Table"
    echo
    echo "| Port | Proto | Service | Process | Type | Risk | OpenGFW | Reason |"
    echo "|---|---|---|---|---|---|---|---|"
    local row port proto service proc jtype risk reason replay_types replay_hits og
    for row in "${JUDGEMENT_ROWS[@]}"; do
      IFS=$'\t' read -r port proto service proc jtype risk reason replay_types replay_hits <<<"$row"
      if [[ -n "$replay_types" && "$replay_types" != "-" && "$replay_hits" != "0" && "$replay_hits" != "-" ]]; then
        og="${replay_types}(${replay_hits})"
      else
        og="-"
      fi
      echo "| ${port} | ${proto} | ${service} | ${proc} | ${jtype} | ${risk} | ${og} | ${reason} |"
    done
    echo

    echo "## Recommendations"
    echo
    echo "1. Start with log-only OpenGFW rules for 24-72 hours before any blocking decision."
    echo "2. Minimize public exposure for high UDP ports and explicit proxy/VPN signatures."
    echo "3. Avoid obvious TLS domain/certificate/IP inconsistencies that trigger mismatch heuristics."
    echo "4. Keep separate audit rules for Trojan/SOCKS/WireGuard/OpenVPN and track false positives."
    echo "5. For known service pools (for example Shadowsocks high-port ranges), set --trusted-ports to reduce noisy heuristics."
    echo

    if [[ "$RUN_OPENGFW_REPLAY" == "1" ]]; then
      echo "## OpenGFW replay summary"
      echo
      if [[ "${#REPLAY_HITS[@]}" -eq 0 ]]; then
        echo "No replay hits were detected in this cycle."
      else
        echo "| Rule | Hits |"
        echo "|---|---|"
        local hit_item hit_rule hit_count
        for hit_item in "${REPLAY_HITS[@]}"; do
          IFS=$'\t' read -r hit_rule hit_count <<<"$hit_item"
          echo "| ${hit_rule} | ${hit_count} |"
        done
      fi
      echo
    fi

    echo "## Files generated"
    echo
    echo "- Rule suggestions: \`${RULES_FILE}\`"
    echo "- This report: \`${REPORT_FILE}\`"
    if [[ -n "$JUDGEMENT_LATEST_FILE" ]]; then
      echo "- Latest judgement file: \`${JUDGEMENT_LATEST_FILE}\`"
    fi
    if [[ -n "$JUDGEMENT_HISTORY_FILE" ]]; then
      echo "- History judgement file: \`${JUDGEMENT_HISTORY_FILE}\`"
    fi
    if [[ -n "$OVERVIEW_LATEST_FILE" ]]; then
      echo "- Latest overview file: \`${OVERVIEW_LATEST_FILE}\`"
    fi
    if [[ -n "$OVERVIEW_HISTORY_FILE" ]]; then
      echo "- History overview file: \`${OVERVIEW_HISTORY_FILE}\`"
    fi
    if [[ -n "$REPLAY_PCAP_FILE" ]]; then
      echo "- Replay capture: \`${REPLAY_PCAP_FILE}\`"
    fi
    if [[ -n "$REPLAY_LOG_FILE" ]]; then
      echo "- Replay log: \`${REPLAY_LOG_FILE}\`"
    fi
    if [[ -n "$REPLAY_LOG_CLEAN_FILE" ]]; then
      echo "- Replay clean log: \`${REPLAY_LOG_CLEAN_FILE}\`"
    fi
  } >"$REPORT_FILE"

  log_info "Generated report: $REPORT_FILE"
}

json_escape() {
  printf '%s' "$1" \
    | sed 's/\\/\\\\/g; s/"/\\"/g; s/\r/\\r/g; s/\t/\\t/g' \
    | sed ':a;N;$!ba;s/\n/\\n/g'
}

build_endpoints_json() {
  local out="["
  local first=1
  local ep port proto service version proc
  for ep in "${ENDPOINTS[@]}"; do
    IFS=$'\t' read -r port proto service version proc <<<"$ep"
    local item
    item="$(printf '{"port":%s,"proto":"%s","service":"%s","process":"%s","version":"%s"}' \
      "$port" \
      "$(json_escape "$proto")" \
      "$(json_escape "$service")" \
      "$(json_escape "$proc")" \
      "$(json_escape "$version")")"
    if [[ "$first" == "1" ]]; then
      out+="$item"
      first=0
    else
      out+=",$item"
    fi
  done
  out+="]"
  echo "$out"
}

build_findings_json() {
  local out="["
  local first=1
  local finding sev port proto service version proc tags reasons
  for finding in "${FINDINGS[@]}"; do
    IFS=$'\t' read -r sev port proto service version proc tags reasons <<<"$finding"
    local item
    item="$(printf '{"severity":%s,"port":%s,"proto":"%s","service":"%s","process":"%s","tags":"%s","reason":"%s"}' \
      "$sev" \
      "$port" \
      "$(json_escape "$proto")" \
      "$(json_escape "$service")" \
      "$(json_escape "$proc")" \
      "$(json_escape "$tags")" \
      "$(json_escape "$reasons")")"
    if [[ "$first" == "1" ]]; then
      out+="$item"
      first=0
    else
      out+=",$item"
    fi
  done
  out+="]"
  echo "$out"
}

collect_local_ips_json() {
  local out="["
  local first=1
  local ip

  while IFS= read -r ip; do
    [[ -z "$ip" ]] && continue
    if [[ "$first" == "1" ]]; then
      out+="\"$(json_escape "$ip")\""
      first=0
    else
      out+=",\"$(json_escape "$ip")\""
    fi
  done < <(
    {
      ip -o -4 addr show 2>/dev/null | awk '{print $4}' | cut -d'/' -f1
      ip -o -6 addr show 2>/dev/null | awk '{print $4}' | cut -d'/' -f1
      echo "127.0.0.1"
      echo "::1"
    } | sort -u
  )

  out+="]"
  echo "$out"
}

build_suspicious_services_json() {
  local out="["
  local first=1
  local finding sev port proto service version proc tags reasons
  for finding in "${FINDINGS[@]}"; do
    IFS=$'\t' read -r sev port proto service version proc tags reasons <<<"$finding"
    local item
    item="$(printf '{"port":"%s","protocol":"%s","service_name":"%s","service_version":"%s","process":"%s","reason":"%s","severity":"%s","blocked":false}' \
      "$(json_escape "$port")" \
      "$(json_escape "$proto")" \
      "$(json_escape "$service")" \
      "$(json_escape "$version")" \
      "$(json_escape "$proc")" \
      "$(json_escape "$reasons")" \
      "$(json_escape "$(severity_text "$sev")")")"
    if [[ "$first" == "1" ]]; then
      out+="$item"
      first=0
    else
      out+=",$item"
    fi
  done
  out+="]"
  echo "$out"
}

build_replay_hits_json() {
  local out="["
  local first=1
  local item name count
  for item in "${REPLAY_HITS[@]}"; do
    IFS=$'\t' read -r name count <<<"$item"
    local row
    row="$(printf '{"rule":"%s","hits":%s}' "$(json_escape "$name")" "$count")"
    if [[ "$first" == "1" ]]; then
      out+="$row"
      first=0
    else
      out+=",$row"
    fi
  done
  out+="]"
  echo "$out"
}

send_report() {
  if [[ "$REPORT_ENABLED" != "1" ]]; then
    log_info "Report upload disabled."
    return
  fi
  if ! have_cmd curl; then
    WARNINGS+=("curl not found; report upload skipped.")
    return
  fi

  local payload endpoints_json findings_json suspicious_json local_ips_json replay_hits_json http_code
  endpoints_json="$(build_endpoints_json)"
  findings_json="$(build_findings_json)"
  suspicious_json="$(build_suspicious_services_json)"
  local_ips_json="$(collect_local_ips_json)"
  replay_hits_json="$(build_replay_hits_json)"

  payload="$(cat <<EOF
{
  "hostname": "$(json_escape "$(hostname)")",
  "timestamp_utc": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "timestamp": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "tool_version": "$(json_escape "$VERSION")",
  "scan_mode": "$(json_escape "$SCAN_MODE")",
  "public_ip": "$(json_escape "${PUBLIC_IP:-}")",
  "trusted_ports": "$(json_escape "${TRUSTED_PORTS:-}")",
  "local_ips": ${local_ips_json},
  "firewall_tool": "",
  "probe_enabled": ${PROBE_TRAFFIC},
  "probe_rounds": ${PROBE_ROUNDS},
  "opengfw_replay_enabled": ${RUN_OPENGFW_REPLAY},
  "replay_capture_seconds": ${REPLAY_CAPTURE_SECONDS},
  "replay_capture_interface": "$(json_escape "${REPLAY_CAPTURE_INTERFACE}")",
  "opengfw_log_level": "$(json_escape "${OPENGFW_LOG_LEVEL}")",
  "replay_with_probe": ${REPLAY_WITH_PROBE},
  "replay_pcap_file": "$(json_escape "${REPLAY_PCAP_FILE}")",
  "replay_log_file": "$(json_escape "${REPLAY_LOG_FILE}")",
  "replay_hits": ${replay_hits_json},
  "rules_file": "$(json_escape "$RULES_FILE")",
  "report_file": "$(json_escape "$REPORT_FILE")",
  "judgement_latest_file": "$(json_escape "${JUDGEMENT_LATEST_FILE}")",
  "judgement_history_file": "$(json_escape "${JUDGEMENT_HISTORY_FILE}")",
  "overview_latest_file": "$(json_escape "${OVERVIEW_LATEST_FILE}")",
  "overview_history_file": "$(json_escape "${OVERVIEW_HISTORY_FILE}")",
  "endpoints": ${endpoints_json},
  "findings": ${findings_json},
  "suspicious_services": ${suspicious_json}
}
EOF
)"

  http_code="$(
    curl -sS -o /dev/null -w "%{http_code}" \
      -X POST \
      -H "Content-Type: application/json" \
      -H "Accept: application/json" \
      --data "$payload" \
      "$REPORT_URL" 2>/dev/null || echo "000"
  )"

  if [[ "$http_code" =~ ^2[0-9][0-9]$ ]]; then
    log_info "Report uploaded: $REPORT_URL (HTTP $http_code)"
  else
    log_warn "Report upload failed: $REPORT_URL (HTTP $http_code)"
    WARNINGS+=("Report upload failed with HTTP ${http_code} to ${REPORT_URL}.")
  fi
}

run_once() {
  reset_runtime_state
  preflight_check_core || return
  preflight_check_replay || return
  if [[ -n "$TRUSTED_PORTS" ]]; then
    log_info "Trusted ports active: $TRUSTED_PORTS"
  fi

  local has_ports=0
  if collect_listening_ports; then
    has_ports=1
  fi

  local tcp_out="" udp_out="" tcp_csv="" udp_csv=""
  if [[ "$has_ports" == "1" ]]; then
    seed_endpoints_from_listening_ports
    tcp_out="$(mktemp)"
    udp_out="$(mktemp)"

    if [[ "${#TCP_PORTS[@]}" -gt 0 ]]; then
      tcp_csv="$(csv_from_array TCP_PORTS)"
      if run_nmap_scan "tcp" "$tcp_csv" "$tcp_out"; then
        append_endpoints_from_nmap "$tcp_out"
        if ! grep -Eq '^[0-9]+/(tcp|udp)[[:space:]]+' "$tcp_out"; then
          WARNINGS+=("Nmap returned no structured port rows; using ss listener table as fallback.")
        fi
      else
        WARNINGS+=("TCP nmap scan failed. Check nmap permissions and local stack state.")
      fi
    fi

    if [[ "$SKIP_UDP" == "0" && "${#UDP_PORTS[@]}" -gt 0 ]]; then
      udp_csv="$(csv_from_array UDP_PORTS)"
      if run_nmap_scan "udp" "$udp_csv" "$udp_out"; then
        append_endpoints_from_nmap "$udp_out"
      else
        WARNINGS+=("UDP nmap scan failed. This is often caused by privilege or firewall restrictions.")
      fi
    fi

    rm -f "$tcp_out" "$udp_out"
  fi

  detect_application_protocols
  apply_application_protocol_labels

  if [[ "$PROBE_TRAFFIC" == "1" ]]; then
    trigger_active_probes
  fi

  classify_endpoints
  build_opengfw_rules
  run_opengfw_replay
  build_judgement_rows
  save_judgement_files
  save_overview_files
  build_markdown_report
  send_report
  apply_block_unblock_lists
  if [[ "$DAEMON_MODE" != "1" ]]; then
    interactive_firewall_actions
  fi
  print_console_summary
}

run_port_inventory_only() {
  reset_runtime_state
  preflight_check_core || return
  local has_ports=0
  if collect_listening_ports; then
    has_ports=1
  fi
  if [[ "$has_ports" != "1" ]]; then
    return
  fi

  seed_endpoints_from_listening_ports
  local tcp_out udp_out tcp_csv udp_csv
  tcp_out="$(mktemp)"
  udp_out="$(mktemp)"

  if [[ "${#TCP_PORTS[@]}" -gt 0 ]]; then
    tcp_csv="$(csv_from_array TCP_PORTS)"
    run_nmap_scan "tcp" "$tcp_csv" "$tcp_out" || true
    append_endpoints_from_nmap "$tcp_out"
    if ! grep -Eq '^[0-9]+/(tcp|udp)[[:space:]]+' "$tcp_out"; then
      WARNINGS+=("Nmap returned no structured port rows; using ss listener table as fallback.")
    fi
  fi
  if [[ "$SKIP_UDP" == "0" && "${#UDP_PORTS[@]}" -gt 0 ]]; then
    udp_csv="$(csv_from_array UDP_PORTS)"
    run_nmap_scan "udp" "$udp_csv" "$udp_out" || true
    append_endpoints_from_nmap "$udp_out"
  fi

  rm -f "$tcp_out" "$udp_out"
  detect_application_protocols
  apply_application_protocol_labels
  classify_endpoints
  build_judgement_rows
  save_judgement_files
  save_overview_files
  print_endpoint_judgement_table
}

pause_enter() {
  if [[ -t 0 ]]; then
    read -r -p "按 Enter 繼續 | Press Enter to continue..." _
  fi
}

menu_read() {
  local prompt="$1"
  local value=""
  read -r -p "$prompt" value
  echo "$value"
}

prepare_default_profile() {
  PROBE_TRAFFIC=0
  RUN_OPENGFW_REPLAY=0
  REPLAY_WITH_PROBE=0
  INTERACTIVE_FIREWALL=0
  FIREWALL_ONLY=0
  BLOCK_LIST=""
  UNBLOCK_LIST=""
}

menu_choose_ip_family() {
  echo "選擇封鎖/解封作用範圍 | Choose IP family for firewall action:"
  echo "  [1] both (IPv4 + IPv6)"
  echo "  [2] ipv4 only"
  echo "  [3] ipv6 only"
  local c
  c="$(menu_read 'Select [1-3] (default 1): ')"
  case "$c" in
    2) FIREWALL_IP_FAMILY="ipv4" ;;
    3) FIREWALL_IP_FAMILY="ipv6" ;;
    *) FIREWALL_IP_FAMILY="both" ;;
  esac
  log_info "防火牆族別已設定 | Firewall family set to: ${FIREWALL_IP_FAMILY}"
}

menu_offer_block_from_findings() {
  if [[ -z "$JUDGEMENT_LATEST_FILE" || ! -f "$JUDGEMENT_LATEST_FILE" ]]; then
    log_warn "找不到最新判斷檔 | Latest judgement file not found."
    return
  fi
  if ! load_judgement_rows_from_file "$JUDGEMENT_LATEST_FILE"; then
    log_warn "讀取判斷檔失敗 | Failed to load latest judgement file."
    return
  fi
  if [[ "${#JUDGEMENT_ROWS[@]}" -eq 0 ]]; then
    log_info "目前無可封鎖項目 | No findings available for block action."
    return
  fi

  if [[ "$(id -u)" -ne 0 ]]; then
    log_warn "需要 root 權限才能封鎖/解封 | Root is required for block/unblock actions."
    return
  fi
  if [[ ! -t 0 ]]; then
    return
  fi

  log_ui "封鎖方式 | Block Mode"
  echo "  [1] 自己選端口封鎖 | Choose specific ports"
  echo "  [2] 一鍵封鎖 HIGH 端口 | One-click block HIGH"
  echo "  [3] 一鍵封鎖 HIGH + MEDIUM 端口 | One-click block HIGH + MEDIUM"
  echo "  [0] 取消 | Cancel"
  local mode
  mode="$(menu_read '請輸入選項 | Select [0-3]: ')"
  if [[ "$mode" == "0" || -z "$mode" ]]; then
    return
  fi

  menu_choose_ip_family

  local idx=1
  local row port proto service proc jtype risk reason replay_types replay_hits
  local -a selected_rows=()

  case "$mode" in
    1)
      echo "可操作風險列表（來源 latest-port-judgement.tsv）| Findings list:"
      local display_idx=1
      local -a display_map=()
      for row in "${JUDGEMENT_ROWS[@]}"; do
        IFS=$'\t' read -r port proto service proc jtype risk reason replay_types replay_hits <<<"$row"
        if [[ "$risk" == "INFO" ]]; then
          continue
        fi
        printf "  [%d] %s/%s %s (type=%s, risk=%s, ogfw=%s/%s)\n" \
          "$display_idx" "$port" "$proto" "$service" "$jtype" "$risk" "${replay_types:-"-"}" "${replay_hits:-"-"}"
        display_map+=("$row")
        display_idx=$((display_idx + 1))
      done

      local pick
      pick="$(menu_read '輸入序號（如 1,3,5）| Choose indexes: ')"
      if [[ -z "$pick" ]]; then
        return
      fi

      local -a selected=()
      IFS=',' read -r -a selected <<<"$pick"
      local raw n
      for raw in "${selected[@]}"; do
        n="$(echo "$raw" | tr -d '[:space:]')"
        if [[ ! "$n" =~ ^[0-9]+$ ]]; then
          continue
        fi
        if (( n < 1 || n > ${#display_map[@]} )); then
          continue
        fi
        selected_rows+=("${display_map[$((n-1))]}")
      done
      ;;
    2)
      for row in "${JUDGEMENT_ROWS[@]}"; do
        IFS=$'\t' read -r port proto service proc jtype risk reason replay_types replay_hits <<<"$row"
        if [[ "$risk" == "HIGH" || "$risk" == "CRITICAL" ]]; then
          selected_rows+=("$row")
        fi
      done
      ;;
    3)
      for row in "${JUDGEMENT_ROWS[@]}"; do
        IFS=$'\t' read -r port proto service proc jtype risk reason replay_types replay_hits <<<"$row"
        if [[ "$risk" == "HIGH" || "$risk" == "CRITICAL" || "$risk" == "MEDIUM" ]]; then
          selected_rows+=("$row")
        fi
      done
      ;;
    *)
      return
      ;;
  esac

  if [[ "${#selected_rows[@]}" -eq 0 ]]; then
    log_info "沒有可封鎖項目 | Nothing selected for block."
    return
  fi

  for row in "${selected_rows[@]}"; do
    IFS=$'\t' read -r port proto service proc jtype risk reason replay_types replay_hits <<<"$row"
    apply_iptables_block "$proto" "$port" "$FIREWALL_IP_FAMILY" \
      && log_info "Blocked ${proto}:${port} (family=${FIREWALL_IP_FAMILY})" \
      || WARNINGS+=("Failed to block ${proto}:${port}")
  done
}

select_rows_by_mode() {
  local mode="$1"
  SELECTED_RESULT_ROWS=()

  local row port proto service proc jtype risk reason replay_types replay_hits
  case "$mode" in
    high)
      for row in "${JUDGEMENT_ROWS[@]}"; do
        IFS=$'\t' read -r port proto service proc jtype risk reason replay_types replay_hits <<<"$row"
        if [[ "$risk" == "HIGH" || "$risk" == "CRITICAL" ]]; then
          SELECTED_RESULT_ROWS+=("$row")
        fi
      done
      ;;
    high_medium)
      for row in "${JUDGEMENT_ROWS[@]}"; do
        IFS=$'\t' read -r port proto service proc jtype risk reason replay_types replay_hits <<<"$row"
        if [[ "$risk" == "HIGH" || "$risk" == "CRITICAL" || "$risk" == "MEDIUM" ]]; then
          SELECTED_RESULT_ROWS+=("$row")
        fi
      done
      ;;
  esac
}

select_rows_interactively() {
  SELECTED_RESULT_ROWS=()
  echo "可操作風險列表（來源 latest-port-judgement.tsv）| Findings list:"
  local display_idx=1
  local -a display_map=()
  local row port proto service proc jtype risk reason replay_types replay_hits
  for row in "${JUDGEMENT_ROWS[@]}"; do
    IFS=$'\t' read -r port proto service proc jtype risk reason replay_types replay_hits <<<"$row"
    if [[ "$risk" == "INFO" ]]; then
      continue
    fi
    printf "  [%d] %s/%s %s (type=%s, risk=%s, ogfw=%s/%s)\n" \
      "$display_idx" "$port" "$proto" "$service" "$jtype" "$risk" "${replay_types:-"-"}" "${replay_hits:-"-"}"
    display_map+=("$row")
    display_idx=$((display_idx + 1))
  done

  local pick
  pick="$(menu_read '輸入序號（如 1,3,5）| Choose indexes: ')"
  if [[ -z "$pick" ]]; then
    return
  fi

  local -a selected=()
  local raw n
  IFS=',' read -r -a selected <<<"$pick"
  for raw in "${selected[@]}"; do
    n="$(echo "$raw" | tr -d '[:space:]')"
    if [[ ! "$n" =~ ^[0-9]+$ ]]; then
      continue
    fi
    if (( n < 1 || n > ${#display_map[@]} )); then
      continue
    fi
    SELECTED_RESULT_ROWS+=("${display_map[$((n-1))]}")
  done
}

apply_whitelist_to_rows() {
  local entries_csv="$1"
  local row port proto service proc jtype risk reason replay_types replay_hits
  for row in "${SELECTED_RESULT_ROWS[@]}"; do
    IFS=$'\t' read -r port proto service proc jtype risk reason replay_types replay_hits <<<"$row"
    if [[ "$FIREWALL_IP_FAMILY" == "both" || "$FIREWALL_IP_FAMILY" == "ipv4" ]]; then
      apply_port_whitelist_rules "$proto" "$port" "ipv4" "$entries_csv" \
        && log_info "Whitelist applied for ${proto}:${port} on ipv4" \
        || true
    fi
    if [[ "$FIREWALL_IP_FAMILY" == "both" || "$FIREWALL_IP_FAMILY" == "ipv6" ]]; then
      apply_port_whitelist_rules "$proto" "$port" "ipv6" "$entries_csv" \
        && log_info "Whitelist applied for ${proto}:${port} on ipv6" \
        || true
    fi
  done
}

remove_whitelist_from_rows() {
  local row port proto service proc jtype risk reason replay_types replay_hits
  for row in "${SELECTED_RESULT_ROWS[@]}"; do
    IFS=$'\t' read -r port proto service proc jtype risk reason replay_types replay_hits <<<"$row"
    if [[ "$FIREWALL_IP_FAMILY" == "both" || "$FIREWALL_IP_FAMILY" == "ipv4" ]]; then
      remove_port_whitelist_rules "$proto" "$port" "ipv4"
    fi
    if [[ "$FIREWALL_IP_FAMILY" == "both" || "$FIREWALL_IP_FAMILY" == "ipv6" ]]; then
      remove_port_whitelist_rules "$proto" "$port" "ipv6"
    fi
    log_info "Whitelist removed for ${proto}:${port} (family=${FIREWALL_IP_FAMILY})"
  done
}

menu_review_latest_results() {
  if [[ -n "$JUDGEMENT_LATEST_FILE" && -f "$JUDGEMENT_LATEST_FILE" ]]; then
    load_judgement_rows_from_file "$JUDGEMENT_LATEST_FILE" || true
  fi

  if [[ "${#JUDGEMENT_ROWS[@]}" -eq 0 ]]; then
    log_warn "找不到最新檢測結果，請先執行普通或進階檢測 | No latest results found. Run detect first."
    return
  fi

  log_ui "掃描結果解讀與封鎖 | Review Results and Block"
  print_endpoint_judgement_table

  echo
  if [[ -n "$OVERVIEW_LATEST_FILE" ]]; then
    echo "最新總覽檔 | Latest overview file: $OVERVIEW_LATEST_FILE"
  fi
  if [[ -n "$JUDGEMENT_LATEST_FILE" ]]; then
    echo "最新判斷檔 | Latest judgement file: $JUDGEMENT_LATEST_FILE"
  fi

  while true; do
    echo
    echo "  [1] 封鎖指定端口 | Block selected ports"
    echo "  [2] 一鍵封鎖 HIGH | One-click block HIGH"
    echo "  [3] 一鍵封鎖 HIGH + MEDIUM | One-click block HIGH + MEDIUM"
    echo "  [4] 白名單指定端口 | Whitelist selected ports"
    echo "  [5] 白名單 HIGH | Whitelist HIGH ports"
    echo "  [6] 白名單 HIGH + MEDIUM | Whitelist HIGH + MEDIUM ports"
    echo "  [7] 移除白名單（指定端口）| Remove whitelist from selected ports"
    echo "  [0] 返回 | Back"
    local action choice whitelist_entries
    action="$(menu_read '請輸入選項 | Select [0-7]: ')"
    case "$action" in
      1)
        menu_choose_ip_family
        select_rows_interactively
        for choice in "${SELECTED_RESULT_ROWS[@]}"; do
          IFS=$'\t' read -r port proto service proc jtype risk reason replay_types replay_hits <<<"$choice"
          apply_iptables_block "$proto" "$port" "$FIREWALL_IP_FAMILY" \
            && log_info "Blocked ${proto}:${port} (family=${FIREWALL_IP_FAMILY})" \
            || WARNINGS+=("Failed to block ${proto}:${port}")
        done
        ;;
      2)
        menu_choose_ip_family
        select_rows_by_mode "high"
        for choice in "${SELECTED_RESULT_ROWS[@]}"; do
          IFS=$'\t' read -r port proto service proc jtype risk reason replay_types replay_hits <<<"$choice"
          apply_iptables_block "$proto" "$port" "$FIREWALL_IP_FAMILY" \
            && log_info "Blocked ${proto}:${port} (family=${FIREWALL_IP_FAMILY})" \
            || WARNINGS+=("Failed to block ${proto}:${port}")
        done
        ;;
      3)
        menu_choose_ip_family
        select_rows_by_mode "high_medium"
        for choice in "${SELECTED_RESULT_ROWS[@]}"; do
          IFS=$'\t' read -r port proto service proc jtype risk reason replay_types replay_hits <<<"$choice"
          apply_iptables_block "$proto" "$port" "$FIREWALL_IP_FAMILY" \
            && log_info "Blocked ${proto}:${port} (family=${FIREWALL_IP_FAMILY})" \
            || WARNINGS+=("Failed to block ${proto}:${port}")
        done
        ;;
      4)
        menu_choose_ip_family
        select_rows_interactively
        if [[ "${#SELECTED_RESULT_ROWS[@]}" -gt 0 ]]; then
          whitelist_entries="$(menu_read '輸入白名單 IP/CIDR，逗號分隔 | Enter whitelist IP/CIDR list: ')"
          if [[ -n "$whitelist_entries" ]]; then
            apply_whitelist_to_rows "$whitelist_entries"
          fi
        fi
        ;;
      5)
        menu_choose_ip_family
        select_rows_by_mode "high"
        if [[ "${#SELECTED_RESULT_ROWS[@]}" -gt 0 ]]; then
          whitelist_entries="$(menu_read '輸入白名單 IP/CIDR，逗號分隔 | Enter whitelist IP/CIDR list: ')"
          if [[ -n "$whitelist_entries" ]]; then
            apply_whitelist_to_rows "$whitelist_entries"
          fi
        fi
        ;;
      6)
        menu_choose_ip_family
        select_rows_by_mode "high_medium"
        if [[ "${#SELECTED_RESULT_ROWS[@]}" -gt 0 ]]; then
          whitelist_entries="$(menu_read '輸入白名單 IP/CIDR，逗號分隔 | Enter whitelist IP/CIDR list: ')"
          if [[ -n "$whitelist_entries" ]]; then
            apply_whitelist_to_rows "$whitelist_entries"
          fi
        fi
        ;;
      7)
        menu_choose_ip_family
        select_rows_interactively
        if [[ "${#SELECTED_RESULT_ROWS[@]}" -gt 0 ]]; then
          remove_whitelist_from_rows
        fi
        ;;
      0)
        return
        ;;
      *)
        log_warn "Invalid choice."
        ;;
    esac
  done
}

menu_firewall_actions() {
  while true; do
    log_ui "防火牆選單 | Firewall Menu"
    echo "  [1] 立即封鎖端口 | Block ports now (tcp:443,udp:51820)"
    echo "  [2] 立即解封端口 | Unblock ports now (tcp:443,udp:51820)"
    echo "  [0] 返回 | Back"
    local c
    c="$(menu_read '請輸入選項 | Select [0-2]: ')"
    case "$c" in
      1)
        menu_choose_ip_family
        BLOCK_LIST="$(menu_read 'Enter block list: ')"
        UNBLOCK_LIST=""
        FIREWALL_ONLY=1
        apply_block_unblock_lists
        FIREWALL_ONLY=0
        BLOCK_LIST=""
        pause_enter
        ;;
      2)
        menu_choose_ip_family
        UNBLOCK_LIST="$(menu_read 'Enter unblock list: ')"
        BLOCK_LIST=""
        FIREWALL_ONLY=1
        apply_block_unblock_lists
        FIREWALL_ONLY=0
        UNBLOCK_LIST=""
        pause_enter
        ;;
      0)
        return
        ;;
      *)
        log_warn "Invalid choice."
        ;;
    esac
  done
}

menu_systemd_actions() {
  while true; do
    log_ui "服務選單 | Service Menu"
    echo "  [1] 安裝並啟用服務 | Install + enable + start service"
    echo "  [2] 查看服務狀態 | Service status"
    echo "  [3] 重新啟動服務 | Service restart"
    echo "  [4] 停止服務 | Service stop"
    echo "  [5] 啟動服務 | Service start"
    echo "  [0] 返回 | Back"
    local c
    c="$(menu_read '請輸入選項 | Select [0-5]: ')"
    case "$c" in
      1)
        INSTALL_SYSTEMD=1
        install_systemd_service || true
        INSTALL_SYSTEMD=0
        pause_enter
        ;;
      2)
        if have_cmd systemctl; then
          systemctl status "${SYSTEMD_SERVICE_NAME}.service" --no-pager || true
        else
          log_warn "systemctl not found."
        fi
        pause_enter
        ;;
      3)
        if have_cmd systemctl; then
          systemctl restart "${SYSTEMD_SERVICE_NAME}.service" || true
          systemctl status "${SYSTEMD_SERVICE_NAME}.service" --no-pager || true
        else
          log_warn "systemctl not found."
        fi
        pause_enter
        ;;
      4)
        if have_cmd systemctl; then
          systemctl stop "${SYSTEMD_SERVICE_NAME}.service" || true
        else
          log_warn "systemctl not found."
        fi
        pause_enter
        ;;
      5)
        if have_cmd systemctl; then
          systemctl start "${SYSTEMD_SERVICE_NAME}.service" || true
          systemctl status "${SYSTEMD_SERVICE_NAME}.service" --no-pager || true
        else
          log_warn "systemctl not found."
        fi
        pause_enter
        ;;
      0)
        return
        ;;
      *)
        log_warn "Invalid choice."
        ;;
    esac
  done
}

run_menu_mode() {
  while true; do
    log_ui "${BRAND_TITLE} | 主選單 Main Menu"
    echo "  [1] 簡易掃描 | Simple Scan"
    echo "  [2] 完整掃描（深度 Nmap + OpenGFW）| Complete Scan"
    echo "  [4] systemd 服務管理 | Service management"
    echo "  [5] 設定可信端口段 | Set trusted ports/ranges"
    echo "  [8] 掃描結果解讀與封鎖 | Review results and block"
    echo "  [0] 退出 | Exit"
    echo
    echo "可信端口段 | Trusted ports: ${TRUSTED_PORTS:-<none>}"
    echo "結果目錄 | Result directory: ${RESULT_DIR:-<unset>}"
    if [[ -n "$JUDGEMENT_LATEST_FILE" ]]; then
      echo "最新判斷檔 | Latest judgement file: $JUDGEMENT_LATEST_FILE"
    fi
    if [[ -n "$OVERVIEW_LATEST_FILE" ]]; then
      echo "最新總覽檔 | Latest overview file: $OVERVIEW_LATEST_FILE"
    fi
    local c
    c="$(menu_read '請輸入選項 | Select [0,1,2,4,5,8]: ')"
    case "$c" in
      1)
        prepare_default_profile
        SCAN_MODE="quick"
        run_once || log_warn "檢測未完成 | Detection did not complete."
        pause_enter
        ;;
      2)
        prepare_default_profile
        SCAN_MODE="full"
        log_info "Complete Scan uses optimized deep Nmap detection, faster than version-all."
        RUN_OPENGFW_REPLAY=1
        REPLAY_CAPTURE_INTERFACE="$(menu_read '抓包介面（預設 any，如 eth0/ens3/lo）| Capture interface: ')"
        if [[ -z "$REPLAY_CAPTURE_INTERFACE" ]]; then
          REPLAY_CAPTURE_INTERFACE="any"
        fi
        REPLAY_CAPTURE_SECONDS="$(menu_read '抓包秒數（預設 120）| Capture seconds: ')"
        if [[ -z "$REPLAY_CAPTURE_SECONDS" ]]; then
          REPLAY_CAPTURE_SECONDS=120
        fi
        if [[ ! "$REPLAY_CAPTURE_SECONDS" =~ ^[0-9]+$ ]] || (( REPLAY_CAPTURE_SECONDS < 5 )); then
          REPLAY_CAPTURE_SECONDS=120
        fi
        local want_probe
        want_probe="$(menu_read '回放時是否加主動探測流量？ | Replay with active probe traffic? [y/N]: ')"
        if [[ "$want_probe" == "y" || "$want_probe" == "Y" ]]; then
          REPLAY_WITH_PROBE=1
          PROBE_TRAFFIC=1
          PROBE_ROUNDS=2
        fi
        log_info "進階模式會以 OpenGFW 回放 pcap | Advanced mode runs OpenGFW replay from captured pcap."
        run_once || log_warn "檢測未完成 | Detection did not complete."
        pause_enter
        ;;
      4)
        menu_systemd_actions
        ;;
      5)
        TRUSTED_PORTS="$(menu_read '可信端口段（如 tcp:32000-32999,tcp:443）| Trusted ports list: ')"
        log_info "可信端口段已設定 | Trusted ports set: ${TRUSTED_PORTS:-<none>}"
        pause_enter
        ;;
      8)
        menu_review_latest_results
        pause_enter
        ;;
      0)
        log_info "Exit."
        return
        ;;
      *)
        log_warn "Invalid choice."
        ;;
    esac
  done
}

main() {
  local arg_count="$#"
  SCRIPT_PATH="$(readlink -f "$0" 2>/dev/null || echo "$0")"
  SCRIPT_DIR="$(cd "$(dirname "$SCRIPT_PATH")" && pwd)"
  RESULT_DIR="${SCRIPT_DIR}/logs"
  if [[ -z "$OUTPUT_DIR" ]]; then
    OUTPUT_DIR="$RESULT_DIR"
  fi
  JUDGEMENT_LATEST_FILE="${RESULT_DIR}/latest-port-judgement.tsv"
  OVERVIEW_LATEST_FILE="${SCRIPT_DIR}/latest-port-risk-overview.md"
  mkdir -p "$RESULT_DIR" >/dev/null 2>&1 || true

  parse_args "$@"
  install_systemd_service
  if [[ "$INSTALL_SYSTEMD" == "1" && "$MENU_MODE" != "1" ]]; then
    exit 0
  fi

  log_ui "${BRAND_TITLE} | OpenGFW + Nmap 自查工具 v${VERSION}"

  if [[ "$FIREWALL_ONLY" == "1" ]]; then
    apply_block_unblock_lists
    log_info "Firewall-only mode complete."
    exit 0
  fi

  download_opengfw_binary_if_needed

  need_cmd ss || exit 1
  need_cmd nmap || exit 1
  need_cmd awk || exit 1
  need_cmd grep || exit 1
  need_cmd sed || exit 1

  if [[ "$MENU_MODE" == "1" ]] || { [[ "$arg_count" -eq 0 ]] && [[ -t 0 ]] && [[ -t 1 ]] && [[ "$DAEMON_MODE" != "1" ]]; }; then
    run_menu_mode
    exit 0
  fi

  if [[ "$DAEMON_MODE" == "1" ]]; then
    log_info "常駐模式已啟用 | Daemon mode enabled. Interval: ${DAEMON_INTERVAL_SECONDS}s"
    while true; do
      run_once
      sleep "$DAEMON_INTERVAL_SECONDS"
    done
  else
    run_once
    echo
    log_info "完成 | Done. 預設為先報告後處置（被動、無自動封鎖）| report-first passive mode."
  fi
}

main "$@"
