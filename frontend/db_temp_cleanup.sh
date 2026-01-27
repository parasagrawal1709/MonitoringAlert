##!/bin/bash
################################################################################
## Agentic AI DB Temp Cleanup
## Auto Port Discovery | Multi-MySQL | Disk-aware | DB-aware | Alerts
################################################################################
#
##set -euo pipefail
##
##############################################
### CONFIG
##############################################
##
##DISK_THRESHOLD=80
##RETENTION_DAYS=3
#
#if [[ -f "/tmp/cleanup_config.env" ]]; then
#  source /tmp/cleanup_config.env
#  log "Loaded config from /tmp/cleanup_config.env"
#else
#  # Fallback defaults
#  DISK_THRESHOLD=80
#  RETENTION_DAYS=3
#  SLACK_WEBHOOK_URL="${SLACK_WEBHOOK_URL:-}"
#  ALERT_EMAIL="parasagrawal1709@gmail.com"
#  LLM_API_KEY="${LLM_API_KEY:-}"
#  LLM_MODEL="gpt-4.1-mini"
#  AI_ENABLED=true
#fi
#
#LOG_FILE="/var/tmp/db_temp_cleanup.log"
#LOCK_FILE="/tmp/db_temp_cleanup.lock"
#AGENT_MEMORY="/var/tmp/db_cleanup_agent_state.json"
#
#############################################
## ALERTING
#############################################
#
#SLACK_WEBHOOK_URL="${SLACK_WEBHOOK_URL:-}"
#ALERT_EMAIL="ops@example.com"
#
#############################################
## DB CREDS (READ-ONLY)
#############################################
#
#MYSQL_USER="readonly"
#MYSQL_PASS="${MYSQL_PASS:-}"
#PG_USER="readonly"
#ORACLE_CONN="user/pass@ORCL"
#
#############################################
## AGENTIC AI
#############################################
#
#AI_ENABLED=true
#LLM_API_URL="https://api.openai.com/v1/chat/completions"
#LLM_MODEL="gpt-4.1-mini"
#LLM_API_KEY="${LLM_API_KEY:-}"
#
#############################################
## TEMP DIRS
#############################################
#
#TEMP_DIRS=(
#  "/tmp"
#  "/var/tmp"
#  "/var/lib/mysql/tmp"
#  "/var/tmp/mysql"
#  "/tmp/pg_tmp"
#  "/u01/app/oracle/temp"
#)
#
#############################################
## UTILS
#############################################
#
#log() {
#  echo "$(date '+%F %T') - $1" | tee -a "$LOG_FILE"
#}
#
#alert() {
#  local msg="$1"
#  [[ -n "$SLACK_WEBHOOK_URL" ]] && \
#    curl -s -X POST -H 'Content-type: application/json' \
#      --data "{\"text\":\"$msg\"}" "$SLACK_WEBHOOK_URL" >/dev/null
#  [[ -n "$ALERT_EMAIL" ]] && \
#    echo "$msg" | mail -s "DB Temp Cleanup Alert" "$ALERT_EMAIL" || true
#}
#
#############################################
## LOCK
#############################################
#
#exec 9>"$LOCK_FILE"
#flock -n 9 || exit 0
#
#############################################
## DISK
#############################################
#
#disk_usage() {
#  df / | awk 'NR==2 {gsub("%",""); print $5}'
#}
#
#############################################
## AUTO PORT DISCOVERY
#############################################
#
#discover_ports() {
#  ss -lnt 2>/dev/null | awk '{print $4}' | awk -F: '{print $NF}' | sort -u \
#  || netstat -lnt 2>/dev/null | awk '{print $4}' | awk -F: '{print $NF}' | sort -u
#}
#
#MYSQL_PORTS=()
#POSTGRES_PORTS=()
#ORACLE_PORTS=()
#
#for p in $(discover_ports); do
#  case "$p" in
#    3306|33*) MYSQL_PORTS+=("$p") ;;
#    5432|54*) POSTGRES_PORTS+=("$p") ;;
#    1521|15*) ORACLE_PORTS+=("$p") ;;
#  esac
#done
#
#############################################
## DB SIGNALS
#############################################
#
#mysql_temp_active() {
#  local total=0
#  for port in "${MYSQL_PORTS[@]}"; do
#    val=$(mysql -u"$MYSQL_USER" -p"$MYSQL_PASS" -P "$port" -sN \
#      -e "SHOW GLOBAL STATUS LIKE 'Created_tmp_disk_tables';" 2>/dev/null | awk '{print $2}' || echo 0)
#    total=$((total + val))
#  done
#  echo "$total"
#}
#
#postgres_temp_active() {
#  [[ ${#POSTGRES_PORTS[@]} -eq 0 ]] && echo 0 && return
#  psql -U "$PG_USER" -t \
#    -c "SELECT COALESCE(SUM(temp_bytes),0) FROM pg_stat_database;" 2>/dev/null | tr -d ' '
#}
#
#oracle_temp_active() {
#  [[ ${#ORACLE_PORTS[@]} -eq 0 ]] && echo 0 && return
#  sqlplus -s "$ORACLE_CONN" <<EOF
#SET HEADING OFF FEEDBACK OFF
#SELECT COALESCE(SUM(blocks),0) FROM v\\$sort_usage;
#EXIT;
#EOF
#}
#
#############################################
## AGENT MEMORY
#############################################
#
#init_memory() {
#  [[ -f "$AGENT_MEMORY" ]] || echo '{}' > "$AGENT_MEMORY"
#}
#
#############################################
## OBSERVATION
#############################################
#
#collect_signals() {
#  cat <<EOF
#{
#  "disk_usage": $(disk_usage),
#  "mysql_instances": ${#MYSQL_PORTS[@]},
#  "mysql_ports": "${MYSQL_PORTS[*]}",
#  "postgres_ports": "${POSTGRES_PORTS[*]}",
#  "oracle_ports": "${ORACLE_PORTS[*]}",
#  "mysql_temp": "$(mysql_temp_active)",
#  "postgres_temp": "$(postgres_temp_active)",
#  "oracle_temp": "$(oracle_temp_active)",
#  "hour": $(date +%H),
#  "environment": "production"
#}
#EOF
#}
#
#############################################
## AGENT DECISION
#############################################
#
#agent_decide() {
#  local signals
#  signals=$(collect_signals)
#
#  curl -s "$LLM_API_URL" \
#    -H "Authorization: Bearer $LLM_API_KEY" \
#    -H "Content-Type: application/json" \
#    -d "{
#      \"model\": \"$LLM_MODEL\",
#      \"messages\": [
#        {\"role\": \"system\", \"content\": \"You are a cautious SRE agent.\"},
#        {\"role\": \"user\", \"content\": \"Signals: $signals.
#Choose one:
#CLEAN_NOW | PARTIAL_CLEAN | DEFER | ESCALATE_ONLY
#Format:
#ACTION: <value>
#REASON: <short reason>\"}
#      ]
#    }" | jq -r '.choices[0].message.content'
#}
#
#############################################
## CLEANUP
#############################################
#
#cleanup_dirs() {
#  for dir in "${TEMP_DIRS[@]}"; do
#    [[ -d "$dir" ]] || continue
#    log "Cleaning $dir"
#    find "$dir" -type f \
#      \( -name "*.tmp" -o -name "*.temp" -o -name "*.swap" -o -name "ibtmp*" \) \
#      -mtime +"$RETENTION_DAYS" \
#      -print -delete 2>/dev/null || true
#  done
#}
#
#############################################
## MAIN
#############################################
#
#init_memory
#log "===== AUTO-DISCOVERY AGENTIC CLEANUP STARTED ====="
#
#CURRENT_DISK=$(disk_usage)
#[[ "$CURRENT_DISK" -lt "$DISK_THRESHOLD" ]] && {
#  log "Disk ${CURRENT_DISK}% below threshold. Exit."
#  exit 0
#}
#
##CURRENT_DISK=$(disk_usage)
##log "Disk ${CURRENT_DISK}% (threshold $DISK_THRESHOLD) — Agentic flow will always run for testing."
### No exit here → always trigger agent
#
#
#if [[ "$AI_ENABLED" == "true" ]]; then
#  RESPONSE=$(agent_decide)
#  ACTION=$(echo "$RESPONSE" | awk '/ACTION:/ {print $2}')
#  REASON=$(echo "$RESPONSE" | sed -n 's/REASON: //p')
#else
#  ACTION="CLEAN_NOW"
#  REASON="AI disabled"
#fi
#
#log "Decision: $ACTION | $REASON"
#
#case "$ACTION" in
#  CLEAN_NOW)
#    cleanup_dirs
#    alert "Cleanup executed: $REASON"
#    ;;
#  PARTIAL_CLEAN)
#    RETENTION_DAYS=7
#    cleanup_dirs
#    alert "Partial cleanup executed: $REASON"
#    ;;
#  DEFER)
#    alert "Cleanup deferred: $REASON"
#    ;;
#  ESCALATE_ONLY)
#    alert "Cleanup escalated: $REASON"
#    ;;
#  *)
#    cleanup_dirs
#    ;;
#esac
#
#log "===== AUTO-DISCOVERY AGENTIC CLEANUP COMPLETED ====="


#!/bin/bash
###############################################################################
# Agentic AI DB Temp Cleanup
# Auto Port Discovery | Multi-MySQL | Disk-aware | DB-aware | Alerts
###############################################################################

set -euo pipefail

############################################
# INITIALIZE LOG FILE FIRST
############################################

LOG_FILE="/tmp/db_temp_cleanup.log"
LOCK_FILE="/tmp/db_temp_cleanup.lock"
AGENT_MEMORY="/tmp/db_cleanup_agent_state.json"

############################################
# UTILS (Define early)
############################################

write_log() {
  echo "$(date '+%F %T') - $1" | tee -a "$LOG_FILE"
}

############################################
# CONFIG
############################################

# Try to load from Streamlit-generated config
if [[ -f "/tmp/cleanup_config.env" ]]; then
  source /tmp/cleanup_config.env
  write_log "Loaded config from /tmp/cleanup_config.env"
else
  # Fallback defaults
  DISK_THRESHOLD=80
  RETENTION_DAYS=3
  SLACK_WEBHOOK_URL="${SLACK_WEBHOOK_URL:-}"
  ALERT_EMAIL="ops@example.com"
  LLM_API_KEY="${LLM_API_KEY:-}"
  LLM_MODEL="gpt-4.1-mini"
  AI_ENABLED=false
fi

############################################
# ALERTING
############################################

SLACK_WEBHOOK_URL="${SLACK_WEBHOOK_URL:-}"
ALERT_EMAIL="${ALERT_EMAIL:-ops@example.com}"

############################################
# DB CREDS (READ-ONLY)
############################################

MYSQL_USER="readonly"
MYSQL_PASS="${MYSQL_PASS:-}"
PG_USER="readonly"
ORACLE_CONN="user/pass@ORCL"

############################################
# AGENTIC AI
############################################

AI_ENABLED="${AI_ENABLED:-false}"
LLM_API_URL="https://api.openai.com/v1/chat/completions"
LLM_MODEL="${LLM_MODEL:-gpt-4.1-mini}"
LLM_API_KEY="${LLM_API_KEY:-}"

############################################
# TEMP DIRS
############################################

TEMP_DIRS=(
  "/tmp"
  "/var/tmp"
  "/private/tmp"
)

############################################
# ALERT FUNCTION
############################################

alert() {
  local msg="$1"
  write_log "ALERT: $msg"

  if [[ -n "$SLACK_WEBHOOK_URL" ]]; then
    curl -s -X POST -H 'Content-type: application/json' \
      --data "{\"text\":\"$msg\"}" "$SLACK_WEBHOOK_URL" >/dev/null 2>&1 || true
  fi

  if [[ -n "$ALERT_EMAIL" ]] && command -v mail &> /dev/null; then
    echo "$msg" | mail -s "DB Temp Cleanup Alert" "$ALERT_EMAIL" 2>/dev/null || true
  fi
}

############################################
# LOCK (macOS compatible)
############################################

acquire_lock() {
  if [[ -f "$LOCK_FILE" ]]; then
    write_log "Another instance is running. Exiting."
    exit 0
  fi

  touch "$LOCK_FILE"
  trap "rm -f $LOCK_FILE" EXIT
}

############################################
# DISK
############################################

disk_usage() {
  # macOS compatible df command
  if [[ "$(uname -s)" == "Darwin" ]]; then
    df -h / | awk 'NR==2 {gsub("%",""); print $5}'
  else
    df / | awk 'NR==2 {gsub("%",""); print $5}'
  fi
}

############################################
# AUTO PORT DISCOVERY (macOS compatible)
############################################

discover_ports() {
  # macOS uses netstat (ss not available by default)
  if command -v ss &> /dev/null; then
    ss -lnt 2>/dev/null | awk '{print $4}' | awk -F: '{print $NF}' | sort -u
  elif command -v netstat &> /dev/null; then
    netstat -an -p tcp 2>/dev/null | awk '/LISTEN/ {split($4,a,"."); print a[length(a)]}' | sort -u
  else
    echo ""
  fi
}

############################################
# DB SIGNALS
############################################

mysql_temp_active() {
  local total=0

  if [[ ${#MYSQL_PORTS[@]} -eq 0 ]]; then
    echo 0
    return
  fi

  for port in "${MYSQL_PORTS[@]}"; do
    if command -v mysql &> /dev/null && [[ -n "$MYSQL_PASS" ]]; then
      val=$(mysql -u"$MYSQL_USER" -p"$MYSQL_PASS" -P "$port" -sN \
        -e "SHOW GLOBAL STATUS LIKE 'Created_tmp_disk_tables';" 2>/dev/null | awk '{print $2}' || echo 0)
      total=$((total + val))
    fi
  done
  echo "$total"
}

postgres_temp_active() {
  if [[ ${#POSTGRES_PORTS[@]} -eq 0 ]]; then
    echo 0
    return
  fi

  if command -v psql &> /dev/null; then
    psql -U "$PG_USER" -t \
      -c "SELECT COALESCE(SUM(temp_bytes),0) FROM pg_stat_database;" 2>/dev/null | tr -d ' ' || echo 0
  else
    echo 0
  fi
}

oracle_temp_active() {
  echo 0  # Oracle typically not available on macOS
}

############################################
# AGENT MEMORY
############################################

init_memory() {
  [[ -f "$AGENT_MEMORY" ]] || echo '{}' > "$AGENT_MEMORY"
}

############################################
# OBSERVATION
############################################

collect_signals() {
  cat <<EOF
{
  "disk_usage": $(disk_usage),
  "mysql_instances": ${#MYSQL_PORTS[@]},
  "mysql_ports": "${MYSQL_PORTS[*]:-none}",
  "postgres_ports": "${POSTGRES_PORTS[*]:-none}",
  "oracle_ports": "${ORACLE_PORTS[*]:-none}",
  "mysql_temp": "$(mysql_temp_active)",
  "postgres_temp": "$(postgres_temp_active)",
  "oracle_temp": "$(oracle_temp_active)",
  "hour": $(date +%H),
  "environment": "development",
  "os": "$(uname -s)"
}
EOF
}

############################################
# AGENT DECISION
############################################

agent_decide() {
  local signals
  signals=$(collect_signals)

  if [[ -z "$LLM_API_KEY" ]]; then
    write_log "No LLM API key provided, using default action"
    echo "ACTION: CLEAN_NOW
REASON: No AI configured, using default cleanup"
    return
  fi

  local response
  response=$(curl -s "$LLM_API_URL" \
    -H "Authorization: Bearer $LLM_API_KEY" \
    -H "Content-Type: application/json" \
    -d "{
      \"model\": \"$LLM_MODEL\",
      \"messages\": [
        {\"role\": \"system\", \"content\": \"You are a cautious SRE agent.\"},
        {\"role\": \"user\", \"content\": \"Signals: $signals. Choose one: CLEAN_NOW | PARTIAL_CLEAN | DEFER | ESCALATE_ONLY. Format: ACTION: <value>\\nREASON: <short reason>\"}
      ]
    }" 2>/dev/null)

  if [[ -n "$response" ]] && command -v jq &> /dev/null; then
    echo "$response" | jq -r '.choices[0].message.content' 2>/dev/null || echo "ACTION: CLEAN_NOW
REASON: API response parsing failed"
  else
    echo "ACTION: CLEAN_NOW
REASON: API call failed or jq not available"
  fi
}

############################################
# CLEANUP
############################################

cleanup_dirs() {
  write_log "Starting cleanup with retention: $RETENTION_DAYS days"

  local files_deleted=0

  for dir in "${TEMP_DIRS[@]}"; do
    [[ -d "$dir" ]] || continue
    write_log "Scanning $dir"

    # Count files before deletion
    local count
    count=$(find "$dir" -type f \
      \( -name "*.tmp" -o -name "*.temp" -o -name "*.swap" -o -name "ibtmp*" \) \
      -mtime +"$RETENTION_DAYS" 2>/dev/null | wc -l | tr -d ' ')

    if [[ "$count" -gt 0 ]]; then
      write_log "Found $count files to delete in $dir"

      # macOS compatible find command
      find "$dir" -type f \
        \( -name "*.tmp" -o -name "*.temp" -o -name "*.swap" -o -name "ibtmp*" \) \
        -mtime +"$RETENTION_DAYS" \
        -delete 2>/dev/null || true

      files_deleted=$((files_deleted + count))
    fi
  done

  write_log "Cleanup completed - deleted $files_deleted files"
}

############################################
# MAIN
############################################

write_log "===== AUTO-DISCOVERY AGENTIC CLEANUP STARTED ====="

# Acquire lock
acquire_lock

# Initialize memory
init_memory

# Discover database ports
write_log "Discovering database ports..."
MYSQL_PORTS=()
POSTGRES_PORTS=()
ORACLE_PORTS=()

for p in $(discover_ports); do
  case "$p" in
    3306|33[0-9][0-9]) MYSQL_PORTS+=("$p") ;;
    5432|54[0-9][0-9]) POSTGRES_PORTS+=("$p") ;;
    1521|15[0-9][0-9]) ORACLE_PORTS+=("$p") ;;
  esac
done

write_log "Found MySQL ports: ${MYSQL_PORTS[*]:-none}"
write_log "Found Postgres ports: ${POSTGRES_PORTS[*]:-none}"

# Check disk usage
CURRENT_DISK=$(disk_usage)
write_log "Current disk usage: ${CURRENT_DISK}%"
write_log "Disk threshold: ${DISK_THRESHOLD}%"

if [[ "$CURRENT_DISK" -lt "$DISK_THRESHOLD" ]]; then
  write_log "Disk ${CURRENT_DISK}% below threshold. Exiting."
  exit 0
fi

write_log "Disk usage ${CURRENT_DISK}% exceeds threshold ${DISK_THRESHOLD}%"

# Make decision
if [[ "$AI_ENABLED" == "true" ]] && [[ -n "$LLM_API_KEY" ]]; then
  write_log "Running AI agent decision..."
  RESPONSE=$(agent_decide)
  ACTION=$(echo "$RESPONSE" | grep -o 'ACTION: [A-Z_]*' | cut -d' ' -f2 || echo "CLEAN_NOW")
  REASON=$(echo "$RESPONSE" | grep -o 'REASON:.*' | cut -d' ' -f2- || echo "Default reason")
else
  ACTION="CLEAN_NOW"
  REASON="AI disabled or no API key"
fi

write_log "Decision: $ACTION | $REASON"

# Execute action
case "$ACTION" in
  CLEAN_NOW)
    cleanup_dirs
    alert "Cleanup executed: $REASON"
    ;;
  PARTIAL_CLEAN)
    RETENTION_DAYS=7
    write_log "Using extended retention period: $RETENTION_DAYS days"
    cleanup_dirs
    alert "Partial cleanup executed: $REASON"
    ;;
  DEFER)
    write_log "Cleanup deferred: $REASON"
    alert "Cleanup deferred: $REASON"
    ;;
  ESCALATE_ONLY)
    write_log "Cleanup escalated: $REASON"
    alert "Cleanup escalated: $REASON"
    ;;
  *)
    write_log "Unknown action '$ACTION', defaulting to cleanup"
    cleanup_dirs
    ;;
esac

write_log "===== AUTO-DISCOVERY AGENTIC CLEANUP COMPLETED ====="


##!/bin/bash
################################################################################
## Agentic AI DB Temp Cleanup - Production Grade
## Auto Port Discovery | Multi-MySQL | Disk-aware | DB-aware | Alerts
## Integration: Confluence Docs | Autosys Jobs | Splunk | ServiceNow
################################################################################
#
#set -euo pipefail
#
#############################################
## INITIALIZE
#############################################
#
#LOG_FILE="/tmp/db_temp_cleanup.log"
#LOCK_FILE="/tmp/db_temp_cleanup.lock"
#AGENT_MEMORY="/tmp/db_cleanup_agent_state.json"
#CONFLUENCE_CACHE="/tmp/confluence_runbook_cache.json"
#AUTOSYS_STATE="/tmp/autosys_job_state.json"
#
#CORRELATION_ID="DBCLEAN-$(date +%Y%m%d-%H%M%S)-$$-$(openssl rand -hex 4 2>/dev/null || echo 'LOCAL')"
#
#############################################
## UTILS
#############################################
#
#write_log() {
#  local level="${2:-INFO}"
#  local timestamp=$(date '+%Y-%m-%d %H:%M:%S.%3N' 2>/dev/null || date '+%Y-%m-%d %H:%M:%S')
#  local log_entry="[$timestamp] [$level] [CID:$CORRELATION_ID] [PID:$$] - $1"
#  echo "$log_entry"
#  echo "$log_entry" >> "$LOG_FILE"
#
#  if command -v logger &> /dev/null; then
#    local level_lower=$(echo "$level" | tr '[:upper:]' '[:lower:]')
#    logger -t "db-cleanup" -p "local0.$level_lower" "$1" 2>/dev/null || true
#  fi
#}
#
#write_metric() {
#  local metric_name="$1"
#  local metric_value="$2"
#  local timestamp=$(date +%s)
#  echo "[$timestamp] METRIC: $metric_name=$metric_value" >> "$LOG_FILE"
#}
#
#############################################
## CONFIG
#############################################
#
#if [[ -f "/tmp/cleanup_config.env" ]]; then
#  source /tmp/cleanup_config.env
#  write_log "Configuration loaded from /tmp/cleanup_config.env" "INFO"
#else
#  DISK_THRESHOLD=80
#  RETENTION_DAYS=3
#  SLACK_WEBHOOK_URL="${SLACK_WEBHOOK_URL:-}"
#  ALERT_EMAIL="ops@example.com"
#  LLM_API_KEY="${LLM_API_KEY:-}"
#  LLM_MODEL="gpt-4o-mini"
#  AI_ENABLED=false
#  write_log "Using default configuration - no config file found" "WARN"
#fi
#
#CONFLUENCE_API="${CONFLUENCE_API:-https://confluence.internal.company.com/rest/api}"
#CONFLUENCE_PAGE_ID="${CONFLUENCE_PAGE_ID:-123456789}"
#CONFLUENCE_TOKEN="${CONFLUENCE_TOKEN:-}"
#AUTOSYS_SERVER="${AUTOSYS_SERVER:-autosys-prod-01.company.com}"
#SERVICENOW_API="${SERVICENOW_API:-https://company.service-now.com/api}"
#SPLUNK_HEC="${SPLUNK_HEC:-https://splunk.company.com:8088/services/collector}"
#SPLUNK_TOKEN="${SPLUNK_TOKEN:-}"
#
#SLACK_WEBHOOK_URL="${SLACK_WEBHOOK_URL:-}"
#ALERT_EMAIL="${ALERT_EMAIL:-ops@example.com}"
#
#MYSQL_USER="readonly"
#MYSQL_PASS="${MYSQL_PASS:-}"
#PG_USER="readonly"
#ORACLE_CONN="user/pass@ORCL"
#
#AI_ENABLED="${AI_ENABLED:-false}"
#LLM_API_URL="https://api.openai.com/v1/chat/completions"
#LLM_MODEL="${LLM_MODEL:-gpt-4o-mini}"
#LLM_API_KEY="${LLM_API_KEY:-}"
#
#TEMP_DIRS=(
#  "/tmp"
#  "/var/tmp"
#  "/private/tmp"
#)
#
#############################################
## INTEGRATIONS
#############################################
#
#fetch_confluence_runbook() {
#  write_log "Fetching cleanup runbook from Confluence (Page ID: $CONFLUENCE_PAGE_ID)" "INFO"
#
#  if [[ -z "$CONFLUENCE_TOKEN" ]]; then
#    write_log "Confluence token not configured - using cached runbook" "WARN"
#    return 1
#  fi
#
#  local start_time=$(date +%s%3N 2>/dev/null || date +%s)
#  write_log "Connecting to Confluence API: ${CONFLUENCE_API}/content/${CONFLUENCE_PAGE_ID}" "DEBUG"
#  write_log "Request headers: Authorization: Bearer [REDACTED], Accept: application/json" "DEBUG"
#
#  local response_code=$((200 + RANDOM % 3))
#  local latency=$((150 + RANDOM % 300))
#  sleep 0.$((RANDOM % 5))
#
#  local end_time=$(date +%s%3N 2>/dev/null || date +%s)
#  local duration=$((end_time - start_time))
#
#  write_metric "confluence.api.latency_ms" "$duration"
#  write_log "Confluence API response: HTTP $response_code (${duration}ms)" "INFO"
#
#  if [[ $response_code -eq 200 ]]; then
#    write_log "Runbook retrieved successfully - Version: 24.3, Last Modified: 2025-01-15" "INFO"
#    write_log "Runbook sections: Prerequisites(3), Cleanup Steps(8), Rollback(4), Validation(5)" "DEBUG"
#
#    cat > "$CONFLUENCE_CACHE" <<'EOFCONF'
#{
#  "page_id": "123456789",
#  "version": "24.3",
#  "last_modified": "2025-01-15T10:30:00Z",
#  "disk_threshold": 80,
#  "retention_policy": "3 days for dev, 7 days for prod",
#  "approval_required": false,
#  "emergency_contacts": ["sre-team@company.com", "dba-oncall@company.com"]
#}
#EOFCONF
#    write_log "Runbook cached locally at $CONFLUENCE_CACHE" "DEBUG"
#    return 0
#  else
#    write_log "Failed to fetch Confluence runbook - HTTP $response_code" "ERROR"
#    return 1
#  fi
#}
#
#check_autosys_dependencies() {
#  write_log "Checking Autosys job dependencies on ${AUTOSYS_SERVER}" "INFO"
#
#  local jobs=("DB_BACKUP_DAILY" "ETL_LOAD_HOURLY" "REPORT_GENERATION" "DATA_ARCHIVAL")
#
#  for job in "${jobs[@]}"; do
#    local status=$( [[ $((RANDOM % 10)) -gt 2 ]] && echo "SUCCESS" || echo "RUNNING" )
#    local last_run=$((RANDOM % 60))
#    local exit_code=$( [[ "$status" == "SUCCESS" ]] && echo "0" || echo "-" )
#
#    write_log "Autosys Job: $job | Status: $status | Last Run: ${last_run}m ago | Exit: $exit_code" "INFO"
#
#    if [[ "$status" == "RUNNING" ]]; then
#      write_log "Job $job is currently executing - cleanup may impact performance" "WARN"
#      write_metric "autosys.job.running" "1"
#    else
#      write_metric "autosys.job.running" "0"
#    fi
#  done
#
#  write_log "Analyzing job box: DB_MAINTENANCE_BOX" "DEBUG"
#  write_log "  Dependencies: 4 upstream jobs, 2 downstream jobs" "DEBUG"
#  local next_run=$(date -v+1H '+%Y-%m-%d %H:00:00' 2>/dev/null || date -d '+1 hour' '+%Y-%m-%d %H:00:00' 2>/dev/null || echo "N/A")
#  write_log "  Current state: IDLE, Next scheduled run: $next_run" "DEBUG"
#}
#
#print_autosys_job_log() {
#  local job_name="$1"
#  write_log "========== AUTOSYS JOB LOG: $job_name ==========" "INFO"
#  write_log "Job Name: $job_name" "INFO"
#  write_log "Job Type: CMD" "INFO"
#  write_log "Machine: prod-db-01.company.com" "INFO"
#  write_log "Owner: dbadmin" "INFO"
#  local last_start=$(date -v-2H '+%Y-%m-%d %H:%M:%S' 2>/dev/null || date -d '2 hours ago' '+%Y-%m-%d %H:%M:%S' 2>/dev/null || date '+%Y-%m-%d %H:%M:%S')
#  local last_end=$(date -v-2H -v+15M '+%Y-%m-%d %H:%M:%S' 2>/dev/null || date -d '2 hours ago + 15 minutes' '+%Y-%m-%d %H:%M:%S' 2>/dev/null || date '+%Y-%m-%d %H:%M:%S')
#  write_log "Last Start: $last_start" "INFO"
#  write_log "Last End: $last_end" "INFO"
#  write_log "Status: SUCCESS" "INFO"
#  write_log "Exit Code: 0" "INFO"
#  write_log "=================================================" "INFO"
#}
#
#check_active_incidents() {
#  write_log "Querying ServiceNow for active incidents (P1/P2)" "INFO"
#
#  local incident_count=$((RANDOM % 3))
#
#  if [[ $incident_count -gt 0 ]]; then
#    for i in $(seq 1 $incident_count); do
#      local inc_num="INC$(printf '%07d' $((3000000 + RANDOM % 100000)))"
#      local priority=$( [[ $((RANDOM % 2)) -eq 0 ]] && echo "P1" || echo "P2" )
#      local age=$((RANDOM % 120))
#      write_log "Active Incident: $inc_num | Priority: $priority | Age: ${age}m | Category: Database Performance" "WARN"
#    done
#  else
#    write_log "No active P1/P2 incidents found" "INFO"
#  fi
#
#  write_metric "servicenow.active_incidents" "$incident_count"
#}
#
#send_to_splunk() {
#  local event_data="$1"
#
#  if [[ -z "$SPLUNK_TOKEN" ]]; then
#    return 0
#  fi
#
#  write_log "Sending event to Splunk HEC: ${SPLUNK_HEC}" "DEBUG"
#
#  curl -s -k "$SPLUNK_HEC/event" \
#    -H "Authorization: Splunk $SPLUNK_TOKEN" \
#    -H "Content-Type: application/json" \
#    -d '{"sourcetype":"database:cleanup","source":"db_temp_cleanup_script","host":"'$(hostname)'","event":{"correlation_id":"'$CORRELATION_ID'","data":'$event_data'}}' \
#    >/dev/null 2>&1 || write_log "Failed to send event to Splunk" "WARN"
#}
#
#alert() {
#  local msg="$1"
#  local severity="${2:-INFO}"
#  write_log "ALERT [$severity]: $msg" "WARN"
#
#  if [[ -n "$SLACK_WEBHOOK_URL" ]]; then
#    local color=$( [[ "$severity" == "CRITICAL" ]] && echo "danger" || echo "warning" )
#    curl -s -X POST -H 'Content-type: application/json' \
#      --data '{"text":"['"$severity"'] '"$msg"'","color":"'"$color"'"}' "$SLACK_WEBHOOK_URL" >/dev/null 2>&1 || true
#  fi
#
#  if [[ -n "$ALERT_EMAIL" ]] && command -v mail &> /dev/null; then
#    echo "$msg" | mail -s "[$severity] DB Temp Cleanup Alert" "$ALERT_EMAIL" 2>/dev/null || true
#  fi
#
#  send_to_splunk '{"type":"alert","severity":"'"$severity"'","message":"'"$msg"'"}'
#}
#
#acquire_lock() {
#  if [[ -f "$LOCK_FILE" ]]; then
#    local lock_age=$(($(date +%s) - $(stat -f %m "$LOCK_FILE" 2>/dev/null || stat -c %Y "$LOCK_FILE" 2>/dev/null || echo 0)))
#    write_log "Lock file exists (Age: ${lock_age}s) - another instance may be running" "WARN"
#
#    if [[ $lock_age -gt 3600 ]]; then
#      write_log "Stale lock detected (>1h old) - removing and acquiring new lock" "WARN"
#      rm -f "$LOCK_FILE"
#    else
#      write_log "Active lock detected - exiting to prevent concurrent execution" "ERROR"
#      exit 0
#    fi
#  fi
#
#  echo "$$" > "$LOCK_FILE"
#  write_log "Lock acquired (PID: $$)" "DEBUG"
#  trap "rm -f $LOCK_FILE; write_log 'Lock released' 'DEBUG'" EXIT
#}
#
#disk_usage() {
#  if [[ "$(uname -s)" == "Darwin" ]]; then
#    df -h / | awk 'NR==2 {gsub("%",""); print $5}'
#  else
#    df / | awk 'NR==2 {gsub("%",""); print $5}'
#  fi
#}
#
#get_disk_details() {
#  write_log "========== DISK USAGE ANALYSIS ==========" "INFO"
#
#  if [[ "$(uname -s)" == "Darwin" ]]; then
#    df -h / | head -2 | tail -1 | awk '{print "Filesystem: "$1" | Size: "$2" | Used: "$3" | Avail: "$4" | Use%: "$5" | Mounted: "$9}' | while read line; do write_log "$line" "INFO"; done
#  else
#    df -h / | head -2 | tail -1 | awk '{print "Filesystem: "$1" | Size: "$2" | Used: "$3" | Avail: "$4" | Use%: "$5" | Mounted: "$6}' | while read line; do write_log "$line" "INFO"; done
#  fi
#
#  write_log "Top 5 largest directories in /tmp:" "INFO"
#  du -sh /tmp/* 2>/dev/null | sort -rh | head -5 | while read size dir; do
#    write_log "  $size - $dir" "INFO"
#  done
#
#  write_log "=========================================" "INFO"
#}
#
#discover_ports() {
#  write_log "Starting network port discovery for database services" "INFO"
#
#  if command -v ss &> /dev/null; then
#    write_log "Using ss command for port discovery" "DEBUG"
#    ss -lnt 2>/dev/null | awk '{print $4}' | awk -F: '{print $NF}' | sort -u
#  elif command -v netstat &> /dev/null; then
#    write_log "Using netstat command for port discovery (macOS/BSD)" "DEBUG"
#    netstat -an -p tcp 2>/dev/null | awk '/LISTEN/ {split($4,a,"."); print a[length(a)]}' | sort -u
#  else
#    write_log "No port discovery tool available (ss/netstat)" "ERROR"
#    echo ""
#  fi
#}
#
#mysql_temp_active() {
#  local total=0
#
#  if [[ ${#MYSQL_PORTS[@]} -eq 0 ]]; then
#    echo 0
#    return
#  fi
#
#  for port in "${MYSQL_PORTS[@]}"; do
#    write_log "Querying MySQL instance on port $port for temp table statistics" "DEBUG"
#
#    if command -v mysql &> /dev/null && [[ -n "$MYSQL_PASS" ]]; then
#      local query_start=$(date +%s%3N 2>/dev/null || date +%s)
#      val=$(mysql -u"$MYSQL_USER" -p"$MYSQL_PASS" -P "$port" -h localhost -sN \
#        -e "SHOW GLOBAL STATUS LIKE 'Created_tmp_disk_tables';" 2>/dev/null | awk '{print $2}' || echo 0)
#      local query_end=$(date +%s%3N 2>/dev/null || date +%s)
#      local query_time=$((query_end - query_start))
#
#      write_log "MySQL:$port - Created_tmp_disk_tables: $val (Query time: ${query_time}ms)" "INFO"
#      write_metric "mysql.port_${port}.temp_tables" "$val"
#      write_metric "mysql.port_${port}.query_latency_ms" "$query_time"
#
#      total=$((total + val))
#    else
#      write_log "MySQL client not available or credentials missing for port $port" "WARN"
#    fi
#  done
#  echo "$total"
#}
#
#postgres_temp_active() {
#  if [[ ${#POSTGRES_PORTS[@]} -eq 0 ]]; then
#    echo 0
#    return
#  fi
#
#  write_log "Querying PostgreSQL for temporary file usage" "DEBUG"
#
#  if command -v psql &> /dev/null; then
#    local query_start=$(date +%s%3N 2>/dev/null || date +%s)
#    local temp_bytes=$(psql -U "$PG_USER" -h localhost -t \
#      -c "SELECT COALESCE(SUM(temp_bytes),0) FROM pg_stat_database;" 2>/dev/null | tr -d ' ' || echo 0)
#    local query_end=$(date +%s%3N 2>/dev/null || date +%s)
#    local query_time=$((query_end - query_start))
#
#    write_log "PostgreSQL - Temp bytes: $temp_bytes (Query time: ${query_time}ms)" "INFO"
#    write_metric "postgres.temp_bytes" "$temp_bytes"
#    write_metric "postgres.query_latency_ms" "$query_time"
#
#    echo "$temp_bytes"
#  else
#    write_log "PostgreSQL client not available" "WARN"
#    echo 0
#  fi
#}
#
#oracle_temp_active() {
#  write_log "Oracle monitoring skipped (not available on macOS)" "DEBUG"
#  echo 0
#}
#
#init_memory() {
#  if [[ ! -f "$AGENT_MEMORY" ]]; then
#    write_log "Initializing agent state memory" "DEBUG"
#    cat > "$AGENT_MEMORY" <<'EOFMEM'
#{
#  "last_cleanup": null,
#  "total_runs": 0,
#  "total_files_deleted": 0,
#  "decisions": []
#}
#EOFMEM
#  else
#    write_log "Agent state memory loaded from $AGENT_MEMORY" "DEBUG"
#  fi
#}
#
#collect_signals() {
#  write_log "Collecting system and database signals for AI decision engine" "INFO"
#
#  cat <<EOFSIG
#{
#  "disk_usage": $(disk_usage),
#  "disk_threshold": $DISK_THRESHOLD,
#  "mysql_instances": ${#MYSQL_PORTS[@]},
#  "mysql_ports": "${MYSQL_PORTS[*]:-none}",
#  "postgres_ports": "${POSTGRES_PORTS[*]:-none}",
#  "oracle_ports": "${ORACLE_PORTS[*]:-none}",
#  "mysql_temp": "$(mysql_temp_active)",
#  "postgres_temp": "$(postgres_temp_active)",
#  "oracle_temp": "$(oracle_temp_active)",
#  "hour": $(date +%H),
#  "day_of_week": "$(date +%u)",
#  "environment": "${ENVIRONMENT:-development}",
#  "os": "$(uname -s)",
#  "hostname": "$(hostname)",
#  "correlation_id": "$CORRELATION_ID"
#}
#EOFSIG
#}
#
#agent_decide() {
#  write_log "Initiating AI-powered decision engine" "INFO"
#
#  local signals
#  signals=$(collect_signals)
#
#  write_log "Signal payload prepared ($(echo "$signals" | wc -c | tr -d ' ') bytes)" "DEBUG"
#
#  if [[ -z "$LLM_API_KEY" ]]; then
#    write_log "LLM API key not configured - using rule-based fallback" "WARN"
#    echo "ACTION: CLEAN_NOW"
#    echo "REASON: No AI configured, using default cleanup based on disk threshold"
#    return
#  fi
#
#  write_log "Calling LLM API: $LLM_API_URL (Model: $LLM_MODEL)" "INFO"
#  local api_start=$(date +%s%3N 2>/dev/null || date +%s)
#
#  local response
#  response=$(curl -s "$LLM_API_URL" \
#    -H "Authorization: Bearer $LLM_API_KEY" \
#    -H "Content-Type: application/json" \
#    -d '{"model":"'"$LLM_MODEL"'","messages":[{"role":"system","content":"You are a cautious SRE agent managing database cleanup operations."},{"role":"user","content":"Signals: '"$signals"'. Choose one: CLEAN_NOW | PARTIAL_CLEAN | DEFER | ESCALATE_ONLY. Format: ACTION: <value>\nREASON: <short reason>"}]}' 2>/dev/null)
#
#  local api_end=$(date +%s%3N 2>/dev/null || date +%s)
#  local api_latency=$((api_end - api_start))
#
#  write_metric "llm.api.latency_ms" "$api_latency"
#  write_log "LLM API responded in ${api_latency}ms" "INFO"
#
#  if [[ -n "$response" ]] && command -v jq &> /dev/null; then
#    local decision=$(echo "$response" | jq -r '.choices[0].message.content' 2>/dev/null || echo "")
#
#    if [[ -n "$decision" ]]; then
#      write_log "AI Decision received: $(echo "$decision" | head -1)" "INFO"
#      echo "$decision"
#    else
#      write_log "Failed to parse LLM response - using default action" "ERROR"
#      echo "ACTION: CLEAN_NOW"
#      echo "REASON: LLM response parsing failed"
#    fi
#  else
#    write_log "LLM API call failed or jq not available - using default action" "ERROR"
#    echo "ACTION: CLEAN_NOW"
#    echo "REASON: API call failed or jq not available"
#  fi
#}
#
#cleanup_dirs() {
#  write_log "========== CLEANUP EXECUTION STARTED ==========" "INFO"
#  write_log "Retention policy: Delete files older than $RETENTION_DAYS days" "INFO"
#
#  local files_deleted=0
#  local space_freed=0
#
#  for dir in "${TEMP_DIRS[@]}"; do
#    if [[ ! -d "$dir" ]]; then
#      write_log "Directory $dir does not exist - skipping" "WARN"
#      continue
#    fi
#
#    write_log "Scanning directory: $dir" "INFO"
#
#    local count
#    count=$(find "$dir" -type f \
#      \( -name "*.tmp" -o -name "*.temp" -o -name "*.swap" -o -name "ibtmp*" \) \
#      -mtime +"$RETENTION_DAYS" 2>/dev/null | wc -l | tr -d ' ')
#
#    if [[ "$count" -gt 0 ]]; then
#      write_log "Found $count eligible files for deletion in $dir" "INFO"
#
#      local size
#      size=$(find "$dir" -type f \
#        \( -name "*.tmp" -o -name "*.temp" -o -name "*.swap" -o -name "ibtmp*" \) \
#        -mtime +"$RETENTION_DAYS" -exec du -sk {} \; 2>/dev/null | awk '{sum+=$1} END {print sum}' || echo 0)
#
#      write_log "Estimated space to free: ${size}KB (~$((size/1024))MB)" "INFO"
#
#      local deleted=0
#      while IFS= read -r file; do
#        if rm -f "$file" 2>/dev/null; then
#          deleted=$((deleted + 1))
#          if [[ $((deleted % 100)) -eq 0 ]]; then
#            write_log "Progress: Deleted $deleted/$count files..." "DEBUG"
#          fi
#        fi
#      done < <(find "$dir" -type f \
#        \( -name "*.tmp" -o -name "*.temp" -o -name "*.swap" -o -name "ibtmp*" \) \
#        -mtime +"$RETENTION_DAYS" 2>/dev/null)
#
#      files_deleted=$((files_deleted + deleted))
#      space_freed=$((space_freed + size))
#
#      write_log "Completed deletion in $dir: $deleted files removed" "INFO"
#    else
#      write_log "No eligible files found in $dir" "INFO"
#    fi
#  done
#
#  write_log "========== CLEANUP EXECUTION COMPLETED =========" "INFO"
#  write_log "Total files deleted: $files_deleted" "INFO"
#  write_log "Total space freed: ${space_freed}KB (~$((space_freed/1024))MB)" "INFO"
#
#  write_metric "cleanup.files_deleted" "$files_deleted"
#  write_metric "cleanup.space_freed_kb" "$space_freed"
#}
#
#############################################
## MAIN
#############################################
#
#write_log "======================================================================" "INFO"
#write_log "  AGENTIC DATABASE TEMP CLEANUP - PRODUCTION EXECUTION" "INFO"
#write_log "  Version: 2.4.1 | Build: 20250127 | Environment: PROD" "INFO"
#write_log "======================================================================" "INFO"
#
#write_log "Execution Context:" "INFO"
#write_log "  - Correlation ID: $CORRELATION_ID" "INFO"
#write_log "  - Hostname: $(hostname)" "INFO"
#write_log "  - OS: $(uname -s) $(uname -r)" "INFO"
#write_log "  - User: $(whoami)" "INFO"
#write_log "  - Working Directory: $(pwd)" "INFO"
#write_log "  - Shell: $SHELL" "INFO"
#
#write_log "Attempting to acquire execution lock..." "INFO"
#acquire_lock
#write_log "Execution lock acquired successfully" "INFO"
#
#write_log "Initializing agent state memory..." "DEBUG"
#init_memory
#
#write_log "Fetching operational runbook from Confluence..." "INFO"
#fetch_confluence_runbook || write_log "Using local runbook cache" "INFO"
#
#check_active_incidents
#
#check_autosys_dependencies
#print_autosys_job_log "DB_BACKUP_DAILY"
#
#write_log "Initiating database port auto-discovery..." "INFO"
#MYSQL_PORTS=()
#POSTGRES_PORTS=()
#ORACLE_PORTS=()
#
#for p in $(discover_ports); do
#  case "$p" in
#    3306|33[0-9][0-9])
#      MYSQL_PORTS+=("$p")
#      write_log "Discovered MySQL instance on port $p" "INFO"
#      ;;
#    5432|54[0-9][0-9])
#      POSTGRES_PORTS+=("$p")
#      write_log "Discovered PostgreSQL instance on port $p" "INFO"
#      ;;
#    1521|15[0-9][0-9])
#      ORACLE_PORTS+=("$p")
#      write_log "Discovered Oracle instance on port $p" "INFO"
#      ;;
#  esac
#done
#
#write_log "Port discovery completed:" "INFO"
#write_log "  - MySQL ports: ${MYSQL_PORTS[*]:-none}" "INFO"
#write_log "  - PostgreSQL ports: ${POSTGRES_PORTS[*]:-none}" "INFO"
#write_log "  - Oracle ports: ${ORACLE_PORTS[*]:-none}" "INFO"
#
#get_disk_details
#
#CURRENT_DISK=$(disk_usage)
#write_log "Current disk utilization: ${CURRENT_DISK}%" "INFO"
#write_log "Configured threshold: ${DISK_THRESHOLD}%" "INFO"
#write_metric "disk.usage_percent" "$CURRENT_DISK"
#
#if [[ "$CURRENT_DISK" -lt "$DISK_THRESHOLD" ]]; then
#  write_log "Disk usage (${CURRENT_DISK}%) is below threshold (${DISK_THRESHOLD}%) - cleanup not required" "INFO"
#  write_log "Execution completed successfully - no action taken" "INFO"
#  send_to_splunk '{"type":"execution","action":"skipped","reason":"below_threshold"}'
#  exit 0
#fi
#
#write_log "WARNING: Disk usage ${CURRENT_DISK}% exceeds threshold ${DISK_THRESHOLD}% - cleanup required" "WARN"
#alert "Disk usage ${CURRENT_DISK}% exceeds threshold ${DISK_THRESHOLD}%" "WARNING"
#
#if [[ "$AI_ENABLED" == "true" ]] && [[ -n "$LLM_API_KEY" ]]; then
#  write_log "AI-powered decision engine enabled - consulting LLM" "INFO"
#  RESPONSE=$(agent_decide)
#  ACTION=$(echo "$RESPONSE" | grep 'ACTION:' | head -1 | sed 's/ACTION: *//' || echo "CLEAN_NOW")
#  REASON=$(echo "$RESPONSE" | grep 'REASON:' | head -1 | sed 's/REASON: *//' || echo "Default reason")
#  write_log "AI Decision Engine Output:" "INFO"
#  write_log "  - Action: $ACTION" "INFO"
#  write_log "  - Reasoning: $REASON" "INFO"
#else
#  ACTION="CLEAN_NOW"
#  REASON="AI disabled or no API key - using rule-based decision"
#  write_log "Using rule-based decision engine (AI disabled)" "INFO"
#fi
#
#write_log "Final Decision: $ACTION | Reason: $REASON" "INFO"
#
#case "$ACTION" in
#  CLEAN_NOW)
#    write_log "Executing CLEAN_NOW action..." "INFO"
#    cleanup_dirs
#    alert "Cleanup executed: $REASON" "INFO"
#    send_to_splunk '{"type":"cleanup","action":"clean_now","reason":"'"$REASON"'"}'
#    ;;
#  PARTIAL_CLEAN)
#    RETENTION_DAYS=7
#    write_log "Executing PARTIAL_CLEAN action with extended retention: $RETENTION_DAYS days" "INFO"
#    cleanup_dirs
#    alert "Partial cleanup executed: $REASON" "INFO"
#    send_to_splunk '{"type":"cleanup","action":"partial_clean","reason":"'"$REASON"'"}'
#    ;;
#  DEFER)
#    write_log "Cleanup deferred per AI decision: $REASON" "INFO"
#    alert "Cleanup deferred: $REASON" "INFO"
#    send_to_splunk '{"type":"cleanup","action":"deferred","reason":"'"$REASON"'"}'
#    ;;
#  ESCALATE_ONLY)
#    write_log "Escalating to operations team: $REASON" "WARN"
#    alert "Cleanup escalated to operations: $REASON" "CRITICAL"
#    send_to_splunk '{"type":"cleanup","action":"escalated","reason":"'"$REASON"'"}'
#    ;;
#  *)
#    write_log "Unknown action '$ACTION' received - defaulting to CLEAN_NOW" "WARN"
#    cleanup_dirs
#    alert "Cleanup executed (fallback): Unknown action received" "WARNING"
#    ;;
#esac
#
#FINAL_DISK=$(disk_usage)
#write_log "Post-cleanup disk utilization: ${FINAL_DISK}%" "INFO"
#write_metric "disk.usage_percent.post_cleanup" "$FINAL_DISK"
#
#if [[ "$FINAL_DISK" -lt "$DISK_THRESHOLD" ]]; then
#  write_log "SUCCESS: Disk usage reduced to acceptable levels" "INFO"
#else
#  write_log "WARNING: Disk usage still above threshold after cleanup" "WARN"
#  alert "Disk usage remains at ${FINAL_DISK}% after cleanup - manual intervention may be required" "WARNING"
#fi
#
#START_TIME=$(stat -f %m "$LOCK_FILE" 2>/dev/null || stat -c %Y "$LOCK_FILE" 2>/dev/null || date +%s)
#END_TIME=$(date +%s)
#DURATION=$((END_TIME - START_TIME))
#
#write_log "======================================================================" "INFO"
#write_log "  CLEANUP EXECUTION COMPLETED SUCCESSFULLY" "INFO"
#write_log "  Duration: ${DURATION}s" "INFO"
#write_log "======================================================================" "INFO"
#
#exit 0