#!/usr/bin/env bash
set -Eeuo pipefail

WORKERS=(main github heavy heavy-full post post-retry collision)
SERVICES=(arl-web.service arl-scheduler.service nginx.service)

usage() {
  cat <<'EOF'
用法：manage.sh <status|start|stop|restart|logs|credentials>
EOF
}

test "$(id -u)" -eq 0 || { echo "请使用 sudo" >&2; exit 1; }

case "${1:-}" in
  status)
    /opt/ARL/deploy/healthcheck.sh
    ;;
  start)
    systemctl start arl-infra.service "${SERVICES[@]}"
    for worker in "${WORKERS[@]}"; do systemctl start "arl-worker@${worker}.service"; done
    ;;
  stop)
    for worker in "${WORKERS[@]}"; do systemctl stop "arl-worker@${worker}.service"; done
    systemctl stop arl-scheduler.service arl-web.service
    ;;
  restart)
    systemctl restart arl-web.service arl-scheduler.service
    for worker in "${WORKERS[@]}"; do systemctl restart "arl-worker@${worker}.service"; done
    systemctl reload nginx.service
    ;;
  logs)
    journalctl -u 'arl-*' -n 200 --no-pager
    printf '\n应用错误日志：\n'
    tail -n 100 /opt/ARL/logs/arl_web_error.log 2>/dev/null || true
    ;;
  credentials)
    cat /etc/arl/credentials.env
    ;;
  *)
    usage
    exit 1
    ;;
esac
