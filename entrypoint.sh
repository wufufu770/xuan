#!/bin/bash
# ARL 容器入口：按 ROLE 分派 web / worker / scheduler
set -e
cd /opt/ARL

ROLE="${ROLE:-web}"

case "${ROLE}" in
  web)
    # 面向容器网络 0.0.0.0（由 nginx 反代对外）；容器内不再只绑 127.0.0.1
    exec gunicorn -w 2 -b 0.0.0.0:5013 app.main:arl_app \
      --access-logfile /opt/ARL/logs/arl_web_access.log \
      --error-logfile /opt/ARL/logs/arl_web_error.log
    ;;
  worker)
    QUEUES="${ARL_QUEUES:-arltask,arlheavy_top,arlheavy_full,arlpost,arlpost_retry,arlcollision,arlgithub}"
    exec celery -A app.celerytask.celery worker \
      -Q "${QUEUES}" -c "${ARL_CONCURRENCY:-2}" -n "dev@arl" -O fair
    ;;
  scheduler)
    exec python -m app.scheduler
    ;;
  *)
    echo "未知 ROLE: ${ROLE}（web/worker/scheduler）" >&2
    exit 1
    ;;
esac
