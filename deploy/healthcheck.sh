#!/usr/bin/env bash
set -Eeuo pipefail

failed=0

check_service() {
  local service="$1"
  if systemctl is-active --quiet "${service}"; then
    printf 'OK   %s\n' "${service}"
  else
    printf 'FAIL %s\n' "${service}"
    failed=1
  fi
}

for service in \
  arl-infra.service arl-web.service arl-scheduler.service \
  arl-worker@main.service arl-worker@github.service \
  arl-worker@heavy.service arl-worker@heavy-full.service \
  arl-worker@post.service arl-worker@post-retry.service \
  arl-worker@collision.service nginx.service; do
  check_service "${service}"
done

for container in arl_mongodb arl_rabbitmq; do
  state="$(docker inspect --format '{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}' "${container}" 2>/dev/null || true)"
  if test "${state}" = "healthy" || test "${state}" = "running"; then
    printf 'OK   %s (%s)\n' "${container}" "${state}"
  else
    printf 'FAIL %s (%s)\n' "${container}" "${state:-missing}"
    failed=1
  fi
done

http_code="$(curl -ksS -o /dev/null -w '%{http_code}' --max-time 10 https://127.0.0.1:5003/ || true)"
if test "${http_code}" = "200"; then
  printf 'OK   HTTPS 5003\n'
else
  printf 'FAIL HTTPS 5003 (HTTP %s)\n' "${http_code:-none}"
  failed=1
fi

if test "${failed}" -ne 0; then
  printf '\n健康检查失败，请执行 /opt/ARL/deploy/manage.sh logs\n' >&2
  exit 1
fi

printf '\n所有核心组件正常。\n'
