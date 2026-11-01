#!/bin/bash
# 本地 Docker 开发栈一键启动（方案 7.4 的"影子/联调环境"轻量版）。
#
# 功能：
#   1. 生成随机凭据（deploy/dev-credentials.env，600，已 gitignore）
#   2. 渲染容器用配置（deploy/dev-config.yaml，Mongo/Rabbit 指向容器服务名）
#   3. 从发行包阶段扫描器二进制到构建上下文 bin/
#   4. docker compose 构建并启动：mongodb/rabbitmq/web/worker/scheduler/nginx
#      nginx 对 0.0.0.0 发布 5003，宿主机/局域网可直接访问
#
# 用法：scripts/dev_up.sh [--no-build]
set -e
cd "$(dirname "$0")/.."

RELEASE_DIR="${RELEASE_DIR:-../arl-friend-v2.6.2-20260820_145749}"
CRED_FILE="deploy/dev-credentials.env"
CONFIG_FILE="deploy/dev-config.yaml"

# ------------------------------------------------------- 凭据 ----
if test ! -f "${CRED_FILE}"; then
  python3 - "${CRED_FILE}" <<'PY'
import hashlib, secrets, sys

def hexn(n):
    return secrets.token_hex(n)

password = secrets.token_hex(8)
admin_hash = hashlib.md5(("arlsalt!@#" + password).encode()).hexdigest()
lines = [
    ("MONGO_ROOT_USER", "arlroot"),
    ("MONGO_ROOT_PASSWORD", hexn(16)),
    ("MONGO_APP_USER", "arlapp"),
    ("MONGO_APP_PASSWORD", hexn(16)),
    ("RABBITMQ_USER", "arl"),
    ("RABBITMQ_PASSWORD", hexn(16)),
    ("RABBITMQ_VHOST", "arl"),
    ("ARL_ADMIN_USER", "admin"),
    ("ARL_ADMIN_PASSWORD", password),
    ("ARL_ADMIN_PASSWORD_HASH", admin_hash),
    ("ARL_API_KEY", hexn(24)),
]
with open(sys.argv[1], "w") as f:
    for k, v in lines:
        f.write("{}={}\n".format(k, v))
print("已生成随机凭据: " + sys.argv[1])
PY
  chmod 600 "${CRED_FILE}"
fi

# --------------------------------------------- 容器配置渲染 ----
MONGO_APP_PASSWORD="$(grep '^MONGO_APP_PASSWORD=' "${CRED_FILE}" | cut -d= -f2)"
RABBITMQ_PASSWORD="$(grep '^RABBITMQ_PASSWORD=' "${CRED_FILE}" | cut -d= -f2)"
ARL_API_KEY="$(grep '^ARL_API_KEY=' "${CRED_FILE}" | cut -d= -f2)"

python3 - app/config.yaml.template "${CONFIG_FILE}" \
    "${MONGO_APP_PASSWORD}" "${RABBITMQ_PASSWORD}" "${ARL_API_KEY}" <<'PY'
import sys
template, out, mongo_pw, mq_pw, api_key = sys.argv[1:6]
text = open(template).read()
text = text.replace("__CELERY_BROKER_URL__",
                    "amqp://arl:{}@rabbitmq:5672/arl".format(mq_pw))
text = text.replace("__MONGO_URI__",
                    "mongodb://arlapp:{}@mongodb:27017/arl".format(mongo_pw))
text = text.replace("__ARL_API_KEY__", api_key)
open(out, "w").write(text)
print("已渲染容器配置: " + out)
PY
chmod 600 "${CONFIG_FILE}"

# ------------------------------------------------ 扫描器阶段 ----
mkdir -p bin
if test -d "${RELEASE_DIR}/payload/bin"; then
  cp -f "${RELEASE_DIR}"/payload/bin/* bin/
  echo "已阶段 $(ls bin | wc -l) 个扫描器二进制"
else
  echo "警告：未找到发行包 bin（${RELEASE_DIR}/payload/bin），容器内将缺少扫描器" >&2
fi

# NPoC（xing 包，services 导入链依赖）
if test -d "${RELEASE_DIR}/payload/ARL-NPoC"; then
  rsync -a --delete --exclude "__pycache__" --exclude "*.pyc" \
    "${RELEASE_DIR}/payload/ARL-NPoC/" ARL-NPoC/
  echo "已阶段 ARL-NPoC"
else
  echo "警告：未找到 ARL-NPoC，容器内 app.services 导入会失败" >&2
fi

# --------------------------------------------------- 构建启动 ----
BUILD_ARGS=""
if test "${1:-}" != "--no-build"; then
  BUILD_ARGS="--build"
fi
docker compose -f deploy/docker-compose.dev.yml --env-file "${CRED_FILE}" up -d ${BUILD_ARGS}

# ------------------------------------------------------- 验证 ----
echo "等待 web 就绪..."
for i in $(seq 1 40); do
  code="$(curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:5003/api/stats/summary/ || true)"
  test "${code}" = "401" && break
  sleep 3
done

echo
echo "================ ARL 开发栈已启动 ================"
IP="$(hostname -I | awk '{print $1}')"
echo "访问地址（0.0.0.0 对外）:"
echo "  http://127.0.0.1:5003          本机"
echo "  http://${IP}:5003              宿主机/局域网"
ADMIN_PASSWORD="$(grep '^ARL_ADMIN_PASSWORD=' "${CRED_FILE}" | cut -d= -f2)"
echo "管理员账号: admin"
echo "管理员密码: ${ADMIN_PASSWORD}"
echo "API Key:    ${ARL_API_KEY}"
echo "凭据文件:   ${CRED_FILE}"
echo "注意: 容器镜像未包含 Chrome，依赖浏览器的阶段（动态爬虫/截图/会话池登录）"
echo "      在容器内不可用；基础扫描（子域/端口/httpx/nuclei）可用。"
