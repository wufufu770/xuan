#!/bin/bash
# 本地 CI：语法编译检查 -> pytest 全量（含鉴权覆盖断言、凤鸟/APP 链路 Mock 契约测试）
# 用法：scripts/ci.sh   （先跑 scripts/setup_dev.sh）
set -e
cd "$(dirname "$0")/.."

# 开发 venv 以 editable 方式引用发行包内的 ARL-NPoC 时，
# 防止 pytest 把 __pycache__ 写进发行包目录（安装器会拒绝包含缓存目录的包）
export PYTHONDONTWRITEBYTECODE=1

PY="${PYTHON:-.venv/bin/python}"
if test ! -x "${PY}"; then
  echo "未找到 ${PY}：请先运行 scripts/setup_dev.sh" >&2
  exit 1
fi

echo "== 1/3 语法编译检查 =="
"${PY}" -m compileall -q app scripts tests
echo "compileall OK"

echo "== 2/3 pytest 全量 =="
"${PY}" -m pytest tests -q

echo "== 3/3 CI PASS =="
