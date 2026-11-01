#!/bin/bash
# 本地开发环境一键搭建（不含生产部署；需 Python3.10+ 与 gcc/pymongo 源码编译头文件）
# ARL_NPOC_PATH 可指定本地 ARL-NPoC 源码位置（xing 包，services eager import 依赖）
set -e
cd "$(dirname "$0")/.."

python3 -m venv .venv
.venv/bin/pip install -q -i https://pypi.tuna.tsinghua.edu.cn/simple 'pip<24.1' wheel setuptools
.venv/bin/pip install -q -i https://pypi.tuna.tsinghua.edu.cn/simple -r requirements-dev.txt

ARL_NPOC_PATH="${ARL_NPOC_PATH:-../arl-friend-v2.6.2-20260820_145749/payload/ARL-NPoC}"
if test -d "${ARL_NPOC_PATH}"; then
  .venv/bin/pip install -q --no-deps -e "${ARL_NPOC_PATH}"
else
  echo "警告：未找到 ARL-NPoC（${ARL_NPOC_PATH}），app.services 导入链会失败" >&2
  echo "      设置 ARL_NPOC_PATH 后重跑，或手动：pip install --no-deps -e <ARL-NPoC 路径>" >&2
  exit 1
fi

# 测试用 config.yaml（已被 gitignore；占位符即可，无真实凭据）
test -f app/config.yaml || cp app/config.yaml.template app/config.yaml

echo "开发环境就绪：.venv/bin/python -m pytest tests -q"
