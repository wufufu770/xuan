"""pytest 全局准备。

app/config.py 在模块导入时读取 app/config.yaml（缺失即 sys.exit），而测试
模块的导入发生在 pytest 收集期——早于任何 fixture 执行。因此配置文件准备
必须在 conftest 模块级完成（conftest 先于测试模块加载）。

本地开发/测试直接从模板复制（占位符是合法 YAML 字符串，无需真实凭据）。
该文件已被 .gitignore 排除。
"""

import os
import shutil

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CONFIG_PATH = os.path.join(BASE_DIR, "app", "config.yaml")
TEMPLATE_PATH = CONFIG_PATH + ".template"

if not os.path.exists(CONFIG_PATH):
    if not os.path.exists(TEMPLATE_PATH):
        raise RuntimeError("找不到 app/config.yaml.template，无法准备测试配置")
    shutil.copy(TEMPLATE_PATH, CONFIG_PATH)
