"""config.yaml 并发安全读写。

gunicorn 多 worker 共享同一份 config.yaml 作为凭证热更新载体（每请求直读，
见 routes/engines.py 说明）。历史实现是"整读→内存改→整写回"且无锁，
两个 worker/admin 并发保存会互相覆盖丢 key。这里提供进程间文件锁
（fcntl.flock）+ 临时文件原子替换，读侧因原子替换无需加锁。
"""

import fcntl
import os
from contextlib import contextmanager

import yaml


def load_config(config_path):
    """无锁读取：写入侧走 tmp + os.replace 原子替换，读到的一定是完整文件。"""
    with open(config_path) as f:
        return yaml.load(f, Loader=yaml.SafeLoader) or {}


def _atomic_write(tmp_path, config_path):
    """tmp -> target 落盘。os.replace 在 Docker 单文件挂载等场景报 EBUSY，
    此时降级为原地覆写（互斥仍由外层 flock 保证）。"""
    try:
        os.replace(tmp_path, config_path)
    except OSError:
        with open(tmp_path) as src:
            content = src.read()
        with open(config_path, "w") as dst:
            dst.write(content)
        os.remove(tmp_path)


@contextmanager
def locked_update(config_path):
    """读-改-写一体加锁：

    with locked_update(CONFIG_PATH) as data:
        data["FENGNIAR_TOKEN"] = token
    # 退出时自动落盘（tmp + 原子替换/降级覆写），全程持锁
    """
    lock_path = config_path + ".lock"
    with open(lock_path, "a+") as lock_fp:
        fcntl.flock(lock_fp.fileno(), fcntl.LOCK_EX)
        try:
            with open(config_path) as f:
                data = yaml.load(f, Loader=yaml.SafeLoader) or {}
            yield data
            tmp_path = config_path + ".tmp"
            with open(tmp_path, "w") as f:
                yaml.safe_dump(data, f, allow_unicode=True, sort_keys=False,
                               default_flow_style=False)
            _atomic_write(tmp_path, config_path)
        finally:
            fcntl.flock(lock_fp.fileno(), fcntl.LOCK_UN)
