"""utils/yamlconf 加锁读-改-写语义测试。"""

import os
import threading

import yaml

from app.utils.yamlconf import load_config, locked_update


def _write(path, data):
    with open(path, "w") as f:
        yaml.safe_dump(data, f)


def test_locked_update_overlay_preserves_sibling_keys(tmp_path):
    """并发保存的核心语义：每次只覆盖自己写的顶层键，不丢兄弟键。"""
    path = str(tmp_path / "config.yaml")
    _write(path, {"A": {"KEY": "k1"}, "FENGNIAR_TOKEN": "t1"})

    # 模拟 engines 保存：快照里没有 FENGNIAR_TOKEN 的最新值
    stale_snapshot = load_config(path)
    stale_snapshot["A"]["KEY"] = "k2"
    with locked_update(path) as fresh:
        fresh["A"] = stale_snapshot["A"]

    # 模拟 fengniao 保存：只写 token
    with locked_update(path) as data:
        data["FENGNIAR_TOKEN"] = "t2"

    result = load_config(path)
    assert result["A"]["KEY"] == "k2"
    assert result["FENGNIAR_TOKEN"] == "t2"


def test_locked_update_is_atomic_no_tmp_left(tmp_path):
    path = str(tmp_path / "config.yaml")
    _write(path, {"X": 1})
    with locked_update(path) as data:
        data["X"] = 2
    assert load_config(path) == {"X": 2}
    assert not os.path.exists(path + ".tmp")


def test_locked_update_no_write_on_exception(tmp_path):
    path = str(tmp_path / "config.yaml")
    _write(path, {"X": 1})
    try:
        with locked_update(path) as data:
            data["X"] = 999
            raise RuntimeError("业务异常")
    except RuntimeError:
        pass
    assert load_config(path) == {"X": 1}, "异常时不得落盘半成品"


def test_concurrent_writers_no_torn_file(tmp_path):
    """多线程并发写：文件始终可解析（flock 保证读不到半成品）。"""
    path = str(tmp_path / "config.yaml")
    _write(path, {"counter": 0})
    errors = []

    def writer(n):
        try:
            for _ in range(20):
                with locked_update(path) as data:
                    data["counter"] = data.get("counter", 0) + 1
                    parsed = load_config(path)
                assert isinstance(parsed, dict)
        except Exception as exc:  # pragma: no cover
            errors.append(exc)

    threads = [threading.Thread(target=writer, args=(i,)) for i in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert not errors
    assert load_config(path)["counter"] == 80


def test_locked_update_fallback_when_replace_unavailable(tmp_path, monkeypatch):
    """Docker 单文件挂载下 os.replace 报 EBUSY：降级原地覆写仍写入成功。"""
    import os as _os
    path = str(tmp_path / "config.yaml")
    _write(path, {"A": 1})

    real_replace = _os.replace

    def fake_replace(src, dst):
        raise OSError(16, "Device or resource busy")

    monkeypatch.setattr(_os, "replace", fake_replace)
    with locked_update(path) as data:
        data["A"] = 42
    monkeypatch.setattr(_os, "replace", real_replace)

    assert load_config(path) == {"A": 42}
    assert not _os.path.exists(path + ".tmp"), "降级路径也须清理 tmp"
