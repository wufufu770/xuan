"""utils/signing 截图签名测试：往返、防篡改、密钥轮换。"""

from app.config import Config
from app.utils import signing


def test_sign_and_verify_round_trip():
    sign = signing.sign_path("task001", "abc123.jpg")
    assert signing.verify_image("task001", "abc123.jpg", sign)
    assert "sign=" in signing.sign_image_url("task001", "abc123.jpg")


def test_tamper_rejected():
    sign = signing.sign_path("task001", "abc123.jpg")
    assert not signing.verify_image("task001", "other.jpg", sign)
    assert not signing.verify_image("task002", "abc123.jpg", sign)
    assert not signing.verify_image("task001", "abc123.jpg", sign[:-1] + ("0" if sign[-1] != "0" else "1"))
    assert not signing.verify_image("task001", "abc123.jpg", "")
    assert not signing.verify_image("task001", "abc123.jpg", None)


def test_key_rotation_invalidates_old_signatures(monkeypatch):
    sign_before = signing.sign_path("task001", "a.jpg")
    monkeypatch.setattr(Config, "API_KEY", "rotated-key-0001", raising=False)
    sign_after = signing.sign_path("task001", "a.jpg")
    assert sign_before != sign_after
    assert not signing.verify_image("task001", "a.jpg", sign_before)
    assert signing.verify_image("task001", "a.jpg", sign_after)


def test_sign_is_deterministic():
    assert signing.sign_path("t", "f.jpg") == signing.sign_path("t", "f.jpg")
