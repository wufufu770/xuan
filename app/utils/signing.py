"""截图等静态资源的 HMAC 签名与校验。

截图 URL 由 storage.py 在落库时生成为 /image/<task_id>/<file>?sign=<hmac>，
前端（含黑盒 bundle）直接引用存储值，因此签名必须写进 URL 本身；
image.py 在响应前校验。签名密钥派生自 ARL_API_KEY，轮换 API_KEY 即可作废全部旧链接。
"""

import hashlib
import hmac

from app.config import Config

_SIGN_KEY_FALLBACK = b"arl-image-signing"


def _key():
    secret = str(getattr(Config, "API_KEY", "") or "").strip()
    return secret.encode() if secret else _SIGN_KEY_FALLBACK


def sign_path(task_id, file_name):
    message = "{}/{}".format(task_id, file_name).encode()
    return hmac.new(_key(), message, hashlib.sha256).hexdigest()[:32]


def sign_image_url(task_id, file_name):
    return "/image/{}/{}?sign={}".format(
        task_id, file_name, sign_path(task_id, file_name))


def verify_image(task_id, file_name, sign):
    if not sign:
        return False
    return hmac.compare_digest(sign_path(task_id, file_name), str(sign))
